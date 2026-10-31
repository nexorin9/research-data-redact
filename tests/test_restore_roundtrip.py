"""脱敏 ↔ 还原往返一致性。

还原这件事最容易出的岔子有两个，都归本测试盯：

1. **还原出来的不是原文** —— 代号换回原文时丢了空白、换了行、或者把另一例的
   身份换进来了。判据很硬：**还原件与原文逐字节相同**（空白与换行保持）。
2. **还原悄悄做了一半** —— 对照索引里查不到某个代号时，如果跳过继续跑，
   产出的就是一份「看着像原文、其实少了一段」的还原件 —— 这种件比不还原
   更危险。所以索引缺项必须**报错中止**：不落盘、不写回执、不推进状态。

另外盯两条纪律：已还原的文本不得被二次还原（幂等），以及回执与访问留痕里
**不含原文**（原文只允许出现在还原件本身里）。

本文件分两段：

- **替身段**（``TokenOperator``）—— 用一个测试替身验证还原服务本身的
  纪律（授权 / 回执 / 留痕 / 失败路径）；
- **生产段**（一致代号 ``hmac_pseudonym`` ↔ ``hmac_restore``）—— 验证真正
  上线的这条链路：脱敏侧把对照登记进对照索引，还原侧按同一份索引取回。

生产段盯的是**同一代号对应多段不同原文**这件事：一致代号建在患者身份上，
同一位患者在正文里的姓名处与主索引处拿到的是同一个代号，对应的却是两段
不同的原文 —— 按「代号 → 原文」单值表记，必然有一处张冠李戴。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.pipeline import redact_text
from research_redact.daemon.state_machine import (
    BatchEvent,
    BatchState,
    TransitionContext,
)
from research_redact.models import RestoreAuthorization
from research_redact.policy.mapping import (
    MappingIndexUnavailableError,
    PseudonymMappingIndex,
)
from research_redact.policy.operators import (
    ActionSpec,
    KeepOperator,
    Operator,
    OperatorContext,
    OperatorRegistry,
    RestoreOperator,
    RestoreTokenNotFoundError,
    default_operator_registry,
)
from research_redact.policy.table import load_policy_table
from research_redact.recognizers.assembly import build_default_registry
from research_redact.recognizers.patient_index import load_patient_index_binding
from research_redact.restore.authority import (
    ApproverRegistry,
    AuthorityValidator,
    authorize_window,
)
from research_redact.restore.service import (
    InMemoryMappingIndex,
    RestoreExecutionError,
    RestoreService,
)

#: 固定时钟
FIXED_NOW = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)

#: 本院授权名单
APPROVERS = ("张主任", "李质控")

#: 测试用密钥（只出现在测试里，不是任何真实凭据）。
TEST_KEY = "test-only-hmac-key-0123456789abcdef"

#: 一份含两处身份、其余为临床正文的样例（自造，非真实患者数据）
SOURCE_TEXT = (
    "患者姓名：张某某\n"
    "住院号：90000001\n"
    "检查号：CHK0000001\n"
    "诊断：右肺下叶磨玻璃结节\n"
    "处理：抗感染治疗，盐酸氨溴索口服液 30mL 静滴\n"
)

#: 身份串：台账、回执、留痕里都不该出现（还原件本身除外）
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001")


class TokenOperator(Operator):
    """可逆处置动作（测试替身）：命中原文换成唯一代号，并把对照登记进索引。

    这是任务 24（一致代号 HMAC）落地前的替身。它复刻了最关键的那条性质 ——
    **同一段原文恒得同一代号**（跨材料也一致）—— 差别只在代号怎么生成：
    这里按出现顺序编号，生产实现按 HMAC(患者主索引主键) 生成。

    替身只存在于测试层：产品代码里的可逆动作由 task 24 / 25 落地。
    """

    name = "replace"

    def __init__(self, index: InMemoryMappingIndex) -> None:
        self._index = index
        self._tokens: dict[str, str] = {}

    def apply(self, source: str, context: OperatorContext) -> str:
        token = self._tokens.get(source)
        if token is None:
            token = f"<代号{len(self._tokens) + 1}>"
            self._tokens[source] = token
        self._index.record(token, source)
        return token

    def describe(self) -> str:
        return "replace（可逆代号替身）"


@pytest.fixture()
def ledger(tmp_path: Path):
    """临时台账（用完即弃，不碰项目 var/）。"""
    with BatchLedger(tmp_path / "ledger.db") as instance:
        yield instance


@pytest.fixture()
def delivered_batch(ledger: BatchLedger) -> str:
    """把一个批次推进到 ``delivered``。"""
    batch_no = "KY20260002"
    ledger.open_batch(
        batch_no,
        ethics_approval_no="EC-2026-0002",
        patient_ids=("P-1001",),
        material_ids=("M-1",),
    )
    ledger.advance(
        batch_no,
        BatchEvent.APPLICATION_VALIDATED,
        TransitionContext(ethics_approval_no="EC-2026-0002", material_count=1),
        reason="申请单齐备",
    )
    ledger.advance(
        batch_no,
        BatchEvent.RECOGNITION_COMPLETED,
        TransitionContext(material_count=1, recognized_material_count=1),
        reason="识别完成",
    )
    ledger.advance(
        batch_no,
        BatchEvent.DELIVERY_SUCCEEDED,
        TransitionContext(residual_count=0, platform_delivered=True),
        reason="平台已回执",
    )
    return batch_no


def _authorization(**overrides) -> RestoreAuthorization:
    """构造一份双人、在时效内的还原授权。"""
    granted_at, expires_at = authorize_window(now=FIXED_NOW, ttl=timedelta(hours=24))
    data = {
        "request_id": "2026-0002",
        "dataset_id": "DS-9002",
        "approver_a": "张主任",
        "approver_b": "李质控",
        "scope": ("M-1",),
        "reason": "伦理核查需要核对第 3 例",
        "granted_at": granted_at,
        "expires_at": expires_at,
    }
    data.update(overrides)
    return RestoreAuthorization(**data)


def _service(ledger: BatchLedger, index: InMemoryMappingIndex) -> RestoreService:
    """装配一个还原服务（授权名单固定，时钟固定）。"""
    validator = AuthorityValidator(
        ApproverRegistry.from_names(APPROVERS),
        now_fn=lambda: FIXED_NOW,
    )
    return RestoreService(
        index=index,
        ledger=ledger,
        validator=validator,
        now_fn=lambda: FIXED_NOW,
    )


def _redact(text: str, index: InMemoryMappingIndex, material_id: str = "M-1"):
    """跑一次脱敏：身份类换成可逆代号，其余原样保留。"""
    operator = TokenOperator(index)
    operators = OperatorRegistry([operator, KeepOperator()])

    def resolve(label: str) -> ActionSpec:
        if label == "DEVICE_ID":
            return ActionSpec(action="keep")
        return ActionSpec(action="replace", placeholder="")

    return redact_text(text, material_id, actions=resolve, operators=operators)


# --------------------------------------------------------------- 往返一致性


def test_脱敏还原往返逐字节一致(ledger, delivered_batch) -> None:
    """脱敏 → 还原后与原文逐字节相同（空白与换行保持）。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)

    # 脱敏后：身份串没了，临床正文原样保留
    assert "张某某" not in outcome.redacted_text
    assert "90000001" not in outcome.redacted_text
    assert "右肺下叶磨玻璃结节" in outcome.redacted_text
    assert "盐酸氨溴索口服液 30mL" in outcome.redacted_text

    service = _service(ledger, index)
    result = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
    )

    assert result.succeeded
    assert result.restored["M-1"] == SOURCE_TEXT


def test_还原件落盘内容与原文逐字节一致(ledger, delivered_batch, tmp_path) -> None:
    """落盘的还原件与原文逐字节相同（不是「差不多」）。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)
    output_dir = tmp_path / "restore"

    service = _service(ledger, index)
    result = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
        output_dir=output_dir,
    )

    assert result.succeeded
    written = (output_dir / "M-1.txt").read_text(encoding="utf-8")
    assert written == SOURCE_TEXT


def test_同一原文跨材料代号一致且还原不串号(ledger, delivered_batch) -> None:
    """同一段原文在两份材料里代号相同；还原后各归各位，不串号。"""
    index = InMemoryMappingIndex()
    operators = OperatorRegistry([TokenOperator(index), KeepOperator()])

    def resolve(label: str) -> ActionSpec:
        return ActionSpec(action="keep" if label == "DEVICE_ID" else "replace")

    first = redact_text(SOURCE_TEXT, "M-1", actions=resolve, operators=operators)
    second = redact_text(SOURCE_TEXT, "M-2", actions=resolve, operators=operators)

    # 同一份原文 → 同一代号（一致性）
    assert first.redacted_text == second.redacted_text

    # 另一份材料里的不同患者不得与它共用代号
    other_text = SOURCE_TEXT.replace("张某某", "李某某").replace("90000001", "90000002")
    third = redact_text(other_text, "M-3", actions=resolve, operators=operators)
    assert third.redacted_text != first.redacted_text

    service = _service(ledger, index)
    result = service.execute(
        _authorization(scope=("M-1", "M-3")),
        batch_no=delivered_batch,
        materials={"M-1": first.redacted_text, "M-3": third.redacted_text},
        allowed_scope=("M-1", "M-3"),
    )
    assert result.succeeded
    assert result.restored["M-1"] == SOURCE_TEXT
    assert result.restored["M-3"] == other_text


# --------------------------------------------------------------- 失败路径


def test_未知代号报错且不落盘不推进状态(ledger, delivered_batch, tmp_path) -> None:
    """对照索引缺项 → 报错中止：不落盘、不写回执、状态不动。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)
    # 往正文里塞一个索引里没有的代号
    broken = outcome.redacted_text.replace("诊断：", "诊断：<代号99> ")
    output_dir = tmp_path / "restore"

    service = _service(ledger, index)
    with pytest.raises(RestoreExecutionError):
        service.execute(
            _authorization(),
            batch_no=delivered_batch,
            materials={"M-1": broken},
            allowed_scope=("M-1",),
            output_dir=output_dir,
        )

    # 没有产出半成品
    assert not output_dir.exists() or list(output_dir.iterdir()) == []
    # 状态没被推进（仍在 restore_pending）
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORE_PENDING
    # 没有「已还原」的回执
    kinds = {item.kind for item in ledger.receipts(delivered_batch)}
    assert "restore" not in kinds


def test_已还原文本不得被二次还原(ledger, delivered_batch) -> None:
    """把还原件再送一次还原：不报错、不改动（幂等）。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)
    service = _service(ledger, index)

    first = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
    )
    assert first.succeeded

    restored_text = first.restored["M-1"]
    again = service._restore_text(restored_text, "M-1")
    assert again == (restored_text, 0)


# --------------------------------------------------------------- 留痕纪律


def test_还原回执与留痕不含原文(ledger, delivered_batch) -> None:
    """原文只允许出现在还原件里；回执、留痕、台账一律不含。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)
    service = _service(ledger, index)
    service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
    )

    payload = json.dumps(
        [item.payload for item in ledger.receipts(delivered_batch)], ensure_ascii=False
    )
    payload += json.dumps(
        [
            {"actor": item.actor, "operation": item.operation, "detail": item.detail}
            for item in ledger.access_log(delivered_batch)
        ],
        ensure_ascii=False,
    )
    for secret in IDENTITY_STRINGS:
        assert secret not in payload


def test_还原结果摘要不含原文(ledger, delivered_batch) -> None:
    """对外摘要只给状态与计数，不给正文。"""
    index = InMemoryMappingIndex()
    outcome = _redact(SOURCE_TEXT, index)
    service = _service(ledger, index)
    result = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
    )
    summary = json.dumps(result.summary(), ensure_ascii=False)
    assert result.summary()["restored_material_count"] == 1
    for secret in IDENTITY_STRINGS:
        assert secret not in summary


# ================================================================== 生产段
# 一致代号（hmac_pseudonym）↔ 还原侧（hmac_restore）：真正上线的这条链路。
#
# 与替身段不同，这里验的是**成对挂载**：脱敏侧把「代号 ↔ 原文」登记进对照
# 索引，还原侧从同一份索引取回。两侧不配对，产品就变成「脱得出去、还原
# 不回来」。

#: 一致代号档下的材料：姓名处与主索引处是**同一位患者**的两个身份字段，
#: 因此拿到同一个代号，对应的却是两段不同的原文 —— 这正是「按代号单值
#: 记对照」会串号的地方。
#:
#: 就诊标识写作 ``ZY-7788``（非纯数字），不会被就诊编号形态命中，所以正文
#: 里没有不可逆的占位符，往返得以逐字节成立。真实报告里的住院号（纯数字）
#: 落占位符，那是**设计如此**：占位符不可逆，只有代号可逆（见下面的
#: 「占位符不可逆」用例）。
PSEUDONYM_SOURCE = (
    "患者姓名：张某某\n"
    "就诊标识：ZY-7788\n"
    "患者主索引：P-1001\n"
    "诊断：右肺下叶磨玻璃结节\n"
    "处理：抗感染治疗，盐酸氨溴索口服液 30mL 静滴\n"
)

#: 另一位患者
OTHER_SOURCE = (
    "患者姓名：李某某\n"
    "就诊标识：ZY-7789\n"
    "患者主索引：P-1002\n"
    "诊断：左肺上叶实变影\n"
)


def _binding(visit_no: str = "ZY-7788", other_visit_no: str = "ZY-7789"):
    """权威名单：两位患者，各带一个就诊标识与姓名。"""
    return load_patient_index_binding(
        records=[
            {"patient_id": "P-1001", "visit_no": visit_no, "name": "张某某"},
            {"patient_id": "P-1002", "visit_no": other_visit_no, "name": "李某某"},
        ],
        declared_patient_ids=["P-1001", "P-1002"],
    )


def _pseudonym_setup(binding=None):
    """按一致代号档装配：策略表 + 识别器注册表 + 动作注册表 + 对照索引。

    脱敏侧与还原侧**共用同一份对照索引** —— 这是成对的前提。
    """
    table = load_policy_table(profile="pseudonym")
    registry = build_default_registry(binding=binding, table=table)
    index = PseudonymMappingIndex()
    operators = default_operator_registry(mapping_index=index)
    return table, registry, operators, index


def _redact_pseudonym(text, material_id, table, registry, operators):
    """按一致代号档脱敏一份材料。"""
    return redact_text(
        text,
        material_id,
        registry=registry,
        actions=table.action_for,
        operators=operators,
    )


@pytest.fixture()
def pseudonym_env(monkeypatch):
    """一致代号需要密钥（缺密钥即报错中止，不降级）。"""
    monkeypatch.setenv("PSEUDONYM_HMAC_KEY", TEST_KEY)
    monkeypatch.setenv("PSEUDONYM_KEY_ID", "key-test-025")
    monkeypatch.delenv("RESEARCH_POLICY_PROFILE", raising=False)


def test_一致代号脱敏还原往返逐字节一致(pseudonym_env):
    """脱敏 → 还原后与原文逐字节相同（空白与换行保持）。

    同一代号在正文里出现两次（姓名处、主索引处），对应两段不同原文 ——
    还原必须各归各位，不能一处还原成另一处。
    """
    table, registry, operators, index = _pseudonym_setup(_binding())
    outcome = _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)

    # 脱敏后：身份串没了，代号只出现一个（同一患者恒等）
    assert "张某某" not in outcome.redacted_text
    assert "P-1001" not in outcome.redacted_text
    assert "右肺下叶磨玻璃结节" in outcome.redacted_text
    assert "盐酸氨溴索口服液 30mL" in outcome.redacted_text
    codes = [token for token in index.tokens("M-1")]
    assert len(codes) == 1, f"同一患者应只有一个代号：{codes}"
    assert outcome.redacted_text.count(codes[0]) == 2, "姓名处与主索引处应是同一个代号"

    restored = operators.get("hmac_restore").restore_text(
        outcome.redacted_text, "M-1"
    )
    assert restored.replaced == 2
    assert restored.text == PSEUDONYM_SOURCE


def test_不同患者各归各位不串号(pseudonym_env):
    """两位患者拿到不同代号，还原后各自还原成自己的原文。"""
    table, registry, operators, index = _pseudonym_setup(_binding())
    first = _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)
    second = _redact_pseudonym(OTHER_SOURCE, "M-2", table, registry, operators)

    codes = index.tokens()
    assert len(codes) == 2, f"两位患者应有两个代号：{codes}"
    assert first.redacted_text != second.redacted_text

    restored_first = operators.get("hmac_restore").restore_text(
        first.redacted_text, "M-1"
    )
    restored_second = operators.get("hmac_restore").restore_text(
        second.redacted_text, "M-2"
    )
    assert restored_first.text == PSEUDONYM_SOURCE
    assert restored_second.text == OTHER_SOURCE


def test_同一患者跨材料代号一致(pseudonym_env):
    """同一位患者在两份材料里代号恒等（跨材料对得上人）。"""
    table, registry, operators, index = _pseudonym_setup(_binding())
    first = _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)
    second = _redact_pseudonym(PSEUDONYM_SOURCE, "M-2", table, registry, operators)
    assert index.tokens("M-1") == index.tokens("M-2")
    assert first.redacted_text == second.redacted_text


def test_占位符不可逆代号可逆(pseudonym_env):
    """占位符字段（住院号）不可逆；一致代号字段可逆 —— 边界要说清楚。

    真实报告里的住院号是纯数字，会被就诊编号形态命中并落占位符；占位符按
    设计不可逆（它不是代号，没有对照索引），因此还原件里那一段仍是占位符。
    """
    binding = _binding(visit_no="90000001", other_visit_no="90000002")
    table, registry, operators, index = _pseudonym_setup(binding)
    source = (
        "患者姓名：张某某\n"
        "住院号：90000001\n"
        "患者主索引：P-1001\n"
        "诊断：右肺下叶磨玻璃结节\n"
    )
    outcome = _redact_pseudonym(source, "M-1", table, registry, operators)
    assert "<住院号>" in outcome.redacted_text

    restored = operators.get("hmac_restore").restore_text(
        outcome.redacted_text, "M-1"
    )
    assert "张某某" in restored.text
    assert "P-1001" in restored.text
    assert "<住院号>" in restored.text
    assert restored.text == source.replace("90000001", "<住院号>")


def test_对照索引缺项报错中止不静默跳过(pseudonym_env):
    """对照索引里查不到这个代号 → 报错中止，不产出半成品。"""
    index = PseudonymMappingIndex()
    operator = RestoreOperator(index=index)
    with pytest.raises(RestoreTokenNotFoundError, match="查不到原文"):
        operator.restore_text("患者姓名：P-0123456789abcdef\n", "M-1")


def test_对照索引不可达报错中止(pseudonym_env):
    """索引不可达（文件缺失 / 解密失败）→ 报错中止，不静默返回原文。"""

    class _UnreachableIndex:
        """对照索引不可达的替身（模拟索引文件缺失 / 解密失败）。"""

        def record_occurrence(self, material_id, token, original):  # pragma: no cover
            return 0

        def lookup_occurrence(self, material_id, token, occurrence):
            raise MappingIndexUnavailableError("对照索引文件缺失")

        def find_occurrences(self, text, material_id):
            raise MappingIndexUnavailableError("对照索引文件缺失")

    operator = RestoreOperator(index=_UnreachableIndex())
    with pytest.raises(MappingIndexUnavailableError, match="对照索引文件缺失"):
        operator.restore_text("患者姓名：P-0123456789abcdef\n", "M-1")


def test_已还原文本不被二次还原(pseudonym_env):
    """把还原件再送一次还原：幂等的空操作，原文不被二次换写。"""
    table, registry, operators, index = _pseudonym_setup(_binding())
    outcome = _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)
    operator = operators.get("hmac_restore")

    first = operator.restore_text(outcome.redacted_text, "M-1")
    assert first.text == PSEUDONYM_SOURCE
    assert first.replaced == 2

    again = operator.restore_text(first.text, "M-1")
    assert again.text == PSEUDONYM_SOURCE
    assert again.replaced == 0
    assert "幂等" in again.reason


def test_受控还原走同一份对照索引逐字节还原(
    ledger, delivered_batch, pseudonym_env
):
    """产品主路径：一致代号脱敏 → 双人授权受控还原 → 还原件与原文逐字节一致。

    还原走的是 task 13 的受控还原服务（授权 / 回执 / 留痕 / 状态推进），
    对照索引与脱敏侧是同一份 —— 这正是「成对挂载」在产品里的样子。
    """
    table, registry, operators, index = _pseudonym_setup(_binding())
    outcome = _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)

    service = _service(ledger, index)
    result = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": outcome.redacted_text},
        allowed_scope=("M-1",),
    )

    assert result.succeeded
    assert result.restored["M-1"] == PSEUDONYM_SOURCE
    # 回执与留痕里仍然不含原文
    payload = json.dumps(
        [item.payload for item in ledger.receipts(delivered_batch)], ensure_ascii=False
    )
    for secret in IDENTITY_STRINGS:
        assert secret not in payload


def test_重新脱敏同一材料不留旧对照(pseudonym_env):
    """同一份材料重新脱敏：旧槽位必须清掉，还原不得取到上一轮的原文。"""
    table, registry, operators, index = _pseudonym_setup(_binding())
    _redact_pseudonym(PSEUDONYM_SOURCE, "M-1", table, registry, operators)
    assert len(index) == 2

    # 同一份材料换一份内容再脱敏（模拟补齐材料后重投）
    updated = PSEUDONYM_SOURCE.replace("右肺下叶磨玻璃结节", "右肺上叶实变影")
    outcome = _redact_pseudonym(updated, "M-1", table, registry, operators)
    assert len(index) == 2, "重新脱敏不得叠加旧对照"

    restored = operators.get("hmac_restore").restore_text(
        outcome.redacted_text, "M-1"
    )
    assert restored.text == updated
