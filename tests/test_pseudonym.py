"""一致代号（HMAC-SHA256 over 患者主索引主键）的验收测试。

一致代号是本轮的**商业楔子**：科研交付要求「同一位患者跨材料对得上人、
又对不上人是谁」。源产品的 hash / encrypt 逐文档独立计算，同一患者在两份
材料里会拿到两个不同的串 —— 跨材料对不上，等于没脱。

本文件验收五件事：

1. **一致性** —— 同一主键跨三份材料（姓名处 / 主键处 / 另一份材料的姓名处）
   代号恒等；
2. **不串号** —— 不同主键代号不同，同一批次内代号不重复；
3. **不泄漏** —— 姓名 / 住院号 / 身份证都不参与计算，不可能出现在代号里；
4. **不降级** —— 缺密钥报错中止（不降级为无密钥哈希）；身份键绑不上报错
   中止（不按姓名硬匹配兜底，也不退回占位符）；
5. **接得上** —— 策略表能声明并选用一致代号档，代号本身不被残留自检当成
   漏脱。
"""

from __future__ import annotations

import re

import pytest

from research_redact.audit.alerts import RecordingAlertSink
from research_redact.audit.residual import ResidualChecker, pseudonym_pattern
from research_redact.config import OutboundConfig
from research_redact.daemon.pipeline import redact_batch, redact_text
from research_redact.policy.operators import (
    PseudonymOperator,
    RestoreOperator,
    default_operator_registry,
)
from research_redact.policy.pseudonym import (
    PseudonymConfig,
    PseudonymConfigError,
    PseudonymIdentityError,
    PseudonymKeyError,
    Pseudonymizer,
    load_pseudonym_config,
    normalize_identity,
)
from research_redact.policy.table import PolicyTableError, load_policy_table
from research_redact.recognizers.assembly import build_default_registry
from research_redact.recognizers.patient_index import load_patient_index_binding

#: 一致代号的形状：前缀 + 固定位数十六进制。
PSEUDONYM_PATTERN = re.compile(r"P-[0-9a-f]{16}")

#: 测试用密钥与密钥版本号（只出现在测试里，不是任何真实凭据）。
TEST_KEY = "test-only-hmac-key-0123456789abcdef"
TEST_KEY_ID = "key-test-001"

#: 样例材料里出现的原始身份串（脱敏副本与代号里都不该出现）。
RAW_NAME = "张某某"
RAW_VISIT_NO = "90000001"
RAW_ID_CARD = "110101194912310016"


def _binding():
    """权威名单：两位患者（P-1001 / P-1002），各带一个就诊号。"""
    return load_patient_index_binding(
        records=[
            {"patient_id": "P-1001", "visit_no": "90000001", "name": "张某某"},
            {"patient_id": "P-1002", "visit_no": "90000002", "name": "李某某"},
        ],
        declared_patient_ids=["P-1001", "P-1002"],
    )


def _pseudonym_table():
    """一致代号档的策略表。"""
    return load_policy_table(profile="pseudonym")


def _redact(text: str, material_id: str = "M-1", binding=None):
    """按一致代号档脱敏一份材料。"""
    table = _pseudonym_table()
    registry = build_default_registry(binding=binding, table=table)
    return redact_text(
        text,
        material_id,
        registry=registry,
        actions=table.action_for,
    )


def _codes(outcome) -> list[str]:
    """从脱敏副本里取出全部一致代号。"""
    return PSEUDONYM_PATTERN.findall(outcome.redacted_text)


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    """每个用例都带上测试密钥（缺密钥的用例自己删掉）。"""
    monkeypatch.setenv("PSEUDONYM_HMAC_KEY", TEST_KEY)
    monkeypatch.setenv("PSEUDONYM_KEY_ID", TEST_KEY_ID)
    monkeypatch.delenv("RESEARCH_POLICY_PROFILE", raising=False)


# --------------------------------------------------------------------- 一致性


def test_同主键跨三份材料代号一致():
    """同一患者在姓名处、主键处、另一份材料的姓名处 —— 代号恒等。"""
    binding = _binding()
    materials = {
        "M-1": "姓名：张某某 住院号：90000001",
        "M-2": "患者主索引：P-1001",
        "M-3": "受检者姓名：张某某 住院号：90000001",
    }
    codes: set[str] = set()
    for material_id, text in materials.items():
        outcome = _redact(text, material_id, binding=binding)
        found = _codes(outcome)
        assert found, f"{material_id} 未产出代号：{outcome.redacted_text!r}"
        codes.add(found[0])
    assert len(codes) == 1, f"同一患者跨材料代号不一致：{codes}"


def test_不同主键代号不同():
    """不同患者不得拿到同一个代号（不串号）。"""
    binding = _binding()
    first = _redact("姓名：张某某 住院号：90000001", "M-1", binding=binding)
    second = _redact("姓名：李某某 住院号：90000002", "M-2", binding=binding)
    assert _codes(first) and _codes(second)
    assert _codes(first)[0] != _codes(second)[0]


def test_同一批次内代号不重复():
    """一个批次里每位患者一个代号，互不重复。"""
    binding = _binding()
    table = _pseudonym_table()
    registry = build_default_registry(binding=binding, table=table)
    batch = redact_batch(
        "KY20260001",
        {
            "M-1": "姓名：张某某 住院号：90000001",
            "M-2": "姓名：李某某 住院号：90000002",
            "M-3": "患者主索引：P-1001",
        },
        checker=ResidualChecker(
            registry=registry, table=table, sink=RecordingAlertSink()
        ),
        registry=registry,
        actions=table.action_for,
    )
    codes: list[str] = []
    for outcome in batch.outcomes:
        codes.extend(_codes(outcome))
    assert len(codes) == 3, f"每处命中应各产出一个代号：{codes}"
    assert len(set(codes)) == 2, f"批次内代号重复（串号）：{codes}"
    # 代号本身不被残留自检当成漏脱 —— 否则批次永远交付不出去
    assert batch.residual is not None
    assert batch.deliverable, batch.residual.summary


def test_归一化后同主键同代号():
    """同一个主键只有一种写法：全半角、空格、大小写都归一化到同一代号。"""
    generator = Pseudonymizer(TEST_KEY, key_id=TEST_KEY_ID)
    baseline = generator.pseudonymize("P-1001")
    assert generator.pseudonymize(" p-1001 ") == baseline
    assert generator.pseudonymize("P-1001".lower()) == baseline
    assert generator.pseudonymize("Ｐ-１００１") == baseline
    assert generator.pseudonymize("P-1002") != baseline


def test_换密钥则整批代号改变():
    """换密钥 = 换一批代号（所以密钥版本号必须随交付体一起交付）。"""
    first = Pseudonymizer(TEST_KEY).pseudonymize("P-1001")
    second = Pseudonymizer("another-test-only-key-0123456789").pseudonymize("P-1001")
    assert first != second


# --------------------------------------------------------------------- 不泄漏


def test_代号不含原文片段():
    """姓名 / 住院号 / 身份证不参与计算，不可能出现在代号或副本里。"""
    binding = _binding()
    outcome = _redact(
        f"姓名：张某某 住院号：90000001 身份证：110101194912310016",
        "M-1",
        binding=binding,
    )
    code = _codes(outcome)
    assert code, outcome.redacted_text
    for raw in (RAW_NAME, RAW_VISIT_NO, RAW_ID_CARD):
        assert raw not in code[0]
        assert raw not in outcome.redacted_text
    # 代号只由前缀与十六进制摘要组成
    assert PSEUDONYM_PATTERN.fullmatch(code[0])
    assert code[0].startswith("P-")
    assert len(code[0]) == 18


# --------------------------------------------------------------------- 不降级


def test_缺密钥报错不降级(monkeypatch):
    """缺密钥即报错中止 —— 绝不降级为无密钥哈希。"""
    monkeypatch.delenv("PSEUDONYM_HMAC_KEY", raising=False)
    binding = _binding()
    with pytest.raises(PseudonymKeyError) as excinfo:
        _redact("姓名：张某某 住院号：90000001", "M-1", binding=binding)
    message = str(excinfo.value)
    assert "PSEUDONYM_HMAC_KEY" in message
    assert "无密钥哈希" in message
    # 直接装配也一样报错
    with pytest.raises(PseudonymKeyError):
        Pseudonymizer.from_env({})
    with pytest.raises(PseudonymKeyError):
        Pseudonymizer("")


def test_身份键绑不上时报错不兜底():
    """这处命中绑不到主索引主键 → 中止，不按姓名硬匹配，也不退回占位符。"""
    with pytest.raises(PseudonymIdentityError) as excinfo:
        _redact("姓名：张某某 住院号：90000001", "M-1", binding=None)
    message = str(excinfo.value)
    assert "患者主索引主键" in message
    # 不是占位符、也不是原文 —— 报错时什么都没产出
    assert "<患者姓名>" not in message
    assert RAW_NAME not in message


# ----------------------------------------------------------------- 策略表接线


def test_策略表默认档仍是占位符():
    """默认档不动 —— 单份材料即时脱敏不必配密钥。"""
    table = load_policy_table()
    assert table.profile == ""
    assert table.action_for("PATIENT_NAME").action == "replace"
    assert table.action_for("PATIENT_NAME").placeholder == "<患者姓名>"


def test_策略表一致代号档可选用():
    """档位可选用：两个身份绑定类切到一致代号，其余类别沿用默认档。"""
    table = load_policy_table(profile="pseudonym")
    assert table.profile == "pseudonym"
    assert table.action_for("PATIENT_NAME").action == "hmac_pseudonym"
    assert table.action_for("PATIENT_ID").action == "hmac_pseudonym"
    assert table.action_for("VISIT_NO").action == "replace"
    assert table.action_for("EXAM_NO").placeholder == "<检查号>"


def test_档名写错即报错不退回默认档(monkeypatch):
    """档名写错必须报错 —— 退回默认档等于「以为按一致代号脱了、实际脱成占位符」。"""
    with pytest.raises(PolicyTableError):
        load_policy_table(profile="pseudonymn")
    monkeypatch.setenv("RESEARCH_POLICY_PROFILE", "pseudonymn")
    with pytest.raises(PolicyTableError):
        load_policy_table()


def test_环境变量选用档位(monkeypatch):
    """$RESEARCH_POLICY_PROFILE 生效（守护进程与 CLI 共用同一份策略表）。"""
    monkeypatch.setenv("RESEARCH_POLICY_PROFILE", "pseudonym")
    table = load_policy_table()
    assert table.profile == "pseudonym"
    assert table.action_for("PATIENT_NAME").action == "hmac_pseudonym"


def test_一致代号与其还原侧成对登记可执行():
    """脱敏侧与其还原侧成对登记（task 25 落地），共用同一份对照索引。

    成对是硬要求：脱敏侧登记的对照槽位，还原侧才取得到 —— 两侧不配对，
    产品就变成「脱得出去、还原不回来」。
    """
    registry = default_operator_registry()
    assert registry.has("hmac_pseudonym")
    assert isinstance(registry.get("hmac_pseudonym"), PseudonymOperator)
    assert registry.has("hmac_restore")
    assert isinstance(registry.get("hmac_restore"), RestoreOperator)
    assert registry.mapping_index is not None


# --------------------------------------------------------------------- 口径


def test_口径配置非法即报错():
    """口径段写错即报错，不静默取默认值。"""
    with pytest.raises(PseudonymConfigError):
        PseudonymConfig.from_policy({"pseudonymization": {"digest_length": 3}})
    with pytest.raises(PseudonymConfigError):
        PseudonymConfig.from_policy({"pseudonymization": {"digest_length": "16"}})
    with pytest.raises(PseudonymConfigError):
        PseudonymConfig.from_policy({"pseudonymization": {"schemee": "x"}})
    with pytest.raises(PseudonymConfigError):
        PseudonymConfig.from_policy({"pseudonymization": {"scheme": ""}})
    with pytest.raises(PseudonymConfigError):
        PseudonymConfig.from_policy({"pseudonymization": "hmac-sha256"})
    # 缺段 → 出厂口径（与 spec.md 4.2 一致）
    assert PseudonymConfig.from_policy({}) == PseudonymConfig()


def test_口径从策略表读():
    """口径随策略表走（换院区改 YAML 即可，不改代码）。"""
    config = load_pseudonym_config()
    assert config.scheme == "hmac-sha256"
    assert config.prefix == "P-"
    assert config.digest_length == 16


def test_密钥版本号随交付体走(monkeypatch):
    """密钥版本号既写进一致代号，也写进交付体的 pseudonymization.key_id。"""
    generator = Pseudonymizer.from_env()
    assert generator.key_id == TEST_KEY_ID
    assert generator.scheme == "hmac-sha256"
    assert OutboundConfig.from_env().pseudonym_key_id == TEST_KEY_ID
    # 描述里只有版本号，没有密钥
    assert TEST_KEY not in generator.describe()
    assert TEST_KEY_ID in generator.describe()


def test_残留自检认得代号形状():
    """代号形状被认作「已脱」，不会被报成残留。"""
    pattern = pseudonym_pattern()
    assert pattern.fullmatch("P-0123456789abcdef")
    assert not pattern.fullmatch("P-0123456789abcde")  # 位数不对
    assert not pattern.fullmatch("P-0123456789abcdeg")  # 非十六进制
    assert not pattern.fullmatch("张某某")


def test_归一化函数口径():
    """归一化：全半角折叠 + 去空白 + 小写。"""
    assert normalize_identity(" P-1001 ") == "p-1001"
    assert normalize_identity("Ｐ-１００１") == "p-1001"
    assert normalize_identity("") == ""
