"""对照索引的加密存储与访问留痕。

对照索引是「代号 ↔ 原文」的反查表 —— 它比交付物本身更危险：交付物里只有
代号（不可逆），索引里躺着姓名、住院号、身份证这些**原文**。所以三件事必须
同时成立，否则这张表等于没脱：

1. **加密落盘** —— 文件字节里搜不到任何原文；
2. **与交付物分离** —— 索引不与交付物同目录；
3. **访问留痕** —— 解密 / 查询 / 写入每次都留一条「谁、何时、做了什么、条数」，
   且留痕里**既没有原文也没有代号**（代号进留痕等于给了反查的半把钥匙）。

另外盯两条红线：

- **索引不可达 = 报错中止 + 批次挂起** —— 索引文件缺失 / 解密失败时不得
  「重建一个空索引继续跑」：空索引会让还原件「看着像原文、其实少了一段」，
  比还原失败危险得多。
- **密钥缺失即报错** —— 不退回内置默认密钥（那等于把索引公开）。

本文件还用真实的一致代号动作（``hmac_pseudonym``）与其还原侧
（``hmac_restore``）跑一遍往返，证明这张加密索引**真的接得上主路径**，
不是一张只能自己看的表。
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.state_machine import BatchEvent, BatchState, TransitionContext
from research_redact.policy.index_store import (
    EncryptedIndexStore,
    IndexDecryptError,
    IndexFileMissingError,
    IndexKeyError,
    IndexStoreError,
    IndexUnavailableError,
    JsonlAccessTrail,
    KEY_SOURCE_DERIVED,
    KEY_SOURCE_EXPLICIT,
    default_index_path,
    load_index_store,
    resolve_index_key,
    suspend_unreachable_batch,
)
from research_redact.policy.mapping import MappingIndexUnavailableError
from research_redact.policy.operators import (
    OperatorContext,
    PseudonymOperator,
    RestoreOperator,
)

#: 测试用密钥（只出现在测试里，不是任何真实凭据）。
TEST_KEY = "test-only-index-key-0123456789abcdef"
OTHER_KEY = "test-only-other-key-9876543210fedcba"

#: 自造样例（非真实患者数据）：原文、代号与材料 ID。
ORIGINAL_NAME = "张某某"
ORIGINAL_VISIT = "90000001"
TOKEN = "P-0daaf6ec23046198"


def _store(path, *, key: str = TEST_KEY, ledger=None, batch_no: str = "KY20260001"):
    """装配一份加密索引（密钥来源按「专用密钥」标注）。"""
    return EncryptedIndexStore(
        path=path,
        key=key.encode("utf-8"),
        key_source=KEY_SOURCE_EXPLICIT,
        ledger=ledger,
        batch_no=batch_no,
        actor="科研数据管理员",
    )


def _ready_ledger(tmp_path, batch_no: str = "KY20260001") -> BatchLedger:
    """建一个已校验（recognized）的批次台账。"""
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    ledger.open_batch(
        batch_no,
        ethics_approval_no="EC-2026-0001",
        patient_ids=["P-1001"],
        material_ids=["M-1"],
    )
    ledger.advance(
        batch_no,
        BatchEvent.APPLICATION_VALIDATED,
        TransitionContext(ethics_approval_no="EC-2026-0001", material_count=1),
    )
    return ledger


# ----------------------------------------------------------------- 加密落盘


def test_加密落盘后文件字节不含明文原文(tmp_path):
    """索引文件里搜不到任何原文 —— 落盘的必须是密文。"""
    path = tmp_path / "index" / "pseudonym_index.enc"
    store = _store(path)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_VISIT)
    store.save()

    raw = path.read_bytes()
    assert raw, "索引文件不应为空"
    for secret in (ORIGINAL_NAME, ORIGINAL_VISIT, "90000001", "张"):
        assert secret.encode("utf-8") not in raw, f"索引文件里出现了明文：{secret}"
    # 也不是「把原文换个格式存起来」：整体不是可读 JSON
    with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
        json.loads(raw.decode("utf-8"))
    # 密文长度远大于明文（说明确实经过了带认证的加密）
    assert len(raw) > 64


def test_解密后能取回原文且分槽不串号(tmp_path):
    """同一代号对应多段原文时按出现次序各归各位。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    assert store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME) == 0
    assert store.record_occurrence("M-1", TOKEN, ORIGINAL_VISIT) == 1
    store.save()

    reopened = _store(path)
    assert reopened.load() == 2
    assert reopened.lookup_occurrence("M-1", TOKEN, 0) == ORIGINAL_NAME
    assert reopened.lookup_occurrence("M-1", TOKEN, 1) == ORIGINAL_VISIT
    # 越界槽位返回 None（不得返回空串冒充命中）
    assert reopened.lookup_occurrence("M-1", TOKEN, 2) is None
    assert reopened.lookup_occurrence("M-9", TOKEN, 0) is None


def test_重开索引后可继续登记并再次落盘(tmp_path):
    """重新装配的索引能接着用，条目数累加。"""
    path = tmp_path / "index.enc"
    first = _store(path)
    first.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    first.save()

    second = _store(path)
    second.load()
    second.record_occurrence("M-2", TOKEN, ORIGINAL_VISIT)
    second.save()

    third = _store(path)
    assert third.load() == 2
    assert third.tokens() == (TOKEN,)


def test_清空材料槽位后旧原文不再可还原(tmp_path):
    """重新脱敏同一份材料前清槽位 —— 旧原文不得留在索引里。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.reset_material("M-1")
    assert len(store) == 0
    assert store.lookup_occurrence("M-1", TOKEN, 0) is None


# ----------------------------------------------------------------- 访问留痕


def test_解密操作在留痕表可见(tmp_path):
    """解密一次就在台账的访问留痕表里留下一条。"""
    ledger = _ready_ledger(tmp_path)
    path = tmp_path / "index.enc"
    store = _store(path, ledger=ledger)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()

    reopened = _store(path, ledger=ledger)
    reopened.load()

    trail = ledger.access_log()
    decrypt_rows = [row for row in trail if row.operation == "index_decrypt"]
    assert len(decrypt_rows) == 1, "解密一次必须留一条痕"
    row = decrypt_rows[0]
    assert row.batch_no == "KY20260001"
    assert row.actor == "科研数据管理员"
    assert "条目 1 条" in row.detail
    assert row.created_at is not None


def test_查询与写入同样留痕(tmp_path):
    """写入、查询、落盘三件事各自留痕，不是只有解密留。"""
    ledger = _ready_ledger(tmp_path)
    store = _store(tmp_path / "index.enc", ledger=ledger)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.lookup_occurrence("M-1", TOKEN, 0)
    store.save()

    operations = [row.operation for row in ledger.access_log()]
    assert "index_record" in operations
    assert "index_lookup" in operations
    assert "index_write" in operations


def test_留痕不含原文也不含代号(tmp_path):
    """留痕里只有谁、何时、操作与条数 —— 原文与代号都不得出现。"""
    ledger = _ready_ledger(tmp_path)
    store = _store(tmp_path / "index.enc", ledger=ledger)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.lookup_occurrence("M-1", TOKEN, 0)
    store.save()

    blob = "\n".join(
        f"{row.actor}|{row.operation}|{row.detail}" for row in ledger.access_log()
    )
    for secret in (ORIGINAL_NAME, ORIGINAL_VISIT, TOKEN, "0daaf6ec"):
        assert secret not in blob, f"访问留痕里出现了不该出现的内容：{secret}"


def test_无台账时留痕落本地JSONL(tmp_path):
    """没配台账也要留痕 —— 否则守护进程外的调用就是无人管的暗箱。"""
    path = tmp_path / "index" / "pseudonym_index.enc"
    store = EncryptedIndexStore(
        path=path,
        key=TEST_KEY.encode("utf-8"),
        key_source=KEY_SOURCE_EXPLICIT,
        batch_no="KY20260002",
        actor="system",
    )
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()

    trail_file = path.parent / "index-access.jsonl"
    assert trail_file.is_file()
    rows = JsonlAccessTrail(trail_file).entries()
    operations = [row["operation"] for row in rows]
    assert "index_record" in operations
    assert "index_write" in operations
    assert all(row["batch_no"] == "KY20260002" for row in rows)
    assert ORIGINAL_NAME not in trail_file.read_text(encoding="utf-8")


# ------------------------------------------------------------- 索引不可达


def test_索引缺失时报错且批次置挂起(tmp_path):
    """索引文件缺失 → 报错中止 + 批次 suspended，**不重建空索引放行**。"""
    ledger = _ready_ledger(tmp_path)
    path = tmp_path / "var" / "index" / "pseudonym_index.enc"
    store = _store(path, ledger=ledger)

    with pytest.raises(IndexFileMissingError) as excinfo:
        store.require_available(ledger=ledger, batch_no="KY20260001")

    message = str(excinfo.value)
    assert str(path) in message
    assert "重建空索引放行" in message
    # 批次已挂起
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.batch_state is BatchState.SUSPENDED
    assert "对照索引" in record.failure_reason
    # 挂起必落告警，且告警码与主索引不可达分开
    alerts = ledger.alerts("KY20260001")
    assert [alert.code for alert in alerts] == ["index_store_unreachable"]
    # 时间线里能看到这一步
    events = [row.event for row in ledger.timeline("KY20260001")]
    assert events[-1] == BatchEvent.INDEX_STORE_UNREACHABLE.value
    # 关键：没有偷偷建一个空索引文件
    assert not path.exists()


def test_索引不可达的错误也是不可达语义(tmp_path):
    """索引缺失 / 解密失败都归「不可达」，与「查得到但缺项」分开。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    with pytest.raises(IndexUnavailableError):
        store.load()
    with pytest.raises(MappingIndexUnavailableError):
        store.load()
    assert issubclass(IndexUnavailableError, IndexStoreError)


def test_状态不允许挂起时不强改状态只留痕(tmp_path):
    """批次已交付时挂起不合法 —— 状态不动，但留痕说明为什么没挂上。"""
    ledger = _ready_ledger(tmp_path)
    ledger.advance(
        "KY20260001",
        BatchEvent.RECOGNITION_COMPLETED,
        TransitionContext(
            material_count=1, recognized_material_count=1, patient_index_reachable=True
        ),
    )
    ledger.advance(
        "KY20260001",
        BatchEvent.DELIVERY_SUCCEEDED,
        TransitionContext(residual_count=0, platform_delivered=True),
    )
    assert ledger.get_batch("KY20260001").batch_state is BatchState.DELIVERED

    result = suspend_unreachable_batch(
        ledger, "KY20260001", "对照索引文件不存在", actor="科研数据管理员"
    )
    assert result is None
    record = ledger.get_batch("KY20260001")
    assert record.batch_state is BatchState.DELIVERED, "状态不得被强改"
    trail = [row.operation for row in ledger.access_log("KY20260001")]
    assert "index_store_suspend_failed" in trail


def test_索引恢复后批次可从挂起迁出(tmp_path):
    """索引恢复可达 → 批次从 suspended 回到 recognized。"""
    ledger = _ready_ledger(tmp_path)
    path = tmp_path / "index.enc"
    store = _store(path, ledger=ledger)
    with pytest.raises(IndexFileMissingError):
        store.require_available(ledger=ledger, batch_no="KY20260001")
    assert ledger.get_batch("KY20260001").batch_state is BatchState.SUSPENDED

    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()
    ledger.advance(
        "KY20260001",
        BatchEvent.INDEX_STORE_RESTORED,
        TransitionContext(index_store_reachable=True),
        reason="对照索引已恢复",
    )
    assert ledger.get_batch("KY20260001").batch_state is BatchState.RECOGNIZED


def test_密钥不匹配时报解密失败而不是空索引(tmp_path):
    """密钥不匹配 → 明确报错；不得读成「索引是空的」。"""
    path = tmp_path / "index.enc"
    writer = _store(path)
    writer.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    writer.save()

    other = _store(path, key=OTHER_KEY)
    with pytest.raises(IndexDecryptError) as excinfo:
        other.load()
    assert "密钥不匹配" in str(excinfo.value)


def test_索引文件被改动时报解密失败(tmp_path):
    """文件被篡改 → 认证标签校验失败 → 报错中止。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()

    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0xFF
    path.write_bytes(bytes(raw))
    with pytest.raises(IndexDecryptError):
        _store(path).load()


def test_索引文件格式不对时报错(tmp_path):
    """不是本系统写出的文件 → 明确报错，不当作空索引。"""
    path = tmp_path / "index.enc"
    path.write_bytes(b"not-an-index-file")
    with pytest.raises(IndexDecryptError):
        _store(path).load()


# ------------------------------------------------------------------ 密钥位


def test_密钥缺失时报错不退回默认密钥():
    """两个凭据位都没配 → 报错，绝不退回内置默认密钥。"""
    with pytest.raises(IndexKeyError) as excinfo:
        resolve_index_key({})
    message = str(excinfo.value)
    assert "INDEX_ENCRYPTION_KEY" in message
    assert "PSEUDONYM_HMAC_KEY" in message
    assert "不得退回内置默认密钥" in message


def test_专用密钥优先于派生(monkeypatch):
    """配了专用索引密钥就用它；没配才由一致代号密钥派生并标注来源。"""
    key, source = resolve_index_key(
        {"INDEX_ENCRYPTION_KEY": "dedicated", "PSEUDONYM_HMAC_KEY": "master"}
    )
    assert key == b"dedicated"
    assert source == KEY_SOURCE_EXPLICIT

    key, source = resolve_index_key({"PSEUDONYM_HMAC_KEY": "master"})
    assert key == b"master"
    assert source == KEY_SOURCE_DERIVED


def test_派生密钥在摘要里看得见(monkeypatch, tmp_path):
    """派生来源必须能被运维看见（密钥分离度下降这件事不能藏）。"""
    monkeypatch.delenv("RESEARCH_INDEX_FILE", raising=False)
    store = load_index_store(
        env={"PSEUDONYM_HMAC_KEY": "master-key"},
        path=tmp_path / "index.enc",
    )
    assert store.derived is True
    summary = store.info().describe()
    assert "派生" in summary
    assert "PSEUDONYM_HMAC_KEY" in summary
    assert "master-key" not in summary


def test_按环境变量装配索引(monkeypatch, tmp_path):
    """端到端装配：环境变量给凭据位与路径，缺一即报错。"""
    path = tmp_path / "index.enc"
    store = load_index_store(
        env={"INDEX_ENCRYPTION_KEY": "dedicated-key"}, path=path
    )
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()
    assert path.is_file()

    with pytest.raises(IndexKeyError):
        load_index_store(env={}, path=path)


# ------------------------------------------------------------- 路径与隔离


def test_索引路径与交付物目录分离(monkeypatch):
    """索引落在 var/index/ 下，不与交付物（var/outbox/）同处一地。"""
    monkeypatch.delenv("RESEARCH_INDEX_FILE", raising=False)
    path = default_index_path({})
    assert "index" in path.parts
    assert "outbox" not in path.parts
    assert path.name == "pseudonym_index.enc"


def test_索引文件路径可由环境变量指定(monkeypatch, tmp_path):
    """路径可配（运维按院内目录规范放），但仍要与交付物分离由人负责。"""
    monkeypatch.setenv("RESEARCH_INDEX_FILE", str(tmp_path / "custom" / "idx.enc"))
    assert default_index_path() == tmp_path / "custom" / "idx.enc"


# ------------------------------------------------------------ 与主路径成对


def test_与一致代号动作成对往返一致(tmp_path):
    """加密索引接得上主路径：脱敏侧登记、还原侧取回，逐字节一致。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    pseudonym = PseudonymOperator(key=TEST_KEY, key_id="test-key", mapping_index=store)
    restore = RestoreOperator(index=store)

    token = pseudonym.apply(
        ORIGINAL_NAME,
        OperatorContext(
            label="PATIENT_NAME", entity_id="P-1001", material_id="M-1", occurrence=0
        ),
    )
    assert token.startswith("P-"), "一致代号形状应为 P- + 16 位十六进制"
    redacted = f"患者 {token} 于今日完成胸部 CT。"
    store.save()

    # 换一份索引实例（模拟守护进程重启后重新读索引）
    reopened = _store(path)
    reopened.load()
    restorer = RestoreOperator(index=reopened)
    result = restorer.restore_text(redacted, "M-1")
    assert result.replaced == 1
    assert result.text == f"患者 {ORIGINAL_NAME} 于今日完成胸部 CT。"
    # 还原后落盘的索引依然不含明文
    assert ORIGINAL_NAME.encode("utf-8") not in path.read_bytes()


def test_落盘文件仅本人可读写(tmp_path):
    """索引文件权限收紧到 0600（POSIX 下）。"""
    path = tmp_path / "index.enc"
    store = _store(path)
    store.record_occurrence("M-1", TOKEN, ORIGINAL_NAME)
    store.save()
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"索引文件权限应为 0600，实际 {oct(mode)}"
