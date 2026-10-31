"""策略表版本快照与批次可复现（task 36）。

对应 task 36 的三条验收：

1. **策略变更后版本号变化** —— 版本号认的是「生效配置」，配置一改（哪怕只改
   一个阈值）版本号必变；同一份配置永远算出同一个版本号。
2. **快照重放结果与原批次逐条一致** —— 策略表改过之后，拿这一批留下的快照
   重放，产出的脱敏副本与逐处命中清单与原批次**逐条一致**。
3. **快照不含密钥** —— 快照里出现凭据（键名像凭据、取值等于当前进程里配好的
   凭据、长得像令牌 / 私钥）一律**拒绝落盘**。

另外覆盖：版本号随批次写进台账与命中清单头；快照落在
``var/snapshots/<批次>/``；没有快照的批次**不得**用当前策略表重放。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from research_redact.audit.alerts import JsonlAlertSink
from research_redact.audit.ledger import BatchLedger
from research_redact.audit.manifest import (
    MANIFEST_HEADER_KEY,
    ManifestWriter,
)
from research_redact.audit.residual import ResidualChecker
from research_redact.daemon.pipeline import redact_batch
from research_redact.daemon.replay import compare_entries, replay_batch
from research_redact.daemon.runner import BatchRunner
from research_redact.policy.snapshot import (
    CredentialLeakError,
    SnapshotError,
    assert_no_credentials,
    capture_snapshot,
    effective_policy_document,
    load_snapshot,
    policy_version,
    snapshot_policy_path,
)
from research_redact.policy.table import load_policy_table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policy" / "research.yaml"

# 合成的放射报告样例（自造数据，与任何真实患者无关）
MATERIAL_TEXT = """市第一人民医院  放射科检查报告
姓名：张某某      性别：男      年龄：64岁
住院号：90000001   科别：呼吸内科
检查号：CHK0000001  床位：12床
出生日期：1949-12-31  手机号：13800138000
检查所见：
  右肺下叶见磨玻璃结节，大小约 8mm，边界尚清晰。
诊断意见：
  1、2 型糖尿病
建议：
  1、餐后服用盐酸氨溴索口服液 30mL 每日 3 次
（本页为第 2 页）
报告日期：2026-01-05    报告医师：示例医师
"""

IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")


# --------------------------------------------------------------------- 工具


def _write_inbox(root: Path, *, application_no: str = "KY20260001") -> Path:
    """在 ``root`` 下造一份可处理的交付目录。"""
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": application_no,
        "ethics_approval_no": "EC-2026-0001",
        "patient_ids": ["P-1001"],
        "materials": [
            {
                "material_id": "M-1",
                "kind": "report_text",
                "path": "materials/report_001.txt",
                "patient_id": "P-1001",
            }
        ],
    }
    (application_dir / "application.json").write_text(
        json.dumps(application, ensure_ascii=False), encoding="utf-8"
    )
    (application_dir / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT, encoding="utf-8"
    )
    return inbox


def _copy_policy(
    target: Path,
    *,
    global_threshold: float | None = None,
    entity_action: dict[str, str] | None = None,
) -> Path:
    """复制一份策略表（可改阈值 / 改某个类别的处置动作），返回副本路径。

    改的是**另一个路径** —— 策略表按「路径 + 修改时间 + 档位」缓存，同一个
    文件改内容容易吃到旧缓存。
    """
    raw = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    if global_threshold is not None:
        raw.setdefault("thresholds", {})["global"] = global_threshold
    for label, action in (entity_action or {}).items():
        raw.setdefault("entities", {}).setdefault(label, {})["action"] = action
    target.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return target


def _runner(tmp_path: Path, inbox: Path) -> tuple[BatchRunner, BatchLedger]:
    """装配处理器与台账（产物、告警、快照都落在临时目录里）。"""
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    checker = ResidualChecker(sink=JsonlAlertSink(tmp_path / "alerts.jsonl"))
    runner = BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        checker=checker,
    )
    return runner, ledger


def _process(runner: BatchRunner, inbox: Path, application_no: str = "KY20260001"):
    """跑一个批次，返回处理结果（走交付目录监听器的取批入口）。"""
    from research_redact.daemon.watcher import InboxWatcher

    applications = InboxWatcher(inbox).applications()
    target = next(
        item for item in applications if item.application_no == application_no
    )
    return runner.process(target, via_event=True)


# --------------------------------------------------------------------- 版本号


def test_策略变更后版本号变化(tmp_path: Path, monkeypatch) -> None:
    """同一份配置版本号不变；改一个阈值，版本号必变。"""
    policy_a = _copy_policy(tmp_path / "policy_a.yaml")
    policy_b = _copy_policy(tmp_path / "policy_b.yaml", global_threshold=0.95)

    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(policy_a))
    version_a = policy_version(effective_policy_document(load_policy_table()))
    version_a_again = policy_version(effective_policy_document(load_policy_table()))
    assert version_a == version_a_again
    assert version_a.startswith("pol-")

    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(policy_b))
    version_b = policy_version(effective_policy_document(load_policy_table()))
    assert version_b != version_a


def test_版本号认生效配置而非文件字节(tmp_path: Path, monkeypatch) -> None:
    """只改注释不改行为 → 版本号不变（行为没变，就不该让人重新复核）。"""
    policy_a = _copy_policy(tmp_path / "policy_a.yaml")
    commented = tmp_path / "policy_commented.yaml"
    commented.write_text(
        "# 这是一行新加的注释，不改任何配置\n"
        + policy_a.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(policy_a))
    first = policy_version(effective_policy_document(load_policy_table()))
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(commented))
    second = policy_version(effective_policy_document(load_policy_table()))
    assert first == second


# --------------------------------------------------------------------- 快照


def test_快照落在批次目录且摘要齐备(tmp_path: Path, monkeypatch) -> None:
    """每批一份快照：配置副本 + 摘要（阈值 / 白名单摘要 / 上下文词表）。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    table = load_policy_table()
    snapshot = capture_snapshot("KY20260001", table, tmp_path / "snapshots")

    assert snapshot.policy_path.is_file()
    assert snapshot.meta_path.is_file()
    assert snapshot.directory.name == "KY20260001"

    summary = snapshot.summary
    assert summary["global_threshold"] == table.global_threshold
    assert summary["per_recognizer_thresholds"] == dict(
        table.per_recognizer_thresholds
    )
    assert summary["allow_list"]["exact_count"] == len(table.allow_list_exact)
    assert summary["allow_list"]["regex_count"] == len(table.allow_list_regex)
    assert summary["context_terms"] == list(table.context_terms)

    # 摘要文件与配置副本都能读回来
    meta = json.loads(snapshot.meta_path.read_text(encoding="utf-8"))
    assert meta["policy_version"] == snapshot.policy_version
    assert meta["batch_no"] == "KY20260001"
    assert meta["policy_sha256"] == snapshot.policy_sha256


def test_快照配置副本可独立装载且版本号不变(tmp_path: Path, monkeypatch) -> None:
    """快照里的 ``policy.yaml`` 本身就是一份合法策略表：装出来版本号不变。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    table = load_policy_table()
    snapshot = capture_snapshot("KY20260001", table, tmp_path / "snapshots")

    # 显式选「默认档」：快照里装的就是已经合并好的生效配置，再选一次档位等于选错
    reloaded = load_policy_table(snapshot.policy_path, profile="")
    assert policy_version(effective_policy_document(reloaded)) == snapshot.policy_version
    assert reloaded.global_threshold == table.global_threshold
    assert reloaded.allow_list_exact == table.allow_list_exact
    assert reloaded.context_terms == table.context_terms


def test_快照不含任何密钥或凭据(tmp_path: Path, monkeypatch) -> None:
    """凭据进快照 → 拒绝落盘（不落半份、直接报错）。"""
    monkeypatch.setenv("PSEUDONYM_HMAC_KEY", "super-secret-hmac-value")
    monkeypatch.setenv("HIS_API_TOKEN", "his-token-value-1234")

    table = load_policy_table()
    snapshot = capture_snapshot("KY20260001", table, tmp_path / "snapshots")

    # 落盘的快照里没有当前进程里配好的任何凭据取值
    for path in sorted(snapshot.directory.iterdir()):
        payload = path.read_text(encoding="utf-8")
        assert "super-secret-hmac-value" not in payload
        assert "his-token-value-1234" not in payload

    # 把凭据写进策略表 → 拒绝落盘
    raw = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    raw["entities"]["PATIENT_NAME"]["placeholder"] = "super-secret-hmac-value"
    leaked = tmp_path / "leaked.yaml"
    leaked.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(leaked))
    with pytest.raises(CredentialLeakError):
        capture_snapshot("KY20260002", load_policy_table(), tmp_path / "snapshots")

    # 敏感键名同样被拦下
    raw = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    raw["entities"]["PATIENT_NAME"]["api_token"] = "x"
    keyed = tmp_path / "keyed.yaml"
    keyed.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    with pytest.raises(CredentialLeakError):
        assert_no_credentials({"entities": {"PATIENT_NAME": {"api_token": "x"}}})


def test_快照不含患者原文(tmp_path: Path, monkeypatch) -> None:
    """快照只装配置，不装患者数据。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    snapshot = capture_snapshot("KY20260001", load_policy_table(), tmp_path / "snapshots")
    for path in sorted(snapshot.directory.iterdir()):
        payload = path.read_text(encoding="utf-8")
        for secret in IDENTITY_STRINGS:
            assert secret not in payload


# ----------------------------------------------------------------- 台账与清单头


def test_版本号写进台账与命中清单头(tmp_path: Path, monkeypatch) -> None:
    """批次跑完：台账里有版本号，命中清单第一行是清单头。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    inbox = _write_inbox(tmp_path)
    runner, ledger = _runner(tmp_path, inbox)

    result = _process(runner, inbox)
    assert result.processed is True

    record = ledger.get_batch("KY20260001")
    assert record.policy_version.startswith("pol-")

    snapshot_record = ledger.policy_snapshot("KY20260001")
    assert snapshot_record is not None
    assert snapshot_record.policy_version == record.policy_version
    assert Path(snapshot_record.policy_path).is_file()

    # 清单头：第一行是抬头，记着这一批用哪一版策略脱的
    manifest_path = Path(result.artifacts["manifest"])
    header = ManifestWriter.read_header(manifest_path)
    assert header["batch_no"] == "KY20260001"
    assert header["policy_version"] == record.policy_version
    assert header["entry_count"] == result.entries

    raw_first = json.loads(
        manifest_path.read_text(encoding="utf-8").splitlines()[0]
    )
    assert MANIFEST_HEADER_KEY in raw_first

    # 清单头的读法不变：读出来还是那几处命中，不多不少
    assert len(ManifestWriter.read(manifest_path)) == result.entries


# --------------------------------------------------------------------- 重放


def test_策略改掉之后按快照重放产出与原批次逐条一致(
    tmp_path: Path, monkeypatch
) -> None:
    """核心场景：策略表改过之后，这一批仍然能按**当时那一版**重放出来。"""
    policy_a = _copy_policy(tmp_path / "policy_a.yaml")
    # 改一处处置动作：科室要求手机号在科研材料里保留（「redact」→「keep」）
    policy_b = _copy_policy(
        tmp_path / "policy_b.yaml", entity_action={"PHONE": "keep"}
    )

    # ---- 第一轮：按 policy_a 脱 ----
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(policy_a))
    inbox = _write_inbox(tmp_path)
    runner, ledger = _runner(tmp_path, inbox)
    first = _process(runner, inbox)
    assert first.processed is True

    original_entries = ManifestWriter.read(first.artifacts["manifest"])
    original_redacted = Path(first.artifacts["M-1"]).read_text(encoding="utf-8")
    original_version = ledger.get_batch("KY20260001").policy_version

    # ---- 策略表改了：PHONE 的处置动作从「整段清空」改成「保留」 ----
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(policy_b))
    checker = ResidualChecker(sink=JsonlAlertSink(tmp_path / "alerts2.jsonl"))
    changed = redact_batch("KY20260001", {"M-1": MATERIAL_TEXT}, checker=checker)
    changed_entries = [entry for item in changed.outcomes for entry in item.entries]

    # 改策略确实改出了不同的结果（否则下面「重放一致」证明不了什么）
    assert compare_entries(original_entries, changed_entries) != []
    assert changed.redacted_texts["M-1"] != original_redacted

    # ---- 按快照重放：用的是**当时那一版**，产出与原批次逐条一致 ----
    replay = replay_batch(
        "KY20260001", {"M-1": MATERIAL_TEXT}, ledger=ledger
    )
    assert replay.policy_version == original_version
    assert compare_entries(original_entries, replay.entries) == []
    assert replay.redacted_texts["M-1"] == original_redacted


def test_没有快照的批次不得用当前策略表重放(tmp_path: Path, monkeypatch) -> None:
    """快照缺失 → 明确报错，**不退回当前策略表**（那证明的是另一件事）。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    with pytest.raises(SnapshotError):
        replay_batch("KY20269999", {"M-1": MATERIAL_TEXT}, snapshot_dir=str(tmp_path))


def test_重放缺材料时报错不留半份(tmp_path: Path, monkeypatch) -> None:
    """快照在、材料不在 → 报错说清是哪种缺，不静默产出空结果。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    inbox = _write_inbox(tmp_path)
    runner, ledger = _runner(tmp_path, inbox)
    first = _process(runner, inbox)
    assert first.processed is True

    # 换一份材料正文 → 重放出来的内容与原批次不同（材料变了就不是同一批）
    replay = replay_batch(
        "KY20260001", {"M-1": MATERIAL_TEXT.replace("示例医师", "示例医师乙")}, ledger=ledger
    )
    assert replay.redacted_texts["M-1"] != Path(first.artifacts["M-1"]).read_text(
        encoding="utf-8"
    )


def test_快照缺失时台账里查得到(tmp_path: Path, monkeypatch) -> None:
    """快照登记在台账里查得到（事后「这批是哪一版」有答案）。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    inbox = _write_inbox(tmp_path)
    runner, ledger = _runner(tmp_path, inbox)
    _process(runner, inbox)

    records = ledger.policy_snapshots()
    assert len(records) == 1
    assert records[0].batch_no == "KY20260001"
    assert records[0].policy_version.startswith("pol-")
    assert Path(records[0].policy_path).is_file()
    assert records[0].snapshot_dir.endswith("KY20260001")


def test_快照目录可由环境变量指定(tmp_path: Path, monkeypatch) -> None:
    """部署时想把快照放到别处（独立磁盘 / 加密卷）就用环境变量。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    monkeypatch.setenv("RESEARCH_SNAPSHOT_DIR", str(tmp_path / "snap"))
    snapshot = capture_snapshot("KY20260001", load_policy_table())
    assert snapshot.directory == tmp_path / "snap" / "KY20260001"
    assert snapshot.policy_path.is_file()
    assert snapshot_policy_path("KY20260001") == snapshot.policy_path


def test_读回快照元信息一致(tmp_path: Path, monkeypatch) -> None:
    """写出去的快照读回来内容一致（版本号 / 摘要 / 路径）。"""
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(_copy_policy(tmp_path / "p.yaml")))
    snapshot = capture_snapshot("KY20260001", load_policy_table(), tmp_path / "snap")
    loaded = load_snapshot("KY20260001", tmp_path / "snap")
    assert loaded.policy_version == snapshot.policy_version
    assert loaded.policy_sha256 == snapshot.policy_sha256
    assert loaded.summary["global_threshold"] == snapshot.summary["global_threshold"]
    assert loaded.policy_path == snapshot.policy_path
