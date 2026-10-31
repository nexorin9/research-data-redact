"""残留自检验收：对脱敏输出二次扫描身份类残留。

残留自检是本轮的差异化关键一环 —— 源产品没有这一步：识别一遍、改写一遍就
交出去，从不回头看「改写后的产物里是不是还留着身份」。医院场景不能这样：
一份残留着患者姓名的科研材料一旦交到平台，伦理批件范围就被打破了。

本测试盯四件事：

1. **干净脱敏副本残留为 0**（主路径真跑一遍，不是构造出来的）；
2. **身份类残留计数正确**（姓名 / 住院号 / 检查号 / 身份证 / 手机号 / 出生日期）；
3. **通用数字与日期不计入**（剂量、金额、页码、床号、报告日期长得像编号，
   但不是患者身份 —— 计进去只会把真正的漏脱淹没）；
4. **残留非 0 时该批次不得投递**，并按批次聚合成**一条**告警落进台账。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from research_redact.audit.alerts import (
    JsonlAlertSink,
    RecordingAlertSink,
    RecordingNotifier,
)
from research_redact.audit.residual import (
    ResidualChecker,
    ResidualReport,
    residual_tier,
    scan_residual,
)
from research_redact.daemon.pipeline import (
    ensure_deliverable,
    redact_batch,
    redact_text,
)
from research_redact.daemon.state_machine import BatchState

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "fixtures" / "report_001.txt"
POLICY = PROJECT_ROOT / "policy" / "research.yaml"

#: 合成样例里的身份串：任何一条都不该出现在告警与自检结论里
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")

#: 通用数字与日期：长得像编号，但不是患者身份，不得计入残留
GENERIC_NUMBERS = (
    "30mL",
    "0.3g",
    "128.50",
    "2450.00",
    "第 2 页",
    "12床",
    "2026-01-05",
)

#: 一份「漏脱了」的脱敏副本：姓名 / 住院号 / 手机号都还在
LEAKY_TEXT = "姓名：张某某  住院号：90000001  手机号：13800138000"


def _write_policy(tmp_path: Path, mutate) -> Path:
    """复制策略表并按需改一处，返回临时策略表路径。

    策略表是本项目的配置真源，改行为就该改 YAML 而不是改代码 —— 测试同理。
    """
    raw = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    mutate(raw)
    target = tmp_path / "research.yaml"
    target.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return target


def _use_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutate) -> Path:
    """把临时策略表挂到环境变量上（三个装载器都读它）。"""
    target = _write_policy(tmp_path, mutate)
    monkeypatch.setenv("RESEARCH_POLICY_FILE", str(target))
    return target


# ------------------------------------------------------------------ 干净副本


def test_clean_redacted_copy_has_zero_residual():
    """主路径真跑一遍：干净脱敏副本的残留计数必须是 0。"""
    text = FIXTURE.read_text(encoding="utf-8")
    outcome = redact_text(text, "report_001")

    report = ResidualChecker().check_batch("KY20260001", {"report_001": outcome.redacted_text})

    assert report.identity_count == 0
    assert report.deliverable is True
    assert report.findings == ()
    assert "残留 0 处" in report.summary


def test_redacted_copy_has_no_identity_string_left():
    """脱敏副本里不该再有身份串 —— 残留自检的前提是产物本身已脱过。"""
    outcome = redact_text(FIXTURE.read_text(encoding="utf-8"), "report_001")
    for secret in IDENTITY_STRINGS:
        assert secret not in outcome.redacted_text


# ------------------------------------------------------------------ 计数正确


def test_identity_residual_count_and_labels():
    """身份类残留计数正确：姓名 / 住院号 / 手机号各一处。"""
    findings = ResidualChecker().scan(LEAKY_TEXT, "M-1")

    assert len(findings) == 3
    assert sorted(finding.label for finding in findings) == [
        "PATIENT_NAME",
        "PHONE",
        "VISIT_NO",
    ]
    assert {finding.material_id for finding in findings} == {"M-1"}
    # 位置可核对：命中区间落在脱敏副本里的对应位置
    by_label = {finding.label: finding for finding in findings}
    assert LEAKY_TEXT[by_label["PATIENT_NAME"].start : by_label["PATIENT_NAME"].end] == "张某某"
    assert LEAKY_TEXT[by_label["VISIT_NO"].start : by_label["VISIT_NO"].end] == "90000001"
    assert LEAKY_TEXT[by_label["PHONE"].start : by_label["PHONE"].end] == "13800138000"


def test_generic_numbers_and_dates_are_not_counted():
    """通用数字与日期不计入残留：剂量、金额、页码、床号、报告日期都不算。"""
    text = (
        "本次检查费用合计 128.50 元，住院总费用 2450.00 元；"
        "盐酸氨溴索口服液 30mL 每日 3 次，布洛芬缓释胶囊 0.3g；"
        "床位：12床；本页为第 2 页；报告日期：2026-01-05"
    )

    findings = ResidualChecker().scan(text, "M-2")

    assert findings == ()


def test_generic_tier_is_not_identity():
    """策略表里划为通用数字类的类别不计入残留。"""
    assert residual_tier("DEVICE_ID") == "generic"
    assert residual_tier("PATIENT_NAME") == "identity"
    assert residual_tier("VISIT_NO") == "encounter"


def test_unclassified_label_counts_as_identity():
    """档位未登记的类别按身份类处理：宁可多拦，不放过。"""
    assert residual_tier("SOME_NEW_ENTITY") == "unclassified"


# ------------------------------------------------------------------ 拦投放行


def test_batch_with_residual_is_not_deliverable():
    """残留非 0 时该批次不得进入 delivered。"""
    checker = ResidualChecker(sink=RecordingAlertSink())
    report = checker.check_batch("KY20260001", {"M-1": LEAKY_TEXT})

    assert report.identity_count == 3
    assert report.deliverable is False
    assert report.affected_materials == ("M-1",)
    assert report.labels == ("PATIENT_NAME", "PHONE", "VISIT_NO")
    assert "残留自检未通过" in report.summary


def test_residual_records_alert_in_ledger():
    """残留非 0 时落一条批次告警（台账有记录）。"""
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink)
    checker.check_batch("KY20260001", {"M-1": LEAKY_TEXT})

    assert len(sink.alerts) == 1
    alert = sink.alerts[0]
    assert alert.batch_no == "KY20260001"
    assert alert.code == "residual_identity"
    assert alert.level == "warning"
    assert alert.count == 3
    assert alert.material_ids == ("M-1",)
    # 通道未配置时明确记「没推出去」，不假装推过
    assert alert.notified is False
    assert alert.notify_channel == "pending"


def test_alert_is_pushed_once_per_batch():
    """按批次聚合：一批里多处残留只推一条，不是逐处推送。"""
    notifier = RecordingNotifier()
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink, notifier=notifier)
    checker.check_batch(
        "KY20260001",
        {"M-1": LEAKY_TEXT, "M-2": "姓名：李某某  住院号：90000002"},
    )

    assert len(notifier.messages) == 1
    assert len(sink.alerts) == 1
    assert sink.alerts[0].count == 5
    assert sink.alerts[0].notified is True
    assert sink.alerts[0].notify_channel == "recording"
    assert "不得投递" in sink.alerts[0].message


def test_clean_batch_records_no_alert():
    """干净批次不落告警、不推送。"""
    notifier = RecordingNotifier()
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink, notifier=notifier)
    outcome = redact_text(FIXTURE.read_text(encoding="utf-8"), "report_001")

    report = checker.check_batch("KY20260001", {"report_001": outcome.redacted_text})

    assert report.deliverable is True
    assert sink.alerts == []
    assert notifier.messages == []


def test_alert_and_report_contain_no_raw_text():
    """告警与自检结论都不含命中原文（与命中清单同一红线）。"""
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink)
    report = checker.check_batch("KY20260001", {"M-1": LEAKY_TEXT})

    payload = report.summary + json.dumps(sink.alerts[0].to_dict(), ensure_ascii=False)
    payload += json.dumps(
        [finding.to_dict() for finding in report.findings], ensure_ascii=False
    )
    for secret in IDENTITY_STRINGS:
        assert secret not in payload


def test_jsonl_alert_ledger_roundtrip(tmp_path):
    """批次告警台账（JSONL）能落盘并读回。"""
    ledger = tmp_path / "alerts.jsonl"
    sink = JsonlAlertSink(ledger)
    checker = ResidualChecker(sink=sink)
    checker.check_batch("KY20260001", {"M-1": LEAKY_TEXT})

    records = JsonlAlertSink.read(ledger)
    assert len(records) == 1
    assert records[0]["batch_no"] == "KY20260001"
    assert records[0]["count"] == 3
    assert "张某某" not in json.dumps(records, ensure_ascii=False)


# ------------------------------------------------------------------ 端到端主路径


def test_redact_batch_blocks_delivery_and_records_alert(tmp_path, monkeypatch):
    """主路径整条走通：策略表让姓名保留 → 残留非 0 → 批次被拦下并留告警。

    这一条验的是「策略表配错 → 残留自检兜住 → 批次不进 delivered」这条链，
    而不是人工构造一段带身份的文本。
    """
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: (
            raw["entities"]["PATIENT_NAME"].pop("placeholder"),
            raw["entities"]["PATIENT_NAME"].update({"action": "keep"}),
        ),
    )
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink)

    batch = redact_batch(
        "KY20260001",
        {"M-1": LEAKY_TEXT},
        checker=checker,
    )

    assert batch.deliverable is False
    assert batch.residual is not None
    assert batch.residual.identity_count >= 1
    assert len(sink.alerts) == 1
    with pytest.raises(Exception) as excinfo:
        ensure_deliverable(batch)
    assert "不得进入 delivered" in str(excinfo.value)


def test_redact_batch_deliverable_when_clean(tmp_path, monkeypatch):
    """干净批次走完主路径后可投递（闸门放行）。"""
    _use_policy(monkeypatch, tmp_path, lambda raw: None)
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink)

    batch = redact_batch(
        "KY20260001",
        {"M-1": FIXTURE.read_text(encoding="utf-8")},
        checker=checker,
    )

    assert batch.deliverable is True
    assert sink.alerts == []
    ensure_deliverable(batch)  # 不抛异常即放行


def test_placeholder_is_not_counted_as_residual(tmp_path, monkeypatch):
    """占位符本身不是残留：二次扫描命中占位符按「已脱」处理。

    占位符写成中文姓名时最危险 —— 长得和真身份一模一样。这类占位符必须靠
    策略表声明来识别，而不是靠长相。
    """
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["entities"]["PATIENT_NAME"].update(
            {"placeholder": "李某某"}
        ),
    )
    outcome = redact_text(LEAKY_TEXT, "M-1")
    assert "李某某" in outcome.redacted_text

    # 不认占位符时，这一处会被当成残留；认占位符后不是
    raw_findings = scan_residual(
        outcome.redacted_text,
        "M-1",
        ResidualChecker().registry,
        placeholders=(),
    )
    assert [finding.label for finding in raw_findings] == ["PATIENT_NAME"]

    findings = ResidualChecker().scan(outcome.redacted_text, "M-1")
    assert findings == ()


# ------------------------------------------------------------------ 运维通道


def test_cli_verify_residual_passes_on_clean_material(tmp_path):
    """CLI 通道：干净材料残留自检通过，退出码 0。"""
    output = tmp_path / "out.txt"
    manifest = tmp_path / "m.jsonl"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "research_redact.cli",
            "redact",
            "--in",
            str(FIXTURE),
            "--out",
            str(output),
            "--manifest",
            str(manifest),
            "--verify-residual",
        ],
        cwd=PROJECT_ROOT,
        env={
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "PATH": "/usr/bin:/bin",
            "RESEARCH_ALERT_LEDGER": str(tmp_path / "alerts.jsonl"),
        },
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "残留自检" in completed.stdout
    assert "残留 0 处" in completed.stdout


def test_cli_verify_residual_fails_on_leaky_material(tmp_path):
    """CLI 通道：残留非 0 时退出码非 0，并落一条批次告警。

    用一份「姓名按 keep 处理」的策略表制造漏脱 —— 残留自检要抓的是
    **首次脱敏没脱干净**的情况，而不是拿一份本来就干净的材料凑数。
    """
    policy = _write_policy(
        tmp_path,
        lambda raw: (
            raw["entities"]["PATIENT_NAME"].pop("placeholder"),
            raw["entities"]["PATIENT_NAME"].update({"action": "keep"}),
        ),
    )
    leaky = tmp_path / "leaky.txt"
    leaky.write_text(LEAKY_TEXT, encoding="utf-8")
    output = tmp_path / "out.txt"
    manifest = tmp_path / "m.jsonl"
    ledger = tmp_path / "alerts.jsonl"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "research_redact.cli",
            "redact",
            "--in",
            str(leaky),
            "--out",
            str(output),
            "--manifest",
            str(manifest),
            "--verify-residual",
        ],
        cwd=PROJECT_ROOT,
        env={
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "PATH": "/usr/bin:/bin",
            "RESEARCH_POLICY_FILE": str(policy),
            "RESEARCH_ALERT_LEDGER": str(ledger),
        },
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 4, completed.stdout + completed.stderr
    assert "不得投递" in completed.stderr
    records = JsonlAlertSink.read(ledger)
    assert len(records) == 1
    assert records[0]["count"] == 1
    assert records[0]["material_ids"] == ["leaky"]


def test_report_is_a_frozen_dataclass():
    """自检结论是不可变值对象：调用方改不动它。"""
    report = ResidualReport(batch_no="KY20260001")
    assert report.deliverable is True
    assert report.identity_count == 0
    with pytest.raises(Exception):
        report.batch_no = "其他批次"  # type: ignore[misc]


# ------------------------------------------------------------------ 分级
#
# task 28 的三条：身份类残留阻断投递并告警；通用数字类残留只提示不阻断；
# 误报（白名单放行区间、非身份类上下文的通用数字）不计入阻断条件。
#
# 分级口径写在策略表 ``residual`` 段，档位归属写在 ``conflicts.priority`` ——
# **改 YAML 即改分级**，不必改代码。


def test_identity_residual_is_blocking_and_raises_alert():
    """身份类残留：阻断级 —— 拦住这批 + 落告警。"""
    scan = ResidualChecker().scan_detailed(LEAKY_TEXT, "M-1")

    assert [f.label for f in scan.findings] == ["PATIENT_NAME", "VISIT_NO", "PHONE"]
    assert all(f.severity == "blocking" for f in scan.findings)
    assert scan.hints == ()


def test_generic_tier_residual_is_hint_only(tmp_path, monkeypatch):
    """通用数字类残留只提示、不阻断：分级口径由策略表驱动。"""
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["conflicts"]["priority"].update({"BIRTH_DATE": "generic"}),
    )
    sink = RecordingAlertSink()
    notifier = RecordingNotifier()
    checker = ResidualChecker(sink=sink, notifier=notifier)

    report = checker.check_batch("KY20260001", {"M-1": "出生日期：1949-12-31"})

    assert report.identity_count == 0
    assert report.hint_count == 1
    assert report.deliverable is True
    assert [finding.label for finding in report.hints] == ["BIRTH_DATE"]
    assert report.hints[0].severity == "hint"
    # 提示既不落告警也不推群：告警流只放「需要人处理的事」
    assert sink.alerts == []
    assert notifier.messages == []
    assert "通用数字类提示 1 处" in report.summary
    assert "不阻断投递" in report.summary


def test_same_residual_blocks_by_default_policy(tmp_path, monkeypatch):
    """同一段内容：默认口径下出生日期属身份类 → 阻断（对照组）。"""
    _use_policy(monkeypatch, tmp_path, lambda raw: None)
    checker = ResidualChecker(sink=RecordingAlertSink())

    report = checker.check_batch("KY20260001", {"M-1": "出生日期：1949-12-31"})

    assert report.identity_count == 1
    assert report.hint_count == 0
    assert report.deliverable is False


def test_unclassified_category_is_treated_as_identity():
    """策略表没登记档位的类别：默认按身份类处理（宁可多拦，不放过）。"""
    from research_redact.policy.residual_policy import (
        ResidualConfig,
        UNCLASSIFIED_TIER,
    )

    config = ResidualConfig()
    assert config.severity_of(UNCLASSIFIED_TIER) == "blocking"
    # 院区口径改成「只提示」也能改（改 YAML 即改口径）
    lenient = ResidualConfig(unclassified_is_blocking=False)
    assert lenient.severity_of(UNCLASSIFIED_TIER) == "hint"


def test_residual_config_rejects_invalid_policy():
    """分级口径写错即报错，不静默取默认值。"""
    from research_redact.policy.residual_policy import (
        ResidualConfig,
        ResidualConfigError,
    )

    with pytest.raises(ResidualConfigError) as excinfo:
        ResidualConfig.from_policy({"blocking_tiers": ["identity", "身份类"]}, "p.yaml")
    assert "未知档位" in str(excinfo.value)

    with pytest.raises(ResidualConfigError) as excinfo:
        ResidualConfig.from_policy({"hint_tiers": ["identity"]}, "p.yaml")
    assert "同时被分派" in str(excinfo.value)

    with pytest.raises(ResidualConfigError) as excinfo:
        ResidualConfig.from_policy({"blocking_tier": ["identity"]}, "p.yaml")
    assert "未知道具键" in str(excinfo.value)


# ------------------------------------------------------------------ 误报抑制


def test_allow_listed_region_is_suppressed_at_residual_level(tmp_path, monkeypatch):
    """白名单放行区间不计入阻断条件（残留自检自己认一遍白名单）。"""
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["allow_list"]["exact"].append("90000001"),
    )
    checker = ResidualChecker(sink=RecordingAlertSink())

    report = checker.check_batch("KY20260001", {"M-1": "住院号：90000001"})

    assert report.identity_count == 0
    assert report.deliverable is True
    # 抑制要留痕：扫到几处、抑制几处、因为什么抑制
    assert report.suppressed.get("allow_list") == 1
    assert "已脱产物抑制 allow_list 1 处" in report.summary


def test_residual_layer_suppresses_even_without_registry_allow_list(tmp_path, monkeypatch):
    """二次扫描自己认白名单：识别层没放行，残留层照样不拦。"""
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["allow_list"]["exact"].append("未登记"),
    )
    registry = ResidualChecker().registry
    from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

    stripped = RecognizerRegistry(
        registry.get_recognizers(),
        RegistryConfig(global_threshold=registry.config.global_threshold),
    )
    checker = ResidualChecker(registry=stripped, sink=RecordingAlertSink())

    report = checker.check_batch("KY20260001", {"M-1": "姓名：未登记"})

    assert report.identity_count == 0
    assert report.deliverable is True
    assert report.suppressed.get("allow_list") == 1


def test_placeholder_and_pseudonym_are_suppressed_with_reason(tmp_path, monkeypatch):
    """占位符与一致代号是脱敏产物本身：抑制并留痕，不算漏脱。

    这两处最危险 —— 占位符写成中文姓名、一致代号写在「姓名：」后面，长得
    和真身份一模一样。二次扫描必须认得出「这是我们自己写出去的」。
    """
    # 占位符写成中文姓名：长得和真身份一模一样
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["entities"]["PATIENT_NAME"].update({"placeholder": "李某某"}),
    )
    checker = ResidualChecker(sink=RecordingAlertSink())
    outcome = redact_text(LEAKY_TEXT, "M-1")
    assert "李某某" in outcome.redacted_text

    scan = checker.scan_detailed(outcome.redacted_text, "M-1")

    assert scan.findings == ()
    assert scan.suppressed.get("placeholder") == 1

    # 一致代号：形状固定（P- + 16 位十六进制），认得出是产物而不是身份
    import re

    from research_redact.audit.residual import scan_residual_detailed

    pseudo_scan = scan_residual_detailed(
        "住院号：P-0daaf6ec23046198",
        "M-1",
        checker.registry,
        pseudonym=re.compile(r"P-[0-9a-f]{16}"),
    )
    assert pseudo_scan.findings == ()
    assert pseudo_scan.suppressed.get("pseudonym") == 1


# ------------------------------------------------------------------ 批次聚合


def test_alert_is_aggregated_per_batch_with_hint_count(tmp_path, monkeypatch):
    """按批次聚合：一批里 2 处身份类 + 1 处提示 → 只推一条，且带上提示数。"""
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: raw["conflicts"]["priority"].update({"BIRTH_DATE": "generic"}),
    )
    notifier = RecordingNotifier()
    sink = RecordingAlertSink()
    checker = ResidualChecker(sink=sink, notifier=notifier)

    checker.check_batch(
        "KY20260001",
        {"M-1": "姓名：张某某  出生日期：1949-12-31", "M-2": "住院号：90000001"},
    )

    assert len(notifier.messages) == 1
    assert len(sink.alerts) == 1
    assert sink.alerts[0].count == 2
    message = sink.alerts[0].message
    assert "身份类残留 2 处" in message
    assert "通用数字类提示 1 处" in message
    assert "不得投递" in message


def test_batch_summary_is_written_to_ledger(tmp_path):
    """批次摘要写台账：扫了什么、结论是什么，事后查得到。"""
    from research_redact.audit.ledger import BatchLedger

    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    checker = ResidualChecker(sink=RecordingAlertSink(), summary_sink=ledger)

    checker.check_batch("KY20260001", {"M-1": LEAKY_TEXT})

    rows = ledger.residual_summaries("KY20260001")
    assert len(rows) == 1
    row = rows[0]
    assert row.identity_count == 3
    assert row.hint_count == 0
    assert row.deliverable is False
    assert row.scanned_materials == ("M-1",)
    assert "残留自检未通过" in row.summary
    # 摘要不含命中原文
    for secret in IDENTITY_STRINGS:
        assert secret not in row.summary


def test_clean_batch_also_writes_summary(tmp_path):
    """通过的批次也要留摘要：事后要回答「这批当时脱干净了没有」。"""
    from research_redact.audit.ledger import BatchLedger

    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    checker = ResidualChecker(sink=RecordingAlertSink(), summary_sink=ledger)
    outcome = redact_text(FIXTURE.read_text(encoding="utf-8"), "report_001")

    checker.check_batch("KY20260001", {"report_001": outcome.redacted_text})

    rows = ledger.residual_summaries("KY20260001")
    assert len(rows) == 1
    assert rows[0].deliverable is True
    assert rows[0].identity_count == 0
    assert "残留自检通过" in rows[0].summary


# ------------------------------------------------------------ 告警态与推送


def _write_inbox(root: Path, text: str) -> Path:
    """造一份可处理的交付目录（材料正文由调用方给）。"""
    inbox = root / "inbox"
    application_dir = inbox / "KY20260001"
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": "KY20260001",
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
    (application_dir / "materials" / "report_001.txt").write_text(text, encoding="utf-8")
    return inbox


def test_residual_failure_marks_batch_alert_state_and_pushes_once(
    tmp_path, monkeypatch
):
    """残留非 0：批次不进 delivered + 置告警态 + 推一次企微。"""
    from research_redact.audit.ledger import BatchLedger
    from research_redact.daemon.runner import BatchRunner
    from research_redact.daemon.watcher import InboxWatcher

    monkeypatch.setenv("RESEARCH_ALERT_LEDGER", str(tmp_path / "alerts.jsonl"))
    # 策略表让姓名保留 —— 制造「脱敏没脱干净」，逼残留自检兜住
    _use_policy(
        monkeypatch,
        tmp_path,
        lambda raw: (
            raw["entities"]["PATIENT_NAME"].pop("placeholder"),
            raw["entities"]["PATIENT_NAME"].update({"action": "keep"}),
        ),
    )

    inbox = _write_inbox(tmp_path, LEAKY_TEXT)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    notifier = RecordingNotifier()
    runner = BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        notifier=notifier,
    )
    events = InboxWatcher(inbox).poll()
    assert len(events) == 1

    result = runner.process(events[0], via_event=True)

    # 1) 不进 delivered
    assert result.deliverable is False
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.batch_state is not BatchState.DELIVERED

    # 2) 置告警态：批次行上看得见「卡在残留自检、卡了几处」
    assert "残留自检未通过" in record.failure_reason
    assert record.current_step == "residual_check"

    # 3) 推一次（按批次聚合，不逐处推）
    assert len(notifier.messages) == 1
    assert "身份类残留" in notifier.messages[0][1]

    # 4) 批次摘要落台账
    summaries = ledger.residual_summaries("KY20260001")
    assert len(summaries) == 1
    assert summaries[0].deliverable is False


def test_clean_batch_enters_no_alert_state(tmp_path, monkeypatch):
    """干净批次：没有失败原因、没有告警推送（对照组）。"""
    from research_redact.audit.ledger import BatchLedger
    from research_redact.daemon.runner import BatchRunner
    from research_redact.daemon.watcher import InboxWatcher

    monkeypatch.setenv("RESEARCH_ALERT_LEDGER", str(tmp_path / "alerts.jsonl"))
    _use_policy(monkeypatch, tmp_path, lambda raw: None)

    inbox = _write_inbox(tmp_path, FIXTURE.read_text(encoding="utf-8"))
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    notifier = RecordingNotifier()
    runner = BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        notifier=notifier,
    )
    events = InboxWatcher(inbox).poll()

    result = runner.process(events[0], via_event=True)

    assert result.deliverable is True
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.failure_reason == ""
    assert notifier.messages == []
