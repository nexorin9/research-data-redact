"""端到端主路径验收：一份材料 → 脱敏副本 + 逐处命中清单。

主路径只有一条（``daemon/pipeline.py``），CLI 与守护进程都调它。本测试
直接对着 ``fixtures/report_001.txt`` 跑，断言三件事：

1. **身份串被脱敏**：姓名 / 住院号 / 检查号 / 出生日期 / 手机号 都不在副本里；
2. **临床内容不误伤**：病名、药名、剂量、金额、页码、床号原样保留；
3. **清单可交差**：条数与类别正确、对照 ``fixtures/manifest_expected.jsonl``、
   且**不含任何命中原文**。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from research_redact.audit.manifest import ManifestWriter, scan_for_raw_text
from research_redact.daemon.pipeline import build_default_registry, redact_text
from research_redact.recognizers.base import PatternRecognizer
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "fixtures" / "report_001.txt"
EXPECTED = PROJECT_ROOT / "fixtures" / "manifest_expected.jsonl"

# 合成样例里的身份串与临床对照串
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")
CLINICAL_STRINGS = (
    "右肺下叶磨玻璃结节",
    "2 型糖尿病",
    "盐酸氨溴索口服液",
    "布洛芬缓释胶囊",
    "30mL",
    "0.3g",
    "128.50",
    "2450.00",
    "第 2 页",
    "12床",
)

# 对照用的稳定字段：识别器与分数会随后续任务的识别器演进而变化，
# 位置 / 类别 / 档位才是这份样例的稳定契约。
STABLE_KEYS = ("material_id", "label", "start", "end", "tier")


@pytest.fixture()
def redacted(tmp_path):
    """跑一次脱敏，返回（脱敏正文, 清单条目列表）。"""
    from research_redact.daemon.pipeline import redact_file

    output = tmp_path / "report_001.redacted.txt"
    manifest = tmp_path / "manifest.jsonl"
    outcome = redact_file(FIXTURE, output, manifest)
    return outcome.redacted_text, list(outcome.entries), output, manifest


# ----------------------------------------------------------------- CLI 主路径


def test_cli_redact_writes_copy_and_manifest(tmp_path):
    """CLI 入口跑通：产出脱敏副本与 JSONL 命中清单，退出码 0。"""
    output = tmp_path / "cli-redacted.txt"
    manifest = tmp_path / "cli-manifest.jsonl"
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
        ],
        cwd=PROJECT_ROOT,
        env={"PYTHONPATH": str(PROJECT_ROOT / "src"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert output.is_file() and manifest.is_file()
    assert "命中清单" in completed.stdout
    lines = [line for line in manifest.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 5
    assert json.loads(lines[0])["label"] == "PATIENT_NAME"


def test_cli_reports_missing_input_with_nonzero_exit(tmp_path):
    """材料不存在时返回非 0 并说明原因，不静默产出空副本。"""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "research_redact.cli",
            "redact",
            "--in",
            str(tmp_path / "缺失.txt"),
            "--out",
            str(tmp_path / "out.txt"),
            "--manifest",
            str(tmp_path / "m.jsonl"),
        ],
        cwd=PROJECT_ROOT,
        env={"PYTHONPATH": str(PROJECT_ROOT / "src"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "不存在" in completed.stderr


# ------------------------------------------------------------------- 脱敏效果


def test_identity_strings_are_removed(redacted):
    """身份串被替换或清空，副本里一处都不剩。"""
    text = redacted[0]
    for secret in IDENTITY_STRINGS:
        assert secret not in text
    assert "<患者姓名>" in text
    assert "<住院号>" in text
    assert "<检查号>" in text


def test_clinical_content_is_untouched(redacted):
    """病名、药名、剂量、金额、页码、床号都不被误伤。"""
    text = redacted[0]
    for kept in CLINICAL_STRINGS:
        assert kept in text


def test_each_hit_is_rewritten_only_once(redacted):
    """同一段只被改写一次：不出现重复占位符。"""
    text = redacted[0]
    assert text.count("<患者姓名>") == 1
    assert text.count("<住院号>") == 1
    assert text.count("<检查号>") == 1


# ------------------------------------------------------------------- 命中清单


def test_manifest_matches_expected_fixture(redacted):
    """清单与 fixtures/manifest_expected.jsonl 逐条对照（稳定字段）。"""
    entries = redacted[1]
    expected = [
        json.loads(line)
        for line in EXPECTED.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) == len(expected)
    for actual, reference in zip(entries, expected):
        for key in STABLE_KEYS:
            assert actual.to_dict()[key] == reference[key], (key, actual, reference)


def test_manifest_labels_and_tiers(redacted):
    """命中类别与档位正确：5 处身份类，全部确认档。"""
    entries = redacted[1]
    assert [entry.label for entry in entries] == [
        "PATIENT_NAME",
        "VISIT_NO",
        "EXAM_NO",
        "BIRTH_DATE",
        "PHONE",
    ]
    assert {entry.tier for entry in entries} == {"confirmed"}
    assert all(entry.material_id == "report_001" for entry in entries)
    assert all(entry.action in ("replace", "redact") for entry in entries)


def test_manifest_contains_no_raw_text(redacted):
    """清单不含任何命中原文。"""
    manifest_text = redacted[3].read_text(encoding="utf-8")
    assert scan_for_raw_text(manifest_text, IDENTITY_STRINGS) == []
    for secret in IDENTITY_STRINGS:
        assert secret not in manifest_text


# --------------------------------------------------------------- 边界与降级


def test_warning_span_is_recorded_but_not_rewritten():
    """低于阈值的命中降为告警档：进清单但不改文本。"""
    registry = RecognizerRegistry(
        [PatternRecognizer("weak", "弱信号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.2)],
        RegistryConfig(global_threshold=0.5),
    )
    outcome = redact_text("住院号 12345678", "M-1", registry=registry)
    assert outcome.redacted_text == "住院号 12345678"
    assert len(outcome.entries) == 1
    assert outcome.entries[0].tier == "warning"
    assert outcome.entries[0].action == "none（告警档，未改写）"
    assert outcome.rewritten == 0


def test_nested_hits_are_rewritten_once():
    """嵌套命中只改写一次：同一段不出现两个占位符。"""
    registry = RecognizerRegistry(
        [
            PatternRecognizer("outer", "外层识别器", {"EXAM_NO": r"\d{8}"}, base_score=0.9),
            PatternRecognizer("inner", "内层识别器", {"VISIT_NO": r"\d{6}"}, base_score=0.8),
        ],
        RegistryConfig(global_threshold=0.5),
    )
    outcome = redact_text("住院号 12345678", "M-2", registry=registry)
    assert outcome.redacted_text.count("<检查号>") == 1
    assert outcome.rewritten == 1
    actions = [entry.action for entry in outcome.entries]
    assert "none（冲突裁决：未改写）" in actions


def test_fixture_with_nested_hit_replaces_segment_once():
    """task 3 端到端样例上补一条嵌套命中：住院号那一段只出一个占位符。

    外层命中覆盖整段住院号，内层命中落在住院号内部 —— 两段互相嵌套。
    裁决后由优先级更高的一方负责改写，被让位的一方记进清单。
    """
    registry = build_default_registry()
    registry.register(
        PatternRecognizer("outer", "外层住院号识别器", {"VISIT_NO": r"90000001"}, base_score=0.95)
    )
    registry.register(
        PatternRecognizer("inner", "内层检查号识别器", {"EXAM_NO": r"9000"}, base_score=0.9)
    )
    text = FIXTURE.read_text(encoding="utf-8")
    outcome = redact_text(text, "report_001", registry=registry)

    # 住院号那一段只出一个占位符（真正的检查号那处照常出一个）
    assert outcome.redacted_text.count("<住院号>") == 1
    assert outcome.redacted_text.count("<检查号>") == 1
    assert "90000001" not in outcome.redacted_text
    assert "9000" not in outcome.redacted_text

    # 被让位的一方在清单里可见，并写明原因
    dropped = [e for e in outcome.entries if e.action == "none（冲突裁决：未改写）"]
    assert [e.label for e in dropped] == ["EXAM_NO"]
    assert "包含" in dropped[0].reason


def test_manifest_writer_serializes_closed_field_set(tmp_path):
    """清单的字段集合是封闭的：结构上就没有承载原文的位置。"""
    from research_redact.models import EntitySpan, SpanTier

    span = EntitySpan(
        start=0,
        end=3,
        label="PATIENT_NAME",
        score=0.9,
        reason="字段标签命中（姓名）",
        tier=SpanTier.CONFIRMED,
        recognizer="labeled_field",
    )
    path = tmp_path / "m.jsonl"
    ManifestWriter(path).write([])
    from research_redact.audit.manifest import entry_from_span

    ManifestWriter(path).write([entry_from_span("M-3", span, "replace")])
    payload = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert set(payload) == {
        "material_id",
        "label",
        "start",
        "end",
        "score",
        "tier",
        "action",
        "reason",
        "recognizer",
        "merged_duplicates",
    }


def test_default_registry_is_usable():
    """默认装配可用：产出实体区间列表（主路径的识别段）。"""
    registry = build_default_registry()
    spans = registry.analyze("姓名：张某某 住院号：90000001")
    assert [span.label for span in spans] == ["PATIENT_NAME", "VISIT_NO"]
