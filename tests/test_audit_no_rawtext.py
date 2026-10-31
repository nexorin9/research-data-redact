"""命中清单「不记原文」红线守卫。

对应 spec.md 参考地基中「命中清单交差」的验收：清单只记位置 / 类别 / 分数 /
解释 / 处置，**不得出现命中原文**。这是交差产物的底线 —— 清单会随批次一起
交给伦理办与核查方，本身就是一份需要脱敏的材料。
"""

from __future__ import annotations

from research_redact.audit.manifest import ManifestWriter, scan_for_raw_text
from research_redact.daemon.pipeline import redact_text

SECRETS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")

SAMPLE = (
    "姓名：张某某 住院号：90000001 检查号：CHK0000001 "
    "出生日期：1949-12-31 手机号：13800138000 诊断：右肺下叶磨玻璃结节"
)


def test_manifest_payload_has_no_raw_text(tmp_path):
    """清单文件全文不含任何命中原文。"""
    from research_redact.daemon.pipeline import redact_file
    from pathlib import Path

    source = tmp_path / "report.txt"
    source.write_text(SAMPLE, encoding="utf-8")
    manifest = tmp_path / "m.jsonl"
    redact_file(source, tmp_path / "out.txt", manifest)

    payload = manifest.read_text(encoding="utf-8")
    assert scan_for_raw_text(payload, SECRETS) == []
    for secret in SECRETS:
        assert secret not in payload


def test_reasons_never_carry_matched_values():
    """解释只说「怎么命中的」，不说「命中了什么」。"""
    outcome = redact_text(SAMPLE, "M-9")
    assert outcome.entries
    for entry in outcome.entries:
        for secret in SECRETS:
            assert secret not in entry.reason


def test_redacted_copy_carries_no_plain_identity():
    """脱敏副本里身份串已不可见（命中即改写，不留原文）。"""
    outcome = redact_text(SAMPLE, "M-10")
    for secret in SECRETS:
        assert secret not in outcome.redacted_text


def test_manifest_writer_round_trip_keeps_closed_fields(tmp_path):
    """清单落盘后读回，字段集合不变（没有多出来的自由文本位）。"""
    outcome = redact_text(SAMPLE, "M-11")
    path = tmp_path / "m.jsonl"
    ManifestWriter(path).write(outcome.entries)
    records = ManifestWriter.read(path)
    assert len(records) == len(outcome.entries)
    for record in records:
        assert set(record) == {
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
