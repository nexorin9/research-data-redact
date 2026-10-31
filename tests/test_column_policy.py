"""列级批处理验收：申请单 JSON / xlsx 按列策略处理。

对应源产品 ``presidio-analyzer/presidio_analyzer/batch_analyzer_engine.py::
BatchAnalyzerEngine.analyze_dict`` 的 ``keys_to_skip`` 机制（保留）：按**列**
决定要不要识别，而不是整份文档一刀切。

本测试断言四件事：

1. **两种格式归一化成同一份结构** —— JSON 与 xlsx 申请单解析结果逐字段一致；
2. **业务列逐字保留** —— 申请单号 / 伦理批件号 / 材料技术内容列不脱敏
   （脱了这一批就和平台台账对不上账）；
3. **内容列按列脱敏** —— 备注列里的手工粘贴的姓名 / 住院号被替换；
4. **缺件即阻断** —— 缺伦理批件号或材料字段缺失时批次 blocked，并给出
   缺失项清单，不静默放行。
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from research_redact.daemon.pipeline import redact_application, redact_rows
from research_redact.ingest.application import (
    ApplicationParseError,
    ApplicationRow,
    BlockedApplicationError,
    IntakeStatus,
    load_application,
    load_json_application,
    load_xlsx_application,
)
from research_redact.ingest.columns import ColumnPolicy, ColumnRole
from research_redact.policy.table import PolicyTableError, load_policy_table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policy" / "research.yaml"
FIXTURE = PROJECT_ROOT / "fixtures" / "application_001.json"

# 明细表列序（xlsx 表头）—— 与 JSON 申请单逐列对应。
XLSX_HEADER = (
    "application_no",
    "ethics_approval_no",
    "patient_id",
    "material_id",
    "kind",
    "path",
    "material_content",
    "note",
)

# 夹带患者身份的内容列取值（合成样例，与 fixtures/report_001.txt 同一套）。
NOTE_WITH_IDENTITY = "复核记录：姓名：张某某，住院号：90000001"


def _write_xlsx(path: Path, rows: list[tuple[str, ...]]) -> Path:
    """写一份明细表 xlsx（第一行表头）。"""
    import openpyxl

    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "materials"
    sheet.append(list(XLSX_HEADER))
    for row in rows:
        sheet.append(list(row))
    workbook.save(path)
    workbook.close()
    return path


def _xlsx_rows_from_fixture() -> list[tuple[str, ...]]:
    """按明细表列序，从 JSON 样例推出等价的 xlsx 行。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rows: list[tuple[str, ...]] = []
    for material in raw["materials"]:
        rows.append(
            (
                raw["application_no"],
                raw["ethics_approval_no"],
                material["patient_id"],
                material["material_id"],
                material["kind"],
                material["path"],
                material["material_content"],
                material["note"],
            )
        )
    return rows


# ------------------------------------------------------------- 两种格式归一化


def test_json_application_parses_into_rows():
    """JSON 申请单折成「行」：一行 = 一份材料。"""
    intake = load_application(FIXTURE)
    assert intake.status is IntakeStatus.ACCEPTED
    assert intake.application_no == "KY20260001"
    assert intake.ethics_approval_no == "EC-2026-0001"
    assert intake.patient_ids == ("P-1001", "P-1002")
    assert len(intake.rows) == 2
    assert intake.rows[0].material_id == "KY20260001-CHK0000001-01"
    assert intake.rows[0].kind == "report_text"
    assert intake.rows[0].path == "materials/report_001.txt"
    assert intake.rows[0].patient_id == "P-1001"
    assert intake.missing == ()
    assert intake.alerts == ()


def test_xlsx_application_parses_into_the_same_rows(tmp_path):
    """xlsx 明细表折成同一份结构：与 JSON 逐字段一致。"""
    xlsx = _write_xlsx(tmp_path / "application_001.xlsx", _xlsx_rows_from_fixture())
    from_json = load_json_application(FIXTURE)
    from_xlsx = load_xlsx_application(xlsx)

    assert from_xlsx.status is from_json.status
    assert from_xlsx.application_no == from_json.application_no
    assert from_xlsx.ethics_approval_no == from_json.ethics_approval_no
    assert from_xlsx.patient_ids == from_json.patient_ids
    assert from_xlsx.missing == from_json.missing
    assert len(from_xlsx.rows) == len(from_json.rows)
    for xlsx_row, json_row in zip(from_xlsx.rows, from_json.rows):
        assert xlsx_row.material_id == json_row.material_id
        assert xlsx_row.kind == json_row.kind
        assert xlsx_row.path == json_row.path
        assert xlsx_row.patient_id == json_row.patient_id
        assert dict(xlsx_row.columns) == dict(json_row.columns)


def test_load_application_dispatches_by_suffix(tmp_path):
    """按后缀分派：.json 走 JSON、.xlsx 走 xlsx。"""
    xlsx = _write_xlsx(tmp_path / "application_001.xlsx", _xlsx_rows_from_fixture())
    assert load_application(FIXTURE).source_format == "json"
    assert load_application(xlsx).source_format == "xlsx"


# --------------------------------------------------------------- 列策略判定


def test_column_policy_comes_from_policy_file():
    """列角色来自策略表：结构性默认列 + 本院追加的业务列。"""
    table = load_policy_table(POLICY_FILE)
    policy = ColumnPolicy.from_config(table.columns)
    assert policy.classify("application_no") is ColumnRole.BUSINESS
    assert policy.classify("ethics_approval_no") is ColumnRole.BUSINESS
    assert policy.classify("material_id") is ColumnRole.BUSINESS
    assert policy.classify("kind") is ColumnRole.BUSINESS
    assert policy.classify("path") is ColumnRole.BUSINESS
    assert policy.classify("material_content") is ColumnRole.BUSINESS
    assert policy.classify("project_no") is ColumnRole.BUSINESS
    assert policy.classify("patient_id") is ColumnRole.BOUND
    assert policy.classify("note") is ColumnRole.CONTENT


def test_policy_file_rejects_conflicting_column_roles(tmp_path):
    """同一列既是业务列又是内容列 → 装载报错，不静默取其一。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            version: 1
            thresholds:
              global: 0.5
              per_recognizer: {}
            entities:
              PATIENT_NAME:
                action: replace
                placeholder: "<患者姓名>"
            allow_list:
              exact: []
              regex: []
            context:
              terms:
                - 住院号
            columns:
              business_columns:
                - note
              bound_columns: []
              content_columns:
                - note
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyTableError, match="列角色冲突"):
        load_policy_table(policy)


# --------------------------------------------------------------- 列级脱敏


def test_business_columns_are_preserved_verbatim():
    """业务列逐字保留：申请单号 / 伦理批件号 / 材料技术内容列不被改写。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    row = ApplicationRow(
        material_id="M-1",
        kind="report_text",
        path="materials/report_001.txt",
        patient_id="P-1001",
        columns={
            "application_no": "KY20260001",
            "ethics_approval_no": "EC-2026-0001",
            "material_id": "M-1",
            "kind": "report_text",
            "path": "materials/report_001.txt",
            "material_content": "胸部CT平扫，三级甲等住院病例",
            "patient_id": "P-1001",
        },
    )
    result = redact_rows([row], policy)[0]
    assert result.columns["application_no"] == "KY20260001"
    assert result.columns["ethics_approval_no"] == "EC-2026-0001"
    assert result.columns["material_content"] == "胸部CT平扫，三级甲等住院病例"
    assert result.entries == ()
    assert set(result.skipped) >= {
        "application_no",
        "ethics_approval_no",
        "material_id",
        "kind",
        "path",
        "material_content",
        "patient_id",
    }


def test_bound_column_patient_id_is_not_pattern_redacted():
    """绑定列（患者主索引主键）不由通用正则改写。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    row = ApplicationRow(
        material_id="M-1",
        kind="report_text",
        path="materials/report_001.txt",
        patient_id="P-1001",
        columns={"patient_id": "P-1001"},
    )
    result = redact_rows([row], policy)[0]
    assert result.columns["patient_id"] == "P-1001"
    assert result.entries == ()


def test_content_column_is_redacted():
    """内容列按列扫描脱敏：备注里的姓名 / 住院号被替换。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    row = ApplicationRow(
        material_id="M-1",
        kind="report_text",
        path="materials/report_001.txt",
        patient_id="P-1001",
        columns={"note": NOTE_WITH_IDENTITY},
    )
    result = redact_rows([row], policy)[0]
    assert "张某某" not in result.columns["note"]
    assert "90000001" not in result.columns["note"]
    assert "<患者姓名>" in result.columns["note"]
    assert "<住院号>" in result.columns["note"]
    assert result.scanned == ("note",)


def test_same_value_treated_differently_by_column_role():
    """同一个取值，落在业务列就不脱、落在内容列就脱 —— 判定只看列名。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    rows = [
        ApplicationRow(
            material_id="M-1",
            kind="report_text",
            path="materials/report_001.txt",
            columns={"material_content": NOTE_WITH_IDENTITY},
        ),
        ApplicationRow(
            material_id="M-2",
            kind="report_text",
            path="materials/report_002.txt",
            columns={"note": NOTE_WITH_IDENTITY},
        ),
    ]
    business_result, content_result = redact_rows(rows, policy)
    assert business_result.columns["material_content"] == NOTE_WITH_IDENTITY
    assert business_result.entries == ()
    assert "张某某" not in content_result.columns["note"]
    assert content_result.entries


def test_manifest_entries_point_at_the_column():
    """命中清单定位到「材料 # 列」：同一材料的不同列不会互相混淆。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    row = ApplicationRow(
        material_id="M-1",
        kind="report_text",
        path="materials/report_001.txt",
        columns={"note": NOTE_WITH_IDENTITY},
    )
    result = redact_rows([row], policy)[0]
    assert result.entries
    assert all(entry.material_id.startswith("M-1#") for entry in result.entries)
    assert {entry.material_id for entry in result.entries} == {"M-1#note"}


def test_application_level_redaction_covers_the_whole_batch():
    """整批列级脱敏：逐行产物 + 逐处清单，两行都处理到。"""
    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    intake = load_application(FIXTURE)
    result = redact_application(intake, policy)
    assert len(result.rows) == 2
    assert result.application_no == "KY20260001"
    for row in result.rows:
        assert row.columns["application_no"] == "KY20260001"
        assert "张某某" not in row.columns["note"]
        assert "李某某" not in row.columns["note"]
    assert result.counts["confirmed"] >= 4
    assert "application_no" in result.skipped_columns
    assert "note" not in result.skipped_columns


# --------------------------------------------------------------- 阻断分支


def test_missing_ethics_approval_blocks_the_batch(tmp_path):
    """缺伦理批件号 → 批次 blocked，并给出缺失项清单与告警。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw.pop("ethics_approval_no")
    target = tmp_path / "application_no_ethics.json"
    target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")

    intake = load_application(target)
    assert intake.status is IntakeStatus.BLOCKED
    assert intake.is_blocked
    assert "ethics_approval_no" in intake.missing
    assert any("伦理批件号" in alert for alert in intake.alerts)
    assert "ethics_approval_no" in intake.missing_summary


def test_blocked_application_is_not_redacted(tmp_path):
    """被阻断的申请单不得进入脱敏 —— 报错中止，不降级放行。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw.pop("ethics_approval_no")
    target = tmp_path / "application_no_ethics.json"
    target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")

    policy = ColumnPolicy.from_config(load_policy_table(POLICY_FILE).columns)
    with pytest.raises(BlockedApplicationError, match="ethics_approval_no"):
        redact_application(load_application(target), policy)


def test_missing_material_fields_block_and_list_missing_items(tmp_path):
    """材料缺 material_id / kind / path → 阻断，并逐项列出缺哪一格。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["materials"][0].pop("material_id")
    raw["materials"][0].pop("path")
    target = tmp_path / "application_missing.json"
    target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")

    intake = load_application(target)
    assert intake.status is IntakeStatus.BLOCKED
    assert "materials[0].material_id" in intake.missing
    assert "materials[0].path" in intake.missing
    assert any("缺材料 ID" in alert for alert in intake.alerts)
    assert any("缺材料路径" in alert for alert in intake.alerts)


def test_unsupported_material_kind_blocks(tmp_path):
    """材料类型不在取值域内 → 阻断并说明支持哪些类型。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["materials"][0]["kind"] = "video"
    target = tmp_path / "application_bad_kind.json"
    target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")

    intake = load_application(target)
    assert intake.status is IntakeStatus.BLOCKED
    assert "materials[0].kind" in intake.missing
    assert any("材料类型不支持" in alert for alert in intake.alerts)


def test_missing_patient_ids_blocks(tmp_path):
    """缺患者主索引主键清单 → 阻断（不得按姓名硬匹配）。"""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw.pop("patient_ids")
    target = tmp_path / "application_no_patients.json"
    target.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")

    intake = load_application(target)
    assert intake.status is IntakeStatus.BLOCKED
    assert "patient_ids" in intake.missing


def test_xlsx_missing_ethics_approval_blocks(tmp_path):
    """xlsx 明细表缺伦理批件号 → 同样阻断。"""
    rows = _xlsx_rows_from_fixture()
    trimmed = [(row[0], "") + row[2:] for row in rows]
    xlsx = _write_xlsx(tmp_path / "application_no_ethics.xlsx", trimmed)

    intake = load_application(xlsx)
    assert intake.status is IntakeStatus.BLOCKED
    assert "ethics_approval_no" in intake.missing


def test_xlsx_with_two_application_numbers_blocks(tmp_path):
    """一张工作簿里出现两个申请单号 → 阻断，不猜。"""
    rows = _xlsx_rows_from_fixture()
    rows.append(("KY20260002", *rows[1][1:]))
    xlsx = _write_xlsx(tmp_path / "application_two_numbers.xlsx", rows)

    intake = load_application(xlsx)
    assert intake.status is IntakeStatus.BLOCKED
    assert any("多个申请单号" in item for item in intake.missing)


# --------------------------------------------------------------- 解析异常


def test_unsupported_format_raises(tmp_path):
    """格式不认识 → 明确报错，不静默跳过。"""
    target = tmp_path / "application.csv"
    target.write_text("application_no\nKY20260001\n", encoding="utf-8")
    with pytest.raises(ApplicationParseError, match="不支持的申请单格式"):
        load_application(target)


def test_broken_json_raises_parse_error(tmp_path):
    """JSON 损坏 → 解析错误（与「字段缺失」分开）。"""
    target = tmp_path / "application_broken.json"
    target.write_text("{ application_no: ", encoding="utf-8")
    with pytest.raises(ApplicationParseError, match="JSON 解析失败"):
        load_application(target)


def test_missing_file_raises_file_not_found(tmp_path):
    """文件不存在 → FileNotFoundError。"""
    with pytest.raises(FileNotFoundError):
        load_application(tmp_path / "nope.json")
