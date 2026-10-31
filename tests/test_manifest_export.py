"""命中清单分组导出验收（task 32）。

命中清单是交差产物 —— 同一批命中，伦理办按**批次**看、科研数据管理员按
**材料**看、质控按**实体类别**看。本测试盯住三件事：

1. **条数守恒**：三种视图是同一批命中的三种切法，任一视图逐文件加总都等于
   总条数 —— 不多不少，也不重；
2. **不含原文**：导出文件（三种视图 + 摘要表 + 索引）全文都不得出现任何命中
   原文 —— 静态扫描命中原文片段，关键词断言逐条排除；
3. **摘要可用**：摘要表给出各类别命中数、平均分、确认 / 告警 / 放行档条数，
   且导出入口（CLI 与脚本）都给出可读的条数摘要、失败时返回非 0。
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from research_redact.audit.manifest import (
    ManifestEntry,
    ManifestWriter,
    VIEW_BY_BATCH,
    VIEW_BY_LABEL,
    VIEW_BY_MATERIAL,
    collect_manifests,
    export_manifest_views,
    format_export_summary,
    read_entries,
    scan_for_raw_text,
    summarize_entries,
)
from research_redact.daemon.pipeline import redact_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT_ROOT / "scripts"
FIXTURE = PROJECT_ROOT / "fixtures" / "report_001.txt"

#: 合成样例里的身份串：导出文件里一处都不该出现
IDENTITY_STRINGS = (
    "张某某",
    "李某某",
    "90000001",
    "CHK0000001",
    "1949-12-31",
    "13800138000",
)

#: 命中清单的封闭字段集合：导出视图必须与原清单逐字一致
MANIFEST_FIELDS = {
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

CLI_ENV = {"PYTHONPATH": str(PROJECT_ROOT / "src"), "PATH": "/usr/bin:/bin"}


# ---------------------------------------------------------------------------
# 取数：跑真实主路径，拿到真实命中清单
# ---------------------------------------------------------------------------


def _entries(material_id: str, text: str) -> list[ManifestEntry]:
    """跑一次主路径脱敏，返回该材料的命中条目。"""
    return list(redact_text(text, material_id).entries)


@pytest.fixture()
def manifests() -> dict[str, list[ManifestEntry]]:
    """两个批次、三份材料的命中清单（都来自真实主路径）。"""
    text = FIXTURE.read_text(encoding="utf-8")
    alt = text.replace("张某某", "李某某")
    return {
        "KY20260001": _entries("M-1", text) + _entries("M-2", alt),
        "KY20260002": _entries("M-3", text),
    }


@pytest.fixture()
def exported(manifests, tmp_path):
    """导出一次，返回（导出结果, 导出目录）。"""
    out_dir = tmp_path / "audit-export"
    return export_manifest_views(manifests, out_dir), out_dir


# ---------------------------------------------------------------------------
# 条数守恒
# ---------------------------------------------------------------------------


def test_三种视图条数守恒(exported):
    """三种视图逐文件加总，都等于总条数。"""
    export, _ = exported
    assert export.total == 15
    assert export.view_total(VIEW_BY_BATCH) == export.total
    assert export.view_total(VIEW_BY_MATERIAL) == export.total
    assert export.view_total(VIEW_BY_LABEL) == export.total


def test_三种视图文件行数与索引一致(exported):
    """每个视图文件的实际行数，与导出结果记录的条数一致。"""
    export, _ = exported
    for view, files in export.view_files.items():
        counted = 0
        for path in files:
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            counted += len(lines)
            assert export.view_counts[view][path.stem] == len(lines)
        assert counted == export.total


def test_分组视图按批次按材料按类别切对(exported, manifests):
    """分组视图的切法正确：批次 2 个、材料 3 份、类别按命中分布。"""
    export, _ = exported
    assert set(export.batch_counts) == {"KY20260001", "KY20260002"}
    assert export.batch_counts["KY20260001"] == 10
    assert export.batch_counts["KY20260002"] == 5
    assert set(export.material_counts) == {"M-1", "M-2", "M-3"}
    assert export.material_counts["M-1"] == 5
    assert "PATIENT_NAME" in export.label_counts
    assert export.label_counts["PATIENT_NAME"] == 3


def test_按批次视图文件按批次命名(exported):
    """按批次视图的文件名就是批次号。"""
    export, out_dir = exported
    names = {path.name for path in export.view_files[VIEW_BY_BATCH]}
    assert names == {"KY20260001.jsonl", "KY20260002.jsonl"}
    assert (out_dir / "by-batch" / "KY20260001.jsonl").is_file()


def test_导出行字段集合与原清单一致(exported):
    """导出的视图行与命中清单字段集合完全一致（逐行可比对）。"""
    export, _ = exported
    for files in export.view_files.values():
        for path in files:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    assert set(json.loads(line)) == MANIFEST_FIELDS


# ---------------------------------------------------------------------------
# 不含原文（安全审计红线）
# ---------------------------------------------------------------------------


def test_导出文件全文不含命中原文(exported):
    """三种视图 + 摘要表 + 索引，逐个文件静态扫描命中原文。"""
    export, out_dir = exported
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file():
            continue
        payload = path.read_text(encoding="utf-8-sig")
        assert scan_for_raw_text(payload, IDENTITY_STRINGS) == [], path


def test_导出文件不含命中区间原文(exported, manifests):
    """按命中位置从原文切出真实片段，逐条确认没进导出文件。"""
    export, out_dir = exported
    text = FIXTURE.read_text(encoding="utf-8")
    fragments = set()
    for entries in manifests.values():
        for entry in entries:
            if entry.material_id == "M-2":
                continue
            fragments.add(text[entry.start : entry.end])
    assert fragments  # 确认真的切到了片段
    payload = "\n".join(
        path.read_text(encoding="utf-8-sig")
        for path in sorted(out_dir.rglob("*"))
        if path.is_file()
    )
    assert scan_for_raw_text(payload, fragments) == []


def test_摘要表不含原文且只给统计(exported):
    """摘要表只有条数与分数，没有命中原文，也没有正文片段。"""
    export, out_dir = exported
    payload = (out_dir / "summary.csv").read_text(encoding="utf-8-sig")
    assert scan_for_raw_text(payload, IDENTITY_STRINGS) == []
    rows = list(csv.DictReader(payload.splitlines()))
    assert {row["实体类别"] for row in rows} == set(export.label_counts)
    for row in rows:
        assert row["实体类别"]
        assert row["命中数"].isdigit()
        assert row["平均分"]
        assert row["确认档"].isdigit()
        assert row["告警档"].isdigit()
        assert row["放行档"].isdigit()
        # 摘要表不得出现任何正文片段
        assert "张" not in row["实体类别"]


# ---------------------------------------------------------------------------
# 摘要口径
# ---------------------------------------------------------------------------


def test_摘要表统计口径正确(exported, manifests):
    """摘要表各类别的命中数、平均分与档位分布算得对。"""
    export, _ = exported
    all_entries = [entry for entries in manifests.values() for entry in entries]
    rows = {row.label: row for row in export.summary_rows}
    assert sum(row.hits for row in rows.values()) == len(all_entries)
    for label, row in rows.items():
        group = [entry for entry in all_entries if entry.label == label]
        assert row.hits == len(group)
        assert row.avg_score == pytest.approx(
            sum(entry.score for entry in group) / len(group)
        )
        assert row.confirmed == sum(1 for entry in group if entry.tier == "confirmed")
        assert row.warning == sum(1 for entry in group if entry.tier == "warning")
        assert row.allowed == sum(1 for entry in group if entry.tier == "allowed")
        assert row.materials == len({entry.material_id for entry in group})


def test_摘要覆盖三种档位():
    """摘要能把确认 / 告警 / 放行三档分别数出来。"""
    entries = [
        ManifestEntry("M-1", "PATIENT_NAME", 0, 3, 0.9, "confirmed", "replace", "字段标签命中（姓名）"),
        ManifestEntry("M-1", "VISIT_NO", 10, 18, 0.4, "warning", "none（告警档，未改写）", "邻近上下文加分不足"),
        ManifestEntry("M-2", "VISIT_NO", 4, 12, 0.0, "allowed", "keep（白名单放行）", "命中白名单（exact），放行"),
    ]
    rows = {row.label: row for row in summarize_entries(entries)}
    assert rows["VISIT_NO"].hits == 2
    assert rows["VISIT_NO"].warning == 1
    assert rows["VISIT_NO"].allowed == 1
    assert rows["VISIT_NO"].confirmed == 0
    assert rows["VISIT_NO"].materials == 2
    assert rows["PATIENT_NAME"].confirmed == 1


def test_导出索引可机读(exported):
    """index.json 给出总条数与每个视图的文件清单。"""
    export, out_dir = exported
    payload = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert payload["total"] == export.total
    assert payload["summary_csv"] == "summary.csv"
    for view in (VIEW_BY_BATCH, VIEW_BY_MATERIAL, VIEW_BY_LABEL):
        entries = payload["views"][view]
        assert sum(row["hits"] for row in entries) == export.total
        for row in entries:
            assert (out_dir / row["file"]).is_file()


# ---------------------------------------------------------------------------
# 取数路径：扫产物目录 / 明确指定清单
# ---------------------------------------------------------------------------


def test_扫产物目录按批次归集(tmp_path, manifests):
    """扫 <产物目录>/<批次号>/manifest.jsonl，每批各算一个批次。"""
    outbox = tmp_path / "outbox"
    for batch_no, entries in manifests.items():
        directory = outbox / batch_no
        directory.mkdir(parents=True)
        ManifestWriter(directory / "manifest.jsonl").write(entries)

    collected = collect_manifests(outbox=outbox)
    assert set(collected) == {"KY20260001", "KY20260002"}
    assert sum(len(v) for v in collected.values()) == 15


def test_清单不存在时明确报错(tmp_path):
    """清单文件不存在时报错，不静默导出空清单。"""
    with pytest.raises(FileNotFoundError):
        collect_manifests(manifest_paths=[tmp_path / "缺失.jsonl"])
    with pytest.raises(FileNotFoundError):
        collect_manifests(outbox=tmp_path / "没有这个目录")


def test_空清单不导出(tmp_path, manifests):
    """产物目录里没有清单时不导出（空清单会被误读成「这批没命中」）。"""
    outbox = tmp_path / "empty"
    outbox.mkdir()
    assert collect_manifests(outbox=outbox) == {}


# ---------------------------------------------------------------------------
# CLI 与脚本
# ---------------------------------------------------------------------------


def test_cli_export_audit打印可读摘要(tmp_path, manifests):
    """CLI 导出：退出码 0，终端给出条数摘要。"""
    manifest = tmp_path / "KY20260001" / "manifest.jsonl"
    manifest.parent.mkdir(parents=True)
    ManifestWriter(manifest).write(manifests["KY20260001"])
    out_dir = tmp_path / "导出"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "research_redact.cli",
            "export-audit",
            "--manifest",
            str(manifest),
            "--out",
            str(out_dir),
        ],
        cwd=PROJECT_ROOT,
        env=CLI_ENV,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "导出命中清单：10 条" in completed.stdout
    assert "按批次" in completed.stdout
    assert "按材料" in completed.stdout
    assert "按实体类别" in completed.stdout
    assert "PATIENT_NAME" in completed.stdout
    assert (out_dir / "summary.csv").is_file()
    assert (out_dir / "by-batch" / "KY20260001.jsonl").is_file()


def test_cli_export_audit清单缺失返回非0(tmp_path):
    """清单缺失时返回非 0 并说明原因。"""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "research_redact.cli",
            "export-audit",
            "--manifest",
            str(tmp_path / "缺失.jsonl"),
            "--out",
            str(tmp_path / "导出"),
        ],
        cwd=PROJECT_ROOT,
        env=CLI_ENV,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "不存在" in completed.stderr


def test_cli_export_audit缺参数返回非0():
    """既没给清单也没给产物目录时返回非 0。"""
    completed = subprocess.run(
        [sys.executable, "-m", "research_redact.cli", "export-audit"],
        cwd=PROJECT_ROOT,
        env=CLI_ENV,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "--manifest" in completed.stderr


def test_脚本导出与CLI同口径(tmp_path, manifests):
    """scripts/export_manifest.py 走同一份产品实现，导出结果一致。"""
    outbox = tmp_path / "outbox"
    for batch_no, entries in manifests.items():
        directory = outbox / batch_no
        directory.mkdir(parents=True)
        ManifestWriter(directory / "manifest.jsonl").write(entries)
    out_dir = tmp_path / "导出"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "export_manifest.py"),
            "--outbox",
            str(outbox),
            "--out",
            str(out_dir),
        ],
        cwd=PROJECT_ROOT,
        env=CLI_ENV,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "导出命中清单：15 条" in completed.stdout

    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["total"] == 15
    assert len(index["views"][VIEW_BY_BATCH]) == 2
    assert len(index["views"][VIEW_BY_MATERIAL]) == 3


def test_脚本清单缺失返回非0(tmp_path):
    """脚本在输入缺失时返回非 0，不产出空导出。"""
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "export_manifest.py"),
            "--manifest",
            str(tmp_path / "缺失.jsonl"),
        ],
        cwd=PROJECT_ROOT,
        env=CLI_ENV,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "不存在" in completed.stderr


def test_重复导出不累加(manifests, tmp_path):
    """同一目录重复导出，条数稳定（不追加、不重复）。"""
    out_dir = tmp_path / "导出"
    first = export_manifest_views(manifests, out_dir)
    second = export_manifest_views(manifests, out_dir)
    assert first.total == second.total == 15
    for view, files in second.view_files.items():
        for path in files:
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            assert len(lines) == second.view_counts[view][path.stem]


def test_重复导出清掉上一次的旧分组文件(manifests, tmp_path):
    """批次集合变小后重导出：上一次的分组文件必须被清掉。

    交差时是按目录数文件的 —— 旧文件留在目录里，条数就在目录这一层破了。
    """
    out_dir = tmp_path / "导出"
    export_manifest_views(manifests, out_dir)
    stale = out_dir / "by-batch" / "KY20260009.jsonl"
    stale.write_text('{"material_id": "M-9"}\n', encoding="utf-8")
    assert stale.is_file()

    export_manifest_views({"KY20260001": manifests["KY20260001"]}, out_dir)

    assert not stale.exists()
    # 目录里剩下的文件数 = 本次写出的文件数（不多不少）
    for view, files in export_manifest_views(
        {"KY20260001": manifests["KY20260001"]}, out_dir
    ).view_files.items():
        directory = out_dir / view
        assert sorted(path.name for path in directory.glob("*.jsonl")) == sorted(
            path.name for path in files
        )


def test_导出索引记录清掉了哪些旧文件(manifests, tmp_path):
    """删了什么要留痕：索引里给出被清掉的文件名。"""
    out_dir = tmp_path / "导出"
    export_manifest_views(manifests, out_dir)
    (out_dir / "by-label" / "OLD_LABEL.jsonl").write_text("{}\n", encoding="utf-8")

    export_manifest_views(manifests, out_dir)
    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["removed"][VIEW_BY_LABEL] == ["OLD_LABEL.jsonl"]
    assert index["removed"][VIEW_BY_BATCH] == []


def test_同段跨类两行不合并(tmp_path):
    """同一段被两个类别命中：清单里仍是两行，不合并成一行。

    task 23 留下的口径问题：一段文字上「确认档被改写」与「让位未改写」是两条
    独立命中。合并成一行会把「这段其实没脱」这件事藏掉 —— 交差时看不见。
    """
    entries = [
        ManifestEntry("M-1", "PATIENT_ID", 4, 12, 0.95, "confirmed", "replace", "主索引主键命中"),
        ManifestEntry("M-1", "VISIT_NO", 4, 12, 0.99, "confirmed", "none（冲突裁决：未改写）", "区间完全重合，让位"),
    ]
    export = export_manifest_views({"KY20260001": entries}, tmp_path / "导出")

    # 两行都在：总数 2，按类别各 1 行
    assert export.total == 2
    assert export.label_counts == {"PATIENT_ID": 1, "VISIT_NO": 1}
    assert export.view_total(VIEW_BY_LABEL) == 2
    # 同一段两行都留着（没被合成一行）
    rows = [
        entry
        for entry in read_entries(export.view_files[VIEW_BY_MATERIAL][0])
    ]
    assert len(rows) == 2
    assert {(row.start, row.end) for row in rows} == {(4, 12)}
    # 摘要表按类别各 1 条，「让位未改写」那一条也在统计里
    summary = {row.label: row for row in export.summary_rows}
    assert summary["VISIT_NO"].hits == 1


def test_导出摘要文本可读(exported):
    """摘要文本给出总条数、视图文件数与类别统计。"""
    export, _ = exported
    text = format_export_summary(export)
    assert "导出命中清单：15 条" in text
    assert "按批次：2 个文件" in text
    assert "按材料：3 个文件" in text
    assert "实体类别" in text
    assert "PATIENT_NAME" in text


def test_导出后仍能读回清单(exported):
    """导出的视图文件可以按清单格式读回来（下游工具接得上）。"""
    export, _ = exported
    path = export.view_files[VIEW_BY_LABEL][0]
    entries = read_entries(path)
    assert entries
    assert all(isinstance(entry, ManifestEntry) for entry in entries)
    assert {entry.label for entry in entries} == {path.stem}


# ---------------------------------------------------------------------------
# 材料 ID 体检（ID 夹带标识符 → 提示，不阻断）
# ---------------------------------------------------------------------------


def test_材料ID夹带标识符时点名提示(tmp_path):
    """材料 ID 里夹带检查号时，导出结果点名提示（不静默、不阻断）。"""
    entries = [
        ManifestEntry(
            "KY2026C0001-CHK0000001-01", "EXAM_NO", 100, 110, 0.85, "confirmed", "replace", "命中"
        ),
    ]
    export = export_manifest_views({"KY2026C0001": entries}, tmp_path / "导出")

    assert len(export.material_id_findings) == 1
    finding = export.material_id_findings[0]
    assert finding.material_id == "KY2026C0001-CHK0000001-01"
    assert finding.label == "EXAM_NO"
    assert finding.tier in ("encounter", "identity")

    index = json.loads(
        (tmp_path / "导出" / "index.json").read_text(encoding="utf-8")
    )
    assert index["material_id_findings"] == [
        {
            "material_id": "KY2026C0001-CHK0000001-01",
            "label": "EXAM_NO",
            "tier": finding.tier,
            "score": finding.score,
        }
    ]


def test_普通材料ID不提示(tmp_path):
    """不夹带标识符的材料 ID 不产生提示（别把提示刷满）。"""
    entries = [
        ManifestEntry("M-1", "VISIT_NO", 0, 8, 0.85, "confirmed", "replace", "命中"),
        ManifestEntry("M-2", "VISIT_NO", 0, 8, 0.85, "confirmed", "replace", "命中"),
    ]
    export = export_manifest_views({"KY20260001": entries}, tmp_path / "导出")
    assert export.material_id_findings == ()


def test_材料ID提示不影响导出条数(tmp_path):
    """提示只是提示：条数守恒与导出完整性不受影响。"""
    entries = [
        ManifestEntry(
            "KY2026C0001-CHK0000001-01", "EXAM_NO", 100, 110, 0.85, "confirmed", "replace", "命中"
        ),
        ManifestEntry("M-2", "VISIT_NO", 0, 8, 0.85, "confirmed", "replace", "命中"),
    ]
    export = export_manifest_views({"KY20260001": entries}, tmp_path / "导出")
    assert export.total == 2
    assert export.view_total(VIEW_BY_MATERIAL) == 2
    assert export.view_total(VIEW_BY_LABEL) == 2


def test_摘要文本点出材料ID提示(tmp_path):
    """CLI 摘要里要看得见这条提示（不然等于没体检）。"""
    entries = [
        ManifestEntry(
            "KY2026C0001-CHK0000001-01", "EXAM_NO", 100, 110, 0.85, "confirmed", "replace", "命中"
        ),
    ]
    export = export_manifest_views({"KY20260001": entries}, tmp_path / "导出")
    text = format_export_summary(export)
    assert "材料 ID 夹带标识符" in text
    assert "EXAM_NO" in text

