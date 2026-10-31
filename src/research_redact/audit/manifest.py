"""逐处命中清单（交差产物）：一行一条命中，**不记命中原文**。

清单是伦理办与科研数据管理员抽检的唯一凭据，也是残留自检（task 9 / 28）与
导出视图（task 32）的上游。每条命中只记：

    材料 ID / 实体类别 / 起止位置 / 分数 / 档位 / 处置动作 / 解释 / 识别器

**红线**：命中原文（被脱敏的那段值）一律不落盘。清单按结构化字段逐项拼装，
不把原文拼进 ``reason`` —— 解释只说「命中方式」，不说「命中了什么」。

本模块对应源产品 CLI 的多格式输出思路（``presidio_cli/cli.py::Format.standard``
的人类可读摘要 与 ``Format.parsable`` 的逐条结构化输出），改写为
**批次级 JSONL 清单**：一行一条，交差与机读都靠它。
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..models import DroppedSpan, EntitySpan

__all__ = [
    "INDEX_JSON_NAME",
    "LabelSummary",
    "MANIFEST_HEADER_KEY",
    "ManifestEntry",
    "ManifestExport",
    "ManifestWriter",
    "MaterialIdFinding",
    "SUMMARY_COLUMNS",
    "SUMMARY_CSV_NAME",
    "VIEW_BY_BATCH",
    "VIEW_BY_LABEL",
    "VIEW_BY_MATERIAL",
    "VIEW_DIRECTORIES",
    "audit_material_ids",
    "build_manifest_header",
    "entry_from_dropped",
    "entry_from_span",
    "collect_manifests",
    "export_manifest_views",
    "format_export_summary",
    "read_entries",
    "scan_for_raw_text",
    "summarize_entries",
]

#: 清单头在清单文件里的标记键。清单头是**批次级**的抬头（这一批用哪一版
#: 策略脱的），不是命中条目 —— 读清单的人按这个键把它跳过去。
MANIFEST_HEADER_KEY = "_manifest_header"


def build_manifest_header(
    *,
    batch_no: str,
    policy_version: str = "",
    policy_sha256: str = "",
    profile: str = "",
    entry_count: int = 0,
    captured_at: str = "",
) -> dict[str, Any]:
    """组装清单头（批次号 + 策略版本号 + 条数）。

    清单头只装**批次与配置的标识**，不装患者数据 —— 它的用途是让交差的人
    事后能对上「这批是哪一版策略脱的」，不是承载正文。
    """
    return {
        "batch_no": batch_no,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "profile": profile,
        "entry_count": int(entry_count),
        "captured_at": captured_at,
    }


@dataclass(frozen=True)
class ManifestEntry:
    """命中清单的一行。

    字段集合是**封闭**的：不提供任何承载原文的位置，``to_dict`` 只逐项拼装
    下列字段，结构上就不可能把原文写进清单。
    """

    material_id: str
    label: str
    start: int
    end: int
    score: float
    tier: str
    action: str
    reason: str
    recognizer: str = ""
    merged_duplicates: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """转成清单的一行（JSON 对象的字段集合）。"""
        return {
            "material_id": self.material_id,
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "score": round(float(self.score), 4),
            "tier": self.tier,
            "action": self.action,
            "reason": self.reason,
            "recognizer": self.recognizer,
            "merged_duplicates": list(self.merged_duplicates),
        }


def entry_from_span(material_id: str, span: EntitySpan, action: str) -> ManifestEntry:
    """由实体区间生成一条清单记录。

    :param action: 这一处实际被怎么处理（replace / redact / keep / none…），
        直接写进清单，供人工抽检时对照产物。
    """
    return ManifestEntry(
        material_id=material_id,
        label=span.label,
        start=span.start,
        end=span.end,
        score=span.score,
        tier=span.tier.value,
        action=action,
        reason=span.reason,
        recognizer=span.recognizer,
        merged_duplicates=tuple(span.merged_duplicates),
    )


#: 冲突裁决中被丢弃 / 被裁剪的区间在清单里的动作标记。
DROPPED_ACTION = "none（冲突裁决：未改写）"


def entry_from_dropped(material_id: str, dropped: DroppedSpan) -> ManifestEntry:
    """由被丢弃 / 被裁剪的区间生成一条清单记录。

    冲突裁决让掉的那一段也要进清单：伦理办抽检时得看得见「这一段为什么
    没脱」，否则清单里少一行就分不清是「没命中」还是「命中了但让位了」。
    记录只含位置与原因，**不含命中原文**。
    """
    return ManifestEntry(
        material_id=material_id,
        label=dropped.label,
        start=dropped.start,
        end=dropped.end,
        score=dropped.score,
        tier=dropped.tier,
        action=DROPPED_ACTION,
        reason=dropped.reason,
        recognizer=dropped.recognizer,
        merged_duplicates=(),
    )


class ManifestWriter:
    """逐处命中清单落盘（JSONL：一行一条命中）。

    **清单头**：批次级清单的第一行可以写一条**清单头**（``_manifest_header``），
    记下这一批是用哪一版策略脱的（task 36）。清单头**不是命中条目** ——
    :meth:`read` 会跳过它，所以「清单条数」的读法不变（读出来几条就是几处
    命中）；单文件临时脱敏（CLI 的 ``redact``）不写清单头 —— 那不是批次，
    没有批次号与策略版本可写。
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(
        self,
        entries: Sequence[ManifestEntry],
        header: Mapping[str, Any] | None = None,
    ) -> int:
        """写入清单，返回写入条数（**不含清单头**）。

        :param entries: 命中条目。
        :param header: 清单头（写到文件第一行）；缺省不写。
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            if header:
                handle.write(
                    json.dumps(
                        {MANIFEST_HEADER_KEY: dict(header)}, ensure_ascii=False
                    )
                    + "\n"
                )
            for entry in entries:
                handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return len(entries)

    @staticmethod
    def read(path: str | Path) -> list[dict[str, object]]:
        """读回清单（每行一个 JSON 对象；**清单头被跳过**）。"""
        entries: list[dict[str, object]] = []
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if isinstance(row, dict) and MANIFEST_HEADER_KEY in row:
                    continue
                entries.append(row)
        return entries

    @staticmethod
    def read_header(path: str | Path) -> dict[str, Any]:
        """读回清单头（没有清单头时返回空字典）。"""
        target = Path(path)
        if not target.is_file():
            return {}
        with target.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if isinstance(row, dict) and MANIFEST_HEADER_KEY in row:
                    payload = row[MANIFEST_HEADER_KEY]
                    return dict(payload) if isinstance(payload, Mapping) else {}
                # 第一行不是清单头 = 这份清单没有头
                return {}
        return {}


def scan_for_raw_text(payload: str, secrets: Iterable[str]) -> list[str]:
    """扫描载荷（清单 / 导出文件）里是否混进了命中原文。

    :param payload: 待扫描的文本内容。
    :param secrets: 已知原文片段（通常取自命中区间）。
    :return: 泄漏的原文片段列表；为空表示未泄漏。
    """
    leaked: list[str] = []
    for secret in secrets:
        if secret and secret in payload:
            leaked.append(secret)
    return leaked


# --------------------------------------------------------------- 分组视图导出

#: 分组视图的三个维度。命中清单是交差产物 —— 同一批命中，伦理办按**批次**看、
#: 科研数据管理员按**材料**看、质控按**实体类别**看，三种视角都得数得清。
VIEW_BY_BATCH = "by-batch"
VIEW_BY_MATERIAL = "by-material"
VIEW_BY_LABEL = "by-label"

#: 视图 → 导出子目录名。
VIEW_DIRECTORIES = {
    VIEW_BY_BATCH: "by-batch",
    VIEW_BY_MATERIAL: "by-material",
    VIEW_BY_LABEL: "by-label",
}

#: 摘要 CSV 文件名（表格化摘要，给伦理办直接看的）。
SUMMARY_CSV_NAME = "summary.csv"

#: 导出索引文件名（机器可读：哪个文件、哪个分组、多少条）。
INDEX_JSON_NAME = "index.json"

#: 摘要 CSV 的列（顺序固定，交差时逐列核对）。
SUMMARY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("label", "实体类别"),
    ("hits", "命中数"),
    ("avg_score", "平均分"),
    ("confirmed", "确认档"),
    ("warning", "告警档"),
    ("allowed", "放行档"),
    ("materials", "涉及材料数"),
)


@dataclass(frozen=True)
class LabelSummary:
    """一个实体类别的汇总行（摘要表的一行）。

    :param label: 实体类别。
    :param hits: 该类别命中总条数。
    :param avg_score: 该类别命中的平均分。
    :param confirmed: 确认档条数。
    :param warning: 告警档条数。
    :param allowed: 放行档条数。
    :param materials: 涉及的材料数。
    """

    label: str
    hits: int
    avg_score: float
    confirmed: int
    warning: int
    allowed: int
    materials: int

    def to_row(self) -> dict[str, object]:
        """转成摘要表的一行（键与 :data:`SUMMARY_COLUMNS` 对齐）。"""
        return {
            "label": self.label,
            "hits": self.hits,
            "avg_score": round(float(self.avg_score), 4),
            "confirmed": self.confirmed,
            "warning": self.warning,
            "allowed": self.allowed,
            "materials": self.materials,
        }


@dataclass(frozen=True)
class MaterialIdFinding:
    """一处「材料 ID 自带标识符」的发现（**提示**，不阻断）。

    :param material_id: 材料 ID。
    :param label: 在材料 ID 里被识别出的实体类别。
    :param tier: 该类别的档位（``identity`` / ``encounter`` / ``generic``）。
    :param score: 识别分数。
    """

    material_id: str
    label: str
    tier: str
    score: float

    def to_dict(self) -> dict[str, object]:
        """转成可落盘 / 可展示的一行。"""
        return {
            "material_id": self.material_id,
            "label": self.label,
            "tier": self.tier,
            "score": round(float(self.score), 4),
        }


def audit_material_ids(
    entries: Sequence[ManifestEntry],
    registry: Any | None = None,
) -> tuple[MaterialIdFinding, ...]:
    """体检材料 ID 本身有没有夹带标识符（**提示**，不阻断导出）。

    **为什么要有这一步**：命中清单不记原文，但**材料 ID 是申请单给的** ——
    而现实里材料 ID 常常就是「检查号 + 后缀」（``KY2026C0001-CHK0000001-01``）。
    这么一来，交差用的导出文件里就会**间接带着一个刚被脱掉的编号**。

    这不是脱敏环节的漏洞（材料 ID 是入站单据上的标识，平台侧还要靠它对账，
    换成别的值就对不上了），但它必须**看得见**：交差的人得知道这批材料 ID
    里内嵌了检查号，由谁来跟平台确认口径。

    因此这里只**点名**（材料 ID + 类别 + 档位），不静默改写材料 ID，也不
    阻断导出 —— 决定权在人。

    :param entries: 命中条目（只取其中的材料 ID）。
    :param registry: 识别器注册表；缺省按策略表装配默认装配。
    :return: 发现列表（按材料 ID、类别排序）。
    """
    from ..recognizers.assembly import build_default_registry
    from .residual import residual_tier

    active = registry if registry is not None else build_default_registry()
    material_ids = sorted({entry.material_id for entry in entries if entry.material_id})
    findings: list[MaterialIdFinding] = []
    for material_id in material_ids:
        for span in active.analyze(material_id):
            tier = residual_tier(span.label)
            if tier not in ("identity", "encounter", "unclassified"):
                # 通用数字类（剂量、金额、页码…）在材料 ID 里不构成身份暴露
                continue
            findings.append(
                MaterialIdFinding(
                    material_id=material_id,
                    label=span.label,
                    tier=tier,
                    score=span.score,
                )
            )
    findings.sort(key=lambda item: (item.material_id, item.label))
    return tuple(findings)


@dataclass(frozen=True)
class ManifestExport:
    """一次分组导出的结果。

    :param out_dir: 导出目录。
    :param total: 导出的命中总条数（三种视图各自加总都等于它）。
    :param summary_csv: 摘要表路径。
    :param index_json: 导出索引路径。
    :param summary_rows: 摘要表的一行行（按命中数降序）。
    :param view_files: 视图 → 导出的文件路径列表。
    :param batch_counts: 批次号 → 命中条数。
    :param material_counts: 材料 ID → 命中条数。
    :param label_counts: 实体类别 → 命中条数。
    :param tier_counts: 档位 → 命中条数。
    :param view_counts: 视图 → 分组键 → 命中条数（条数守恒校验用）。
    """

    out_dir: Path
    total: int
    summary_csv: Path
    index_json: Path
    summary_rows: tuple[LabelSummary, ...] = ()
    view_files: Mapping[str, tuple[Path, ...]] = field(default_factory=dict)
    batch_counts: Mapping[str, int] = field(default_factory=dict)
    material_counts: Mapping[str, int] = field(default_factory=dict)
    label_counts: Mapping[str, int] = field(default_factory=dict)
    tier_counts: Mapping[str, int] = field(default_factory=dict)
    view_counts: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    material_id_findings: tuple[MaterialIdFinding, ...] = ()

    def view_total(self, view: str) -> int:
        """某个视图的条数合计（用于条数守恒校验）。

        :param view: 视图名（``by-batch`` / ``by-material`` / ``by-label``）。
        """
        return sum(self.view_counts.get(view, {}).values())


def entry_from_dict(payload: Mapping[str, object]) -> ManifestEntry:
    """由清单的一行（JSON 对象）还原成 :class:`ManifestEntry`。

    导出的视图文件与原清单**字段集合完全一致** —— 交差时可以直接逐行比对，
    不必再处理「导出格式另有一套」的麻烦。
    """
    duplicates = payload.get("merged_duplicates") or []
    return ManifestEntry(
        material_id=str(payload.get("material_id", "")),
        label=str(payload.get("label", "")),
        start=int(payload.get("start", 0) or 0),
        end=int(payload.get("end", 0) or 0),
        score=float(payload.get("score", 0.0) or 0.0),
        tier=str(payload.get("tier", "")),
        action=str(payload.get("action", "")),
        reason=str(payload.get("reason", "")),
        recognizer=str(payload.get("recognizer", "")),
        merged_duplicates=tuple(str(item) for item in duplicates),
    )


def read_entries(path: str | Path) -> list[ManifestEntry]:
    """读回清单文件（JSONL），返回条目列表。

    :param path: 清单路径。
    """
    return [entry_from_dict(row) for row in ManifestWriter.read(path)]


def summarize_entries(entries: Sequence[ManifestEntry]) -> tuple[LabelSummary, ...]:
    """按实体类别汇总命中（摘要表的数据来源）。

    摘要只给**条数、平均分、档位分布** —— 命中原文一律不进摘要。

    :param entries: 命中条目。
    :return: 汇总行，按命中数降序、同数按类别名升序。
    """
    buckets: dict[str, list[ManifestEntry]] = {}
    for entry in entries:
        buckets.setdefault(entry.label, []).append(entry)

    rows: list[LabelSummary] = []
    for label, group in buckets.items():
        rows.append(
            LabelSummary(
                label=label,
                hits=len(group),
                avg_score=sum(item.score for item in group) / len(group),
                confirmed=sum(1 for item in group if item.tier == "confirmed"),
                warning=sum(1 for item in group if item.tier == "warning"),
                allowed=sum(1 for item in group if item.tier == "allowed"),
                materials=len({item.material_id for item in group}),
            )
        )
    rows.sort(key=lambda row: (-row.hits, row.label))
    return tuple(rows)


def export_manifest_views(
    manifests: Mapping[str, Sequence[ManifestEntry]],
    out_dir: str | Path,
) -> ManifestExport:
    """把命中清单导出成三种分组视图 + 一张表格化摘要。

    导出目录长这样::

        <out_dir>/
            by-batch/<批次号>.jsonl        按批次
            by-material/<材料 ID>.jsonl    按材料
            by-label/<实体类别>.jsonl      按实体类别
            summary.csv                    各类别命中数 / 平均分 / 档位分布
            index.json                     机器可读索引（哪个文件、多少条）

    **三种视图是同一批命中的三种切法** —— 条数守恒是硬要求：任一视图逐文件
    加总，都等于 ``total``。导出文件与原清单字段集合完全一致，且**不含任何
    命中原文**（沿用清单的封闭字段集合，结构上就写不进原文）。

    :param manifests: 批次号 → 该批次的命中条目。
    :param out_dir: 导出目录（不存在则创建）。
    """
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    by_batch: dict[str, list[ManifestEntry]] = {}
    for batch_no, entries in manifests.items():
        by_batch.setdefault(batch_no, []).extend(entries)

    by_material: dict[str, list[ManifestEntry]] = {}
    by_label: dict[str, list[ManifestEntry]] = {}
    for entries in by_batch.values():
        for entry in entries:
            by_material.setdefault(entry.material_id, []).append(entry)
            by_label.setdefault(entry.label, []).append(entry)

    groups = {
        VIEW_BY_BATCH: by_batch,
        VIEW_BY_MATERIAL: by_material,
        VIEW_BY_LABEL: by_label,
    }
    view_files: dict[str, tuple[Path, ...]] = {}
    view_index: dict[str, list[dict[str, object]]] = {}
    view_removed: dict[str, list[str]] = {}
    for view, buckets in groups.items():
        directory = target / VIEW_DIRECTORIES[view]
        directory.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        listing: list[dict[str, object]] = []
        for key in sorted(buckets):
            path = directory / f"{_safe_name(key)}.jsonl"
            ManifestWriter(path).write(buckets[key])
            written.append(path)
            listing.append(
                {
                    "key": key,
                    "file": str(path.relative_to(target)),
                    "hits": len(buckets[key]),
                }
            )
        view_removed[view] = _prune_stale_view_files(
            directory, {path.name for path in written}
        )
        view_files[view] = tuple(written)
        view_index[view] = listing

    summary_rows = summarize_entries(
        [entry for entries in by_batch.values() for entry in entries]
    )
    summary_csv = target / SUMMARY_CSV_NAME
    _write_summary_csv(summary_csv, summary_rows)

    # 材料 ID 体检：ID 本身夹带了标识符时点名提示（不阻断、不改写）。
    all_entries = [entry for entries in by_batch.values() for entry in entries]
    id_findings = audit_material_ids(all_entries)

    index_json = target / INDEX_JSON_NAME
    index_payload = {
        "total": sum(len(entries) for entries in by_batch.values()),
        "summary_csv": SUMMARY_CSV_NAME,
        "views": view_index,
        "removed": view_removed,
        "material_id_findings": [
            finding.to_dict() for finding in id_findings
        ],
        "batches": [
            {"key": key, "hits": len(by_batch[key])} for key in sorted(by_batch)
        ],
        "materials": [
            {"key": key, "hits": len(by_material[key])} for key in sorted(by_material)
        ],
        "labels": [
            {"key": key, "hits": len(by_label[key])} for key in sorted(by_label)
        ],
        "tiers": _tier_counts(
            [entry for entries in by_batch.values() for entry in entries]
        ),
    }
    index_json.write_text(
        json.dumps(index_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    export = ManifestExport(
        out_dir=target,
        total=index_payload["total"],
        summary_csv=summary_csv,
        index_json=index_json,
        summary_rows=summary_rows,
        view_files=view_files,
        batch_counts={key: len(value) for key, value in by_batch.items()},
        material_counts={key: len(value) for key, value in by_material.items()},
        label_counts={key: len(value) for key, value in by_label.items()},
        tier_counts=index_payload["tiers"],
        view_counts={
            view: {row["key"]: row["hits"] for row in listing}
            for view, listing in view_index.items()
        },
        material_id_findings=id_findings,
    )
    return export


def collect_manifests(
    manifest_paths: Sequence[str | Path] = (),
    outbox: str | Path | None = None,
    batch_label: str | None = None,
) -> dict[str, list[ManifestEntry]]:
    """收集要导出的命中清单（批次号 → 条目）。

    两条取数路径：

    - **明确指定**：``manifest_paths`` 里的清单文件；归到哪个批次由
      ``batch_label`` 决定，缺省取清单所在父目录名（守护进程把每批清单写在
      ``<产物目录>/<批次号>/manifest.jsonl``，父目录名就是批次号）。
    - **扫产物目录**：``outbox`` 下每个 ``<批次号>/manifest.jsonl`` 各算一批。

    :raises FileNotFoundError: 清单文件或产物目录不存在 —— 明确报错，
        不静默导出空清单（空清单会被误读成「这批没命中」）。
    """
    collected: dict[str, list[ManifestEntry]] = {}

    for raw_path in manifest_paths:
        path = Path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(f"命中清单不存在：{path}")
        key = batch_label or path.parent.name or path.stem
        collected.setdefault(key, []).extend(read_entries(path))

    if outbox is not None:
        root = Path(outbox)
        if not root.is_dir():
            raise FileNotFoundError(f"产物目录不存在：{root}")
        found = sorted(root.glob("*/manifest.jsonl"))
        for path in found:
            key = path.parent.name
            collected.setdefault(key, []).extend(read_entries(path))

    return collected


def format_export_summary(export: ManifestExport) -> str:
    """把导出结果排成人类可读的摘要（CLI 与脚本共用同一份渲染）。"""
    lines: list[str] = []
    lines.append(f"导出命中清单：{export.total} 条 → {export.out_dir}")
    for view, title in (
        (VIEW_BY_BATCH, "按批次"),
        (VIEW_BY_MATERIAL, "按材料"),
        (VIEW_BY_LABEL, "按实体类别"),
    ):
        files = export.view_files.get(view, ())
        lines.append(f"  {title}：{len(files)} 个文件")
    if export.batch_counts:
        detail = "、".join(
            f"{key} {count} 条" for key, count in sorted(export.batch_counts.items())
        )
        lines.append(f"    批次分布：{detail}")
    if export.material_counts:
        detail = "、".join(
            f"{key} {count} 条" for key, count in sorted(export.material_counts.items())
        )
        lines.append(f"    材料分布：{detail}")
    lines.append(f"  摘要表：{export.summary_csv}")
    lines.append(f"  导出索引：{export.index_json}")
    if export.material_id_findings:
        labels = "、".join(
            sorted({finding.label for finding in export.material_id_findings})
        )
        lines.append(
            f"  提示：{len(export.material_id_findings)} 处材料 ID 夹带标识符"
            f"（类别 {labels}）—— 材料 ID 来自申请单，交差前请与平台确认口径"
        )
    if export.summary_rows:
        lines.append(
            f"  {'实体类别':<18}{'命中数':<8}{'平均分':<9}{'确认档':<8}{'告警档':<8}放行档"
        )
        for row in export.summary_rows:
            lines.append(
                f"  {row.label:<18}{row.hits:<8}{row.avg_score:<9.2f}"
                f"{row.confirmed:<8}{row.warning:<8}{row.allowed}"
            )
    return "\n".join(lines)


def _prune_stale_view_files(directory: Path, keep: set[str]) -> list[str]:
    """清掉上一次导出留在视图目录里的旧分组文件。

    同一目录重复导出、而这次的批次集合变小（批次被合并、批次号改了）时，
    上一次的分组文件会**留在目录里** —— 交差时按目录数文件，就会数出比实际
    多的条数，条数守恒在目录这一层就破了。

    视图目录由导出层独占，所以这里把**本次没写到的 .jsonl** 删掉（只删
    ``.jsonl``，不碰目录里的其他东西），并把删掉的文件名记进导出索引 ——
    删了什么要留痕，不能悄悄清场。

    :param directory: 视图目录。
    :param keep: 本次写到的文件名集合。
    :return: 被删掉的文件名（升序）。
    """
    removed: list[str] = []
    for path in sorted(directory.glob("*.jsonl")):
        if path.name in keep:
            continue
        try:
            path.unlink()
        except OSError:
            # 删不掉不静默：留着旧文件会让目录条数对不上，宁可报错。
            raise
        removed.append(path.name)
    return removed


def _write_summary_csv(path: Path, rows: Sequence[LabelSummary]) -> None:
    """写摘要表（CSV）。

    用 ``utf-8-sig`` 落盘：伦理办多半直接拿 Excel 打开， BOM 中文表头才不乱码。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([title for _, title in SUMMARY_COLUMNS])
        for row in rows:
            payload = row.to_row()
            writer.writerow([payload[key] for key, _ in SUMMARY_COLUMNS])


def _tier_counts(entries: Sequence[ManifestEntry]) -> dict[str, int]:
    """按档位统计条数（确认 / 告警 / 放行）。"""
    counts = {"confirmed": 0, "warning": 0, "allowed": 0}
    for entry in entries:
        counts[entry.tier] = counts.get(entry.tier, 0) + 1
    return counts


def _safe_name(value: str) -> str:
    """把批次号 / 材料 ID / 实体类别变成安全的文件名。

    路径分隔符与控制字符一律换成 ``_``；``#`` 保留（列级材料 ID 形如
    ``M-1#note``，保留它比换成 ``_`` 更便于人工核对是哪一列）。
    """
    cleaned = "".join(
        char if (char.isalnum() or char in "-_.#") else "_" for char in value.strip()
    )
    if not cleaned:
        # 空键用内容摘要占位：不同分组不会撞到同一个文件名。
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        return f"unnamed-{digest}"
    return cleaned
