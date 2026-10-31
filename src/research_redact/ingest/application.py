"""入站申请单：读 ``application.json`` / ``application.xlsx``，校验并归一化。

两种申请单格式归一化成**同一份结构**（:class:`IntakeResult`）—— JSON 与
xlsx 的解析结果逐字段一致，测试直接对照（``tests/test_column_policy.py``）。

**归一化后的结构**：一份申请单 = 一组**行**，一行 = 一份材料
（:class:`ApplicationRow`）。行的列 = 该材料自身的字段 + 从申请单继承的列
（``application_no`` / ``ethics_approval_no``）。xlsx 明细表天然就是这个
形状；JSON 申请单把它摊平成「申请单级字段 + ``materials`` 数组」，这里再
折回行 —— 两种格式因此可以逐字段对照。

**阻断纪律**：字段缺失**不抛异常也不静默放行** —— 返回 ``status=BLOCKED``
的入站结果，附**缺失项清单**与**告警文案**，由批次状态机（task 10）据此把
批次置 ``blocked``。缺伦理批件号尤其要紧：没有批件号的批次不得自动交付。

**不变量**

1. 解析不改动任何原始值 —— 脱敏在别处做，这里只负责「读进来、查齐、说清
   缺什么」；
2. 缺失项清单写清**缺哪一格**（``materials[2].path``），不只说「材料不完整」；
3. 解析不出内容（文件损坏、格式不认识）→ 抛 :class:`ApplicationParseError`，
   与「内容齐不齐」分开：前者是投递事故，后者是业务待补。
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "ApplicationError",
    "ApplicationParseError",
    "ApplicationRow",
    "BlockedApplicationError",
    "IntakeResult",
    "IntakeStatus",
    "MATERIAL_KINDS",
    "MaterialPlan",
    "dedupe_material_rows",
    "load_application",
    "load_json_application",
    "load_xlsx_application",
]


class ApplicationError(ValueError):
    """申请单相关错误（格式不认识、内容不可解析）。"""


class ApplicationParseError(ApplicationError):
    """申请单**读不出来**（格式不认识 / 文件损坏 / 表头缺失）。

    与「字段缺失」分开：读不出来是投递事故，字段缺失是业务待补 ——
    前者该退回去重投，后者该退回去补件。
    """


class BlockedApplicationError(ApplicationError):
    """申请单被阻断（缺伦理批件号 / 字段缺失），不得进入脱敏。

    阻断是**业务判断**：缺伦理批件号的批次没有授权范围，脱了也不能交。
    这里报错中止，而不是「先脱了再说」或「按正则硬脱」。
    """


class IntakeStatus(str, enum.Enum):
    """入站结果的状态。"""

    #: 字段齐备，可以进入识别。
    ACCEPTED = "accepted"
    #: 缺项或冲突，不得放行。
    BLOCKED = "blocked"


#: 材料类型取值（与 spec.md「入站 · 材料清单项」一致）。
MATERIAL_KINDS: tuple[str, ...] = ("report_text", "report_json", "table", "dicom")

#: 申请单级字段（不出现在「行」的额外列里）。
_APPLICATION_KEYS = frozenset({"application_no", "ethics_approval_no", "patient_ids", "materials"})

#: 材料清单项的规范字段。
_MATERIAL_KEYS = frozenset({"material_id", "kind", "path", "patient_id"})

#: 材料项里不得作为「额外列」出现的字段（由申请单级继承）。
_RESERVED_MATERIAL_KEYS = _MATERIAL_KEYS | {"application_no", "ethics_approval_no"}


@dataclass(frozen=True)
class ApplicationRow:
    """申请单的一行 = 一份材料。

    :param material_id: 材料 ID。
    :param kind: 材料类型（:data:`MATERIAL_KINDS` 之一）。
    :param path: 相对交付目录的材料路径。
    :param patient_id: 患者主索引主键；缺则走正文识别 + 名单反查。
    :param columns: 该行的全部列（含从申请单继承的列）。列值统一为字符串，
        空值为空串 —— 列级策略只看列名，值形态一致才不会漏判。
    """

    material_id: str
    kind: str
    path: str
    patient_id: str | None = None
    columns: Mapping[str, str] = field(default_factory=dict)

    def column(self, name: str) -> str:
        """取一列的值；列不存在返回空串。"""
        return self.columns.get(name, "")


@dataclass(frozen=True)
class IntakeResult:
    """一份申请单的入站结果。

    :param application_no: 申请单号。
    :param ethics_approval_no: 伦理批件号；缺失即 ``BLOCKED``。
    :param patient_ids: 本批涉及的患者主索引主键。
    :param rows: 归一化后的行（一行 = 一份材料）。
    :param status: 入站状态。
    :param missing: 缺失 / 不一致项清单（写清缺哪一格）。
    :param alerts: 告警文案（为什么阻断、需要人工做什么）。
    :param source_path: 来源文件路径。
    :param source_format: 来源格式（``json`` / ``xlsx``）。
    """

    application_no: str = ""
    ethics_approval_no: str | None = None
    patient_ids: tuple[str, ...] = ()
    rows: tuple[ApplicationRow, ...] = ()
    status: IntakeStatus = IntakeStatus.ACCEPTED
    missing: tuple[str, ...] = ()
    alerts: tuple[str, ...] = ()
    source_path: str = ""
    source_format: str = ""

    @property
    def is_blocked(self) -> bool:
        """是否被阻断（不得进入交付）。"""
        return self.status is IntakeStatus.BLOCKED

    @property
    def missing_summary(self) -> str:
        """缺失项清单的可读摘要（一行一项）。"""
        if not self.missing:
            return ""
        return "；".join(self.missing)

    def material_ids(self) -> tuple[str, ...]:
        """本批材料 ID 列表（按行序）。"""
        return tuple(row.material_id for row in self.rows)


# ------------------------------------------------------------------ 材料去重


@dataclass(frozen=True)
class MaterialPlan:
    """去重后的材料计划。

    :param rows: 去重后的行（**首次出现优先**）。
    :param duplicates: 重复出现的材料 ID（按首次重复出现的顺序）。
    :param dropped: 被丢弃的那些行的定位（如 ``materials[2].path``）—— 用来
        在告警文案里说清「丢的是哪一行」，让人能回申请单里改。
    """

    rows: tuple[ApplicationRow, ...] = ()
    duplicates: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()

    @property
    def has_duplicates(self) -> bool:
        """清单里有没有重复的材料 ID。"""
        return bool(self.duplicates)

    @property
    def material_ids(self) -> tuple[str, ...]:
        """去重后的材料 ID 清单（按行序）。"""
        return tuple(row.material_id for row in self.rows)


def dedupe_material_rows(rows: Iterable[ApplicationRow]) -> MaterialPlan:
    """按材料 ID 去重（**首次出现优先**）。

    **为什么要去重**：一份申请单里同一个材料 ID 出现两次，可能是管理员复制
    了行，也可能是两份不同材料被填了同一个 ID。不去重的话，后一行会**悄悄
    覆盖**前一行 —— 脱敏的是哪一份、交付的是哪一份，台账与清单都对不上；
    而重复替换同一段正文更是会把清单条数翻倍。

    **口径**：留**首次出现**的那一份（申请单里靠前的行通常是管理员先登记的），
    其余的丢弃并点名 —— 重复的材料 ID 要**告警**，不能静默去重：静默去重
    等于替人做决定，而这份申请单到底哪一行是对的，只有申请单的主人知道。

    :param rows: 归一化后的行。
    :return: 去重后的材料计划。
    """
    kept: list[ApplicationRow] = []
    dropped: list[str] = []
    duplicates: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        material_id = (row.material_id or "").strip()
        if not material_id or material_id not in seen:
            if material_id:
                seen.add(material_id)
            kept.append(row)
            continue
        if material_id not in duplicates:
            duplicates.append(material_id)
        dropped.append(f"materials[{index}].path（材料 ID {material_id} 重复）")
    return MaterialPlan(
        rows=tuple(kept),
        duplicates=tuple(duplicates),
        dropped=tuple(dropped),
    )


# --------------------------------------------------------------------- 入口


def load_application(path: str | Path) -> IntakeResult:
    """读一份申请单（按后缀分派 JSON / xlsx），校验并归一化。

    :param path: 申请单路径。
    :raises FileNotFoundError: 文件不存在。
    :raises ApplicationParseError: 格式不认识或内容读不出来。
    """
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"申请单不存在：{target}")
    suffix = target.suffix.lower()
    if suffix == ".json":
        return load_json_application(target)
    if suffix in (".xlsx", ".xlsm"):
        return load_xlsx_application(target)
    raise ApplicationParseError(
        f"不支持的申请单格式：{target.suffix or '（无后缀）'}（支持 .json / .xlsx）"
    )


# --------------------------------------------------------------------- JSON


def load_json_application(path: str | Path) -> IntakeResult:
    """读 JSON 申请单。

    :raises ApplicationParseError: JSON 解析失败或根节点不是对象。
    """
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ApplicationParseError(f"申请单不是 UTF-8 文本：{target}（{exc}）") from exc
    except OSError as exc:
        raise ApplicationParseError(f"申请单读取失败：{target}（{exc}）") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ApplicationParseError(f"申请单 JSON 解析失败：{target}（{exc}）") from exc
    if not isinstance(raw, dict):
        raise ApplicationParseError(f"申请单 JSON 根节点必须是对象：{target}")
    return _intake_from_json(raw, source_path=str(target), source_format="json")


def _intake_from_json(
    raw: Mapping[str, Any], source_path: str, source_format: str
) -> IntakeResult:
    """把 JSON 申请单折成「行」。"""
    missing: list[str] = []
    alerts: list[str] = []

    application_no = _text(raw.get("application_no")).strip()
    ethics_approval_no = _text(raw.get("ethics_approval_no")).strip()
    if not application_no:
        missing.append("application_no")
        alerts.append("申请单号缺失：无法定位批次，也无法与科研数据平台台账对账")
    if not ethics_approval_no:
        missing.append("ethics_approval_no")
        alerts.append(
            "缺伦理批件号：该批次不得交付，须补齐伦理批件号后重新投递（不降级放行）"
        )

    patient_ids: list[str] = []
    patient_ids_raw = raw.get("patient_ids")
    if not isinstance(patient_ids_raw, (list, tuple)) or not patient_ids_raw:
        missing.append("patient_ids")
        alerts.append(
            "患者主索引主键清单缺失：身份锚定与跨材料一致代号都依赖它，不得按姓名硬匹配"
        )
    else:
        for item in patient_ids_raw:
            value = _text(item).strip()
            if value:
                patient_ids.append(value)
        if not patient_ids:
            missing.append("patient_ids")
            alerts.append("患者主索引主键清单为空：无可锚定的患者，批次不得放行")

    # 申请单级额外字段（如「申请事由」「负责人」）继承到每一行 —— xlsx 明细表
    # 本来就是每行都带这些列，折回去之后两种格式才能逐字段对照。
    application_extras = {
        key: _text(value)
        for key, value in raw.items()
        if key not in _APPLICATION_KEYS
    }

    rows: list[ApplicationRow] = []
    materials_raw = raw.get("materials")
    if not isinstance(materials_raw, (list, tuple)) or not materials_raw:
        missing.append("materials")
        alerts.append("材料清单为空：批次没有可交付的内容")
    else:
        for index, item in enumerate(materials_raw):
            row, row_missing, row_alerts = _row_from_mapping(
                item if isinstance(item, Mapping) else {},
                prefix=f"materials[{index}]",
                inherited={
                    "application_no": application_no,
                    "ethics_approval_no": ethics_approval_no,
                },
                application_extras=application_extras,
                item_is_mapping=isinstance(item, Mapping),
            )
            rows.append(row)
            missing.extend(row_missing)
            alerts.extend(row_alerts)

    return IntakeResult(
        application_no=application_no,
        ethics_approval_no=ethics_approval_no or None,
        patient_ids=tuple(dict.fromkeys(patient_ids)),
        rows=tuple(rows),
        status=_status_of(missing),
        missing=tuple(missing),
        alerts=tuple(alerts),
        source_path=source_path,
        source_format=source_format,
    )


# --------------------------------------------------------------------- xlsx


def load_xlsx_application(path: str | Path) -> IntakeResult:
    """读 xlsx 申请单（明细表：一行一例 = 一份材料）。

    表结构：第一行是表头，之后每一行是一份材料。列名就是列策略的判定依据。

    :raises ApplicationParseError: 工作簿打不开、表头缺失或没有数据行。
    """
    target = Path(path)
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - 依赖缺失
        raise ApplicationParseError(
            f"读取 xlsx 申请单需要 openpyxl：{target}（{exc}）"
        ) from exc

    try:
        workbook = openpyxl.load_workbook(target, read_only=True, data_only=True)
    except Exception as exc:  # openpyxl 的异常类型很杂，统一收口
        raise ApplicationParseError(f"申请单 xlsx 打开失败：{target}（{exc}）") from exc

    try:
        sheet = workbook[workbook.sheetnames[0]]
        header: list[str] | None = None
        data_rows: list[list[str]] = []
        for raw_row in sheet.iter_rows(values_only=True):
            cells = [_text(value) for value in raw_row]
            if not any(cell.strip() for cell in cells):
                continue  # 空行跳过
            if header is None:
                header = cells
                continue
            data_rows.append(cells)
    finally:
        workbook.close()

    if header is None or not any(cell.strip() for cell in header):
        raise ApplicationParseError(f"申请单 xlsx 缺少表头行：{target}")
    if not data_rows:
        raise ApplicationParseError(f"申请单 xlsx 没有数据行：{target}")

    return _intake_from_rows(header, data_rows, source_path=str(target), source_format="xlsx")


def _intake_from_rows(
    header: Sequence[str], data_rows: Sequence[Sequence[str]], source_path: str, source_format: str
) -> IntakeResult:
    """把 xlsx 明细表折成「行」。"""
    missing: list[str] = []
    alerts: list[str] = []

    column_names = [name.strip() for name in header]
    mappings: list[dict[str, str]] = []
    for cells in data_rows:
        mapping: dict[str, str] = {}
        for index, name in enumerate(column_names):
            if not name:
                continue  # 空表头列直接忽略
            mapping[name] = cells[index] if index < len(cells) else ""
        mappings.append(mapping)

    # 申请单号 / 伦理批件号：取全表首个非空值；出现互相矛盾的值即为不一致。
    application_no = ""
    ethics_approval_no = ""
    for mapping in mappings:
        value = mapping.get("application_no", "").strip()
        if value and not application_no:
            application_no = value
        elif value and value != application_no:
            missing.append(f"application_no（工作簿内出现多个申请单号：{value}）")
            alerts.append(
                f"一份工作簿只能对应一张申请单，但出现了申请单号 {value}；"
                "请按申请单拆分工作簿后重新投递"
            )
        ethics = mapping.get("ethics_approval_no", "").strip()
        if ethics and not ethics_approval_no:
            ethics_approval_no = ethics
    if not application_no:
        missing.append("application_no")
        alerts.append("申请单号缺失：无法定位批次，也无法与科研数据平台台账对账")
    if not ethics_approval_no:
        missing.append("ethics_approval_no")
        alerts.append(
            "缺伦理批件号：该批次不得交付，须补齐伦理批件号后重新投递（不降级放行）"
        )

    patient_ids: list[str] = []
    for mapping in mappings:
        value = mapping.get("patient_id", "").strip()
        if value and value not in patient_ids:
            patient_ids.append(value)
    if not patient_ids:
        missing.append("patient_ids")
        alerts.append(
            "患者主索引主键清单缺失：身份锚定与跨材料一致代号都依赖它，不得按姓名硬匹配"
        )

    rows: list[ApplicationRow] = []
    for index, mapping in enumerate(mappings):
        row, row_missing, row_alerts = _row_from_mapping(
            mapping,
            prefix=f"materials[{index}]",
            inherited={
                "application_no": mapping.get("application_no", "").strip() or application_no,
                "ethics_approval_no": mapping.get("ethics_approval_no", "").strip()
                or ethics_approval_no,
            },
            application_extras={},
            item_is_mapping=True,
        )
        rows.append(row)
        missing.extend(row_missing)
        alerts.extend(row_alerts)

    return IntakeResult(
        application_no=application_no,
        ethics_approval_no=ethics_approval_no or None,
        patient_ids=tuple(patient_ids),
        rows=tuple(rows),
        status=_status_of(missing),
        missing=tuple(missing),
        alerts=tuple(alerts),
        source_path=source_path,
        source_format=source_format,
    )


# ------------------------------------------------------------------ 行装配


def _row_from_mapping(
    item: Mapping[str, Any],
    prefix: str,
    inherited: Mapping[str, str],
    application_extras: Mapping[str, str],
    item_is_mapping: bool,
) -> tuple[ApplicationRow, list[str], list[str]]:
    """把一份材料（JSON 项或 xlsx 行）装配成 :class:`ApplicationRow`。

    :param prefix: 缺失项清单里的定位前缀（如 ``materials[2]``）。
    :param inherited: 从申请单继承的列（申请单号 / 伦理批件号）。
    :param application_extras: 申请单级额外列，继承到每一行。
    :param item_is_mapping: 该项是不是映射（JSON 里可能塞了字符串或数字）。
    :return: （行, 缺失项清单, 告警文案）
    """
    missing: list[str] = []
    alerts: list[str] = []

    if not item_is_mapping:
        missing.append(prefix)
        alerts.append(f"{prefix} 不是对象，无法作为材料清单项解析")
        item = {}

    material_id = _text(item.get("material_id")).strip()
    kind = _text(item.get("kind")).strip()
    path = _text(item.get("path")).strip()
    patient_id = _text(item.get("patient_id")).strip() or None

    if not material_id:
        missing.append(f"{prefix}.material_id")
        alerts.append(f"{prefix} 缺材料 ID：材料无法与脱敏产物一一对应")
    if not kind:
        missing.append(f"{prefix}.kind")
        alerts.append(f"{prefix} 缺材料类型：无法选择对应的处理路径")
    elif kind not in MATERIAL_KINDS:
        missing.append(f"{prefix}.kind")
        alerts.append(
            f"{prefix} 的材料类型不支持：{kind}（支持 {'、'.join(MATERIAL_KINDS)}）"
        )
    if not path:
        missing.append(f"{prefix}.path")
        alerts.append(f"{prefix} 缺材料路径：交付目录里找不到这份材料")

    extras = {
        key: _text(value)
        for key, value in item.items()
        if key not in _RESERVED_MATERIAL_KEYS
    }
    columns: dict[str, str] = {}
    columns.update(inherited)
    columns.update(application_extras)
    columns.update(
        {
            "material_id": material_id,
            "kind": kind,
            "path": path,
            "patient_id": patient_id or "",
        }
    )
    columns.update(extras)

    row = ApplicationRow(
        material_id=material_id,
        kind=kind,
        path=path,
        patient_id=patient_id,
        columns=columns,
    )
    return row, missing, alerts


# ------------------------------------------------------------------ 工具函数


def _status_of(missing: Iterable[str]) -> IntakeStatus:
    """有缺失项即阻断；没有缺失项即放行。"""
    return IntakeStatus.BLOCKED if tuple(missing) else IntakeStatus.ACCEPTED


def _text(value: Any) -> str:
    """把任意单元格值转成字符串（``None`` → 空串）。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
