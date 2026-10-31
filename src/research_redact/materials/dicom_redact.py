"""DICOM tag 级去标识：身份 tag 清空、私有 tag 一律清空、必要 tag 保留。

**首版只做 tag 级，不做像素层。** 影像里的身份有两处：一处在 tag（患者姓名、
患者编号、出生日期、申请医师、机构名……），一处在**像素**（画面角上烧录的
姓名 / 住院号 / 检查号）。本模块只处理前者 —— 像素烧录明确不在首版，理由与
源产品一致但取舍不同：

- 源产品 ``presidio-image-redactor`` 走 OCR + bbox 像素填充（见
  ``github_ref/presidio/presidio-image-redactor/app.py::Server.redact``），
  依赖 OCR 与 DICOM 双栈，且中文烧录字 OCR 召回不稳；
- 本轮产品形态是**事件驱动守护**（批量科研交付），逐帧 OCR 的耗时与召回都
  不适合放进常驻路径；因此首版把「像素烧录」作为**已知未覆盖项**显式留白，
  并保留 ``(0028,0301) BurnedInAnnotation`` 这个判定旗标 —— 该 tag 为
  ``YES`` 时由人工点检（``docs/`` 留痕），不假装「已涂除」。

**源产品能力与本轮取舍**（详见 round 根 ``spec.md`` → ``## 开源对照``）：

| 源产品主能力 | 本轮判定 |
|---|---|
| OCR 定位 + bbox 像素填充（图像涂除主路径） | **本轮不做**（依赖重、中文召回不稳） |
| DICOM 元数据处理 | **改写**：本模块（最小 tag 解析器 + 处置表） |
| 涂除记录清单 | **改写**：并入批次级逐处命中清单（JSONL） |

**处置表**（策略表 ``dicom`` 段，见 :mod:`research_redact.policy.dicom`）：
``keep`` 保留必要 tag（检查号 / 序列号 / 设备信息）、``clear`` 清空身份 tag、
``replace`` 替换取值、**私有 tag（奇数组）一律清空**。

**命中清单**：每一处处置都进清单（tag 号 + 关键字 + 处置 + 字节区间），
**不记 tag 的原值** —— 与文本材料同一红线（清单是交差产物，伦理办抽检要看
「哪一处被怎么处理了」，不是「患者叫什么」）。

**二次自检**：脱敏产物再解析一遍 —— 身份 tag 与私有 tag 必须都是零长度。
这一层对应文本路径的残留自检（``audit/residual.py``）：DICOM 是二进制，
文本识别器扫不了它，只能按 tag 号复核。

**依赖**：不引 pydicom —— 用一个**最小 tag 解析器**（标准字典键名匹配 +
显式 / 隐式 VR 小端）读文件、写文件。理由见 ``spec.md``：研究交付目录里
躺着的 DICOM 文件来自各厂商设备，解析行为必须**可预期、可审计**，而不是
交给一个第三方库的版本差异。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from ..audit.manifest import ManifestEntry, ManifestWriter
from ..policy.dicom import DicomConfig
from ..policy.table import PolicyTable, load_policy_table

__all__ = [
    "DicomConfig",
    "DicomDataset",
    "DicomElement",
    "DicomError",
    "DicomFinding",
    "DicomItem",
    "DicomParseError",
    "DicomRedaction",
    "DicomSelfCheck",
    "DicomUnsupportedError",
    "DicomVerificationError",
    "IDENTITY_TAGS",
    "default_dicom_config",
    "iter_elements",
    "parse_dicom",
    "redact_dicom_bytes",
    "redact_dicom_file",
    "serialize_dicom",
    "verify_dicom",
]


# --------------------------------------------------------------------- 错误


class DicomError(Exception):
    """DICOM 处理相关错误基类。"""


class DicomParseError(DicomError):
    """DICOM 文件读不出来（不是 DICOM / 结构损坏 / 长度越界）。

    与「文件里没有身份信息」分开：读不出来是投递事故，交给人工重投；
    没读到身份是正常结果。
    """


class DicomUnsupportedError(DicomError):
    """传输语法不支持（如 Deflated / 大端）。**不猜、不降级** —— 猜错编码
    会把二进制写坏，比不做更危险。"""


class DicomVerificationError(DicomError):
    """脱敏产物的二次自检未通过 —— 产物不得交付。"""


# ----------------------------------------------------------------- 常量表

#: 文件前导：128 字节填充 + ``DICM``。
_PREAMBLE_LENGTH = 128
_MAGIC = b"DICM"

#: 支持的传输语法 → 是否显式 VR。
TRANSFER_SYNTAX_EXPLICIT: Mapping[str, bool] = {
    "1.2.840.10008.1.2": False,  # Implicit VR Little Endian
    "1.2.840.10008.1.2.1": True,  # Explicit VR Little Endian
}

#: 已知但**不支持**的传输语法（报错时点名，避免「读出来是乱码」）。
_UNSUPPORTED_SYNTAXES: Mapping[str, str] = {
    "1.2.840.10008.1.2.1.99": "Deflated Explicit VR Little Endian",
    "1.2.840.10008.1.2.2": "Explicit VR Big Endian",
}

#: 长度字段为 4 字节（2 字节保留）的 VR。
_EXTENDED_LENGTH_VRS = frozenset(
    {"OB", "OW", "OF", "OD", "OL", "OV", "SQ", "UT", "UN", "UC", "UR"}
)

#: 序列 / 项目 / 分隔符 tag。
_ITEM_TAG = (0xFFFE, 0xE000)
_ITEM_DELIMITER_TAG = (0xFFFE, 0xE00D)
_SEQUENCE_DELIMITER_TAG = (0xFFFE, 0xE0DD)
_DELIMITER_TAGS = frozenset({_ITEM_DELIMITER_TAG, _SEQUENCE_DELIMITER_TAG})

#: 最小标准字典：(组, 元素) → (关键字, VR)。
#:
#: 只收本产品真正要判的 tag：身份 tag（清空）、必要 tag（保留）、去标识标记
#: 与少量上下文 tag。未收录的 tag 仍能解析与写回（按文件里的 VR / 隐式 UN），
#: 只是拿不到关键字名 —— 清单里会记成 ``(gggg,eeee)`` 形式。
STANDARD_TAGS: Mapping[tuple[int, int], tuple[str, str]] = {
    # --- 文件元信息（组 0002，永远显式 VR 小端）---
    (0x0002, 0x0000): ("FileMetaInformationGroupLength", "UL"),
    (0x0002, 0x0001): ("FileMetaInformationVersion", "OB"),
    (0x0002, 0x0002): ("MediaStorageSOPClassUID", "UI"),
    (0x0002, 0x0003): ("MediaStorageSOPInstanceUID", "UI"),
    (0x0002, 0x0010): ("TransferSyntaxUID", "UI"),
    (0x0002, 0x0012): ("ImplementationClassUID", "UI"),
    (0x0002, 0x0013): ("ImplementationVersionName", "SH"),
    # --- 通用 ---
    (0x0008, 0x0005): ("SpecificCharacterSet", "CS"),
    (0x0008, 0x0008): ("ImageType", "CS"),
    (0x0008, 0x0016): ("SOPClassUID", "UI"),
    (0x0008, 0x0018): ("SOPInstanceUID", "UI"),
    (0x0008, 0x0020): ("StudyDate", "DA"),
    (0x0008, 0x0021): ("SeriesDate", "DA"),
    (0x0008, 0x0023): ("ContentDate", "DA"),
    (0x0008, 0x0030): ("StudyTime", "TM"),
    (0x0008, 0x0032): ("AcquisitionTime", "TM"),
    (0x0008, 0x0050): ("AccessionNumber", "SH"),
    (0x0008, 0x0060): ("Modality", "CS"),
    (0x0008, 0x0070): ("Manufacturer", "LO"),
    (0x0008, 0x0080): ("InstitutionName", "LO"),
    (0x0008, 0x0081): ("InstitutionAddress", "ST"),
    (0x0008, 0x0090): ("ReferringPhysicianName", "PN"),
    (0x0008, 0x0092): ("ReferringPhysicianAddress", "ST"),
    (0x0008, 0x1010): ("StationName", "SH"),
    (0x0008, 0x1030): ("StudyDescription", "LO"),
    (0x0008, 0x1032): ("ProcedureCodeSequence", "SQ"),
    (0x0008, 0x103E): ("SeriesDescription", "LO"),
    (0x0008, 0x1070): ("OperatorsName", "PN"),
    (0x0008, 0x1090): ("ManufacturerModelName", "LO"),
    (0x0008, 0x1110): ("ReferencedStudySequence", "SQ"),
    (0x0008, 0x1115): ("ReferencedSeriesSequence", "SQ"),
    (0x0008, 0x1140): ("ReferencedImageSequence", "SQ"),
    # --- 患者（身份核心）---
    (0x0010, 0x0010): ("PatientName", "PN"),
    (0x0010, 0x0020): ("PatientID", "LO"),
    (0x0010, 0x0021): ("IssuerOfPatientID", "LO"),
    (0x0010, 0x0030): ("PatientBirthDate", "DA"),
    (0x0010, 0x0040): ("PatientSex", "CS"),
    (0x0010, 0x1010): ("PatientAge", "AS"),
    (0x0010, 0x1020): ("PatientSize", "DS"),
    (0x0010, 0x1030): ("PatientWeight", "DS"),
    (0x0010, 0x1040): ("PatientAddress", "LO"),
    (0x0010, 0x2154): ("PatientTelephoneNumbers", "SH"),
    (0x0010, 0x2160): ("EthnicGroup", "SH"),
    (0x0010, 0x4000): ("PatientComments", "LT"),
    # --- 去标识标记 ---
    (0x0012, 0x0010): ("ClinicalTrialSponsorName", "LO"),
    (0x0012, 0x0020): ("ClinicalTrialProtocolID", "LO"),
    (0x0012, 0x0030): ("ClinicalTrialSiteID", "LO"),
    (0x0012, 0x0062): ("PatientIdentityRemoved", "CS"),
    (0x0012, 0x0063): ("DeidentificationMethod", "LO"),
    (0x0012, 0x0064): ("DeidentificationMethodCodeSequence", "SQ"),
    # --- 检查 / 序列标识 ---
    (0x0020, 0x000D): ("StudyInstanceUID", "UI"),
    (0x0020, 0x000E): ("SeriesInstanceUID", "UI"),
    (0x0020, 0x0010): ("StudyID", "SH"),
    (0x0020, 0x0011): ("SeriesNumber", "IS"),
    (0x0020, 0x0013): ("InstanceNumber", "IS"),
    (0x0020, 0x0052): ("FrameOfReferenceUID", "UI"),
    # --- 影像参数 ---
    (0x0028, 0x0010): ("Rows", "US"),
    (0x0028, 0x0011): ("Columns", "US"),
    (0x0028, 0x0100): ("BitsAllocated", "US"),
    (0x0028, 0x0101): ("BitsStored", "US"),
    (0x0028, 0x0301): ("BurnedInAnnotation", "CS"),
    # --- 申请 / 住院 ---
    (0x0032, 0x1032): ("RequestingPhysician", "PN"),
    (0x0032, 0x1064): ("RequestedProcedureCodeSequence", "SQ"),
    (0x0038, 0x0010): ("AdmissionID", "LO"),
    (0x0038, 0x0011): ("IssuerOfAdmissionID", "LO"),
    (0x0038, 0x0300): ("CurrentPatientLocation", "LO"),
    (0x0038, 0x0400): ("PatientInstitutionResidence", "LO"),
    (0x0040, 0x0006): ("ScheduledPerformingPhysicianName", "PN"),
    (0x0040, 0x0007): ("ScheduledProcedureStepDescription", "LO"),
    (0x0040, 0x0253): ("PerformedProcedureStepID", "SH"),
    (0x0040, 0x0254): ("PerformedProcedureStepDescription", "LO"),
    (0x0040, 0x0275): ("RequestAttributesSequence", "SQ"),
    (0x0040, 0x0555): ("AcquisitionContextSequence", "SQ"),
}

#: 命中清单里用的类别前缀（与文本材料的类别区分开）。
LABEL_TAG = "DICOM_TAG"
LABEL_PRIVATE_TAG = "DICOM_PRIVATE_TAG"
LABEL_SUMMARY = "DICOM_SUMMARY"

#: DICOM 里**必须**清空的身份 tag（模块自带的安全底线）。
#:
#: 这份清单**不依赖策略表**：策略表漏登记一个身份 tag 时，处置照旧执行，
#: 但二次自检仍会把它报出来并中止交付 —— 否则就成了「配置漏了 → 漏脱 →
#: 静默交付」。策略表可以加更多要清的 tag，但清单里的这些一个都不能少。
IDENTITY_TAGS: frozenset[str] = frozenset(
    {
        # 患者身份（核心）
        "PatientName",
        "PatientID",
        "IssuerOfPatientID",
        "PatientBirthDate",
        "PatientSex",
        "PatientAge",
        "PatientSize",
        "PatientWeight",
        "PatientAddress",
        "PatientTelephoneNumbers",
        "EthnicGroup",
        "PatientComments",
        # 住院 / 申请关联（能反查患者）
        "AdmissionID",
        "IssuerOfAdmissionID",
        "CurrentPatientLocation",
        "PatientInstitutionResidence",
        # 人员与机构（可识别到人）
        "ReferringPhysicianName",
        "ReferringPhysicianAddress",
        "RequestingPhysician",
        "ScheduledPerformingPhysicianName",
        "OperatorsName",
        "InstitutionName",
        "InstitutionAddress",
    }
)

#: 清单里记录的识别器名。
_RECOGNIZER = "dicom_tag"


# --------------------------------------------------------------- 数据模型


@dataclass(frozen=True)
class DicomElement:
    """一个 DICOM 元素（tag + VR + 取值）。

    :param group: 组号。
    :param element: 元素号。
    :param vr: 值表示（Value Representation）。
    :param keyword: 标准字典关键字；字典里没有时为空串。
    :param value: 原始字节值。
    :param items: 序列（VR 为 SQ）里的条目。
    :param offset: 该元素在**源文件**里的字节偏移（值区起点）。
    :param undefined_length: 长度是否未定义（0xFFFFFFFF）。
    """

    group: int
    element: int
    vr: str
    keyword: str = ""
    value: bytes = b""
    items: tuple["DicomItem", ...] = ()
    offset: int = 0
    undefined_length: bool = False

    @property
    def tag(self) -> tuple[int, int]:
        """(组, 元素)。"""
        return (self.group, self.element)

    @property
    def is_private(self) -> bool:
        """是否私有 tag（奇数组 = 厂商私有区）。"""
        return self.group % 2 == 1

    @property
    def name(self) -> str:
        """清单里显示的名字：关键字优先，没有关键字就用 tag 号。"""
        return self.keyword or f"({self.group:04X},{self.element:04X})"

    @property
    def tag_text(self) -> str:
        """tag 号文本（``(0010,0010)``）。"""
        return f"({self.group:04X},{self.element:04X})"


@dataclass(frozen=True)
class DicomItem:
    """序列里的一个条目（一段嵌套的数据集）。"""

    elements: tuple[DicomElement, ...] = ()
    undefined_length: bool = False


@dataclass(frozen=True)
class DicomDataset:
    """一份 DICOM 文件的结构。

    :param preamble: 文件前导（128 字节 + ``DICM``；没有则为空）。
    :param meta: 文件元信息组（0002）的元素。
    :param elements: 主数据集的元素。
    :param transfer_syntax: 传输语法 UID。
    :param explicit_vr: 是否显式 VR（决定读写时的元素头格式）。
    """

    preamble: bytes = b""
    meta: tuple[DicomElement, ...] = ()
    elements: tuple[DicomElement, ...] = ()
    transfer_syntax: str = "1.2.840.10008.1.2.1"
    explicit_vr: bool = True


@dataclass(frozen=True)
class DicomFinding:
    """一处 tag 级残留（**不记原值**）。"""

    tag_text: str
    keyword: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        """转成可落盘 / 可展示的一行（不含原值）。"""
        return {"tag": self.tag_text, "keyword": self.keyword, "reason": self.reason}


@dataclass(frozen=True)
class DicomSelfCheck:
    """DICOM 产物二次自检结论。

    :param findings: 残留明细（身份 tag / 私有 tag 里仍有非空值）。
    """

    findings: tuple[DicomFinding, ...] = ()

    @property
    def passed(self) -> bool:
        """自检是否通过（无残留）。"""
        return not self.findings

    @property
    def summary(self) -> str:
        """一句人话结论（进运维摘要与告警文案，不含原值）。"""
        if self.passed:
            return "DICOM tag 级自检通过：身份 tag 与私有 tag 均已清空"
        names = "、".join(dict.fromkeys(item.keyword or item.tag_text for item in self.findings))
        return f"DICOM tag 级自检未通过：{len(self.findings)} 处 tag 仍有非空值（{names}）"


@dataclass(frozen=True)
class DicomRedaction:
    """一次 DICOM 去标识的结果。

    :param material_id: 材料 ID。
    :param data: 去标识后的文件字节。
    :param entries: 逐处处置清单（不含 tag 原值）。
    :param counts: 分类计数（身份 tag 清空 / 私有 tag 清空 / 替换 / 保留）。
    :param self_check: 产物二次自检结论。
    :param transfer_syntax: 原文件的传输语法。
    """

    material_id: str
    data: bytes = b""
    entries: tuple[ManifestEntry, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)
    self_check: DicomSelfCheck = field(default_factory=DicomSelfCheck)
    transfer_syntax: str = ""

    @property
    def deliverable(self) -> bool:
        """该材料可否交付：二次自检通过才放行。"""
        return self.self_check.passed


# ------------------------------------------------------------------- 解析


def parse_dicom(data: bytes) -> DicomDataset:
    """解析一份 DICOM 文件。

    支持显式 VR 小端与隐式 VR 小端两种传输语法；其余（大端 / Deflated）
    **明确报错**，不猜 —— 猜错编码会把二进制写坏。

    :param data: 文件字节。
    :raises DicomParseError: 不是 DICOM 文件 / 结构损坏。
    :raises DicomUnsupportedError: 传输语法不支持。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise DicomParseError("DICOM 输入必须是字节")
    payload = bytes(data)
    if len(payload) < 16:
        raise DicomParseError(f"文件过短（{len(payload)} 字节），不是 DICOM 文件")

    preamble = b""
    offset = 0
    if payload[_PREAMBLE_LENGTH : _PREAMBLE_LENGTH + 4] == _MAGIC:
        preamble = payload[: _PREAMBLE_LENGTH + 4]
        offset = _PREAMBLE_LENGTH + 4

    meta, dataset_offset = _parse_meta(payload, offset)
    transfer_syntax = _transfer_syntax_of(meta)

    if transfer_syntax in _UNSUPPORTED_SYNTAXES:
        raise DicomUnsupportedError(
            f"不支持的传输语法 {transfer_syntax}"
            f"（{_UNSUPPORTED_SYNTAXES[transfer_syntax]}）："
            "本轮只支持显式 / 隐式 VR 小端，不做格式转换（转换会把原始文件改样）"
        )
    explicit_vr = TRANSFER_SYNTAX_EXPLICIT.get(transfer_syntax)
    if explicit_vr is None:
        raise DicomUnsupportedError(
            f"未知的传输语法 {transfer_syntax}：本轮只支持"
            f"{'、'.join(sorted(TRANSFER_SYNTAX_EXPLICIT))}"
        )

    elements, _ = _parse_dataset(payload, dataset_offset, len(payload), explicit_vr)
    return DicomDataset(
        preamble=preamble,
        meta=meta,
        elements=tuple(elements),
        transfer_syntax=transfer_syntax,
        explicit_vr=explicit_vr,
    )


def _parse_meta(payload: bytes, offset: int) -> tuple[list[DicomElement], int]:
    """解析文件元信息组（0002），返回（元素, 数据集起点）。

    元信息组永远是显式 VR 小端；遇到组号不是 0002 的元素即停止。
    """
    elements: list[DicomElement] = []
    cursor = offset
    while cursor + 8 <= len(payload):
        group, element = struct.unpack_from("<HH", payload, cursor)
        if group != 0x0002:
            break
        parsed, cursor = _parse_element(payload, cursor, len(payload), True)
        elements.append(parsed)
    return elements, cursor


def _transfer_syntax_of(meta: Sequence[DicomElement]) -> str:
    """从元信息组取传输语法 UID；取不到按显式 VR 小端处理。"""
    for element in meta:
        if element.tag == (0x0002, 0x0010):
            return element.value.decode("ascii", "replace").strip().rstrip("\x00")
    return "1.2.840.10008.1.2.1"


def _parse_dataset(
    payload: bytes, offset: int, end: int, explicit_vr: bool, depth: int = 0
) -> tuple[list[DicomElement], int]:
    """解析一段数据集，返回（元素列表, 结束偏移）。

    遇到项目 / 序列分隔符即停止（由上层消费）。
    """
    if depth > 8:
        raise DicomParseError("序列嵌套过深（> 8 层），文件结构异常")
    elements: list[DicomElement] = []
    cursor = offset
    while cursor + 8 <= end:
        group, element = struct.unpack_from("<HH", payload, cursor)
        if (group, element) in _DELIMITER_TAGS:
            break
        parsed, cursor = _parse_element(payload, cursor, end, explicit_vr, depth)
        elements.append(parsed)
    return elements, cursor


def _parse_element(
    payload: bytes,
    offset: int,
    end: int,
    explicit_vr: bool,
    depth: int = 0,
) -> tuple[DicomElement, int]:
    """解析一个元素，返回（元素, 下一个元素的偏移）。"""
    group, element = struct.unpack_from("<HH", payload, offset)
    keyword, dict_vr = STANDARD_TAGS.get((group, element), ("", ""))

    if explicit_vr:
        vr = payload[offset + 4 : offset + 6].decode("ascii", "replace")
        if len(vr) != 2 or not vr.isalpha() or not vr.isupper():
            raise DicomParseError(
                f"非法的显式 VR：tag ({group:04X},{element:04X}) 处读到 {vr!r}"
                " —— 文件可能不是显式 VR 小端"
            )
        if vr in _EXTENDED_LENGTH_VRS:
            length = struct.unpack_from("<I", payload, offset + 8)[0]
            value_start = offset + 12
        else:
            length = struct.unpack_from("<H", payload, offset + 6)[0]
            value_start = offset + 8
    else:
        vr = dict_vr or "UN"
        length = struct.unpack_from("<I", payload, offset + 4)[0]
        value_start = offset + 8

    undefined = length == 0xFFFFFFFF
    if undefined and vr != "SQ":
        raise DicomParseError(
            f"tag ({group:04X},{element:04X}) 的长度未定义，但 VR 为 {vr}（只有序列可以）"
        )

    if vr == "SQ":
        items, cursor = _parse_sequence(payload, value_start, end, explicit_vr, depth)
        return (
            DicomElement(
                group=group,
                element=element,
                vr=vr,
                keyword=keyword,
                value=b"",
                items=items,
                offset=value_start,
                undefined_length=undefined,
            ),
            cursor,
        )

    value_end = end if undefined else value_start + length
    if value_end > end:
        raise DicomParseError(
            f"tag ({group:04X},{element:04X}) 的长度越界"
            f"（声明 {length} 字节，剩余 {end - value_start} 字节）"
        )
    value = payload[value_start:value_end]
    return (
        DicomElement(
            group=group,
            element=element,
            vr=vr,
            keyword=keyword,
            value=value,
            offset=value_start,
            undefined_length=undefined,
        ),
        value_end,
    )


def _parse_sequence(
    payload: bytes, offset: int, end: int, explicit_vr: bool, depth: int
) -> tuple[tuple[DicomItem, ...], int]:
    """解析序列内容，返回（条目列表, 结束偏移）。"""
    items: list[DicomItem] = []
    cursor = offset
    while cursor + 8 <= end:
        group, element = struct.unpack_from("<HH", payload, cursor)
        if (group, element) == _SEQUENCE_DELIMITER_TAG:
            cursor += 8
            break
        if (group, element) != _ITEM_TAG:
            break
        item_length = struct.unpack_from("<I", payload, cursor + 4)[0]
        cursor += 8
        if item_length == 0xFFFFFFFF:
            item_elements, cursor = _parse_dataset(
                payload, cursor, end, explicit_vr, depth + 1
            )
            if cursor + 8 <= end:
                cursor += 8  # 消费项目分隔符 (FFFE,E00D)
            items.append(DicomItem(elements=tuple(item_elements), undefined_length=True))
        else:
            item_end = cursor + item_length
            if item_end > end:
                raise DicomParseError("序列条目长度越界")
            item_elements, _ = _parse_dataset(
                payload, cursor, item_end, explicit_vr, depth + 1
            )
            items.append(DicomItem(elements=tuple(item_elements)))
            cursor = item_end
    return tuple(items), cursor


# ------------------------------------------------------------------- 写回


def serialize_dicom(dataset: DicomDataset) -> bytes:
    """把数据集写回文件字节（结构与源文件同款传输语法）。

    **文件元信息组（0002）永远用显式 VR 小端** —— 这是 DICOM 标准的规定，
    与数据集本身用哪种传输语法无关。隐式 VR 的文件在写回时也必须把元信息组
    按显式 VR 写，写错的话接收方的解析器读不懂「这份文件是哪种编码」。
    """
    chunks: list[bytes] = []
    if dataset.preamble:
        chunks.append(dataset.preamble)
    for element in dataset.meta:
        chunks.append(_serialize_element(element, True))
    for element in dataset.elements:
        chunks.append(_serialize_element(element, dataset.explicit_vr))
    return b"".join(chunks)


def _serialize_element(element: DicomElement, explicit_vr: bool) -> bytes:
    """写回一个元素（序列按条目逐个写）。"""
    if element.vr == "SQ":
        body = b"".join(_serialize_item(item, explicit_vr) for item in element.items)
        if explicit_vr:
            header = (
                struct.pack("<HH", element.group, element.element)
                + b"SQ"
                + b"\x00\x00"
                + struct.pack("<I", len(body))
            )
        else:
            header = struct.pack("<HHI", element.group, element.element, len(body))
        return header + body

    value = element.value
    if explicit_vr:
        vr = element.vr or "UN"
        if len(value) > 0xFFFF and vr not in _EXTENDED_LENGTH_VRS:
            raise DicomError(
                f"tag ({element.group:04X},{element.element:04X}) 的取值过长"
                f"（{len(value)} 字节，VR {vr} 的长度字段只有 16 位）"
            )
        if vr in _EXTENDED_LENGTH_VRS:
            header = (
                struct.pack("<HH", element.group, element.element)
                + vr.encode("ascii")
                + b"\x00\x00"
                + struct.pack("<I", len(value))
            )
        else:
            header = (
                struct.pack("<HH", element.group, element.element)
                + vr.encode("ascii")
                + struct.pack("<H", len(value))
            )
    else:
        header = struct.pack("<HHI", element.group, element.element, len(value))
    return header + value


def _serialize_item(item: DicomItem, explicit_vr: bool) -> bytes:
    """写回序列里的一个条目。"""
    content = b"".join(_serialize_element(child, explicit_vr) for child in item.elements)
    if item.undefined_length:
        return (
            struct.pack("<HHI", _ITEM_TAG[0], _ITEM_TAG[1], 0xFFFFFFFF)
            + content
            + struct.pack("<HHI", _ITEM_DELIMITER_TAG[0], _ITEM_DELIMITER_TAG[1], 0)
        )
    return struct.pack("<HHI", _ITEM_TAG[0], _ITEM_TAG[1], len(content)) + content


# ----------------------------------------------------------------- 工具函数


def default_dicom_config(table: PolicyTable | None = None) -> DicomConfig:
    """取当前生效的 DICOM 处置口径（缺省读策略表 ``dicom`` 段）。"""
    active = table if table is not None else load_policy_table()
    return active.dicom


def iter_elements(
    elements: Iterable[DicomElement],
) -> Iterator[DicomElement]:
    """按深度优先遍历全部元素（含序列内的嵌套元素）。"""
    for element in elements:
        yield element
        for item in element.items:
            yield from iter_elements(item.elements)


def _decode_text(value: bytes, charset: str = "") -> str:
    """按字符集解码 tag 取值（仅供人工可读输出，**不进清单**）。"""
    for candidate in (charset, "GB18030", "utf-8"):
        if not candidate:
            continue
        try:
            return value.decode(candidate)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("latin-1", "replace")


def _charset_of(elements: Iterable[DicomElement]) -> str:
    """取 ``SpecificCharacterSet`` 的取值（决定中文名怎么解）。"""
    for element in elements:
        if element.keyword == "SpecificCharacterSet":
            return element.value.decode("ascii", "replace").strip()
    return ""


def _pad_value(value: bytes, vr: str) -> bytes:
    """把取值补齐到偶数长度（DICOM 要求值为偶数字节）。"""
    if len(value) % 2 == 0:
        return value
    return value + (b"\x00" if vr == "UI" else b" ")


# ----------------------------------------------------------------- 去标识


def redact_dicom_bytes(
    data: bytes,
    material_id: str,
    config: DicomConfig | None = None,
) -> DicomRedaction:
    """对一份 DICOM 做 tag 级去标识。

    :param data: 原始文件字节。
    :param material_id: 材料 ID（写进清单每一行）。
    :param config: 处置口径；缺省读策略表 ``dicom`` 段。
    :raises DicomParseError: 文件读不出来。
    :raises DicomUnsupportedError: 传输语法不支持。
    :raises DicomVerificationError: 产物二次自检未通过（**不静默交付**）。
    """
    active = config if config is not None else default_dicom_config()
    dataset = parse_dicom(data)

    entries: list[ManifestEntry] = []
    counts = {"identity_cleared": 0, "private_cleared": 0, "replaced": 0, "kept": 0}
    elements = _redact_elements(dataset.elements, active, material_id, entries, counts)
    elements = _mark_identity_removed(elements, active, dataset.explicit_vr)

    redacted = serialize_dicom(
        DicomDataset(
            preamble=dataset.preamble,
            meta=dataset.meta,
            elements=elements,
            transfer_syntax=dataset.transfer_syntax,
            explicit_vr=dataset.explicit_vr,
        )
    )

    check = verify_dicom(redacted, active)
    if not check.passed:
        raise DicomVerificationError(
            f"{check.summary} —— 该材料不得交付（材料 {material_id}）"
        )

    entries.append(_summary_entry(material_id, len(data), counts))
    return DicomRedaction(
        material_id=material_id,
        data=redacted,
        entries=tuple(entries),
        counts=counts,
        self_check=check,
        transfer_syntax=dataset.transfer_syntax,
    )


def _redact_elements(
    elements: Sequence[DicomElement],
    config: DicomConfig,
    material_id: str,
    entries: list[ManifestEntry],
    counts: dict[str, int],
) -> tuple[DicomElement, ...]:
    """逐元素套用处置表（序列内递归处理）。"""
    result: list[DicomElement] = []
    for element in elements:
        # 私有 tag：奇数组，内容不可预知 —— 一律清空。
        if element.is_private and config.clear_private_tags:
            counts["private_cleared"] += 1
            entries.append(
                _entry(
                    material_id,
                    LABEL_PRIVATE_TAG,
                    element,
                    "redact",
                    f"DICOM 私有 tag {element.tag_text} 已清空（厂商私有区，内容不可预知）",
                )
            )
            result.append(replace(element, value=b"", items=_redact_items(element, config, material_id, entries, counts)))
            continue

        if element.keyword in config.clear_tags:
            counts["identity_cleared"] += 1
            entries.append(
                _entry(
                    material_id,
                    LABEL_TAG,
                    element,
                    "redact",
                    f"DICOM 身份 tag {element.tag_text} {element.name} 已清空",
                )
            )
            result.append(replace(element, value=b"", items=_redact_items(element, config, material_id, entries, counts)))
            continue

        if element.keyword in config.replace_tags:
            replacement = _pad_value(
                config.replace_tags[element.keyword].encode("utf-8"), element.vr
            )
            counts["replaced"] += 1
            entries.append(
                _entry(
                    material_id,
                    LABEL_TAG,
                    element,
                    "replace",
                    f"DICOM 身份 tag {element.tag_text} {element.name} 的取值已替换",
                )
            )
            result.append(replace(element, value=replacement, items=_redact_items(element, config, material_id, entries, counts)))
            continue

        if element.keyword in config.keep_tags:
            counts["kept"] += 1
            entries.append(
                _entry(
                    material_id,
                    LABEL_TAG,
                    element,
                    "keep",
                    f"DICOM 必要 tag {element.tag_text} {element.name} 保留"
                    "（研究交付需要的关联号 / 序列号 / 设备信息）",
                )
            )
            result.append(replace(element, items=_redact_items(element, config, material_id, entries, counts)))
            continue

        if config.default_action == "clear":
            counts["identity_cleared"] += 1
            entries.append(
                _entry(
                    material_id,
                    LABEL_TAG,
                    element,
                    "redact",
                    f"DICOM tag {element.tag_text} {element.name} 未列入保留表，已按白名单口径清空",
                )
            )
            result.append(replace(element, value=b"", items=_redact_items(element, config, material_id, entries, counts)))
            continue

        result.append(replace(element, items=_redact_items(element, config, material_id, entries, counts)))
    return tuple(result)


def _redact_items(
    element: DicomElement,
    config: DicomConfig,
    material_id: str,
    entries: list[ManifestEntry],
    counts: dict[str, int],
) -> tuple[DicomItem, ...]:
    """递归处理序列内的嵌套元素。"""
    if not element.items:
        return element.items
    return tuple(
        DicomItem(
            elements=_redact_elements(
                item.elements, config, material_id, entries, counts
            ),
            undefined_length=item.undefined_length,
        )
        for item in element.items
    )


def _mark_identity_removed(
    elements: tuple[DicomElement, ...], config: DicomConfig, explicit_vr: bool
) -> tuple[DicomElement, ...]:
    """写入去标识标记 tag（``PatientIdentityRemoved`` / ``DeidentificationMethod``）。

    这是 DICOM 标准做法：文件自己声明「身份已移除、去标识方式是什么」。
    收件方（研究方、伦理办）不必猜这份片子是不是脱过。
    """
    if not config.mark_identity_removed:
        return elements
    wanted = {
        (0x0012, 0x0062): ("PatientIdentityRemoved", "CS", b"YES"),
        (0x0012, 0x0063): (
            "DeidentificationMethod",
            "LO",
            config.deidentification_method.encode("ascii", "replace"),
        ),
    }
    updated = list(elements)
    for tag, (keyword, vr, value) in wanted.items():
        index = next(
            (i for i, element in enumerate(updated) if element.tag == tag), None
        )
        new_element = DicomElement(
            group=tag[0],
            element=tag[1],
            vr=vr,
            keyword=keyword,
            value=_pad_value(value, vr),
        )
        if index is None:
            # 按 tag 序插入（数据集的元素按 tag 升序排列）
            position = len(updated)
            for i, element in enumerate(updated):
                if element.tag > tag:
                    position = i
                    break
            updated.insert(position, new_element)
        else:
            updated[index] = new_element
    return tuple(updated)


def _entry(
    material_id: str,
    label: str,
    element: DicomElement,
    action: str,
    reason: str,
) -> ManifestEntry:
    """构造一条清单记录（**不记 tag 原值**）。"""
    return ManifestEntry(
        material_id=material_id,
        label=label,
        start=element.offset,
        end=element.offset + len(element.value),
        score=1.0,
        tier="confirmed",
        action=action,
        reason=reason,
        recognizer=_RECOGNIZER,
    )


def _summary_entry(
    material_id: str, file_size: int, counts: Mapping[str, int]
) -> ManifestEntry:
    """构造一条批次级处置摘要记录。

    清单里除了逐处明细，还要有一行**总计** —— 伦理办抽检时先看这一行：
    「私有 tag 清空了几个、身份 tag 清空了几个、必要 tag 留了几个」。
    """
    return ManifestEntry(
        material_id=material_id,
        label=LABEL_SUMMARY,
        start=0,
        end=max(file_size, 1),
        score=1.0,
        tier="confirmed",
        action="summary",
        reason=(
            f"DICOM 私有 tag 已清空（{counts.get('private_cleared', 0)} 个）；"
            f"身份 tag 已清空（{counts.get('identity_cleared', 0)} 个）；"
            f"取值已替换（{counts.get('replaced', 0)} 个）；"
            f"必要 tag 保留（{counts.get('kept', 0)} 个）；"
            "像素烧录未处理（BurnedInAnnotation 旗标留待人工点检）"
        ),
        recognizer=_RECOGNIZER,
    )


# ----------------------------------------------------------------- 二次自检


def verify_dicom(data: bytes, config: DicomConfig | None = None) -> DicomSelfCheck:
    """对脱敏产物再扫一遍：身份 tag 与私有 tag 必须都是零长度。

    这是 DICOM 路径上的「残留自检」—— 文本路径靠识别器二次扫描，二进制路径
    只能按 tag 号复核。**不记原值**，只报 tag 号与关键字。

    判定依据是 :data:`IDENTITY_TAGS`（模块自带的身份 tag 底线）**加上**策略表
    声明的清空项 —— 不只看策略表：策略表漏登记一个身份 tag 时，自检照样把它
    报出来并中止交付。

    **占位符不算残留**：取值被换成占位符（如 ``<患者编号>``）是「已脱」，与
    文本路径把占位符排除在残留之外的取法一致。

    :param data: 产物字节。
    :param config: 处置口径；缺省读策略表 ``dicom`` 段。
    """
    active = config if config is not None else default_dicom_config()
    must_be_empty = set(IDENTITY_TAGS) | set(active.clear_tags)
    placeholders = _known_placeholders(active)
    dataset = parse_dicom(data)
    findings: list[DicomFinding] = []
    for element in iter_elements(dataset.elements):
        if element.vr == "SQ":
            continue
        if not element.value:
            continue
        if _is_placeholder(element.value, placeholders):
            continue
        if element.is_private and active.clear_private_tags:
            findings.append(
                DicomFinding(
                    tag_text=element.tag_text,
                    keyword=element.name,
                    reason="私有 tag 在产物中仍有非空取值",
                )
            )
        elif element.keyword in must_be_empty:
            findings.append(
                DicomFinding(
                    tag_text=element.tag_text,
                    keyword=element.name,
                    reason="身份 tag 在产物中仍有非空取值",
                )
            )
    return DicomSelfCheck(findings=tuple(findings))


def _known_placeholders(
    config: DicomConfig, table: PolicyTable | None = None
) -> set[str]:
    """已知的「脱敏产物取值」（占位符）—— 命中它们不算残留。

    取自策略表的 ``replace`` 占位符与 DICOM 段的 ``replace_tags`` 取值。
    """
    values = {value.strip() for value in config.replace_tags.values() if value.strip()}
    active = table if table is not None else load_policy_table()
    for spec in active.entity_actions.values():
        if spec.placeholder:
            values.add(spec.placeholder.strip())
    return values


def _is_placeholder(value: bytes, placeholders: set[str]) -> bool:
    """取值是不是已知占位符（DICOM 取值按字节对齐补空格/NULL）。"""
    if not placeholders:
        return False
    text = value.strip(b" \x00").decode("utf-8", "replace").strip()
    return text in placeholders


# ------------------------------------------------------------------- 落盘


def redact_dicom_file(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    material_id: str | None = None,
    config: DicomConfig | None = None,
) -> DicomRedaction:
    """对一份 DICOM 材料做 tag 级去标识，落脱敏副本与逐处命中清单。

    :param input_path: 原始 DICOM 路径。
    :param output_path: 脱敏副本输出路径。
    :param manifest_path: 命中清单输出路径（JSONL）。
    :param material_id: 材料 ID；缺省取输入文件名（不含后缀）。
    :param config: 处置口径；缺省读策略表 ``dicom`` 段。
    :raises FileNotFoundError: 材料不存在。
    :raises DicomParseError / DicomUnsupportedError / DicomVerificationError: 见
        :func:`redact_dicom_bytes`。
    """
    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(f"材料文件不存在：{source}")
    material = material_id or source.stem
    data = source.read_bytes()

    outcome = redact_dicom_bytes(data, material, config=config)

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(outcome.data)

    ManifestWriter(manifest_path).write(outcome.entries)
    return outcome
