"""出站字段规范校验层（pydantic）。

**为什么要有这一层**：出站报文是**对外契约** —— 平台按 spec.md 的字段规范接收，
我们按同一份规范交付。少一个字段、类型错一个、材料类型写错一个，平台要么
拒收（批次挂起等人重投），要么**收下一份半成品**（材料挂不上批次、命中清单
找不到）。后者更麻烦：东西已经交出去了，对不上却没人知道。

所以这一层的规矩是 **校验不过就不外发**（不是「先发出去试试」）：

- 校验不过 → 归到 ``payload_invalid`` 失败类别（**不重试**，重试只是把同一个
  错再犯一遍），批次按通道口径处置（平台通道 → ``pending_delivery`` 等人重投）；
- 错误信息必须说清**是哪个字段、期望是什么**，且**不回显字段取值** ——
  报错文案会进告警、也会进台账，患者原文不能从报错里漏出去。

三份契约（spec.md「最小数据格式与字段要求」）：

======================================  ==========================================
模型                                     对应的报文
======================================  ==========================================
:class:`DatasetRequest`                 ``POST /api/v1/datasets`` 请求体
:class:`RestoreAuditRequest`             ``POST /api/v1/datasets/{id}/restore-audit`` 请求体
:class:`PatientIndexResponse`            ``GET /api/v1/patient-index`` 响应体
======================================  ==========================================

**材料 ID 的形状**：spec.md 把材料 ID 定义成「申请单号 + 院内检查号 + 材料
序号」三元组 —— 交付给平台的就是这个复合键，平台按它把材料挂回批次。形状不对
（缺一段、序号不是数字）的材料键**不外发**：交出去平台也挂不上批次。

**还原回执的 scope 不做形状校验**：scope 是一份「本次授权覆盖哪些材料」的清单，
形状由交付时那一关把关；授权范围够不够由 :mod:`research_redact.restore.authority`
裁决 —— 两处各管一件事，不重复裁决。
"""

from __future__ import annotations

from typing import Any, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

from .channels import CHANNEL_HIS, CHANNEL_RESEARCH
from .errors import OutboundError
from .failures import FailureCategory

__all__ = [
    "DatasetRequest",
    "MaterialItem",
    "MATERIAL_KINDS",
    "OutboundPayloadError",
    "PatientIndexResponse",
    "Pseudonymization",
    "RestoreAuditRequest",
    "validate_dataset_request",
    "validate_patient_index_response",
    "validate_restore_audit_request",
]


#: 材料类型（与 ``ingest.application.MATERIAL_KINDS`` 同一份口径）。
MATERIAL_KINDS: tuple[str, ...] = ("report_text", "report_json", "table", "dicom")

#: 一致代号方案名（交付体 ``pseudonymization.scheme`` 的唯一合法取值）。
PSEUDONYM_SCHEME = "hmac-sha256"


class OutboundPayloadError(OutboundError):
    """出站字段规范校验不过 —— **请求根本没发出去**。

    :param message: 校验结论（说清哪个字段、期望是什么；**不回显取值**）。
    :param channel: 通道名。
    :param fields: 出问题的字段路径（``materials[0].kind`` 这种定位）。
    """

    def __init__(
        self,
        message: str,
        *,
        channel: str = "",
        fields: tuple[str, ...] = (),
    ) -> None:
        super().__init__(
            message,
            channel=channel,
            category=FailureCategory.PAYLOAD_INVALID,
            retryable=False,
        )
        self.fields = tuple(fields)


# --------------------------------------------------------------------- 模型


class _StrictModel(BaseModel):
    """出站请求体的基类：字段多余即报错（少字段、多字段都不放行）。"""

    model_config = ConfigDict(extra="forbid")


class MaterialItem(_StrictModel):
    """交付体里的一份材料（**不含正文，不含患者原文**）。

    :param material_id: 材料键（三段式：申请单号-院内检查号-材料序号）。
    :param kind: 材料类型（四值之一）。
    :param sha256: 脱敏副本的内容摘要（64 位十六进制）。
    :param storage_uri: 脱敏副本的存储位置。
    """

    material_id: str
    kind: str
    sha256: str
    storage_uri: str

    @field_validator("material_id", mode="before")
    @classmethod
    def _check_material_id(cls, value: Any) -> Any:
        """材料键必须是「申请单号-院内检查号-材料序号」三段式。"""
        text = _require_str(value, "材料键 material_id")
        parts = text.split("-")
        if len(parts) < 3:
            raise ValueError(
                "材料键 material_id 必须是「申请单号-院内检查号-材料序号」三段式，"
                f"当前只有 {len(parts)} 段"
            )
        if not parts[-2].strip():
            raise ValueError("材料键 material_id 的院内检查号段为空")
        sequence = parts[-1].strip()
        if not sequence.isdigit():
            raise ValueError("材料键 material_id 的材料序号段必须是数字")
        if len(sequence) < 2:
            raise ValueError("材料键 material_id 的材料序号段至少两位数字")
        return text

    @field_validator("kind", mode="before")
    @classmethod
    def _check_kind(cls, value: Any) -> Any:
        """材料类型只支持四个取值。"""
        text = _require_str(value, "材料类型 kind")
        if text not in MATERIAL_KINDS:
            raise ValueError(
                "材料类型 kind 只支持 "
                + " / ".join(MATERIAL_KINDS)
                + " 四个取值"
            )
        return text

    @field_validator("sha256", mode="before")
    @classmethod
    def _check_sha256(cls, value: Any) -> Any:
        """内容摘要必须是 64 位十六进制。"""
        text = _require_str(value, "内容摘要 sha256")
        if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text.lower()):
            raise ValueError("内容摘要 sha256 必须是 64 位十六进制")
        return text.lower()

    @field_validator("storage_uri", mode="before")
    @classmethod
    def _check_storage_uri(cls, value: Any) -> Any:
        """存储位置不能为空 —— 空位置等于「材料没交上去」。"""
        text = _require_str(value, "存储位置 storage_uri")
        if not text.strip():
            raise ValueError("存储位置 storage_uri 不能为空")
        return text


class Pseudonymization(_StrictModel):
    """一致代号方案说明（交付体里必须写明用了哪把密钥）。"""

    scheme: str
    key_id: str

    @field_validator("scheme", mode="before")
    @classmethod
    def _check_scheme(cls, value: Any) -> Any:
        """一致代号方案只有一种。"""
        text = _require_str(value, "一致代号方案 scheme")
        if text != PSEUDONYM_SCHEME:
            raise ValueError(f"一致代号方案 scheme 只支持 {PSEUDONYM_SCHEME}")
        return text

    @field_validator("key_id", mode="before")
    @classmethod
    def _check_key_id(cls, value: Any) -> Any:
        """密钥版本号不能为空 —— 事后说不清这批代号是用哪把密钥生成的。"""
        text = _require_str(value, "一致代号密钥版本号 key_id")
        if not text.strip():
            raise ValueError(
                "一致代号密钥版本号 key_id 不能空：事后说不清这批代号用的哪把密钥"
            )
        return text


class DatasetRequest(_StrictModel):
    """数据集交付请求体（``POST /api/v1/datasets``）。

    字段与 spec.md「最小数据格式与字段要求」逐项对应：顶层 7 项，材料项 4 项。
    """

    application_no: str
    ethics_approval_no: str
    dataset_name: str
    material_count: int
    materials: list[MaterialItem]
    pseudonymization: Pseudonymization
    manifest_uri: str

    @field_validator("application_no", mode="before")
    @classmethod
    def _check_application_no(cls, value: Any) -> Any:
        """申请单号不能为空（幂等键的组成部分，也是材料键的第一段）。"""
        text = _require_str(value, "申请单号 application_no")
        if not text.strip():
            raise ValueError("申请单号 application_no 不能为空")
        return text.strip()

    @field_validator("ethics_approval_no", mode="before")
    @classmethod
    def _check_ethics_approval_no(cls, value: Any) -> Any:
        """伦理批件号不能为空 —— 缺批件号的批次不得交付。"""
        text = _require_str(value, "伦理批件号 ethics_approval_no")
        if not text.strip():
            raise ValueError(
                "伦理批件号 ethics_approval_no 不能为空：缺批件号的批次不得交付"
            )
        return text.strip()

    @field_validator("dataset_name", mode="before")
    @classmethod
    def _check_dataset_name(cls, value: Any) -> Any:
        """数据集名不能为空。"""
        text = _require_str(value, "数据集名 dataset_name")
        if not text.strip():
            raise ValueError("数据集名 dataset_name 不能为空")
        return text.strip()

    @field_validator("material_count", mode="before")
    @classmethod
    def _check_material_count(cls, value: Any) -> Any:
        """材料数必须是整数（布尔值不算数）。"""
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("材料数 material_count 必须是整数")
        if value < 0:
            raise ValueError("材料数 material_count 不能为负")
        return value

    @field_validator("materials", mode="before")
    @classmethod
    def _check_materials(cls, value: Any) -> Any:
        """材料清单必须是列表，且每项是对象。"""
        if not isinstance(value, (list, tuple)):
            raise ValueError("材料清单 materials 必须是列表")
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                raise ValueError(f"材料清单 materials[{index}] 必须是对象")
        return list(value)

    @field_validator("manifest_uri", mode="before")
    @classmethod
    def _check_manifest_uri(cls, value: Any) -> Any:
        """命中清单位置不能为空 —— 平台要按它去取逐处命中清单。"""
        text = _require_str(value, "命中清单位置 manifest_uri")
        if not text.strip():
            raise ValueError(
                "命中清单位置 manifest_uri 不能为空：平台要按它取逐处命中清单"
            )
        return text.strip()

    @model_validator(mode="after")
    def _check_count_matches(self) -> "DatasetRequest":
        """声明的材料数必须与清单条数一致（对不上就是半成品）。"""
        if self.material_count != len(self.materials):
            raise ValueError(
                "material_count 与材料清单条数对不上："
                f"声明 {self.material_count} 份，实际 {len(self.materials)} 份"
            )
        return self


class RestoreAuditRequest(_StrictModel):
    """还原回执请求体（``POST /api/v1/datasets/{dataset_id}/restore-audit``）。

    固定 9 个字段，**不含任何还原出来的原文**。
    """

    restore_request_id: str
    dataset_id: str
    approver_a: str
    approver_b: str
    scope: list[str]
    reason: str = ""
    granted_at: str = ""
    expires_at: str = ""
    result_summary: str = ""

    @field_validator("restore_request_id", mode="before")
    @classmethod
    def _check_restore_request_id(cls, value: Any) -> Any:
        """还原请求号不能为空。"""
        text = _require_str(value, "还原请求号 restore_request_id")
        if not text.strip():
            raise ValueError("还原请求号 restore_request_id 不能为空")
        return text.strip()

    @field_validator("dataset_id", mode="before")
    @classmethod
    def _check_dataset_id(cls, value: Any) -> Any:
        """数据集 ID 不能为空（回执挂在哪个数据集上要说清）。"""
        text = _require_str(value, "数据集 ID dataset_id")
        if not text.strip():
            raise ValueError("数据集 ID dataset_id 不能为空")
        return text.strip()

    @field_validator("approver_a", mode="before")
    @classmethod
    def _check_approver_a(cls, value: Any) -> Any:
        """授权人 A 不能为空。"""
        text = _require_str(value, "授权人 approver_a")
        if not text.strip():
            raise ValueError("授权人 approver_a 不能为空")
        return text.strip()

    @field_validator("approver_b", mode="before")
    @classmethod
    def _check_approver_b(cls, value: Any) -> Any:
        """授权人 B 不能为空 —— 单人还原的回执不成立。"""
        text = _require_str(value, "授权人 approver_b")
        if not text.strip():
            raise ValueError("授权人 approver_b 不能为空：单人还原不留回执")
        return text.strip()

    @field_validator("scope", mode="before")
    @classmethod
    def _check_scope(cls, value: Any) -> Any:
        """授权范围必须是列表，每项是材料 ID（不校验三段式，理由见模块说明）。"""
        if not isinstance(value, (list, tuple)):
            raise ValueError("授权范围 scope 必须是列表")
        items = list(value)
        for index, item in enumerate(items):
            text = _require_str(item, f"授权范围 scope[{index}]")
            if not text.strip():
                raise ValueError(f"授权范围 scope[{index}] 不能为空")
            items[index] = text.strip()
        return items


class PatientIndexResponse(BaseModel):
    """HIS 患者主索引响应体（``GET /api/v1/patient-index``）。

    响应里可能带对端自己的附加字段（患者主索引是院内系统，各家字段不一），
    所以这里**允许多余字段** —— 但身份主键必须有，否则患者身份锚定不了。
    """

    model_config = ConfigDict(extra="ignore")

    patient_id: str
    visit_no: str = ""
    name: str = ""
    id_card_masked: str = ""
    birth_date: str = ""
    sex: str = ""

    @field_validator("patient_id", mode="before")
    @classmethod
    def _check_patient_id(cls, value: Any) -> Any:
        """患者主索引主键不能为空 —— 锚定不了身份就不能继续脱敏。"""
        text = _require_str(value, "患者主索引主键 patient_id")
        if not text.strip():
            raise ValueError("患者主索引主键 patient_id 不能为空：无法锚定患者身份")
        return text.strip()

    @field_validator("visit_no", "name", "id_card_masked", "birth_date", "sex", mode="before")
    @classmethod
    def _check_optional_text(cls, value: Any) -> Any:
        """其余字段是字符串（缺省空串）。"""
        if value is None:
            return ""
        return _require_str(value, "主索引字段")


# ------------------------------------------------------------------ 校验入口


def validate_dataset_request(
    body: Mapping[str, Any], *, channel: str = CHANNEL_RESEARCH
) -> DatasetRequest:
    """按字段规范校验数据集交付请求体。

    :param body: 请求体。
    :param channel: 通道名（写进错误对象）。
    :return: 校验通过的模型（客户端按它组装最终报文）。
    :raises OutboundPayloadError: 字段不过 —— **请求不得外发**。
    """
    return _validate(DatasetRequest, body, channel=channel)


def validate_restore_audit_request(
    body: Mapping[str, Any], *, channel: str = CHANNEL_RESEARCH
) -> RestoreAuditRequest:
    """按字段规范校验还原回执请求体。

    :param body: 请求体。
    :param channel: 通道名（写进错误对象）。
    :return: 校验通过的模型。
    :raises OutboundPayloadError: 字段不过 —— **请求不得外发**。
    """
    return _validate(RestoreAuditRequest, body, channel=channel)


def validate_patient_index_response(
    payload: Mapping[str, Any], *, channel: str = CHANNEL_HIS
) -> PatientIndexResponse:
    """按字段规范校验患者主索引响应体。

    :param payload: 响应体。
    :param channel: 通道名（写进错误对象）。
    :return: 校验通过的模型。
    :raises OutboundPayloadError: 字段不过 —— 响应不能当成成功。
    """
    return _validate(PatientIndexResponse, payload, channel=channel)


# --------------------------------------------------------------------- 内部


def _validate(
    model: type[BaseModel], payload: Mapping[str, Any], *, channel: str
) -> Any:
    """跑一遍 pydantic 校验，把错误收口成 :class:`OutboundPayloadError`。"""
    if not isinstance(payload, Mapping):
        raise OutboundPayloadError(
            "出站报文必须是对象（JSON 字典），当前是 "
            + type(payload).__name__,
            channel=channel,
        )
    try:
        return model.model_validate(dict(payload))
    except ValidationError as exc:
        raise _payload_error(exc, channel=channel) from exc


def _payload_error(exc: ValidationError, *, channel: str) -> OutboundPayloadError:
    """把 pydantic 的校验错误翻成中文的「哪个字段、期望是什么」。"""
    details: list[str] = []
    fields: list[str] = []
    for item in exc.errors():
        loc = _format_loc(item.get("loc", ()))
        message = _translate(item.get("msg", ""))
        fields.append(loc)
        details.append(f"{loc}：{message}")
    summary = "；".join(details) if details else "出站字段规范校验不过"
    return OutboundPayloadError(summary, channel=channel, fields=tuple(fields))


def _format_loc(loc: Any) -> str:
    """字段路径 → 人读的定位串（``materials[0].kind``）。"""
    parts: list[str] = []
    for item in loc or ():
        if isinstance(item, int):
            parts.append(f"[{item}]")
        elif parts:
            parts.append(f".{item}")
        else:
            parts.append(str(item))
    return "".join(parts) or "报文字段"


#: pydantic 内建报错 → 中文说法（自定义校验器的报错本身已是中文）。
_MESSAGE_ZH: dict[str, str] = {
    "Field required": "必填字段缺失",
    "Input should be a valid integer": "必须是整数",
    "Input should be a valid string": "必须是字符串",
    "Input should be a valid list": "必须是列表",
    "Input should be a valid dictionary": "必须是对象",
    "Input should be a valid boolean": "必须是布尔值",
    "Extra inputs are not permitted": "出现了报文字段之外的字段",
    "Value error, ": "",
}


def _translate(message: str) -> str:
    """pydantic 的英文报错 → 中文。"""
    text = str(message)
    for source, target in _MESSAGE_ZH.items():
        if text == source:
            return target
        if text.startswith(source):
            return target + text[len(source) :]
    return text


def _require_str(value: Any, label: str) -> str:
    """取值 → 字符串；不是字符串就报错（不静默转字符串）。"""
    if isinstance(value, str):
        return value
    if value is None:
        raise ValueError(f"{label} 必填，不能为空")
    raise ValueError(f"{label} 必须是字符串（当前是 {type(value).__name__}）")
