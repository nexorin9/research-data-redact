"""出站失败的错误码分类与处置裁决。

出站调用失败的原因不同，处置**完全不同**。把「令牌没配」和「平台抖了一下」
一锅脑重试三遍：前者会把配置问题放大成事故，后者会把瞬时抖动拖成批次挂起。
本模块给出唯一一套分类口径与裁决口径。

**分类**（:class:`FailureCategory`）—— 按「失败发生在哪一层」分：

=========================  ==========================================  ======
类别                      含义                                        可重试
=========================  ==========================================  ======
``auth_failed``           鉴权失败（401 / 403）                        否
``endpoint_unconfigured`` 端点或凭据没配（通道挂起）                  否
``request_rejected``      对端说请求不对（400 / 404 / 409 / 422）       否
``payload_invalid``       本地组装或校验不过，请求根本没发出去        否
``response_invalid``      响应结构不对（不是合法 JSON 对象）           否
``client_error``          本地调用异常（不是对端的问题）               否
``server_error``          对端 5xx                                     是
``timeout``               超时                                         是
``connection_error``      连不上                                       是
=========================  ==========================================  ======

**裁决**（:func:`decide_failure`）—— 每一类映射三件事：能不能重试、批次落到
哪个状态、告警什么级别什么码。批次状态按**通道**区分：

- 主索引通道（``his-patient-index``）：连不上 / 鉴权不过 / 端点没配 →
  ``suspended``。身份锚定不可信时**不得**继续脱敏（spec.md「不降级」）。
- 平台通道（``research-platform``）：任何交付失败 → ``pending_delivery``，
  等人修好配置或平台恢复后重投。

**纪律**：分类只依据**状态码与异常类型**，不解析对端的错误文案 —— 文案可能
带患者信息，也可能换个版本就变；据此判定「该不该重试」不可靠。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .channels import CHANNEL_HIS, CHANNEL_RESEARCH

__all__ = [
    "FailureCategory",
    "FailureDecision",
    "classify_exception",
    "classify_status",
    "decide_failure",
]


class FailureCategory(str, enum.Enum):
    """出站失败类别。"""

    #: 鉴权失败（401 / 403）。
    AUTH_FAILED = "auth_failed"
    #: 端点或凭据没配 —— 通道挂起。
    ENDPOINT_UNCONFIGURED = "endpoint_unconfigured"
    #: 对端拒绝请求（4xx）。
    REQUEST_REJECTED = "request_rejected"
    #: 请求体本地校验不过 —— 根本没发出去。
    PAYLOAD_INVALID = "payload_invalid"
    #: 响应结构不对（不是合法 JSON 对象）。
    RESPONSE_INVALID = "response_invalid"
    #: 本地调用异常（不是对端的问题）。
    CLIENT_ERROR = "client_error"
    #: 对端 5xx。
    SERVER_ERROR = "server_error"
    #: 超时。
    TIMEOUT = "timeout"
    #: 连不上。
    CONNECTION_ERROR = "connection_error"


@dataclass(frozen=True)
class FailureDecision:
    """一类失败该怎么处置。

    :param category: 失败类别。
    :param retryable: 是否值得退避重试。
    :param batch_state: 批次应落到的状态（``suspended`` / ``pending_delivery`` /
        空串 = 状态不推进，只留告警）。
    :param alert_level: 告警级别（``error`` / ``warning``）。
    :param alert_code: 告警码（供程序按码分流）。
    :param summary: 一句人话说明（写进告警文案，**不含患者原文**）。
    """

    category: FailureCategory
    retryable: bool
    batch_state: str
    alert_level: str
    alert_code: str
    summary: str

    def describe(self) -> str:
        """一句人话说明（带告警码），供告警文案使用。"""
        return f"{self.summary}（{self.alert_code}）"


#: 类别 → （可重试, 告警级别, 告警码, 一句话说明）。
_CATEGORY_TABLE: dict[FailureCategory, tuple[bool, str, str, str]] = {
    FailureCategory.AUTH_FAILED: (
        False,
        "error",
        "outbound_auth_failed",
        "对端拒绝凭据：令牌无效或权限不足",
    ),
    FailureCategory.ENDPOINT_UNCONFIGURED: (
        False,
        "error",
        "outbound_channel_suspended",
        "通道未配置：端点或凭据缺失，该通道置挂起，不指向本地替身",
    ),
    FailureCategory.REQUEST_REJECTED: (
        False,
        "error",
        "outbound_request_rejected",
        "对端拒绝请求：请求内容不合规，重试没有意义",
    ),
    FailureCategory.PAYLOAD_INVALID: (
        False,
        "error",
        "outbound_payload_invalid",
        "请求体本地校验不过：不外发",
    ),
    FailureCategory.RESPONSE_INVALID: (
        False,
        "error",
        "outbound_response_invalid",
        "对端响应结构不对：不能当成成功",
    ),
    FailureCategory.CLIENT_ERROR: (
        False,
        "error",
        "outbound_client_error",
        "本地调用异常：不是对端的问题",
    ),
    FailureCategory.SERVER_ERROR: (
        True,
        "error",
        "outbound_server_error",
        "对端服务端错误（5xx）：可退避重试",
    ),
    FailureCategory.TIMEOUT: (
        True,
        "warning",
        "outbound_timeout",
        "出站调用超时：可退避重试",
    ),
    FailureCategory.CONNECTION_ERROR: (
        True,
        "warning",
        "outbound_unreachable",
        "出站通道连不上：可退避重试",
    ),
}

#: 平台通道：这些类别一律把批次挂到「等重投」，等人修好再投一次。
_RESEARCH_PARK_CATEGORIES = frozenset(
    {
        FailureCategory.AUTH_FAILED,
        FailureCategory.ENDPOINT_UNCONFIGURED,
        FailureCategory.REQUEST_REJECTED,
        FailureCategory.PAYLOAD_INVALID,
        FailureCategory.RESPONSE_INVALID,
        FailureCategory.CLIENT_ERROR,
        FailureCategory.SERVER_ERROR,
        FailureCategory.TIMEOUT,
        FailureCategory.CONNECTION_ERROR,
    }
)

#: 主索引通道：这些类别把批次挂起 —— 身份锚定不可信时不得继续脱敏。
_HIS_SUSPEND_CATEGORIES = frozenset(
    {
        FailureCategory.AUTH_FAILED,
        FailureCategory.ENDPOINT_UNCONFIGURED,
        FailureCategory.SERVER_ERROR,
        FailureCategory.TIMEOUT,
        FailureCategory.CONNECTION_ERROR,
    }
)


def classify_status(status: int) -> FailureCategory | None:
    """按 HTTP 状态码分类。

    :param status: 对端返回的状态码；0 表示压根没拿到响应。
    :return: 失败类别；**2xx 返回 None**（不是失败）。
    """
    code = int(status or 0)
    if 200 <= code < 300:
        return None
    if code in (401, 403):
        return FailureCategory.AUTH_FAILED
    if code >= 500:
        return FailureCategory.SERVER_ERROR
    if code >= 400:
        return FailureCategory.REQUEST_REJECTED
    if code == 0:
        return FailureCategory.CONNECTION_ERROR
    return FailureCategory.REQUEST_REJECTED


def classify_exception(exc: BaseException) -> FailureCategory:
    """按异常类型分类。

    认得两类来源：``httpx`` 的传输异常，以及已经带好类别的出站错误
    （鸭子类型读 ``category`` 属性 —— 这样本模块不必反向依赖
    :mod:`research_redact.outbound.errors`，导入关系才不会绕成环）。

    :param exc: 捕获到的异常。
    """
    import httpx  # 局部导入：分类模块本身不该把 httpx 拉进导入链

    if isinstance(exc, httpx.TimeoutException):
        return FailureCategory.TIMEOUT
    if isinstance(exc, httpx.TransportError):
        return FailureCategory.CONNECTION_ERROR
    if isinstance(exc, httpx.HTTPError):
        return FailureCategory.CONNECTION_ERROR

    category = getattr(exc, "category", None)
    if isinstance(category, FailureCategory):
        return category
    if isinstance(category, str):
        try:
            return FailureCategory(category)
        except ValueError:
            pass
    return FailureCategory.CLIENT_ERROR


def decide_failure(
    category: FailureCategory, *, channel: str = ""
) -> FailureDecision:
    """把失败类别裁决成处置口径。

    :param category: 失败类别。
    :param channel: 通道名（``his-patient-index`` / ``research-platform``）。
    :return: 处置裁决（可重试与否 + 批次状态 + 告警级别与告警码）。
    """
    retryable, level, code, summary = _CATEGORY_TABLE[category]

    batch_state = ""
    if channel == CHANNEL_HIS:
        if category in _HIS_SUSPEND_CATEGORIES:
            batch_state = "suspended"
    elif channel == CHANNEL_RESEARCH:
        if category in _RESEARCH_PARK_CATEGORIES:
            batch_state = "pending_delivery"

    return FailureDecision(
        category=category,
        retryable=retryable,
        batch_state=batch_state,
        alert_level=level,
        alert_code=code,
        summary=summary,
    )
