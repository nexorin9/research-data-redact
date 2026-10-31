"""出站调用的错误类型。

出站调用失败的原因分三类，对应的处理完全不同：

1. **通道没配**（:class:`ChannelSuspendedError`）—— 端点或凭据缺失。这不是
   事故，是部署没做完：通道置挂起并告警，**不外发**，也**不退回本地替身**。
2. **对端说不行**（4xx）—— 请求本身有问题，重试没有意义。
3. **对端没准备好**（5xx / 超时 / 连接失败）—— 可以退避重试。

:class:`OutboundError` 带上 ``status`` 与 ``retryable``，让上层（待投递队列）
能按错误分类决定「退避重试」还是「立刻挂起」，而不是把所有失败一锅脑地
重试三遍。
"""

from __future__ import annotations

from dataclasses import replace

from .failures import (
    FailureCategory,
    FailureDecision,
    classify_status,
    decide_failure,
)

__all__ = [
    "ChannelSuspendedError",
    "OutboundError",
]


class OutboundError(RuntimeError):
    """出站调用失败。

    :param message: 失败原因（写进告警文案，**不含患者原文**）。
    :param status: 对端返回的 HTTP 状态码；未拿到响应时为 0。
    :param channel: 通道名（``his-patient-index`` / ``research-platform`` …）。
    :param retryable: 是否值得退避重试。4xx、通道未配置都是 False。给了
        ``category`` 时由类别裁决；没给时按状态码推导。
    :param category: 失败类别（:class:`~research_redact.outbound.failures.FailureCategory`）；
        给了就以它为准，错误分类与处置口径只有一处说了算。
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        channel: str = "",
        retryable: bool | None = None,
        category: FailureCategory | str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.channel = channel
        self._explicit_retryable = retryable
        self.category = _as_category(category)
        if self.category is None:
            self.category = _category_from_status(status)
        decision = decide_failure(self.category, channel=channel)
        self.retryable = decision.retryable if retryable is None else bool(retryable)

    @property
    def decision(self) -> FailureDecision:
        """这个错误的处置裁决（可重试与否 + 批次状态 + 告警级别与告警码）。

        显式指定过 ``retryable`` 的错误尊重调用方的判断 —— 「住院号为空」
        这类本地校验失败不该被当成「连不上」而反复重试。
        """
        decision = decide_failure(self.category, channel=self.channel)
        if (
            self._explicit_retryable is not None
            and decision.retryable != self._explicit_retryable
        ):
            decision = replace(decision, retryable=self._explicit_retryable)
        return decision

    def describe(self) -> str:
        """一句人话说明（带状态码），供告警文案使用。"""
        base = str(self)
        if self.status:
            return f"{base}（HTTP {self.status}）"
        return base


class ChannelSuspendedError(OutboundError):
    """通道未配置：端点或凭据缺失，该通道置挂起。

    抛出这个错的客户端**不会发出任何 HTTP 请求** —— 「没配置」不是「失败了
    就当成功」，也不是「悄悄换成本地替身跑一遍」。
    """

    def __init__(self, message: str, *, channel: str = "") -> None:
        super().__init__(
            message,
            status=0,
            channel=channel,
            category=FailureCategory.ENDPOINT_UNCONFIGURED,
        )


def _as_category(value: FailureCategory | str | None) -> FailureCategory | None:
    """类别入参 → :class:`FailureCategory`（字符串按枚举值解析）。"""
    if value is None:
        return None
    if isinstance(value, FailureCategory):
        return value
    try:
        return FailureCategory(str(value))
    except ValueError as exc:
        raise ValueError(f"未知的出站失败类别：{value!r}") from exc


def _category_from_status(status: int) -> FailureCategory:
    """没有显式类别时，按状态码推导一个类别。

    2xx 不该出现在失败路径上；真出现了，按「响应结构不对」处理 —— 不能把
    一个说不清道不明的响应当成成功。
    """
    category = classify_status(status)
    if category is None:
        return FailureCategory.RESPONSE_INVALID
    return category
