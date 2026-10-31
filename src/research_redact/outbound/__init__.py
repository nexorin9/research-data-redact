"""outbound 子包：出站对接层。

三个通道，一条纪律：**没配置就不发**。

- :mod:`research_redact.outbound.patient_index_client` —— 出站读：HIS 患者
  主索引（患者身份的权威来源）。
- :mod:`research_redact.outbound.research_platform_client` —— 出站写：科研
  数据平台（数据集交付 + 还原回执）。
- :mod:`research_redact.outbound.notifier` —— 出站推：企业微信群机器人。
- :mod:`research_redact.outbound.failures` —— 出站失败的错误码分类与处置裁决。
- :mod:`research_redact.outbound.retry` —— 出站调用的统一重试策略。

端点与凭据一律从环境变量读（见 :mod:`research_redact.config`）；缺端点或缺
凭据时对应通道置**挂起**并告警，**不指向本地替身**。

本包的导出用**惰性加载**（PEP 562）：``daemon.queue`` 需要
``outbound.errors``，若这里 eagerly import 各客户端就会绕成循环导入。
按需 ``from research_redact.outbound import ResearchPlatformClient`` 照样能用。
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "ChannelSuspendedError",
    "DatasetReceipt",
    "FailureCategory",
    "FailureDecision",
    "MaterialEntry",
    "OutboundError",
    "PatientIndexClient",
    "PatientIndexRecord",
    "ResearchPlatformClient",
    "RestoreAuditReceipt",
    "RetryPolicy",
    "WeComNotifier",
    "build_notifier",
    "call_with_retry",
    "classify_status",
    "decide_failure",
]

_LAZY = {
    "ChannelSuspendedError": (
        "research_redact.outbound.errors",
        "ChannelSuspendedError",
    ),
    "OutboundError": ("research_redact.outbound.errors", "OutboundError"),
    "FailureCategory": ("research_redact.outbound.failures", "FailureCategory"),
    "FailureDecision": ("research_redact.outbound.failures", "FailureDecision"),
    "classify_status": ("research_redact.outbound.failures", "classify_status"),
    "decide_failure": ("research_redact.outbound.failures", "decide_failure"),
    "RetryPolicy": ("research_redact.outbound.retry", "RetryPolicy"),
    "call_with_retry": ("research_redact.outbound.retry", "call_with_retry"),
    "PatientIndexClient": (
        "research_redact.outbound.patient_index_client",
        "PatientIndexClient",
    ),
    "PatientIndexRecord": (
        "research_redact.outbound.patient_index_client",
        "PatientIndexRecord",
    ),
    "ResearchPlatformClient": (
        "research_redact.outbound.research_platform_client",
        "ResearchPlatformClient",
    ),
    "DatasetReceipt": (
        "research_redact.outbound.research_platform_client",
        "DatasetReceipt",
    ),
    "MaterialEntry": (
        "research_redact.outbound.research_platform_client",
        "MaterialEntry",
    ),
    "RestoreAuditReceipt": (
        "research_redact.outbound.research_platform_client",
        "RestoreAuditReceipt",
    ),
    "WeComNotifier": ("research_redact.outbound.notifier", "WeComNotifier"),
    "build_notifier": ("research_redact.outbound.notifier", "build_notifier"),
}


def __getattr__(name: str) -> Any:
    """惰性导出：真正用到时才 import 对应子模块。"""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module = import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))
