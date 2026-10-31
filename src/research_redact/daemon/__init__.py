"""daemon 子包：事件驱动守护（常驻进程）+ 与之共用的批次处理主路径。

模块分工：

- :mod:`research_redact.daemon.pipeline` —— **脱敏主路径**（识别 → 处置 →
  命中清单 → 残留自检）。守护进程与运维 CLI 都调它，全项目只有这一处。
- :mod:`research_redact.daemon.state_machine` —— 批次状态机（10 态 + 守卫）。
- :mod:`research_redact.daemon.watcher` —— 交付目录监听（新增 / 修改事件 +
  定时兜底扫描）。
- :mod:`research_redact.daemon.runner` —— 批次处理（入站 → 脱敏 → 残留自检
  → 落产物 → 投递载荷）。
- :mod:`research_redact.daemon.queue` —— 待投递队列（指数退避重试，超次挂起）。
- :mod:`research_redact.daemon.settings` —— 运行配置（全部来自环境变量）。
- :mod:`research_redact.daemon.__main__` —— 常驻入口
  ``python -m research_redact.daemon``。

本包的导出用**惰性加载**（PEP 562）：``audit.ledger`` 反过来依赖本包的
``state_machine``，若在这里 eagerly import 各子模块就会绕成循环导入。
按需 ``from research_redact.daemon import BatchRunner`` 照样能用。
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "BatchRunResult",
    "BatchRunner",
    "DaemonSettings",
    "DeliveryError",
    "DeliveryOutcome",
    "DeliveryQueue",
    "InboxApplication",
    "InboxWatcher",
]

_LAZY = {
    "BatchRunResult": ("research_redact.daemon.runner", "BatchRunResult"),
    "BatchRunner": ("research_redact.daemon.runner", "BatchRunner"),
    "DaemonSettings": ("research_redact.daemon.settings", "DaemonSettings"),
    "DeliveryError": ("research_redact.daemon.queue", "DeliveryError"),
    "DeliveryOutcome": ("research_redact.daemon.queue", "DeliveryOutcome"),
    "DeliveryQueue": ("research_redact.daemon.queue", "DeliveryQueue"),
    "InboxApplication": ("research_redact.daemon.watcher", "InboxApplication"),
    "InboxWatcher": ("research_redact.daemon.watcher", "InboxWatcher"),
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
