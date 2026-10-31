"""批次告警台账与推送出口。

残留自检（:mod:`research_redact.audit.residual`）发现身份类残留时，需要两件事：

1. **落一条可查的记录** —— 伦理办与信息科事后要看得见「哪一批被拦下、拦下
   几处、涉及哪些材料、为什么」；
2. **推一次出去** —— 值班的人不该等到下次巡检才发现有一批没交出去。

本模块把这两件事收敛成两个协议：

- :class:`AlertSink` —— 落点。默认实现是 JSONL 追加台账
  （:class:`JsonlAlertSink`）；task 10 的 SQLite 批次台账会实现同一协议接管落点。
- :class:`AlertNotifier` —— 推送出口。task 12 的企业微信客户端实现同一协议。

**纪律**：通道没配置就说没配置。默认通知器 :class:`PendingNotifier` 明确返回
「没推出去」，并把通道状态写进告警记录 —— 不静默指向本地替身，也不假装推过。

**不变量**：告警记录**不含命中原文**。记录只有批次号、条数、类别、材料 ID 与
一句人话说明；被脱敏的那段值一个字符都不落盘（与命中清单同一红线）。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..models import utcnow

__all__ = [
    "ALERT_LEDGER_ENV",
    "AlertNotifier",
    "AlertSink",
    "BatchAlert",
    "JsonlAlertSink",
    "PendingNotifier",
    "RecordingAlertSink",
    "RecordingNotifier",
    "default_alert_ledger_path",
]


#: 批次告警台账默认位置：项目根目录下的 var/alerts.jsonl（运行时数据，不进版本库）
_DEFAULT_LEDGER_RELATIVE = ("var", "alerts.jsonl")

#: 环境变量：批次告警台账路径（.env.example 里的 RESEARCH_ALERT_LEDGER）
ALERT_LEDGER_ENV = "RESEARCH_ALERT_LEDGER"


def default_alert_ledger_path() -> Path:
    """批次告警台账默认路径：项目根目录下的 ``var/alerts.jsonl``。

    环境变量 ``$RESEARCH_ALERT_LEDGER`` 优先 —— 守护进程与运维 CLI 跑在不同
    工作目录下时，台账不该散在各处。
    """
    env_value = os.environ.get(ALERT_LEDGER_ENV)
    if env_value:
        return Path(env_value)
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent.joinpath(*_DEFAULT_LEDGER_RELATIVE)
        if candidate.parent.is_dir():
            return candidate
    root = here.parents[3] if len(here.parents) > 3 else here.parent
    return root.joinpath(*_DEFAULT_LEDGER_RELATIVE)


@dataclass(frozen=True)
class BatchAlert:
    """一条批次告警（**不含命中原文**）。

    :param batch_no: 批次号（申请单号）。
    :param code: 告警码（如 ``residual_identity``），供程序按码分流。
    :param level: 告警级别（``warning`` / ``error``）。
    :param count: 触发告警的条数（残留自检里是身份类残留处数）。
    :param message: 一句人话说明（写给人看，也写给企业微信推送用）。
    :param material_ids: 涉及的材料 ID。
    :param notified: 是否真的推送出去了。
    :param notify_channel: 推送通道名（``wecom`` / ``pending`` …）。
    :param created_at: 记录时间。
    """

    batch_no: str
    code: str
    level: str
    count: int
    message: str
    material_ids: tuple[str, ...] = ()
    notified: bool = False
    notify_channel: str = ""
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, object]:
        """转成可落盘 / 可推送的一行。"""
        return {
            "batch_no": self.batch_no,
            "code": self.code,
            "level": self.level,
            "count": self.count,
            "message": self.message,
            "material_ids": list(self.material_ids),
            "notified": self.notified,
            "notify_channel": self.notify_channel,
            "created_at": self.created_at.isoformat(),
        }


@runtime_checkable
class AlertSink(Protocol):
    """批次告警的落点。"""

    def record(self, alert: BatchAlert) -> None:
        """落一条告警记录。"""


@runtime_checkable
class AlertNotifier(Protocol):
    """告警推送出口（企业微信等）。"""

    #: 通道名：写进告警记录，让「推没推出去」可核对。
    channel: str

    def notify(self, message: str, *, batch_no: str) -> bool:
        """推送一条告警；返回是否真的推出去了。"""


class PendingNotifier:
    """未配置推送通道时的占位实现。

    明确返回「没推出去」，让告警记录里的 ``notified`` 为 False、
    ``notify_channel`` 为 ``pending`` —— **不静默指向本地替身，也不假装推过**。
    真实的企业微信客户端由 task 12 落地，实现同一个协议。
    """

    channel = "pending"

    def notify(self, message: str, *, batch_no: str) -> bool:
        """不推送，直接返回 False（通道未配置）。"""
        return False


class RecordingNotifier:
    """把推送内容记在内存里的通知器（测试与本地排查用）。"""

    channel = "recording"

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def notify(self, message: str, *, batch_no: str) -> bool:
        self.messages.append((batch_no, message))
        return True


class JsonlAlertSink:
    """批次告警台账（JSONL 追加，一行一条）。

    追加而非覆盖：同一批可能反复触发告警（重投、续跑），历史记录要留得住。
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_alert_ledger_path()

    def record(self, alert: BatchAlert) -> None:
        """追加一条告警记录。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")

    @staticmethod
    def read(path: str | Path) -> list[dict[str, object]]:
        """读回台账（每行一个 JSON 对象）。"""
        records: list[dict[str, object]] = []
        target = Path(path)
        if not target.is_file():
            return records
        with target.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
        return records


class RecordingAlertSink:
    """把告警记在内存里的落点（测试用）。"""

    def __init__(self) -> None:
        self.alerts: list[BatchAlert] = []

    def record(self, alert: BatchAlert) -> None:
        self.alerts.append(alert)
