"""守护进程运行配置：全部从环境变量读，缺省值写在代码里。

配置项与 ``.env.example`` 一一对应（不新增第二套环境变量名）：

===========================  ==================================  ============
环境变量                     含义                                缺省
===========================  ==================================  ============
``RESEARCH_DELIVERY_DIR``   科研交付目录（守护进程监听）        ``./var/inbox``
``RESEARCH_OUTPUT_DIR``     脱敏产物与命中清单输出目录          ``./var/outbox``
``RESEARCH_LEDGER_DB``      SQLite 批次台账路径                 项目内 ``var/ledger.sqlite3``
``RESEARCH_ALERT_LEDGER``   批次告警台账路径（JSONL）           项目内 ``var/alerts.jsonl``
``RESEARCH_POLL_INTERVAL``  目录轮询间隔（秒）                  2.0
``RESEARCH_HEARTBEAT_INTERVAL``  心跳间隔（秒）                  30.0
``RESEARCH_DELIVERY_MAX_RETRIES``  投递最多退避重试次数          2
``RESEARCH_DELIVERY_BACKOFF``     退避基准（秒）                2.0
===========================  ==================================  ============
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..audit.alerts import default_alert_ledger_path
from ..audit.ledger import default_ledger_path

__all__ = ["DaemonSettings", "DELIVERY_DIR_ENV", "OUTPUT_DIR_ENV"]

DELIVERY_DIR_ENV = "RESEARCH_DELIVERY_DIR"
OUTPUT_DIR_ENV = "RESEARCH_OUTPUT_DIR"

_DEFAULT_DELIVERY_DIR = Path("var") / "inbox"
_DEFAULT_OUTPUT_DIR = Path("var") / "outbox"


@dataclass(frozen=True)
class DaemonSettings:
    """守护进程的一次性配置快照。"""

    delivery_dir: Path
    output_dir: Path
    ledger_path: Path
    alert_ledger_path: Path
    poll_interval: float = 2.0
    heartbeat_interval: float = 30.0
    delivery_max_retries: int = 2
    delivery_backoff_base: float = 2.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "DaemonSettings":
        """从环境变量装配配置。

        数值项写错（不是数字 / 负数）时**报错**，不静默取缺省值 —— 轮询间隔
        被写成 ``abc`` 却默默用 2 秒跑起来，排查起来很费劲。
        """
        source = os.environ if env is None else env
        return cls(
            delivery_dir=_path(source.get(DELIVERY_DIR_ENV), _DEFAULT_DELIVERY_DIR),
            output_dir=_path(source.get(OUTPUT_DIR_ENV), _DEFAULT_OUTPUT_DIR),
            ledger_path=_path(source.get("RESEARCH_LEDGER_DB"), default_ledger_path()),
            alert_ledger_path=_path(
                source.get("RESEARCH_ALERT_LEDGER"), default_alert_ledger_path()
            ),
            poll_interval=_number(source.get("RESEARCH_POLL_INTERVAL"), 2.0, minimum=0.05),
            heartbeat_interval=_number(
                source.get("RESEARCH_HEARTBEAT_INTERVAL"), 30.0, minimum=0.05
            ),
            delivery_max_retries=int(
                _number(source.get("RESEARCH_DELIVERY_MAX_RETRIES"), 2.0, minimum=0.0)
            ),
            delivery_backoff_base=_number(
                source.get("RESEARCH_DELIVERY_BACKOFF"), 2.0, minimum=0.0
            ),
        )


def _path(value: str | None, default: Path) -> Path:
    """环境变量 → 路径；空值走缺省。"""
    text = (value or "").strip()
    return Path(text).expanduser() if text else default


def _number(value: str | None, default: float, *, minimum: float) -> float:
    """环境变量 → 数值；非法或越界时报错。"""
    text = (value or "").strip()
    if not text:
        return default
    try:
        number = float(text)
    except ValueError as exc:
        raise ValueError(f"配置项不是合法数字：{text!r}") from exc
    if number < minimum:
        raise ValueError(f"配置项不得小于 {minimum}：{text!r}")
    return number
