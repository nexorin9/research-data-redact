"""常驻入口：``python -m research_redact.daemon``。

这是本轮锁定的交付形态 —— **事件驱动守护**：进程常驻，盯着科研交付目录，
管理员把一批材料放进目录就自动跑完「身份锚定 → 脱敏 → 残留自检 → 投递」，
并持续打心跳，供信息科判断「有没有积压、哪个批次卡住了」。

守护进程与运维 CLI 共用同一条脱敏主路径
(:mod:`research_redact.daemon.pipeline`) 和同一张批次台账
(:mod:`research_redact.audit.ledger`)：CLI 是运维通道，守护进程是常驻通道，
**不各写一份处理逻辑**。

一轮循环做四件事：

1. **事件轮询**：交付目录里新增或内容有改动的申请单 → 立即处理。
2. **兜底扫描**：把交付目录整个扫一遍，捡回上一轮漏掉 / 中途崩了的批次。
   已交付的批次不会重复处理（按台账状态判定）。
3. **投递重试**：到点的待投递批次重投；退避超次的已挂起并推送。
4. **心跳**：打印一行结构化运行日志，说明进程存活、队列长度与最近批次状态。

用法::

    RESEARCH_DELIVERY_DIR=./var/inbox python -m research_redact.daemon
    python -m research_redact.daemon --once        # 跑一轮就退出（自检用）
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import Any

from ..audit.ledger import BatchLedger
from ..logging_setup import Stopwatch, describe_error
from ..logging_setup import emit as _emit
from ..logging_setup import error_code_for
from . import ops
from .settings import DaemonSettings
from .watcher import InboxWatcher

__all__ = ["build_parser", "main", "run"]


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="research-redact-daemon",
        description="科研影像数据脱敏系统 · 常驻守护进程",
    )
    parser.add_argument(
        "--delivery-dir",
        dest="delivery_dir",
        default=None,
        help="科研交付目录（缺省取 $RESEARCH_DELIVERY_DIR）",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="脱敏产物与命中清单输出目录（缺省取 $RESEARCH_OUTPUT_DIR）",
    )
    parser.add_argument(
        "--ledger",
        dest="ledger",
        default=None,
        help="SQLite 批次台账路径（缺省取 $RESEARCH_LEDGER_DB）",
    )
    parser.add_argument(
        "--poll-interval",
        dest="poll_interval",
        type=float,
        default=None,
        help="目录轮询间隔（秒）",
    )
    parser.add_argument(
        "--heartbeat-interval",
        dest="heartbeat_interval",
        type=float,
        default=None,
        help="心跳间隔（秒）",
    )
    parser.add_argument(
        "--once",
        dest="once",
        action="store_true",
        help="只跑一轮就退出（自检 / 冒烟用）",
    )
    parser.add_argument(
        "--cycles",
        dest="cycles",
        type=int,
        default=0,
        help="跑多少轮就退出（0 = 常驻；配合 --once 只需跑一轮）",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """守护进程入口。正常退出返回 0。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = _settings_from_args(args)
    cycles = 1 if args.once else (args.cycles or None)
    try:
        summary = run(settings, cycles=cycles)
    except KeyboardInterrupt:  # pragma: no cover - 交互中断
        emit("daemon_stopped", reason="keyboard_interrupt")
        return 0
    return 0 if summary.get("errors", 0) == 0 else 1


def run(
    settings: DaemonSettings,
    *,
    cycles: int | None = None,
    stop: Any | None = None,
    deliver: Any | None = None,
) -> dict[str, Any]:
    """跑守护循环。

    :param settings: 运行配置。
    :param cycles: 跑多少轮就停；``None`` = 常驻直到收到停止信号。
    :param stop: 停止判据（``() -> bool``）；收到信号后置位。
    :param deliver: 投递出口覆盖（测试用）；缺省接科研数据平台客户端。
    :return: 本次运行的汇总（处理批次数、投递数、队列长度、错误数）。
    """
    watcher = InboxWatcher(settings.delivery_dir)
    # 启动前就躺在目录里的申请单不算「刚落盘的事件」：由兜底扫描按台账状态接手，
    # 免得进程一重启就把历史批次当新事件重跑一遍。
    watcher.prime()
    # 运行时装配只有一份实现（daemon/ops.py）—— 运维 CLI 的子命令也调它，
    # 两条触发通道共用同一张台账、同一套脱敏主路径。
    runtime = ops.build_runtime(settings, deliver=deliver)
    ledger = runtime.ledger
    notifier = runtime.notifier
    platform = runtime.platform
    queue = runtime.queue
    runner = runtime.runner

    summary: dict[str, Any] = {
        "cycles": 0,
        "processed": 0,
        "delivered": 0,
        "parked": 0,
        "skipped": 0,
        "errors": 0,
    }
    # 最近一个批次的号与状态：心跳要报出来 —— 信息科排查积压时，先要知道
    # 「最后动的是哪一批、它停在哪个状态」，而不是只看队列长度。
    latest = _LatestBatch()

    emit(
        "daemon_started",
        delivery_dir=str(settings.delivery_dir),
        output_dir=str(settings.output_dir),
        ledger=str(settings.ledger_path),
        notify_channel=getattr(notifier, "channel", "pending"),
        poll_interval=settings.poll_interval,
    )
    _report_suspended_channels(ledger, platform)

    # 上一轮进程退出时还在「已代号化、没交付」的批次：重新进队列补投。
    # 队列是进程内的，不补这一手，重启就会把待交付的批次悄悄丢掉。
    for batch_no, payload in _pending_deliveries(ledger):
        outcome = queue.submit(batch_no, payload)
        if outcome.delivered:
            summary["delivered"] += 1
        elif outcome.exhausted:
            summary["parked"] += 1
        emit(
            "delivery_resumed",
            batch_no=batch_no,
            delivered=outcome.delivered,
            reason=outcome.reason,
        )

    last_heartbeat = 0.0
    try:
        while True:
            summary["cycles"] += 1
            _run_cycle(watcher, runner, queue, summary, latest)

            now = time.monotonic()
            if now - last_heartbeat >= settings.heartbeat_interval:
                last_heartbeat = now
                emit(
                    "heartbeat",
                    cycles=summary["cycles"],
                    queue=len(queue),
                    pending_batches=[
                        item.batch_no for item in queue.pending()
                    ],
                    batch_no=latest.batch_no or None,
                    state=latest.state or None,
                    delivered=summary["delivered"],
                    errors=summary["errors"],
                )

            if cycles is not None and summary["cycles"] >= cycles:
                break
            if stop is not None and stop():
                break
            time.sleep(settings.poll_interval)
    finally:
        ledger.close()
        emit("daemon_stopped", **{k: v for k, v in summary.items()})
    return summary


def _run_cycle(
    watcher: InboxWatcher,
    runner: Any,
    queue: Any,
    summary: dict[str, Any],
    latest: "_LatestBatch",
) -> None:
    """跑一轮：事件处理 → 兜底扫描 → 投递重试。"""
    seen: set[str] = set()
    for application in watcher.poll():
        seen.add(application.application_no)
        _handle(runner, queue, application, via_event=True, summary=summary, latest=latest)
    # 队列里正等着重投的批次由队列管，兜底扫描不再去碰它（免得每轮都刷一遍跳过日志）
    queued = {item.batch_no for item in queue.pending()}
    for application in watcher.applications():
        if application.application_no in seen or application.application_no in queued:
            continue
        _handle(runner, queue, application, via_event=False, summary=summary, latest=latest)
    for outcome in queue.run_due():
        if outcome.delivered:
            summary["delivered"] += 1
        elif outcome.exhausted:
            summary["parked"] += 1
            emit("delivery_parked", batch_no=outcome.batch_no, reason=outcome.reason)


def _handle(
    runner: Any,
    queue: Any,
    application: Any,
    *,
    via_event: bool,
    summary: dict[str, Any],
    latest: "_LatestBatch",
) -> None:
    """处理一份申请单并把可交付的批次送进投递队列。"""
    with Stopwatch() as watch:
        try:
            result = runner.process(application, via_event=via_event)
        except Exception as exc:  # 守护进程不能因为一份坏材料就退出
            summary["errors"] += 1
            emit(
                "batch_error",
                level="error",
                batch_no=application.application_no,
                duration_ms=watch.ms,
                error_code=error_code_for(exc),
                error=describe_error(exc),
            )
            return
    if result.skipped:
        summary["skipped"] += 1
        latest.note(result.batch_no, result.state)
        emit(
            "batch_skipped",
            batch_no=result.batch_no,
            state=result.state,
            duration_ms=watch.ms,
            reason=result.note,
        )
        return
    if not result.processed:
        return
    summary["processed"] += 1
    latest.note(result.batch_no, result.state)
    emit(
        "batch_processed",
        batch_no=result.batch_no,
        materials=result.materials,
        state=result.state,
        duration_ms=watch.ms,
        entries=result.entries,
        residual=result.residual,
        deliverable=result.deliverable,
    )
    if not result.deliverable:
        summary["errors"] += 1
        emit(
            "batch_not_deliverable",
            level="warning",
            batch_no=result.batch_no,
            materials=result.materials,
            state=result.state,
            duration_ms=watch.ms,
            error_code="residual_identity",
            reason=result.residual,
        )
        return
    outcome = queue.submit(result.batch_no, result.payload)
    if outcome.delivered:
        summary["delivered"] += 1
    elif outcome.exhausted:
        summary["parked"] += 1
    else:
        emit(
            "delivery_deferred",
            batch_no=outcome.batch_no,
            attempts=outcome.attempts,
            reason=outcome.reason,
        )


class _LatestBatch:
    """记住最近动过的批次号与状态（心跳报出来用）。

    信息科排查积压时，光看「队列里有几批」不够 —— 还要知道**最后动的是哪一批、
    它停在哪个状态**。心跳里把这行带上，终端一眼能看出进程还在干活还是卡住。
    """

    def __init__(self) -> None:
        self.batch_no = ""
        self.state = ""

    def note(self, batch_no: str, state: str) -> None:
        """记一笔最近批次。"""
        self.batch_no = batch_no or self.batch_no
        self.state = state or self.state


def _pending_deliveries(ledger: BatchLedger) -> list[tuple[str, dict[str, object]]]:
    """台账里「已代号化、尚未交付」的批次 → 补投载荷。

    实现已挪到 :mod:`research_redact.daemon.ops`（运维 CLI 的 ``deliver``
    子命令走同一份）；这里保留这个名字只是为了不打断既有调用点。
    """
    return ops.pending_deliveries(ledger)


def _report_suspended_channels(ledger: Any, platform: Any) -> None:
    """出站通道没配齐时，启动即挂起 + 告警（不等到第一批撞上才说）。

    只在真有通道挂着的时候才发声 —— 部署齐了就不刷屏。
    """
    from ..config import OutboundConfig

    config = OutboundConfig.from_env()
    suspended = config.suspended_channels()
    if not suspended:
        return
    for channel in suspended:
        emit("channel_suspended", channel=channel.name, reason=channel.reason)
    for alert in config.alerts(batch_no="*"):
        ledger.record(alert)


def _build_checker(settings: DaemonSettings, ledger=None, notifier=None):
    """按配置装配残留自检器。

    装配实现已挪到 :mod:`research_redact.daemon.ops`（运维 CLI 的
    ``verify-residual`` 子命令走同一份）；这里保留这个名字只是为了不打断
    既有调用点。
    """
    return ops.build_checker(settings, ledger=ledger, notifier=notifier)


def _settings_from_args(args: argparse.Namespace) -> DaemonSettings:
    """命令行覆盖环境变量（与运维 CLI 共用同一份覆盖口径）。"""
    return ops.settings_from_args(args)


def emit(event: str, **fields: Any) -> dict[str, Any]:
    """打一行结构化运行日志（JSON，一行一条）。

    实现已挪到 :mod:`research_redact.logging_setup`（运维 CLI 与守护进程共用
    这一份装配 —— 两边看到的字段口径必须一致）；这里保留这个名字只是为了
    不打断既有调用点。
    """
    return _emit(event, **fields)


if __name__ == "__main__":  # pragma: no cover - 入口
    raise SystemExit(main())
