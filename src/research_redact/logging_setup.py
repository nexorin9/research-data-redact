"""结构化运行日志：守护进程与运维 CLI 共用的 JSON 日志装配。

守护进程常驻在信息科的服务器上，出问题时没人守在旁边看屏幕 —— 排查只能靠
日志。所以日志这一层得先立住三件事：

1. **字段固定**：每条日志都带齐 8 个标准字段（时间 / 级别 / 事件 / 批次号 /
   材料数 / 状态 / 耗时 / 错误码）。不适用时写 ``null``，而不是「这一条没有
   这个字段」—— 后者会让按字段筛日志的脚本时灵时不灵。
2. **一行一条**：JSONL（每行一个 JSON 对象）。可以直接 ``grep``、可以直接
   ``jq``、可以直接被日志采集器收走。
3. **同一份实现**：守护进程与运维 CLI 都调这里，两边看到的字段口径一致；
   交差时「守护进程打的日志」与「CLI 打的日志」能对得上。

**纪律**：日志不含命中原文。批次号、材料数、状态、耗时、错误码都不是患者
数据；错误文案只写异常类型与消息（异常消息本身就不带患者原文 —— 命中原文
只在命中清单里，而清单不记原文）。

用法::

    from research_redact.logging_setup import Stopwatch, emit

    with Stopwatch() as watch:
        result = runner.process(application)
    emit(
        "batch_processed",
        batch_no=result.batch_no,
        materials=result.materials,
        state=result.state,
        duration_ms=watch.ms,
    )
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, IO, Mapping

__all__ = [
    "STANDARD_FIELDS",
    "Stopwatch",
    "StructuredLogger",
    "build_record",
    "default_logger",
    "describe_error",
    "emit",
    "error_code_for",
]


#: 每条日志都带齐的标准字段（顺序即 JSON 里的键序，便于人眼扫）。
STANDARD_FIELDS: tuple[str, ...] = (
    "ts",          # 时间（UTC，ISO 8601，毫秒精度）
    "level",       # 级别（info / warning / error）
    "event",       # 事件名（daemon_started / batch_processed / heartbeat …）
    "batch_no",    # 批次号（申请单号）
    "materials",   # 材料数
    "state",       # 批次状态
    "duration_ms", # 耗时（毫秒）
    "error_code",  # 错误码
)

#: 异常类型 → 错误码。取不到更细的分类时按异常类型兜底。
_ERROR_CODES: dict[str, str] = {
    "ApplicationParseError": "application_parse_failed",
    "ApplicationError": "application_invalid",
    "BlockedApplicationError": "application_blocked",
    "ChannelSuspendedError": "channel_suspended",
    "DeliveryError": "delivery_failed",
    "IllegalTransitionError": "illegal_transition",
    "IndexDecryptError": "index_decrypt_failed",
    "IndexFileMissingError": "index_store_unreachable",
    "MappingIndexUnavailableError": "mapping_index_unreachable",
    "OutboundError": "outbound_failed",
    "PseudonymKeyError": "pseudonym_key_missing",
    "RestoreTokenNotFoundError": "restore_token_not_found",
    "TransitionRejectedError": "transition_rejected",
}


def build_record(
    event: str,
    *,
    level: str = "info",
    batch_no: str | None = None,
    materials: int | None = None,
    state: str | None = None,
    duration_ms: float | None = None,
    error_code: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """装配一条结构化日志记录。

    8 个标准字段**恒定存在**（不适用写 ``None``），额外字段追加在后面。
    同一个键不会被传两遍 —— 额外字段里若出现标准字段名，以标准字段为准。
    """
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "level": level,
        "event": event,
        "batch_no": batch_no,
        "materials": materials,
        "state": state,
        "duration_ms": duration_ms,
        "error_code": error_code,
    }
    for key, value in extra.items():
        if key in record:
            continue
        record[key] = value
    return record


class StructuredLogger:
    """JSONL 日志出口。

    :param stream: 写到哪里；缺省取 ``sys.stdout``（**每次写的时候现取**，
        这样测试里替换 ``sys.stdout`` 也能收得到）。
    :param base: 每条日志都带上的公共字段（如进程号、主机名）。
    """

    def __init__(
        self,
        stream: IO[str] | None = None,
        *,
        base: Mapping[str, Any] | None = None,
    ) -> None:
        self._stream = stream
        self.base: dict[str, Any] = dict(base or {})

    @property
    def stream(self) -> IO[str]:
        """当前输出流（未显式指定时取 ``sys.stdout``）。"""
        return self._stream if self._stream is not None else sys.stdout

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        """打一条日志，返回这条记录本身（便于调用方断言字段齐备）。"""
        record = build_record(event, **fields)
        if self.base:
            record = {**self.base, **record}
        line = json.dumps(record, ensure_ascii=False, default=str)
        self.stream.write(line + "\n")
        try:
            self.stream.flush()
        except (OSError, ValueError):  # pragma: no cover - 流已关闭
            pass
        return record

    def __call__(self, event: str, **fields: Any) -> dict[str, Any]:
        """``logger("event", ...)`` 与 ``logger.emit("event", ...)`` 等价。"""
        return self.emit(event, **fields)


_DEFAULT_LOGGER = StructuredLogger()


def default_logger() -> StructuredLogger:
    """进程级默认日志出口（写 stdout）。"""
    return _DEFAULT_LOGGER


def emit(event: str, **fields: Any) -> dict[str, Any]:
    """打一条结构化日志（模块级快捷方式，走默认出口）。"""
    return _DEFAULT_LOGGER.emit(event, **fields)


class Stopwatch:
    """测一段代码的耗时。

    ::

        with Stopwatch() as watch:
            do_work()
        emit("batch_processed", duration_ms=watch.ms)
    """

    def __init__(self) -> None:
        self._start = time.monotonic()

    def __enter__(self) -> "Stopwatch":
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    @property
    def ms(self) -> float:
        """已过去的毫秒数（保留 3 位小数）。"""
        return round((time.monotonic() - self._start) * 1000, 3)


def error_code_for(exc: BaseException) -> str:
    """异常 → 错误码。

    出站异常自带失败类别（``timeout`` / ``auth_failed`` / ``server_error`` …），
    优先用那个 —— 细过按类型猜。取不到再按异常类型兜底，最后落到
    ``internal_error``。
    """
    category = getattr(exc, "category", None)
    if category is not None:
        value = getattr(category, "value", category)
        text = str(value).strip()
        if text:
            return text
    return _ERROR_CODES.get(type(exc).__name__, "internal_error")


def describe_error(exc: BaseException) -> str:
    """一句人话说明（异常类型 + 消息）。"""
    return f"{type(exc).__name__}: {exc}"
