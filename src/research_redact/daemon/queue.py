"""待投递队列：指数退避重试（≤2 次），超次置 ``pending_delivery`` 并推送。

科研数据平台偶发 5xx 是常态，不是事故。队列要做的三件事：

1. **重试**：退避重投（默认最多退避重试 2 次，即共 3 次尝试），退避间隔
   按 ``基准 × 2^(已试次数-1)`` 拉开 —— 平台抖动是短时的，密集重试只会
   加压。**只重试值得重试的失败**：连接错误、超时、5xx；4xx 与鉴权失败
   直接挂起（重试只是把同一个错再犯一遍）。
2. **超次挂起**：重试超次仍失败，批次转 ``pending_delivery``（**不静默丢弃**）：
   台账里看得见、告警台账里留得下、运维 CLI 的 ``deliver`` 子命令能重投。
   不可重试的失败**当场挂起**（不占着队列空转），告警码按错误分类给。
3. **推送**：挂起原因推给人（企业微信群机器人）。推不出去也**不算推出去** ——
   告警记录里的 ``notified`` 如实写 False。

错误分类与处置裁决在 :mod:`research_redact.outbound.failures`（唯一真源）；
队列只管**什么时候再试**与**试够了没有**，「怎么投」由投递函数决定
（守护进程默认接 :mod:`research_redact.outbound` 的科研数据平台客户端）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Mapping, Protocol

from ..audit.alerts import AlertNotifier, BatchAlert, PendingNotifier
from ..outbound.errors import OutboundError
from ..outbound.failures import FailureCategory, FailureDecision
from .state_machine import BatchEvent, BatchState, TransitionContext

if TYPE_CHECKING:  # pragma: no cover - 类型用
    from ..audit.ledger import BatchLedger

__all__ = [
    "DeliveryError",
    "DeliveryOutcome",
    "DeliveryQueue",
    "QueuedDelivery",
]


class DeliveryError(OutboundError):
    """投递失败。

    :param message: 失败原因（写进告警文案，不含患者原文）。
    :param status: 对端返回的 HTTP 状态码；未知时为 0。
    :param category: 出站失败类别；不给就按状态码推导（5xx 可重试、4xx 不可重试）。
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        category: FailureCategory | str | None = None,
    ) -> None:
        super().__init__(
            message,
            status=status,
            channel="research-platform",
            category=category,
        )


class BatchDeliverer(Protocol):
    """投递出口：把一个批次交给科研数据平台。

    实现方约定（task 12 的 ``outbound/research_platform_client.py`` 照此接入）：

    - 成功返回 True；
    - 失败抛 :class:`DeliveryError`（带 ``status``），或直接返回 False。
    """

    def deliver(self, batch_no: str, payload: Mapping[str, object]) -> bool:
        """投递一个批次；返回是否交付成功。"""
        ...


@dataclass
class QueuedDelivery:
    """队列里的一项待投递。"""

    batch_no: str
    payload: Mapping[str, object] = field(default_factory=dict)
    attempts: int = 0
    next_attempt_at: float = 0.0
    last_error: str = ""


@dataclass(frozen=True)
class DeliveryOutcome:
    """一次投递尝试的结果。"""

    batch_no: str
    attempts: int
    delivered: bool
    exhausted: bool = False
    next_attempt_in: float = 0.0
    reason: str = ""


class DeliveryQueue:
    """待投递队列。

    :param deliver: 投递函数，签名 ``(batch_no, payload) -> bool``；缺省视为
        「通道未配置」。
    :param ledger: 批次台账；用于把批次推进到 ``delivered`` /
        ``pending_delivery`` 并落持久告警。
    :param notifier: 推送出口；缺省为「未配置」占位（明确返回未推送）。
    :param max_retries: 最多退避重试几次（缺省 2，即共 3 次尝试）。
    :param backoff_base: 退避基准秒数；第 n 次失败后等 ``base × 2^(n-1)``。
    :param clock: 单调时钟（测试可注入假时钟）。
    """

    def __init__(
        self,
        *,
        deliver: Callable[[str, Mapping[str, object]], bool] | BatchDeliverer | None = None,
        ledger: BatchLedger | None = None,
        notifier: AlertNotifier | None = None,
        max_retries: int = 2,
        backoff_base: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._deliver = _as_callable(deliver)
        self._ledger = ledger
        self._notifier = notifier if notifier is not None else PendingNotifier()
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._clock = clock
        self._items: dict[str, QueuedDelivery] = {}
        self._history: list[DeliveryOutcome] = []

    # ------------------------------------------------------------------ 查询

    def __len__(self) -> int:
        """队列里待投递的批次数。"""
        return len(self._items)

    def pending(self) -> tuple[QueuedDelivery, ...]:
        """队列里的全部待投递项（按入队顺序）。"""
        return tuple(self._items.values())

    def history(self) -> tuple[DeliveryOutcome, ...]:
        """历次投递尝试的结果（供台账 / 排查用）。"""
        return tuple(self._history)

    def due(self) -> tuple[QueuedDelivery, ...]:
        """到点该重试的项。"""
        now = self._clock()
        return tuple(item for item in self._items.values() if item.next_attempt_at <= now)

    # ------------------------------------------------------------------ 入队

    def submit(self, batch_no: str, payload: Mapping[str, object] | None = None) -> DeliveryOutcome:
        """入队并**立刻试一次**（第一次尝试不算重试）。

        :param batch_no: 批次号。
        :param payload: 投递载荷（交付体字段，task 12 组装请求体时用）。
        """
        item = QueuedDelivery(batch_no=batch_no, payload=dict(payload or {}))
        self._items[batch_no] = item
        return self._attempt(item)

    def run_due(self) -> tuple[DeliveryOutcome, ...]:
        """把到点的项重试一遍，返回本轮各次尝试的结果。"""
        outcomes: list[DeliveryOutcome] = []
        for item in self.due():
            outcomes.append(self._attempt(item))
        return tuple(outcomes)

    # ------------------------------------------------------------------ 内部

    def _attempt(self, item: QueuedDelivery) -> DeliveryOutcome:
        """试一次投递：成功就出队，失败就退避重排，超次就挂起。"""
        item.attempts += 1
        error = ""
        delivered = False
        decision: FailureDecision | None = None
        try:
            delivered = bool(self._deliver(item.batch_no, item.payload))
            if not delivered:
                error = "科研数据平台未回执（投递函数返回失败）"
        except DeliveryError as exc:
            error = f"{exc}（HTTP {exc.status}）" if exc.status else str(exc)
            decision = exc.decision
        except OutboundError as exc:
            # 出站客户端自己抛的错（通道挂起 / 对端 4xx / 5xx）：带上状态码与
            # 错误分类 —— 分类决定「该不该退避重试」与「挂起时告警什么码」。
            error = exc.describe()
            decision = exc.decision
        except Exception as exc:  # 投递实现抛的异常类型杂，统一收口
            error = f"{type(exc).__name__}: {exc}"

        if delivered:
            self._mark_delivered(item.batch_no)
            self._items.pop(item.batch_no, None)
            outcome = DeliveryOutcome(
                batch_no=item.batch_no,
                attempts=item.attempts,
                delivered=True,
                reason="科研数据平台已回执：交付完成",
            )
            self._history.append(outcome)
            return outcome

        item.last_error = error
        if decision is not None and not decision.retryable:
            # **不可重试**的失败（4xx / 鉴权失败 / 端点没配 / 请求体不合格）：
            # 退避重试只会把同一个错再犯一遍 —— 直接挂起，等人修好再重投。
            outcome = self._park(item, decision, exhausted_by_retry=False)
            self._history.append(outcome)
            return outcome
        if item.attempts > self.max_retries:
            outcome = self._park(item, decision)
            self._history.append(outcome)
            return outcome

        delay = self.backoff_base * (2 ** (item.attempts - 1))
        item.next_attempt_at = self._clock() + delay
        outcome = DeliveryOutcome(
            batch_no=item.batch_no,
            attempts=item.attempts,
            delivered=False,
            next_attempt_in=delay,
            reason=f"第 {item.attempts} 次投递失败：{error}；{delay:.0f}s 后重试",
        )
        self._history.append(outcome)
        return outcome

    def _park(
        self,
        item: QueuedDelivery,
        decision: FailureDecision | None = None,
        *,
        exhausted_by_retry: bool = True,
    ) -> DeliveryOutcome:
        """挂起：批次转 ``pending_delivery``，落持久告警并推送。

        两种挂起走同一个出口，但**告警码不同**：

        - 退避重试超次 → ``delivery_exhausted``（重试过，不行）；
        - 不可重试的失败（4xx / 鉴权失败 / 端点没配）→ 按错误分类给专属告警码
          （根本没得重试，等人修配置或改请求）。
        """
        reason = item.last_error or "投递失败"
        if self._ledger is not None:
            record = self._ledger.get_batch(item.batch_no)
            if record is not None and record.batch_state is BatchState.PSEUDONYMIZED:
                self._ledger.advance(
                    item.batch_no,
                    BatchEvent.DELIVERY_FAILED,
                    TransitionContext(platform_delivered=False),
                    reason=(
                        f"投递失败退避超次（{item.attempts} 次）：{reason}"
                        if exhausted_by_retry
                        else f"投递失败（不可重试）：{reason}"
                    ),
                )
        if exhausted_by_retry:
            code = "delivery_exhausted"
            level = "error"
            message = (
                f"批次 {item.batch_no} 投递退避超次（已试 {item.attempts} 次），已挂起等重投：{reason}"
                "。请到运维通道执行 deliver 重投，或检查科研数据平台与出站通道配置。"
            )
        else:
            code = decision.alert_code if decision is not None else "delivery_rejected"
            level = decision.alert_level if decision is not None else "error"
            category = decision.category.value if decision is not None else "unknown"
            message = (
                f"批次 {item.batch_no} 投递失败且不可重试（{category}），已挂起等重投：{reason}"
                "。请检查出站通道配置与请求内容，修正后到运维通道执行 deliver 重投。"
            )
        notified = False
        try:
            notified = bool(self._notifier.notify(message, batch_no=item.batch_no))
        except Exception as exc:  # 推送失败也不能吞掉挂起这件事
            message = f"{message}（推送失败：{type(exc).__name__}）"
        if self._ledger is not None:
            self._ledger.record(
                BatchAlert(
                    batch_no=item.batch_no,
                    code=code,
                    level=level,
                    count=item.attempts,
                    message=message,
                    notified=notified,
                    notify_channel=getattr(self._notifier, "channel", "pending"),
                )
            )
        self._items.pop(item.batch_no, None)
        return DeliveryOutcome(
            batch_no=item.batch_no,
            attempts=item.attempts,
            delivered=False,
            exhausted=True,
            reason=message,
        )

    def _mark_delivered(self, batch_no: str) -> None:
        """投递成功：把批次推进到 ``delivered``。"""
        if self._ledger is None:
            return
        record = self._ledger.get_batch(batch_no)
        if record is None:
            return
        ctx = TransitionContext(residual_count=0, platform_delivered=True)
        if record.batch_state is BatchState.PSEUDONYMIZED:
            self._ledger.advance(
                batch_no,
                BatchEvent.DELIVERY_SUCCEEDED,
                ctx,
                reason="科研数据平台已回执：交付完成",
            )
        elif record.batch_state is BatchState.PENDING_DELIVERY:
            self._ledger.advance(
                batch_no,
                BatchEvent.DELIVERY_RETRIED,
                ctx,
                reason="重投成功：交付完成",
            )


def _as_callable(
    deliver: Callable[[str, Mapping[str, object]], bool] | BatchDeliverer | None,
) -> Callable[[str, Mapping[str, object]], bool]:
    """把投递实现统一成「函数」形态。

    接受两种写法：直接给函数，或给带 ``deliver`` 方法的对象。
    """
    if deliver is None:
        def _unconfigured(batch_no: str, payload: Mapping[str, object]) -> bool:
            raise DeliveryError(
                "科研数据平台投递通道未配置（$RESEARCH_DATA_BASE_URL 未设置）"
            )

        return _unconfigured
    method = getattr(deliver, "deliver", None)
    if callable(method):
        return method
    return deliver  # type: ignore[return-value]
