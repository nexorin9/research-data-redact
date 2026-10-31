"""出站调用的统一重试策略。

**为什么重试要落在客户端里**：上层队列管的是「这一批什么时候再投」，客户端
管的是「这一次调用本身是不是瞬时抖动」。科研数据平台在交付高峰偶尔回一个
5xx，过两秒再投同一个幂等键就成了 —— 这件事必须在**真实客户端代码**里做，
不能指望上层队列替它兜：上层看不见 5xx 与 4xx 的区别，只会把「令牌没配」
也重试三遍。

**重试口径**（:class:`RetryPolicy`）：

- 退避重试**最多 2 次**（即最多 3 次尝试），间隔按 ``基准 × 2^(已试次数-1)``
  指数拉开并封顶；
- **只有可重试类别才退避**：连接错误、超时、5xx；
- **4xx 与鉴权失败不重试**：请求本身不对，重试只是把同一个错再犯一遍；
- **通道未配置不重试**：压根没配置，重试多少次都是同一个错。

**幂等**：重试的每一次请求都带**同一把** ``Idempotency-Key``
（申请单号 + 材料集合指纹，见 :mod:`research_redact.idempotency`）——
平台按键去重，重试不会产生第二个数据集。

**与队列退避的关系**：两层退避各管一件事，总尝试次数 =
``(1 + 客户端重试次数) × (1 + 队列重试次数)``。客户端层对付**瞬时抖动**，
队列层对付**批次挂起等重投**（跨进程重启也要记得住）。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .failures import (
    FailureCategory,
    FailureDecision,
    classify_exception,
    classify_status,
    decide_failure,
)

__all__ = [
    "DEFAULT_RETRY_POLICY",
    "RetryPolicy",
    "call_with_retry",
]

logger = logging.getLogger(__name__)

#: 默认退避基准（秒）。客户端层对付的是瞬时抖动，间隔不宜拉得太长。
DEFAULT_BACKOFF_BASE = 0.5
#: 默认退避上限（秒）。
DEFAULT_BACKOFF_MAX = 10.0
#: 默认最多退避重试次数（≤2 次，即最多 3 次尝试）。
DEFAULT_MAX_RETRIES = 2


@dataclass(frozen=True)
class RetryPolicy:
    """出站重试策略。

    :param max_retries: 最多退避重试几次（缺省 2，即共 3 次尝试）。
    :param backoff_base: 退避基准秒数；第 n 次失败后等 ``base × 2^(n-1)``。
    :param backoff_max: 退避上限秒数（封顶，防止夜里退避到几小时）。
    :param sleep: 等待函数（测试注入假等待，不必真等）。
    """

    max_retries: int = DEFAULT_MAX_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_max: float = DEFAULT_BACKOFF_MAX
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError(f"max_retries 必须为非负整数：{self.max_retries}")
        if self.backoff_base <= 0:
            raise ValueError(f"backoff_base 必须为正数：{self.backoff_base}")
        if self.backoff_max < self.backoff_base:
            raise ValueError(
                f"backoff_max 不得小于 backoff_base：{self.backoff_max} < {self.backoff_base}"
            )

    def delay_for(self, attempt: int) -> float:
        """第 ``attempt`` 次尝试失败后的退避秒数（指数，封顶）。

        :param attempt: 已尝试次数（1 起算）。
        """
        exponent = max(0, int(attempt) - 1)
        return min(self.backoff_max, self.backoff_base * (2**exponent))

    def should_retry(self, decision: FailureDecision, attempt: int) -> bool:
        """这一类失败、已经试了 ``attempt`` 次，还要不要再试一次。

        :param decision: 失败处置裁决。
        :param attempt: 已尝试次数（1 起算）。
        """
        return decision.retryable and attempt <= self.max_retries


#: 模块级默认策略（只读使用）。
DEFAULT_RETRY_POLICY = RetryPolicy()


def call_with_retry(
    request: Callable[[], Any],
    *,
    policy: RetryPolicy,
    channel: str = "",
    build_error: Callable[[str, FailureCategory, int], BaseException],
    on_retry: Callable[[int, FailureDecision, float], None] | None = None,
) -> Any:
    """跑一次出站调用；按错误分类决定退避重试还是直接报错。

    :param request: 真正发请求的函数（抛 ``httpx`` 异常或返回响应对象）。
    :param policy: 重试策略。
    :param channel: 通道名（决定失败后批次落到哪个状态）。
    :param build_error: 构造最终抛出的错误：``(说明, 类别, 状态码)``。
    :param on_retry: 每次退避前的回调：``(已试次数, 裁决, 退避秒数)``。
    :return: 2xx 的响应对象。
    :raises BaseException: 重试耗尽或遇到不可重试的失败时，抛出
        ``build_error`` 构造的错误。
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            response = request()
        except Exception as exc:  # 网络异常类型杂，统一收口成类别
            category = classify_exception(exc)
            status = 0
            detail = type(exc).__name__
        else:
            status = int(getattr(response, "status_code", 0) or 0)
            category = classify_status(status)
            if category is None:
                return response
            detail = f"HTTP {status}"

        decision = decide_failure(category, channel=channel)
        if policy.should_retry(decision, attempt):
            delay = policy.delay_for(attempt)
            if on_retry is not None:
                on_retry(attempt, decision, delay)
            else:
                logger.warning(
                    "出站调用第 %s 次失败（%s），%.1fs 后重试",
                    attempt,
                    decision.alert_code,
                    delay,
                )
            policy.sleep(delay)
            continue
        raise build_error(f"{decision.summary}：{detail}", category, status)
