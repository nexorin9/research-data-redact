"""出站推：企业微信群机器人（批次状态、失败原因与待处理提示）。

守护进程在「退避重试超次」时要把批次挂到 ``pending_delivery`` 并把原因推给人
看 —— 不推，批次就只是躺在台账里等人自己翻。本模块实现
:class:`research_redact.audit.alerts.AlertNotifier` 协议：**真的发 HTTP
请求**，通道未配置时明确返回 False（**不静默改指本地替身，也不假装推过**）。

接口形态：企业微信群机器人 webhook（``POST $WECOM_WEBHOOK_URL``），请求体::

    {"msgtype": "text", "text": {"content": "..."}}

返回体 ``errcode`` 为 0 才算推出去了 —— 企业微信在 HTTP 200 的情况下照样
可能回 ``errcode != 0``（例如群机器人被移除），只看状态码会把失败当成功。
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping

import httpx

__all__ = [
    "DEFAULT_TIMEOUT",
    "WECOM_WEBHOOK_ENV",
    "WeComNotifier",
    "build_batch_message",
    "build_notifier",
]

logger = logging.getLogger(__name__)

#: 环境变量：企业微信群机器人 webhook（.env.example 里的 WECOM_WEBHOOK_URL）
WECOM_WEBHOOK_ENV = "WECOM_WEBHOOK_URL"

#: 推送超时（秒）：群机器人是给人看消息的通道，不值得为它等很久。
DEFAULT_TIMEOUT = 5.0


class WeComNotifier:
    """企业微信群机器人推送。

    :param webhook_url: webhook 地址；缺省取 ``$WECOM_WEBHOOK_URL``。
    :param timeout: 单次推送超时（秒）。
    :param client: 预置的 httpx 客户端（测试用）；缺省按调用临时建一个。

    用法::

        notifier = WeComNotifier()
        if notifier.configured:
            notifier.notify("批次 KY20260001 投递退避超次，已挂起等重投", batch_no="KY20260001")
    """

    #: 通道名：写进告警记录，让「推没推出去」可核对。
    channel = "wecom"

    def __init__(
        self,
        webhook_url: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        client: Any | None = None,
    ) -> None:
        raw = webhook_url if webhook_url is not None else os.environ.get(WECOM_WEBHOOK_ENV, "")
        self.webhook_url = (raw or "").strip()
        self.timeout = timeout
        self._client = client

    @property
    def configured(self) -> bool:
        """推送通道是否已配置。"""
        return bool(self.webhook_url)

    def payload(self, message: str) -> dict[str, object]:
        """群机器人文本消息的请求体。"""
        return {"msgtype": "text", "text": {"content": message}}

    def notify(self, message: str, *, batch_no: str) -> bool:
        """推送一条消息；返回是否真的推出去了。

        通道未配置、网络不可达、对端回非 0 ``errcode`` —— 三种情况都返回
        False，并在日志里写明原因。调用方据此把告警记成 ``notified=False``，
        **不静默丢弃**。
        """
        if not self.configured:
            logger.warning(
                "企业微信推送通道未配置（$%s 未设置）：批次 %s 的告警未推出",
                WECOM_WEBHOOK_ENV,
                batch_no,
            )
            return False
        body = self.payload(message)
        try:
            if self._client is not None:
                response = self._client.post(self.webhook_url, json=body)
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(self.webhook_url, json=body)
        except Exception as exc:  # 网络异常类型杂，统一收口为「没推出去」
            logger.error("企业微信推送失败（批次 %s）：%s", batch_no, exc)
            return False
        return self._accept(response, batch_no)

    def notify_batch(
        self,
        batch_no: str,
        *,
        state: str = "",
        title: str = "",
        reason: str = "",
        pending_hint: str = "",
    ) -> bool:
        """按「批次状态 + 失败原因 + 待处理提示」三段式推一条消息。

        :param batch_no: 批次号（申请单号）。
        :param state: 批次当前状态（如 ``pending_delivery``）。
        :param title: 一句话事件标题（如「投递退避超次」）。
        :param reason: 失败原因（**不含患者原文**）。
        :param pending_hint: 待处理提示（告诉人下一步做什么）。
        """
        message = build_batch_message(
            batch_no,
            state=state,
            title=title,
            reason=reason,
            pending_hint=pending_hint,
        )
        return self.notify(message, batch_no=batch_no)

    def _accept(self, response: Any, batch_no: str) -> bool:
        """判定响应是否算推送成功（HTTP 2xx 且 errcode 为 0）。"""
        status = getattr(response, "status_code", 0)
        if status < 200 or status >= 300:
            logger.error(
                "企业微信推送未成功（批次 %s）：HTTP %s", batch_no, status
            )
            return False
        try:
            body: Mapping[str, Any] = response.json()
        except Exception:
            body = {}
        errcode = body.get("errcode") if isinstance(body, Mapping) else None
        if errcode not in (None, 0):
            logger.error(
                "企业微信推送未成功（批次 %s）：errcode=%s errmsg=%s",
                batch_no,
                errcode,
                body.get("errmsg"),
            )
            return False
        return True


def build_batch_message(
    batch_no: str,
    *,
    state: str = "",
    title: str = "",
    reason: str = "",
    pending_hint: str = "",
) -> str:
    """把「批次状态 + 失败原因 + 待处理提示」拼成一条群机器人文本。

    值班的人看群消息就能知道两件事：**哪一批卡住了** 与 **我该做什么**。
    文案里只放批次号、状态与原因 —— **不放任何患者原文**。
    """
    lines = [f"【科研影像数据脱敏】批次 {batch_no}"]
    if title:
        lines.append(f"事件：{title}")
    if state:
        lines.append(f"状态：{state}")
    if reason:
        lines.append(f"原因：{reason}")
    if pending_hint:
        lines.append(f"待处理：{pending_hint}")
    return "\n".join(lines)


def build_notifier(webhook_url: str | None = None) -> WeComNotifier | Any:
    """构造推送出口：配置了 webhook 就用群机器人，没配置就返回「未配置」占位。

    没配置时返回 :class:`research_redact.audit.alerts.PendingNotifier` ——
    它明确返回 False，让告警记录里的 ``notified`` 为 False、
    ``notify_channel`` 为 ``pending``，既不假装推过，也不指向本地替身。
    """
    from ..audit.alerts import PendingNotifier

    notifier = WeComNotifier(webhook_url)
    if notifier.configured:
        return notifier
    return PendingNotifier()
