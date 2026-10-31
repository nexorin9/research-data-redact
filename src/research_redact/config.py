"""出站通道配置：端点与凭据全部从环境变量读，缺端点即挂起并告警。

四条硬纪律（贯穿全项目）：

1. **凭据只从环境变量读** —— 代码里不得出现任何密钥字面量，也不得在缺配置
   时回落到某个「示例地址」。缺了就是缺了。
2. **缺端点 = 通道挂起** —— 缺 ``$HIS_BASE_URL`` / ``$RESEARCH_DATA_BASE_URL`` /
   ``$WECOM_WEBHOOK_URL`` 时，对应通道置「挂起」并产生一条告警，**绝不静默
   改指本地替身**：跑起来看着像成功了，交付出去的东西却没人知道送到了哪里。
3. **缺凭据 ≠ 缺端点** —— 端点配了但令牌没配，同样不放行（状态
   ``unauthenticated``），但原因要说清楚是哪一项没配。
4. **不静默降级** —— 一致代号密钥（``$PSEUDONYM_HMAC_KEY``）缺失不在这三个
   通道里，但它同样是凭据位：缺失时报错，不降级为无密钥哈希。

通道与凭据位一览（与 ``.env.example`` 一一对应）：

=========================  ==========================================  ==========
通道                      端点环境变量                                令牌
=========================  ==========================================  ==========
``his-patient-index``     ``$HIS_BASE_URL``                           ``$HIS_API_TOKEN``
``research-platform``     ``$RESEARCH_DATA_BASE_URL``                 ``$RESEARCH_DATA_TOKEN``
``wecom``                 ``$WECOM_WEBHOOK_URL``                      —（群机器人自带 key）
=========================  ==========================================  ==========
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from .audit.alerts import BatchAlert
from .outbound.channels import CHANNEL_HIS, CHANNEL_RESEARCH, CHANNEL_WECOM
from .outbound.errors import ChannelSuspendedError

__all__ = [
    "CHANNEL_HIS",
    "CHANNEL_RESEARCH",
    "CHANNEL_WECOM",
    "CHANNEL_STATUS_READY",
    "CHANNEL_STATUS_SUSPENDED",
    "CHANNEL_STATUS_UNAUTHENTICATED",
    "ChannelConfig",
    "ChannelSuspendedError",
    "OutboundConfig",
]

#: 通道就绪。
CHANNEL_STATUS_READY = "ready"
#: 通道挂起（端点没配）。
CHANNEL_STATUS_SUSPENDED = "suspended"
#: 通道端点配了但凭据没配。
CHANNEL_STATUS_UNAUTHENTICATED = "unauthenticated"

#: 出站调用默认超时（秒）。
DEFAULT_TIMEOUT = 10.0

#: 环境变量名（与 .env.example 一一对应）。
HIS_BASE_URL_ENV = "HIS_BASE_URL"
HIS_API_TOKEN_ENV = "HIS_API_TOKEN"
RESEARCH_DATA_BASE_URL_ENV = "RESEARCH_DATA_BASE_URL"
RESEARCH_DATA_TOKEN_ENV = "RESEARCH_DATA_TOKEN"
WECOM_WEBHOOK_ENV = "WECOM_WEBHOOK_URL"
PSEUDONYM_HMAC_KEY_ENV = "PSEUDONYM_HMAC_KEY"
PSEUDONYM_KEY_ID_ENV = "PSEUDONYM_KEY_ID"
RESEARCH_DATA_STORAGE_BASE_ENV = "RESEARCH_DATA_STORAGE_BASE"
OUTBOUND_TIMEOUT_ENV = "RESEARCH_OUTBOUND_TIMEOUT"


@dataclass(frozen=True)
class ChannelConfig:
    """一个出站通道的配置快照。

    :param name: 通道名。
    :param base_url: 端点地址（企微通道填 webhook 地址）。
    :param token: 令牌（企微通道没有令牌，为空串）。
    :param missing_env: 缺哪几项环境变量（空元组 = 已就绪）。
    :param timeout: 单次调用超时（秒）。
    """

    name: str
    base_url: str = ""
    token: str = ""
    missing_env: tuple[str, ...] = ()
    timeout: float = DEFAULT_TIMEOUT

    @property
    def configured(self) -> bool:
        """通道是否已就绪（端点与凭据齐备）。"""
        return not self.missing_env

    @property
    def status(self) -> str:
        """通道状态：``ready`` / ``suspended`` / ``unauthenticated``。"""
        if self.configured:
            return CHANNEL_STATUS_READY
        if not self.base_url:
            return CHANNEL_STATUS_SUSPENDED
        return CHANNEL_STATUS_UNAUTHENTICATED

    @property
    def reason(self) -> str:
        """一句人话说明（写进告警文案与启动日志）。"""
        if self.configured:
            return "通道已就绪"
        missing = "、".join(self.missing_env)
        return f"通道未配置（缺 {missing}）：该通道置挂起并告警，不指向本地替身"

    def require(self) -> None:
        """通道没就绪就抛错 —— 调用方据此中止外发。

        :raises ChannelSuspendedError: 端点或凭据缺失。
        """
        if not self.configured:
            raise ChannelSuspendedError(f"{self.name}：{self.reason}", channel=self.name)

    def to_dict(self) -> dict[str, object]:
        """转成可落盘 / 可打印的字典（**不含令牌**）。"""
        return {
            "channel": self.name,
            "status": self.status,
            "base_url": self.base_url,
            "missing_env": list(self.missing_env),
            "timeout": self.timeout,
        }


@dataclass(frozen=True)
class OutboundConfig:
    """出站配置总览：三个通道 + 一致代号凭据位。

    :param his: HIS 患者主索引通道。
    :param research: 科研数据平台通道。
    :param wecom: 企业微信推送通道。
    :param pseudonym_key: 一致代号 HMAC 密钥（**不写进任何交付体**）。
    :param pseudonym_key_id: 密钥版本号（写进交付体的 ``pseudonymization.key_id``）。
    :param storage_base: 交付物的存储基地址（留空则用本地暂存路径的 file URI）。
    """

    his: ChannelConfig
    research: ChannelConfig
    wecom: ChannelConfig
    pseudonym_key: str = ""
    pseudonym_key_id: str = ""
    storage_base: str = ""

    # ------------------------------------------------------------------ 装配

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "OutboundConfig":
        """从环境变量装配出站配置。

        :param env: 环境变量映射；缺省读 ``os.environ``。
        """
        source = os.environ if env is None else env
        timeout = _timeout(source.get(OUTBOUND_TIMEOUT_ENV))

        his_url = _text(source.get(HIS_BASE_URL_ENV))
        his_token = _text(source.get(HIS_API_TOKEN_ENV))
        his_missing: list[str] = []
        if not his_url:
            his_missing.append(HIS_BASE_URL_ENV)
        if not his_token:
            his_missing.append(HIS_API_TOKEN_ENV)

        research_url = _text(source.get(RESEARCH_DATA_BASE_URL_ENV))
        research_token = _text(source.get(RESEARCH_DATA_TOKEN_ENV))
        research_missing: list[str] = []
        if not research_url:
            research_missing.append(RESEARCH_DATA_BASE_URL_ENV)
        if not research_token:
            research_missing.append(RESEARCH_DATA_TOKEN_ENV)

        wecom_url = _text(source.get(WECOM_WEBHOOK_ENV))
        wecom_missing: list[str] = []
        if not wecom_url:
            wecom_missing.append(WECOM_WEBHOOK_ENV)

        return cls(
            his=ChannelConfig(
                name=CHANNEL_HIS,
                base_url=his_url,
                token=his_token,
                missing_env=tuple(his_missing),
                timeout=timeout,
            ),
            research=ChannelConfig(
                name=CHANNEL_RESEARCH,
                base_url=research_url,
                token=research_token,
                missing_env=tuple(research_missing),
                timeout=timeout,
            ),
            wecom=ChannelConfig(
                name=CHANNEL_WECOM,
                base_url=wecom_url,
                token="",
                missing_env=tuple(wecom_missing),
                timeout=timeout,
            ),
            pseudonym_key=_text(source.get(PSEUDONYM_HMAC_KEY_ENV)),
            pseudonym_key_id=_text(source.get(PSEUDONYM_KEY_ID_ENV)),
            storage_base=_text(source.get(RESEARCH_DATA_STORAGE_BASE_ENV)),
        )

    # ------------------------------------------------------------------ 查询

    def channel(self, name: str) -> ChannelConfig:
        """按通道名取配置。

        :raises KeyError: 通道名不存在。
        """
        mapping = {
            CHANNEL_HIS: self.his,
            CHANNEL_RESEARCH: self.research,
            CHANNEL_WECOM: self.wecom,
        }
        if name not in mapping:
            raise KeyError(f"未知道的出站通道：{name}")
        return mapping[name]

    def require(self, name: str) -> ChannelConfig:
        """取通道并要求它已就绪；未就绪直接抛错（**不外发**）。

        :raises ChannelSuspendedError: 端点或凭据缺失。
        """
        channel = self.channel(name)
        channel.require()
        return channel

    def suspended_channels(self) -> tuple[ChannelConfig, ...]:
        """没就绪的通道（挂起清单）。"""
        return tuple(
            channel
            for channel in (self.his, self.research, self.wecom)
            if not channel.configured
        )

    # ------------------------------------------------------------------ 告警

    def alerts(self, batch_no: str) -> tuple[BatchAlert, ...]:
        """为挂起的通道各生成一条告警。

        通道没配不是「小事」：批次要么交付不出去、要么推送不出去。挂起这件事
        必须落在台账里并推给人看，**不能只写在启动日志里**。
        """
        alerts: list[BatchAlert] = []
        for channel in self.suspended_channels():
            alerts.append(
                BatchAlert(
                    batch_no=batch_no,
                    code="outbound_channel_suspended",
                    level="error",
                    count=1,
                    message=(
                        f"出站通道 {channel.name} 挂起：{channel.reason}"
                        "（该批次不得按本地替身外发，请补齐环境变量后重投）"
                    ),
                )
            )
        return tuple(alerts)

    def describe(self) -> list[dict[str, object]]:
        """三个通道的状态快照（**不含令牌**），供启动日志与 CLI status 打印。"""
        return [
            self.his.to_dict(),
            self.research.to_dict(),
            self.wecom.to_dict(),
        ]


def _text(value: str | None) -> str:
    """环境变量取值 → 去空白字符串。"""
    return (value or "").strip()


def _timeout(value: str | None) -> float:
    """出站超时（秒）；非法值报错，不静默取缺省。"""
    text = (value or "").strip()
    if not text:
        return DEFAULT_TIMEOUT
    try:
        number = float(text)
    except ValueError as exc:
        raise ValueError(f"{OUTBOUND_TIMEOUT_ENV} 不是合法数字：{text!r}") from exc
    if number <= 0:
        raise ValueError(f"{OUTBOUND_TIMEOUT_ENV} 必须为正数：{text!r}")
    return number
