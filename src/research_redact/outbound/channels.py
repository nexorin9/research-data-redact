"""出站通道名（单一真源）。

通道名单独成模块，是因为错误分类（:mod:`research_redact.outbound.failures`）
也要按通道区分处置 —— 而 ``config.py`` 依赖 ``outbound.errors``，
``outbound.errors`` 又依赖 ``outbound.failures``。通道名本身没有任何依赖，
放在最底层，三方都从这儿取，导入关系就不会绕成环。

通道名进日志、进告警、进台账 —— 一处改，三处跟着改。
"""

from __future__ import annotations

__all__ = [
    "CHANNEL_HIS",
    "CHANNEL_RESEARCH",
    "CHANNEL_WECOM",
]

#: 出站读：HIS 患者主索引（患者身份的权威来源）。
CHANNEL_HIS = "his-patient-index"
#: 出站写：科研数据平台（数据集交付 + 还原回执）。
CHANNEL_RESEARCH = "research-platform"
#: 出站推：企业微信群机器人（批次状态与失败原因推给人看）。
CHANNEL_WECOM = "wecom"
