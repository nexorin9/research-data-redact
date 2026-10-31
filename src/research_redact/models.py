"""核心数据模型：实体区间、识别结果、批次、还原授权与还原回执。

模型层只描述数据与不变量，不做识别、不做策略、不做外发调用。

三条贯穿全项目的不变量（在这里定下来，后续模块不得违反）：

1. **命中清单不记原文** —— ``EntitySpan`` 只记位置 / 类别 / 分数 / 解释，
   ``RecognizerResult.metadata`` 也不得塞入命中原文，否则清单导出（task 32）
   与残留自检（task 9 / 28）的「不含原文」红线会被打破。
2. **档位显式化** —— 一段文本被识别出来之后有三种档位：
   ``confirmed``（判定为身份类）、``warning``（分数不足，降为告警）、
   ``allowed``（命中白名单，放行）。低分命中降档而非丢弃，由调用方决定
   是否计入残留统计。
3. **解释可读** —— 每条命中都带一句人话解释（命中方式 / 阈值 / 放行原因），
   供伦理办与科研数据管理员人工抽检。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def utcnow() -> datetime:
    """当前 UTC 时间（带时区）。"""
    return datetime.now(timezone.utc)


class SpanTier(str, enum.Enum):
    """实体区间的档位。

    - ``CONFIRMED``：分数达到阈值，判定为身份类实体，计入残留自检。
    - ``WARNING``：分数低于阈值，降为告警档；**不丢弃**，由调用方决定是否计入残留。
    - ``ALLOWED``：命中白名单，一律放行；不替换、不计入残留，但在命中清单中可见。
    """

    CONFIRMED = "confirmed"
    WARNING = "warning"
    ALLOWED = "allowed"


@dataclass(frozen=True)
class RecognizerResult:
    """单个识别器对一段文本的原始命中（尚未经阈值与白名单裁决）。

    ``recognizer`` 记录产出该命中的识别器 ID，注册表据此解析逐识别器阈值。
    """

    start: int
    end: int
    label: str
    score: float
    reason: str = ""
    recognizer: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"start 不得为负：{self.start}")
        if self.end <= self.start:
            raise ValueError(f"非法区间：start={self.start} end={self.end}")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"分数越界：{self.score}")


@dataclass(frozen=True)
class EntitySpan:
    """注册表裁决后的实体区间 —— 命中清单的一行来源。

    只记位置 / 类别 / 分数 / 解释，**不记命中原文**。
    ``merged_duplicates`` 记录被折叠掉的重复命中（形如 ``标签@识别器ID``），
    供 task 23 的冲突裁决把「被裁剪方」写进清单。
    ``metadata`` 承接识别器给出的**非原文**附属信息（如名单形态识别器绑定的
    患者主索引主键）—— 主路径据此把身份键交给处置动作（一致代号的取值输入）。
    它不进命中清单（清单字段封闭），也不得含命中原文。
    """

    start: int
    end: int
    label: str
    score: float
    reason: str = ""
    tier: SpanTier = SpanTier.CONFIRMED
    recognizer: str = ""
    merged_duplicates: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"start 不得为负：{self.start}")
        if self.end <= self.start:
            raise ValueError(f"非法区间：start={self.start} end={self.end}")

    @property
    def is_confirmed(self) -> bool:
        """是否判定为身份类实体。"""
        return self.tier is SpanTier.CONFIRMED

    @property
    def is_warning(self) -> bool:
        """是否被降为告警档（分数不足）。"""
        return self.tier is SpanTier.WARNING

    @property
    def is_allowed(self) -> bool:
        """是否命中白名单而放行。"""
        return self.tier is SpanTier.ALLOWED

    @property
    def counts_as_residual(self) -> bool:
        """是否应计入身份类残留统计：只有确认档计入。"""
        return self.is_confirmed


@dataclass(frozen=True)
class DroppedSpan:
    """冲突裁决中被丢弃 / 被裁剪掉的区间（记入命中清单，**不记原文**）。

    冲突区间处理（``policy/conflicts.py``）裁掉一段时，不能只留一句日志 ——
    伦理办抽检时必须看得见「这一段为什么没脱」。本模型只承载位置与原因，
    命中原文一律不进 ``reason``（与 :class:`EntitySpan` 同一红线）。
    """

    start: int
    end: int
    label: str
    score: float
    tier: str = SpanTier.CONFIRMED.value
    recognizer: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"start 不得为负：{self.start}")
        if self.end <= self.start:
            raise ValueError(f"非法区间：start={self.start} end={self.end}")


@dataclass(frozen=True)
class Material:
    """材料清单项（来自申请单 materials 数组）。"""

    material_id: str
    kind: str
    path: str
    patient_id: str | None = None


@dataclass
class Batch:
    """批次：一个科研数据申请单及其材料集合。

    ``state`` 取值与迁移规则由 ``daemon/state_machine.py`` 定义（task 10），
    本模型只承载状态值，不做迁移判断。
    """

    application_no: str
    ethics_approval_no: str | None = None
    patient_ids: tuple[str, ...] = ()
    materials: tuple[Material, ...] = ()
    state: str = "detected"
    idempotency_key: str = ""
    current_step: str = ""
    failure_reason: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    def material_by_id(self, material_id: str) -> Material | None:
        """按材料 ID 取材料；不存在返回 None。"""
        for material in self.materials:
            if material.material_id == material_id:
                return material
        return None


@dataclass(frozen=True)
class RestoreAuthorization:
    """还原授权：双人授权 + 时效 + 范围。

    ``approver_b`` 为空表示第二授权人尚未签字 —— 服务层必须挂起，
    不降级为单人还原（task 13）。
    """

    request_id: str
    dataset_id: str
    approver_a: str
    approver_b: str | None = None
    scope: tuple[str, ...] = ()
    reason: str = ""
    granted_at: datetime | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True)
class RestoreReceipt:
    """还原回执：一次受控还原的事实记录（不含原文）。"""

    receipt_id: str
    restore_request_id: str
    dataset_id: str
    approver_a: str
    approver_b: str
    scope: tuple[str, ...]
    reason: str
    result_summary: str
    granted_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)
    platform_receipt_id: str | None = None
