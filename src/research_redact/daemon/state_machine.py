"""批次状态机：10 态迁移守卫。

**源产品没有这一层** —— 参考实现是 SDK（识别 → 改写 → 返回），没有工作流层、
没有批次、没有状态。医院场景却必须有一层：科研材料不是「一份文件」，而是
**一张申请单、一个伦理批件、一个批次**。批次能不能交付，取决于它走到哪一步、
有没有被授权、能不能被追回。状态机就是这一层的骨架。

**10 个状态**（spec.md「批次状态机」）::

    detected → recognized → pseudonymized → delivered → restore_pending → restored
                                              ↘ restore_rejected
    旁路态：blocked（缺伦理批件号）· suspended（主索引不可达）· pending_delivery（平台 5xx 退避超次）

**四条纪律**（这一层存在的全部理由）：

1. **非法迁移抛明确错误并拒绝推进** —— 状态不推进、批次不前进。没有「跳一步
   试试」这回事：科研材料一旦脱敏完成就进不了「未脱」状态，反之亦然。
2. **旁路态只能由规定事件迁出** —— ``blocked`` 只能由「补齐后重新投递」迁出，
   ``suspended`` 只能由「主索引恢复」或「对照索引恢复」迁出，
   ``pending_delivery`` 只能由「重投成功」迁出。**不得被自动跳过**：绕过
   ``suspended`` 去脱敏，等于在没有权威身份的情况下按正则硬脱 —— 这正是
   spec.md 里写死「不降级」的那一条。挂起的批次必须**两样故障都排除**
   （主索引与对照索引都可达）才准继续。
3. **守卫写在迁移表里** —— 能不能走这一步不是调用方说了算，是迁移表说了算。
   守卫不通过就抛 :class:`TransitionRejectedError`，批次停在原地。
4. **状态值只有一个真源** —— 状态字符串只在本模块定义（:class:`BatchState`），
   其余模块引用枚举，不写裸字符串。

**与台账的关系**：本模块只管「能不能走这一步」，落库由
:mod:`research_redact.audit.ledger` 负责（SQLite 批次表 / 回执表 / 访问留痕表）。
台账的 :meth:`~research_redact.audit.ledger.BatchLedger.advance` 把两者接在一起 ——
一次调用既判迁移、又落库、又按需落告警。

**不变量**：本模块不碰任何患者数据 —— 守卫只看「有没有批件号」「识别覆盖了几份
材料」「残留几处」「授权人是否齐备」这类**计数与布尔**，不接触姓名与编号本身。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, Sequence

from ..models import utcnow

__all__ = [
    "BatchEvent",
    "BatchState",
    "DEFAULT_STATE_MACHINE",
    "IllegalTransitionError",
    "StateMachine",
    "StateMachineError",
    "Transition",
    "TransitionContext",
    "TransitionRejectedError",
    "TransitionResult",
    "default_state_machine",
    "intake_event",
    "recognition_event",
]


class StateMachineError(RuntimeError):
    """状态机相关错误基类。"""


class IllegalTransitionError(StateMachineError):
    """非法迁移：当前状态不接受该事件。

    「不接受」有两种：这一对（状态, 事件）在迁移表里根本不存在；或者这个状态
    只允许特定事件迁出（如 ``blocked`` 只允许「补齐后重新投递」迁出）。
    两种都**拒绝推进** —— 批次停在原地，调用方拿到的就是这个异常。
    """


class TransitionRejectedError(StateMachineError):
    """迁移被守卫拒绝：这一步能走，但当前条件不满足。

    与 :class:`IllegalTransitionError` 分开是因为处置不同：非法迁移是**流程走错**
    （要改调用方），守卫拒绝是**业务条件不满足**（要补材料 / 等主索引 / 补授权人）。
    """


class BatchState(str, enum.Enum):
    """批次状态（10 个，与 spec.md 一一对应）。"""

    #: 申请单落目录，尚未校验。
    DETECTED = "detected"
    #: 申请单校验通过（批件号齐备、材料清单完整）。
    RECOGNIZED = "recognized"
    #: 识别完成、实体区间已产出，身份已换成一致代号。
    PSEUDONYMIZED = "pseudonymized"
    #: 已交付到科研数据平台，平台回了 2xx。
    DELIVERED = "delivered"
    #: 还原请求已受理，等第二授权人签字。
    RESTORE_PENDING = "restore_pending"
    #: 双人授权完成、授权未过期，原文已按范围还原。
    RESTORED = "restored"
    #: 还原被拒（单人 / 过期 / 超范围）。
    RESTORE_REJECTED = "restore_rejected"
    #: 缺伦理批件号或字段缺失 —— 不得放行。
    BLOCKED = "blocked"
    #: 主索引不可达 —— 挂起等恢复，**不降级**为按正则直接脱。
    SUSPENDED = "suspended"
    #: 平台 5xx 退避超次 —— 等重投。
    PENDING_DELIVERY = "pending_delivery"

    @property
    def is_terminal(self) -> bool:
        """终态：不再有后继迁移。"""
        return self in (BatchState.RESTORED, BatchState.RESTORE_REJECTED)

    @property
    def is_bypass(self) -> bool:
        """旁路态：只能由规定事件迁出，不得被自动跳过。"""
        return self in (
            BatchState.BLOCKED,
            BatchState.SUSPENDED,
            BatchState.PENDING_DELIVERY,
        )

    @property
    def is_delivered(self) -> bool:
        """是否已交付（平台侧已有数据集）。"""
        return self is BatchState.DELIVERED


class BatchEvent(str, enum.Enum):
    """触发状态迁移的事件。"""

    #: 申请单落目录。
    APPLICATION_DETECTED = "application_detected"
    #: 申请单校验通过。
    APPLICATION_VALIDATED = "application_validated"
    #: 申请单缺项 —— 阻断。
    APPLICATION_BLOCKED = "application_blocked"
    #: 补齐批件号 / 字段后重新投递 —— 从阻断迁出。
    APPLICATION_REPAIRED = "application_repaired"
    #: 识别完成，每份材料的实体区间都产出了。
    RECOGNITION_COMPLETED = "recognition_completed"
    #: 患者主索引不可达 —— 挂起。
    PATIENT_INDEX_UNREACHABLE = "patient_index_unreachable"
    #: 患者主索引恢复可达 —— 从挂起迁出。
    PATIENT_INDEX_RESTORED = "patient_index_restored"
    #: 对照索引不可达（索引文件缺失 / 解密失败）—— 挂起。
    INDEX_STORE_UNREACHABLE = "index_store_unreachable"
    #: 对照索引恢复可达 —— 从挂起迁出。
    INDEX_STORE_RESTORED = "index_store_restored"
    #: 残留自检通过且平台回了 2xx —— 交付。
    DELIVERY_SUCCEEDED = "delivery_succeeded"
    #: 平台 5xx，退避超次 —— 等重投。
    DELIVERY_FAILED = "delivery_failed"
    #: 重投成功 —— 从等重投迁出。
    DELIVERY_RETRIED = "delivery_retried"
    #: 还原请求到达，授权人 A 在位。
    RESTORE_REQUESTED = "restore_requested"
    #: 双人授权齐备且未过期 —— 执行还原。
    RESTORE_APPROVED = "restore_approved"
    #: 还原被拒（单人 / 过期 / 超范围）。
    RESTORE_REJECTED = "restore_rejected"
    #: 第二授权人尚未签字 —— 原地挂起等签字（自环）。
    RESTORE_AUTHORIZATION_PENDING = "restore_authorization_pending"


@dataclass(frozen=True)
class TransitionContext:
    """迁移守卫的判定依据。

    守卫只看**计数、布尔与是否齐备**，不接触姓名、住院号这类患者数据本身 ——
    状态机这一层不需要（也不该）知道患者是谁。

    :param ethics_approval_no: 伦理批件号；为空即缺授权范围。
    :param missing_fields: 缺失 / 不一致的字段清单。
    :param material_count: 本批材料总数。
    :param recognized_material_count: 已产出实体区间的材料数。
    :param patient_index_reachable: HIS 患者主索引是否可达。
    :param index_store_reachable: 对照索引是否可达（索引文件缺失 / 解密失败
        时为 False —— 批次挂起等索引恢复，不重建空索引放行）。
    :param residual_count: 残留自检的身份类残留处数。
    :param platform_delivered: 科研数据平台是否已回 2xx。
    :param approver_a: 还原授权人 A。
    :param approver_b: 还原授权人 B（缺即不得单人还原）。
    :param authorization_expired: 还原授权是否已过期。
    :param scope_ok: 还原范围是否在授权范围内。
    """

    ethics_approval_no: str | None = None
    missing_fields: tuple[str, ...] = ()
    material_count: int = 0
    recognized_material_count: int = 0
    patient_index_reachable: bool = True
    index_store_reachable: bool = True
    residual_count: int = 0
    platform_delivered: bool = False
    approver_a: str | None = None
    approver_b: str | None = None
    authorization_expired: bool = False
    scope_ok: bool = True

    def with_changes(self, **changes: object) -> "TransitionContext":
        """派生一份改过若干字段的上下文（测试与调用方便利）。"""
        data = {
            "ethics_approval_no": self.ethics_approval_no,
            "missing_fields": self.missing_fields,
            "material_count": self.material_count,
            "recognized_material_count": self.recognized_material_count,
            "patient_index_reachable": self.patient_index_reachable,
            "index_store_reachable": self.index_store_reachable,
            "residual_count": self.residual_count,
            "platform_delivered": self.platform_delivered,
            "approver_a": self.approver_a,
            "approver_b": self.approver_b,
            "authorization_expired": self.authorization_expired,
            "scope_ok": self.scope_ok,
        }
        data.update(changes)
        return TransitionContext(**data)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Transition:
    """迁移表的一行。

    :param source: 起始状态；``None`` 表示「批次尚未存在」（新建批次）。
    :param event: 触发事件。
    :param target: 目标状态。
    :param guard: 守卫函数：条件满足返回 ``None``，不满足返回**拒绝原因**。
    :param description: 一句话说明这一步在做什么（进台账时间线）。
    """

    source: BatchState | None
    event: BatchEvent
    target: BatchState
    guard: Callable[[TransitionContext], str | None]
    description: str


@dataclass(frozen=True)
class TransitionResult:
    """一次成功迁移的结果。"""

    source: BatchState | None
    event: BatchEvent
    target: BatchState
    description: str = ""
    at: datetime = field(default_factory=utcnow)


#: 守卫返回拒绝原因时用的类型别名。
GuardResult = str | None


# --------------------------------------------------------------------- 守卫


def _guard_application_complete(ctx: TransitionContext) -> GuardResult:
    """申请单齐备：批件号在、材料清单不空、无缺项。"""
    if not (ctx.ethics_approval_no or "").strip():
        return "缺伦理批件号：该批次没有授权范围，不得进入脱敏与交付"
    if ctx.missing_fields:
        return "申请单字段缺失：" + "、".join(ctx.missing_fields) + "：该批次不得放行"
    if ctx.material_count <= 0:
        return "材料清单为空：批次没有可交付的内容"
    return None


def _guard_application_incomplete(ctx: TransitionContext) -> GuardResult:
    """申请单确有缺项才允许置阻断（否则是无故阻断）。"""
    if (ctx.ethics_approval_no or "").strip() and not ctx.missing_fields:
        return "申请单齐备：不无故阻断批次"
    return None


def _guard_recognition_complete(ctx: TransitionContext) -> GuardResult:
    """识别完成：主索引可达且覆盖全部材料。"""
    if not ctx.patient_index_reachable:
        return "主索引不可达：不得按正则直接脱，批次须挂起等主索引恢复"
    if ctx.material_count <= 0:
        return "材料清单为空：无可识别内容"
    if ctx.recognized_material_count < ctx.material_count:
        return (
            f"识别未覆盖全部材料（{ctx.recognized_material_count}/{ctx.material_count}）"
            "：不得进入代号化"
        )
    return None


def _guard_index_unreachable(ctx: TransitionContext) -> GuardResult:
    """主索引确实不可达才允许挂起。"""
    if ctx.patient_index_reachable:
        return "主索引可达：无须挂起批次"
    return None


def _guard_index_restored(ctx: TransitionContext) -> GuardResult:
    """主索引恢复可达才允许从挂起迁出。

    同时要求对照索引可达 —— 挂起的批次必须**两样故障都排除**才准继续，
    否则会在另一个故障还没解决时把批次放出去。
    """
    if not ctx.patient_index_reachable:
        return "主索引仍不可达：批次不得继续处理"
    if not ctx.index_store_reachable:
        return "对照索引仍不可达：批次不得继续处理"
    return None


def _guard_index_store_unreachable(ctx: TransitionContext) -> GuardResult:
    """对照索引确实不可达才允许挂起。

    与「主索引不可达」分开：索引文件缺失 / 解密失败是**另一件事** ——
    台账与时间线里必须能分清是哪一样出了故障。
    """
    if ctx.index_store_reachable:
        return "对照索引可达：无须挂起批次"
    return None


def _guard_index_store_restored(ctx: TransitionContext) -> GuardResult:
    """对照索引恢复可达才允许从挂起迁出（同样要求主索引可达）。"""
    if not ctx.index_store_reachable:
        return "对照索引仍不可达：批次不得继续处理"
    if not ctx.patient_index_reachable:
        return "主索引仍不可达：批次不得继续处理"
    return None


def _guard_delivery_succeeded(ctx: TransitionContext) -> GuardResult:
    """交付：残留为 0 且平台回 2xx。"""
    if ctx.residual_count > 0:
        return f"身份类残留 {ctx.residual_count} 处：该批次不得投递"
    if not ctx.platform_delivered:
        return "科研数据平台未回 2xx：尚未交付"
    return None


def _guard_delivery_failed(ctx: TransitionContext) -> GuardResult:
    """平台未回 2xx 才允许进入等重投。"""
    if ctx.platform_delivered:
        return "平台已回 2xx：不应置等重投"
    return None


def _guard_delivery_retried(ctx: TransitionContext) -> GuardResult:
    """重投成功：残留仍须为 0，平台回 2xx。"""
    if ctx.residual_count > 0:
        return f"身份类残留 {ctx.residual_count} 处：该批次不得投递"
    if not ctx.platform_delivered:
        return "科研数据平台未回 2xx：重投未成功"
    return None


def _guard_restore_requested(ctx: TransitionContext) -> GuardResult:
    """还原请求：授权人 A 在位才受理。"""
    if not (ctx.approver_a or "").strip():
        return "还原请求缺授权人 A：不得进入还原待办"
    return None


def _guard_restore_approved(ctx: TransitionContext) -> GuardResult:
    """执行还原：双人 + 不得同一人 + 未过期 + 在范围内。"""
    if not (ctx.approver_a or "").strip():
        return "还原缺授权人 A"
    if not (ctx.approver_b or "").strip():
        return "还原缺授权人 B：不得单人还原，须挂起等待第二授权人"
    if ctx.approver_a == ctx.approver_b:
        return "两位授权人相同：双人授权不得由一人兼任"
    if ctx.authorization_expired:
        return "还原授权已过期：不得执行"
    if not ctx.scope_ok:
        return "还原范围超出授权：不得执行"
    return None


def _guard_restore_rejected(ctx: TransitionContext) -> GuardResult:
    """拒绝分支不需要守卫（拒绝本身总是合法）。"""
    return None


def _guard_restore_authorization_pending(ctx: TransitionContext) -> GuardResult:
    """缺第二授权人时原地挂起（不降级为单人还原）。"""
    if (ctx.approver_a or "").strip() and (ctx.approver_b or "").strip():
        return "双人授权已齐备：应执行还原而非继续挂起"
    return None


# ----------------------------------------------------------------- 迁移表


def _build_default_transitions() -> tuple[Transition, ...]:
    """默认迁移表（10 态全覆盖）。"""
    return (
        Transition(
            source=None,
            event=BatchEvent.APPLICATION_DETECTED,
            target=BatchState.DETECTED,
            guard=lambda ctx: None,
            description="申请单落目录，进入待校验",
        ),
        Transition(
            source=BatchState.DETECTED,
            event=BatchEvent.APPLICATION_VALIDATED,
            target=BatchState.RECOGNIZED,
            guard=_guard_application_complete,
            description="申请单校验通过（批件号齐备、材料清单完整）",
        ),
        Transition(
            source=BatchState.DETECTED,
            event=BatchEvent.APPLICATION_BLOCKED,
            target=BatchState.BLOCKED,
            guard=_guard_application_incomplete,
            description="申请单缺项，阻断该批次",
        ),
        Transition(
            source=BatchState.BLOCKED,
            event=BatchEvent.APPLICATION_REPAIRED,
            target=BatchState.RECOGNIZED,
            guard=_guard_application_complete,
            description="补齐批件号与字段后重新投递",
        ),
        Transition(
            source=BatchState.RECOGNIZED,
            event=BatchEvent.RECOGNITION_COMPLETED,
            target=BatchState.PSEUDONYMIZED,
            guard=_guard_recognition_complete,
            description="识别完成，身份已换成一致代号",
        ),
        Transition(
            source=BatchState.RECOGNIZED,
            event=BatchEvent.PATIENT_INDEX_UNREACHABLE,
            target=BatchState.SUSPENDED,
            guard=_guard_index_unreachable,
            description="主索引不可达，批次挂起等恢复（不降级为按正则直接脱）",
        ),
        Transition(
            source=BatchState.SUSPENDED,
            event=BatchEvent.PATIENT_INDEX_RESTORED,
            target=BatchState.RECOGNIZED,
            guard=_guard_index_restored,
            description="主索引恢复可达，批次回到识别前一步",
        ),
        Transition(
            source=BatchState.RECOGNIZED,
            event=BatchEvent.INDEX_STORE_UNREACHABLE,
            target=BatchState.SUSPENDED,
            guard=_guard_index_store_unreachable,
            description="对照索引不可达，批次挂起等索引恢复（不重建空索引放行）",
        ),
        Transition(
            source=BatchState.PSEUDONYMIZED,
            event=BatchEvent.INDEX_STORE_UNREACHABLE,
            target=BatchState.SUSPENDED,
            guard=_guard_index_store_unreachable,
            description="对照索引不可达，批次挂起等索引恢复（不重建空索引放行）",
        ),
        Transition(
            source=BatchState.SUSPENDED,
            event=BatchEvent.INDEX_STORE_RESTORED,
            target=BatchState.RECOGNIZED,
            guard=_guard_index_store_restored,
            description="对照索引恢复可达，批次回到识别前一步",
        ),
        Transition(
            source=BatchState.PSEUDONYMIZED,
            event=BatchEvent.DELIVERY_SUCCEEDED,
            target=BatchState.DELIVERED,
            guard=_guard_delivery_succeeded,
            description="残留自检通过且平台回 2xx，交付完成",
        ),
        Transition(
            source=BatchState.PSEUDONYMIZED,
            event=BatchEvent.DELIVERY_FAILED,
            target=BatchState.PENDING_DELIVERY,
            guard=_guard_delivery_failed,
            description="平台 5xx 退避超次，转入等重投",
        ),
        Transition(
            source=BatchState.PENDING_DELIVERY,
            event=BatchEvent.DELIVERY_RETRIED,
            target=BatchState.DELIVERED,
            guard=_guard_delivery_retried,
            description="重投成功，交付完成",
        ),
        Transition(
            source=BatchState.DELIVERED,
            event=BatchEvent.RESTORE_REQUESTED,
            target=BatchState.RESTORE_PENDING,
            guard=_guard_restore_requested,
            description="还原请求到达，等第二授权人签字",
        ),
        Transition(
            source=BatchState.RESTORE_PENDING,
            event=BatchEvent.RESTORE_APPROVED,
            target=BatchState.RESTORED,
            guard=_guard_restore_approved,
            description="双人授权齐备且未过期，按范围执行还原",
        ),
        Transition(
            source=BatchState.RESTORE_PENDING,
            event=BatchEvent.RESTORE_REJECTED,
            target=BatchState.RESTORE_REJECTED,
            guard=_guard_restore_rejected,
            description="还原被拒（单人 / 过期 / 超范围）",
        ),
        Transition(
            source=BatchState.RESTORE_PENDING,
            event=BatchEvent.RESTORE_AUTHORIZATION_PENDING,
            target=BatchState.RESTORE_PENDING,
            guard=_guard_restore_authorization_pending,
            description="第二授权人尚未签字，原地挂起等待",
        ),
    )


class StateMachine:
    """批次状态机：迁移表 + 守卫。

    :param transitions: 迁移表；缺省用 :func:`_build_default_transitions`。
    :raises StateMachineError: 同一（状态, 事件）重复登记。
    """

    def __init__(self, transitions: Sequence[Transition] | None = None) -> None:
        rows = _build_default_transitions() if transitions is None else tuple(transitions)
        table: dict[tuple[BatchState | None, BatchEvent], Transition] = {}
        for row in rows:
            key = (row.source, row.event)
            if key in table:
                raise StateMachineError(
                    f"迁移表重复登记：{_state_text(row.source)} --{row.event.value}-->"
                )
            table[key] = row
        self._table = table

    # ------------------------------------------------------------------ 查询

    @property
    def transitions(self) -> tuple[Transition, ...]:
        """迁移表全量（按登记顺序）。"""
        return tuple(self._table.values())

    def states(self) -> tuple[BatchState, ...]:
        """本机覆盖的全部状态（10 个）。"""
        seen: dict[BatchState, None] = {}
        for row in self._table.values():
            if row.source is not None:
                seen.setdefault(row.source, None)
            seen.setdefault(row.target, None)
        return tuple(seen)

    def outgoing_events(self, source: BatchState | None) -> tuple[BatchEvent, ...]:
        """某状态允许的事件（供报错文案与 CLI 提示用）。"""
        return tuple(
            row.event for row in self._table.values() if row.source is source
        )

    def can_transition(self, source: BatchState | None, event: BatchEvent) -> bool:
        """该（状态, 事件）是否在迁移表里。"""
        return (source, event) in self._table

    def target_state(
        self, source: BatchState | None, event: BatchEvent
    ) -> BatchState:
        """目标状态。

        :raises IllegalTransitionError: 该（状态, 事件）不在迁移表里。
        """
        row = self._table.get((source, event))
        if row is None:
            raise IllegalTransitionError(self._illegal_message(source, event))
        return row.target

    # ------------------------------------------------------------------ 迁移

    def transition(
        self,
        source: BatchState | None,
        event: BatchEvent,
        ctx: TransitionContext | None = None,
    ) -> TransitionResult:
        """走一步迁移。

        :param source: 当前状态；``None`` 表示新建批次。
        :param event: 触发事件。
        :param ctx: 守卫判定依据。
        :return: 迁移结果（目标状态 + 说明 + 时间）。
        :raises IllegalTransitionError: 该（状态, 事件）不在迁移表里。
        :raises TransitionRejectedError: 守卫不通过（条件不满足）。
        """
        row = self._table.get((source, event))
        if row is None:
            raise IllegalTransitionError(self._illegal_message(source, event))
        reason = row.guard(ctx or TransitionContext())
        if reason:
            raise TransitionRejectedError(
                f"{_state_text(source)} --{event.value}--> 被拒绝：{reason}"
            )
        return TransitionResult(
            source=source,
            event=event,
            target=row.target,
            description=row.description,
        )

    # ------------------------------------------------------------------ 内部

    def _illegal_message(
        self, source: BatchState | None, event: BatchEvent
    ) -> str:
        allowed = self.outgoing_events(source)
        allowed_text = "、".join(item.value for item in allowed) or "（无）"
        return (
            f"非法迁移：{_state_text(source)} 不接受事件 {event.value}"
            f"（该状态允许的事件：{allowed_text}）"
        )


def _state_text(source: BatchState | None) -> str:
    """状态的可读名（新建批次写作「（无）」）。"""
    return "（无）" if source is None else source.value


def default_state_machine() -> StateMachine:
    """默认状态机（迁移表全量）。"""
    return StateMachine()


#: 模块级默认状态机（只读使用；表本身在构造时冻结）。
DEFAULT_STATE_MACHINE = default_state_machine()


# ------------------------------------------------------------------ 便捷判定


def intake_event(
    *, ethics_approval_no: str | None, missing_fields: Iterable[str] = ()
) -> BatchEvent:
    """按入站结果给出第一个事件。

    :param ethics_approval_no: 伦理批件号。
    :param missing_fields: 缺失 / 不一致字段清单。
    :return: 齐备给 :attr:`BatchEvent.APPLICATION_VALIDATED`，有缺项给
        :attr:`BatchEvent.APPLICATION_BLOCKED`。
    """
    missing = tuple(item for item in missing_fields if str(item).strip())
    if not (ethics_approval_no or "").strip() or missing:
        return BatchEvent.APPLICATION_BLOCKED
    return BatchEvent.APPLICATION_VALIDATED


def recognition_event(*, patient_index_reachable: bool) -> BatchEvent:
    """按主索引可达性给出识别阶段的事件。

    :param patient_index_reachable: HIS 患者主索引是否可达。
    :return: 可达给 :attr:`BatchEvent.RECOGNITION_COMPLETED`，不可达给
        :attr:`BatchEvent.PATIENT_INDEX_UNREACHABLE`（挂起，**不降级**）。
    """
    if patient_index_reachable:
        return BatchEvent.RECOGNITION_COMPLETED
    return BatchEvent.PATIENT_INDEX_UNREACHABLE
