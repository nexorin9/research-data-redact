"""受控还原的执行方：还原、回执、留痕、拒绝分支。

**源产品主路径**：``github_ref/presidio/presidio-anonymizer/presidio_anonymizer/
deanonymize_engine.py::DeanonymizeEngine.deanonymize``（:813-830）走
``_operate(text, entities, operators, OperatorType.Deanonymize)`` —— 输入
「已脱敏文本 + 实体 + operator」，输出「反解后的文本」；配套的
``add_deanonymizer``（:837-844）是挂载还原 operator 的扩展点，
``batch_deanonymize_engine.py::BatchDeanonymizeEngine`` 是它的批量形态。

**本轮保留什么、改了什么**：

- **保留主路径**：输入已脱敏文本 → 逐段按对照索引反解 → 输出还原文本；
  「可插拔的还原动作」这一扩展点保留为 :class:`MappingIndex` 协议
  （一致代号 HMAC 与加密对照索引都挂在这上面）。
- **改的是「谁来批」**：源产品的还原是一个**附赠能力** —— 拿到密文与
  operator 就能反解，没有授权、没有回执、没有留痕。本轮把它从附赠升为
  **产品主线**：还原必须双人授权、限时、限范围，且必须留下还原回执与
  访问留痕（详见 :mod:`research_redact.restore.authority`）。

还原不是「把文本里的代号换回去」这么简单 —— 它是一次**有人签字的例外**，
必须留下「谁批的、批了什么、还原了什么、结果如何」四条事实。所以本模块
的产出不是一段文本，而是：

    还原后的材料 + 一条还原回执 + 一条访问留痕 + 一次批次状态推进

**对照索引（代号 ↔ 原文）**：还原靠它把代号换回原文。本模块只认一个协议
（:class:`MappingIndex`），具体实现可换：

- :class:`InMemoryMappingIndex` —— 进程内对照表（本轮默认实现）；
- 加密持久化对照索引（``policy/index_store.py``，task 26 落地）与
  一致代号（``policy/pseudonym.py``，task 24 落地）都挂在这同一个协议上。

**对照索引不可达 = 报错中止**，不静默跳过：索引里查不到某个代号，说明这
一段的原文要么没登记、要么索引丢了 —— 两种情况都意味着「还原出来的文本
可能是残缺的」。宁可整批停下让人查，也不产出半真半假的还原件。

**三条纪律**：

1. **失败不静默改数据** —— 还原失败（未知代号 / 索引不可达）时**不落盘**、
   **不写回执**、**不推进批次状态**。批次停在 ``restore_pending`` 等人处理。
2. **留痕与回执不含原文** —— 回执里只有材料 ID、条数、授权人与结论；还原
   出来的原文只在还原件本身里，与命中清单「不记原文」是同一条红线。
3. **平台回执写不进去不吞掉** —— 还原已执行、平台侧回执写失败时，本地回执
   照落（它是权威记录），同时落一条 ``restore_platform_receipt_missing``
   告警，回执里写明平台侧状态。**不回滚已执行的还原**：把已经还原出来的
   文本再抹掉，比回执缺失更危险。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from ..audit.alerts import BatchAlert
from ..daemon.state_machine import (
    BatchEvent,
    BatchState,
    TransitionContext,
)
from ..models import RestoreAuthorization, RestoreReceipt, utcnow
from ..outbound.errors import OutboundError
from .authority import (
    CODE_MISSING_APPROVER_A,
    CODE_MISSING_APPROVER_B,
    DEFAULT_AUTHORIZATION_TTL,
    AuthorityDecision,
    AuthorityValidator,
)

__all__ = [
    "DEFAULT_TOKEN_PATTERN",
    "InMemoryMappingIndex",
    "MappingIndex",
    "RestoreExecutionError",
    "RestoreOutcome",
    "RestoreService",
    "RestoreServiceError",
    "RestoreStateError",
]


#: 代号（token）的默认形状：尖括号包裹的占位符（``<患者姓名>``），
#: 或 ``P-`` + 16 位十六进制的一致代号（task 24 的产物形态）。
DEFAULT_TOKEN_PATTERN = (
    r"<(?:[^<>\s]{1,32})>|(?<![0-9A-Za-z-])P-[0-9a-fA-F]{16}(?![0-9A-Za-z-])"
)

#: 还原操作在访问留痕里的操作名。
OPERATION_REQUESTED = "restore_requested"
OPERATION_PENDING = "restore_authorization_pending"
OPERATION_REJECTED = "restore_rejected"
OPERATION_EXECUTED = "restore_executed"


class RestoreServiceError(RuntimeError):
    """还原服务相关错误基类。"""


class RestoreStateError(RestoreServiceError):
    """批次当前状态不允许执行该还原动作。"""


class RestoreExecutionError(RestoreServiceError):
    """还原执行失败（未知代号 / 对照索引缺项）。

    抛出即中止：**不落盘、不写回执、不推进批次状态**。
    """


# --------------------------------------------------------------------- 对照索引


@runtime_checkable
class MappingIndex(Protocol):
    """对照索引（代号 ↔ 原文）的协议。

    脱敏侧登记（``record``），还原侧查询（``lookup`` / ``find_tokens``）。
    实现可换：进程内表、加密文件（task 26）、数据库 —— 业务层只认这四个方法。
    """

    def record(self, token: str, original: str) -> None:
        """登记一条对照（代号 → 原文）。"""

    def lookup(self, token: str) -> str | None:
        """按代号查原文；查不到返回 None（**不得返回空串冒充命中**）。"""

    def tokens(self) -> tuple[str, ...]:
        """已登记的全部代号。"""

    def find_tokens(self, text: str) -> tuple[str, ...]:
        """在文本里找出全部候选代号（按出现顺序去重）。"""


class InMemoryMappingIndex:
    """进程内对照表。

    本轮默认实现：脱敏与还原在同一个进程里完成时够用。**加密持久化版本**
    （与交付物分离存放、带访问留痕）由 task 26 落地，业务层不感知差异。

    :param token_pattern: 代号形状的正则；缺省见 :data:`DEFAULT_TOKEN_PATTERN`。
    """

    def __init__(self, token_pattern: str | re.Pattern[str] | None = None) -> None:
        self._pattern = re.compile(token_pattern or DEFAULT_TOKEN_PATTERN)
        self._entries: dict[str, str] = {}

    def record(self, token: str, original: str) -> None:
        """登记一条对照。"""
        key = str(token or "").strip()
        if not key:
            raise ValueError("代号不得为空串")
        self._entries[key] = str(original)

    def lookup(self, token: str) -> str | None:
        """按代号查原文；查不到返回 None。"""
        return self._entries.get(str(token))

    def tokens(self) -> tuple[str, ...]:
        """已登记的全部代号（按登记顺序）。"""
        return tuple(self._entries)

    def find_tokens(self, text: str) -> tuple[str, ...]:
        """在文本里找出全部候选代号（按出现顺序去重）。"""
        found: list[str] = []
        for match in self._pattern.finditer(text):
            token = match.group(0)
            if token not in found:
                found.append(token)
        return tuple(found)

    def __len__(self) -> int:
        return len(self._entries)


# --------------------------------------------------------------------- 结果


@dataclass(frozen=True)
class RestoreOutcome:
    """一次还原动作的结果。

    :param status: ``requested``（已受理待签字）/ ``pending``（挂起等签字）/
        ``rejected``（拒绝）/ ``restored``（已还原）。
    :param batch_no: 批次号。
    :param restore_request_id: 还原请求号（幂等键：同一请求重复执行不产生第二条回执）。
    :param approver_a: 授权人 A。
    :param approver_b: 授权人 B。
    :param scope: 涉及的材料 ID 清单。
    :param code: 裁决码。
    :param reason: 一句人话说明（**不含原文**）。
    :param receipt: 还原回执（挂起 / 拒绝时也有：挂起回执记「尚待签字」）。
    :param restored: 还原后的正文（material_id → 正文）；拒绝 / 挂起时为空。
    :param platform_receipt_status: 平台侧回执状态
        （``written`` / ``channel_suspended`` / ``failed`` / ``skipped``）。
    """

    status: str
    batch_no: str = ""
    restore_request_id: str = ""
    approver_a: str = ""
    approver_b: str = ""
    scope: tuple[str, ...] = ()
    code: str = ""
    reason: str = ""
    receipt: RestoreReceipt | None = None
    restored: Mapping[str, str] = field(default_factory=dict)
    platform_receipt_status: str = "skipped"

    @property
    def succeeded(self) -> bool:
        """是否已完成还原。"""
        return self.status == "restored"

    @property
    def rejected(self) -> bool:
        """是否被拒绝。"""
        return self.status == "rejected"

    @property
    def pending(self) -> bool:
        """是否挂起等签字。"""
        return self.status in ("requested", "pending")

    def summary(self) -> dict[str, object]:
        """一句可核对的摘要（**不含还原出来的原文**）。"""
        return {
            "status": self.status,
            "batch_no": self.batch_no,
            "restore_request_id": self.restore_request_id,
            "approver_a": self.approver_a,
            "approver_b": self.approver_b,
            "scope": list(self.scope),
            "code": self.code,
            "reason": self.reason,
            "restored_material_count": len(self.restored),
            "platform_receipt_status": self.platform_receipt_status,
        }


# --------------------------------------------------------------------- 服务


class RestoreService:
    """受控还原服务。

    :param index: 对照索引（代号 ↔ 原文）。
    :param ledger: 批次台账；给了就落回执、访问留痕与状态迁移。
    :param platform: 科研数据平台客户端；给了就把还原回执写到平台侧。
    :param alert_sink: 告警落点；缺省用台账。
    :param validator: 授权裁决器；缺省按环境变量装配。
    :param now_fn: 取当前时间的方式（测试可注入固定时钟）。
    """

    def __init__(
        self,
        *,
        index: MappingIndex,
        ledger: Any | None = None,
        platform: Any | None = None,
        alert_sink: Any | None = None,
        validator: AuthorityValidator | None = None,
        now_fn: Callable[[], datetime] = utcnow,
        ttl: timedelta = DEFAULT_AUTHORIZATION_TTL,
    ) -> None:
        self.index = index
        self._ledger = ledger
        self._platform = platform
        self._alert_sink = alert_sink if alert_sink is not None else ledger
        self._validator = validator if validator is not None else AuthorityValidator()
        self._now = now_fn
        self.ttl = ttl

    # ------------------------------------------------------------------ 受理

    def request(
        self,
        authorization: RestoreAuthorization,
        *,
        batch_no: str,
        dataset_id: str = "",
        allowed_scope: Sequence[str] = (),
    ) -> RestoreOutcome:
        """受理还原请求：授权人 A 在位 → 批次进入 ``restore_pending``。

        这一步只认「授权人 A 在位且在授权名单内」；授权是否齐备、是否过期、
        范围是否相符由 :meth:`execute` 裁决。**缺授权人 A 的请求直接拒绝** ——
        无人授权的请求连「待办」都不该建。

        :param authorization: 还原授权。
        :param batch_no: 批次号。
        :param dataset_id: 平台侧数据集 ID（缺省从台账的交付回执里取）。
        :param allowed_scope: 本批已交付的材料 ID 清单。
        """
        approver_a = str(authorization.approver_a or "").strip()
        if not approver_a:
            return self._reject(
                authorization,
                batch_no=batch_no,
                dataset_id=dataset_id,
                code=CODE_MISSING_APPROVER_A,
                reason="还原请求缺授权人 A：无人授权不得进入还原流程",
                advance=False,
            )
        if not self._validator.registry.contains(approver_a):
            return self._reject(
                authorization,
                batch_no=batch_no,
                dataset_id=dataset_id,
                code="approver_not_registered",
                reason=(
                    f"授权人 A 不在授权名单内：{approver_a}"
                    f"（{self._validator.registry.describe()}）"
                ),
                advance=False,
            )
        self._advance(
            batch_no,
            BatchEvent.RESTORE_REQUESTED,
            TransitionContext(approver_a=approver_a),
            reason="还原请求到达，等第二授权人签字",
        )
        self._record_access(
            batch_no,
            actor=approver_a,
            operation=OPERATION_REQUESTED,
            detail=(
                "还原请求已受理，等待第二授权人签字；"
                f"授权范围材料：{'、'.join(authorization.scope) or '（未声明）'}"
            ),
        )
        return RestoreOutcome(
            status="requested",
            batch_no=batch_no,
            restore_request_id=authorization.request_id,
            approver_a=approver_a,
            scope=tuple(authorization.scope),
            code=CODE_MISSING_APPROVER_B,
            reason="还原请求已受理，等待第二授权人签字",
        )

    # ------------------------------------------------------------------ 执行

    def execute(
        self,
        authorization: RestoreAuthorization,
        *,
        batch_no: str,
        materials: Mapping[str, str],
        dataset_id: str = "",
        allowed_scope: Sequence[str] = (),
        output_dir: str | Path | None = None,
    ) -> RestoreOutcome:
        """执行一次受控还原。

        流程：授权裁决 → 全量回填（先算完再落盘）→ 落还原件 → 推进状态 →
        写回执与留痕 → 写平台侧还原回执。

        :param authorization: 还原授权（双人、时效、范围都要齐备）。
        :param batch_no: 批次号。
        :param materials: 要还原的脱敏正文（material_id → 正文）。
        :param dataset_id: 平台侧数据集 ID；缺省从台账的交付回执里取。
        :param allowed_scope: 本批已交付的材料 ID 清单。
        :param output_dir: 还原件落盘目录；给了就写出还原后的正文。
        :return: 还原结果（放行 / 挂起 / 拒绝）。
        :raises RestoreStateError: 批次当前状态不允许还原。
        :raises RestoreExecutionError: 对照索引缺项（未知代号）—— 中止，不落盘。
        """
        rejection = self._ensure_restore_pending(
            authorization, batch_no=batch_no, dataset_id=dataset_id, allowed_scope=allowed_scope
        )
        if rejection is not None:
            # 请求本身就被拒（如授权人 A 不在名单内）：直接返回拒绝结论，
            # 不进入执行阶段。
            return rejection
        resolved_dataset_id = dataset_id or self._dataset_id_of(batch_no)
        decision = self._validator.validate(
            authorization,
            allowed_scope=allowed_scope,
            requested_scope=tuple(materials.keys()),
        )
        if decision.pending:
            return self._pending(
                authorization,
                decision,
                batch_no=batch_no,
                dataset_id=resolved_dataset_id,
            )
        if not decision.approved:
            return self._reject(
                authorization,
                batch_no=batch_no,
                dataset_id=resolved_dataset_id,
                code=decision.code,
                reason=decision.reason,
                advance=True,
            )

        # 全量回填：先算完，任何一份材料出错就整体中止（不留半成品）
        restored: dict[str, str] = {}
        replaced = 0
        for material_id, text in materials.items():
            restored_text, count = self._restore_text(text, material_id)
            restored[material_id] = restored_text
            replaced += count

        # 落还原件
        if output_dir is not None:
            target = Path(output_dir)
            target.mkdir(parents=True, exist_ok=True)
            for material_id, text in restored.items():
                (target / f"{material_id}.txt").write_text(text, encoding="utf-8")

        # 状态推进：批次 → restored（推进失败就不写「已还原」的回执）
        self._advance(
            batch_no,
            BatchEvent.RESTORE_APPROVED,
            TransitionContext(
                approver_a=decision.approver_a,
                approver_b=decision.approver_b,
                authorization_expired=False,
                scope_ok=True,
            ),
            reason=(
                f"双人授权齐备（{decision.approver_a} / {decision.approver_b}），"
                f"按范围还原 {len(restored)} 份材料"
            ),
        )

        receipt = self._build_receipt(
            authorization,
            decision,
            dataset_id=resolved_dataset_id,
            result_summary=(
                f"已还原 {len(restored)} 份材料，回填代号 {replaced} 处"
            ),
            restored_material_count=len(restored),
            replaced_count=replaced,
        )
        self._record_receipt(batch_no, receipt, kind="restore")

        # 平台侧还原回执：写不进去要留痕，不能吞掉
        platform_status, platform_id = self._write_platform_audit(
            receipt,
            batch_no=batch_no,
            dataset_id=resolved_dataset_id,
        )
        receipt = replace(receipt, platform_receipt_id=platform_id or None)
        self._record_receipt(batch_no, receipt, kind="restore")

        self._record_access(
            batch_no,
            actor=decision.approver_a,
            operation=OPERATION_EXECUTED,
            detail=(
                f"第二授权人：{decision.approver_b}；"
                f"还原材料：{'、'.join(sorted(restored)) or '（无）'}；"
                f"回填代号 {replaced} 处；平台回执：{platform_status}"
            ),
        )
        return RestoreOutcome(
            status="restored",
            batch_no=batch_no,
            restore_request_id=authorization.request_id,
            approver_a=decision.approver_a,
            approver_b=decision.approver_b,
            scope=tuple(sorted(restored)),
            code="approved",
            reason=decision.reason,
            receipt=receipt,
            restored=restored,
            platform_receipt_status=platform_status,
        )

    # ------------------------------------------------------------------ 分支

    def _pending(
        self,
        authorization: RestoreAuthorization,
        decision: AuthorityDecision,
        *,
        batch_no: str,
        dataset_id: str,
    ) -> RestoreOutcome:
        """挂起分支：缺第二授权人 —— 原地等签字，不降级为单人。"""
        self._advance(
            batch_no,
            BatchEvent.RESTORE_AUTHORIZATION_PENDING,
            TransitionContext(approver_a=decision.approver_a),
            reason=decision.reason,
        )
        self._record_access(
            batch_no,
            actor=decision.approver_a,
            operation=OPERATION_PENDING,
            detail=f"还原挂起等待第二授权人签字：{decision.reason}",
        )
        receipt = self._build_receipt(
            authorization,
            decision,
            dataset_id=dataset_id,
            result_summary="尚待第二授权人签字，未执行还原",
            restored_material_count=0,
            replaced_count=0,
        )
        self._record_receipt(batch_no, receipt, kind="restore_pending")
        return RestoreOutcome(
            status="pending",
            batch_no=batch_no,
            restore_request_id=authorization.request_id,
            approver_a=decision.approver_a,
            approver_b="",
            scope=tuple(authorization.scope),
            code=decision.code,
            reason=decision.reason,
            receipt=receipt,
        )

    def _reject(
        self,
        authorization: RestoreAuthorization,
        *,
        batch_no: str,
        dataset_id: str,
        code: str,
        reason: str,
        advance: bool,
    ) -> RestoreOutcome:
        """拒绝分支：批次转 ``restore_rejected`` 并留痕。"""
        if advance:
            self._advance(
                batch_no,
                BatchEvent.RESTORE_REJECTED,
                TransitionContext(
                    approver_a=str(authorization.approver_a or "").strip(),
                    approver_b=str(authorization.approver_b or "").strip(),
                ),
                reason=reason,
            )
        self._record_access(
            batch_no,
            actor=str(authorization.approver_a or "").strip(),
            operation=OPERATION_REJECTED,
            detail=f"还原被拒（{code}）：{reason}",
        )
        receipt = self._build_receipt(
            authorization,
            AuthorityDecision(
                approved=False,
                pending=False,
                code=code,
                reason=reason,
                approver_a=str(authorization.approver_a or "").strip(),
                approver_b=str(authorization.approver_b or "").strip(),
            ),
            dataset_id=dataset_id,
            result_summary=f"还原被拒：{reason}",
            restored_material_count=0,
            replaced_count=0,
        )
        self._record_receipt(batch_no, receipt, kind="restore_rejected")
        return RestoreOutcome(
            status="rejected",
            batch_no=batch_no,
            restore_request_id=authorization.request_id,
            approver_a=str(authorization.approver_a or "").strip(),
            approver_b=str(authorization.approver_b or "").strip(),
            scope=tuple(authorization.scope),
            code=code,
            reason=reason,
            receipt=receipt,
        )

    # ------------------------------------------------------------------ 内部

    def _restore_text(self, text: str, material_id: str) -> tuple[str, int]:
        """把一份脱敏正文里的代号换回原文。

        **两条还原路径**（按对照索引的能力自动选择）：

        - **按出现次序还原**（对照索引按「材料 + 代号 + 第几次出现」分槽时）——
          同一代号在正文里可能对应多段不同原文（姓名一处、住院号一处），
          按次序逐处取回才对得上位置；
        - **按代号还原**（单值对照表时）—— 一个代号对应一段原文，整串替换。

        :raises RestoreExecutionError: 出现对照索引里查不到的代号 —— 不静默跳过。
        """
        occurrences = self._find_occurrences(text, material_id)
        if occurrences is not None:
            return self._restore_by_occurrence(text, occurrences, material_id)

        tokens = self.index.find_tokens(text)
        unknown = [token for token in tokens if self.index.lookup(token) is None]
        if unknown:
            raise RestoreExecutionError(
                f"材料 {material_id} 含 {len(unknown)} 处未知代号（对照索引缺项）："
                "不得静默跳过，请先补齐对照索引再还原"
            )
        result = text
        replaced = 0
        for token in sorted(tokens, key=len, reverse=True):
            original = self.index.lookup(token)
            if original is None or original == token:
                continue
            replaced += result.count(token)
            result = result.replace(token, original)
        return result, replaced

    def _find_occurrences(self, text: str, material_id: str):
        """取正文里的代号及其出现次序；对照索引不支持分槽时返回 None。"""
        finder = getattr(self.index, "find_occurrences", None)
        if finder is None:
            return None
        return tuple(finder(text, material_id))

    def _restore_by_occurrence(self, text, occurrences, material_id: str) -> tuple[str, int]:
        """按出现次序逐处还原（位置替换，长度变化不影响其它位置）。

        :raises RestoreExecutionError: 某一处代号在对照索引里缺项 —— 中止，
            不落盘、不写回执、不推进状态。
        """
        pieces: list[str] = []
        cursor = 0
        replaced = 0
        for occurrence in occurrences:
            original = self.index.lookup_occurrence(
                material_id, occurrence.token, occurrence.occurrence
            )
            if original is None:
                raise RestoreExecutionError(
                    f"材料 {material_id} 的第 {occurrence.occurrence + 1} 处代号"
                    "在对照索引里缺项：不得静默跳过，请先补齐对照索引再还原"
                )
            pieces.append(text[cursor : occurrence.start])
            pieces.append(original)
            cursor = occurrence.end
            replaced += 1
        pieces.append(text[cursor:])
        return "".join(pieces), replaced

    def _ensure_restore_pending(
        self,
        authorization: RestoreAuthorization,
        *,
        batch_no: str,
        dataset_id: str,
        allowed_scope: Sequence[str],
    ) -> RestoreOutcome | None:
        """确保批次处在 ``restore_pending``；还在 ``delivered`` 就先受理请求。

        :return: 受理阶段的拒绝结论（None = 已进入 ``restore_pending``）。
        """
        state = self._batch_state(batch_no)
        if state is None:
            raise RestoreStateError(f"批次不存在：{batch_no}")
        if state is BatchState.DELIVERED:
            outcome = self.request(
                authorization,
                batch_no=batch_no,
                dataset_id=dataset_id,
                allowed_scope=allowed_scope,
            )
            if outcome.rejected:
                return outcome
            return None
        if state is not BatchState.RESTORE_PENDING:
            raise RestoreStateError(
                f"批次 {batch_no} 当前状态为 {state.value}，不接受还原"
                "（还原只发生在已交付批次上）"
            )
        return None

    def _batch_state(self, batch_no: str) -> BatchState | None:
        """取批次当前状态；没有台账时返回 None。"""
        if self._ledger is None:
            return None
        record = self._ledger.get_batch(batch_no)
        if record is None:
            return None
        return record.batch_state

    def _advance(
        self,
        batch_no: str,
        event: BatchEvent,
        ctx: TransitionContext,
        *,
        reason: str,
    ) -> None:
        """走一步状态迁移（没有台账时什么都不做）。"""
        if self._ledger is None:
            return
        self._ledger.advance(batch_no, event, ctx, reason=reason, current_step="restore")

    def _dataset_id_of(self, batch_no: str) -> str:
        """从台账的交付回执里取平台侧数据集 ID。"""
        if self._ledger is None:
            return ""
        for receipt in self._ledger.receipts(batch_no):
            if receipt.kind == "delivery":
                return str(receipt.payload.get("dataset_id") or "")
        return ""

    def _build_receipt(
        self,
        authorization: RestoreAuthorization,
        decision: AuthorityDecision,
        *,
        dataset_id: str,
        result_summary: str,
        restored_material_count: int,
        replaced_count: int,
    ) -> RestoreReceipt:
        """组装还原回执（**不含原文**）。"""
        return RestoreReceipt(
            receipt_id=f"RR-{authorization.request_id}",
            restore_request_id=authorization.request_id,
            dataset_id=dataset_id,
            approver_a=decision.approver_a,
            approver_b=decision.approver_b,
            scope=tuple(authorization.scope),
            reason=str(authorization.reason or ""),
            result_summary=result_summary,
            granted_at=authorization.granted_at,
            expires_at=authorization.expires_at,
            created_at=self._now(),
        )

    def _record_receipt(
        self, batch_no: str, receipt: RestoreReceipt, *, kind: str
    ) -> None:
        """回执落台账（**不含原文**：只记材料 ID、条数、授权人与结论）。"""
        if self._ledger is None:
            return
        self._ledger.record_receipt(
            receipt_id=receipt.receipt_id,
            batch_no=batch_no,
            kind=kind,
            payload={
                "restore_request_id": receipt.restore_request_id,
                "dataset_id": receipt.dataset_id,
                "approver_a": receipt.approver_a,
                "approver_b": receipt.approver_b,
                "scope": list(receipt.scope),
                "reason": receipt.reason,
                "result_summary": receipt.result_summary,
                "granted_at": receipt.granted_at.isoformat()
                if receipt.granted_at
                else "",
                "expires_at": receipt.expires_at.isoformat()
                if receipt.expires_at
                else "",
            },
            platform_receipt_id=receipt.platform_receipt_id,
        )

    def _record_access(
        self, batch_no: str, *, actor: str, operation: str, detail: str
    ) -> None:
        """落一条访问留痕（谁、何时、还原了哪些材料、结果摘要）。"""
        if self._ledger is None:
            return
        self._ledger.record_access(batch_no, actor, operation, detail)

    def _write_platform_audit(
        self, receipt: RestoreReceipt, *, batch_no: str, dataset_id: str
    ) -> tuple[str, str]:
        """把还原回执写到科研数据平台。

        :return: ``(状态, 平台侧回执 ID)``；状态取值
            ``written`` / ``channel_suspended`` / ``failed`` / ``skipped``。
        """
        if self._platform is None:
            return "skipped", ""
        if not dataset_id:
            self._record_platform_alert(
                batch_no,
                receipt,
                "平台侧数据集 ID 未知：还原回执未能写到平台侧",
            )
            return "failed", ""
        try:
            platform_receipt = self._platform.record_restore_audit(
                restore_request_id=receipt.restore_request_id,
                dataset_id=dataset_id,
                approver_a=receipt.approver_a,
                approver_b=receipt.approver_b,
                scope=receipt.scope,
                reason=receipt.reason,
                granted_at=(
                    receipt.granted_at.isoformat() if receipt.granted_at else ""
                ),
                expires_at=(
                    receipt.expires_at.isoformat() if receipt.expires_at else ""
                ),
                result_summary=receipt.result_summary,
            )
        except OutboundError as exc:
            status = (
                "channel_suspended"
                if exc.__class__.__name__ == "ChannelSuspendedError"
                else "failed"
            )
            self._record_platform_alert(
                batch_no, receipt, f"还原回执未能写到平台侧：{exc}"
            )
            return status, ""
        platform_id = getattr(platform_receipt, "restore_audit_id", "") or ""
        return "written", platform_id

    def _record_platform_alert(
        self, batch_no: str, receipt: RestoreReceipt, message: str
    ) -> None:
        """平台回执写不进去 → 落一条告警（不吞掉）。"""
        if self._alert_sink is None:
            return
        self._alert_sink.record(
            BatchAlert(
                batch_no=batch_no,
                code="restore_platform_receipt_missing",
                level="error",
                count=1,
                message=(
                    f"{message}（本地还原回执已落台账，平台侧待补写；"
                    "已执行的还原不回滚）"
                ),
                notified=False,
                notify_channel="pending",
            )
        )
