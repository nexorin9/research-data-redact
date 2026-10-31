"""批次处理：入站校验 → 脱敏 → 残留自检 → 落产物 → 进投递队列。

这是守护进程的处理主路径，**与运维 CLI 共用**
:mod:`research_redact.daemon.pipeline` 的脱敏主路径和
:mod:`research_redact.audit.ledger` 的批次台账 —— 守护进程与 CLI 不各写一份
处理逻辑，只是一个常驻、一个手动触发。

一个批次的完整闭环：

1. **入站**：读申请单 → 校验伦理批件号与材料清单。缺批件号即 ``blocked``，
   不降级放行。
2. **脱敏**：逐份材料跑识别 → 按策略处置 → 产出脱敏副本与逐处命中清单。
3. **残留自检**：对脱敏副本再扫一遍身份类。残留非 0 时**不放行**。
4. **落产物**：脱敏副本与命中清单写进产物目录，路径记进台账。
5. **投递**：交投递队列；投递成功才进 ``delivered``。

**断点续跑**：上一步崩了（断电、进程被 kill、机器重启）时，这一批不能从头
再来 —— 每一步都落进台账的 ``completed_steps``，重启后从最后一步接上：识别
已完成且产物还在、摘要对得上、源材料没变 → **复用上一轮的脱敏产物，不重跑
识别**（见 :mod:`research_redact.daemon.resume`）。

**去重**：处理不处理由批次状态说了算 —— 已交付的批次不会被兜底扫描重复处理
（见 :meth:`BatchRunner.is_processable`）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ..audit.alerts import AlertNotifier, BatchAlert, JsonlAlertSink
from ..audit.ledger import BatchLedger
from ..audit.residual import ResidualChecker
from ..idempotency import compute_idempotency_key, material_set_fingerprint
from ..ingest.application import (
    ApplicationError,
    IntakeResult,
    MaterialPlan,
    dedupe_material_rows,
    load_application,
)
from ..materials.dicom_redact import (
    DicomError,
    DicomRedaction,
    redact_dicom_bytes,
)
from ..policy.conflicts import ConflictRules
from ..policy.dicom import DicomConfig
from ..policy.mapping import OccurrenceMappingIndex, PseudonymMappingIndex
from ..policy.operators import ActionSpec, OperatorRegistry, default_operator_registry
from ..policy.snapshot import (
    PolicySnapshot,
    SnapshotError,
    capture_snapshot,
    default_snapshot_dir,
)
from ..policy.table import PolicyTable, load_policy_table
from ..recognizers.registry import RecognizerRegistry
from .pipeline import redact_batch
from .resume import (
    STEP_INTAKE,
    STEP_PAYLOAD,
    STEP_REDACT,
    STEP_RESIDUAL,
    ResumePlan,
    plan_resume,
)
from .state_machine import BatchState
from .locks import BatchLock, LockOutcome, default_lock_dir
from .watcher import InboxApplication

__all__ = [
    "BatchRunResult",
    "BatchRunner",
    "MAX_CONSECUTIVE_FAILURES",
]

#: 同一批次连续失败多少次后，本进程不再自动重试（避免死循环刷屏）。
#: 失败原因已落告警台账，人工处理后重启守护进程即可恢复。
MAX_CONSECUTIVE_FAILURES = 3

#: 这些材料类型按文本处理（识别 → 处置 → 残留自检）。
_TEXT_KINDS = ("report_text", "report_json", "table")

#: 影像材料类型：走 DICOM tag 级去标识（身份 tag 清空、私有 tag 全清）。
_DICOM_KIND = "dicom"


@dataclass(frozen=True)
class BatchRunResult:
    """一次批次处理的结果。

    :param batch_no: 批次号（申请单号）。
    :param state: 处理完之后的批次状态。
    :param processed: 是否真的跑了脱敏主路径。
    :param skipped: 是否被跳过（原因在 ``note``）。
    :param note: 人话说明（跳过原因 / 残留结论）。
    :param entries: 命中清单条数。
    :param materials: 本批处理的材料份数（结构化日志的「材料数」字段）。
    :param residual: 残留自检结论摘要。
    :param deliverable: 是否可以进入投递（残留自检通过）。
    :param payload: 投递载荷（可交付时才有）。
    :param artifacts: 产物路径（材料 ID → 脱敏副本路径；另含 ``manifest``）。
    :param resumed: 本次是**断点续跑**（复用了上一轮的脱敏产物，没重跑识别）。
    :param duplicates: 申请单里重复出现的材料 ID（已按首次出现去重）。
    :param concurrent: 本次因**并发互斥**没有重复处理（另一执行者在处理，
        或已处理完可复用）。
    """

    batch_no: str
    state: str = ""
    processed: bool = False
    skipped: bool = False
    note: str = ""
    entries: int = 0
    materials: int = 0
    residual: str = ""
    deliverable: bool = False
    payload: Mapping[str, object] = field(default_factory=dict)
    artifacts: Mapping[str, str] = field(default_factory=dict)
    resumed: bool = False
    duplicates: tuple[str, ...] = ()
    concurrent: bool = False


class BatchRunner:
    """批次处理器。

    :param output_dir: 产物目录（``$RESEARCH_OUTPUT_DIR``）。
    :param ledger: 批次台账。
    :param registry: 识别器注册表；缺省按策略表装配。
    :param notifier: 告警推送出口（企业微信等）；缺省按环境变量装配，
        未配置时明确记「没推出去」。
    :param checker: 残留自检器；缺省新建一个（告警落 JSONL 台账、批次摘要
        落 SQLite 台账、阻断级残留推一次企业微信）。
    :param lock_dir: 批次互斥锁目录；缺省跟着台账走（守护进程与运维 CLI
        共用同一张台账 → 共用同一把锁）。
    :param lock_timeout: 拿不到批次锁时最多等多久（秒）；等不到就跳过这一轮。
    :param policy_table: 本次生效的策略表；缺省按 ``$RESEARCH_POLICY_FILE``
        装载。**快照按它取**（task 36）—— 注入注册表时也该注入同一份策略表，
        否则快照记的版本与实际跑的识别口径对不上。
    :param snapshot_dir: 策略快照目录；缺省 :func:`default_snapshot_dir`。
    """

    def __init__(
        self,
        *,
        output_dir: str | Path,
        ledger: BatchLedger,
        registry: RecognizerRegistry | None = None,
        actions: Callable[[str], ActionSpec] | None = None,
        operators: OperatorRegistry | None = None,
        rules: ConflictRules | None = None,
        checker: ResidualChecker | None = None,
        mapping_index: OccurrenceMappingIndex | None = None,
        dicom_config: DicomConfig | None = None,
        notifier: AlertNotifier | None = None,
        lock_dir: str | Path | None = None,
        lock_timeout: float = 30.0,
        policy_table: PolicyTable | None = None,
        snapshot_dir: str | Path | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self._ledger = ledger
        self._lock_dir = (
            Path(lock_dir)
            if lock_dir is not None
            else default_lock_dir(ledger, self.output_dir)
        )
        self._lock_timeout = max(0.0, float(lock_timeout))
        self._registry = registry
        self._actions = actions
        self._policy_table = policy_table
        self._snapshot_dir = Path(snapshot_dir) if snapshot_dir is not None else None
        self._mapping_index = (
            mapping_index if mapping_index is not None else PseudonymMappingIndex()
        )
        self._operators = (
            operators
            if operators is not None
            else default_operator_registry(mapping_index=self._mapping_index)
        )
        self._rules = rules
        self._notifier = notifier if notifier is not None else _build_notifier()
        self._checker = (
            checker
            if checker is not None
            else ResidualChecker(
                sink=JsonlAlertSink(),
                notifier=self._notifier,
                summary_sink=self._ledger,
            )
        )
        self._dicom_config = dicom_config
        self._failures: dict[str, int] = {}

    @property
    def dicom_config(self) -> DicomConfig:
        """本次使用的 DICOM 处置口径（缺省读策略表 ``dicom`` 段）。"""
        if self._dicom_config is None:
            self._dicom_config = load_policy_table().dicom
        return self._dicom_config

    @property
    def mapping_index(self) -> OccurrenceMappingIndex:
        """本进程共用的对照索引。

        脱敏侧把「代号 ↔ 原文」登记进来，还原侧（受控还原）从同一份索引取回
        —— 两边必须共用一份，否则「脱得出去、还原不回来」。
        """
        return self._mapping_index

    @property
    def policy_table(self) -> PolicyTable:
        """本次生效的策略表（快照按它取，task 36）。"""
        if self._policy_table is None:
            self._policy_table = load_policy_table()
        return self._policy_table

    @property
    def snapshot_dir(self) -> Path:
        """策略快照目录（缺省**跟着台账走** —— 与批次锁同一个道理）。"""
        if self._snapshot_dir is None:
            self._snapshot_dir = default_snapshot_dir(
                ledger=self._ledger, output_dir=self.output_dir
            )
        return self._snapshot_dir

    # ------------------------------------------------------------------ 判定

    def is_processable(
        self, batch_no: str, *, via_event: bool = False
    ) -> tuple[bool, str]:
        """这个批次现在该不该处理。

        :param batch_no: 批次号。
        :param via_event: 是否由「目录内容有变化」触发。事件触发允许重投
            （补齐批件号、材料补齐后重新脱敏）；兜底扫描只处理还没走完的批次。
        :return: ``(该不该处理, 说明)``。
        """
        failures = self._failures.get(batch_no, 0)
        if failures >= MAX_CONSECUTIVE_FAILURES:
            return False, f"该批次已连续失败 {failures} 次，等待人工处理后重启守护进程"
        record = self._ledger.get_batch(batch_no)
        if record is None:
            return True, ""
        state = record.batch_state
        if state in (BatchState.DETECTED, BatchState.RECOGNIZED):
            return True, ""
        if via_event and state is BatchState.BLOCKED:
            return True, ""
        if state is BatchState.PSEUDONYMIZED:
            if via_event:
                return True, ""
            if not self._has_delivery_record(record):
                # 崩在「产物已落盘、投递载荷还没登记」那一步：这份记录交不出
                # 一份完整交付体，得重跑识别把记录补齐（见 daemon/resume.py）。
                return True, ""
            return False, "批次已代号化，等投递"
        if state in (BatchState.DELIVERED, BatchState.RESTORED, BatchState.RESTORE_REJECTED):
            return False, f"批次已处于 {state.value}，不重复处理"
        if state is BatchState.PENDING_DELIVERY:
            return False, "批次挂起等重投，由投递通道处理"
        if state is BatchState.SUSPENDED:
            return False, "批次挂起等主索引恢复"
        return False, f"批次处于 {state.value}，本轮不处理"

    @staticmethod
    def _has_delivery_record(record) -> bool:
        """台账里这一批的投递记录是否**完整**（能重建出一份交付体）。

        完整 = 产物路径已登记 + 材料清单已登记 + 幂等键已登记。三样缺一样，
        补投就会交出一份缺材料或缺幂等键的交付体 —— 宁可重跑识别补齐。
        """
        if record is None:
            return False
        artifacts = dict(record.artifacts or {})
        if not artifacts.get("manifest"):
            return False
        if not record.material_entries:
            return False
        return bool(record.idempotency_key)

    # ------------------------------------------------------------------ 处理

    def process(self, application: InboxApplication, *, via_event: bool = False) -> BatchRunResult:
        """处理一份申请单（**同批次互斥**：同一时刻只有一个执行者在处理）。

        守护进程与运维 CLI 可能同时盯上同一批材料（管理员投目录的同时，
        值班的人在 CLI 上点了一次 run）。两个执行者同时脱敏的后果不是「慢
        一点」：一致代号会分叉、命中清单会翻倍、外发会多一次。所以这里先拿
        **批次锁**：拿不到就说明另一个执行者正在处理，本轮不重复脱敏。

        :param application: 交付目录里的申请单。
        :param via_event: 是否由目录内容变化触发。
        """
        batch_no = application.application_no
        lock = BatchLock(self._lock_path(batch_no), timeout=self._lock_timeout)
        outcome = lock.acquire()
        if not outcome.acquired:
            return self._concurrent_result(batch_no, outcome)
        try:
            return self._process_locked(application, via_event=via_event)
        finally:
            lock.release()

    def _process_locked(
        self, application: InboxApplication, *, via_event: bool = False
    ) -> BatchRunResult:
        """持锁处理一份申请单（临界区里的真正处理逻辑）。"""
        batch_no = application.application_no
        record = self._ledger.get_batch(batch_no)
        state = record.batch_state if record is not None else None
        processable, reason = self.is_processable(batch_no, via_event=via_event)
        if not processable:
            # 已交付的批次：**材料集合变了就是新的一批**（不能当重复丢掉），
            # 没变就复用已有产物与回执 —— 不重跑脱敏，也不重复外发。
            if state is BatchState.DELIVERED and self._material_set_changed(
                application, record
            ):
                reason = "材料集合已变化：按新的材料集合重新交付"
            else:
                return BatchRunResult(
                    batch_no=batch_no,
                    state=state.value if state is not None else "",
                    skipped=True,
                    note=reason,
                )

        try:
            intake = load_application(application.application_file)
        except (ApplicationError, FileNotFoundError, OSError) as exc:
            self._fail(batch_no, f"申请单读不出来：{exc}")
            return BatchRunResult(
                batch_no=batch_no, skipped=True, note=f"申请单读不出来：{exc}"
            )

        record = self._ledger.get_batch(batch_no)
        state = record.batch_state if record is not None else None

        # ---- 1. 入站校验 ----
        if state in (None, BatchState.DETECTED, BatchState.BLOCKED):
            if state is BatchState.BLOCKED and intake.is_blocked:
                return BatchRunResult(
                    batch_no=batch_no,
                    state=state.value,
                    skipped=True,
                    note=f"申请单仍缺项（{intake.missing_summary}），等待人工补齐后重新投递",
                )
            record = self._ledger.apply_intake(intake)
            state = record.batch_state
        if state is BatchState.BLOCKED:
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value,
                skipped=True,
                note=f"申请单被阻断：{intake.missing_summary}",
            )

        # ---- 1b. 断点续跑：识别已完成就不重跑 ----
        # 崩在识别之后（断电、进程被 kill）时，这一批的脱敏产物还在磁盘上，
        # 台账里也有步骤记录 —— 直接复用，不重跑识别（重跑会让一致代号变样）。
        resumed = self._try_resume(application, intake, record, state)
        if resumed is not None:
            return resumed

        # ---- 2. 读材料（材料 ID 重复的先按首次出现去重）----
        plan = dedupe_material_rows(intake.rows)
        materials, dicom_materials, missing, deferred = self._read_materials(
            application, plan
        )
        duplicates = plan.duplicates
        duplicate_note = ""
        if duplicates:
            # 重复材料 ID 要**告警**：静默去重等于替人决定哪一行才是对的。
            self._record_duplicate_materials(batch_no, plan)
            duplicate_note = (
                "（材料 ID 重复 "
                + "、".join(duplicates)
                + "：已按首次出现去重，未重复替换）"
            )
        if missing:
            self._fail(batch_no, "材料缺失：" + "、".join(missing))
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value,
                skipped=True,
                note="材料缺失：" + "、".join(missing),
                duplicates=duplicates,
            )
        if not materials and not dicom_materials:
            self._fail(batch_no, "本批没有可处理的材料")
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value,
                skipped=True,
                note="本批没有可处理的材料（" + ("、".join(deferred) or "无") + "）",
                duplicates=duplicates,
            )

        # ---- 2b. 批次身份（材料集合指纹 / 幂等键）----
        # 先算身份再脱敏：命中清单的重放去重要按批次身份划范围（同一批材料
        # 重放 = 同一条；材料换了 = 新的一批，清单也要跟着换）。
        source_digests = self._source_digests(application, intake)
        fingerprint = material_set_fingerprint(
            [
                {"material_id": material_id, "source_sha256": digest}
                for material_id, digest in source_digests.items()
            ]
        )
        idempotency_key = compute_idempotency_key(batch_no, fingerprint)

        # ---- 2c. 策略快照（这一批是用哪一版策略脱的）----
        # 策略表是活的：科室改阈值、信息科改白名单，改完上一批「怎么脱出来的」
        # 就说不清了。快照把生效配置冻结一份，事后能重放、能对上版本号。
        #
        # 快照写不出 / 含凭据 → **这一批不交付**：没有快照的批次事后不可复现，
        # 交出去以后没人说得清当时按什么规则脱的。不静默跳过、不留半份。
        try:
            snapshot = capture_snapshot(
                batch_no, self.policy_table, self.snapshot_dir
            )
        except SnapshotError as exc:
            self._fail(batch_no, f"策略快照写不出：{exc}")
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value if state is not None else "",
                skipped=True,
                note=f"策略快照写不出：{exc}",
                duplicates=duplicates,
            )
        self._ledger.record_policy_snapshot(
            batch_no,
            policy_version=snapshot.policy_version,
            policy_sha256=snapshot.policy_sha256,
            profile=snapshot.profile,
            source=snapshot.source,
            source_sha256=snapshot.source_sha256,
            snapshot_dir=str(snapshot.directory),
            policy_path=str(snapshot.policy_path),
        )
        self._ledger.set_policy_version(batch_no, snapshot.policy_version)

        # ---- 3. 脱敏 + 残留自检（共用主路径）----
        batch = redact_batch(
            batch_no,
            materials,
            checker=self._checker,
            registry=self._registry,
            actions=self._actions,
            operators=self._operators,
            rules=self._rules,
        )
        entries = sum(len(outcome.entries) for outcome in batch.outcomes)

        # ---- 3b. DICOM 材料：tag 级去标识（身份 tag 清空、私有 tag 全清）----
        dicom_outcomes, dicom_error = self._redact_dicom_materials(
            batch_no, dicom_materials
        )
        if dicom_error:
            self._fail(batch_no, dicom_error)
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value,
                skipped=True,
                note=dicom_error,
                duplicates=duplicates,
            )
        entries += sum(len(outcome.entries) for outcome in dicom_outcomes)

        # ---- 4. 落产物（命中清单按批次身份追加去重）----
        artifacts = self._write_artifacts(
            batch_no, batch, dicom_outcomes, scope=fingerprint, snapshot=snapshot
        )
        self._ledger.set_artifacts(batch_no, artifacts)
        # 清单条数以**落盘的那份**为准（去重后的行数）—— 交差时数的是清单，
        # 不是这一轮识别出了几处。
        entries = len(self._ledger.manifest_entries(batch_no, fingerprint))

        # ---- 4b. 登记批次身份（材料集合指纹 / 材料清单 / 幂等键）----
        # 这一步紧跟落产物：崩在这里之前，台账里就没有「这批是哪批材料、
        # 用哪把幂等键」的记录 —— 重启后既认不出重复批次，也交不出完整
        # 交付体。登记齐了，后面哪一步崩了都能接着走（见 daemon/resume.py）。
        material_entries = self._material_manifest(intake, artifacts, source_digests)
        self._ledger.set_material_fingerprint(batch_no, fingerprint)
        self._ledger.set_material_entries(batch_no, material_entries)
        self._ledger.set_idempotency_key(batch_no, idempotency_key)
        self._ledger.complete_step(batch_no, STEP_INTAKE)
        self._ledger.complete_step(batch_no, STEP_REDACT)

        # ---- 5. 状态推进 ----
        if state is BatchState.RECOGNIZED:
            self._ledger.apply_recognition(
                batch_no,
                material_count=len(materials) + len(dicom_materials),
                recognized_material_count=len(batch.outcomes) + len(dicom_outcomes),
            )
            state = BatchState.PSEUDONYMIZED
        else:
            # 已经代号化过的批次（材料补齐后重投）：状态保持代号化，重新入队投递。
            state = state or BatchState.PSEUDONYMIZED

        # ---- 6. 残留闸门 + 投递载荷 ----
        residual_summary = batch.residual.summary if batch.residual else ""
        if not batch.deliverable:
            self._failures[batch_no] = self._failures.get(batch_no, 0) + 1
            # 置告警态：把「卡在残留自检上、卡了几处」写进批次台账。
            # 状态**不推进**（残留是可修复的，改材料重投即可），但批次行上
            # 必须看得见原因 —— 否则这一批只是停在原地等人猜。
            self._ledger.mark_residual_alert(batch_no, residual_summary)
            return BatchRunResult(
                batch_no=batch_no,
                state=state.value,
                processed=True,
                note=residual_summary + duplicate_note,
                entries=entries,
                materials=len(materials) + len(dicom_materials),
                residual=residual_summary,
                deliverable=False,
                artifacts=artifacts,
                duplicates=duplicates,
            )

        self._failures.pop(batch_no, None)
        self._ledger.complete_step(batch_no, STEP_RESIDUAL)
        payload = {
            "application_no": batch_no,
            "ethics_approval_no": intake.ethics_approval_no or "",
            "patient_ids": list(intake.patient_ids),
            "material_count": len(materials) + len(dicom_materials),
            "material_ids": list(batch.redacted_texts)
            + [outcome.material_id for outcome in dicom_outcomes],
            "manifest_path": artifacts.get("manifest", ""),
            "artifacts": dict(artifacts),
            # 批次身份：幂等键与材料集合指纹（台账与请求头用的是同一把键）。
            "idempotency_key": idempotency_key,
            "material_fingerprint": fingerprint,
            # 交付体的材料清单：材料 ID + 类别 + 脱敏副本的 sha256 + 本机暂存路径
            # + 源文件 sha256。只有摘要与路径，没有正文 —— 交接给平台的是
            # 「哪份材料、在哪、内容对不对得上」，不是材料本身。
            "materials": material_entries,
        }
        self._ledger.complete_step(batch_no, STEP_PAYLOAD)
        return BatchRunResult(
            batch_no=batch_no,
            state=state.value,
            processed=True,
            note="脱敏与残留自检通过，可投递" + duplicate_note,
            entries=entries,
            materials=len(materials) + len(dicom_materials),
            residual=residual_summary,
            deliverable=True,
            payload=payload,
            artifacts=artifacts,
            duplicates=duplicates,
        )

    # ------------------------------------------------------------------ 内部

    def _try_resume(
        self,
        application: InboxApplication,
        intake: IntakeResult,
        record,
        state: BatchState | None,
    ) -> BatchRunResult | None:
        """能不能从上一轮的脱敏产物接上。

        接得上 → 返回续跑结果（**不重跑识别**）；接不上 → 返回 None，调用方
        按「没跑过识别」处理（重跑）。判定口径见
        :mod:`research_redact.daemon.resume`。
        """
        if record is None or state is not BatchState.PSEUDONYMIZED:
            return None
        source_digests = self._source_digests(application, intake)
        plan = plan_resume(record, source_digests=source_digests)
        if plan is None:
            return None
        return self._resume_batch(intake, record, plan)

    def _resume_batch(
        self,
        intake: IntakeResult,
        record,
        plan: ResumePlan,
    ) -> BatchRunResult:
        """续跑：复用上一轮的脱敏产物，重建投递载荷。

        **不重跑识别** —— 产物是上一轮跑出来的，一致代号与命中清单都原样
        保留（重跑会让代号变样，平台侧核不出来）。

        残留自检：上一轮已有结论就沿用；没有结论（崩在残留自检与记录之间）
        就**对着将要交付的产物重扫一遍** —— 交出去的是磁盘上这份副本，不是
        上一轮内存里那份。
        """
        from ..audit.manifest import ManifestWriter

        batch_no = record.batch_no
        artifacts = dict(plan.artifacts)
        entries = [dict(item) for item in plan.material_entries]
        manifest_path = artifacts.get("manifest", "")
        try:
            hit_count = len(ManifestWriter.read(manifest_path))
        except OSError:
            hit_count = 0

        if plan.residual_known:
            residual_summary = "（续跑）残留自检结论沿用上一轮：身份类残留 0 处"
            deliverable = True
        else:
            report = self._checker.check_batch(
                batch_no, self._read_redacted_artifacts(artifacts)
            )
            residual_summary = report.summary
            deliverable = report.deliverable
            if not deliverable:
                self._failures[batch_no] = self._failures.get(batch_no, 0) + 1
                self._ledger.mark_residual_alert(batch_no, residual_summary)
                return BatchRunResult(
                    batch_no=batch_no,
                    state=BatchState.PSEUDONYMIZED.value,
                    processed=True,
                    note=residual_summary,
                    entries=hit_count,
                    materials=len(entries),
                    residual=residual_summary,
                    deliverable=False,
                    artifacts=artifacts,
                    resumed=True,
                )

        payload = {
            "application_no": batch_no,
            "ethics_approval_no": intake.ethics_approval_no or "",
            "patient_ids": list(intake.patient_ids),
            "material_count": len(entries),
            "material_ids": [str(item.get("material_id") or "") for item in entries],
            "manifest_path": manifest_path,
            "artifacts": dict(artifacts),
            # 批次身份沿用上一轮登记的值（同一批材料 = 同一把幂等键）。
            "idempotency_key": plan.idempotency_key,
            "material_fingerprint": plan.fingerprint,
            "materials": entries,
            "resumed": True,
        }
        self._ledger.set_material_fingerprint(batch_no, plan.fingerprint)
        self._ledger.set_material_entries(batch_no, entries)
        self._ledger.set_idempotency_key(batch_no, plan.idempotency_key)
        self._ledger.complete_step(batch_no, STEP_PAYLOAD)
        self._backfill_policy_snapshot(batch_no, record)
        # 复用旧产物这件事要留痕：事后说得清「这一批的脱敏是哪一次跑的」。
        self._ledger.record_access(
            batch_no,
            actor="daemon",
            operation="batch_resumed",
            detail=plan.reason,
        )
        return BatchRunResult(
            batch_no=batch_no,
            state=BatchState.PSEUDONYMIZED.value,
            processed=True,
            note=plan.reason,
            entries=hit_count,
            materials=len(entries),
            residual=residual_summary,
            deliverable=True,
            payload=payload,
            artifacts=artifacts,
            resumed=True,
        )

    @staticmethod
    def _read_redacted_artifacts(artifacts: Mapping[str, str]) -> dict[str, str]:
        """读回磁盘上的脱敏副本（材料 ID → 正文）。

        读法只有一份（运维 CLI 的 ``verify-residual`` 走同一个函数），两边
        看到的残留结论才对得上。
        """
        from .ops import read_redacted_artifacts

        return read_redacted_artifacts(artifacts)

    def _read_materials(
        self, application: InboxApplication, plan: MaterialPlan
    ) -> tuple[dict[str, str], dict[str, bytes], list[str], list[str]]:
        """读材料正文。

        文本材料按 UTF-8 读；DICOM 材料按字节读（**不当作文本读** —— 二进制
        当文本读会读坏，等于把片子处理成乱码）。

        **材料 ID 重复的已经去重**（首次出现优先，见
        :func:`~research_redact.ingest.application.dedupe_material_rows`）——
        同一份材料不会被读两遍、更不会被替换两遍。

        :return: ``(材料 ID → 正文, 材料 ID → DICOM 字节, 缺失清单, 暂不处理的
            材料清单)``。
        """
        materials: dict[str, str] = {}
        dicom_materials: dict[str, bytes] = {}
        missing: list[str] = []
        deferred: list[str] = []
        for row in plan.rows:
            if row.kind == _DICOM_KIND:
                target = self._material_path(application, row.path)
                if target is None:
                    missing.append(f"{row.material_id}（{row.path}）")
                    continue
                try:
                    dicom_materials[row.material_id] = target.read_bytes()
                except OSError as exc:
                    missing.append(f"{row.material_id}（读不出来：{exc}）")
                continue
            if row.kind not in _TEXT_KINDS:
                deferred.append(f"{row.material_id}（{row.kind}）")
                continue
            target = self._material_path(application, row.path)
            if target is None:
                missing.append(f"{row.material_id}（{row.path}）")
                continue
            try:
                materials[row.material_id] = target.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                missing.append(f"{row.material_id}（读不出来：{exc}）")
        return materials, dicom_materials, missing, deferred

    @staticmethod
    def _material_path(application: InboxApplication, path: str) -> Path | None:
        """材料路径（相对交付目录的路径补成绝对路径）；不存在返回 None。"""
        target = Path(path)
        if not target.is_absolute():
            target = application.directory / target
        return target if target.is_file() else None

    def _redact_dicom_materials(
        self, batch_no: str, dicom_materials: Mapping[str, bytes]
    ) -> tuple[tuple[DicomRedaction, ...], str]:
        """对 DICOM 材料做 tag 级去标识。

        :return: ``(去标识结果, 失败原因)``。失败原因为空串表示全部成功。
            失败时**不产出产物**、不推进批次状态 —— 一份没脱干净的片子留在
            产物目录里，比没有产物更危险。
        """
        outcomes: list[DicomRedaction] = []
        for material_id, data in dicom_materials.items():
            try:
                outcomes.append(
                    redact_dicom_bytes(data, material_id, config=self.dicom_config)
                )
            except DicomError as exc:
                return (), (
                    f"DICOM 材料 {material_id} 去标识失败：{exc}"
                    " —— 该批次不得交付，请人工核对这份材料（未产出脱敏副本）"
                )
        return tuple(outcomes), ""

    def _write_artifacts(
        self,
        batch_no: str,
        batch,
        dicom_outcomes: Sequence[DicomRedaction] = (),
        *,
        scope: str = "",
        snapshot: PolicySnapshot | None = None,
    ) -> dict[str, str]:
        """脱敏副本与命中清单落盘，返回产物路径表。

        文本材料落 ``<材料 ID>.txt``，DICOM 落 ``<材料 ID>.dcm``；**两类材料
        共用同一份批次命中清单** —— 清单是整批交差用的，不该按材料类型分家。

        **命中清单按批次身份追加去重**：条目先落台账（唯一约束在数据库上），
        再由台账里**去重后**的条目写出清单文件。同一批材料被重放处理
        （两个执行者同时触发、进程重启后补投、兜底扫描再扫一遍）时，清单
        不会多出一行 —— 交差时数得清。

        **清单头**（task 36）：批次级清单的第一行写清单头，记下这一批用的
        策略版本号 —— 交差的人一眼能对上是哪一版策略脱的。清单头不是命中
        条目，读清单的人按标记键跳过它，**「清单条数」的读法不变**。

        :param scope: 批次身份范围（材料集合指纹）；材料集合变了就是新的一批，
            新的一批有自己的清单，不被旧范围的记录挡住。
        :param snapshot: 本批的策略快照（写清单头用）。
        """
        from ..audit.manifest import ManifestWriter, build_manifest_header, entry_from_dict

        directory = self.output_dir / _safe_name(batch_no)
        materials_dir = directory / "materials"
        materials_dir.mkdir(parents=True, exist_ok=True)
        artifacts: dict[str, str] = {}
        for outcome in batch.outcomes:
            target = materials_dir / f"{_safe_name(outcome.material_id)}.txt"
            target.write_text(outcome.redacted_text, encoding="utf-8")
            artifacts[outcome.material_id] = str(target)
        for outcome in dicom_outcomes:
            target = materials_dir / f"{_safe_name(outcome.material_id)}.dcm"
            target.write_bytes(outcome.data)
            artifacts[outcome.material_id] = str(target)
        entries = [entry for outcome in batch.outcomes for entry in outcome.entries]
        entries += [entry for outcome in dicom_outcomes for entry in outcome.entries]
        # 先落台账（去重在唯一约束上），再由台账写出清单 —— 文件里的行数与
        # 台账里的行数永远一致，交差时两边对得上。
        self._ledger.record_manifest_entries(
            batch_no, scope, [entry.to_dict() for entry in entries]
        )
        recorded = self._ledger.manifest_entries(batch_no, scope)
        manifest_path = directory / "manifest.jsonl"
        header = None
        if snapshot is not None:
            header = build_manifest_header(
                batch_no=batch_no,
                policy_version=snapshot.policy_version,
                policy_sha256=snapshot.policy_sha256,
                profile=snapshot.profile,
                entry_count=len(recorded),
                captured_at=snapshot.captured_at,
            )
        ManifestWriter(manifest_path).write(
            [entry_from_dict(row) for row in recorded], header=header
        )
        artifacts["manifest"] = str(manifest_path)
        return artifacts

    def _material_manifest(
        self,
        intake: IntakeResult,
        artifacts: Mapping[str, str],
        source_digests: Mapping[str, str] | None = None,
    ) -> list[dict[str, str]]:
        """交付体的材料清单：材料 ID + 类别 + sha256 + 本机暂存路径。

        只有摘要与位置，**没有正文** —— 交给平台的是「哪份材料、在哪、内容对
        不对得上」。摘要算不出来时留空串（不编造），由平台侧校验时暴露。

        ``source_sha256`` 是**源文件**摘要 —— 幂等键按它算批次身份：材料换了
        内容就是新的一批，不会被当成重复批次丢掉。
        """
        from ..outbound.research_platform_client import file_sha256

        digests = source_digests or {}
        entries: list[dict[str, str]] = []
        for row in dedupe_material_rows(intake.rows).rows:
            path = artifacts.get(row.material_id)
            if not path:
                continue
            try:
                digest = file_sha256(path)
            except OSError:
                digest = ""
            entries.append(
                {
                    "material_id": row.material_id,
                    "kind": row.kind,
                    "sha256": digest,
                    "source_sha256": digests.get(row.material_id, ""),
                    "path": path,
                }
            )
        return entries

    def _source_digests(
        self, application: InboxApplication, intake: IntakeResult
    ) -> dict[str, str]:
        """材料 ID → 源文件 sha256（读不出来的材料不计入）。

        材料读不出来时前一步已经按「材料缺失」把批次挡住了 —— 这里的
        「读不出来」只是兜底，不会让指纹少算一份材料还照样放行。
        """
        from ..outbound.research_platform_client import file_sha256

        digests: dict[str, str] = {}
        for row in dedupe_material_rows(intake.rows).rows:
            target = self._material_path(application, row.path)
            if target is None:
                continue
            try:
                digests[row.material_id] = file_sha256(target)
            except OSError:
                continue
        return digests

    def _material_set_changed(
        self, application: InboxApplication, record
    ) -> bool:
        """材料集合是不是变了（源文件摘要口径）。

        读不出申请单 / 没有可比的指纹时按「没变」处理 —— 拿不准的时候
        宁可复用已有产物，也不要平白多交一次。
        """
        if record is None or not record.material_fingerprint:
            return False
        try:
            intake = load_application(application.application_file)
        except (ApplicationError, FileNotFoundError, OSError):
            return False
        digests = self._source_digests(application, intake)
        if not digests:
            return False
        current = material_set_fingerprint(
            [
                {"material_id": material_id, "source_sha256": digest}
                for material_id, digest in digests.items()
            ]
        )
        return current != record.material_fingerprint

    def _lock_path(self, batch_no: str) -> Path:
        """批次锁文件路径（一个批次一把锁）。"""
        return self._lock_dir / f"{_safe_name(batch_no)}.lock"

    def _concurrent_result(
        self, batch_no: str, outcome: LockOutcome
    ) -> BatchRunResult:
        """没抢到批次锁时的结果：**复用已有产物，不重复脱敏、不重复外发**。

        两种情形都归到这里：

        1. 另一个执行者正在处理这一批 → 本轮跳过，等它跑完（兜底扫描或
           下一轮事件会接手）；
        2. 另一个执行者已经处理完这一批（产物在磁盘上、台账里有记录）→
           直接复用已有产物与回执。

        :param batch_no: 批次号。
        :param outcome: 抢锁结果。
        """
        record = self._ledger.get_batch(batch_no)
        state = record.batch_state.value if record is not None else ""
        artifacts = dict(record.artifacts or {}) if record is not None else {}
        holder = outcome.holder or {}
        holder_text = ""
        if holder.get("pid"):
            holder_text = f"（持有者进程 {holder.get('pid')}）"
        if artifacts.get("manifest"):
            return BatchRunResult(
                batch_no=batch_no,
                state=state,
                skipped=True,
                note=(
                    "另一执行者已处理本批次，本轮复用已有产物与回执"
                    f"（未重复脱敏、未重复外发）{holder_text}"
                ),
                artifacts=artifacts,
                concurrent=True,
            )
        return BatchRunResult(
            batch_no=batch_no,
            state=state,
            skipped=True,
            note=(
                "另一执行者正在处理本批次，本轮不重复处理"
                f"（{outcome.reason or '批次锁未抢到'}）{holder_text}"
            ),
            concurrent=True,
        )

    def _backfill_policy_snapshot(self, batch_no: str, record) -> None:
        """老批次补记策略快照（task 36）。

        补齐本功能之前跑的批次没有策略版本号。续跑时补记一份当前生效配置的
        快照，**并在访问留痕里说明这是补记的** —— 事后看得出它不等于原始
        那一版，不能拿它冒充「当时就是按这版脱的」。

        补记失败（写不出 / 含凭据）不阻断续跑：产物已经在盘上，续跑是把它
        交出去；缺一份快照是**可复现性**的缺口，不是交付的前置条件 ——
        但它会落一条告警，不静默。
        """
        if record.policy_version:
            return
        try:
            snapshot = capture_snapshot(
                batch_no, self.policy_table, self.snapshot_dir
            )
        except SnapshotError as exc:
            self._ledger.record(
                BatchAlert(
                    batch_no=batch_no,
                    code="policy_snapshot_missing",
                    level="warning",
                    count=1,
                    message=(
                        f"批次 {batch_no} 续跑时补记策略快照失败：{exc}"
                        "（该批次没有原始策略版本，事后重放需人工核对）"
                    ),
                )
            )
            return
        self._ledger.record_policy_snapshot(
            batch_no,
            policy_version=snapshot.policy_version,
            policy_sha256=snapshot.policy_sha256,
            profile=snapshot.profile,
            source=snapshot.source,
            source_sha256=snapshot.source_sha256,
            snapshot_dir=str(snapshot.directory),
            policy_path=str(snapshot.policy_path),
        )
        self._ledger.set_policy_version(batch_no, snapshot.policy_version)
        self._ledger.record_access(
            batch_no,
            actor="daemon",
            operation="policy_snapshot_backfilled",
            detail=(
                f"补记策略快照 {snapshot.policy_version}"
                "（原批次未留策略版本，这不是原始那一版）"
            ),
        )

    def _record_duplicate_materials(self, batch_no: str, plan: MaterialPlan) -> None:
        """材料 ID 重复时落一条告警（**不静默去重**）。

        静默去重等于替人决定「哪一行才是对的」—— 而这份申请单到底哪一行
        对，只有申请单的主人知道。所以：按首次出现去重（不重复替换），
        同时把重复的材料 ID 点名落进告警台账。

        告警文案只含材料 ID 与定位，**不含患者原文**。
        """
        self._ledger.record(
            BatchAlert(
                batch_no=batch_no,
                code="duplicate_material_id",
                level="warning",
                count=len(plan.duplicates),
                message=(
                    f"批次 {batch_no} 的申请单里材料 ID 重复："
                    + "、".join(plan.duplicates)
                    + "。已按首次出现去重（同一份材料只脱一次，不重复替换）；"
                    "请核对申请单材料清单，重复的 ID 应改为各自唯一的材料 ID"
                ),
                material_ids=tuple(plan.duplicates),
                notified=False,
                notify_channel="pending",
            )
        )

    def _fail(self, batch_no: str, reason: str) -> None:
        """记一次失败：计数 + 落一条持久告警（不静默）。"""
        count = self._failures.get(batch_no, 0) + 1
        self._failures[batch_no] = count
        self._ledger.record(
            BatchAlert(
                batch_no=batch_no,
                code="batch_processing_failed",
                level="error",
                count=count,
                message=(
                    f"批次 {batch_no} 处理失败（第 {count} 次）：{reason}"
                    "（未降级放行，请人工核对投递目录与申请单）"
                ),
            )
        )


def _safe_name(value: str) -> str:
    """把批次号 / 材料 ID 变成安全的文件名（去掉路径分隔符与控制字符）。"""
    cleaned = "".join(
        char if (char.isalnum() or char in "-_.") else "_" for char in value.strip()
    )
    return cleaned or "unnamed"


def _build_notifier() -> AlertNotifier:
    """按环境变量装配告警推送出口。

    企业微信 webhook 没配时返回「未配置」占位（明确记 ``notified=False``）——
    既不假装推过，也不指向本地替身。
    """
    from ..outbound.notifier import build_notifier

    return build_notifier()
