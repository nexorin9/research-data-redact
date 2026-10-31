"""运维操作层：守护进程与运维 CLI 共用的运行时装配与单批处理。

守护进程（``python -m research_redact.daemon``）与运维 CLI
（``python -m research_redact.cli``）是两条**触发**通道，不是两条处理通道：

- 「装一套运行时（台账 / 处理器 / 投递队列 / 出站客户端）」只有一份实现
  （:func:`build_runtime`）；
- 「处理一份申请单并把它送进投递队列」只有一份实现
  （:func:`process_application`）。

两条通道都调这两个函数，所以 CLI 不写第二套脱敏逻辑，守护进程也不写 ——
两者共用 :mod:`research_redact.daemon.pipeline` 的脱敏主路径、
:mod:`research_redact.daemon.runner` 的批次处理与
:mod:`research_redact.audit.ledger` 的批次台账。

**共享的另一个理由**：一致代号、幂等键、命中清单去重、批次锁都住在台账与
主路径里。CLI 另起一套就会出现「守护进程脱出来的是一套、CLI 脱出来的是另一套」
—— 交差时两份代号对不上，谁也说不清哪份是对的。

**投递队列是进程内的**：守护进程重启后队列会空，靠
:func:`pending_deliveries` 从台账里把「已代号化、还没交付」的批次捞回来补投。
CLI 的 ``deliver`` 子命令走的是同一套判定，两边捞出来的是同一批。
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..audit.alerts import BatchAlert, JsonlAlertSink
from ..audit.ledger import BatchLedger
from ..audit.residual import ResidualChecker
from ..outbound.notifier import build_notifier
from .queue import DeliveryOutcome, DeliveryQueue
from .runner import BatchRunner, BatchRunResult
from .settings import DaemonSettings
from .state_machine import BatchState
from .watcher import InboxApplication

__all__ = [
    "BatchOutcome",
    "Runtime",
    "build_checker",
    "build_runtime",
    "export_timeline",
    "format_timeline",
    "pending_deliveries",
    "process_application",
    "read_redacted_artifacts",
    "rebuild_payload",
    "settings_from_args",
]


# --------------------------------------------------------------------- 运行时


@dataclass
class Runtime:
    """一套跑起来的运行时（台账 + 处理器 + 投递队列 + 出站客户端）。

    :param settings: 运行配置。
    :param ledger: 批次台账。
    :param runner: 批次处理器（内部走 :mod:`research_redact.daemon.pipeline`）。
    :param queue: 待投递队列。
    :param platform: 科研数据平台客户端（投递出口）。
    :param notifier: 告警推送出口。
    :param index: 一致代号的对照索引（加密落盘的持久索引，或进程内索引）。
    """

    settings: DaemonSettings
    ledger: BatchLedger
    runner: BatchRunner
    queue: DeliveryQueue
    platform: Any
    notifier: Any
    index: Any = None

    def close(self) -> None:
        """关台账连接。"""
        self.ledger.close()


def build_runtime(
    settings: DaemonSettings,
    *,
    deliver: Any | None = None,
    ledger: BatchLedger | None = None,
    notifier: Any | None = None,
) -> Runtime:
    """按配置装配一套运行时。

    :param settings: 运行配置。
    :param deliver: 投递函数覆盖（测试用）；缺省接科研数据平台客户端。
    :param ledger: 台账覆盖；缺省按 ``settings.ledger_path`` 新建。
    :param notifier: 推送出口覆盖；缺省按环境变量装配（未配置时明确记「没推出去」）。
    """
    ledger = ledger if ledger is not None else BatchLedger(settings.ledger_path)
    notifier = notifier if notifier is not None else build_notifier()
    platform = _build_platform_client(ledger)
    index = _build_mapping_index(ledger)
    queue = DeliveryQueue(
        deliver=deliver if deliver is not None else platform.deliver,
        ledger=ledger,
        notifier=notifier,
        max_retries=settings.delivery_max_retries,
        backoff_base=settings.delivery_backoff_base,
    )
    runner = BatchRunner(
        output_dir=settings.output_dir,
        ledger=ledger,
        checker=_build_checker(settings, ledger=ledger, notifier=notifier),
        mapping_index=index,
    )
    return Runtime(
        settings=settings,
        ledger=ledger,
        runner=runner,
        queue=queue,
        platform=platform,
        notifier=notifier,
        index=index,
    )


def _build_mapping_index(ledger: Any) -> Any:
    """装配一致代号的对照索引。

    **优先用加密落盘的索引**（``$RESEARCH_INDEX_FILE``）：它是跨进程、跨重启
    唯一查得回来的那一份 —— 运维 CLI 的 ``restore-request`` 事后要靠它把
    指定几例换回原文。进程内索引只在本进程有效，守护进程一重启就丢，
    「交出去还能换回来」就成了空话。

    索引密钥（``$INDEX_ENCRYPTION_KEY`` 或 ``$PSEUDONYM_HMAC_KEY``）没配时
    退回进程内索引：**不做持久化承诺**，此时还原只能在同一进程内做。

    索引文件读不出来（被改动 / 密钥不匹配）时**报错**，不拿空索引覆盖 ——
    覆盖掉就等于把整批对照关系永久删掉了。
    """
    from ..policy.index_store import (
        IndexFileMissingError,
        IndexKeyError,
        load_index_store,
    )
    from ..policy.mapping import PseudonymMappingIndex

    try:
        store = load_index_store(ledger=ledger, batch_no="", actor="daemon")
    except IndexKeyError:
        # 密钥凭据位没配 → 进程内索引（不落盘、不承诺跨进程还原）
        return PseudonymMappingIndex()
    try:
        store.load()
    except IndexFileMissingError:
        # 第一批：索引文件还没有，从空开始（不报错 —— 这是正常起点）
        return store
    return store


def _build_platform_client(ledger: Any) -> Any:
    """装配科研数据平台客户端（默认投递出口）。

    端点或令牌没配时，客户端的 ``deliver`` 会直接抛「通道挂起」错，批次被
    挂起等重投 —— **不静默改指本地替身，也不假装交付成功**。
    """
    from ..outbound.research_platform_client import ResearchPlatformClient

    return ResearchPlatformClient(ledger=ledger)


def _build_checker(settings: DaemonSettings, ledger: Any = None, notifier: Any = None):
    """按配置装配残留自检器。

    - **告警**落配置的 JSONL 台账（``$RESEARCH_ALERT_LEDGER``）；
    - **阻断级残留**推一次企业微信（按批次聚合，不逐处推）；
    - **批次摘要**落 SQLite 批次台账（通过与否都落 —— 事后要回答「这批当时
      到底脱干净了没有」，答案在这里）。
    """
    return ResidualChecker(
        sink=JsonlAlertSink(settings.alert_ledger_path),
        notifier=notifier,
        summary_sink=ledger,
    )


# --------------------------------------------------------------------- 单批处理


@dataclass(frozen=True)
class BatchOutcome:
    """一次「处理 + 投递」的结果。

    :param result: 批次处理结果（脱敏主路径的产物）。
    :param delivery: 投递结果；没走到投递这一步时为 None。
    """

    result: BatchRunResult
    delivery: DeliveryOutcome | None = None

    @property
    def delivered(self) -> bool:
        """是否已交付（平台已回执）。"""
        return bool(self.delivery and self.delivery.delivered)

    @property
    def parked(self) -> bool:
        """是否挂起等重投（退避超次或不可重试）。"""
        return bool(self.delivery and self.delivery.exhausted)


def process_application(
    runtime: Runtime,
    application: InboxApplication,
    *,
    via_event: bool = True,
    deliver: bool = True,
) -> BatchOutcome:
    """处理一份申请单；可交付时把它送进投递队列。

    守护进程的每轮循环与运维 CLI 的 ``run`` 子命令都调这里 —— **同一份实现**。

    :param runtime: 运行时。
    :param application: 交付目录里的一份申请单。
    :param via_event: 是否按「目录内容有变化」触发（事件触发允许重投）。
    :param deliver: 是否把可交付的批次送进投递队列。
    """
    result = runtime.runner.process(application, via_event=via_event)
    _persist_index(runtime, result.batch_no)
    if result.skipped or not result.processed or not result.deliverable:
        return BatchOutcome(result=result)
    if not deliver:
        return BatchOutcome(result=result)
    outcome = runtime.queue.submit(result.batch_no, result.payload)
    return BatchOutcome(result=result, delivery=outcome)


def _persist_index(runtime: Runtime, batch_no: str = "") -> None:
    """把这一批的对照关系落盘（**投递之前**落）。

    落盘的时机很要紧：**先落对照，再交出去**。反过来的话，平台上手里已经有
    一批材料、这边却查不到对应的对照关系 —— 那就成了一批「交出去就再也
    换不回来」的材料。

    只在真的一致代号索引上有内容时才写盘 —— 默认档（占位符替换）根本不产生
    对照关系，没必要凭空造一个空索引文件。
    """
    store = runtime.index
    if store is None:
        return
    save = getattr(store, "save", None)
    if save is None or len(store) == 0:
        return
    bind = getattr(store, "bind_batch", None)
    if bind is not None:
        bind(batch_no)
    try:
        save()
    except OSError as error:
        # 索引落不下去 = 这一批交出去就换不回来 → 落告警，不静默。
        runtime.ledger.record(
            BatchAlert(
                batch_no=batch_no or "*",
                code="pseudonym_index_not_persisted",
                level="error",
                count=1,
                message=(
                    f"一致代号对照索引落盘失败：{error}"
                    "（该批交付后无法受控还原，请人工核对后再投）"
                ),
            )
        )


# --------------------------------------------------------------------- 补投载荷


def pending_deliveries(ledger: BatchLedger) -> list[tuple[str, dict[str, object]]]:
    """台账里「已代号化、尚未交付」的批次 → 补投载荷。

    载荷按台账里已登记的产物路径与材料清单重建：脱敏副本与命中清单都还在，
    不需要重跑脱敏，也不碰患者原文。

    **幂等键随载荷一起重建**（台账里记着的那把）—— 重启后的补投与当初那次
    是同一批材料，必须用同一把键，否则平台会当成新的一批再收一次。

    **只补投「真的可以投」的批次**（三条都要成立）：

    1. 投递记录完整（产物路径 + 材料清单 + 幂等键都在）—— 记录缺一半的批次
       交出去的是一份缺材料的交付体，宁可交给主路径重跑识别补齐；
    2. 残留自检已通过（台账里有 ``residual_check`` 步骤）—— 残留没过就补投，
       等于把没脱干净的材料送到平台上；
    3. 产物路径已登记（脱敏副本与命中清单还在磁盘上）。

    不满足的批次**不静默丢掉**：它们由兜底扫描接手（主路径会重跑或续跑），
    台账里也看得见状态与失败原因。
    """
    from .resume import STEP_RESIDUAL

    pending: list[tuple[str, dict[str, object]]] = []
    for record in ledger.list_batches(BatchState.PSEUDONYMIZED):
        artifacts = dict(record.artifacts)
        materials = [dict(item) for item in record.material_entries]
        if not artifacts.get("manifest") or not materials or not record.idempotency_key:
            # 崩在「产物已落盘、投递载荷还没登记」那一步：这份记录交不出
            # 一份完整交付体 —— 不补投，交给主路径重跑识别补齐。
            continue
        if STEP_RESIDUAL not in tuple(record.completed_steps):
            # 残留自检没过（或崩在自检与记录之间）：不补投。
            continue
        pending.append(
            (
                record.batch_no,
                {
                    "application_no": record.batch_no,
                    "ethics_approval_no": record.ethics_approval_no or "",
                    "patient_ids": list(record.patient_ids),
                    "material_count": len(materials) or len(record.material_ids),
                    "material_ids": list(record.material_ids),
                    "manifest_path": artifacts.get("manifest", ""),
                    "artifacts": artifacts,
                    "materials": materials,
                    "idempotency_key": record.idempotency_key,
                    "material_fingerprint": record.material_fingerprint,
                    "resumed": True,
                },
            )
        )
    return pending


def rebuild_payload(ledger: BatchLedger, batch_no: str) -> dict[str, object]:
    """按台账登记重建某一批的投递载荷。

    载荷与 :func:`pending_deliveries` 同口径 —— **幂等键取台账里记着的那把**，
    补投与当初那次是同一批材料。

    :raises KeyError: 批次不在台账里，或记录不完整（交不出完整交付体）。
    """
    record = ledger.get_batch(batch_no)
    if record is None:
        raise KeyError(f"批次不在台账里：{batch_no}")
    artifacts = dict(record.artifacts)
    materials = [dict(item) for item in record.material_entries]
    if not artifacts.get("manifest") or not materials or not record.idempotency_key:
        raise KeyError(
            f"批次 {batch_no} 的投递记录不完整"
            "（缺产物路径 / 材料清单 / 幂等键）：交不出完整交付体，请重跑识别补齐"
        )
    return {
        "application_no": record.batch_no,
        "ethics_approval_no": record.ethics_approval_no or "",
        "patient_ids": list(record.patient_ids),
        "material_count": len(materials) or len(record.material_ids),
        "material_ids": list(record.material_ids),
        "manifest_path": artifacts.get("manifest", ""),
        "artifacts": artifacts,
        "materials": materials,
        "idempotency_key": record.idempotency_key,
        "material_fingerprint": record.material_fingerprint,
        "resumed": True,
    }


# --------------------------------------------------------------------- 产物读取


def read_redacted_artifacts(artifacts: Mapping[str, str]) -> dict[str, str]:
    """读回磁盘上的脱敏副本（材料 ID → 正文）。

    只读文本材料：DICOM 是二进制，按文本读会读坏（它另有自己的 tag 级
    自检，见 :mod:`research_redact.materials.dicom_redact`）。

    守护进程的残留自检与运维 CLI 的 ``verify-residual`` 子命令读的是同一批
    产物 —— 读法只有一份，两边看到的残留结论才对得上。
    """
    texts: dict[str, str] = {}
    for material_id, path in artifacts.items():
        if material_id == "manifest" or not path:
            continue
        target = Path(path)
        if target.suffix.lower() != ".txt":
            continue
        try:
            texts[material_id] = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return texts


# --------------------------------------------------------------------- 配置


def settings_from_args(
    args: Any,
    base: DaemonSettings | None = None,
) -> DaemonSettings:
    """命令行覆盖环境变量（守护进程与运维 CLI 共用同一份覆盖口径）。

    :param args: 解析后的命令行参数（需含 ``delivery_dir`` / ``output_dir`` /
        ``ledger`` 属性，没有就当作没给）。
    :param base: 基础配置；缺省按环境变量装配。
    """
    settings = base if base is not None else DaemonSettings.from_env()
    overrides: dict[str, Any] = {}
    if getattr(args, "delivery_dir", None):
        overrides["delivery_dir"] = Path(args.delivery_dir).expanduser()
    if getattr(args, "output_dir", None):
        overrides["output_dir"] = Path(args.output_dir).expanduser()
    if getattr(args, "ledger", None):
        overrides["ledger_path"] = Path(args.ledger).expanduser()
    if getattr(args, "poll_interval", None) is not None:
        overrides["poll_interval"] = args.poll_interval
    if getattr(args, "heartbeat_interval", None) is not None:
        overrides["heartbeat_interval"] = args.heartbeat_interval
    return dataclasses.replace(settings, **overrides)


# --------------------------------------------------------------------- 时间线


def format_timeline(records: Sequence[Any]) -> str:
    """把状态迁移流水排成一行一条的可读文本。

    运维 CLI 的 ``status`` 子命令与守护进程的结构化日志共用这一份排版 ——
    同一批事实在两处看到的写法一致，交差时不至于对不上。

    :param records: :class:`~research_redact.audit.ledger.TransitionRecord` 序列。
    """
    lines: list[str] = []
    for item in records:
        stamp = item.created_at.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"  {stamp}  {item.source_state:<18}→ {item.target_state:<18}"
            f"{item.event:<30}{item.reason}"
        )
    return "\n".join(lines)


def export_timeline(
    ledger: BatchLedger,
    batch_no: str,
    path: str | Path,
) -> Path:
    """把批次时间线导出一个 JSON 文件（可按批次导出）。

    时间线本身已经落在台账的 ``batch_transitions`` 表里；这一步是把它**导出来**
    —— 伦理办与信息科要交差时，要的是一份能归档、能对拍的清单，而不是一句
    「那批已经交出去了」。

    导出内容只有状态、事件、时间与原因 —— **不含任何患者原文**（时间线里本来
    就没有）。

    :param ledger: 批次台账。
    :param batch_no: 批次号（申请单号）。
    :param path: 导出文件路径（JSON）。
    :return: 实际写出的文件路径。
    """
    records = ledger.timeline(batch_no)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "batch_no": batch_no,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "steps": len(records),
        "timeline": [
            {
                "source_state": item.source_state,
                "event": item.event,
                "target_state": item.target_state,
                "reason": item.reason,
                "created_at": item.created_at.isoformat(),
            }
            for item in records
        ],
    }
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return target
