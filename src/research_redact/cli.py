"""运维 CLI：守护进程的手动通道。

CLI 是**运维与批处理通道**，不是第二套处理逻辑 —— 它与守护进程共用
:mod:`research_redact.daemon.ops` 的运行时装配、:mod:`research_redact.daemon.pipeline`
的脱敏主路径和 :mod:`research_redact.audit.ledger` 的批次台账。

子命令面（task 39）：

=================  ======================================================
子命令            干什么
=================  ======================================================
``scan``          扫科研交付目录，列出待处理批次与台账状态
``run``           处理单个批次（脱敏 → 残留自检 → 投递）
``deliver``       重投待交付队列（按台账里登记的载荷重建，不重跑脱敏）
``restore-request``  提交受控还原请求（双人授权 + 时效 + 范围）
``export-audit``  把命中清单导出成三种分组视图与摘要表
``verify-residual``  对脱敏产物再扫一遍身份类残留
``status``        打印批次时间线（从 detected 到 delivered 每一步）
=================  ======================================================

另有两条窄口子：``redact``（单份材料脱敏 + 逐处命中清单）与
``redact-dicom``（DICOM tag 级去标识）。

**退出码**（运维脚本靠它分流，不要只看终端有没有报错）：

===  ==========================================================
码   含义
===  ==========================================================
0    成功
2    参数 / 用法错误（含批次不存在、目录不存在）
3    处理失败（申请单读不出来、脱敏报错、索引不可达）
4    残留自检未通过 —— 该批不得投递
5    投递未完成（挂起等重投，或等下一次退避重试）
6    还原授权不足或被拒
===  ==========================================================

对应源产品的多格式输出思路（``presidio_cli/cli.py::Format.standard`` 的
人类可读摘要 + ``Format.parsable`` 的逐条结构化输出）：本 CLI 的每个子命令
都同时给出**人类可读摘要**（终端）与**机读产物**（JSONL 清单 / SQLite 台账）。
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Sequence

from .audit.alerts import JsonlAlertSink
from .audit.ledger import BatchLedger
from .audit.manifest import (
    collect_manifests,
    export_manifest_views,
    format_export_summary,
)
from .audit.residual import ResidualChecker
from .daemon import ops
from .daemon.pipeline import redact_file
from .daemon.settings import DaemonSettings
from .daemon.watcher import InboxWatcher
from .materials.dicom_redact import DicomError, redact_dicom_file

__all__ = [
    "EXIT_AUTHORITY",
    "EXIT_DELIVERY",
    "EXIT_FAILED",
    "EXIT_OK",
    "EXIT_RESIDUAL",
    "EXIT_USAGE",
    "build_parser",
    "main",
]

#: 成功。
EXIT_OK = 0
#: 参数 / 用法错误。
EXIT_USAGE = 2
#: 处理失败（读不出来、脱敏报错、索引不可达）。
EXIT_FAILED = 3
#: 残留自检未通过 —— 该批不得投递。
EXIT_RESIDUAL = 4
#: 投递未完成（挂起等重投，或等下一次退避重试）。
EXIT_DELIVERY = 5
#: 还原授权不足或被拒。
EXIT_AUTHORITY = 6


# --------------------------------------------------------------------- 解析器


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="research-redact",
        description="科研影像数据脱敏系统 · 运维通道",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描科研交付目录，列出待处理批次与台账状态")
    _add_common(scan)
    scan.set_defaults(func=_cmd_scan)

    run = sub.add_parser("run", help="处理单个批次：脱敏 → 残留自检 → 投递")
    run.add_argument("--batch", required=True, help="批次号（申请单号）")
    run.add_argument(
        "--no-deliver",
        dest="no_deliver",
        action="store_true",
        help="只脱敏不投递（产物落盘，交付留给 deliver 子命令）",
    )
    _add_common(run)
    run.set_defaults(func=_cmd_run)

    deliver = sub.add_parser("deliver", help="重投待交付队列（不重跑脱敏）")
    deliver.add_argument(
        "--batch",
        default=None,
        help="只重投这一个批次（缺省重投台账里全部待交付批次）",
    )
    _add_common(deliver)
    deliver.set_defaults(func=_cmd_deliver)

    restore = sub.add_parser(
        "restore-request", help="提交受控还原请求（双人授权 + 时效 + 范围）"
    )
    restore.add_argument("--batch", required=True, help="批次号（申请单号）")
    restore.add_argument(
        "--approver-a", dest="approver_a", required=True, help="授权人 A（第一签字人）"
    )
    restore.add_argument(
        "--approver-b",
        dest="approver_b",
        default=None,
        help="授权人 B（第二签字人）；缺省只受理请求，等补签",
    )
    restore.add_argument(
        "--scope",
        nargs="*",
        default=None,
        help="授权范围（材料 ID 清单）；缺省为该批已交付的全部材料",
    )
    restore.add_argument("--reason", default="", help="还原事由（写进回执）")
    restore.add_argument("--request-id", dest="request_id", default=None, help="还原请求号")
    restore.add_argument(
        "--dataset-id", dest="dataset_id", default=None, help="平台侧数据集 ID（缺省从台账取）"
    )
    restore.add_argument(
        "--out", default=None, help="还原件输出目录（缺省 <产物目录>/restored/<批次号>）"
    )
    _add_common(restore)
    restore.set_defaults(func=_cmd_restore_request)

    export = sub.add_parser(
        "export-audit",
        help="把命中清单导出成按批次 / 按材料 / 按实体类别三种分组视图与摘要表",
    )
    export.add_argument(
        "--manifest",
        dest="manifests",
        action="append",
        default=[],
        help="命中清单路径（可重复给多个）",
    )
    export.add_argument(
        "--outbox",
        dest="outbox",
        default=None,
        help="产物目录：扫 <批次号>/manifest.jsonl，每批各算一个批次",
    )
    export.add_argument(
        "--batch",
        dest="batch",
        default=None,
        help="--manifest 指定的清单归到哪个批次（缺省取清单所在父目录名）",
    )
    export.add_argument(
        "--out",
        dest="out",
        default=None,
        help="导出目录（缺省 <产物目录>/audit-export）",
    )
    export.set_defaults(func=_cmd_export_audit)

    residual = sub.add_parser(
        "verify-residual", help="对脱敏产物再扫一遍身份类残留"
    )
    residual.add_argument(
        "--batch", default=None, help="按批次扫（读台账登记的脱敏副本）"
    )
    residual.add_argument(
        "--in", dest="input", default=None, help="扫单个脱敏副本文件"
    )
    _add_common(residual)
    residual.set_defaults(func=_cmd_verify_residual)

    status = sub.add_parser("status", help="打印批次时间线（每一步迁移的时间与原因）")
    status.add_argument(
        "--batch", default=None, help="只看这一个批次（缺省列出全部批次）"
    )
    status.add_argument(
        "--export-timeline",
        dest="export_timeline",
        default=None,
        help="把该批次的时间线导成一个 JSON 文件（可归档、可对拍）",
    )
    _add_common(status)
    status.set_defaults(func=_cmd_status)

    redact = sub.add_parser(
        "redact", help="对单份材料跑一次脱敏，产出脱敏副本与逐处命中清单"
    )
    redact.add_argument("--in", dest="input", required=True, help="材料路径（UTF-8 文本）")
    redact.add_argument("--out", dest="output", required=True, help="脱敏副本输出路径")
    redact.add_argument("--manifest", dest="manifest", required=True, help="逐处命中清单路径（JSONL）")
    redact.add_argument(
        "--material-id",
        dest="material_id",
        default=None,
        help="材料 ID（默认取输入文件名，不含后缀）",
    )
    redact.add_argument(
        "--verify-residual",
        dest="verify_residual",
        action="store_true",
        help="脱敏后再扫一遍身份类残留；残留非 0 时该批不得投递并返回非 0",
    )
    redact.set_defaults(func=_cmd_redact)

    dicom = sub.add_parser(
        "redact-dicom",
        help="对一份 DICOM 材料做 tag 级去标识（身份 tag 清空、私有 tag 全清）",
    )
    dicom.add_argument("--in", dest="input", required=True, help="DICOM 材料路径")
    dicom.add_argument("--out", dest="output", required=True, help="脱敏副本输出路径")
    dicom.add_argument(
        "--manifest", dest="manifest", required=True, help="逐处命中清单路径（JSONL）"
    )
    dicom.add_argument(
        "--material-id",
        dest="material_id",
        default=None,
        help="材料 ID（默认取输入文件名，不含后缀）",
    )
    dicom.set_defaults(func=_cmd_redact_dicom)
    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    """挂上三条通用覆盖项（命令行优先于环境变量）。"""
    parser.add_argument(
        "--delivery-dir",
        dest="delivery_dir",
        default=None,
        help="科研交付目录（缺省取 $RESEARCH_DELIVERY_DIR）",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="脱敏产物与命中清单输出目录（缺省取 $RESEARCH_OUTPUT_DIR）",
    )
    parser.add_argument(
        "--ledger",
        dest="ledger",
        default=None,
        help="SQLite 批次台账路径（缺省取 $RESEARCH_LEDGER_DB）",
    )


def main(argv: list[str] | None = None) -> int:
    """CLI 入口。成功返回 0，失败返回非 0 并给出明确原因。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


# --------------------------------------------------------------------- scan


def _cmd_scan(args: argparse.Namespace) -> int:
    """``scan``：扫交付目录，列出待处理批次与台账状态。"""
    settings = ops.settings_from_args(args)
    delivery_dir = settings.delivery_dir
    if not delivery_dir.is_dir():
        print(
            f"交付目录不存在：{delivery_dir}"
            "（用 --delivery-dir 或 $RESEARCH_DELIVERY_DIR 指定）",
            file=sys.stderr,
        )
        return EXIT_USAGE

    applications = InboxWatcher(delivery_dir).applications()
    ledger = BatchLedger(settings.ledger_path)
    try:
        print(f"交付目录：{delivery_dir}")
        print(f"待处理批次：{len(applications)} 个")
        print("-" * 84)
        print(
            f"  {'批次号':<20}{'材料':<6}{'伦理批件号':<20}{'台账状态':<18}说明"
        )
        for application in applications:
            material_count, ethics, note = _peek_application(application.application_file)
            record = ledger.get_batch(application.application_no)
            state = record.state if record is not None else "（未处理）"
            print(
                f"  {application.application_no:<20}{material_count:<6}"
                f"{ethics:<20}{state:<18}{note}"
            )
        known = {application.application_no for application in applications}
        orphans = [
            record for record in ledger.list_batches() if record.batch_no not in known
        ]
        if orphans:
            print("-" * 84)
            print(f"台账里另有 {len(orphans)} 个批次不在交付目录（已处理完或已移走）：")
            for record in orphans:
                print(
                    f"  {record.batch_no:<20}状态 {record.state:<18}"
                    f"材料 {len(record.material_ids)} 份"
                )
    finally:
        ledger.close()
    return EXIT_OK


def _peek_application(path: Path) -> tuple[int, str, str]:
    """看一眼申请单：材料数、伦理批件号、说明（读不出来就说读不出来）。"""
    from .ingest.application import ApplicationError, load_application

    try:
        intake = load_application(path)
    except (ApplicationError, FileNotFoundError, OSError) as error:
        return 0, "（读不出来）", str(error)
    ethics = intake.ethics_approval_no or "（缺）"
    note = ""
    if intake.is_blocked:
        note = f"阻断：{intake.missing_summary}"
    return len(intake.rows), ethics, note


# --------------------------------------------------------------------- run


def _cmd_run(args: argparse.Namespace) -> int:
    """``run``：处理单个批次（脱敏 → 残留自检 → 投递）。"""
    settings = ops.settings_from_args(args)
    batch_no = str(args.batch or "").strip()
    if not batch_no:
        print("必须给 --batch <批次号>", file=sys.stderr)
        return EXIT_USAGE
    if not settings.delivery_dir.is_dir():
        print(
            f"交付目录不存在：{settings.delivery_dir}"
            "（用 --delivery-dir 或 $RESEARCH_DELIVERY_DIR 指定）",
            file=sys.stderr,
        )
        return EXIT_USAGE

    applications = {
        application.application_no: application
        for application in InboxWatcher(settings.delivery_dir).applications()
    }
    application = applications.get(batch_no)
    if application is None:
        existing = "、".join(sorted(applications)) or "无"
        print(
            f"交付目录里没有这个批次：{batch_no}（现有批次：{existing}）",
            file=sys.stderr,
        )
        return EXIT_USAGE

    runtime = ops.build_runtime(settings)
    try:
        outcome = ops.process_application(
            runtime,
            application,
            via_event=True,
            deliver=not args.no_deliver,
        )
    except Exception as error:  # CLI 也要说清楚是哪一步坏了
        print(f"批次处理失败：{type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        runtime.close()

    result = outcome.result
    print(f"批次：{result.batch_no}")
    print(f"状态：{result.state or '（未推进）'}")
    print(f"命中条数：{result.entries}")
    print(f"残留自检：{result.residual or '（未跑）'}")
    if result.artifacts:
        print("产物：")
        for material_id, path in result.artifacts.items():
            print(f"  {material_id}")
            print(f"    → {path}")
    if result.duplicates:
        print(f"重复材料 ID：{'、'.join(result.duplicates)}（已按首次出现去重）")
    if result.note:
        print(f"说明：{result.note}")

    if outcome.delivery is not None:
        delivery = outcome.delivery
        print(
            f"投递：{'已交付' if delivery.delivered else '未完成'}"
            f"（尝试 {delivery.attempts} 次）"
        )
        print(f"  {delivery.reason}")

    if result.skipped:
        if result.state in ("blocked", "suspended"):
            return EXIT_FAILED
        return EXIT_OK
    if not result.deliverable:
        print(
            "残留自检未通过：该批次不得投递（告警已落台账）",
            file=sys.stderr,
        )
        return EXIT_RESIDUAL
    if outcome.delivery is not None and not outcome.delivery.delivered:
        return EXIT_DELIVERY
    return EXIT_OK


# --------------------------------------------------------------------- deliver


def _cmd_deliver(args: argparse.Namespace) -> int:
    """``deliver``：重投待交付队列（载荷按台账重建，不重跑脱敏）。"""
    settings = ops.settings_from_args(args)
    runtime = ops.build_runtime(settings)
    try:
        if getattr(args, "batch", None):
            try:
                payload = ops.rebuild_payload(runtime.ledger, args.batch)
            except KeyError as error:
                print(f"重投失败：{error}", file=sys.stderr)
                return EXIT_USAGE
            targets = [(args.batch, payload)]
        else:
            targets = ops.pending_deliveries(runtime.ledger)
            if not targets:
                print("待投递队列为空：台账里没有「已代号化、尚未交付」的批次")
                return EXIT_OK

        print(f"待投递批次：{len(targets)} 个")
        print("-" * 84)
        undelivered = 0
        for batch_no, payload in targets:
            outcome = runtime.queue.submit(batch_no, payload)
            if outcome.delivered:
                verdict = "已交付"
            elif outcome.exhausted:
                verdict = "挂起等重投"
                undelivered += 1
            else:
                verdict = "待重试"
                undelivered += 1
            print(
                f"  {batch_no:<20}{verdict:<14}尝试 {outcome.attempts} 次"
                f"  幂等键 {payload.get('idempotency_key', '')}"
            )
            print(f"    {outcome.reason}")
    finally:
        runtime.close()

    if undelivered:
        print(
            f"有 {undelivered} 个批次未交付：批次已挂起等重投（台账可查）",
            file=sys.stderr,
        )
        return EXIT_DELIVERY
    return EXIT_OK


# --------------------------------------------------------------------- restore


def _cmd_restore_request(args: argparse.Namespace) -> int:
    """``restore-request``：提交受控还原请求（双人授权 + 时效 + 范围）。"""
    from .models import RestoreAuthorization
    from .policy.index_store import IndexStoreError
    from .restore.authority import authorize_window, default_authority_validator
    from .restore.service import InMemoryMappingIndex, RestoreService

    settings = ops.settings_from_args(args)
    batch_no = str(args.batch or "").strip()
    approver_a = str(args.approver_a or "").strip()
    approver_b = str(args.approver_b or "").strip() or None
    if not batch_no or not approver_a:
        print("必须给 --batch <批次号> 与 --approver-a <授权人>", file=sys.stderr)
        return EXIT_USAGE

    runtime = ops.build_runtime(settings)
    try:
        record = runtime.ledger.get_batch(batch_no)
        if record is None:
            print(f"还原失败：批次 {batch_no} 不在台账里", file=sys.stderr)
            return EXIT_USAGE
        scope = tuple(args.scope) if args.scope else tuple(record.material_ids)
        if not scope:
            print(
                f"还原失败：批次 {batch_no} 没有可还原的材料（台账里没有材料清单）",
                file=sys.stderr,
            )
            return EXIT_USAGE

        granted_at, expires_at = authorize_window(ttl=timedelta(hours=24))
        authorization = RestoreAuthorization(
            request_id=str(
                args.request_id or f"{batch_no}-R{granted_at:%Y%m%d%H%M%S}"
            ),
            dataset_id=str(args.dataset_id or ""),
            approver_a=approver_a,
            approver_b=approver_b,
            scope=scope,
            reason=str(args.reason or ""),
            granted_at=granted_at,
            expires_at=expires_at,
        )

        if not approver_b:
            # 只受理请求（等第二授权人签字）：**不解密对照索引** ——
            # 这一步不还原任何东西，就不该去碰装着原文的那份索引。
            service = RestoreService(
                index=InMemoryMappingIndex(),
                ledger=runtime.ledger,
                platform=runtime.platform,
                validator=default_authority_validator(),
            )
            outcome = service.request(
                authorization,
                batch_no=batch_no,
                dataset_id=str(args.dataset_id or ""),
                allowed_scope=tuple(record.material_ids),
            )
        else:
            # 真要还原了：对照索引必须可达 —— 不可达就把批次挂起，
            # **不重建空索引放行**（还原件会缺段却看不出来）。
            index = runtime.index
            if not hasattr(index, "require_available"):
                print(
                    "还原失败：对照索引未启用持久化"
                    "（未配置 $INDEX_ENCRYPTION_KEY 或 $PSEUDONYM_HMAC_KEY）"
                    "：跨进程换不回原文，请先补齐凭据位",
                    file=sys.stderr,
                )
                return EXIT_FAILED
            try:
                index.require_available(ledger=runtime.ledger, batch_no=batch_no)
            except IndexStoreError as error:
                print(f"还原失败：{error}", file=sys.stderr)
                return EXIT_FAILED

            materials: dict[str, str] = {}
            missing: list[str] = []
            for material_id in scope:
                path = record.artifacts.get(material_id)
                if not path or not Path(path).is_file():
                    missing.append(material_id)
                    continue
                try:
                    materials[material_id] = Path(path).read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    missing.append(material_id)
            if missing:
                print(
                    "还原失败：脱敏副本读不出来："
                    + "、".join(missing)
                    + "（产物不在盘上，不得凭空还原）",
                    file=sys.stderr,
                )
                return EXIT_FAILED

            service = RestoreService(
                index=index,
                ledger=runtime.ledger,
                platform=runtime.platform,
                validator=default_authority_validator(),
            )
            output_dir = (
                Path(args.out)
                if args.out
                else settings.output_dir / "restored" / batch_no
            )
            outcome = service.execute(
                authorization,
                batch_no=batch_no,
                materials=materials,
                dataset_id=str(args.dataset_id or ""),
                allowed_scope=tuple(record.material_ids),
                output_dir=output_dir,
            )
    except Exception as error:
        print(_restore_error_text(error, batch_no), file=sys.stderr)
        return EXIT_FAILED
    finally:
        runtime.close()

    print(f"批次：{outcome.batch_no}")
    print(f"状态：{outcome.status}")
    print(f"裁决码：{outcome.code or '（无）'}")
    print(f"授权人：{outcome.approver_a or '（无）'} / {outcome.approver_b or '（缺第二签字人）'}")
    print(f"授权范围：{'、'.join(outcome.scope) or '（无）'}")
    print(f"请求号：{outcome.restore_request_id}")
    if outcome.receipt is not None:
        print(f"还原回执：{outcome.receipt.receipt_id}")
    print(f"平台回执：{outcome.platform_receipt_status}")
    print(f"说明：{outcome.reason}")
    if outcome.restored:
        print(f"已还原材料：{len(outcome.restored)} 份")
    if outcome.pending:
        print(
            "待办：本批处于挂起态，等第二授权人签字后重跑本命令（补 --approver-b）"
            "（不降级为单人还原）"
        )

    if outcome.rejected:
        print(
            "还原被拒：授权不齐 / 过期 / 超范围（已留痕，不降级放行）",
            file=sys.stderr,
        )
        return EXIT_AUTHORITY
    return EXIT_OK


def _restore_error_text(error: Exception, batch_no: str) -> str:
    """还原失败的原因文案（把状态机错误讲成人话）。"""
    from .daemon.state_machine import (
        IllegalTransitionError,
        TransitionRejectedError,
    )

    if isinstance(error, (IllegalTransitionError, TransitionRejectedError)):
        return (
            f"还原失败：批次 {batch_no} 当前状态不接受还原请求：{error}"
            "（还原只对已交付的批次开放；请先把该批交付出去）"
        )
    return f"还原失败：{type(error).__name__}: {error}"


# --------------------------------------------------------------------- export


def _cmd_export_audit(args: argparse.Namespace) -> int:
    """``export-audit``：导出分组视图并打印条数摘要。"""
    manifests = list(getattr(args, "manifests", []) or [])
    outbox = getattr(args, "outbox", None)
    if not manifests and not outbox:
        print(
            "导出失败：至少要给一个 --manifest 清单路径或 --outbox 产物目录",
            file=sys.stderr,
        )
        return EXIT_USAGE

    settings = DaemonSettings.from_env()
    out_dir = Path(args.out) if getattr(args, "out", None) else (
        settings.output_dir / "audit-export"
    )

    try:
        collected = collect_manifests(
            manifest_paths=manifests,
            outbox=outbox,
            batch_label=getattr(args, "batch", None),
        )
    except FileNotFoundError as error:
        print(f"导出失败：{error}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, ValueError) as error:
        print(f"导出失败：{error}", file=sys.stderr)
        return EXIT_FAILED

    if not collected:
        print("导出失败：没有可导出的命中清单", file=sys.stderr)
        return EXIT_USAGE

    export = export_manifest_views(collected, out_dir)
    print(format_export_summary(export))
    return EXIT_OK


# --------------------------------------------------------------------- residual


def _cmd_verify_residual(args: argparse.Namespace) -> int:
    """``verify-residual``：对脱敏产物再扫一遍身份类残留。"""
    settings = ops.settings_from_args(args)
    batch_no = str(getattr(args, "batch", None) or "").strip()
    source = str(getattr(args, "input", None) or "").strip()
    if bool(batch_no) == bool(source):
        print(
            "必须且只能给一个：--batch <批次号> 或 --in <脱敏副本路径>",
            file=sys.stderr,
        )
        return EXIT_USAGE

    checker = ResidualChecker(sink=JsonlAlertSink(settings.alert_ledger_path))
    if source:
        path = Path(source)
        if not path.is_file():
            print(f"残留自检失败：文件不存在：{path}", file=sys.stderr)
            return EXIT_USAGE
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            print(f"残留自检失败：读不出来：{error}", file=sys.stderr)
            return EXIT_FAILED
        report = checker.check_batch(path.stem, {path.stem: text})
    else:
        ledger = BatchLedger(settings.ledger_path)
        try:
            record = ledger.get_batch(batch_no)
            if record is None:
                print(
                    f"残留自检失败：批次 {batch_no} 不在台账里", file=sys.stderr
                )
                return EXIT_USAGE
            texts = ops.read_redacted_artifacts(record.artifacts)
            if not texts:
                print(
                    f"残留自检失败：批次 {batch_no} 的脱敏副本不在盘上"
                    "（台账登记的产物路径读不出来）",
                    file=sys.stderr,
                )
                return EXIT_FAILED
            report = checker.check_batch(batch_no, texts)
        finally:
            ledger.close()

    print(f"批次：{report.batch_no}")
    print(f"已扫材料：{len(report.scanned_materials)} 份")
    print(f"残留自检：{report.summary}")
    if report.identity_count:
        print(f"  身份类残留：{report.identity_count} 处")
        for finding in report.findings:
            print(
                f"    {finding.material_id:<20}{finding.label:<16}"
                f"{finding.start}-{finding.end}"
            )
    if report.hint_count:
        labels = "、".join(sorted({finding.label for finding in report.hints}))
        print(f"  提示（不阻断投递）：通用数字类 {report.hint_count} 处（类别 {labels}）")
    if report.suppressed_count:
        detail = "、".join(
            f"{reason} {count} 处" for reason, count in sorted(report.suppressed.items())
        )
        print(f"  已脱产物（不计入残留）：{detail}")
    if not report.deliverable:
        print(
            "残留自检未通过：该批次不得投递（告警已落台账）",
            file=sys.stderr,
        )
        return EXIT_RESIDUAL
    return EXIT_OK


# --------------------------------------------------------------------- status


def _cmd_status(args: argparse.Namespace) -> int:
    """``status``：打印批次时间线（每一步迁移的时间与原因）。"""
    settings = ops.settings_from_args(args)
    batch_no = str(getattr(args, "batch", None) or "").strip()
    ledger = BatchLedger(settings.ledger_path)
    try:
        if not batch_no:
            if getattr(args, "export_timeline", None):
                print(
                    "导出时间线要指定批次：--batch <批次号>",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            records = ledger.list_batches()
            if not records:
                print("台账里还没有批次")
                return EXIT_OK
            print(f"批次总数：{len(records)} 个")
            print("-" * 84)
            print(f"  {'批次号':<20}{'状态':<18}{'材料':<8}{'命中':<8}策略版本")
            for record in records:
                entries = len(ledger.manifest_entries(record.batch_no))
                print(
                    f"  {record.batch_no:<20}{record.state:<18}"
                    f"{len(record.material_ids):<8}{entries:<8}"
                    f"{record.policy_version or '（未记录）'}"
                )
            return EXIT_OK

        record = ledger.get_batch(batch_no)
        if record is None:
            print(f"查不到批次：{batch_no}", file=sys.stderr)
            return EXIT_USAGE
        print(f"批次：{record.batch_no}")
        print(f"状态：{record.state}")
        print(f"伦理批件号：{record.ethics_approval_no or '（缺）'}")
        print(f"材料：{len(record.material_ids)} 份（{'、'.join(record.material_ids) or '无'}）")
        print(f"幂等键：{record.idempotency_key or '（未登记）'}")
        print(f"策略版本：{record.policy_version or '（未记录）'}")
        if record.failure_reason:
            print(f"失败原因：{record.failure_reason}")
        if record.current_step:
            print(f"当前步骤：{record.current_step}")
        print("-" * 84)
        print("产物：")
        for material_id, path in (record.artifacts or {}).items():
            print(f"  {material_id}")
            print(f"    → {path}")
        entries = ledger.manifest_entries(batch_no)
        print(f"命中清单：{len(entries)} 条")
        summaries = ledger.residual_summaries(batch_no)
        for summary in summaries:
            print(
                f"残留自检：{summary.summary}"
                f"（阻断 {summary.identity_count} / 提示 {summary.hint_count}）"
            )
        receipts = ledger.receipts(batch_no)
        if receipts:
            print("回执：")
            for receipt in receipts:
                print(
                    f"  {receipt.receipt_id:<24}{receipt.kind:<10}"
                    f"{receipt.platform_receipt_id or ''}"
                )
        timeline = ledger.timeline(batch_no)
        print("-" * 84)
        print(f"时间线（{len(timeline)} 步）：")
        print(ops.format_timeline(timeline) or "  （暂无迁移记录）")
        export_path = getattr(args, "export_timeline", None)
        if export_path:
            written = ops.export_timeline(ledger, batch_no, export_path)
            print(f"时间线已导出：{written}（{len(timeline)} 步）")
    finally:
        ledger.close()
    return EXIT_OK


# --------------------------------------------------------------------- redact


def _cmd_redact(args: argparse.Namespace) -> int:
    """``redact`` 子命令：跑一次脱敏并打印可核对摘要。"""
    source = Path(args.input)
    if not source.is_file():
        print(f"材料文件不存在：{source}", file=sys.stderr)
        return EXIT_USAGE

    try:
        outcome = redact_file(
            source,
            args.output,
            args.manifest,
            material_id=args.material_id,
        )
    except (OSError, ValueError, RuntimeError) as error:
        print(f"脱敏失败：{error}", file=sys.stderr)
        return EXIT_FAILED

    _print_summary(source, Path(args.output), Path(args.manifest), outcome)
    if getattr(args, "verify_residual", False):
        return _verify_residual(source, outcome)
    return EXIT_OK


def _cmd_redact_dicom(args: argparse.Namespace) -> int:
    """``redact-dicom`` 子命令：跑一次 DICOM tag 级去标识并打印可核对摘要。"""
    source = Path(args.input)
    if not source.is_file():
        print(f"材料文件不存在：{source}", file=sys.stderr)
        return EXIT_USAGE

    try:
        outcome = redact_dicom_file(
            source,
            args.output,
            args.manifest,
            material_id=args.material_id,
        )
    except (OSError, ValueError, RuntimeError, DicomError) as error:
        print(f"DICOM 去标识失败：{error}", file=sys.stderr)
        return EXIT_FAILED

    print(f"材料：{source}")
    print(f"脱敏副本：{args.output}")
    print(f"命中清单：{args.manifest}（{len(outcome.entries)} 行）")
    print(f"传输语法：{outcome.transfer_syntax}")
    print("-" * 68)
    print(
        f"  私有 tag 清空 {outcome.counts.get('private_cleared', 0)} 个；"
        f"身份 tag 清空 {outcome.counts.get('identity_cleared', 0)} 个；"
        f"取值替换 {outcome.counts.get('replaced', 0)} 个；"
        f"必要 tag 保留 {outcome.counts.get('kept', 0)} 个"
    )
    print(f"  {outcome.self_check.summary}")
    print("  像素烧录未处理：BurnedInAnnotation 旗标留待人工点检")
    print("-" * 68)
    for entry in outcome.entries:
        if entry.label == "DICOM_SUMMARY":
            continue
        position = f"{entry.start}-{entry.end}"
        print(
            f"  {entry.label:<20}{position:<14}{entry.action:<10}{entry.reason}"
        )
    return EXIT_OK


def _verify_residual(source: Path, outcome) -> int:
    material_id = outcome.material_id
    checker = ResidualChecker(sink=JsonlAlertSink())
    report = checker.check_batch(material_id, {material_id: outcome.redacted_text})
    print(f"残留自检：{report.summary}")
    if report.hint_count:
        labels = "、".join(
            sorted({finding.label for finding in report.hints})
        )
        print(f"  提示（不阻断投递）：通用数字类 {report.hint_count} 处（类别 {labels}）")
    if report.suppressed_count:
        detail = "、".join(
            f"{reason} {count} 处" for reason, count in sorted(report.suppressed.items())
        )
        print(f"  已脱产物（不计入残留）：{detail}")
    if not report.deliverable:
        print(
            "残留自检未通过：该批次不得投递（告警已落 var/alerts.jsonl）",
            file=sys.stderr,
        )
        return EXIT_RESIDUAL
    return EXIT_OK


def _print_summary(source: Path, output: Path, manifest: Path, outcome) -> None:
    """打印人类可读摘要：产物路径 + 逐处命中 + 档位统计。"""
    print(f"材料：{source}")
    print(f"脱敏副本：{output}")
    print(f"命中清单：{manifest}（{len(outcome.entries)} 行）")
    print("-" * 68)
    print(f"  {'档位':<6}{'位置':<12}{'类别':<16}{'分数':<7}{'处置':<12}说明")
    for entry in outcome.entries:
        position = f"{entry.start}-{entry.end}"
        print(
            f"  {_tier_label(entry.tier):<6}{position:<12}{entry.label:<16}"
            f"{entry.score:<7.2f}{entry.action:<12}{entry.reason}"
        )
    print("-" * 68)
    print(
        f"合计：确认 {outcome.counts.get('confirmed', 0)} / "
        f"告警 {outcome.counts.get('warning', 0)} / "
        f"放行 {outcome.counts.get('allowed', 0)}；已改写 {outcome.rewritten} 处"
    )


def _tier_label(tier: str) -> str:
    """档位的中文短名。"""
    return {"confirmed": "确认", "warning": "告警", "allowed": "放行"}.get(tier, tier)


if __name__ == "__main__":  # pragma: no cover - 入口
    raise SystemExit(main())
