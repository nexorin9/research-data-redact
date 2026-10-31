#!/usr/bin/env python3
"""命中清单分组导出脚本（按批次 / 按材料 / 按实体类别）。

**为什么要有这个脚本**：命中清单是交差产物。一批交付下来往往几十份材料、
上千处命中，伦理办要看的是「这一批一共脱了多少、按类别各多少」，科研数据
管理员要看的是「这份材料被改了几处」，信息科要看的是「哪个批次最费人工」。
一份平铺的 JSONL 谁也数不清 —— 这个脚本把同一批命中切成三种视角，并给一张
可以直接看的摘要表。

**产物形态**::

    <导出目录>/
        by-batch/<批次号>.jsonl        按批次切
        by-material/<材料 ID>.jsonl    按材料切
        by-label/<实体类别>.jsonl      按实体类别切
        summary.csv                    各类别命中数 / 平均分 / 档位分布
        index.json                     机器可读索引（哪个文件、多少条）

**三种视图条数守恒**：任一视图逐文件加总，都等于导出的总条数 —— 同一批命中
在三个视角下都能数清，不多不少。

**不含命中原文**：视图文件沿用命中清单的封闭字段集合（材料 ID / 实体类别 /
起止位置 / 分数 / 档位 / 处置动作 / 解释 / 识别器），结构上就写不进原文；
摘要表只给条数、平均分与档位分布。

**与产品同源**：导出逻辑走产品包 :mod:`research_redact.audit.manifest`，脚本
只负责取数与打印摘要 —— 不另写一套导出实现。

用法::

    python scripts/export_manifest.py --outbox var/outbox
    python scripts/export_manifest.py --manifest var/outbox/KY20260001/manifest.jsonl
    python scripts/export_manifest.py --outbox var/outbox --out reports/audit-export
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from research_redact.audit.manifest import (  # noqa: E402
    collect_manifests,
    export_manifest_views,
    format_export_summary,
)
from research_redact.daemon.settings import DaemonSettings  # noqa: E402

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="export_manifest.py",
        description="命中清单分组导出：按批次 / 按材料 / 按实体类别 + 摘要表",
    )
    parser.add_argument(
        "--manifest",
        dest="manifests",
        action="append",
        default=[],
        help="命中清单路径（可重复给多个）",
    )
    parser.add_argument(
        "--outbox",
        dest="outbox",
        default=None,
        help="产物目录：扫 <批次号>/manifest.jsonl，每批各算一个批次",
    )
    parser.add_argument(
        "--batch",
        dest="batch",
        default=None,
        help="--manifest 指定的清单归到哪个批次（缺省取清单所在父目录名）",
    )
    parser.add_argument(
        "--out",
        dest="out",
        default=None,
        help="导出目录（缺省 <产物目录>/audit-export）",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """脚本入口。成功返回 0，失败返回非 0 并说明原因。"""
    args = build_parser().parse_args(argv)

    if not args.manifests and not args.outbox:
        print(
            "导出失败：至少要给一个 --manifest 清单路径或 --outbox 产物目录",
            file=sys.stderr,
        )
        return 2

    settings = DaemonSettings.from_env()
    out_dir = Path(args.out) if args.out else settings.output_dir / "audit-export"

    try:
        collected = collect_manifests(
            manifest_paths=args.manifests,
            outbox=args.outbox,
            batch_label=args.batch,
        )
    except FileNotFoundError as error:
        print(f"导出失败：{error}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"导出失败：{error}", file=sys.stderr)
        return 3

    if not collected:
        print("导出失败：没有可导出的命中清单", file=sys.stderr)
        return 2

    export = export_manifest_views(collected, out_dir)
    print(format_export_summary(export))
    return 0


if __name__ == "__main__":  # pragma: no cover - 入口
    raise SystemExit(main())
