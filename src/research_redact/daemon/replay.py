"""用策略快照重放批次：复算产出与原批次逐条一致。

**为什么需要重放**：策略表是活的。三个月后伦理办抽检一批材料，问「这一批
当时是怎么脱的」，光有命中清单不够 —— 清单里写着「分数 0.55，告警档」，而
0.55 算确认档还是告警档取决于**当时的全局阈值**；改了阈值之后，这一行记录
就再也解释不清了。

快照把当时的生效配置冻结成一份**合法的策略表**（``var/snapshots/<批次>/
policy.yaml``），把它喂回 :func:`~research_redact.policy.table.load_policy_table`
就能装出与当时逐字一致的注册表 —— 于是同一批材料可以**再脱一遍**，产出的
脱敏副本与逐处命中清单应当与原批次**逐条一致**。

**重放用的是快照，不是当前策略表**：这是这一层的全部意义。若重放读的是当前
策略表，那它证明的只是「现在脱出来还是这个样子」，跟「当时那一版」无关。

**不变量**

1. 重放**只读**：不写台账、不写产物、不动对照索引（还原用的对照索引另算）；
2. 重放的输入是**同一批材料的正文**（正文从投递目录或产物目录取），配置
   从快照取 —— 两边都不能错；
3. 快照缺失 → **明确报错**，不静默退回当前策略表（退回去就等于用另一版配置
   重放，结论是假的）。
"""

from __future__ import annotations

from typing import Any, Mapping

from ..policy.snapshot import SnapshotError, snapshot_policy_path
from ..audit.residual import ResidualChecker

__all__ = [
    "ReplayResult",
    "compare_entries",
    "replay_batch",
]


class ReplayResult:
    """一次重放的结果。

    :param batch_no: 批次号。
    :param policy_version: 快照里的策略版本号（重放实际按这一版跑的）。
    :param redacted_texts: 材料 ID → 重放出来的脱敏正文。
    :param entries: 重放产出的逐处命中清单（不含命中原文）。
    :param residual: 批次级残留自检结论（缺省不跑 —— 传了 checker 才跑）。
    """

    def __init__(
        self,
        batch_no: str,
        policy_version: str,
        redacted_texts: Mapping[str, str],
        entries: tuple[Any, ...],
        residual: Any = None,
    ) -> None:
        self.batch_no = batch_no
        self.policy_version = policy_version
        self.redacted_texts = dict(redacted_texts)
        self.entries = tuple(entries)
        self.residual = residual


def replay_batch(
    batch_no: str,
    materials: Mapping[str, str],
    *,
    snapshot_dir: str | None = None,
    ledger: Any = None,
    checker: ResidualChecker | None = None,
) -> ReplayResult:
    """按快照重放一个批次。

    :param batch_no: 批次号（申请单号）。
    :param materials: 材料 ID → 材料正文（与当初脱敏时**同一份**正文）。
    :param snapshot_dir: 快照根目录；缺省按台账登记的路径 / 环境变量 / 默认。
    :param ledger: 批次台账；给了就按台账里登记的快照路径找（**最准** ——
        快照落在哪儿是台账说了算，不靠猜目录）。
    :param checker: 残留自检器；缺省不跑残留自检（重放只为比对产出）。
    :return: 重放结果（脱敏正文 + 命中清单 + 用的策略版本号）。
    :raises SnapshotError: 该批次没有策略快照 —— **不回退到当前策略表**。
    """
    from ..policy.conflicts import load_conflict_rules
    from ..policy.mapping import PseudonymMappingIndex
    from ..policy.operators import default_operator_registry
    from ..policy.snapshot import load_snapshot
    from ..policy.table import load_policy_table
    from ..recognizers.assembly import build_default_registry
    from .pipeline import redact_batch

    policy_path = _resolve_policy_path(batch_no, snapshot_dir, ledger)
    if not policy_path.is_file():
        raise SnapshotError(
            f"批次 {batch_no} 没有策略快照（{policy_path}）—— "
            "不得用当前策略表重放：那证明的是另一件事"
        )
    snapshot = load_snapshot(batch_no, policy_path.parent.parent)

    # 档位写死成「默认档」：快照里装的就是**已经合并好的生效配置**，
    # 再选一次档位等于选错。
    table = load_policy_table(policy_path, profile="")
    registry = build_default_registry(table=table)
    operators = default_operator_registry(mapping_index=PseudonymMappingIndex())
    rules = load_conflict_rules(policy_path)

    batch = redact_batch(
        batch_no,
        dict(materials),
        checker=checker,
        registry=registry,
        actions=table.resolver(),
        operators=operators,
        rules=rules,
    )
    entries = tuple(entry for outcome in batch.outcomes for entry in outcome.entries)
    return ReplayResult(
        batch_no=batch_no,
        policy_version=snapshot.policy_version,
        redacted_texts=batch.redacted_texts,
        entries=entries,
        residual=batch.residual,
    )


def compare_entries(
    original: Any,
    replayed: Any,
    *,
    keys: tuple[str, ...] = (
        "material_id",
        "label",
        "start",
        "end",
        "tier",
        "action",
    ),
) -> list[str]:
    """逐条比对两份命中清单，返回**不一致的说明**（空列表 = 逐条一致）。

    比对的是**稳定字段**：位置 / 类别 / 档位 / 处置动作。分数与解释不参与
    —— 分数会随识别器演进而变，解释措辞也会改；位置与档位才是「这一批当时
    脱成了什么样」的稳定契约。

    :param original: 原批次的清单条目（:class:`ManifestEntry` 或 dict）。
    :param replayed: 重放产出的清单条目。
    """
    left = [_as_row(entry, keys) for entry in original]
    right = [_as_row(entry, keys) for entry in replayed]
    diffs: list[str] = []
    if len(left) != len(right):
        diffs.append(f"条目数不一致：原批次 {len(left)} 条，重放 {len(right)} 条")
    for index, (old_row, new_row) in enumerate(zip(left, right)):
        if old_row != new_row:
            diffs.append(
                f"第 {index + 1} 条不一致：原 {old_row} ≠ 重放 {new_row}"
            )
    return diffs


def _as_row(entry: Any, keys: tuple[str, ...]) -> tuple[Any, ...]:
    """把一条清单条目（对象或 dict）取成可比对的元组。"""
    if isinstance(entry, Mapping):
        return tuple(entry.get(key) for key in keys)
    return tuple(getattr(entry, key, None) for key in keys)


def _resolve_policy_path(
    batch_no: str, snapshot_dir: str | None, ledger: Any
) -> Path:
    """找出这一批的快照配置路径。

    优先级：**台账登记的路径** → 显式 ``snapshot_dir`` → 默认目录。台账最准 ——
    快照落在哪儿是台账说了算（守护进程与运维 CLI 可能跑在不同目录下）。
    """
    from pathlib import Path

    if ledger is not None:
        record = ledger.policy_snapshot(batch_no)
        if record is not None and record.policy_path:
            return Path(record.policy_path)
    return snapshot_policy_path(batch_no, snapshot_dir)
