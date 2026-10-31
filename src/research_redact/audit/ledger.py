"""SQLite 批次台账：批次 / 状态迁移 / 回执 / 访问留痕 / 告警。

源产品**没有台账** —— 它是 SDK：识别完就返回，调用方自己决定拿结果去哪儿。
医院场景必须有台账：科研材料交付出去以后，伦理办要问「这批什么时候脱的、
谁批的、平台回执在哪」，信息科要问「上周那批为什么卡着」，还原的时候还要查
「这批当时用了哪一版策略」。这些都要有个**落得下来、查得到**的地方。

**九张表**：

| 表 | 装什么 |
|---|---|
| ``batches`` | 批次主表：状态、幂等键、当前步骤、已完成步骤、产物路径、失败原因、策略版本号 |
| ``batch_transitions`` | 状态迁移流水（每次迁移的来源态、事件、目标态、原因、时间） |
| ``receipts`` | 回执：交付回执、还原回执（平台侧回执 ID 一并留档） |
| ``access_log`` | 访问留痕：谁、何时、对哪一批做了什么（**不含原文**） |
| ``alerts`` | 批次告警落点（实现 :class:`~research_redact.audit.alerts.AlertSink` 协议） |
| ``residual_checks`` | 批次级残留自检摘要（通过与否都留，task 28） |
| ``idempotency_keys`` | 幂等键认领表：键为主键，**唯一约束落在这里**（task 33） |
| ``manifest_entries`` | 命中清单条目：重放防护的唯一约束落在这里（task 35） |
| ``policy_snapshots`` | 策略快照登记：这一批用哪一版策略脱的（task 36） |

**三条纪律**：

1. **失败不静默改数据** —— 非法迁移 / 守卫拒绝时抛出明确错误，批次状态**不动**，
   台账里不会留下一条「其实没走成」的迁移记录。
2. **状态只有一个真源** —— 状态列存的是 :class:`~research_redact.daemon.state_machine.BatchState`
   的取值，模块之间不传裸字符串。
3. **台账不记患者原文** —— 批次表、回执表、访问留痕表都只记编号、路径、计数与
   原因。回执体里若要带原文片段，**调用方自己负责脱**（本模块不代劳、也不该代劳）。

**与状态机的关系**：:meth:`BatchLedger.advance` 把两者接在一起 —— 一次调用既判
迁移（:class:`~research_redact.daemon.state_machine.StateMachine`）、又落库、又按
需落告警（阻断 / 挂起必落告警）。守护进程（task 11）与运维 CLI（task 39）都调它。

**幂等与并发**：幂等键认领表 :meth:`BatchLedger.claim_idempotency_key` 以
``INSERT OR IGNORE`` 落唯一约束 —— 两个执行者同时认领同一个键，只有一个拿到
``is_new=True``，另一个复用已有回执，**不产生第二次真实外发**。断点续跑
（task 34）与并发互斥（task 35）在其上叠加。
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from ..daemon.state_machine import (
    BatchEvent,
    BatchState,
    IllegalTransitionError,
    StateMachine,
    TransitionContext,
    TransitionResult,
    default_state_machine,
    intake_event,
    recognition_event,
)
from ..models import Batch, utcnow
from ..paths import project_root
from .alerts import BatchAlert

if TYPE_CHECKING:  # pragma: no cover - 类型用
    from .residual import ResidualReport

__all__ = [
    "AccessRecord",
    "BatchLedger",
    "BatchRecord",
    "IDEMPOTENCY_CLAIMED",
    "IDEMPOTENCY_DELIVERED",
    "LEDGER_PATH_ENV",
    "IdempotencyClaim",
    "IdempotencyRecord",
    "PolicySnapshotRecord",
    "ReceiptRecord",
    "ResidualSummaryRecord",
    "TransitionRecord",
    "default_ledger_path",
]


#: 环境变量：台账路径（.env.example 里的 RESEARCH_LEDGER_DB）
LEDGER_PATH_ENV = "RESEARCH_LEDGER_DB"

#: 台账默认文件名（放在项目根 var/ 下，属运行时数据，不进版本库）
_LEDGER_FILE = "ledger.sqlite3"

#: 幂等认领状态：已认领、尚未交付（可能正在交付中，也可能上次交付失败）。
IDEMPOTENCY_CLAIMED = "claimed"

#: 幂等认领状态：已交付（平台回了回执）。
IDEMPOTENCY_DELIVERED = "delivered"

#: 陈旧认领的租约时长（秒）：认领后超过这个时长还没交付，视为上次执行者
#: 已经不在了，下一个执行者可以接管（否则崩溃留下的认领会永远挡住重投）。
IDEMPOTENCY_LEASE_SECONDS = 300.0


def default_ledger_path() -> Path:
    """台账默认路径：项目根目录下的 ``var/ledger.sqlite3``。

    环境变量 ``$RESEARCH_LEDGER_DB`` 优先 —— 守护进程与运维 CLI 跑在不同工作
    目录下时，台账不该散在各处。

    缺省路径按**项目根目录**解析（见 :func:`research_redact.paths.project_root`）：
    只看 ``policy/`` 会把包目录 ``src/research_redact/`` 认成项目根，台账就
    会落到 ``src/research_redact/var/`` 里 —— 既不是 ``.env.example`` 写的
    位置，也不在 ``.gitignore`` 覆盖的运行时目录里。
    """
    env_value = os.environ.get(LEDGER_PATH_ENV)
    if env_value:
        return Path(env_value)
    return project_root() / "var" / _LEDGER_FILE


# --------------------------------------------------------------------- 记录


@dataclass(frozen=True)
class BatchRecord:
    """批次台账的一行。

    :param batch_no: 批次号（申请单号）。
    :param ethics_approval_no: 伦理批件号。
    :param state: 当前状态（:class:`BatchState` 的取值）。
    :param idempotency_key: 幂等键（申请单号 + 材料集合指纹，唯一约束见
        ``idempotency_keys`` 表）。
    :param current_step: 当前步骤。
    :param completed_steps: 已完成步骤集合。
    :param failure_reason: 失败 / 阻断 / 挂起的原因。
    :param artifacts: 产物路径（脱敏副本、命中清单、平台数据集 …）。
    :param patient_ids: 本批涉及的患者主索引主键。
    :param material_ids: 本批材料 ID。
    :param material_fingerprint: 材料集合指纹（源文件摘要口径）—— 材料集合
        变了就是新的一批，不该被当成重复批次丢掉。
    :param material_entries: 交付体里的材料清单（材料 ID / 类别 / 摘要 / 路径），
        守护进程重启补投时据此重建投递载荷，不必重跑脱敏。
    :param policy_version: 本批用的策略表版本号（task 36）—— 策略表改过之后，
        靠它 + 快照目录里的配置副本把这一批重放一遍。
    :param created_at: 建批时间。
    :param updated_at: 更新时间。
    """

    batch_no: str
    ethics_approval_no: str | None = None
    state: str = BatchState.DETECTED.value
    idempotency_key: str = ""
    current_step: str = ""
    completed_steps: tuple[str, ...] = ()
    failure_reason: str = ""
    artifacts: Mapping[str, str] = field(default_factory=dict)
    patient_ids: tuple[str, ...] = ()
    material_ids: tuple[str, ...] = ()
    material_fingerprint: str = ""
    material_entries: tuple[Mapping[str, str], ...] = ()
    policy_version: str = ""
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    @property
    def batch_state(self) -> BatchState:
        """当前状态（枚举形式）。"""
        return BatchState(self.state)

    @property
    def is_delivered(self) -> bool:
        """是否已交付。"""
        return self.batch_state is BatchState.DELIVERED

    def to_model(self) -> Batch:
        """转成 :class:`~research_redact.models.Batch`（进程内表示）。"""
        return Batch(
            application_no=self.batch_no,
            ethics_approval_no=self.ethics_approval_no,
            patient_ids=self.patient_ids,
            state=self.state,
            idempotency_key=self.idempotency_key,
            current_step=self.current_step,
            failure_reason=self.failure_reason,
            artifacts=dict(self.artifacts),
            created_at=self.created_at,
        )


@dataclass(frozen=True)
class TransitionRecord:
    """一条状态迁移流水。"""

    batch_no: str
    source_state: str
    event: str
    target_state: str
    reason: str = ""
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class ReceiptRecord:
    """一条回执（交付回执 / 还原回执）。"""

    receipt_id: str
    batch_no: str
    kind: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    platform_receipt_id: str | None = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class AccessRecord:
    """一条访问留痕（谁、何时、对哪一批做了什么）。"""

    batch_no: str
    actor: str
    operation: str
    detail: str = ""
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class ResidualSummaryRecord:
    """一条批次级残留自检摘要。

    摘要**每批必留**（通过与否都留）—— 事后伦理办问「这批当时到底脱干净了
    没有」，答案在这里：扫了几份材料、阻断级残留几处、提示级几处、抑制了几处。

    :param batch_no: 批次号（申请单号）。
    :param scanned_materials: 扫过的材料 ID。
    :param identity_count: 阻断级残留处数。
    :param hint_count: 提示级残留处数。
    :param suppressed: 被抑制的处数（按原因分）。
    :param deliverable: 该批次是否可投递（阻断级残留为 0）。
    :param summary: 一句人话结论（不含命中原文）。
    :param created_at: 记录时间。
    """

    batch_no: str
    scanned_materials: tuple[str, ...] = ()
    identity_count: int = 0
    hint_count: int = 0
    suppressed: Mapping[str, int] = field(default_factory=dict)
    deliverable: bool = True
    summary: str = ""
    created_at: datetime = field(default_factory=utcnow)

    @property
    def suppressed_count(self) -> int:
        """被抑制的总处数。"""
        return sum(self.suppressed.values())


@dataclass(frozen=True)
class PolicySnapshotRecord:
    """一批的策略快照登记（task 36）。

    :param batch_no: 批次号。
    :param policy_version: 策略版本号（``pol-`` + 16 位十六进制）。
    :param policy_sha256: 生效配置的完整 sha256。
    :param profile: 当时选用的档位名。
    :param source: 策略表来源路径（当时的文件）。
    :param source_sha256: 策略表文件的 sha256（含注释的原始字节）。
    :param snapshot_dir: 快照目录。
    :param policy_path: 生效配置副本路径（可喂回 ``load_policy_table()``）。
    :param created_at: 登记时间。
    """

    batch_no: str
    policy_version: str = ""
    policy_sha256: str = ""
    profile: str = ""
    source: str = ""
    source_sha256: str = ""
    snapshot_dir: str = ""
    policy_path: str = ""
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class IdempotencyRecord:
    """幂等键认领表的一行。

    幂等键是**主键** —— 同一把键只能被认领一次。这是「重复投递不产生第二次
    真实外发」的落地处：认领走 ``INSERT OR IGNORE``，两个执行者同时抢同一把
    键，只有一个拿到「这是新认领」。

    :param idempotency_key: 幂等键（申请单号 + 材料集合指纹）。
    :param batch_no: 认领的批次号。
    :param fingerprint: 材料集合指纹。
    :param material_ids: 本批材料 ID。
    :param state: 认领状态（``claimed`` / ``delivered``）。
    :param dataset_id: 平台侧数据集 ID（交付后回填）。
    :param receipt_id: 平台侧回执 ID（交付后回填）。
    :param created_at: 认领时间。
    :param updated_at: 更新时间。
    """

    idempotency_key: str
    batch_no: str = ""
    fingerprint: str = ""
    material_ids: tuple[str, ...] = ()
    state: str = IDEMPOTENCY_CLAIMED
    dataset_id: str = ""
    receipt_id: str = ""
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    @property
    def is_delivered(self) -> bool:
        """是否已交付（平台回了回执）。"""
        return self.state == IDEMPOTENCY_DELIVERED


@dataclass(frozen=True)
class IdempotencyClaim:
    """一次幂等键认领的结果。

    :param record: 认领表里的那一行。
    :param is_new: 这次是不是**首次**认领。

    ``is_new=False`` 表示这把键已经有人认领了 —— 调用方**不得**再次外发，
    应当复用已有回执（或等前一个执行者交付完）。
    """

    record: IdempotencyRecord
    is_new: bool = True

    @property
    def idempotency_key(self) -> str:
        """幂等键。"""
        return self.record.idempotency_key


# --------------------------------------------------------------------- 台账


_SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_no        TEXT PRIMARY KEY,
    ethics_approval_no TEXT,
    state           TEXT NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    current_step    TEXT NOT NULL DEFAULT '',
    completed_steps TEXT NOT NULL DEFAULT '[]',
    failure_reason  TEXT NOT NULL DEFAULT '',
    artifacts       TEXT NOT NULL DEFAULT '{}',
    patient_ids     TEXT NOT NULL DEFAULT '[]',
    material_ids    TEXT NOT NULL DEFAULT '[]',
    material_fingerprint TEXT NOT NULL DEFAULT '',
    material_entries TEXT NOT NULL DEFAULT '[]',
    policy_version  TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_batches_state ON batches(state);
CREATE INDEX IF NOT EXISTS idx_batches_idem ON batches(idempotency_key);

CREATE TABLE IF NOT EXISTS batch_transitions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no     TEXT NOT NULL,
    source_state TEXT NOT NULL,
    event        TEXT NOT NULL,
    target_state TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transitions_batch ON batch_transitions(batch_no);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id         TEXT PRIMARY KEY,
    batch_no           TEXT NOT NULL,
    kind               TEXT NOT NULL,
    payload            TEXT NOT NULL DEFAULT '{}',
    platform_receipt_id TEXT,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_batch ON receipts(batch_no);

CREATE TABLE IF NOT EXISTS access_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no   TEXT NOT NULL,
    actor      TEXT NOT NULL,
    operation  TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_batch ON access_log(batch_no);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no       TEXT NOT NULL,
    code           TEXT NOT NULL,
    level          TEXT NOT NULL,
    count          INTEGER NOT NULL DEFAULT 0,
    message        TEXT NOT NULL,
    material_ids   TEXT NOT NULL DEFAULT '[]',
    notified       INTEGER NOT NULL DEFAULT 0,
    notify_channel TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_batch ON alerts(batch_no);

CREATE TABLE IF NOT EXISTS residual_checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no     TEXT NOT NULL,
    scanned_materials TEXT NOT NULL DEFAULT '[]',
    identity_count INTEGER NOT NULL DEFAULT 0,
    hint_count   INTEGER NOT NULL DEFAULT 0,
    suppressed   TEXT NOT NULL DEFAULT '{}',
    deliverable  INTEGER NOT NULL DEFAULT 0,
    summary      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_residual_batch ON residual_checks(batch_no);

-- 策略快照表：这一批是用哪一版策略脱的（task 36）。
-- 一批一条（UNIQUE(batch_no)）：策略表改过之后，事后靠这张表 + 快照目录
-- 里的配置副本把这一批重放一遍，产物与原批次逐条一致。
-- 表里只存**标识与路径**，不存配置正文（正文在 var/snapshots/<批次>/policy.yaml），
-- 更不存任何密钥。
CREATE TABLE IF NOT EXISTS policy_snapshots (
    batch_no       TEXT PRIMARY KEY,
    policy_version TEXT NOT NULL,
    policy_sha256  TEXT NOT NULL DEFAULT '',
    profile        TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',
    source_sha256  TEXT NOT NULL DEFAULT '',
    snapshot_dir   TEXT NOT NULL DEFAULT '',
    policy_path    TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);

-- 幂等键认领表：键即主键 —— 唯一约束就落在这里。
-- 两个执行者（守护进程 + 运维 CLI）同时认领同一把键，INSERT OR IGNORE 只会有
-- 一个拿到「首次认领」，另一个必须复用已有回执，不得再次外发。
CREATE TABLE IF NOT EXISTS idempotency_keys (
    idempotency_key TEXT PRIMARY KEY,
    batch_no       TEXT NOT NULL,
    fingerprint    TEXT NOT NULL DEFAULT '',
    material_ids   TEXT NOT NULL DEFAULT '[]',
    state          TEXT NOT NULL DEFAULT 'claimed',
    dataset_id     TEXT NOT NULL DEFAULT '',
    receipt_id     TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idem_batch ON idempotency_keys(batch_no);

-- 命中清单条目表：**重放防护的唯一约束落在这里**。
-- 同一批次、同一材料集合（scope = 批次身份指纹）、同一 (材料 ID, 起点, 实体类别)
-- 只记一条 —— 同一批材料被重放处理时，清单不会翻倍。
-- scope 用批次指纹而不是批次号：材料集合变了就是新的一批（task 33 的口径），
-- 新的一批要有自己的清单，不能被旧范围的记录挡住。
CREATE TABLE IF NOT EXISTS manifest_entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no     TEXT NOT NULL,
    scope        TEXT NOT NULL,
    material_id  TEXT NOT NULL,
    label        TEXT NOT NULL,
    span_start   INTEGER NOT NULL,
    span_end     INTEGER NOT NULL,
    score        REAL NOT NULL DEFAULT 0,
    tier         TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    recognizer   TEXT NOT NULL DEFAULT '',
    merged_duplicates TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    UNIQUE(batch_no, scope, material_id, span_start, label)
);
CREATE INDEX IF NOT EXISTS idx_manifest_batch ON manifest_entries(batch_no, scope);
"""

#: 台账表结构补齐用的列（老库升级时补上）。
_BATCHES_EXTRA_COLUMNS: tuple[tuple[str, str], ...] = (
    ("material_fingerprint", "TEXT NOT NULL DEFAULT ''"),
    ("material_entries", "TEXT NOT NULL DEFAULT '[]'"),
    ("policy_version", "TEXT NOT NULL DEFAULT ''"),
)


class BatchLedger:
    """SQLite 批次台账。

    :param path: 台账文件路径；缺省 :func:`default_ledger_path`。
    :param machine: 状态机；缺省默认迁移表。

    用法::

        with BatchLedger(tmp_path / "ledger.db") as ledger:
            record = ledger.apply_intake(intake)
            record = ledger.advance(record.batch_no, BatchEvent.DELIVERY_SUCCEEDED, ctx)
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        machine: StateMachine | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else default_ledger_path()
        raw_path = str(path) if path is not None else str(default_ledger_path())
        self._in_memory = raw_path == ":memory:"
        if not self._in_memory:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._machine = machine or default_state_machine()
        # timeout=30：守护进程与运维 CLI 可能同时写同一张台账（幂等认领），
        # 写锁冲突时等对方提交，而不是直接抛「database is locked」。
        self._connection = sqlite3.connect(raw_path, timeout=30.0)
        self._connection.row_factory = sqlite3.Row
        self.ensure_schema()

    # ------------------------------------------------------------------ 生命周期

    def close(self) -> None:
        """关连接。"""
        self._connection.close()

    def __enter__(self) -> "BatchLedger":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def ensure_schema(self) -> None:
        """建表（幂等）。"""
        self._connection.executescript(_SCHEMA)
        self._connection.commit()
        self._ensure_batch_columns()

    def _ensure_batch_columns(self) -> None:
        """老台账补列（表已存在时 ``CREATE TABLE IF NOT EXISTS`` 不会补字段）。

        升级不丢数据：已有批次行原样留着，新列落默认值。
        """
        existing = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(batches)").fetchall()
        }
        for name, ddl in _BATCHES_EXTRA_COLUMNS:
            if name in existing:
                continue
            self._connection.execute(
                f"ALTER TABLE batches ADD COLUMN {name} {ddl}"  # noqa: S608 - 片段固定
            )
        self._connection.commit()

    # ------------------------------------------------------------------ 批次

    def open_batch(
        self,
        application_no: str,
        *,
        ethics_approval_no: str | None = None,
        patient_ids: Sequence[str] = (),
        material_ids: Sequence[str] = (),
        idempotency_key: str = "",
    ) -> BatchRecord:
        """建批（状态 ``detected``），并落一条「申请单落目录」迁移流水。

        同一批次号重复建批时**不覆盖**已有记录，只补齐空缺字段 —— 重投是常态，
        建批不该把上一次的状态抹掉。

        :param application_no: 批次号（申请单号）。
        :param ethics_approval_no: 伦理批件号。
        :param patient_ids: 患者主索引主键清单。
        :param material_ids: 材料 ID 清单。
        :param idempotency_key: 幂等键（task 33 落唯一约束）。
        """
        existing = self.get_batch(application_no)
        now = utcnow().isoformat()
        if existing is None:
            self._connection.execute(
                "INSERT INTO batches (batch_no, ethics_approval_no, state,"
                " idempotency_key, current_step, completed_steps, failure_reason,"
                " artifacts, patient_ids, material_ids, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    application_no,
                    ethics_approval_no,
                    BatchState.DETECTED.value,
                    idempotency_key,
                    "",
                    "[]",
                    "",
                    "{}",
                    json.dumps(list(patient_ids), ensure_ascii=False),
                    json.dumps(list(material_ids), ensure_ascii=False),
                    now,
                    now,
                ),
            )
            self._connection.commit()
            self.record_transition(
                application_no,
                source_state="",
                event=BatchEvent.APPLICATION_DETECTED.value,
                target_state=BatchState.DETECTED.value,
                reason="申请单落目录，进入待校验",
            )
        else:
            if ethics_approval_no and not existing.ethics_approval_no:
                self._write(
                    application_no,
                    "ethics_approval_no = ?",
                    (ethics_approval_no,),
                )
            if idempotency_key and not existing.idempotency_key:
                self._write(application_no, "idempotency_key = ?", (idempotency_key,))
        record = self.get_batch(application_no)
        assert record is not None  # 刚建好/刚更新过
        return record

    def get_batch(self, batch_no: str) -> BatchRecord | None:
        """取批次记录；不存在返回 None。"""
        row = self._connection.execute(
            "SELECT * FROM batches WHERE batch_no = ?", (batch_no,)
        ).fetchone()
        return None if row is None else _batch_from_row(row)

    def list_batches(self, state: BatchState | str | None = None) -> list[BatchRecord]:
        """列批次（可按状态过滤），按建批时间排序。"""
        if state is None:
            rows = self._connection.execute(
                "SELECT * FROM batches ORDER BY created_at, batch_no"
            ).fetchall()
        else:
            value = state.value if isinstance(state, BatchState) else str(state)
            rows = self._connection.execute(
                "SELECT * FROM batches WHERE state = ? ORDER BY created_at, batch_no",
                (value,),
            ).fetchall()
        return [_batch_from_row(row) for row in rows]

    # ------------------------------------------------------------------ 迁移

    def advance(
        self,
        batch_no: str,
        event: BatchEvent,
        ctx: TransitionContext | None = None,
        *,
        reason: str = "",
        current_step: str | None = None,
    ) -> BatchRecord:
        """走一步状态迁移并落库。

        :param batch_no: 批次号。
        :param event: 触发事件。
        :param ctx: 守卫判定依据。
        :param reason: 这一步的原因（写进迁移流水）。
        :param current_step: 本步的步骤名（写进批次表）。
        :return: 更新后的批次记录。
        :raises IllegalTransitionError: 该状态不接受该事件 —— **状态不推进**。
        :raises TransitionRejectedError: 守卫不通过 —— **状态不推进**。
        """
        record = self.get_batch(batch_no)
        if record is None:
            raise IllegalTransitionError(f"批次不存在：{batch_no}（不得凭空迁移）")
        result = self._machine.transition(record.batch_state, event, ctx)
        self._apply_result(record, result, reason=reason, current_step=current_step)
        updated = self.get_batch(batch_no)
        assert updated is not None
        return updated

    def apply_intake(self, intake: Any) -> BatchRecord:
        """按入站结果推进批次（校验 → 放行 / 阻断）。

        :param intake: :class:`~research_redact.ingest.application.IntakeResult`。
        :return: 更新后的批次记录。
        """
        application_no = getattr(intake, "application_no", "") or ""
        ethics = getattr(intake, "ethics_approval_no", None)
        missing = tuple(getattr(intake, "missing", ()) or ())
        rows = getattr(intake, "rows", ()) or ()
        material_ids = tuple(
            getattr(row, "material_id", "") for row in rows if getattr(row, "material_id", "")
        )
        patient_ids = tuple(getattr(intake, "patient_ids", ()) or ())
        self.open_batch(
            application_no,
            ethics_approval_no=ethics,
            patient_ids=patient_ids,
            material_ids=material_ids,
        )
        event = intake_event(ethics_approval_no=ethics, missing_fields=missing)
        existing = self.get_batch(application_no)
        if (
            existing is not None
            and existing.batch_state is BatchState.BLOCKED
            and event is BatchEvent.APPLICATION_VALIDATED
        ):
            # 阻断后补齐批件号重新投递：走「补齐后重新投递」这条规定事件，
            # 不得从 blocked 直接跳到 recognized（旁路态不得被自动跳过）。
            event = BatchEvent.APPLICATION_REPAIRED
        ctx = TransitionContext(
            ethics_approval_no=ethics,
            missing_fields=missing,
            material_count=len(material_ids),
        )
        reason = (
            "；".join(missing)
            if missing
            else "申请单齐备（伦理批件号与材料清单完整）"
        )
        return self.advance(
            application_no,
            event,
            ctx,
            reason=reason,
            current_step="intake",
        )

    def apply_recognition(
        self,
        batch_no: str,
        *,
        material_count: int = 0,
        recognized_material_count: int = 0,
        patient_index_reachable: bool = True,
        reason: str = "",
    ) -> BatchRecord:
        """按识别阶段结果推进批次（代号化 / 挂起等主索引）。

        主索引不可达时批次置 ``suspended`` 并落告警 —— **不降级**为按正则直接脱。

        :param batch_no: 批次号。
        :param material_count: 本批材料总数。
        :param recognized_material_count: 已产出实体区间的材料数。
        :param patient_index_reachable: HIS 患者主索引是否可达。
        :param reason: 这一步的原因。
        """
        event = recognition_event(patient_index_reachable=patient_index_reachable)
        ctx = TransitionContext(
            material_count=material_count,
            recognized_material_count=recognized_material_count,
            patient_index_reachable=patient_index_reachable,
        )
        note = reason or (
            f"主索引不可达：批次挂起等恢复（不得按正则直接脱）"
            if not patient_index_reachable
            else f"识别覆盖 {recognized_material_count}/{material_count} 份材料"
        )
        return self.advance(
            batch_no,
            event,
            ctx,
            reason=note,
            current_step="recognize",
        )

    def _apply_result(
        self,
        record: BatchRecord,
        result: TransitionResult,
        *,
        reason: str,
        current_step: str | None,
    ) -> None:
        """把一次成功迁移落库（批次表 + 迁移流水 + 按需告警）。"""
        note = reason or result.description
        failure_states = (
            BatchState.BLOCKED,
            BatchState.SUSPENDED,
            BatchState.PENDING_DELIVERY,
            BatchState.RESTORE_REJECTED,
        )
        failure_reason = note if result.target in failure_states else ""
        self._write(
            record.batch_no,
            "state = ?, failure_reason = ?, current_step = COALESCE(?, current_step),"
            " updated_at = ?",
            (
                result.target.value,
                failure_reason,
                current_step,
                utcnow().isoformat(),
            ),
        )
        self.record_transition(
            record.batch_no,
            source_state=result.source.value if result.source else "",
            event=result.event.value,
            target_state=result.target.value,
            reason=note,
        )
        if result.target in (BatchState.BLOCKED, BatchState.SUSPENDED):
            self.record(self._build_alert(record.batch_no, result, note))

    def _build_alert(
        self, batch_no: str, result: TransitionResult, reason: str
    ) -> BatchAlert:
        """阻断 / 挂起必落一条告警（文案不含患者原文）。"""
        if result.target is BatchState.BLOCKED:
            code = "application_blocked"
            message = (
                f"批次 {batch_no} 已阻断：{reason}"
                "（不降级放行，须补齐伦理批件号与字段后重新投递）"
            )
        elif result.event is BatchEvent.INDEX_STORE_UNREACHABLE:
            code = "index_store_unreachable"
            message = (
                f"批次 {batch_no} 已挂起：{reason}"
                "（对照索引不可达，不得重建空索引放行，须待索引恢复）"
            )
        else:
            code = "patient_index_unreachable"
            message = (
                f"批次 {batch_no} 已挂起：{reason}"
                "（主索引不可达，不得按正则直接脱，须待主索引恢复）"
            )
        return BatchAlert(
            batch_no=batch_no,
            code=code,
            level="error",
            count=1,
            message=message,
            material_ids=(),
            notified=False,
            notify_channel="pending",
        )

    # ------------------------------------------------------------ 状态迁移流水

    def record_transition(
        self,
        batch_no: str,
        *,
        source_state: str,
        event: str,
        target_state: str,
        reason: str = "",
    ) -> None:
        """落一条状态迁移流水。"""
        self._connection.execute(
            "INSERT INTO batch_transitions"
            " (batch_no, source_state, event, target_state, reason, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                batch_no,
                source_state,
                event,
                target_state,
                reason,
                utcnow().isoformat(),
            ),
        )
        self._connection.commit()

    def timeline(self, batch_no: str) -> list[TransitionRecord]:
        """批次时间线：按序返回每一步迁移。"""
        rows = self._connection.execute(
            "SELECT * FROM batch_transitions WHERE batch_no = ? ORDER BY id",
            (batch_no,),
        ).fetchall()
        return [
            TransitionRecord(
                batch_no=row["batch_no"],
                source_state=row["source_state"],
                event=row["event"],
                target_state=row["target_state"],
                reason=row["reason"],
                created_at=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ 回执

    def record_receipt(
        self,
        receipt_id: str,
        batch_no: str,
        kind: str,
        payload: Mapping[str, Any] | None = None,
        *,
        platform_receipt_id: str | None = None,
    ) -> None:
        """落一条回执（交付回执 / 还原回执）。

        :param receipt_id: 回执 ID（幂等键：同一回执重复落只留一条）。
        :param batch_no: 批次号。
        :param kind: 回执类型（``delivery`` / ``restore`` …）。
        :param payload: 回执内容（**调用方自己保证已脱敏**）。
        :param platform_receipt_id: 平台侧回执 ID。
        """
        self._connection.execute(
            "INSERT OR REPLACE INTO receipts"
            " (receipt_id, batch_no, kind, payload, platform_receipt_id, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                receipt_id,
                batch_no,
                kind,
                json.dumps(dict(payload or {}), ensure_ascii=False),
                platform_receipt_id,
                utcnow().isoformat(),
            ),
        )
        self._connection.commit()

    def receipts(self, batch_no: str | None = None) -> list[ReceiptRecord]:
        """回执列表（可按批次过滤）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM receipts ORDER BY created_at, receipt_id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM receipts WHERE batch_no = ? ORDER BY created_at, receipt_id",
                (batch_no,),
            ).fetchall()
        return [_receipt_from_row(row) for row in rows]

    def get_receipt(self, receipt_id: str) -> ReceiptRecord | None:
        """按回执 ID 取回执；不存在返回 None。

        交付回执的 ID **就是幂等键** —— 幂等键已交付时，靠它复用回执，
        不再外发第二次。
        """
        row = self._connection.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        return None if row is None else _receipt_from_row(row)

    # ------------------------------------------------------------------ 留痕

    def record_access(
        self, batch_no: str, actor: str, operation: str, detail: str = ""
    ) -> None:
        """落一条访问留痕（谁、何时、对哪一批做了什么）。"""
        self._connection.execute(
            "INSERT INTO access_log"
            " (batch_no, actor, operation, detail, created_at) VALUES (?,?,?,?,?)",
            (batch_no, actor, operation, detail, utcnow().isoformat()),
        )
        self._connection.commit()

    def access_log(self, batch_no: str | None = None) -> list[AccessRecord]:
        """访问留痕列表（可按批次过滤）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM access_log ORDER BY id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM access_log WHERE batch_no = ? ORDER BY id", (batch_no,)
            ).fetchall()
        return [
            AccessRecord(
                batch_no=row["batch_no"],
                actor=row["actor"],
                operation=row["operation"],
                detail=row["detail"],
                created_at=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ 告警

    def record(self, alert: BatchAlert) -> None:
        """落一条批次告警（实现 :class:`~research_redact.audit.alerts.AlertSink`）。

        告警文案**不含命中原文** —— 与命中清单同一红线。
        """
        self._connection.execute(
            "INSERT INTO alerts"
            " (batch_no, code, level, count, message, material_ids, notified,"
            "  notify_channel, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                alert.batch_no,
                alert.code,
                alert.level,
                int(alert.count),
                alert.message,
                json.dumps(list(alert.material_ids), ensure_ascii=False),
                1 if alert.notified else 0,
                alert.notify_channel,
                alert.created_at.isoformat(),
            ),
        )
        self._connection.commit()

    def alerts(self, batch_no: str | None = None) -> list[BatchAlert]:
        """批次告警列表（可按批次过滤）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM alerts ORDER BY id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM alerts WHERE batch_no = ? ORDER BY id", (batch_no,)
            ).fetchall()
        return [
            BatchAlert(
                batch_no=row["batch_no"],
                code=row["code"],
                level=row["level"],
                count=row["count"],
                message=row["message"],
                material_ids=tuple(json.loads(row["material_ids"])),
                notified=bool(row["notified"]),
                notify_channel=row["notify_channel"],
                created_at=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ 字段

    def record_residual_summary(self, report: "ResidualReport") -> None:
        """落一条批次级残留自检摘要（实现残留摘要落点协议）。

        **通过与否都落** —— 事后要回答「这批当时到底脱干净了没有」，答案在
        这里。摘要只记计数与一句结论，**不含命中原文**（与命中清单同一红线）。
        """
        self._connection.execute(
            "INSERT INTO residual_checks"
            " (batch_no, scanned_materials, identity_count, hint_count,"
            "  suppressed, deliverable, summary, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                report.batch_no,
                json.dumps(list(report.scanned_materials), ensure_ascii=False),
                report.identity_count,
                report.hint_count,
                json.dumps(dict(report.suppressed), ensure_ascii=False),
                1 if report.deliverable else 0,
                report.summary,
                report.created_at.isoformat(),
            ),
        )
        self._connection.commit()

    def residual_summaries(
        self, batch_no: str | None = None
    ) -> list[ResidualSummaryRecord]:
        """残留自检摘要列表（可按批次过滤，按记录顺序）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM residual_checks ORDER BY id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM residual_checks WHERE batch_no = ? ORDER BY id",
                (batch_no,),
            ).fetchall()
        return [
            ResidualSummaryRecord(
                batch_no=row["batch_no"],
                scanned_materials=tuple(json.loads(row["scanned_materials"])),
                identity_count=row["identity_count"],
                hint_count=row["hint_count"],
                suppressed=json.loads(row["suppressed"]),
                deliverable=bool(row["deliverable"]),
                summary=row["summary"],
                created_at=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    def mark_residual_alert(self, batch_no: str, reason: str) -> None:
        """把批次标成**告警态**：写失败原因与当前步骤（状态不推进）。

        残留未清零的批次**不进入** ``delivered``（投递守卫会拒绝），但也不能
        悄悄停在原地让人看不出来 —— 这里把原因写进批次行，运维看台账就知道
        「这一批卡在残留自检上、卡了几处」。状态**不推进**：残留是**可修复**
        的问题（改材料重投即可），不是终态。
        """
        self._write(
            batch_no,
            "failure_reason = ?, current_step = COALESCE(?, current_step),"
            " updated_at = ?",
            (reason, "residual_check", utcnow().isoformat()),
        )

    def set_idempotency_key(self, batch_no: str, key: str) -> None:
        """写批次幂等键（唯一约束见 :meth:`claim_idempotency_key`）。"""
        self._write(batch_no, "idempotency_key = ?", (key,))

    def set_material_fingerprint(self, batch_no: str, fingerprint: str) -> None:
        """写材料集合指纹（材料变了就是新的一批，不当重复丢掉）。"""
        self._write(batch_no, "material_fingerprint = ?", (fingerprint,))

    def set_material_entries(
        self, batch_no: str, entries: Iterable[Mapping[str, Any]]
    ) -> None:
        """写交付体的材料清单（守护进程重启补投时据此重建投递载荷）。"""
        self._write(
            batch_no,
            "material_entries = ?",
            (json.dumps([dict(item) for item in entries], ensure_ascii=False),),
        )

    # ------------------------------------------------------------ 幂等键认领

    def claim_idempotency_key(
        self,
        idempotency_key: str,
        batch_no: str,
        *,
        fingerprint: str = "",
        material_ids: Sequence[str] = (),
        lease_seconds: float = IDEMPOTENCY_LEASE_SECONDS,
    ) -> IdempotencyClaim:
        """认领一把幂等键（**唯一约束落在这里**）。

        走 ``INSERT OR IGNORE``：键是主键，两个执行者同时认领同一把键，
        只有一个拿到 ``is_new=True`` —— 另一个**不得**再次外发。

        :param idempotency_key: 幂等键（申请单号 + 材料集合指纹）。
        :param batch_no: 认领的批次号。
        :param fingerprint: 材料集合指纹（留档，便于事后核「这批交的是哪批材料」）。
        :param material_ids: 本批材料 ID。
        :param lease_seconds: 认领租约：认领后超过这个时长还没交付，视为上次
            执行者已经不在了，下一个执行者可以接管（否则崩溃留下的认领会
            永远挡住重投）。
        :return: 认领结果（记录 + 是不是首次认领）。
        """
        key = str(idempotency_key or "").strip()
        if not key:
            raise IllegalTransitionError("幂等键为空：不得认领（无法判定重复）")
        now = utcnow()
        cursor = self._connection.execute(
            "INSERT OR IGNORE INTO idempotency_keys"
            " (idempotency_key, batch_no, fingerprint, material_ids, state,"
            "  dataset_id, receipt_id, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                key,
                batch_no,
                fingerprint,
                json.dumps(list(material_ids), ensure_ascii=False),
                IDEMPOTENCY_CLAIMED,
                "",
                "",
                now.isoformat(),
                now.isoformat(),
            ),
        )
        self._connection.commit()
        inserted = cursor.rowcount > 0
        record = self.get_idempotency_key(key)
        if record is None:  # pragma: no cover - 刚写入必然读得到
            raise IllegalTransitionError(f"幂等键认领落库失败：{key}")
        if inserted:
            # 首次认领 —— 调用方据此认定「这一次就是唯一一次外发」。
            return IdempotencyClaim(record=record, is_new=True)
        if record.state == IDEMPOTENCY_DELIVERED:
            # 已交付：不是首次认领，调用方复用已有回执即可。
            return IdempotencyClaim(record=record, is_new=False)
        age = (now - record.updated_at).total_seconds()
        if age > lease_seconds:
            # 陈旧认领（上次执行者崩了）→ 接管，把租约刷新。
            self._connection.execute(
                "UPDATE idempotency_keys SET batch_no = ?, fingerprint = ?,"
                " material_ids = ?, updated_at = ?"
                " WHERE idempotency_key = ? AND state != ?",
                (
                    batch_no,
                    fingerprint,
                    json.dumps(list(material_ids), ensure_ascii=False),
                    now.isoformat(),
                    key,
                    IDEMPOTENCY_DELIVERED,
                ),
            )
            self._connection.commit()
            refreshed = self.get_idempotency_key(key)
            if refreshed is not None:
                record = refreshed
            return IdempotencyClaim(record=record, is_new=True)
        return IdempotencyClaim(record=record, is_new=False)

    def get_idempotency_key(self, idempotency_key: str) -> IdempotencyRecord | None:
        """取幂等键认领记录；不存在返回 None。"""
        row = self._connection.execute(
            "SELECT * FROM idempotency_keys WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        return None if row is None else _idempotency_from_row(row)

    def idempotency_keys(self, batch_no: str | None = None) -> list[IdempotencyRecord]:
        """幂等认领记录列表（可按批次过滤，按认领顺序）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM idempotency_keys ORDER BY created_at, idempotency_key"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM idempotency_keys WHERE batch_no = ?"
                " ORDER BY created_at, idempotency_key",
                (batch_no,),
            ).fetchall()
        return [_idempotency_from_row(row) for row in rows]

    def mark_idempotency_delivered(
        self, idempotency_key: str, *, dataset_id: str = "", receipt_id: str = ""
    ) -> None:
        """把一把幂等键标成已交付（平台回了回执）。

        标了之后，任何一次重投都只会**复用**这份回执，不会再外发一次。
        """
        self._connection.execute(
            "UPDATE idempotency_keys SET state = ?, dataset_id = ?, receipt_id = ?,"
            " updated_at = ? WHERE idempotency_key = ?",
            (
                IDEMPOTENCY_DELIVERED,
                dataset_id,
                receipt_id,
                utcnow().isoformat(),
                idempotency_key,
            ),
        )
        self._connection.commit()

    def release_idempotency_key(self, idempotency_key: str) -> None:
        """释放一把幂等键（本次交付失败，让下一次能重新认领）。

        **只释放未交付的** —— 已交付的键不能释放（释放了就会再交一次）。
        """
        self._connection.execute(
            "DELETE FROM idempotency_keys WHERE idempotency_key = ? AND state != ?",
            (idempotency_key, IDEMPOTENCY_DELIVERED),
        )
        self._connection.commit()

    def find_batch_by_idempotency_key(self, idempotency_key: str) -> BatchRecord | None:
        """按幂等键找批次（键变了 → 是新的一批，不是同一批）。"""
        row = self._connection.execute(
            "SELECT * FROM batches WHERE idempotency_key = ? ORDER BY updated_at DESC",
            (idempotency_key,),
        ).fetchone()
        return None if row is None else _batch_from_row(row)

    def set_artifacts(self, batch_no: str, artifacts: Mapping[str, str]) -> None:
        """写产物路径（脱敏副本 / 命中清单 / 平台数据集 …）。"""
        self._write(
            batch_no,
            "artifacts = ?",
            (json.dumps(dict(artifacts), ensure_ascii=False),),
        )

    def set_current_step(self, batch_no: str, step: str) -> None:
        """写当前步骤。"""
        self._write(batch_no, "current_step = ?", (step,))

    # ------------------------------------------------------- 策略快照（可复现）

    def set_policy_version(self, batch_no: str, version: str) -> None:
        """写本批用的策略表版本号（task 36）。

        版本号跟着批次走：事后问「这批是哪一版策略脱的」，台账里就有答案，
        不必去翻快照目录。
        """
        self._write(batch_no, "policy_version = ?", (version,))

    def record_policy_snapshot(
        self,
        batch_no: str,
        *,
        policy_version: str,
        policy_sha256: str = "",
        profile: str = "",
        source: str = "",
        source_sha256: str = "",
        snapshot_dir: str = "",
        policy_path: str = "",
    ) -> PolicySnapshotRecord:
        """登记一批的策略快照（**一批一条**，重投覆盖同一行）。

        表里只存**标识与路径**：配置正文在快照目录的 ``policy.yaml`` 里，
        密钥永远不进台账。
        """
        now = utcnow().isoformat()
        self._connection.execute(
            "INSERT OR REPLACE INTO policy_snapshots"
            " (batch_no, policy_version, policy_sha256, profile, source,"
            "  source_sha256, snapshot_dir, policy_path, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                batch_no,
                policy_version,
                policy_sha256,
                profile,
                source,
                source_sha256,
                snapshot_dir,
                policy_path,
                now,
            ),
        )
        self._connection.commit()
        record = self.policy_snapshot(batch_no)
        assert record is not None  # 刚写进去的
        return record

    def policy_snapshot(self, batch_no: str) -> PolicySnapshotRecord | None:
        """取某批的策略快照登记；没有返回 None。"""
        row = self._connection.execute(
            "SELECT * FROM policy_snapshots WHERE batch_no = ?", (batch_no,)
        ).fetchone()
        return None if row is None else _policy_snapshot_from_row(row)

    def policy_snapshots(
        self, batch_no: str | None = None
    ) -> list[PolicySnapshotRecord]:
        """列出策略快照登记（按批次号排序）。"""
        if batch_no is None:
            rows = self._connection.execute(
                "SELECT * FROM policy_snapshots ORDER BY batch_no"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM policy_snapshots WHERE batch_no = ? ORDER BY batch_no",
                (batch_no,),
            ).fetchall()
        return [_policy_snapshot_from_row(row) for row in rows]

    def complete_step(self, batch_no: str, step: str) -> None:
        """把一步记进「已完成步骤」（断点续跑用，task 34 消费）。"""
        record = self.get_batch(batch_no)
        if record is None:
            raise IllegalTransitionError(f"批次不存在：{batch_no}")
        completed = list(record.completed_steps)
        if step not in completed:
            completed.append(step)
        self._write(
            batch_no,
            "completed_steps = ?",
            (json.dumps(completed, ensure_ascii=False),),
        )

    # ------------------------------------------------------- 命中清单（重放防护）

    def record_manifest_entries(
        self,
        batch_no: str,
        scope: str,
        entries: Iterable[Mapping[str, Any]],
    ) -> int:
        """追加写入命中清单条目（**重放防护**：同一条只记一次）。

        唯一约束落在数据库上：``(批次, 范围, 材料 ID, 起点, 实体类别)``。
        同一批材料被重放处理（守护进程与运维 CLI 同时触发、进程重启后补投、
        兜底扫描再扫一遍）时，重复的条目**写不进去** —— 清单不会翻倍，
        交差时数不清的「同一处命中」也就不会出现。

        :param batch_no: 批次号（申请单号）。
        :param scope: 批次身份范围（材料集合指纹）—— 材料集合变了就是新的一批，
            新的一批有自己的清单，不被旧范围的记录挡住。
        :param entries: 命中条目（字段与清单一致，**不含命中原文**）。
        :return: 实际**新写入**的条数（被去重挡掉的条数不计入）。
        """
        now = utcnow().isoformat()
        inserted = 0
        for entry in entries:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO manifest_entries"
                " (batch_no, scope, material_id, label, span_start, span_end,"
                "  score, tier, action, reason, recognizer, merged_duplicates,"
                "  created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_no,
                    scope,
                    str(entry.get("material_id", "")),
                    str(entry.get("label", "")),
                    int(entry.get("start", 0) or 0),
                    int(entry.get("end", 0) or 0),
                    float(entry.get("score", 0.0) or 0.0),
                    str(entry.get("tier", "")),
                    str(entry.get("action", "")),
                    str(entry.get("reason", "")),
                    str(entry.get("recognizer", "")),
                    json.dumps(list(entry.get("merged_duplicates") or []), ensure_ascii=False),
                    now,
                ),
            )
            inserted += 1 if cursor.rowcount > 0 else 0
        self._connection.commit()
        return inserted

    def manifest_entries(
        self, batch_no: str, scope: str = ""
    ) -> list[dict[str, Any]]:
        """读回该批次（该范围）的命中清单条目（按写入顺序）。

        :param batch_no: 批次号。
        :param scope: 批次身份范围；缺省读该批次的全部范围。
        """
        if scope:
            rows = self._connection.execute(
                "SELECT * FROM manifest_entries WHERE batch_no = ? AND scope = ?"
                " ORDER BY id",
                (batch_no, scope),
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM manifest_entries WHERE batch_no = ? ORDER BY id",
                (batch_no,),
            ).fetchall()
        return [
            {
                "material_id": str(row["material_id"]),
                "label": str(row["label"]),
                "start": int(row["span_start"]),
                "end": int(row["span_end"]),
                "score": float(row["score"]),
                "tier": str(row["tier"]),
                "action": str(row["action"]),
                "reason": str(row["reason"]),
                "recognizer": str(row["recognizer"]),
                "merged_duplicates": json.loads(row["merged_duplicates"]),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------ 内部

    def _write(self, batch_no: str, clause: str, params: Sequence[Any]) -> None:
        """更新批次表的一组字段。"""
        self._connection.execute(
            f"UPDATE batches SET {clause} WHERE batch_no = ?",  # noqa: S608 - 片段固定
            (*params, batch_no),
        )
        self._connection.commit()


# --------------------------------------------------------------------- 工具


def _batch_from_row(row: sqlite3.Row) -> BatchRecord:
    """台账行 → :class:`BatchRecord`。"""
    columns = set(row.keys())
    return BatchRecord(
        batch_no=row["batch_no"],
        ethics_approval_no=row["ethics_approval_no"],
        state=row["state"],
        idempotency_key=row["idempotency_key"],
        current_step=row["current_step"],
        completed_steps=tuple(json.loads(row["completed_steps"])),
        failure_reason=row["failure_reason"],
        artifacts=json.loads(row["artifacts"]),
        patient_ids=tuple(json.loads(row["patient_ids"])),
        material_ids=tuple(json.loads(row["material_ids"])),
        material_fingerprint=row["material_fingerprint"],
        material_entries=tuple(json.loads(row["material_entries"])),
        policy_version=str(row["policy_version"]) if "policy_version" in columns else "",
        created_at=_parse_dt(row["created_at"]),
        updated_at=_parse_dt(row["updated_at"]),
    )


def _policy_snapshot_from_row(row: sqlite3.Row) -> PolicySnapshotRecord:
    """策略快照登记行 → :class:`PolicySnapshotRecord`。"""
    return PolicySnapshotRecord(
        batch_no=row["batch_no"],
        policy_version=row["policy_version"],
        policy_sha256=row["policy_sha256"],
        profile=row["profile"],
        source=row["source"],
        source_sha256=row["source_sha256"],
        snapshot_dir=row["snapshot_dir"],
        policy_path=row["policy_path"],
        created_at=_parse_dt(row["created_at"]),
    )


def _receipt_from_row(row: sqlite3.Row) -> ReceiptRecord:
    """回执行 → :class:`ReceiptRecord`。"""
    return ReceiptRecord(
        receipt_id=row["receipt_id"],
        batch_no=row["batch_no"],
        kind=row["kind"],
        payload=json.loads(row["payload"]),
        platform_receipt_id=row["platform_receipt_id"],
        created_at=_parse_dt(row["created_at"]),
    )


def _idempotency_from_row(row: sqlite3.Row) -> IdempotencyRecord:
    """幂等认领行 → :class:`IdempotencyRecord`。"""
    return IdempotencyRecord(
        idempotency_key=row["idempotency_key"],
        batch_no=row["batch_no"],
        fingerprint=row["fingerprint"],
        material_ids=tuple(json.loads(row["material_ids"])),
        state=row["state"],
        dataset_id=row["dataset_id"],
        receipt_id=row["receipt_id"],
        created_at=_parse_dt(row["created_at"]),
        updated_at=_parse_dt(row["updated_at"]),
    )


def _parse_dt(value: str) -> datetime:
    """ISO 字符串 → datetime（解析不了就退回 epoch，绝不让台账读不出来）。"""
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0)
