"""脱敏主路径：识别 → 处置 → 逐处命中清单。

**全项目只有这一处主路径**：运维 CLI（``research_redact.cli``）与守护进程
（``research_redact.daemon``，task 11 接入）都调它，不各写一份处理逻辑。

对应源产品 CLI 的主路径 ``presidio_cli/cli.py::run``（读文件 → 分析 →
按格式输出），改写为医院场景的批次级产物：**材料正文 → 脱敏副本 + 逐处命中
清单**，两份产物都可核对。

本任务（task 3）落的是**最窄一条**：单份文本材料 → 脱敏副本 + JSONL 清单。
批次状态机（task 10）、残留自检（task 9）、幂等与续跑（task 33 / 34）
都在这条主路径之上叠加，不改这里的处理逻辑。

处置策略由**策略表**接管（task 6）：``policy/research.yaml`` 的「实体类别 →
处置动作」段决定每个类别怎么改写，动作怎么执行由 ``policy/operators.py``
的动作注册表负责。一致代号（hmac_pseudonym）是已登记的预留挂载位，实现由
task 24 落地；引用了却没落地时**报错中止**，绝不静默退回「保留原文」。

两段命中互相重叠时，由 ``policy/conflicts.py`` 裁决（task 7）：同一段正文
只由一处负责改写，被裁掉的一方记入命中清单（**不记原文**）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ..audit.manifest import (
    ManifestEntry,
    ManifestWriter,
    entry_from_dropped,
    entry_from_span,
    scan_for_raw_text,
)
from ..ingest.application import ApplicationRow, BlockedApplicationError, IntakeResult
from ..ingest.columns import ColumnPolicy, ColumnRole
from ..models import EntitySpan, SpanTier
from ..arbitration import arbitrate
from ..policy.conflicts import ConflictRules, load_conflict_rules
from ..policy.operators import (
    ActionSpec,
    Operator,
    OperatorContext,
    OperatorRegistry,
    default_operator_registry,
)
from ..audit.alerts import BatchAlert, JsonlAlertSink
from ..audit.residual import ResidualBlockedError, ResidualChecker, ResidualReport
from ..policy.table import UndeclaredEntityError, load_policy_table
from ..recognizers.assembly import build_default_registry
from ..recognizers.registry import RecognizerRegistry, RegistryConfig

__all__ = [
    "ActionSpec",
    "ApplicationRedaction",
    "BatchRedaction",
    "RedactOutcome",
    "ResidualBlockedError",
    "RowRedaction",
    "build_default_registry",
    "default_action_resolver",
    "default_operator_registry",
    "ensure_deliverable",
    "redact_application",
    "redact_batch",
    "redact_file",
    "redact_rows",
    "redact_text",
]


#: 只有确认档（分数达到阈值）才改写文本。告警档是「不敢确定」，
#: 改写会脱过头，不改写会漏脱 —— 两者都留痕：告警档只进清单不改文本，
#: 由 task 9 的残留自检二次扫描兜底。
REDACTED_TIERS = (SpanTier.CONFIRMED,)

#: 命中原文长度达到该值才做运行时泄漏检查（短姓名容易与正文巧合重复，
#: 误报会中断批次；短片段由结构性保证 + 测试守卫覆盖）。
RAW_TEXT_GUARD_MIN_LENGTH = 6


def default_action_resolver(label: str) -> ActionSpec:
    """按策略表给出实体类别的处置动作。

    :raises UndeclaredEntityError: 该类别未在策略表声明 —— 由调用方记为
        「保留原文（策略表未声明）」并留痕，既不默认脱掉也不默认放过。
    """
    return load_policy_table().action_for(label)


@dataclass(frozen=True)
class RedactOutcome:
    """一次脱敏的结果。

    :param material_id: 材料 ID（写进清单每一行）。
    :param redacted_text: 脱敏后的正文。
    :param entries: 逐处命中清单（不含命中原文）。
    :param counts: 按档位统计（``confirmed`` / ``warning`` / ``allowed``）。
    :param rewritten: 实际改写文本的命中条数。
    """

    material_id: str
    redacted_text: str
    entries: tuple[ManifestEntry, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    rewritten: int = 0


def redact_text(
    text: str,
    material_id: str,
    registry: RecognizerRegistry | None = None,
    actions: Callable[[str], ActionSpec] | None = None,
    operators: OperatorRegistry | None = None,
    rules: ConflictRules | None = None,
) -> RedactOutcome:
    """对一段正文跑一次脱敏。

    :param text: 材料正文。
    :param material_id: 材料 ID，写进清单每一行。
    :param registry: 识别器注册表；缺省用 :func:`build_default_registry`。
    :param actions: 实体类别 → 处置动作的解析函数；缺省按策略表
        （``policy/research.yaml``）解析。
    :param operators: 动作注册表（动作怎么执行）；缺省用内置的三种动作。
    :param rules: 冲突裁决规则；缺省从策略表装载。
    :return: 脱敏正文 + 逐处命中清单 + 统计。
    :raises OperatorUnavailableError: 策略表声明的动作尚未落地（预留挂载位）——
        此时中止，不静默退回「保留原文」。
    """
    registry = registry or build_default_registry()
    resolver = actions or default_action_resolver
    operator_registry = operators or default_operator_registry()
    _reset_mapping_scope(operator_registry, material_id)
    spans = registry.analyze(text)

    entries: list[tuple[int, int, ManifestEntry]] = []
    plan: list[tuple[EntitySpan, ActionSpec, Operator]] = []
    rewrite_spans: list[EntitySpan] = []

    for span in spans:
        if span.is_allowed:
            entries.append(
                (span.start, span.end, entry_from_span(material_id, span, "keep（白名单放行）"))
            )
            continue
        if span.tier not in REDACTED_TIERS:
            entries.append(
                (span.start, span.end, entry_from_span(material_id, span, "none（告警档，未改写）"))
            )
            continue
        try:
            action = resolver(span.label)
        except UndeclaredEntityError:
            # 策略表没声明这个类别：保留原文，但在清单里留痕 ——
            # 宁可让人看见「这里没脱」，也不默认脱掉或默认放过。
            entries.append(
                (
                    span.start,
                    span.end,
                    entry_from_span(material_id, span, "keep（策略表未声明该类别）"),
                )
            )
            continue
        # 动作未落地（预留挂载位）在这里报错中止，不静默降级
        operator_registry.get(action.action)
        if action.action == "keep":
            entries.append((span.start, span.end, entry_from_span(material_id, span, "keep")))
            continue
        # 会改写正文的区间才参与冲突裁决：白名单放行与告警档不改写正文，
        # 不该影响别人的边界。
        rewrite_spans.append(span)

    # 统一裁决：同一段正文只由一处负责改写（research_redact/arbitration.py）
    # —— 重叠 / 包含 / 交叉 / 完全重合一处定案，规则固定为
    # 档位优先 > 同级比分数 > 解释更完整者胜 > 同类先合并。
    resolution = arbitrate(
        rewrite_spans,
        text=text,
        rules=rules if rules is not None else load_conflict_rules(),
    )
    for span in resolution.kept:
        action = resolver(span.label)
        operator = operator_registry.get(action.action)
        entries.append(
            (
                span.start,
                span.end,
                _with_fold_note(entry_from_span(material_id, span, action.action)),
            )
        )
        plan.append((span, action, operator))
    for dropped in resolution.dropped:
        entries.append(
            (dropped.start, dropped.end, entry_from_dropped(material_id, dropped))
        )

    entries.sort(key=lambda item: (item[0], item[1]))
    ordered_entries = tuple(item[2] for item in entries)

    redacted = _apply_plan(text, plan, material_id)
    counts = {
        "confirmed": sum(
            1 for entry in ordered_entries if entry.tier == SpanTier.CONFIRMED.value
        ),
        "warning": sum(
            1 for entry in ordered_entries if entry.tier == SpanTier.WARNING.value
        ),
        "allowed": sum(
            1 for entry in ordered_entries if entry.tier == SpanTier.ALLOWED.value
        ),
    }
    return RedactOutcome(
        material_id=material_id,
        redacted_text=redacted,
        entries=ordered_entries,
        counts=counts,
        rewritten=len(plan),
    )


def redact_file(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    material_id: str | None = None,
    registry: RecognizerRegistry | None = None,
    actions: Callable[[str], ActionSpec] | None = None,
    operators: OperatorRegistry | None = None,
    rules: ConflictRules | None = None,
) -> RedactOutcome:
    """对一份材料文件跑脱敏，落脱敏副本与逐处命中清单。

    :param input_path: 材料路径（UTF-8 文本）。
    :param output_path: 脱敏副本输出路径。
    :param manifest_path: 命中清单输出路径（JSONL）。
    :param material_id: 材料 ID；缺省取输入文件名（不含后缀）。
    :param registry: 识别器注册表；缺省用 :func:`build_default_registry`。
    :param actions: 实体类别 → 处置动作的解析函数；缺省按策略表解析。
    :param operators: 动作注册表；缺省用内置的三种动作。
    :param rules: 冲突裁决规则；缺省从策略表装载。
    """
    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(f"材料文件不存在：{source}")
    material = material_id or source.stem
    text = source.read_text(encoding="utf-8")

    active_registry = registry or build_default_registry()
    outcome = redact_text(
        text,
        material,
        registry=active_registry,
        actions=actions,
        operators=operators,
        rules=rules,
    )

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(outcome.redacted_text, encoding="utf-8")

    ManifestWriter(manifest_path).write(outcome.entries)
    _guard_no_raw_text(text, outcome, active_registry.boost_terms)
    return outcome


# ------------------------------------------------------- 列级批处理（结构化材料）


@dataclass(frozen=True)
class RowRedaction:
    """一行的列级脱敏结果。

    :param material_id: 材料 ID。
    :param columns: 脱敏后的列值（业务列 / 绑定列逐字保留）。
    :param entries: 本行的逐处命中清单（不含命中原文）。
    :param skipped: 跳过的列名（业务列 + 绑定列）。
    :param scanned: 扫描过的内容列名。
    """

    material_id: str
    columns: Mapping[str, str] = field(default_factory=dict)
    entries: tuple[ManifestEntry, ...] = ()
    skipped: tuple[str, ...] = ()
    scanned: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApplicationRedaction:
    """一份申请单（多行）的列级脱敏结果。"""

    application_no: str = ""
    rows: tuple[RowRedaction, ...] = ()
    entries: tuple[ManifestEntry, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    skipped_columns: tuple[str, ...] = ()


def redact_rows(
    rows: Sequence[ApplicationRow],
    policy: ColumnPolicy,
    registry: RecognizerRegistry | None = None,
    actions: Callable[[str], ActionSpec] | None = None,
    operators: OperatorRegistry | None = None,
    rules: ConflictRules | None = None,
) -> tuple[RowRedaction, ...]:
    """按列策略处理一组行（结构化材料的列级批处理）。

    对应源产品 ``batch_analyzer_engine.py::BatchAnalyzerEngine.analyze_dict``
    的 ``keys_to_skip`` 机制（保留）：**按列**决定要不要识别，而不是整份文档
    一刀切。

    - **业务列**（申请单号 / 伦理批件号 / 材料 ID / 类型 / 路径 / 材料技术
      内容列）—— 逐字保留：交付回执按申请单号与平台台账对账，脱掉它等于
      这一批「谁都对不上」。
    - **绑定列**（患者主索引主键）—— 不由通用正则改写：身份锚定走 HIS 主
      索引读回的权威名单（task 17），一致代号（task 24）也建在它上面。
    - **内容列** —— 按列扫描脱敏，走的仍是 :func:`redact_text` 这一条主路径。

    命中清单里的 ``material_id`` 记成 ``<材料 ID>#<列名>``：同一份材料的
    不同列是不同位置，只靠材料 ID + 偏移量区分不开（两列都从第 0 个字符
    开始）。

    :param rows: 归一化后的行。
    :param policy: 列角色判定表。
    :param registry: 识别器注册表；缺省用 :func:`build_default_registry`。
    :param actions: 实体类别 → 处置动作的解析函数；缺省按策略表解析。
    :param operators: 动作注册表；缺省用内置的三种动作。
    :param rules: 冲突裁决规则；缺省从策略表装载。
    """
    active_registry = registry or build_default_registry()
    resolver = actions or default_action_resolver
    operator_registry = operators or default_operator_registry()

    results: list[RowRedaction] = []
    for row in rows:
        columns: dict[str, str] = {}
        entries: list[ManifestEntry] = []
        skipped: list[str] = []
        scanned: list[str] = []
        for name, value in row.columns.items():
            role = policy.classify(name)
            if role in (ColumnRole.BUSINESS, ColumnRole.BOUND):
                columns[name] = value
                skipped.append(name)
                continue
            scanned.append(name)
            if not value.strip():
                columns[name] = value
                continue
            outcome = redact_text(
                value,
                f"{row.material_id}#{name}",
                registry=active_registry,
                actions=resolver,
                operators=operator_registry,
                rules=rules,
            )
            columns[name] = outcome.redacted_text
            entries.extend(outcome.entries)
        results.append(
            RowRedaction(
                material_id=row.material_id,
                columns=columns,
                entries=tuple(entries),
                skipped=tuple(skipped),
                scanned=tuple(scanned),
            )
        )
    return tuple(results)


def redact_application(
    intake: IntakeResult,
    policy: ColumnPolicy,
    registry: RecognizerRegistry | None = None,
    actions: Callable[[str], ActionSpec] | None = None,
    operators: OperatorRegistry | None = None,
    rules: ConflictRules | None = None,
) -> ApplicationRedaction:
    """对一份申请单做列级批处理，产出逐行脱敏结果与整批命中清单。

    :param intake: 入站结果（:func:`research_redact.ingest.application.load_application`）。
    :param policy: 列角色判定表。
    :raises BlockedApplicationError: 申请单被阻断（缺伦理批件号 / 字段缺失）——
        **不降级放行**：没有授权范围的批次不脱也不交。
    """
    if intake.is_blocked:
        raise BlockedApplicationError(
            f"申请单被阻断，不得进入脱敏：{intake.missing_summary}"
            f"（{'；'.join(intake.alerts)}）"
        )

    rows = redact_rows(
        intake.rows,
        policy,
        registry=registry,
        actions=actions,
        operators=operators,
        rules=rules,
    )
    entries = tuple(entry for row in rows for entry in row.entries)
    skipped_columns = tuple(
        dict.fromkeys(name for row in rows for name in row.skipped)
    )
    counts = {
        "confirmed": sum(1 for entry in entries if entry.tier == SpanTier.CONFIRMED.value),
        "warning": sum(1 for entry in entries if entry.tier == SpanTier.WARNING.value),
        "allowed": sum(1 for entry in entries if entry.tier == SpanTier.ALLOWED.value),
    }
    return ApplicationRedaction(
        application_no=intake.application_no,
        rows=rows,
        entries=entries,
        counts=counts,
        skipped_columns=skipped_columns,
    )


# ----------------------------------------------------------------- 批次级主路径


@dataclass(frozen=True)
class BatchRedaction:
    """一个批次的脱敏结果 + 残留自检结论。

    :param batch_no: 批次号（申请单号）。
    :param outcomes: 每份材料的脱敏结果。
    :param residual: 批次级残留自检结论。
    :param alert: 残留未通过时落下的那条批次告警（通过时为 None）。
    """

    batch_no: str
    outcomes: tuple[RedactOutcome, ...] = ()
    residual: ResidualReport | None = None
    alert: BatchAlert | None = None

    @property
    def deliverable(self) -> bool:
        """该批次可否进入 ``delivered``：残留自检通过才放行。"""
        return self.residual is not None and self.residual.deliverable

    @property
    def redacted_texts(self) -> dict[str, str]:
        """材料 ID → 脱敏后的正文（供残留自检与后续投递使用）。"""
        return {outcome.material_id: outcome.redacted_text for outcome in self.outcomes}


def redact_batch(
    batch_no: str,
    materials: Mapping[str, str],
    checker: ResidualChecker | None = None,
    registry: RecognizerRegistry | None = None,
    actions: Callable[[str], ActionSpec] | None = None,
    operators: OperatorRegistry | None = None,
    rules: ConflictRules | None = None,
) -> BatchRedaction:
    """对一批材料跑脱敏，并做批次级残留自检。

    这是「识别 → 处置 → 清单 → **残留自检**」的批次级主路径：守护进程
    （task 11）与运维 CLI（task 39）都调它。残留自检未通过时，批次**不得**
    进入 ``delivered``（:attr:`BatchRedaction.deliverable` 为 False），并已落下
    一条批次告警。

    :param batch_no: 批次号（申请单号）。
    :param materials: 材料 ID → 材料正文。
    :param checker: 残留自检器；缺省按默认装配新建（告警落项目内
        ``var/alerts.jsonl``）。
    :param registry: 识别器注册表；缺省用 :func:`build_default_registry`。
    :param actions: 实体类别 → 处置动作的解析函数；缺省按策略表解析。
    :param operators: 动作注册表；缺省用内置的三种动作。
    :param rules: 冲突裁决规则；缺省从策略表装载。
    """
    active_registry = registry or build_default_registry()
    resolver = actions or default_action_resolver
    operator_registry = operators or default_operator_registry()

    outcomes = tuple(
        redact_text(
            text,
            material_id,
            registry=active_registry,
            actions=resolver,
            operators=operator_registry,
            rules=rules,
        )
        for material_id, text in materials.items()
    )
    redacted = {outcome.material_id: outcome.redacted_text for outcome in outcomes}

    active_checker = checker if checker is not None else ResidualChecker(
        registry=active_registry,
        sink=JsonlAlertSink(),
    )
    report = active_checker.check_batch(batch_no, redacted)
    return BatchRedaction(
        batch_no=batch_no,
        outcomes=outcomes,
        residual=report,
        alert=active_checker.last_alert,
    )


def ensure_deliverable(batch: BatchRedaction) -> None:
    """投递前的闸门：残留自检未通过的批次不得进入 ``delivered``。

    :raises ResidualBlockedError: 批次有身份类残留。
    """
    if not batch.deliverable:
        summary = batch.residual.summary if batch.residual else "残留自检未通过"
        raise ResidualBlockedError(
            f"{summary} —— 该批次不得进入 delivered，请人工核对脱敏副本后重新处理"
        )


# --------------------------------------------------------------------- 内部实现


def _overlaps(span: EntitySpan, occupied: Sequence[tuple[int, int]]) -> bool:
    """区间是否与已改写过的区间重叠。

    正式的冲突区间合并与裁剪由 ``policy/conflicts.py`` 接管（同一段只替换一次、
    被裁剪方留痕）；本函数只作兜底断言用：主路径产出的计划本就不该重叠，
    真重叠了说明裁决环节出了问题，宁可报错也不要悄悄替换两次。
    """
    return any(span.start < end and start < span.end for start, end in occupied)


def _with_fold_note(entry: ManifestEntry) -> ManifestEntry:
    """折叠掉的同类重复命中写进清单解释。

    同段、同一实体类别被两个识别器各命中一次时，注册表折叠掉一份 —— 被折叠
    的那一条要看得见（类别 + 识别器 + 原因），否则清单里少一行就分不清是
    「没命中」还是「命中了但折叠了」。只写类别与识别器，不含命中原文。
    """
    if not entry.merged_duplicates:
        return entry
    tags = "、".join(entry.merged_duplicates)
    return replace(
        entry,
        reason=(
            f"{entry.reason}；同段另有同类别命中（{tags}）已折叠，"
            "按统一裁决保留解释更完整者"
        ),
    )


def _apply_plan(
    text: str,
    plan: Sequence[tuple[EntitySpan, ActionSpec, Operator]],
    material_id: str = "",
) -> str:
    """按替换计划拼出脱敏正文（改写由动作实现负责）。

    **不变量**：计划按起点排序且互不重叠 —— 同一段正文最多被改写一次。
    计划由 ``policy/conflicts.py`` 的冲突裁决产出，这里再兜一道断言：
    真出现重叠就报错中止，不产出「同一段两个占位符」的副本。

    计划按起点排序 ⇒ 一致代号的对照登记顺序即正文出现顺序 —— 还原侧按同样
    的次序取回才对得上位置。
    """
    pieces: list[str] = []
    cursor = 0
    for span, action, operator in plan:
        if span.start < cursor:
            raise RuntimeError(
                f"替换计划出现重叠区间：{span.label} [{span.start}, {span.end})"
                f" 与前一处重叠 —— 同一段正文不得被改写两次"
            )
        pieces.append(text[cursor : span.start])
        pieces.append(
            operator.apply(
                text[span.start : span.end],
                OperatorContext(
                    label=span.label,
                    placeholder=action.placeholder,
                    # 身份键（患者主索引主键）：名单形态识别器绑定的归属。
                    # 一致代号按它取值 —— 同一患者跨材料恒等，靠的就是这个键。
                    entity_id=str(span.metadata.get("patient_id", "") or ""),
                    # 材料 ID：一致代号据此把对照登记到本材料的槽位。
                    material_id=material_id,
                ),
            )
        )
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _reset_mapping_scope(operator_registry: OperatorRegistry, material_id: str) -> None:
    """清空本材料在对照索引里的旧槽位。

    同一份材料重新脱敏（补齐材料后重投）时，上一轮登记的旧原文必须清掉 ——
    否则还原时按次序取到的是过期的那一份。索引没装配时无事可做。
    """
    index = getattr(operator_registry, "mapping_index", None)
    reset = getattr(index, "reset_material", None)
    if reset is None:
        return
    reset(material_id)


def _guard_no_raw_text(
    source: str, outcome: RedactOutcome, policy_words: Sequence[str] = ()
) -> None:
    """落盘后的最后一道闸：命中原文不得出现在清单里。

    只检查长度达标的命中片段（号码 / 证件号等），短姓名靠结构性保证
    （清单字段封闭、解释不含原文）与测试守卫覆盖。

    :param policy_words: 上下文词表（策略表里的公共词）。上下文词会原样写进
        命中解释，本身不是患者数据；命中原文恰好等于某个公共词时按公共词处理，
        免得把公共词误判成泄漏。
    """
    vocabulary = set(policy_words)
    secrets = [
        source[entry.start : entry.end]
        for entry in outcome.entries
        if entry.tier == SpanTier.CONFIRMED.value
        and (entry.end - entry.start) >= RAW_TEXT_GUARD_MIN_LENGTH
        and source[entry.start : entry.end] not in vocabulary
    ]
    payload = "\n".join(entry.reason for entry in outcome.entries)
    leaked = scan_for_raw_text(payload, secrets)
    if leaked:
        raise RuntimeError(f"命中清单疑似混入命中原文：{len(leaked)} 处")
