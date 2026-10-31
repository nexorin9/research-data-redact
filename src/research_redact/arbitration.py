"""统一裁决：跨识别器的重叠 / 包含 / 交叉 / 完全重合 —— 一处定案。

源产品把「同一段正文归谁管」分成两处：

- ``presidio-analyzer/presidio_analyzer/analyzer_engine.py`` →
  ``EntityRecognizer.remove_duplicates``：只处理**完全重合**的同一段命中，
  按分数留一条、其余丢弃；
- ``presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py`` →
  ``_remove_conflicts_and_get_text_manipulation_data``：处理部分重叠 / 包含 /
  交叉，按分数决定谁让谁。

两处各有一套取舍，本轮合并为**一处统一裁决**（:func:`arbitrate`），四条规则
固定、顺序固定：

1. **档位优先** —— 身份类 > 就诊编号类 > 通用数字类（档位取自策略表
   ``conflicts.priority``）；
2. **同级比分数** —— 同档时分数高者胜；
3. **解释更完整者胜** —— 档位与分数都相同时保留解释更完整的一条
   （解释更完整 = 命中依据说明得更细，抽检时看得出凭什么判它）；
4. **同类先合并** —— 同类命中重叠或只隔空白时合成一段，一次改写覆盖两处。

**为什么档位必须排在分数前面**：源产品按分数决定谁让谁，但「分数高」不等于
「该优先脱」。住院号识别器命中 0.95 分、身份证识别器命中同一段 0.60 分时，
按分数会让**身份类输给就诊编号类** —— 这一段于是按住院号处置，主索引绑定
（一致代号的取值输入）随之丢失，同一患者跨材料代号可能不一致。脱敏产品里
这类「让位」不是格式问题，是**脱错了**。

**为什么完全重合要单独记一条**：完全重合的两段是两类实体落在同一段正文上，
必须让出的一方在命中清单里看得见（实体类别 + 起止位置 + 让位原因），
伦理办抽检时才知道「这一段为什么按另一类处置」。

**不变量**：

- 裁决产出的 ``kept`` **互不重叠** —— 任何一段正文最多被一个动作改写一次；
- 被丢弃 / 被裁剪的部分**只记位置与原因**，不记命中原文；
- 裁决**不改写正文**，只决定「哪一段由谁负责改写」。

本模块是纯规则引擎：只依赖数据模型（``models``），不读策略表、不碰 I/O。
策略表的装载与校验在 ``policy/conflicts.py``，两者通过
:class:`ArbitrationRules` 连接 —— 换院区改配置，不改这里。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping, Sequence

from .models import DroppedSpan, EntitySpan

__all__ = [
    "ArbitrationError",
    "ArbitrationResult",
    "ArbitrationRules",
    "TIER_ORDER",
    "TIER_ZH",
    "arbitrate",
    "fold_exact_duplicates",
]


#: 档位顺序：数值小 = 优先脱。档位名与策略表 ``conflicts.priority`` 取值一一对应。
TIER_ORDER: dict[str, int] = {
    "identity": 0,  # 身份类：姓名 / 患者编号 / 身份证 / 手机号 / 出生日期
    "encounter": 1,  # 就诊编号类：住院号 / 门诊号 / 检查号
    "generic": 2,  # 通用数字类：其余实体类别
}

#: 档位中文名（进命中解释，供人工抽检读懂「谁让了谁」）。
TIER_ZH: dict[str, str] = {
    "identity": "身份类",
    "encounter": "就诊编号类",
    "generic": "通用数字类",
}


class ArbitrationError(RuntimeError):
    """统一裁决未收敛（内部防御，正常路径不会触发）。"""


@dataclass(frozen=True)
class ArbitrationRules:
    """统一裁决规则。

    :param priority: 实体类别 → 档位名（策略表 ``conflicts.priority``）。
    :param default_tier: 未在 ``priority`` 里声明的实体类别所用档位。
    :param merge_adjacent_same_label: 同类区间之间只隔空白时是否合并成一段。
    :param source: 规则来源路径（写进报错信息，让人知道该改哪个文件）。
    """

    priority: Mapping[str, str] = field(default_factory=dict)
    default_tier: str = "generic"
    merge_adjacent_same_label: bool = True
    source: str = ""

    def tier_of(self, label: str) -> str:
        """某实体类别的优先级档位名。"""
        return self.priority.get(label, self.default_tier)

    def tier_zh(self, label: str) -> str:
        """某实体类别的档位中文名（进命中解释）。"""
        return TIER_ZH.get(self.tier_of(label), self.default_tier)

    def rank(self, span: EntitySpan) -> tuple[int, float, int, int, int]:
        """区间的优先级序：档位 → 分数 → 解释完整度 → 命中长度 → 起点。

        **小者优先**。分数、解释长度、命中长度取负：同档时分数高者、
        解释更完整者、命中更长者依次胜出。
        """
        tier = self.tier_of(span.label)
        return (
            TIER_ORDER.get(tier, len(TIER_ORDER)),
            -float(span.score),
            -len(span.reason or ""),
            -(span.end - span.start),
            span.start,
        )


@dataclass(frozen=True)
class ArbitrationResult:
    """统一裁决的结果。

    :param kept: 保留下来负责改写的区间，**互不重叠**，按起点排序。
    :param dropped: 被丢弃 / 被裁剪掉的区间（含原因），逐条进命中清单。
    """

    kept: tuple[EntitySpan, ...] = ()
    dropped: tuple[DroppedSpan, ...] = ()


# --------------------------------------------------------------------- 入口


def arbitrate(
    spans: Sequence[EntitySpan],
    *,
    text: str = "",
    rules: ArbitrationRules | None = None,
) -> ArbitrationResult:
    """裁决互相冲突的实体区间，产出**互不重叠**的改写计划。

    :param spans: 待裁决的实体区间（调用方只放**会被改写**的区间；白名单放行
        与告警档不参与裁决 —— 它们不改写正文，不该影响别人的边界）。
    :param text: 原文（判断两段之间是否只隔空白时要用）。
    :param rules: 裁决规则；缺省用不带档位的默认规则（同档按分数）。
    :return: 保留的区间（互不重叠）+ 被丢弃 / 被裁剪的区间（含原因）。
    """
    active = rules or ArbitrationRules()
    if not spans:
        return ArbitrationResult()

    ordered = sorted(spans, key=lambda span: (span.start, span.end, span.label))
    dropped: list[DroppedSpan] = []
    merged = _merge_same_label(ordered, text, active, dropped)
    working = _resolve_conflicts(merged, active, dropped)

    working.sort(key=lambda span: (span.start, span.end))
    dropped.sort(key=lambda item: (item.start, item.end, item.label))
    return ArbitrationResult(kept=tuple(working), dropped=tuple(dropped))


def fold_exact_duplicates(spans: Sequence[EntitySpan]) -> list[EntitySpan]:
    """同一段（起点 + 终点完全重合）且**同一实体类别**的命中只保留一条。

    保留规则：分数高者胜；同分时解释更完整者胜（与统一裁决同一套取舍）。
    被折叠的一方记入 ``merged_duplicates``（形如 ``标签@识别器ID``），
    由命中清单登记「同段另有同类别命中」。

    **不同实体类别的同段命中不折叠** —— 那是两类实体争同一段正文，
    该由 :func:`arbitrate` 按档位优先级定案（身份类优先于就诊编号类），
    而不是在这里按分数悄悄决定：住院号 0.95 分压过身份证 0.60 分时，
    主索引绑定会随之丢失，一致代号就不一致了。
    """
    kept: list[EntitySpan] = []
    positions: dict[tuple[int, int, str], int] = {}
    for span in spans:
        key = (span.start, span.end, span.label)
        position = positions.get(key)
        if position is None:
            positions[key] = len(kept)
            kept.append(span)
            continue
        winner, loser = kept[position], span
        if (loser.score, len(loser.reason or "")) > (
            winner.score,
            len(winner.reason or ""),
        ):
            winner, loser = loser, winner
        merged = (
            winner.merged_duplicates
            + loser.merged_duplicates
            + (f"{loser.label}@{loser.recognizer or '未命名识别器'}",)
        )
        kept[position] = replace(winner, merged_duplicates=merged)
    return kept


# --------------------------------------------------------------------- 内部


def _merge_same_label(
    spans: Sequence[EntitySpan],
    text: str,
    rules: ArbitrationRules,
    dropped: list[DroppedSpan],
) -> list[EntitySpan]:
    """同类区间合并：重叠的合成一段，只隔空白的也合成一段。

    合并后保留分数更高的那段的解释与分数，被并掉的一方记入 ``dropped``。
    """
    by_label: dict[str, list[EntitySpan]] = {}
    for span in spans:
        by_label.setdefault(span.label, []).append(span)

    kept: list[EntitySpan] = []
    for label, group in by_label.items():
        group.sort(key=lambda span: (span.start, span.end))
        current: EntitySpan | None = None
        for span in group:
            if current is None:
                current = span
                continue
            if span.start < current.end:
                reason = f"同类区间合并（与同类别 {label} 同段重叠）"
            elif rules.merge_adjacent_same_label and _only_blank(
                text[current.end : span.start]
            ):
                reason = f"同类区间合并（与同类别 {label} 仅隔空白）"
            else:
                kept.append(current)
                current = span
                continue
            merged, loser = _union(current, span)
            current = merged
            dropped.append(_dropped(loser, reason))
        if current is not None:
            kept.append(current)
    return kept


def _union(left: EntitySpan, right: EntitySpan) -> tuple[EntitySpan, EntitySpan]:
    """合并两段同类区间：取并集，分数取高者。

    :return: (合并后的区间, 被并掉的一方)
    """
    if (left.score, len(left.reason or "")) >= (right.score, len(right.reason or "")):
        winner, loser = left, right
    else:
        winner, loser = right, left
    merged = replace(
        winner,
        start=min(left.start, right.start),
        end=max(left.end, right.end),
        merged_duplicates=winner.merged_duplicates
        + loser.merged_duplicates
        + (f"{loser.label}@{loser.recognizer or '未命名识别器'}",),
    )
    return merged, loser


def _resolve_conflicts(
    spans: Sequence[EntitySpan],
    rules: ArbitrationRules,
    dropped: list[DroppedSpan],
) -> list[EntitySpan]:
    """按统一规则裁决互相重叠的区间，直到剩下的区间互不重叠。"""
    kept = list(spans)
    max_iterations = 4 * len(spans) + 16
    for _ in range(max_iterations):
        pair = _find_conflict(kept, rules)
        if pair is None:
            return kept
        winner, loser = pair
        kept = _apply_conflict(kept, winner, loser, rules, dropped)
    raise ArbitrationError(
        f"冲突裁决未收敛：{max_iterations} 轮后仍有重叠区间"
        " —— 这是内部错误，请把该批材料与策略表一并反馈"
    )


def _find_conflict(
    spans: Sequence[EntitySpan], rules: ArbitrationRules
) -> tuple[EntitySpan, EntitySpan] | None:
    """找出第一对互相重叠且类别不同的区间，按统一规则给出胜方与让位方。"""
    ordered = sorted(spans, key=lambda span: (span.start, span.end, span.label))
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            if right.start >= left.end:
                # 按起点排序后，后面的区间更不可能与 left 重叠
                break
            if left.label == right.label:
                continue
            if not _overlaps(left, right):
                continue
            if rules.rank(left) <= rules.rank(right):
                return left, right
            return right, left
    return None


def _apply_conflict(
    kept: list[EntitySpan],
    winner: EntitySpan,
    loser: EntitySpan,
    rules: ArbitrationRules,
    dropped: list[DroppedSpan],
) -> list[EntitySpan]:
    """按四种关系裁决一对冲突区间：

    - **完全重合**（起止都相同）→ 让位方整段让位，胜方按原样保留；
    - **内层被外层包含** → 内层整段让位（外层的替换范围已覆盖它）；
    - **外层被内层包含** → 优先级高的内层**接管整段**（范围扩到并集），
      外层整段让位：既只替换一次，又不留半截原文；
    - **交叉** → 按优先级裁剪让位方的边界，保留未重叠的那一段。
    """
    if winner.start == loser.start and winner.end == loser.end:
        reason = _yield_reason(
            winner, loser, rules, f"本段与 {winner.label} 区间完全重合"
        )
        dropped.append(_dropped(loser, reason))
        return [span for span in kept if span is not loser]

    if loser.start >= winner.start and loser.end <= winner.end:
        reason = _yield_reason(winner, loser, rules, f"本段被 {winner.label} 包含")
        dropped.append(_dropped(loser, reason))
        return [span for span in kept if span is not loser]

    if winner.start >= loser.start and winner.end <= loser.end:
        reason = _yield_reason(winner, loser, rules, f"本段与 {winner.label} 嵌套")
        dropped.append(_dropped(loser, reason))
        promoted = replace(
            winner,
            start=loser.start,
            end=loser.end,
            reason=f"{winner.reason}；与 {loser.label} 嵌套，整段替换为一段",
        )
        return [promoted if span is winner else span for span in kept if span is not loser]

    # 交叉：裁掉让位方与胜方重叠的那一段，保留未重叠的部分
    if loser.start < winner.start:
        kept_range = (loser.start, winner.start)
        cut_range = (winner.start, loser.end)
    else:
        kept_range = (winner.end, loser.end)
        cut_range = (loser.start, winner.end)
    reason = _yield_reason(winner, loser, rules, f"本段与 {winner.label} 交叉")
    dropped.append(_dropped_region(cut_range, loser, reason))
    trimmed = replace(
        loser,
        start=kept_range[0],
        end=kept_range[1],
        reason=f"{loser.reason}；交叉冲突，按优先级裁剪后保留未重叠部分",
    )
    return [trimmed if span is loser else span for span in kept]


def _yield_reason(
    winner: EntitySpan, loser: EntitySpan, rules: ArbitrationRules, phrase: str
) -> str:
    """让位原因：跨档说档位，同档说分数，再同分说解释完整度。

    理由必须写明**实际**的取舍依据 —— 抽检的人要能据此复核这次让位。
    """
    winner_tier = rules.tier_of(winner.label)
    loser_tier = rules.tier_of(loser.label)
    if winner_tier != loser_tier:
        return (
            f"{phrase}，按优先级让位"
            f"（{rules.tier_zh(winner.label)} 优先于 {rules.tier_zh(loser.label)}）"
        )
    if float(winner.score) != float(loser.score):
        return (
            f"{phrase}，同级按分数让位"
            f"（{winner.score:.2f} > {loser.score:.2f}）"
        )
    winner_reason = len(winner.reason or "")
    loser_reason = len(loser.reason or "")
    if winner_reason != loser_reason:
        return (
            f"{phrase}，同级同分，保留解释更完整者"
            f"（解释 {winner_reason} 字 > {loser_reason} 字）"
        )
    winner_length = winner.end - winner.start
    loser_length = loser.end - loser.start
    if winner_length != loser_length:
        return (
            f"{phrase}，同级同分同解释长度，保留命中更长者"
            f"（{winner_length} 字 > {loser_length} 字）"
        )
    return f"{phrase}，同级同分同长度，保留起点靠前者"


def _dropped(span: EntitySpan, reason: str) -> DroppedSpan:
    """整段让位的一条记录。"""
    return DroppedSpan(
        start=span.start,
        end=span.end,
        label=span.label,
        score=span.score,
        tier=span.tier.value,
        recognizer=span.recognizer,
        reason=reason,
    )


def _dropped_region(
    region: tuple[int, int], span: EntitySpan, reason: str
) -> DroppedSpan:
    """被裁剪掉的那一段（区间是原区间的一部分）。"""
    return DroppedSpan(
        start=region[0],
        end=region[1],
        label=span.label,
        score=span.score,
        tier=span.tier.value,
        recognizer=span.recognizer,
        reason=reason,
    )


def _overlaps(left: EntitySpan, right: EntitySpan) -> bool:
    """两段是否重叠。"""
    return left.start < right.end and right.start < left.end


def _only_blank(gap: str) -> bool:
    """两段之间是否只隔空白（不含换行以外的实质内容）。"""
    return bool(gap) and not gap.strip()
