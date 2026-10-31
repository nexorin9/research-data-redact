"""冲突区间合并与裁剪：同一段只替换一次。

本模块（``policy/conflicts.py``）在识别层之后、处置层之前，把互相重叠的命中
裁成**互不重叠**的一份改写计划，并把被裁掉的一方记进逐处命中清单。

三条主线：

1. **同类区间合并** —— 同类命中重叠的合成一段，只隔空白的也合成一段；
2. **按优先级裁决** —— 身份类 > 就诊编号类 > 通用数字类；同档再比分数；
3. **留痕** —— 每一次丢弃 / 裁剪都写进清单（含原因，不含原文）。

测试分两层：单元层直接调 ``resolve_conflicts``，集成层走主路径
（``daemon/pipeline.py``），断言产物里同一段只有一个占位符。
"""

from __future__ import annotations

from itertools import combinations

import pytest

from research_redact.daemon.pipeline import redact_text
from research_redact.models import EntitySpan, SpanTier
from research_redact.policy.conflicts import (
    ConflictConfigError,
    ConflictRules,
    load_conflict_rules,
    resolve_conflicts,
)
from research_redact.recognizers.base import PatternRecognizer
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig


#: 单元测试用的规则：身份类 / 就诊编号类 / 通用数字类三档。
RULES = ConflictRules(
    priority={
        "ID_CARD": "identity",
        "PATIENT_NAME": "identity",
        "VISIT_NO": "encounter",
        "EXAM_NO": "encounter",
    },
    default_tier="generic",
)


def _span(start: int, end: int, label: str, score: float = 0.9, recognizer: str = "r"):
    """造一个确认档的实体区间。"""
    return EntitySpan(
        start=start,
        end=end,
        label=label,
        score=score,
        reason="测试命中",
        tier=SpanTier.CONFIRMED,
        recognizer=recognizer,
    )


def _registry(*recognizers: PatternRecognizer) -> RecognizerRegistry:
    return RecognizerRegistry(
        list(recognizers), RegistryConfig(global_threshold=0.5)
    )


# ------------------------------------------------------------------ 同类合并


def test_same_label_overlapping_spans_are_merged():
    """同类命中重叠：合成一段，分数取高者，被并掉的一方留痕。"""
    spans = [_span(0, 10, "PHONE", 0.9, "a"), _span(5, 15, "PHONE", 0.8, "b")]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    assert len(resolution.kept) == 1
    assert (resolution.kept[0].start, resolution.kept[0].end) == (0, 15)
    assert resolution.kept[0].score == 0.9
    assert len(resolution.dropped) == 1
    assert "同类区间合并" in resolution.dropped[0].reason


def test_adjacent_same_label_spans_separated_by_blank_are_merged():
    """相邻同类命中之间只隔空白：合成一段，一次改写覆盖两处。"""
    text = "电话 13800138000 13900139000"
    spans = [_span(3, 14, "PHONE", 0.9, "a"), _span(15, 26, "PHONE", 0.9, "b")]
    resolution = resolve_conflicts(spans, text=text, rules=RULES)

    assert len(resolution.kept) == 1
    assert (resolution.kept[0].start, resolution.kept[0].end) == (3, 26)
    assert "仅隔空白" in resolution.dropped[0].reason


def test_same_label_spans_separated_by_text_are_not_merged():
    """同类命中之间隔着实质内容：不合并，各改各的。"""
    text = "甲 13800138000 乙 13900139000"
    spans = [_span(2, 13, "PHONE", 0.9), _span(16, 27, "PHONE", 0.9)]
    resolution = resolve_conflicts(spans, text=text, rules=RULES)

    assert len(resolution.kept) == 2
    assert resolution.dropped == ()


# ------------------------------------------------------------------ 优先级裁决


def test_identity_class_wins_over_generic_number_even_with_lower_score():
    """身份类优先于通用数字类：档位优先于分数。"""
    spans = [_span(0, 8, "GENERIC_NO", 0.95), _span(2, 6, "ID_CARD", 0.6)]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    # 身份类接管整段（范围扩到并集），通用数字类整段让位
    assert [(s.label, s.start, s.end) for s in resolution.kept] == [("ID_CARD", 0, 8)]
    assert [(d.label, d.start, d.end) for d in resolution.dropped] == [
        ("GENERIC_NO", 0, 8)
    ]
    assert "身份类" in resolution.dropped[0].reason


def test_encounter_class_wins_over_generic_number():
    """就诊编号类优先于通用数字类。"""
    spans = [_span(0, 20, "VISIT_NO", 0.9), _span(5, 15, "GENERIC_NO", 0.95)]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    assert [(s.label, s.start, s.end) for s in resolution.kept] == [("VISIT_NO", 0, 20)]
    assert [(d.label, d.start, d.end) for d in resolution.dropped] == [
        ("GENERIC_NO", 5, 15)
    ]
    assert "包含" in resolution.dropped[0].reason


def test_same_tier_is_decided_by_score():
    """同档时分数高者胜，并写明分数差距。"""
    spans = [_span(0, 20, "VISIT_NO", 0.7), _span(5, 15, "EXAM_NO", 0.9)]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    assert [s.label for s in resolution.kept] == ["EXAM_NO"]
    assert "同级按分数让位" in resolution.dropped[0].reason


def test_crossing_spans_are_trimmed_by_priority():
    """交叉冲突：按优先级裁剪让位方的边界，保留未重叠的那一段。"""
    spans = [_span(0, 10, "VISIT_NO", 0.9), _span(5, 15, "ID_CARD", 0.7)]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    assert [(s.label, s.start, s.end) for s in resolution.kept] == [
        ("VISIT_NO", 0, 5),
        ("ID_CARD", 5, 15),
    ]
    # 被裁掉的那一段记入清单（它由胜方负责改写，不留半截原文）
    assert [(d.label, d.start, d.end) for d in resolution.dropped] == [
        ("VISIT_NO", 5, 10)
    ]
    assert "交叉" in resolution.dropped[0].reason


def test_kept_spans_never_overlap():
    """输出计划互不重叠：同一段正文最多被一个动作改写一次。"""
    spans = [
        _span(0, 20, "VISIT_NO", 0.9),
        _span(5, 15, "ID_CARD", 0.6),
        _span(12, 30, "EXAM_NO", 0.8),
        _span(25, 35, "PATIENT_NAME", 0.7),
    ]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    for left, right in combinations(resolution.kept, 2):
        assert not (left.start < right.end and right.start < left.end)


def test_dropped_reasons_never_contain_raw_text():
    """被裁剪方的记录只讲原因，不含命中原文。"""
    spans = [_span(0, 10, "VISIT_NO", 0.9), _span(5, 15, "ID_CARD", 0.7)]
    resolution = resolve_conflicts(spans, text="", rules=RULES)

    for dropped in resolution.dropped:
        assert "12345" not in dropped.reason
        assert dropped.reason


# ------------------------------------------------------------------ 集成（主路径）


def test_id_card_and_visit_no_on_same_segment_replaced_once():
    """身份证号与住院号命中同一段：只替换一次，身份类优先并留痕。

    构造：一串 18 位号码，身份证识别器命中整段，住院号识别器命中其中 8 位 ——
    两段落在同一段正文上，只能有一处负责改写。
    """
    registry = _registry(
        PatternRecognizer(
            "id_card", "身份证识别器", {"ID_CARD": r"\d{17}[\dX]"}, base_score=0.6
        ),
        PatternRecognizer(
            "visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.95
        ),
    )
    outcome = redact_text("证件 11010119491231001X", "M-1", registry=registry)

    # 同一段只改写一次
    assert outcome.rewritten == 1
    assert "11010119491231001X" not in outcome.redacted_text

    kept = [e for e in outcome.entries if e.action != "none（冲突裁决：未改写）"]
    dropped = [e for e in outcome.entries if e.action == "none（冲突裁决：未改写）"]
    assert [e.label for e in kept] == ["ID_CARD"]
    assert {e.label for e in dropped} == {"VISIT_NO"}
    assert "ID_CARD" in dropped[0].reason


def test_nested_hits_replaced_once_by_priority():
    """嵌套命中：身份类接管整段，低优先级的整段让位，同一段只改写一次。"""
    registry = _registry(
        PatternRecognizer(
            "outer", "外层识别器", {"VISIT_NO": r"\d{10}"}, base_score=0.9
        ),
        PatternRecognizer(
            "inner", "内层识别器", {"ID_CARD": r"\d{4}(?=\d{6})"}, base_score=0.5
        ),
    )
    outcome = redact_text("编号 1234567890", "M-2", registry=registry)

    assert outcome.rewritten == 1
    assert "1234567890" not in outcome.redacted_text
    dropped = [e for e in outcome.entries if e.action == "none（冲突裁决：未改写）"]
    assert [e.label for e in dropped] == ["VISIT_NO"]
    assert "嵌套" in dropped[0].reason


def test_adjacent_same_label_hits_rewritten_once():
    """相邻同类命中只隔空白：合成一段，一次改写。"""
    registry = _registry(
        PatternRecognizer(
            "phone", "手机号识别器", {"PHONE": r"\d{11}"}, base_score=0.9
        )
    )
    outcome = redact_text("电话 13800138000 13900139000", "M-3", registry=registry)

    assert outcome.rewritten == 1
    assert "13800138000" not in outcome.redacted_text
    assert "13900139000" not in outcome.redacted_text
    dropped = [e for e in outcome.entries if e.action == "none（冲突裁决：未改写）"]
    assert len(dropped) == 1
    assert "同类区间合并" in dropped[0].reason


def test_dropped_entries_carry_reason_without_raw_text():
    """被裁剪方在清单里可见，且不含命中原文。"""
    registry = _registry(
        PatternRecognizer(
            "outer", "外层识别器", {"VISIT_NO": r"\d{10}"}, base_score=0.9
        ),
        PatternRecognizer(
            "inner", "内层识别器", {"ID_CARD": r"\d{4}(?=\d{6})"}, base_score=0.5
        ),
    )
    outcome = redact_text("编号 1234567890", "M-4", registry=registry)

    dropped = [e for e in outcome.entries if e.action == "none（冲突裁决：未改写）"]
    assert dropped
    for entry in dropped:
        assert entry.reason
        assert "1234567890" not in entry.reason
        assert "1234" not in entry.reason


# ------------------------------------------------------------------ 策略表装配


def test_policy_table_declares_conflict_priority_for_every_entity():
    """策略表里每个实体类别都分配了优先级档位，不留静默默认。"""
    rules = load_conflict_rules()
    assert rules.tier_of("ID_CARD") == "identity"
    assert rules.tier_of("VISIT_NO") == "encounter"
    assert rules.tier_of("EXAM_NO") == "encounter"
    assert rules.tier_of("PATIENT_NAME") == "identity"


def test_missing_conflicts_section_raises(tmp_path):
    """策略表缺 conflicts 段即报错，不静默取默认优先级。"""
    import yaml

    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "thresholds": {"global": 0.5},
                "entities": {"VISIT_NO": {"action": "keep"}},
                "allow_list": {"exact": [], "regex": []},
                "context": {"terms": ["住院号"]},
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConflictConfigError, match="缺少 conflicts 段"):
        load_conflict_rules(path)


def test_unknown_priority_tier_raises(tmp_path):
    """优先级档位名写错即报错。"""
    import yaml

    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "thresholds": {"global": 0.5},
                "entities": {"VISIT_NO": {"action": "keep"}},
                "allow_list": {"exact": [], "regex": []},
                "context": {"terms": ["住院号"]},
                "conflicts": {"priority": {"VISIT_NO": "身份类"}},
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConflictConfigError, match="档位非法"):
        load_conflict_rules(path)


def test_entity_without_priority_tier_raises(tmp_path):
    """策略表声明了实体类别却没分配档位即报错（不能静默落到通用数字类）。"""
    import yaml

    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "thresholds": {"global": 0.5},
                "entities": {"VISIT_NO": {"action": "keep"}},
                "allow_list": {"exact": [], "regex": []},
                "context": {"terms": ["住院号"]},
                "conflicts": {"priority": {"PATIENT_NAME": "identity"}},
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConflictConfigError, match="未分配优先级档位"):
        load_conflict_rules(path)
