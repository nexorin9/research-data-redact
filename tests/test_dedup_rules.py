"""统一裁决：跨识别器的重叠 / 包含 / 交叉 / 完全重合 —— 一处定案。

源产品把「同一段正文归谁管」分成两处（分析引擎的 ``remove_duplicates`` 与
匿名化引擎的 ``_remove_conflicts_and_get_text_manipulation_data``），本轮合并为
:func:`research_redact.arbitration.arbitrate` 一处，规则固定：

    档位优先（身份类 > 就诊编号类 > 通用数字类）
      > 同级比分数 > 解释更完整者胜 > 同类先合并

本文件分三层验收：

1. **单元层** —— 直接调统一裁决引擎，覆盖重叠 / 包含 / 交叉 / 完全重合四类关系；
2. **装配层** —— 识别层只折叠「同段同类」的重复命中，跨类同段交给统一裁决；
3. **集成层** —— 走主路径（``daemon/pipeline.py``），断言被裁剪方在命中清单里
   看得见（类别 + 起止位置 + 原因）、清单不含原文、同一段不出现重复占位符。
"""

from __future__ import annotations

from itertools import combinations

import pytest

from research_redact.arbitration import ArbitrationRules, arbitrate, fold_exact_duplicates
from research_redact.audit.manifest import DROPPED_ACTION, scan_for_raw_text
from research_redact.audit.residual import scan_residual
from research_redact.daemon.pipeline import redact_text
from research_redact.models import EntitySpan, SpanTier
from research_redact.policy.conflicts import load_conflict_rules
from research_redact.recognizers.base import AuthorityEntry, ListRecognizer, PatternRecognizer
from research_redact.recognizers.patient_index import (
    PatientIndexBinding,
    PatientIndexEntry,
    PatientIndexRecognizer,
)
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

#: 单元测试用的档位表：与策略表 ``conflicts.priority`` 同口径。
RULES = ArbitrationRules(
    priority={
        "ID_CARD": "identity",
        "PATIENT_NAME": "identity",
        "PATIENT_ID": "identity",
        "VISIT_NO": "encounter",
        "EXAM_NO": "encounter",
    },
    default_tier="generic",
)

#: 单元测试里反复出现的一段正文（脱敏后不得残留）。
RAW_DIGITS = "90000001"


def _span(
    start: int,
    end: int,
    label: str,
    score: float = 0.9,
    reason: str = "测试命中",
    recognizer: str = "r",
) -> EntitySpan:
    """造一个确认档的实体区间。"""
    return EntitySpan(
        start=start,
        end=end,
        label=label,
        score=score,
        reason=reason,
        tier=SpanTier.CONFIRMED,
        recognizer=recognizer,
    )


def _registry(*recognizers) -> RecognizerRegistry:
    return RecognizerRegistry(list(recognizers), RegistryConfig(global_threshold=0.5))


# ------------------------------------------------------------------ 重叠关系


def test_overlap_is_arbitrated_by_tier_before_score():
    """部分重叠：档位优先于分数 —— 身份类接管，低档类整段让位。"""
    spans = [
        _span(0, 12, "VISIT_NO", 0.99, "就诊编号识别器命中"),
        _span(4, 10, "ID_CARD", 0.60, "身份证识别器命中"),
    ]
    result = arbitrate(spans, text="", rules=RULES)

    assert [(s.label, s.start, s.end) for s in result.kept] == [("ID_CARD", 0, 12)]
    assert [(d.label, d.start, d.end) for d in result.dropped] == [("VISIT_NO", 0, 12)]
    assert "身份类" in result.dropped[0].reason
    assert "按优先级让位" in result.dropped[0].reason


def test_contained_span_yields_to_the_containing_span():
    """包含关系：内层被外层包含时整段让位（外层的替换范围已覆盖它）。

    外层是身份类、内层是就诊编号类 —— 档位优先于分数，内层让位。
    """
    spans = [_span(0, 20, "ID_CARD", 0.6), _span(5, 15, "VISIT_NO", 0.95)]
    result = arbitrate(spans, text="", rules=RULES)

    assert [(s.label, s.start, s.end) for s in result.kept] == [("ID_CARD", 0, 20)]
    assert [(d.label, d.start, d.end) for d in result.dropped] == [("VISIT_NO", 5, 15)]
    assert "包含" in result.dropped[0].reason
    assert "身份类 优先于 就诊编号类" in result.dropped[0].reason


def test_contained_span_of_same_tier_is_decided_by_score():
    """同档的包含关系：分数高者胜，并写明分数差距。"""
    spans = [_span(0, 20, "VISIT_NO", 0.7), _span(5, 15, "EXAM_NO", 0.95)]
    result = arbitrate(spans, text="", rules=RULES)

    assert [s.label for s in result.kept] == ["EXAM_NO"]
    assert "同级按分数让位" in result.dropped[0].reason


def test_crossing_spans_are_trimmed_and_loser_region_is_traced():
    """交叉关系：按优先级裁剪让位方的边界，被裁掉的那一段单独留痕。"""
    spans = [_span(0, 10, "VISIT_NO", 0.9), _span(5, 15, "ID_CARD", 0.7)]
    result = arbitrate(spans, text="", rules=RULES)

    assert [(s.label, s.start, s.end) for s in result.kept] == [
        ("VISIT_NO", 0, 5),
        ("ID_CARD", 5, 15),
    ]
    assert [(d.label, d.start, d.end) for d in result.dropped] == [("VISIT_NO", 5, 10)]
    assert "交叉" in result.dropped[0].reason


# ------------------------------------------------------------------ 完全重合


def test_exactly_coincident_identity_class_wins_despite_lower_score():
    """完全重合：档位优先于分数 —— 身份类不能输给就诊编号类。

    这是本任务要修的那一刀：源产品按分数去重，住院号 0.99 分压过身份证
    0.60 分时，主索引绑定随之丢失，一致代号就不一致了。
    """
    spans = [
        _span(0, 12, "VISIT_NO", 0.99, "就诊编号识别器命中"),
        _span(0, 12, "ID_CARD", 0.60, "身份证识别器命中"),
    ]
    result = arbitrate(spans, text="", rules=RULES)

    assert [s.label for s in result.kept] == ["ID_CARD"]
    assert [d.label for d in result.dropped] == ["VISIT_NO"]
    assert "区间完全重合" in result.dropped[0].reason
    assert "身份类 优先于 就诊编号类" in result.dropped[0].reason


def test_exactly_coincident_same_tier_and_score_keeps_more_complete_explanation():
    """完全重合且档位、分数都相同时：保留解释更完整者。"""
    spans = [
        _span(0, 12, "VISIT_NO", 0.9, "短"),
        _span(0, 12, "EXAM_NO", 0.9, "这一段解释写得更完整，说明命中依据更细"),
    ]
    result = arbitrate(spans, text="", rules=RULES)

    assert [s.label for s in result.kept] == ["EXAM_NO"]
    assert "保留解释更完整者" in result.dropped[0].reason
    assert "解释" in result.dropped[0].reason


def test_same_tier_is_decided_by_score():
    """同档时分数高者胜，并写明分数差距。"""
    spans = [_span(0, 20, "VISIT_NO", 0.7), _span(5, 15, "EXAM_NO", 0.9)]
    result = arbitrate(spans, text="", rules=RULES)

    assert [s.label for s in result.kept] == ["EXAM_NO"]
    assert "同级按分数让位" in result.dropped[0].reason


def test_same_label_spans_are_merged_into_one_segment():
    """同类命中重叠：合成一段，一次改写覆盖两处。"""
    spans = [_span(0, 10, "PHONE", 0.9, "a"), _span(5, 15, "PHONE", 0.8, "b")]
    result = arbitrate(spans, text="", rules=RULES)

    assert len(result.kept) == 1
    assert (result.kept[0].start, result.kept[0].end) == (0, 15)
    assert "同类区间合并" in result.dropped[0].reason


# ------------------------------------------------------------------ 裁决不变量


def test_kept_spans_never_overlap():
    """输出计划互不重叠：同一段正文最多被一个动作改写一次。"""
    spans = [
        _span(0, 20, "VISIT_NO", 0.9),
        _span(5, 15, "ID_CARD", 0.6),
        _span(12, 30, "EXAM_NO", 0.8),
        _span(25, 35, "PATIENT_NAME", 0.7),
    ]
    result = arbitrate(spans, text="", rules=RULES)

    for left, right in combinations(result.kept, 2):
        assert not (left.start < right.end and right.start < left.end)


def test_dropped_records_carry_label_positions_and_reason():
    """被裁剪方带齐类别、起止位置与原因 —— 抽检的人才知道「这一段为什么没脱」。"""
    spans = [_span(0, 10, "VISIT_NO", 0.9), _span(5, 15, "ID_CARD", 0.7)]
    result = arbitrate(spans, text="", rules=RULES)

    assert result.dropped
    for dropped in result.dropped:
        assert dropped.label
        assert dropped.start < dropped.end
        assert dropped.reason


def test_dropped_reason_never_contains_raw_text():
    """被裁剪方的记录只讲原因，不含命中原文。"""
    spans = [_span(0, 8, "VISIT_NO", 0.9), _span(0, 8, "ID_CARD", 0.6)]
    result = arbitrate(spans, text=RAW_DIGITS, rules=RULES)

    for dropped in result.dropped:
        assert RAW_DIGITS not in dropped.reason
        assert dropped.reason


def test_policy_table_drives_the_tier_order():
    """档位顺序取自策略表：改配置即换取舍，不改代码。"""
    rules = load_conflict_rules()
    assert rules.tier_of("ID_CARD") == "identity"
    assert rules.tier_of("PATIENT_ID") == "identity"
    assert rules.tier_of("VISIT_NO") == "encounter"

    spans = [
        _span(0, 12, "VISIT_NO", 0.99, "就诊编号识别器命中"),
        _span(0, 12, "PATIENT_ID", 0.60, "主索引主键命中"),
    ]
    result = arbitrate(spans, text="", rules=rules)

    assert [s.label for s in result.kept] == ["PATIENT_ID"]


# ------------------------------------------------------------ 识别层的折叠边界


def test_same_label_coincident_spans_are_folded_by_registry():
    """同段、同一实体类别被两个识别器各命中一次：折叠掉一份（同一实体）。"""
    registry = _registry(
        PatternRecognizer("visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.7),
        PatternRecognizer("backup_no", "备用住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.9),
    )
    spans = registry.analyze("住院号 90000001")

    assert len(spans) == 1
    assert spans[0].recognizer == "backup_no"
    assert spans[0].merged_duplicates == ("VISIT_NO@visit_no",)


def test_cross_label_coincident_spans_are_not_folded_by_registry():
    """同段、不同实体类别**不折叠**：两类实体争同一段，交给统一裁决定案。

    折叠掉身份类那一侧，就等于按分数把主索引绑定丢了。
    """
    registry = _registry(
        ListRecognizer(
            "patient_index",
            "患者主索引名单识别器",
            [AuthorityEntry(value="90000001", label="PATIENT_ID", score=0.6)],
        ),
        PatternRecognizer("visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.95),
    )
    spans = registry.analyze("住院号 90000001")

    assert {span.label for span in spans} == {"PATIENT_ID", "VISIT_NO"}
    assert all(not span.merged_duplicates for span in spans)


def test_fold_exact_duplicates_keeps_label_aware_folding():
    """折叠函数本身按「起点 + 终点 + 类别」分组，跨类别不折叠。"""
    spans = [
        _span(0, 8, "VISIT_NO", 0.9, "a", recognizer="a"),
        _span(0, 8, "VISIT_NO", 0.7, "b", recognizer="b"),
        _span(0, 8, "ID_CARD", 0.6, "c", recognizer="c"),
    ]
    folded = fold_exact_duplicates(spans)

    assert len(folded) == 2
    by_label = {span.label: span for span in folded}
    assert by_label["VISIT_NO"].recognizer == "a"
    assert by_label["VISIT_NO"].merged_duplicates == ("VISIT_NO@b",)
    assert by_label["ID_CARD"].merged_duplicates == ()


# ------------------------------------------------------------------ 集成（主路径）


def _coincident_registry() -> RecognizerRegistry:
    """主索引主键与住院号命中同一段的注册表。"""
    return _registry(
        PatientIndexRecognizer(
            PatientIndexBinding(
                entries=(PatientIndexEntry(patient_id="90000001", name="张某某"),),
                source="测试装配",
            )
        ),
        PatternRecognizer("visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.99),
    )


def test_dropped_party_is_visible_in_manifest_with_label_positions_and_reason():
    """被裁剪方在命中清单里看得见：类别 + 起止位置 + 让位原因。"""
    outcome = redact_text("住院号 90000001", "M-1", registry=_coincident_registry())

    dropped = [entry for entry in outcome.entries if entry.action == DROPPED_ACTION]
    assert len(dropped) == 1
    assert dropped[0].label == "VISIT_NO"
    assert (dropped[0].start, dropped[0].end) == (4, 12)
    assert "区间完全重合" in dropped[0].reason
    assert "身份类" in dropped[0].reason


def test_same_segment_replaced_once_without_duplicate_placeholder():
    """同一段只改写一次：产物里不出现重复占位符。"""
    outcome = redact_text("住院号 90000001", "M-2", registry=_coincident_registry())

    assert outcome.rewritten == 1
    assert "90000001" not in outcome.redacted_text
    assert outcome.redacted_text.count("<患者编号>") == 1
    assert "<住院号>" not in outcome.redacted_text


def test_identity_class_keeps_master_index_binding_over_higher_scored_encounter():
    """身份类胜出后，主索引绑定（一致代号的取值输入）不得丢。"""
    outcome = redact_text("住院号 90000001", "M-3", registry=_coincident_registry())

    kept = [
        entry for entry in outcome.entries if entry.action not in (DROPPED_ACTION,)
    ]
    assert [entry.label for entry in kept] == ["PATIENT_ID"]
    assert kept[0].recognizer == "patient_index"


def test_manifest_contains_no_raw_text():
    """命中清单全文不含命中原文（与命中解释一起扫）。"""
    outcome = redact_text("住院号 90000001", "M-4", registry=_coincident_registry())

    payload = "\n".join(entry.reason for entry in outcome.entries)
    assert scan_for_raw_text(payload, [RAW_DIGITS]) == []


def test_coincident_identity_hits_count_as_one_residual():
    """同一段被两个身份类识别器命中：残留按段算一处，不按条算两处。"""
    registry = _registry(
        ListRecognizer(
            "patient_index",
            "患者主索引名单识别器",
            [AuthorityEntry(value="90000001", label="PATIENT_ID", score=0.9)],
        ),
        PatternRecognizer("visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.9),
    )
    findings = scan_residual(
        "住院号 90000001",
        "M-5",
        registry,
        rules=load_conflict_rules(),
    )

    assert len(findings) == 1
    assert findings[0].start == 4
    assert findings[0].end == 12


def test_folded_same_label_duplicate_is_visible_in_manifest():
    """同段同类被折叠的那一条，在清单里看得见（类别 + 识别器 + 原因）。"""
    registry = _registry(
        PatternRecognizer("visit_no", "住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.7),
        PatternRecognizer("backup_no", "备用住院号识别器", {"VISIT_NO": r"\d{8}"}, base_score=0.9),
    )
    outcome = redact_text("住院号 90000001", "M-6", registry=registry)

    assert len(outcome.entries) == 1
    entry = outcome.entries[0]
    assert entry.merged_duplicates == ("VISIT_NO@visit_no",)
    assert "已折叠" in entry.reason
    assert "VISIT_NO@visit_no" in entry.reason


def test_arbitration_error_on_rules_with_unknown_tier_is_rejected_by_policy_loader(tmp_path):
    """档位名写错即报错 —— 不静默落到默认档（宁可不裁决，也不默默让错）。"""
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
    with pytest.raises(Exception, match="档位非法"):
        load_conflict_rules(path)
