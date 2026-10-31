"""识别引擎地基验收：逐识别器阈值 / 全局阈值 / 重叠去重 / 白名单放行 / 低分降档。

对应源产品分析引擎主路径：注册表 → 逐识别器打分 → 阈值过滤 → 去重 → 白名单。
本轮改写为项目内自有确定性实现，差异是「低于阈值不丢弃、白名单放行可见」。
"""

from __future__ import annotations

import pytest

from research_redact.models import SpanTier
from research_redact.recognizers.base import (
    AuthorityEntry,
    ChecksumRecognizer,
    ListRecognizer,
    PatternRecognizer,
)
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

VISIT_NO_PATTERN = r"(?<!\d)\d{8}(?!\d)"
PHONE_PATTERN = r"(?<!\d)1\d{10}(?!\d)"


def _visit_recognizer(score: float = 0.7, recognizer_id: str = "visit_no") -> PatternRecognizer:
    return PatternRecognizer(
        recognizer_id, "就诊编号识别器", {"VISIT_NO": VISIT_NO_PATTERN}, base_score=score
    )


# ---------------------------------------------------------------- 逐识别器阈值


def test_per_recognizer_threshold_overrides_global_threshold():
    """逐识别器阈值命中即覆盖全局阈值：同分命中按识别器分出不同档位。"""
    registry = RecognizerRegistry(
        [
            _visit_recognizer(score=0.6),
            PatternRecognizer(
                "phone_birth", "手机号识别器", {"PHONE": PHONE_PATTERN}, base_score=0.6
            ),
        ],
        RegistryConfig(global_threshold=0.5, per_recognizer_thresholds={"phone_birth": 0.8}),
    )
    spans = registry.analyze("住院号 12345678 手机 13800138000")
    assert len(spans) == 2
    tiers = {span.recognizer: span.tier for span in spans}
    assert tiers["visit_no"] is SpanTier.CONFIRMED
    assert tiers["phone_birth"] is SpanTier.WARNING
    warning = next(span for span in spans if span.recognizer == "phone_birth")
    assert "0.80" in warning.reason


def test_recognizer_level_category_threshold_applies():
    """识别器自带的逐类别阈值生效（无逐识别器覆盖时）。"""
    recognizer = PatternRecognizer(
        "visit_no",
        "就诊编号识别器",
        {"VISIT_NO": VISIT_NO_PATTERN},
        base_score=0.6,
        score_thresholds={"VISIT_NO": 0.65},
    )
    registry = RecognizerRegistry([recognizer], RegistryConfig(global_threshold=0.5))
    spans = registry.analyze("住院号 12345678")
    assert spans[0].tier is SpanTier.WARNING
    assert "0.65" in spans[0].reason


# ------------------------------------------------------------------ 全局阈值


def test_global_threshold_demotes_low_score_result():
    """全局阈值：分数不足降为告警档，而不是被丢弃。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.4)], RegistryConfig(global_threshold=0.5)
    )
    spans = registry.analyze("住院号 12345678")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert spans[0].score == pytest.approx(0.4)
    assert spans[0].counts_as_residual is False


def test_global_threshold_confirms_reaching_result():
    """达到全局阈值的命中判为确认档。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.5)], RegistryConfig(global_threshold=0.5)
    )
    spans = registry.analyze("住院号 12345678")
    assert spans[0].tier is SpanTier.CONFIRMED
    assert spans[0].counts_as_residual is True


# ------------------------------------------------------------------ 重叠去重


def test_same_segment_overlap_keeps_single_span():
    """同一段被两个识别器完全命中时只保留一条，被折叠方记入 merged_duplicates。"""
    registry = RecognizerRegistry(
        [
            _visit_recognizer(score=0.7, recognizer_id="visit_no"),
            _visit_recognizer(score=0.9, recognizer_id="backup_no"),
        ],
        RegistryConfig(global_threshold=0.5),
    )
    spans = registry.analyze("住院号 12345678")
    assert len(spans) == 1
    assert spans[0].recognizer == "backup_no"
    assert spans[0].merged_duplicates == ("VISIT_NO@visit_no",)


def test_different_segments_are_not_collapsed():
    """不同区间不参与去重。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.7)], RegistryConfig(global_threshold=0.5)
    )
    spans = registry.analyze("住院号 12345678 与 87654321")
    assert len(spans) == 2
    assert {span.start for span in spans} == {4, 15}


# ------------------------------------------------------------------ 白名单放行


def test_allow_list_exact_and_regex_release_spans():
    """白名单两种匹配形态都放行：放行档可见，且不计入残留。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.8)],
        RegistryConfig(
            global_threshold=0.5,
            allow_list_exact=("87654321",),
            allow_list_regex=(r"^1234\d{4}$",),
        ),
    )
    spans = registry.analyze("住院号 87654321 与 12345678")
    allowed = [span for span in spans if span.is_allowed]
    confirmed = [span for span in spans if span.is_confirmed]
    assert len(allowed) == 2
    assert len(confirmed) == 0
    assert all(span.counts_as_residual is False for span in allowed)
    assert "白名单" in allowed[0].reason


def test_non_allow_listed_span_stays_confirmed():
    """未命中白名单的区间不受白名单影响。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.8)],
        RegistryConfig(global_threshold=0.5, allow_list_exact=("87654321",)),
    )
    spans = registry.analyze("住院号 87654321 与 12345678")
    assert [span.tier for span in spans] == [SpanTier.ALLOWED, SpanTier.CONFIRMED]


# ------------------------------------------------------------------ 低分降档


def test_low_score_result_is_demoted_not_dropped():
    """低于阈值的命中仍在结果里，只是降为告警档并写明阈值差距。"""
    registry = RecognizerRegistry(
        [_visit_recognizer(score=0.3)], RegistryConfig(global_threshold=0.6)
    )
    spans = registry.analyze("住院号 12345678")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert "低于阈值" in spans[0].reason
    assert "0.60" in spans[0].reason


def test_warning_span_is_not_dropped_when_other_span_confirms():
    """降档不吞掉别的命中：确认档与告警档同时存在。"""
    registry = RecognizerRegistry(
        [
            _visit_recognizer(score=0.9, recognizer_id="visit_no"),
            PatternRecognizer(
                "phone", "手机号识别器", {"PHONE": PHONE_PATTERN}, base_score=0.2
            ),
        ],
        RegistryConfig(global_threshold=0.5),
    )
    spans = registry.analyze("住院号 12345678 手机 13800138000")
    tiers = {span.label: span.tier for span in spans}
    assert tiers["VISIT_NO"] is SpanTier.CONFIRMED
    assert tiers["PHONE"] is SpanTier.WARNING


# --------------------------------------------------------------- 三种识别形态


def test_checksum_form_passes_and_fails_apart():
    """校验位形态：校验通过的判为身份，校验不通过的降为告警。"""

    def validator(value: str) -> bool:
        return value.endswith("7")

    registry = RecognizerRegistry(
        [
            ChecksumRecognizer(
                "id_card", "身份证识别器", r"\d{17}[\dX]", "ID_CARD", validator
            )
        ],
        RegistryConfig(global_threshold=0.5),
    )
    spans = registry.analyze("身份证 11010519491231002X 与 110105194912310017")
    tiers = {span.start: span.tier for span in spans}
    assert tiers[4] is SpanTier.WARNING  # 末位 X，不通过校验
    assert tiers[25] is SpanTier.CONFIRMED  # 末位 7，校验通过


def test_list_form_matches_authority_entries_only():
    """名单形态：只认权威名单里的值，名单外不命中；名单为空时不产出任何命中。"""
    registry = RecognizerRegistry(
        [
            ListRecognizer(
                "patient_index",
                "患者主索引名单识别器",
                [AuthorityEntry(value="12345678", label="PATIENT_ID", score=0.95)],
            )
        ],
        RegistryConfig(global_threshold=0.5),
    )
    spans = registry.analyze("住院号 12345678 与 87654321")
    assert [span.label for span in spans] == ["PATIENT_ID"]
    assert spans[0].start == 4

    empty_registry = RecognizerRegistry(
        [ListRecognizer("patient_index", "患者主索引名单识别器", [])],
        RegistryConfig(global_threshold=0.5),
    )
    assert empty_registry.analyze("住院号 12345678") == []


def test_list_form_normalizes_full_width_digits():
    """名单形态：全角数字同样命中，区间换算回原文坐标。"""
    registry = RecognizerRegistry(
        [
            ListRecognizer(
                "patient_index",
                "患者主索引名单识别器",
                [AuthorityEntry(value="12345678", label="PATIENT_ID", score=0.95)],
            )
        ],
        RegistryConfig(global_threshold=0.5),
    )
    text = "住院号 １２３４５６７８"
    spans = registry.analyze(text)
    assert len(spans) == 1
    assert text[spans[0].start : spans[0].end] == "１２３４５６７８"


# ------------------------------------------------------------------ 装配错误


def test_duplicate_recognizer_id_raises():
    """装配非法即报错，不静默覆盖。"""
    registry = RecognizerRegistry()
    registry.register(_visit_recognizer())
    with pytest.raises(ValueError, match="id 重复"):
        registry.register(_visit_recognizer())


def test_unavailable_recognizer_produces_no_span():
    """识别器不可用（如主索引不可达）时不产出任何命中，不按姓名硬匹配。"""
    registry = RecognizerRegistry(
        [
            ListRecognizer(
                "patient_index",
                "患者主索引名单识别器",
                [AuthorityEntry(value="12345678", label="PATIENT_ID")],
                available=False,
            )
        ],
        RegistryConfig(global_threshold=0.5),
    )
    assert registry.analyze("住院号 12345678") == []
