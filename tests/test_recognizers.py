"""识别器包（正则形态）验收：住院号 / 检查号 / 手机号 / 出生日期 + 最小误伤回归。

对应源产品的正则形态识别器（``PatternRecognizer``：按标签给若干正则、整段扫描
取全部命中）。本轮改写为**形状约束驱动** —— 位数、前缀、字符集写在
``policy/research.yaml``，识别器按配置生成正则。

本测试守住三件事：

1. **该命中的命中**：住院号 / 门诊号 / 检查号 / 手机号 / 出生日期各 ≥1 例；
2. **不该命中的不命中**：疾病名、药品名、科室名一个都不许被当成身份；
3. **形状真的由策略表驱动**：改 YAML 就改行为，不改代码；配置非法即报错。
"""

from __future__ import annotations

import textwrap

import pytest

from research_redact.daemon.pipeline import build_default_registry, redact_text
from research_redact.models import SpanTier
from research_redact.recognizers.phone_birth import PhoneBirthRecognizer
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig
from research_redact.recognizers.shapes import ShapeConfigError, load_shapes
from research_redact.recognizers.visit_no import VisitNoRecognizer

# 合成样例里的临床对照串：全部虚构，与任何真实患者信息无关
CLINICAL_TERMS = (
    "呼吸内科",
    "放射科",
    "右肺下叶磨玻璃结节",
    "2 型糖尿病",
    "盐酸氨溴索口服液",
    "布洛芬缓释胶囊",
    "阿莫西林胶囊",
    "胸部CT平扫",
)


def _registry() -> RecognizerRegistry:
    """只装两个正则形态识别器的注册表（不掺字段标签形态，便于定位）。"""
    shapes = load_shapes()
    return RecognizerRegistry(
        [
            VisitNoRecognizer(shapes=shapes.number_shapes),
            PhoneBirthRecognizer(
                phone_shapes=shapes.phone_shapes,
                birth_date_shapes=shapes.birth_date_shapes,
            ),
        ],
        RegistryConfig(global_threshold=0.5),
    )


def _labels(text: str) -> list[str]:
    """跑一遍识别，返回命中的实体类别列表。"""
    return [span.label for span in _registry().analyze(text)]


# ------------------------------------------------------------------ 该命中的命中


def test_inpatient_visit_number_is_detected():
    """住院号：无标签的裸编号也能按形状命中。"""
    spans = _registry().analyze("本次住院流水 90000001 已登记")
    assert [span.label for span in spans] == ["VISIT_NO"]
    assert spans[0].tier is SpanTier.CONFIRMED
    assert spans[0].recognizer == "visit_no"


def test_outpatient_number_with_prefix_is_detected():
    """门诊号：带 MZ 前缀的编号按门诊号形态命中。"""
    spans = _registry().analyze("今日门诊号 MZ123456 已缴费")
    assert [span.label for span in spans] == ["VISIT_NO"]
    assert spans[0].reason == "编号形态命中（门诊号）"


def test_exam_number_with_prefix_is_detected():
    """检查号：带字母前缀的检查流水号按检查号形态命中。"""
    spans = _registry().analyze("本次检查 CHK0000001 已完成采集")
    assert [span.label for span in spans] == ["EXAM_NO"]
    assert spans[0].reason == "编号形态命中（检查号）"


def test_mobile_phone_is_detected():
    """手机号：11 位号段按联系方式形态命中。"""
    spans = _registry().analyze("联系手机 13800138000 核实")
    assert [span.label for span in spans] == ["PHONE"]
    assert spans[0].tier is SpanTier.CONFIRMED


def test_birth_date_with_birth_context_is_detected():
    """出生日期：附近有出生语义词时命中。"""
    spans = _registry().analyze("出生日期 1949-12-31 复核")
    assert [span.label for span in spans] == ["BIRTH_DATE"]
    assert spans[0].tier is SpanTier.CONFIRMED


def test_birth_date_in_chinese_format_is_detected():
    """出生日期：中文写法（1949年12月31日）同样命中。"""
    spans = _registry().analyze("生于1949年12月31日")
    assert [span.label for span in spans] == ["BIRTH_DATE"]


# ------------------------------------------------------- 不该命中的不命中（误伤）


def test_clinical_terms_are_not_matched():
    """疾病名、药品名、科室名一个都不该被当成身份。"""
    text = (
        "科别：呼吸内科　诊断：右肺下叶磨玻璃结节、2 型糖尿病　"
        "用药：盐酸氨溴索口服液 30mL 每日 3 次，布洛芬缓释胶囊 0.3g，阿莫西林胶囊 0.5g　"
        "项目：胸部CT平扫"
    )
    assert _labels(text) == []


def test_clinical_terms_survive_redaction_untouched():
    """最小误伤回归：临床内容在脱敏副本里逐字保留。"""
    text = "科别：呼吸内科　诊断：右肺下叶磨玻璃结节　用药：布洛芬缓释胶囊 0.3g"
    outcome = redact_text(text, "M-误伤回归")
    assert outcome.redacted_text == text
    assert outcome.entries == ()


def test_report_date_is_not_treated_as_birth_date():
    """报告日期与出生日期同形：无出生语义词时不判为出生日期。"""
    assert _labels("报告日期：2026-01-05　报告医师：示例医师") == []


def test_negative_context_wins_over_positive_context():
    """排除语义词优先：同一行里出现「报告日期」时，即便前面有「出生」也不判出生日期。"""
    assert _labels("出生日期 1949-12-31　报告日期 2026-01-05") == ["BIRTH_DATE"]


def test_birth_date_context_does_not_cross_lines():
    """邻近语义不跨行继承：别处的「出生日期」不能让报告日期变成出生日期。"""
    text = "出生日期：1949-12-31\n报告日期：2026-01-05"
    assert _labels(text) == ["BIRTH_DATE"]


def test_longer_number_run_is_not_split():
    """更长的数字串不被从中间切开：11 位号不被拆成 8 位住院号。"""
    assert _labels("流水 12345678901") == []


def test_prefixed_number_is_not_double_counted():
    """带前缀的编号不重复命中：MZ123456 里的数字不再单独判一次住院号。"""
    spans = _registry().analyze("门诊号 MZ123456")
    assert len(spans) == 1


def test_pure_digits_are_not_counted_as_two_shapes():
    """纯数字编号只按一种形态命中一次（门诊号形态要求 MZ 前缀）。"""
    results = VisitNoRecognizer(shapes=load_shapes().number_shapes).analyze(
        "住院流水 90000001"
    )
    assert len(results) == 1
    assert results[0].reason == "编号形态命中（住院号）"


def test_full_width_digits_are_detected():
    """全角数字同样命中（医院系统导出常见全角）。"""
    spans = _registry().analyze("住院号：９００００００１")
    assert [span.label for span in spans] == ["VISIT_NO"]


# ------------------------------------------------------- 形状由策略表驱动


def test_number_shape_comes_from_policy_file(tmp_path):
    """位数约束真的由策略表驱动：改成 9 位后只认 9 位编号。"""
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            number_shapes:
              visit_no:
                enabled: true
                label_zh: 住院号
                entity: VISIT_NO
                score: 0.7
                digit_length: [9, 9]
                prefixes: []
                require_prefix: false
                allow_alphanumeric: false
            contact_shapes:
              phone:
                enabled: true
                shape_type: phone
                label_zh: 手机号
                entity: PHONE
                score: 0.75
                length: 11
                prefixes: ["13", "14", "15", "16", "17", "18", "19"]
              birth_date:
                enabled: true
                shape_type: birth_date
                label_zh: 出生日期
                entity: BIRTH_DATE
                score: 0.7
                separators: ["-"]
                chinese_format: false
                context_window: 16
                context_terms: ["出生日期"]
                negative_terms: []
            """
        ).strip(),
        encoding="utf-8",
    )
    shapes = load_shapes(policy)
    recognizer = VisitNoRecognizer(shapes=shapes.number_shapes)
    results = recognizer.analyze("住院流水 123456789 与 12345678")
    assert len(results) == 1
    assert results[0].label == "VISIT_NO"


def test_invalid_digit_length_raises(tmp_path):
    """位数区间倒置即报错，不静默取默认值。"""
    policy = tmp_path / "bad.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            number_shapes:
              visit_no:
                enabled: true
                label_zh: 住院号
                entity: VISIT_NO
                score: 0.7
                digit_length: [10, 6]
                prefixes: []
                require_prefix: false
                allow_alphanumeric: false
            contact_shapes:
              phone:
                enabled: true
                shape_type: phone
                label_zh: 手机号
                entity: PHONE
                score: 0.75
                length: 11
                prefixes: ["13"]
              birth_date:
                enabled: true
                shape_type: birth_date
                label_zh: 出生日期
                entity: BIRTH_DATE
                score: 0.7
                separators: ["-"]
                context_terms: ["出生日期"]
            """
        ).strip(),
        encoding="utf-8",
    )
    with pytest.raises(ShapeConfigError, match="digit_length"):
        load_shapes(policy)


def test_missing_section_raises(tmp_path):
    """缺整段配置即报错，不当成「本院没有这类编号」。"""
    policy = tmp_path / "partial.yaml"
    policy.write_text("number_shapes: {}\n", encoding="utf-8")
    with pytest.raises(ShapeConfigError, match="contact_shapes"):
        load_shapes(policy)


def test_unknown_shape_key_raises(tmp_path):
    """拼错的键不会被静默忽略。"""
    policy = tmp_path / "typo.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            number_shapes:
              visit_no:
                enabled: true
                label_zh: 住院号
                entity: VISIT_NO
                score: 0.7
                digit_length: [6, 10]
                digt_length: [1, 2]
            contact_shapes:
              phone:
                enabled: true
                shape_type: phone
                label_zh: 手机号
                entity: PHONE
                score: 0.75
                length: 11
                prefixes: ["13"]
              birth_date:
                enabled: true
                shape_type: birth_date
                label_zh: 出生日期
                entity: BIRTH_DATE
                score: 0.7
                separators: ["-"]
                context_terms: ["出生日期"]
            """
        ).strip(),
        encoding="utf-8",
    )
    with pytest.raises(ShapeConfigError, match="未知道具键"):
        load_shapes(policy)


# --------------------------------------------------------- 与主路径的关系


def test_default_registry_includes_pattern_forms():
    """默认装配含正则形态：编号与联系方式都在主路径的识别段里。"""
    registry = build_default_registry()
    identifiers = {recognizer.id for recognizer in registry.get_recognizers()}
    assert {"labeled_field", "visit_no", "phone_birth"} <= identifiers


def test_pattern_form_hits_are_recorded_without_raw_text():
    """正则形态的命中也进清单，且清单不带命中原文。"""
    outcome = redact_text("住院流水 90000001 联系 13800138000", "M-正则形态")
    labels = [entry.label for entry in outcome.entries]
    assert "VISIT_NO" in labels
    assert "PHONE" in labels
    for entry in outcome.entries:
        assert "90000001" not in entry.reason
        assert "13800138000" not in entry.reason
