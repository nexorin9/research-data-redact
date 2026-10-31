"""数字类歧义消解验收：剂量 / 金额 / 页码 / 床号 / 序号不得判为编号。

对应 task 19「数字类识别器边界治理」。本测试守住三件事：

1. **不该判为身份的不能判** —— 剂量、金额、页码、床号、序号、日期片段在脱敏
   副本里逐字保留（脱过头是事故：把剂量当住院号抹掉，临床数据就失真了）；
2. **该判的还得判** —— 带编号类上下文词的住院号 / 检查号仍然命中，且达阈值；
3. **边界规则由策略表驱动** —— 改 YAML 就改行为，不改代码；配置非法即报错。

无上下文的编号候选（形状像、语义不明）**降为告警档**：不改写正文，但进命中
清单等人抽检 —— 漏脱与误脱都留痕，谁也不替人做决定。
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from research_redact.daemon.pipeline import redact_text
from research_redact.models import SpanTier
from research_redact.recognizers.context_boost import ContextBooster, load_context_config
from research_redact.recognizers.numeric_boundary import (
    NumericBoundary,
    NumericBoundaryConfigError,
    load_numeric_boundary_config,
)
from research_redact.recognizers.phone_birth import PhoneBirthRecognizer
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig
from research_redact.recognizers.shapes import load_shapes
from research_redact.recognizers.visit_no import VisitNoRecognizer


# --------------------------------------------------------------- 工具


#: 策略表模板：编号形态 + 联系方式形态 + 数字类消歧段。
#: 模板写在第 0 列（不用 dedent）—— 数字类消歧段是插进来的，缩进层级不一致时
#: dedent 的公共前缀会算空，整份 YAML 就废了。
_POLICY_TEMPLATE = """number_shapes:
  visit_no:
    enabled: true
    label_zh: 住院号
    entity: VISIT_NO
    score: 0.7
    digit_length: [{low}, {high}]
    prefixes: []
    require_prefix: false
    allow_alphanumeric: false
  exam_no:
    enabled: true
    label_zh: 检查号
    entity: EXAM_NO
    score: 0.7
    digit_length: [6, 14]
    prefixes: ["CHK"]
    require_prefix: true
    allow_alphanumeric: true
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
    context_window: 16
    context_terms: ["出生日期", "出生", "生于"]
    negative_terms: ["报告日期", "检查日期"]
numeric_boundary:
{boundary}
"""

#: 默认的数字类消歧段（与项目内策略表同口径）。
_DEFAULT_BOUNDARY = """dose_units: ["mg", "mL", "片", "袋", "IU", "次", "ml"]
currency_marks: ["元", "￥", "¥"]
page_markers: ["页", "第"]
bed_markers: ["床"]
date_markers: ["年", "月", "日"]
sequence_markers: ["序号"]
require_context: true
window: 16
context_terms: ["住院号", "住院", "检查号", "检查", "患者"]
"""


def _write_policy(
    path: Path,
    digit_length: tuple[int, int] = (6, 10),
    numeric_boundary: str | None = None,
) -> Path:
    """写一份策略表：编号形态 + 联系方式形态 + 数字类消歧段。"""
    boundary = numeric_boundary if numeric_boundary is not None else _DEFAULT_BOUNDARY
    path.write_text(
        _POLICY_TEMPLATE.format(
            low=digit_length[0],
            high=digit_length[1],
            boundary=textwrap.indent(boundary.strip(), "  "),
        ),
        encoding="utf-8",
    )
    return path


def _registry(policy_path: Path | None = None) -> RecognizerRegistry:
    """只装两个正则形态识别器的注册表（不掺字段标签形态，便于定位）。"""
    shapes = load_shapes(policy_path)
    boundary = NumericBoundary(load_numeric_boundary_config(policy_path))
    return RecognizerRegistry(
        [
            VisitNoRecognizer(shapes=shapes.number_shapes, boundary=boundary),
            PhoneBirthRecognizer(
                phone_shapes=shapes.phone_shapes,
                birth_date_shapes=shapes.birth_date_shapes,
                boundary=boundary,
            ),
        ],
        RegistryConfig(global_threshold=0.5),
    )


def _labels(text: str, policy_path: Path | None = None) -> list[str]:
    """跑一遍识别，返回命中的实体类别列表。"""
    return [span.label for span in _registry(policy_path).analyze(text)]


# ------------------------------------------------- 剂量 / 金额：不得判为编号


def test_剂量不被判为住院号():
    """大剂量单位后面的数字不是住院号（剂量单位不看位数）。"""
    assert _labels("维生素 D 1000000 IU 一次") == []
    assert _labels("用药 500 mg 每日 3 次") == []


def test_金额不被判为住院号():
    """金额是六七位数 —— 正是最像住院号的那一档，必须挡住。"""
    assert _labels("本次费用 245000.00 元") == []
    assert _labels("住院总费用 128000 元") == []


def test_剂量与金额在脱敏副本里逐字保留():
    """最小误伤回归：剂量与金额逐字保留，不被替换成占位符。"""
    text = "用药 盐酸氨溴索口服液 30mL 每日 3 次，本次费用 2450.00 元"
    outcome = redact_text(text, "M-剂量金额")
    assert outcome.redacted_text == text
    assert outcome.entries == ()


def test_金额小数部分不影响判定():
    """金额写成 245000.00 元：小数部分一起跳过，仍然判为金额。"""
    assert _labels("合计 245000.00 元") == []
    assert _labels("合计 245000元") == []


# --------------------------------------------- 页码 / 床号 / 序号：不得判为编号


def test_页码不被判为住院号(tmp_path: Path):
    """页码不是住院号（策略表把位数放宽到 1 位起，页码才可能撞上形状）。"""
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 12))
    assert _labels("（本页为第 2 页）", policy) == []
    assert _labels("第 12 页", policy) == []


def test_床号不被判为住院号(tmp_path: Path):
    """床号不是住院号。"""
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 12))
    assert _labels("床位 12床", policy) == []
    assert _labels("床号：12", policy) == []


def test_序号不被判为住院号(tmp_path: Path):
    """序号不是住院号。"""
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 12))
    assert _labels("序号 3", policy) == []
    assert _labels("第 3 次复查", policy) == []


def test_长数字不被当成页码床号放过(tmp_path: Path):
    """六位以上的数字出现在床位 / 页码语境时仍按编号候选判（漏脱比脱过头更糟）。

    「床位 90000001」这种句子现实里不会出现，但真住院号被当成床号放过就是漏脱 ——
    宁可多脱一次。
    """
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 12))
    spans = _registry(policy).analyze("床位 90000001")
    assert [span.label for span in spans] == ["VISIT_NO"]


# --------------------------------------------- 连字符复合标识与日期片段


def test_连字符写法的证件号不被拆判():
    """分段写的证件号不该被拆出「住院号」那一段（拆了就是脱过头 + 漏脱两头都占）。"""
    assert _labels("证件号 110101-19491231002") == []


def test_连字符写法的证件号两侧都不判为编号(tmp_path: Path):
    """前半段与后半段都挡住：只挡一半等于把证件号拆出来判（两头都占）。"""
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 14))
    assert _labels("证件号 110101-19491231002", policy) == []


def test_ISO写法日期整串不被判为编号(tmp_path: Path):
    """2026-01-05 三段都是日期片段，不该有任何一段被判成编号。"""
    policy = _write_policy(tmp_path / "policy.yaml", digit_length=(1, 14))
    assert _labels("检查日期 2026-01-05", policy) == []


def test_序号后缀不被当成复合标识():
    """连字符另一侧只有 1–3 位数字时是序号后缀，前一段仍按编号候选判。"""
    spans = _registry().analyze("90000001-1")
    assert [span.label for span in spans] == ["VISIT_NO"]


def test_紧邻年月日的数字判为日期片段():
    """日期片段不是编号。"""
    assert _labels("2026年") == []


# --------------------------------------------- 该判的还得判（上下文要求）


def test_带上下文词的住院号命中并达阈值():
    """住院号附近有编号类上下文词 → 确认档。"""
    spans = _registry().analyze("本次住院流水 90000001 已登记")
    assert [span.label for span in spans] == ["VISIT_NO"]
    assert spans[0].tier is SpanTier.CONFIRMED
    assert spans[0].score >= 0.5


def test_带上下文词的检查号命中并达阈值():
    """检查号附近有编号类上下文词 → 确认档。"""
    spans = _registry().analyze("本次检查 CHK0000001 已完成采集")
    assert [span.label for span in spans] == ["EXAM_NO"]
    assert spans[0].tier is SpanTier.CONFIRMED
    assert spans[0].score >= 0.5


def test_无上下文词的住院号降为告警档():
    """形状像、语义不明 → 降为告警档：进清单但不改写正文。"""
    spans = _registry().analyze("登记流水 90000001")
    assert [span.label for span in spans] == ["VISIT_NO"]
    assert spans[0].tier is SpanTier.WARNING
    assert "没有编号类上下文词" in spans[0].reason


def test_告警档的编号不改写正文但进命中清单():
    """降档不等于丢弃：正文留着，命中清单里看得见（漏脱要留痕）。"""
    outcome = redact_text("登记流水 90000001", "M-无上下文")
    assert outcome.redacted_text == "登记流水 90000001"
    assert len(outcome.entries) == 1
    assert outcome.entries[0].tier == "warning"
    assert outcome.entries[0].action == "none（告警档，未改写）"
    assert outcome.rewritten == 0


def test_邻近上下文加分不得把告警档抬成确认档():
    """告警档是「已经判定证据不足」，邻近窗口的上下文词也不许把它抬成确认档。

    这里的「附近」用的是**上下文加分**的词表（年龄 / 性别 …），与数字类消歧的
    编号类词表不是同一份 —— 所以这一处既够不着编号类上下文词，又落在加分窗口内。
    """
    shapes = load_shapes()
    boundary = NumericBoundary(load_numeric_boundary_config())
    registry = RecognizerRegistry(
        [VisitNoRecognizer(shapes=shapes.number_shapes, boundary=boundary)],
        RegistryConfig(
            global_threshold=0.9,
            per_recognizer_thresholds={"visit_no": 0.9},
        ),
        booster=ContextBooster(load_context_config()),
    )
    spans = registry.analyze("年龄 65 90000001")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert spans[0].score < 0.9


def test_窗口之外的上下文词不算数():
    """上下文词必须邻近：隔得远的不算数。"""
    spans = _registry().analyze("住院号" + "甲" * 40 + "90000001")
    assert spans[0].tier is SpanTier.WARNING


# --------------------------------------------- 策略表驱动与配置校验


def test_消歧规则由策略表驱动(tmp_path: Path):
    """改 YAML 就改行为：把剂量单位换掉，判定跟着换。

    两侧用**同一份编号形态**（位数放宽到 1 位起，否则 500 这种短数字压根不是
    候选，「mg 不再是剂量单位」这半句就是空话），只换消歧段：默认口径下两个
    数字都是剂量、压根不进命中列表；改掉剂量单位后它们回到编号候选。
    """
    default_policy = _write_policy(tmp_path / "default.yaml", digit_length=(1, 12))
    changed_policy = _write_policy(
        tmp_path / "changed.yaml",
        digit_length=(1, 12),
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["g"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: true
            window: 16
            context_terms: ["住院号", "住院"]
            """
        ).strip(),
    )
    # 默认口径：mg / IU 都是剂量单位 → 这两个数字不是身份候选
    assert _labels("维生素 D 1000000 IU 一次", default_policy) == []
    assert _labels("用药 500 mg", default_policy) == []
    # 改 YAML：剂量单位换掉 → 判定跟着换
    # 新配置里没有 IU —— 大剂量数字不再被排除
    labels = _labels("维生素 D 1000000 IU 一次", changed_policy)
    assert "VISIT_NO" in labels
    # 而 mg 也不再是剂量单位
    labels = _labels("用药 500 mg", changed_policy)
    assert "VISIT_NO" in labels


def test_位数阈值由策略表驱动(tmp_path: Path):
    """页码 / 床号只对小数字生效 —— 阈值由策略表给，改 YAML 就改行为。"""
    wide = _write_policy(
        tmp_path / "wide.yaml",
        digit_length=(1, 12),
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: false
            window: 16
            context_terms: []
            short_number_max_digits: 6
            """
        ).strip(),
    )
    # 阈值放宽到 6 位 → 「12床」这种小数字仍按床号放过
    assert _labels("床位 12床", wide) == []
    narrow = _write_policy(
        tmp_path / "narrow.yaml",
        digit_length=(1, 12),
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: false
            window: 16
            context_terms: []
            short_number_max_digits: 1
            """
        ).strip(),
    )
    # 阈值收紧到 1 位 → 12 不再算小数字，按编号候选判（宁可多脱一次）
    assert _labels("床位 12床", narrow) == ["VISIT_NO"]


def test_复合标识位数阈值由策略表驱动(tmp_path: Path):
    """连字符另一侧要有多少位才算复合标识的一段 —— 阈值由策略表给。

    判定是**逐候选**的：一段算不算复合标识，取决于**另一侧**够不够长。
    所以「序号后缀」（90000001-1）的前一段仍按编号判 —— 另一侧太短。
    """
    strict = _write_policy(
        tmp_path / "strict.yaml",
        digit_length=(1, 14),
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: false
            window: 16
            context_terms: []
            composite_min_digits: 8
            """
        ).strip(),
    )
    # 另一侧只有 6 位、不到 8 位 → 不算复合标识，按编号候选判
    assert _labels("123456-654321", strict) == ["VISIT_NO", "VISIT_NO"]
    loose = _write_policy(
        tmp_path / "loose.yaml",
        digit_length=(1, 14),
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: false
            window: 16
            context_terms: []
            composite_min_digits: 4
            """
        ).strip(),
    )
    # 阈值放宽到 4 位 → 整串是一个复合标识，两段都不判为编号
    assert _labels("123456-654321", loose) == []


def test_位数阈值非法报错(tmp_path: Path):
    """位数阈值必须是正整数。"""
    policy = _write_policy(
        tmp_path / "policy.yaml",
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            require_context: true
            window: 16
            context_terms: ["住院号"]
            short_number_max_digits: 0
            """
        ).strip(),
    )
    with pytest.raises(NumericBoundaryConfigError, match="short_number_max_digits"):
        load_numeric_boundary_config(policy)


def test_关闭上下文要求后无上下文的编号判为确认档(tmp_path: Path):
    """require_context 关掉 → 形状像就算身份候选。"""
    policy = _write_policy(
        tmp_path / "policy.yaml",
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg", "IU"]
            currency_marks: ["元"]
            page_markers: ["页"]
            bed_markers: ["床"]
            require_context: false
            window: 16
            context_terms: []
            """
        ).strip(),
    )
    spans = _registry(policy).analyze("登记流水 90000001")
    assert spans[0].tier is SpanTier.CONFIRMED


def test_未知道具键报错(tmp_path: Path):
    """拼错的键不会被静默忽略。"""
    policy = _write_policy(
        tmp_path / "policy.yaml",
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            require_context: true
            window: 16
            context_terms: ["住院号"]
            dose_unit: ["g"]
            """
        ).strip(),
    )
    with pytest.raises(NumericBoundaryConfigError, match="未知道具键"):
        load_numeric_boundary_config(policy)


def test_缺整段报错(tmp_path: Path):
    """缺 numeric_boundary 段即报错，不当成「本院没有这类数字」。"""
    policy = tmp_path / "policy.yaml"
    policy.write_text("number_shapes: {}\n", encoding="utf-8")
    with pytest.raises(NumericBoundaryConfigError, match="缺少 numeric_boundary"):
        load_numeric_boundary_config(policy)


def test_窗口半径非法报错(tmp_path: Path):
    """窗口半径必须是正整数。"""
    policy = _write_policy(
        tmp_path / "policy.yaml",
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            require_context: true
            window: 0
            context_terms: ["住院号"]
            """
        ).strip(),
    )
    with pytest.raises(NumericBoundaryConfigError, match="window"):
        load_numeric_boundary_config(policy)


def test_要求上下文却没有词表报错(tmp_path: Path):
    """require_context 为真却没给词表 → 全部编号都会降档，必须报错而不是放行。"""
    policy = _write_policy(
        tmp_path / "policy.yaml",
        numeric_boundary=textwrap.dedent(
            """
            dose_units: ["mg"]
            currency_marks: ["元"]
            require_context: true
            window: 16
            context_terms: []
            """
        ).strip(),
    )
    with pytest.raises(NumericBoundaryConfigError, match="context_terms"):
        load_numeric_boundary_config(policy)


# --------------------------------------------- 主路径接线


def test_主路径上剂量金额不被改写():
    """主路径（默认装配）上剂量与金额同样逐字保留。"""
    text = "用药 盐酸氨溴索口服液 30mL 每日 3 次，住院总费用 245000.00 元"
    outcome = redact_text(text, "M-主路径")
    assert outcome.redacted_text == text
    assert outcome.entries == ()


def test_主路径上真实住院号仍被脱敏():
    """消歧不是把编号一并放过：带上下文的住院号照常脱敏。"""
    outcome = redact_text("住院号：90000001  科别：呼吸内科", "M-主路径")
    assert "90000001" not in outcome.redacted_text
    assert "VISIT_NO" in [entry.label for entry in outcome.entries]


def test_命中清单不含命中原文():
    """边界判定与降档都不得把命中原文写进解释。"""
    outcome = redact_text("登记流水 90000001", "M-无上下文")
    payload = "\n".join(entry.reason for entry in outcome.entries)
    assert "90000001" not in payload
