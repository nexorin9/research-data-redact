"""联系方式与出生日期识别器（正则形态）：手机号 + 出生日期。

对应源产品的正则形态识别器（``PatternRecognizer``），本轮改写为形状约束驱动
（位数与号段写在 ``policy/research.yaml``，见 :mod:`research_redact.recognizers.shapes`）。

**手机号**：11 位、号段前缀写在策略表里（13x–19x），边界不吃进更长的数字串。

**出生日期**：与手机号不同 —— 一条裸日期**不足以**判为出生日期。报告日期、
检查日期、检验日期与出生日期在字面上完全同形，硬判必然把报告日期当成患者
出生日期（脱过头），漏判反而更隐蔽（机构看不出来）。因此本形态要求：

1. 命中附近（同一行、窗口内）出现「出生 / 生日 / 生于」等**正向语义词**；
2. 附近**不出现**「报告日期 / 入院日期 / 送检日期」等**排除语义词**。

两条都不满足就**不产出命中**（不是降档、不是静默放过 —— 这条日期根本不是
身份类信息，留在正文里无害）。带标签的写法（「出生日期：1949-12-31」）由字段
标签形态负责，本形态只补没有标签、只有语义词的那一类。

**task 19 起加的一道闸**（边界判定，见 ``recognizers/numeric_boundary.py``）：
手机号候选先过数字类歧义消解 —— 紧邻剂量单位 / 货币符号 / 页码床号的数字不判为
手机号。出生日期**不适用**这条判定（日期本身就是日期语义，恰恰是要识别的那一类）。

**不变量**：命中原文不得进入 ``reason``（``reason`` 会原样写进命中清单）。
"""

from __future__ import annotations

from typing import Sequence

from ..models import RecognizerResult
from .base import Recognizer
from .numeric_boundary import NumericBoundary, load_numeric_boundary_config
from .shapes import BirthDateShape, PhoneShape, load_shapes

__all__ = ["PhoneBirthRecognizer"]


class PhoneBirthRecognizer(Recognizer):
    """联系方式识别器：手机号 + 出生日期。

    :param phone_shapes: 手机号形态约束；缺省从策略表装载。
    :param birth_date_shapes: 出生日期形态约束；缺省从策略表装载。
    :param boundary: 数字类歧义消解器；缺省从策略表装载。
    """

    def __init__(
        self,
        recognizer_id: str = "phone_birth",
        name: str = "联系方式识别器",
        phone_shapes: Sequence[PhoneShape] | None = None,
        birth_date_shapes: Sequence[BirthDateShape] | None = None,
        score_thresholds: dict[str, float] | None = None,
        available: bool = True,
        boundary: NumericBoundary | None = None,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        if phone_shapes is None or birth_date_shapes is None:
            shapes = load_shapes()
            phone_shapes = shapes.phone_shapes if phone_shapes is None else phone_shapes
            birth_date_shapes = (
                shapes.birth_date_shapes if birth_date_shapes is None else birth_date_shapes
            )
        self.phone_shapes = tuple(phone_shapes)
        self.birth_date_shapes = tuple(birth_date_shapes)
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = tuple(
            dict.fromkeys(
                [shape.entity for shape in self.phone_shapes]
                + [shape.entity for shape in self.birth_date_shapes]
            )
        )
        self._available = available
        self._boundary = (
            boundary
            if boundary is not None
            else NumericBoundary(load_numeric_boundary_config())
        )
        self._phone_patterns = [
            (shape, shape.build_pattern()) for shape in self.phone_shapes if shape.enabled
        ]
        self._birth_patterns = [
            (shape, pattern)
            for shape in self.birth_date_shapes
            if shape.enabled
            for pattern in shape.build_patterns()
        ]

    def is_available(self) -> bool:
        return self._available

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        """扫描文本，产出命中列表。"""
        wanted = set(entities) if entities else None
        results: list[RecognizerResult] = []

        for shape, pattern in self._phone_patterns:
            if wanted is not None and shape.entity not in wanted:
                continue
            for match in pattern.finditer(text):
                start, end = match.span()
                if end <= start:
                    continue
                # 数字类歧义消解：紧邻剂量 / 金额 / 页码床号的数字不是手机号
                if self._boundary.classify(text, start, end) is not None:
                    continue
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=shape.entity,
                        score=shape.score,
                        reason=f"联系方式形态命中（{shape.label_zh}）",
                        recognizer=self.id,
                        metadata={"shape": shape.kind},
                    )
                )

        for shape, pattern in self._birth_patterns:
            if wanted is not None and shape.entity not in wanted:
                continue
            for match in pattern.finditer(text):
                start, end = match.span()
                if end <= start:
                    continue
                if not self._is_birth_date_context(text, start, end, shape):
                    continue
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=shape.entity,
                        score=shape.score,
                        reason=f"日期形态命中（{shape.label_zh}，邻近语义词）",
                        recognizer=self.id,
                        metadata={"shape": shape.kind},
                    )
                )
        return results

    # ------------------------------------------------------------------ 内部

    @staticmethod
    def _is_birth_date_context(
        text: str, start: int, end: int, shape: BirthDateShape
    ) -> bool:
        """判断这条日期是否带出生语义。

        语义词写在日期**前面**（「出生日期 1990-01-01」「生于1990年1月1日」）
        或紧跟在后面（「1990-01-01 出生」）。两侧都查，但排除语义词只在
        **前面**一侧生效 —— 否则同一行里跟在出生日期后面的「报告日期」
        会把真正的出生日期一起否掉。
        """
        line_start = text.rfind("\n", 0, start) + 1
        before = text[max(line_start, start - shape.context_window) : start]
        after_end = text.find("\n", end)
        if after_end == -1:
            after_end = len(text)
        after = text[end : min(after_end, end + shape.context_window)]
        if any(term in before for term in shape.negative_terms):
            return False
        return any(term in before or term in after for term in shape.context_terms)
