"""就诊编号识别器（正则形态）：住院号 / 门诊号 / 检查号。

对应源产品的正则形态识别器（``PatternRecognizer``：按标签给若干正则、整段扫描
取全部命中）。本轮把它改写为医院场景的**形状约束**驱动：位数、前缀、字符集
写在 ``policy/research.yaml``（见 :mod:`research_redact.recognizers.shapes`），
识别器按配置生成正则 —— 不同医院住院号位数与前缀写法不同，改 YAML 即可。

与其它形态的关系：

- **字段标签形态**（``labeled_field``）管「住院号：90000001」这种带标签的写法，
  命中的是标签后面那个值，信号更强；
- 本形态管**没有标签**的裸编号（表格里一列住院号、正文里的检查流水号），
  靠形状与上下文判断；
- **名单形态**（task 17，主索引读回）管「这个串确实属于某个患者」，
  是权威依据；本形态只是形状证据。

**为什么检查号要求前缀**：裸数字串在住院号与检查号之间字面无差别 —— 同样是
8 位数字，硬判必然两头都错。本轮的处理是：住院号形态收纯数字 6–10 位；
检查号形态要求带字母前缀（PACS 申请号 / 检查流水号的常见写法），
纯数字的检查号交给带标签的形态与 task 19 的邻近词消歧，不在这里硬猜。

**task 19 起加的两道闸**（边界判定，见 ``recognizers/numeric_boundary.py``）：

1. **数字语义消歧** —— 剂量（30mL）、金额（245000.00 元）、页码、床号、序号、
   日期片段压根不是身份候选，不进入命中列表（脱过头是事故：把剂量当住院号抹掉，
   临床数据就失真了）；
2. **上下文要求** —— 住院号 / 检查号的命中，附近必须有编号类上下文词；没有就
   **降为告警档**：不改写正文，但进命中清单等人抽检。

**不变量**：命中原文不得进入 ``reason``（``reason`` 会原样写进命中清单）。
"""

from __future__ import annotations

from typing import Any, Sequence

from ..models import RecognizerResult
from .base import Recognizer
from .numeric_boundary import NumericBoundary, load_numeric_boundary_config
from .shapes import NumberShape, load_shapes

__all__ = ["VisitNoRecognizer"]


class VisitNoRecognizer(Recognizer):
    """就诊编号识别器：按形状约束识别住院号 / 门诊号 / 检查号。

    :param shapes: 编号形态约束；缺省从策略表装载。
    :param score_thresholds: 逐类别阈值覆盖（形如 ``{"VISIT_NO": 0.7}``）。
    :param boundary: 数字类歧义消解器；缺省从策略表装载。
    """

    def __init__(
        self,
        recognizer_id: str = "visit_no",
        name: str = "就诊编号识别器",
        shapes: Sequence[NumberShape] | None = None,
        score_thresholds: dict[str, float] | None = None,
        available: bool = True,
        boundary: NumericBoundary | None = None,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        self.shapes = tuple(shapes if shapes is not None else load_shapes().number_shapes)
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = tuple(dict.fromkeys(shape.entity for shape in self.shapes))
        self._available = available
        self._boundary = (
            boundary
            if boundary is not None
            else NumericBoundary(load_numeric_boundary_config())
        )
        self._compiled: list[tuple[NumberShape, object]] = [
            (shape, shape.build_pattern()) for shape in self.shapes if shape.enabled
        ]

    def is_available(self) -> bool:
        return self._available

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        """扫描文本，产出命中列表。

        同一段文本可能被多个形态同时命中（如带前缀的门诊号），由注册表
        （``recognizers/registry.py``）统一裁决去重与档位。
        """
        wanted = set(entities) if entities else None
        results: list[RecognizerResult] = []
        for shape, pattern in self._compiled:
            if wanted is not None and shape.entity not in wanted:
                continue
            for match in pattern.finditer(text):
                start, end = match.span()
                if end <= start:
                    continue
                # 剂量 / 金额 / 页码 / 床号 / 序号 / 日期片段：不是身份候选
                if self._boundary.classify(text, start, end) is not None:
                    continue
                metadata: dict[str, Any] = {"shape": shape.kind}
                if self._boundary.requires_context(
                    shape.entity
                ) and not self._boundary.has_context(text, start, end):
                    # 附近没有编号类上下文词：不敢确定是住院号 —— 降为告警档，
                    # 不改写正文（改写会脱过头），但进命中清单等人抽检。
                    metadata["force_warning"] = True
                    metadata["boost_allowed"] = False
                    metadata["boundary"] = "no_context"
                    metadata["warning_note"] = (
                        "附近没有编号类上下文词，降为告警档（不判定为身份）"
                    )
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=shape.entity,
                        score=shape.score,
                        reason=f"编号形态命中（{shape.label_zh}）",
                        recognizer=self.id,
                        metadata=metadata,
                    )
                )
        return results
