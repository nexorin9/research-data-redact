"""字段标签驱动形态识别器：标签 + 分隔符 + 值 → 命中「标签后面那个值」。

源产品的识别层只有三种形态（正则 / 校验位 / 名单）。本轮新增第四种
**结构绑定**形态：放射与检验报告的表头字段（「姓名：」「住院号：」「检查号：」）
本身给出了值的语义 —— 把值与标签绑在一起比「按形状猜」准，也不必等患者
主索引读回名单就能先跑通主路径。

与后续任务的关系（互补，不重复）：

- task 4 落「正则形态」：不依赖标签出现，按位数 / 前缀约束识别编号；
- task 17 落「名单形态」：主索引主键绑定，单独姓名一律降告警档；
- task 18 落「校验位形态」：身份证 GB 11643 校验位。

本形态只在**标签出现**时命中；标签不出现就交还给上面三种形态。
本形态**不覆盖身份证** —— 校验位语义由 task 18 独占，避免与「校验位不通过
降告警档」规则打架。

**不变量**：命中原文（字段值）不得进入 ``reason``，否则会随命中清单外泄。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from ..models import RecognizerResult
from .base import Recognizer

__all__ = ["DEFAULT_FIELDS", "FIELD_BOUNDARY_KEYWORDS", "FieldSpec", "LabeledFieldRecognizer"]


# 字段边界词：中文姓名后常紧跟下一个字段（「姓名：张某某性别：男」），
# 取值时在此切断，避免把下一个字段一起脱掉（脱过头）。
FIELD_BOUNDARY_KEYWORDS: tuple[str, ...] = (
    "性别",
    "年龄",
    "科别",
    "科室",
    "病区",
    "床号",
    "床位",
    "电话",
    "手机",
    "身份证",
    "出生",
    "检查",
    "诊断",
    "意见",
    "建议",
    "主诉",
    "现病史",
    "既往史",
    "过敏史",
    "备注",
    "报告",
    "医师",
    "医生",
    "先生",
    "女士",
    "住院",
    "门诊",
    "民族",
    "籍贯",
    "职业",
    "婚姻",
    "序号",
    "页",
)


@dataclass(frozen=True)
class FieldSpec:
    """一个字段的识别规格。

    :param entity: 命中后给出的实体类别。
    :param labels: 该字段在报告里可能出现的标签写法（正则里按长度降序交替）。
    :param value_pattern: 字段值的正则。
    :param score: 命中基础分数（标签驱动属强信号，默认高于全局阈值）。
    :param trim_at_field_boundary: 取值是否按字段边界词切断（中文姓名用）。
    """

    entity: str
    labels: tuple[str, ...]
    value_pattern: str
    score: float = 0.85
    trim_at_field_boundary: bool = False


DEFAULT_FIELDS: tuple[FieldSpec, ...] = (
    FieldSpec(
        entity="PATIENT_NAME",
        labels=("受检者姓名", "患者姓名", "病人姓名", "姓名"),
        value_pattern=r"[一-龥·]{2,8}",
        trim_at_field_boundary=True,
    ),
    FieldSpec(
        entity="VISIT_NO",
        labels=("住院流水号", "住院号", "病案号", "病历号", "门诊号"),
        value_pattern=r"[A-Za-z0-9][A-Za-z0-9\-]{3,19}",
    ),
    FieldSpec(
        entity="EXAM_NO",
        labels=("检查流水号", "检查号", "申请号", "登记号"),
        value_pattern=r"[A-Za-z0-9][A-Za-z0-9\-]{3,19}",
    ),
    FieldSpec(
        entity="PHONE",
        labels=("手机号码", "手机号", "联系电话", "手机"),
        value_pattern=r"1\d{10}(?!\d)",
    ),
    FieldSpec(
        entity="BIRTH_DATE",
        labels=("出生日期", "出生年月", "生日"),
        value_pattern=r"\d{4}[-/年]\d{1,2}[-/月]\d{1,2}日?(?!\d)",
    ),
)


class LabeledFieldRecognizer(Recognizer):
    """字段标签驱动形态识别器。

    命中区间只覆盖**字段值**（标签本身不在命中范围内）—— 标签是结构信息，
    不是患者身份数据。
    """

    def __init__(
        self,
        recognizer_id: str = "labeled_field",
        name: str = "字段标签识别器",
        fields: Sequence[FieldSpec] = DEFAULT_FIELDS,
        score_thresholds: dict[str, float] | None = None,
        available: bool = True,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        self.fields = tuple(fields)
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = tuple(dict.fromkeys(spec.entity for spec in self.fields))
        self._available = available
        self._compiled: list[tuple[FieldSpec, re.Pattern[str]]] = []
        for spec in self.fields:
            label_alt = "|".join(
                re.escape(label)
                for label in sorted(spec.labels, key=len, reverse=True)
            )
            # 标签与取值之间不允许跨行：取值必须与标签同行，避免把下一行的内容接上
            pattern = rf"(?P<label>{label_alt})[ \t]*[:：]?[ \t]*(?P<value>{spec.value_pattern})"
            self._compiled.append((spec, re.compile(pattern)))

    def is_available(self) -> bool:
        return self._available

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        wanted = set(entities) if entities else None
        results: list[RecognizerResult] = []
        for spec, pattern in self._compiled:
            if wanted is not None and spec.entity not in wanted:
                continue
            for match in pattern.finditer(text):
                start, end = match.span("value")
                if spec.trim_at_field_boundary:
                    end = self._trimmed_end(text, start, end)
                if end <= start:
                    continue
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=spec.entity,
                        score=spec.score,
                        reason=f"字段标签命中（{match.group('label')}）",
                        recognizer=self.id,
                    )
                )
        return results

    @staticmethod
    def _trimmed_end(text: str, start: int, end: int) -> int:
        """按字段边界词把取值截短（中文姓名常紧跟下一个字段）。"""
        raw = text[start:end]
        cut = len(raw)
        for keyword in FIELD_BOUNDARY_KEYWORDS:
            index = raw.find(keyword)
            if index != -1 and index < cut:
                cut = index
        if cut < 2:  # 截得太短说明不是姓名，放弃这次命中
            return start
        return start + cut
