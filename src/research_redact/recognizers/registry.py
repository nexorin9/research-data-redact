"""识别器注册表：装配 → 逐识别器打分 → 上下文加分 → 阈值过滤 → 重叠去重 → 白名单放行。

这一段沿用源产品分析引擎的主路径顺序（注册表 → 逐识别器打分 → **上下文加分** →
阈值过滤 → 去重 → 白名单），改写为项目内自有确定性实现（不引语言模型）。三处刻意不同：

1. **低于阈值的命中不丢弃**，降为告警档（``warning``）并写明阈值差距，
   由调用方决定是否计入残留统计 —— 漏检与误检都要留痕，不能悄悄消失。
2. **白名单命中的区间不丢弃**，降为放行档（``allowed``）——
   放行也是一条要人工抽检的事实，须在命中清单中可见。
3. **上下文加分封顶在门槛上**（``recognizers/context_boost.py``）——
   加分只可能把告警档抬成确认档，不会把已确认的分数推得更高，
   也不会绕过更严的逐识别器阈值。
4. **识别器可以显式要求降档**（``metadata["force_warning"]``）——
   「形状像但证据不足」的命中（如 task 19 的数字类歧义消解：附近没有编号类
   上下文词的住院号候选）不论分数多高都只进告警档：分数够高只说明「形状像」，
   不代表「确实是住院号」。

跨识别器的**部分重叠 / 包含 / 交叉 / 完全重合**裁决不在本模块：那是实体级统一
裁决（``research_redact.arbitration``）的事，这里只负责「同一段、同一实体类别」
的重复命中折叠。两者的分界很要紧：**同一实体类别**被两个识别器各命中一次，
是同一个实体被看见两遍，折叠掉一份；**不同实体类别**落在同一段正文上，
是两类实体争同一段，该由统一裁决按档位优先级定案（身份类优先于就诊编号类），
不能在这里按分数悄悄决定 —— 住院号 0.95 分压过身份证 0.60 分时，主索引绑定
会随之丢失，一致代号就不一致了。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Iterable, Sequence

from ..arbitration import fold_exact_duplicates
from ..models import EntitySpan, RecognizerResult, SpanTier
from .base import Recognizer
from .context_boost import ContextBooster

__all__ = ["RecognizerRegistry", "RegistryConfig"]


@dataclass(frozen=True)
class RegistryConfig:
    """注册表配置。

    :param global_threshold: 全局阈值，低于它降为告警档。
    :param per_recognizer_thresholds: 逐识别器阈值覆盖，键为识别器 ID；
        命中即覆盖该识别器的全部类别阈值（policy/research.yaml 的
        ``thresholds.per_recognizer``）。
    :param allow_list_exact: 白名单精确项。
    :param allow_list_regex: 白名单正则项。
    """

    global_threshold: float = 0.5
    per_recognizer_thresholds: dict[str, float] = field(default_factory=dict)
    allow_list_exact: tuple[str, ...] = ()
    allow_list_regex: tuple[str, ...] = ()


class RecognizerRegistry:
    """识别器注册表：装配识别器并按阈值 / 去重 / 白名单裁决命中。

    :param recognizers: 识别器清单。
    :param config: 阈值与白名单配置。
    :param booster: 邻近窗口上下文加分器；缺省不加分。
    """

    def __init__(
        self,
        recognizers: Iterable[Recognizer] | None = None,
        config: RegistryConfig | None = None,
        booster: ContextBooster | None = None,
    ) -> None:
        self._recognizers: list[Recognizer] = []
        self._config = config or RegistryConfig()
        self._booster = booster
        for recognizer in recognizers or ():
            self.register(recognizer)
        self._allow_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self._config.allow_list_regex
            if pattern
        ]

    @property
    def booster(self) -> ContextBooster | None:
        """当前装配的上下文加分器（未装配时为 None）。"""
        return self._booster

    @property
    def boost_terms(self) -> tuple[str, ...]:
        """上下文词表（命中清单解释与原文泄漏检查都要用）。"""
        return self._booster.terms if self._booster else ()

    # ------------------------------------------------------------------ 装配

    def register(self, recognizer: Recognizer) -> None:
        """注册一个识别器；ID 重复视为装配错误，直接报错。"""
        if not recognizer.id:
            raise ValueError("识别器必须声明 id")
        if any(existing.id == recognizer.id for existing in self._recognizers):
            raise ValueError(f"识别器 id 重复：{recognizer.id}")
        self._recognizers.append(recognizer)

    def unregister(self, recognizer_id: str) -> None:
        """移除一个识别器（未注册则忽略）。"""
        self._recognizers = [
            existing for existing in self._recognizers if existing.id != recognizer_id
        ]

    def get_recognizers(self) -> list[Recognizer]:
        """按注册顺序返回识别器列表。"""
        return list(self._recognizers)

    @property
    def config(self) -> RegistryConfig:
        """当前注册表配置。"""
        return self._config

    # ------------------------------------------------------------------ 分析

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[EntitySpan]:
        """扫描文本，返回裁决后的实体区间列表。

        :param entities: 只分析这些实体类别；``None`` 表示全部分析。
        :return: 按起点、终点、类别排序的 ``EntitySpan`` 列表。
        """
        results: list[RecognizerResult] = []
        for recognizer in self._recognizers:
            if not recognizer.is_available():
                continue
            results.extend(recognizer.analyze(text, entities=entities))

        # 上下文加分在阈值判定之前：加分的作用就是把「证据不足」抬成「够门槛」
        if self._booster is not None:
            results = self._booster.boost_all(text, results, self.threshold_for)

        spans = [self._classify(result) for result in results]
        spans = fold_exact_duplicates(spans)
        spans = [self._apply_allow_list(span, text) for span in spans]
        spans.sort(key=lambda span: (span.start, span.end, span.label))
        return spans

    def threshold_for(self, result: RecognizerResult) -> float:
        """解析一条命中应适用的阈值。

        优先级：逐识别器阈值覆盖 → 识别器逐类别阈值 → 识别器默认阈值 → 全局阈值。
        """
        override = self._config.per_recognizer_thresholds.get(result.recognizer)
        if override is not None:
            return override
        for recognizer in self._recognizers:
            if recognizer.id != result.recognizer:
                continue
            if result.label in recognizer.score_thresholds:
                return recognizer.score_thresholds[result.label]
            if "default" in recognizer.score_thresholds:
                return recognizer.score_thresholds["default"]
            break
        return self._config.global_threshold

    # ------------------------------------------------------------- 内部裁决

    def _classify(self, result: RecognizerResult) -> EntitySpan:
        """按阈值把命中定为确认档或告警档（不丢弃）。

        识别器可以显式要求降档（``metadata["force_warning"] = True``）——
        用于「已经判定证据不足」的情形（如 task 19 的数字类歧义消解：附近没有
        编号类上下文词的住院号候选）。这类命中不论分数多高都只进告警档：
        分数够高只说明「形状像」，不代表「确实是住院号」。
        """
        threshold = self.threshold_for(result)
        if result.metadata.get("force_warning"):
            note = str(
                result.metadata.get("warning_note")
                or "证据不足，降为告警档（不判定为身份）"
            )
            return EntitySpan(
                start=result.start,
                end=result.end,
                label=result.label,
                score=result.score,
                reason=f"{result.reason}；{note}",
                tier=SpanTier.WARNING,
                recognizer=result.recognizer,
                metadata=dict(result.metadata),
            )
        if result.score >= threshold:
            return EntitySpan(
                start=result.start,
                end=result.end,
                label=result.label,
                score=result.score,
                reason=result.reason,
                tier=SpanTier.CONFIRMED,
                recognizer=result.recognizer,
                metadata=dict(result.metadata),
            )
        reason = (
            f"{result.reason}；分数 {result.score:.2f} 低于阈值 {threshold:.2f}"
            f"（{result.recognizer or '未命名识别器'}），降为告警档"
        )
        return EntitySpan(
            start=result.start,
            end=result.end,
            label=result.label,
            score=result.score,
            reason=reason,
            tier=SpanTier.WARNING,
            recognizer=result.recognizer,
            metadata=dict(result.metadata),
        )

    def _apply_allow_list(self, span: EntitySpan, text: str) -> EntitySpan:
        """白名单命中即放行：降为放行档，附放行原因。"""
        word = text[span.start : span.end]
        if not word:
            return span
        if word in self._config.allow_list_exact:
            return replace(
                span,
                tier=SpanTier.ALLOWED,
                reason=f"{span.reason}；命中白名单（exact），放行",
            )
        for pattern in self._allow_patterns:
            if pattern.search(word):
                return replace(
                    span,
                    tier=SpanTier.ALLOWED,
                    reason=f"{span.reason}；命中白名单（regex），放行",
                )
        return span
