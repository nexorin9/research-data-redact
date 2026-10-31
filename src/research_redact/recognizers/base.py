"""识别器基类：三种形态 —— 正则匹配 / 校验位验证 / 权威名单匹配。

形态划分沿用源产品识别器基类里的三条实现路线（正则、结构化校验、名单匹配），
本轮改写为项目内自有确定性实现：``ai_role=none``，全链路不引任何语言模型。

三种形态各自的取舍：

- **正则形态**（``PatternRecognizer``）：按标签给若干正则，整段扫描取全部命中。
  宽泛、无歧义的模式用它；容易被误伤的编号类会在 task 19 追加形态约束。
- **校验位形态**（``ChecksumRecognizer``）：正则只给候选，校验函数给真伪。
  校验不通过的候选**不消失**，而是以低于阈值的分数产出，由注册表降为告警档 ——
  避免把形似身份证的普通数字串判成身份。
- **权威名单形态**（``ListRecognizer``）：以权威名单（患者主索引等）为准，
  不做通用模式猜测。名单为空或不可达时不产出任何命中，由批次状态机把批次置为
  挂起（``suspended``），不降级为「按姓名硬匹配」。

**不变量**：任何形态产出的解释（``reason``）都不得包含命中原文 ——
解释会原样写进逐处命中清单。
"""

from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from ..models import RecognizerResult

__all__ = [
    "AuthorityEntry",
    "ChecksumRecognizer",
    "ListRecognizer",
    "PatternRecognizer",
    "Recognizer",
    "normalize_text",
    "normalize_with_offsets",
]


def normalize_with_offsets(text: str) -> tuple[str, list[int]]:
    """归一化文本并保留「归一化位置 → 原文位置」的映射。

    归一化动作：NFKC（全角转半角）→ 去空白 → 小写。NFKC 对绝大多数全角字符是
    1:1 映射；个别字符会展开成多字符，这时把展开出来的每个字符都指回同一个
    原文位置，保证命中区间仍能还原到原文坐标。
    """
    chars: list[str] = []
    offsets: list[int] = []
    for index, char in enumerate(text):
        folded = unicodedata.normalize("NFKC", char)
        lowered = folded.lower()
        if len(lowered) != len(folded):  # 罕见的长度变化展开，放弃折叠以免错位
            lowered = folded
        for piece in lowered:
            if piece.isspace():
                continue
            chars.append(piece)
            offsets.append(index)
    return "".join(chars), offsets


def normalize_text(value: str) -> str:
    """归一化字符串（NFKC + 去空白 + 小写），用于名单键与策略表键的稳定比较。"""
    return "".join(unicodedata.normalize("NFKC", value).split()).lower()


class Recognizer(ABC):
    """识别器基类：所有识别器统一产出 ``RecognizerResult``。

    子类须声明：

    - ``id``：识别器 ID，逐识别器阈值按它匹配（policy/research.yaml 的键）。
    - ``name``：中文名，进解释与清单。
    - ``score_thresholds``：逐类别阈值（形如 ``{"VISIT_NO": 0.7}``），
      未声明的类别回退到 ``"default"``；两者都缺时回退到注册表的全局阈值。
    - ``supported_entities``：本识别器产出的实体类别。
    """

    id: str = ""
    name: str = ""
    score_thresholds: dict[str, float] = {}
    supported_entities: tuple[str, ...] = ()

    @abstractmethod
    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        """扫描文本，产出命中列表。"""

    def is_available(self) -> bool:
        """识别器当前是否可用。

        主索引不可达时名单识别器返回 False —— 此时不产出任何命中，
        由批次状态机把批次置为 ``suspended``，不降级为按正则硬脱。
        """
        return True


class PatternRecognizer(Recognizer):
    """正则形态识别器。

    :param patterns: 标签 → 正则模式；同一标签可给多条（按插入顺序扫描）。
    :param base_score: 命中基础分数，逐类别阈值在 ``score_thresholds`` 内覆盖。
    """

    def __init__(
        self,
        recognizer_id: str,
        name: str,
        patterns: dict[str, str],
        base_score: float = 0.6,
        score_thresholds: dict[str, float] | None = None,
        supported_entities: Sequence[str] | None = None,
        flags: int = re.MULTILINE,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        self.patterns = dict(patterns)
        self.base_score = base_score
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = tuple(supported_entities or tuple(patterns))
        self._compiled = {
            label: re.compile(pattern, flags) for label, pattern in self.patterns.items()
        }

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        wanted = set(entities) if entities else None
        results: list[RecognizerResult] = []
        for label, pattern in self._compiled.items():
            if wanted is not None and label not in wanted:
                continue
            for match in pattern.finditer(text):
                start, end = match.span()
                if end <= start:
                    continue
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=label,
                        score=self.base_score,
                        reason=f"正则命中（{label}）",
                        recognizer=self.id,
                    )
                )
        return results


class ChecksumRecognizer(Recognizer):
    """校验位形态识别器：正则给候选，校验函数给真伪。

    :param validator: 校验函数，入参为候选原文，返回是否通过校验位。
    :param base_score: 校验通过时的分数。
    :param invalid_score: 校验不通过时的分数 —— 必须低于阈值，
        以便注册表把它降为告警档而不是判成身份。

    校验不通过的候选会带上 ``metadata["boost_allowed"] = False``：
    它是**已经判定不通过**，不是「证据不足」，因此邻近上下文加分
    （``recognizers/context_boost.py``）不得把它抬成身份类。
    """

    def __init__(
        self,
        recognizer_id: str,
        name: str,
        pattern: str,
        label: str,
        validator: Callable[[str], bool],
        base_score: float = 0.9,
        invalid_score: float = 0.2,
        score_thresholds: dict[str, float] | None = None,
        flags: int = re.MULTILINE,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        self.pattern = pattern
        self.label = label
        self.validator = validator
        self.base_score = base_score
        self.invalid_score = invalid_score
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = (label,)
        self._compiled = re.compile(pattern, flags)

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        if entities is not None and self.label not in set(entities):
            return []
        results: list[RecognizerResult] = []
        for match in self._compiled.finditer(text):
            start, end = match.span()
            if end <= start:
                continue
            candidate = match.group(0)
            try:
                passed = bool(self.validator(candidate))
            except Exception:  # 校验函数自身异常按「不通过」处理，不吞掉整批
                passed = False
            if passed:
                score, reason = self.base_score, f"校验位通过（{self.label}）"
                metadata: dict[str, object] = {}
            else:
                score = self.invalid_score
                reason = f"校验位不通过（{self.label}），按告警档处理"
                # 校验位不通过不是「证据不足」，而是「已经判定不通过」：
                # 邻近窗口再出现「身份证」之类的词也不许把它抬成身份类。
                metadata = {"boost_allowed": False}
            results.append(
                RecognizerResult(
                    start=start,
                    end=end,
                    label=self.label,
                    score=score,
                    reason=reason,
                    recognizer=self.id,
                    metadata=metadata,
                )
            )
        return results


@dataclass(frozen=True)
class AuthorityEntry:
    """权威名单条目。

    :param value: 权威值（如患者主索引主键对应的就诊号）。
    :param label: 命中后给出的实体类别。
    :param aliases: 别名（如同一患者的归一化姓名 + 就诊号组合）。
    """

    value: str
    label: str
    score: float = 0.9
    reason: str = ""
    aliases: tuple[str, ...] = ()


class ListRecognizer(Recognizer):
    """权威名单形态识别器：以权威名单为准，不做通用模式猜测。

    名单为空或不可达时**不产出任何命中**（而不是退化成按姓名硬匹配）。
    匹配在归一化文本上进行，命中区间换算回原文坐标，全角数字同样能命中。
    """

    def __init__(
        self,
        recognizer_id: str,
        name: str,
        entries: Iterable[AuthorityEntry],
        score_thresholds: dict[str, float] | None = None,
        available: bool = True,
    ) -> None:
        self.id = recognizer_id
        self.name = name
        self.entries = tuple(entries)
        self.score_thresholds = dict(score_thresholds or {})
        self.supported_entities = tuple(
            dict.fromkeys(entry.label for entry in self.entries)
        )
        self._available = available

    def is_available(self) -> bool:
        return self._available and bool(self.entries)

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        if not self.is_available():
            return []
        wanted = set(entities) if entities else None
        normalized_text, offsets = normalize_with_offsets(text)
        results: list[RecognizerResult] = []
        for entry in self.entries:
            if wanted is not None and entry.label not in wanted:
                continue
            for candidate in (entry.value, *entry.aliases):
                needle = normalize_text(candidate)
                if not needle:
                    continue
                start = normalized_text.find(needle)
                while start != -1:
                    end = start + len(needle) - 1
                    original_start = offsets[start]
                    original_end = offsets[end] + 1
                    results.append(
                        RecognizerResult(
                            start=original_start,
                            end=original_end,
                            label=entry.label,
                            score=entry.score,
                            reason=entry.reason or f"命中权威名单（{entry.label}）",
                            recognizer=self.id,
                        )
                    )
                    start = normalized_text.find(needle, start + 1)
        return results
