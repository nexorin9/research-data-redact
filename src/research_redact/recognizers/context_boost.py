"""邻近窗口上下文加分：字符 n-gram + 局部最佳对齐 Dice 相似度打分。

源产品靠 spaCy 的 lemma 做上下文加分（``analyzer_engine.py::_enhance_using_context``，
:299-358，配 ``LemmaContextAwareEnhancer``）—— 它的前提是「文本已经被分词并还原成
词元」，没有词元就没有上下文。本项目 ``ai_role=none``、全链路不引任何语言模型，
词元拿不到，于是把上下文语义**降级为字符层面的邻近证据**：

- 取命中区间前后各 ``window_radius`` 个字符作为**邻近窗口**（默认 24，可配）；
- 窗口与上下文词表里的每个词都拆成**字符 n-gram 集合**（长度可配，默认 2-gram
  与 3-gram）；
- 相似度用 **Dice 系数**：``2|A∩B| / (|A|+|B|)``，对称、不偏向长的一方；
- 词在窗口里的位置不固定，所以先在窗口里找**最佳局部对齐**（把词按 n-gram 锚点
  对齐到窗口的各个位置，逐个算 Dice，取最大），再取词表里的最高分。

为什么用「局部最佳对齐」而不是直接拿整个窗口算 Dice：邻近窗口有几十个字符，
直接比会让一个原样出现的词被窗口里的大量无关 n-gram 稀释（窗口越长分数越低，
同一份材料换个窗口半径结论就变）。局部对齐把它变成「这个词在这段窗口里像不像」，
原样出现即 1.0，被空格或错字打断则按 Dice 逐级下降，窗口外的词永远得 0。

四条不可违反的纪律：

1. **窗口外的命中绝不加分** —— 相似度为 0 时分数一字不动。
2. **加分封顶在门槛上** —— 分数不会越过生效阈值（逐识别器阈值优先，其次全局
   阈值），因此更严的逐识别器阈值不会被上下文词绕过；加分只可能把「告警档」
   抬到「确认档」，不会把已确认的分数推得更高。
3. **加分只升档，不改实体类别** —— 上下文词能说明「这段大概是什么」，不能说明
   「这段一定是住院号」：识别器给出的标签原样保留。
4. **被判定为「不是身份」的命中不得靠上下文复活** —— 识别器可用
   ``metadata["boost_allowed"] = False`` 显式退出加分（例如校验位不通过的
   身份证候选：它不是「证据不足」，而是「已经判定不通过」）。

**不变量**：命中解释（``reason``）只写上下文词（策略表里的公共词表，不是患者
数据）、相似度数值与加分数值，绝不写命中原文，也不写窗口正文 —— 解释会原样
进命中清单。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from ..models import RecognizerResult
from .shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "ContextBoostConfig",
    "ContextBooster",
    "ContextConfigError",
    "load_context_config",
    "ngram_set",
    "dice_similarity",
    "term_similarity",
]


#: ``context`` 段允许的键。出现未知道具键即报错 —— 拼错的键不会被静默忽略，
#: 否则「以为配了窗口半径、其实没配」会一直没人发现。
_CONTEXT_KEYS = ("window_radius", "ngram_sizes", "base_weight", "max_boost", "terms")

#: 上下文词最短长度：1 个字的词切不出 n-gram，进了词表也不会生效，
#: 属于配置笔误，直接报错。
_MIN_TERM_LENGTH = 2

#: 装载缓存：(策略表路径, 修改时间) → 上下文配置
_CACHE: dict[tuple[str, float], ContextBoostConfig] = {}


class ContextConfigError(ValueError):
    """邻近窗口上下文配置非法（缺段 / 未知道具键 / 数值越界 / 词表非法）。"""


# --------------------------------------------------------------------- 配置


@dataclass(frozen=True)
class ContextBoostConfig:
    """邻近窗口上下文加分的配置。

    :param window_radius: 邻近窗口半径（命中区间前后各取多少个字符）。
    :param ngram_sizes: 字符 n-gram 长度集合（如 ``(2, 3)``）。
    :param base_weight: 加分系数：加分 = ``base_weight`` × 相似度。
    :param max_boost: 单次加分上限。
    :param terms: 上下文词表（策略表里的公共词，可按院区调整）。
    """

    window_radius: int = 24
    ngram_sizes: tuple[int, ...] = (2, 3)
    base_weight: float = 0.2
    max_boost: float = 0.2
    terms: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        """加分是否生效（词表为空或系数为 0 时不生效）。"""
        return bool(self.terms) and self.base_weight > 0 and self.max_boost > 0

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "ContextBoostConfig":
        """从策略表原始内容装配上下文配置。

        :param raw: 策略表 YAML 解析结果（整份策略表，不只是 context 段）。
        :param source: 策略表来源（写进报错信息，让人知道该改哪个文件）。
        :raises ContextConfigError: 缺 ``context`` 段、出现未知道具键或数值非法。
        """
        if not isinstance(raw, Mapping):
            raise ContextConfigError(f"策略表根节点必须是映射：{source}")
        if "context" not in raw:
            raise ContextConfigError(f"策略表缺少 context 段：{source}")
        section = raw["context"]
        if not isinstance(section, Mapping):
            raise ContextConfigError("策略表 context 段必须是映射")
        unknown = sorted(set(section) - set(_CONTEXT_KEYS))
        if unknown:
            raise ContextConfigError(
                f"策略表 context 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_CONTEXT_KEYS)}）"
            )

        radius = section.get("window_radius", 24)
        if not isinstance(radius, int) or isinstance(radius, bool) or radius < 1:
            raise ContextConfigError(f"策略表 context.window_radius 非法：{radius!r}")

        sizes_raw = section.get("ngram_sizes", [2, 3])
        if not isinstance(sizes_raw, (list, tuple)) or not sizes_raw:
            raise ContextConfigError("策略表 context.ngram_sizes 必须是非空列表")
        sizes: list[int] = []
        for item in sizes_raw:
            if not isinstance(item, int) or isinstance(item, bool) or item < 1:
                raise ContextConfigError(
                    f"策略表 context.ngram_sizes 含非法长度：{item!r}"
                )
            sizes.append(item)

        base_weight = float(section.get("base_weight", 0.2))
        if not 0.0 <= base_weight <= 1.0:
            raise ContextConfigError(f"策略表 context.base_weight 越界：{base_weight}")

        max_boost = float(section.get("max_boost", 0.2))
        if not 0.0 <= max_boost <= 1.0:
            raise ContextConfigError(f"策略表 context.max_boost 越界：{max_boost}")

        terms_raw = section.get("terms", [])
        if not isinstance(terms_raw, (list, tuple)):
            raise ContextConfigError("策略表 context.terms 必须是列表")
        terms: list[str] = []
        for item in terms_raw:
            if not isinstance(item, str):
                raise ContextConfigError(f"策略表 context.terms 含非字符串：{item!r}")
            word = item.strip()
            if len(word) < _MIN_TERM_LENGTH:
                raise ContextConfigError(
                    f"策略表 context.terms 含过短词：{item!r}"
                    f"（至少 {_MIN_TERM_LENGTH} 个字，否则切不出 n-gram）"
                )
            terms.append(word)

        return cls(
            window_radius=radius,
            ngram_sizes=tuple(sorted(set(sizes))),
            base_weight=base_weight,
            max_boost=max_boost,
            terms=tuple(dict.fromkeys(terms)),
        )


def load_context_config(path: str | Path | None = None) -> ContextBoostConfig:
    """装载邻近窗口上下文配置。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises ContextConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise ContextConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ContextConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    config = ContextBoostConfig.from_policy(raw, source=str(target))
    _CACHE[key] = config
    return config


def _resolve_policy_path(path: str | Path | None) -> Path:
    """解析策略表路径：显式路径 → 环境变量 → 项目内默认。"""
    if path is not None:
        return Path(path)
    env_value = os.environ.get(POLICY_PATH_ENV)
    if env_value:
        return Path(env_value)
    return default_policy_path()


# --------------------------------------------------------------------- 打分


def ngram_set(text: str, sizes: Sequence[int]) -> set[str]:
    """把文本拆成字符 n-gram 集合。

    :param text: 待拆文本。
    :param sizes: n-gram 长度集合（如 ``(2, 3)``）。
    """
    grams: set[str] = set()
    for size in sizes:
        if size < 1 or len(text) < size:
            continue
        for index in range(len(text) - size + 1):
            grams.add(text[index : index + size])
    return grams


def dice_similarity(left: set[str], right: set[str]) -> float:
    """两个 n-gram 集合的 Dice 相似度。

    ``Dice(A, B) = 2|A∩B| / (|A| + |B|)``，取值 0 ~ 1。

    - 对称：``Dice(A, B) == Dice(B, A)``（不偏向长的一方）；
    - 两个集合完全相同 → 1.0；没有公共 n-gram → 0.0；
    - 任一集合为空 → 0.0（没有可比的东西，不给 0.5 之类的默认值）。

    :param left: 左边的 n-gram 集合。
    :param right: 右边的 n-gram 集合。
    """
    if not left or not right:
        return 0.0
    overlap = len(left & right)
    if overlap == 0:
        return 0.0
    return 2.0 * overlap / (len(left) + len(right))


def _anchor_offsets(term: str, sizes: Sequence[int]) -> tuple[tuple[str, int], ...]:
    """词内每个 n-gram 的出现位置（锚点）。

    锚点用来在窗口里定位「这个词最可能出现在哪」：窗口的 n-gram 与词的 n-gram
    在同一个相对位置对上时，才算一次对齐尝试。

    :return: ``(n-gram, 相对词首的偏移)`` 列表。
    """
    anchors: list[tuple[str, int]] = []
    for size in sizes:
        if size < 1 or len(term) < size:
            continue
        for offset in range(len(term) - size + 1):
            anchors.append((term[offset : offset + size], offset))
    return tuple(anchors)


def _gram_index(text: str, sizes: Sequence[int]) -> dict[str, list[int]]:
    """文本的 n-gram 位置索引（n-gram → 出现位置列表）。"""
    index: dict[str, list[int]] = {}
    for size in sizes:
        if size < 1 or len(text) < size:
            continue
        for offset in range(len(text) - size + 1):
            index.setdefault(text[offset : offset + size], []).append(offset)
    return index


def _best_alignment_similarity(
    window: str,
    term: str,
    sizes: Sequence[int],
    term_grams: frozenset[str] | None = None,
    index: dict[str, list[int]] | None = None,
) -> float:
    """上下文词在窗口里的**最佳局部对齐 Dice** 相似度。

    先用词里的 n-gram 锚点在窗口里定位候选位置，再对每个候选位置取一段与词
    等长的片段算 Dice，取最大值。

    - 词原样出现在窗口里 → 1.0；
    - 词被空格或错字打断 → 按公共 n-gram 比例逐级下降；
    - 词完全不在窗口里 → 0.0。

    :param window: 邻近窗口正文。
    :param term: 上下文词。
    :param sizes: n-gram 长度集合。
    :param term_grams: 预先算好的词 n-gram 集合（省重复计算）。
    :param index: 预先算好的窗口 n-gram 位置索引（省重复计算）。
    """
    if not window or not term:
        return 0.0
    length = len(term)
    if len(window) < length:
        return 0.0
    grams = term_grams if term_grams is not None else frozenset(ngram_set(term, sizes))
    if not grams:
        return 0.0
    if term in window:
        # 原样出现：Dice 满分，不必再找位置
        return 1.0

    positions = index if index is not None else _gram_index(window, sizes)
    starts: set[int] = set()
    for gram, offset in _anchor_offsets(term, sizes):
        for position in positions.get(gram, ()):
            start = position - offset
            if 0 <= start and start + length <= len(window):
                starts.add(start)

    best = 0.0
    for start in sorted(starts):
        segment = window[start : start + length]
        score = dice_similarity(set(grams), ngram_set(segment, sizes))
        if score > best:
            best = score
            if best >= 1.0:
                return 1.0
    return best


def term_similarity(window: str, term: str, sizes: Sequence[int]) -> float:
    """上下文词落在窗口里的程度（最佳局部对齐 Dice，0 ~ 1）。

    词完整出现在窗口里 → 1.0；只对齐一部分 → 中间值；完全不在 → 0.0。
    """
    return _best_alignment_similarity(window, term, sizes)


class ContextBooster:
    """邻近窗口上下文加分器。

    :param config: 加分配置；缺省取一份「不生效」的默认配置。
    """

    def __init__(self, config: ContextBoostConfig | None = None) -> None:
        self.config = config or ContextBoostConfig()
        # 词表的 n-gram 集合与锚点预先算好：守护进程常驻，逐份材料重复切词是
        # 白烧 CPU
        self._terms: tuple[str, ...] = tuple(self.config.terms)
        self._term_grams: tuple[tuple[str, frozenset[str]], ...] = tuple(
            (term, frozenset(ngram_set(term, self.config.ngram_sizes)))
            for term in self._terms
        )

    @property
    def terms(self) -> tuple[str, ...]:
        """上下文词表（命中清单解释与原文泄漏检查都要用）。"""
        return self._terms

    def window_for(self, text: str, start: int, end: int) -> str:
        """取命中区间的邻近窗口（前后各 ``window_radius`` 个字符）。"""
        radius = self.config.window_radius
        return text[max(0, start - radius) : min(len(text), end + radius)]

    def best_match(self, window: str) -> tuple[str, float]:
        """窗口里最贴近的上下文词与相似度。

        :return: ``(上下文词, 相似度)``；没有词命中时相似度为 0.0。
        """
        if not self.config.enabled or not window:
            return "", 0.0
        # 快路径：词原样出现即满分（整词命中是绝大多数情况）
        for term in self._terms:
            if term in window:
                return term, 1.0
        # 慢路径：局部最佳对齐 Dice
        sizes = self.config.ngram_sizes
        index = _gram_index(window, sizes)
        best_term, best_score = "", 0.0
        for term, term_grams in self._term_grams:
            if not term_grams:
                continue
            score = _best_alignment_similarity(
                window, term, sizes, term_grams=term_grams, index=index
            )
            if score > best_score:
                best_term, best_score = term, score
                if best_score >= 1.0:
                    break
        return best_term, best_score

    def boost(
        self, text: str, result: RecognizerResult, threshold: float
    ) -> RecognizerResult:
        """给一条命中加分。

        加分只升档，不改实体类别：标签是识别器给的判定，上下文词只能补充证据，
        不能改写判定。

        :param text: 材料正文。
        :param result: 识别器给出的原始命中。
        :param threshold: 该命中的生效阈值（加分封顶在门槛上）。
        :return: 加分后的命中；不加分时原样返回。
        """
        if not self.config.enabled:
            return result
        # 已达门槛的命中不再加分：加分封顶在门槛上，再加只会被压回去
        if result.score >= threshold:
            return result
        # 被判定为「不是身份」的命中不得靠上下文复活（如校验位不通过）
        if result.metadata.get("boost_allowed") is False:
            return result
        window = self.window_for(text, result.start, result.end)
        term, similarity = self.best_match(window)
        if similarity <= 0:
            return result
        delta = min(self.config.base_weight * similarity, self.config.max_boost)
        if delta <= 0:
            return result
        new_score = min(result.score + delta, threshold)
        reason = (
            f"{result.reason}；邻近窗口命中上下文词「{term}」，"
            f"相似度 {similarity:.2f}，加分 {delta:.2f}"
        )
        metadata = dict(result.metadata)
        metadata["context_boost"] = {
            "term": term,
            "similarity": round(similarity, 4),
            "delta": round(delta, 4),
            "method": "dice_local_alignment",
            "ngram_sizes": list(self.config.ngram_sizes),
            "window_radius": self.config.window_radius,
        }
        return replace(result, score=new_score, reason=reason, metadata=metadata)

    def boost_all(
        self,
        text: str,
        results: Sequence[RecognizerResult],
        threshold_for: Callable[[RecognizerResult], float],
    ) -> list[RecognizerResult]:
        """给一批命中逐条加分。

        :param threshold_for: 解析某条命中的生效阈值的函数（注册表提供）。
        """
        if not self.config.enabled:
            return list(results)
        return [
            self.boost(text, result, threshold_for(result)) for result in results
        ]
