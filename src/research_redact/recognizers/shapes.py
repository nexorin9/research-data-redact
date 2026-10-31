"""形态约束：编号 / 联系方式的位数、前缀、字符集 —— 全部从策略表读。

源产品把识别器的正则与分数写在各自的 Python 类里（``PatternRecognizer`` 的
``patterns`` 字典），改一个院区的住院号位数要改代码。本轮把「形状」抽到
``policy/research.yaml``：位数区间、前缀写法、字符集、基础分数都写在策略表，
识别器按配置生成正则 —— 换院区只改 YAML。

装配纪律（与 ``policy/table.py`` 同一条，但本模块只管「形状」这一小段，
不抢 task 6 的完整策略表）：

- 配置非法（位数区间倒置、前缀为空、分数越界、出现未知道具键）一律抛
  :class:`ShapeConfigError`，**不静默取默认值** —— 静默降级会让人以为
  「已经按本院写法识别过了」；
- 缺整段配置（如没有 ``number_shapes``）同样报错，不当成「本院没有这类编号」；
- 装载结果按 (路径, 修改时间) 缓存：守护进程常驻时不必每份材料重读一遍
  YAML，而策略表一改就重新装载。

**不变量**：形态配置里不出现任何命中原文，也不出现任何凭据。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

__all__ = [
    "BirthDateShape",
    "NumberShape",
    "PhoneShape",
    "RecognizerShapes",
    "ShapeConfigError",
    "default_policy_path",
    "load_shapes",
]


#: 策略表默认位置：项目根目录下的 policy/research.yaml
_DEFAULT_POLICY_RELATIVE = ("policy", "research.yaml")

#: 环境变量：策略表路径（.env.example 里的 RESEARCH_POLICY_FILE）
POLICY_PATH_ENV = "RESEARCH_POLICY_FILE"

#: 数字本体长度上限：位数区间越界即报错，防止写出灾难性回溯的正则
_MAX_DIGIT_LENGTH = 32


class ShapeConfigError(ValueError):
    """形态约束配置非法（位数越界 / 前缀为空 / 未知道具键 …）。"""


# --------------------------------------------------------------------- 数据形状


@dataclass(frozen=True)
class NumberShape:
    """编号形态约束：住院号 / 门诊号 / 检查号。

    :param kind: 形态键（与策略表里的键同名）。
    :param label_zh: 中文名，进命中解释（供人工抽检读懂「按哪种形状命中的」）。
    :param entity: 命中后给出的实体类别。
    :param score: 命中基础分数。
    :param digit_length: 数字本体长度区间 ``(下限, 上限)``。
    :param prefixes: 允许的前缀写法（空表示只认纯数字）。
    :param require_prefix: 前缀必须出现（此时前缀表不可为空）。
    :param allow_alphanumeric: 数字本体允许混入字母。
    """

    kind: str
    label_zh: str
    entity: str
    score: float
    digit_length: tuple[int, int]
    prefixes: tuple[str, ...] = ()
    require_prefix: bool = False
    allow_alphanumeric: bool = False
    enabled: bool = True

    def build_pattern(self) -> re.Pattern[str]:
        """按约束生成匹配正则。

        边界用 ``(?<![0-9A-Za-z])`` / ``(?![0-9A-Za-z])``：不把
        ``MZ123456`` 里的 ``123456`` 单独再判一次住院号，也不把更长的数字串
        从中间切开。
        """
        low, high = self.digit_length
        if self.allow_alphanumeric:
            body = rf"(?=[0-9A-Za-z]*\d)[0-9A-Za-z]{{{low},{high}}}"
        else:
            body = rf"\d{{{low},{high}}}"
        prefix = ""
        if self.prefixes:
            alternatives = "|".join(
                re.escape(item) for item in sorted(self.prefixes, key=len, reverse=True)
            )
            prefix = f"(?:{alternatives})" if self.require_prefix else f"(?:{alternatives})?"
        return re.compile(
            rf"(?<![0-9A-Za-z]){prefix}{body}(?![0-9A-Za-z])", re.IGNORECASE
        )


@dataclass(frozen=True)
class PhoneShape:
    """手机号形态约束：号段前缀 + 总长度。"""

    kind: str
    label_zh: str
    entity: str
    score: float
    length: int
    prefixes: tuple[str, ...] = ()
    enabled: bool = True

    def build_pattern(self) -> re.Pattern[str]:
        """按约束生成匹配正则（11 位号段 + 9 位数字本体）。"""
        prefix_length = len(self.prefixes[0])
        body_length = self.length - prefix_length
        alternatives = "|".join(
            re.escape(item) for item in sorted(self.prefixes, key=len, reverse=True)
        )
        return re.compile(
            rf"(?<!\d)(?:{alternatives})\d{{{body_length}}}(?!\d)", re.IGNORECASE
        )


@dataclass(frozen=True)
class BirthDateShape:
    """出生日期形态约束：分隔符写法 + 邻近语义词。

    :param context_terms: 判定「这条日期确实是出生日期」的邻近语义词。
    :param negative_terms: 判定「这条日期不是出生日期」的排除语义词。
    """

    kind: str
    label_zh: str
    entity: str
    score: float
    separators: tuple[str, ...] = ("-",)
    chinese_format: bool = False
    context_window: int = 16
    context_terms: tuple[str, ...] = ()
    negative_terms: tuple[str, ...] = ()
    enabled: bool = True

    def build_patterns(self) -> list[re.Pattern[str]]:
        """生成分隔符写法与中文写法的两套正则。"""
        patterns: list[re.Pattern[str]] = []
        if self.separators:
            alternatives = "|".join(re.escape(item) for item in self.separators)
            patterns.append(
                re.compile(
                    rf"(?<!\d)\d{{4}}(?P<sep>[{alternatives}])\d{{1,2}}(?P=sep)\d{{1,2}}(?!\d)"
                )
            )
        if self.chinese_format:
            patterns.append(re.compile(r"(?<!\d)\d{4}年\d{1,2}月\d{1,2}日(?!\d)"))
        return patterns


@dataclass(frozen=True)
class RecognizerShapes:
    """一次装载得到的全部形态约束。"""

    number_shapes: tuple[NumberShape, ...] = ()
    phone_shapes: tuple[PhoneShape, ...] = ()
    birth_date_shapes: tuple[BirthDateShape, ...] = ()
    source: str = ""


# --------------------------------------------------------------------- 装载


#: 装载缓存：(策略表路径, 修改时间) → 形态约束
_CACHE: dict[tuple[str, float], RecognizerShapes] = {}


def default_policy_path() -> Path:
    """策略表默认路径：项目根目录下的 ``policy/research.yaml``。"""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent.joinpath(*_DEFAULT_POLICY_RELATIVE)
        if candidate.is_file():
            return candidate
    # 找不到时给出「看起来最像项目根」的那一条，报错信息才说人话
    root = here.parents[3] if len(here.parents) > 3 else here.parent
    return root.joinpath(*_DEFAULT_POLICY_RELATIVE)


def load_shapes(path: str | Path | None = None) -> RecognizerShapes:
    """装载形态约束。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内
        的 ``policy/research.yaml``。
    :raises ShapeConfigError: 策略表缺失、结构不对或约束非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise ShapeConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ShapeConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    shapes = _build_shapes(raw, source=str(target))
    _CACHE[key] = shapes
    return shapes


def _resolve_policy_path(path: str | Path | None) -> Path:
    """解析策略表路径：显式路径 → 环境变量 → 项目内默认。"""
    if path is not None:
        return Path(path)
    env_value = os.environ.get(POLICY_PATH_ENV)
    if env_value:
        return Path(env_value)
    return default_policy_path()


def _build_shapes(raw: Any, source: str) -> RecognizerShapes:
    """把策略表原始内容装配成形态约束对象。"""
    if not isinstance(raw, Mapping):
        raise ShapeConfigError(f"策略表根节点必须是映射：{source}")
    if "number_shapes" not in raw:
        raise ShapeConfigError(f"策略表缺少 number_shapes 段：{source}")
    if "contact_shapes" not in raw:
        raise ShapeConfigError(f"策略表缺少 contact_shapes 段：{source}")

    number_shapes = tuple(
        _build_number_shape(kind, section)
        for kind, section in _sections(raw["number_shapes"], "number_shapes")
    )
    contact_raw = _sections(raw["contact_shapes"], "contact_shapes")
    phone_shapes: list[PhoneShape] = []
    birth_date_shapes: list[BirthDateShape] = []
    for kind, section in contact_raw:
        shape_type = str(section.get("shape_type", "")).strip()
        if shape_type == "phone":
            phone_shapes.append(_build_phone_shape(kind, section))
        elif shape_type == "birth_date":
            birth_date_shapes.append(_build_birth_date_shape(kind, section))
        else:
            raise ShapeConfigError(
                f"策略表 contact_shapes.{kind}.shape_type 非法：{shape_type!r}"
                "（可用：phone、birth_date）"
            )
    return RecognizerShapes(
        number_shapes=number_shapes,
        phone_shapes=tuple(phone_shapes),
        birth_date_shapes=tuple(birth_date_shapes),
        source=source,
    )


def _sections(raw: Any, section_name: str) -> list[tuple[str, Mapping[str, Any]]]:
    """取出某段下的全部子项，逐项校验是映射。"""
    if not isinstance(raw, Mapping):
        raise ShapeConfigError(f"策略表 {section_name} 段必须是映射")
    sections: list[tuple[str, Mapping[str, Any]]] = []
    for kind, section in raw.items():
        if not isinstance(section, Mapping):
            raise ShapeConfigError(f"策略表 {section_name}.{kind} 必须是映射")
        sections.append((str(kind), section))
    return sections


def _reject_unknown(kind: str, section: Mapping[str, Any], allowed: Sequence[str]) -> None:
    """出现未知道具键即报错（拼错的键不会被静默忽略）。"""
    unknown = sorted(set(section) - set(allowed))
    if unknown:
        raise ShapeConfigError(
            f"策略表 {kind} 含未知道具键：{'、'.join(unknown)}"
            f"（可用：{'、'.join(sorted(allowed))}）"
        )


def _require(section: Mapping[str, Any], key: str, kind: str) -> Any:
    """取必填项，缺失即报错。"""
    if key not in section:
        raise ShapeConfigError(f"策略表 {kind} 缺少必填项：{key}")
    return section[key]


def _build_number_shape(kind: str, section: Mapping[str, Any]) -> NumberShape:
    """装配一个编号形态约束。"""
    _reject_unknown(
        kind,
        section,
        (
            "enabled",
            "label_zh",
            "entity",
            "score",
            "digit_length",
            "prefixes",
            "require_prefix",
            "allow_alphanumeric",
        ),
    )
    digit_length = _require(section, "digit_length", kind)
    if (
        not isinstance(digit_length, (list, tuple))
        or len(digit_length) != 2
        or not all(isinstance(item, int) for item in digit_length)
    ):
        raise ShapeConfigError(f"策略表 {kind}.digit_length 必须是两个整数：{digit_length!r}")
    low, high = int(digit_length[0]), int(digit_length[1])
    if low < 1 or high < low or high > _MAX_DIGIT_LENGTH:
        raise ShapeConfigError(
            f"策略表 {kind}.digit_length 越界：[{low}, {high}]（要求 1 ≤ 下限 ≤ 上限 ≤ {_MAX_DIGIT_LENGTH}）"
        )

    prefixes = section.get("prefixes", []) or []
    if not isinstance(prefixes, (list, tuple)):
        raise ShapeConfigError(f"策略表 {kind}.prefixes 必须是列表")
    prefix_items: list[str] = []
    for item in prefixes:
        if not isinstance(item, str) or not item.strip():
            raise ShapeConfigError(f"策略表 {kind}.prefixes 含空值或非字符串：{item!r}")
        prefix_items.append(item.strip())

    require_prefix = bool(section.get("require_prefix", False))
    if require_prefix and not prefix_items:
        raise ShapeConfigError(f"策略表 {kind} 要求前缀必须出现，但 prefixes 为空")

    score = float(_require(section, "score", kind))
    if not 0.0 <= score <= 1.0:
        raise ShapeConfigError(f"策略表 {kind}.score 越界：{score}")

    return NumberShape(
        kind=kind,
        label_zh=str(_require(section, "label_zh", kind)),
        entity=str(_require(section, "entity", kind)),
        score=score,
        digit_length=(low, high),
        prefixes=tuple(prefix_items),
        require_prefix=require_prefix,
        allow_alphanumeric=bool(section.get("allow_alphanumeric", False)),
        enabled=bool(section.get("enabled", True)),
    )


def _build_phone_shape(kind: str, section: Mapping[str, Any]) -> PhoneShape:
    """装配一个手机号形态约束。"""
    _reject_unknown(
        kind,
        section,
        ("enabled", "label_zh", "entity", "score", "length", "prefixes", "shape_type"),
    )
    length = _require(section, "length", kind)
    if not isinstance(length, int) or length < 4:
        raise ShapeConfigError(f"策略表 {kind}.length 非法：{length!r}")
    prefixes = section.get("prefixes", []) or []
    if not isinstance(prefixes, (list, tuple)) or not prefixes:
        raise ShapeConfigError(f"策略表 {kind}.prefixes 必须是非空列表")
    prefix_items = [str(item).strip() for item in prefixes]
    if any(not item for item in prefix_items):
        raise ShapeConfigError(f"策略表 {kind}.prefixes 含空值")
    if len({len(item) for item in prefix_items}) != 1:
        raise ShapeConfigError(f"策略表 {kind}.prefixes 长度必须一致：{prefix_items}")
    if length <= len(prefix_items[0]):
        raise ShapeConfigError(f"策略表 {kind}.length 必须大于前缀长度")
    score = float(_require(section, "score", kind))
    if not 0.0 <= score <= 1.0:
        raise ShapeConfigError(f"策略表 {kind}.score 越界：{score}")
    return PhoneShape(
        kind=kind,
        label_zh=str(_require(section, "label_zh", kind)),
        entity=str(_require(section, "entity", kind)),
        score=score,
        length=length,
        prefixes=tuple(prefix_items),
        enabled=bool(section.get("enabled", True)),
    )


def _build_birth_date_shape(kind: str, section: Mapping[str, Any]) -> BirthDateShape:
    """装配一个出生日期形态约束。"""
    _reject_unknown(
        kind,
        section,
        (
            "enabled",
            "label_zh",
            "entity",
            "score",
            "separators",
            "chinese_format",
            "context_window",
            "context_terms",
            "negative_terms",
            "shape_type",
        ),
    )
    separators = section.get("separators", []) or []
    if not isinstance(separators, (list, tuple)) or not separators:
        raise ShapeConfigError(f"策略表 {kind}.separators 必须是非空列表")
    separator_items = [str(item) for item in separators]
    if any(not item for item in separator_items):
        raise ShapeConfigError(f"策略表 {kind}.separators 含空值")

    context_terms = section.get("context_terms", []) or []
    if not isinstance(context_terms, (list, tuple)) or not context_terms:
        raise ShapeConfigError(
            f"策略表 {kind}.context_terms 必须是非空列表"
            "（没有邻近语义词就无法区分出生日期与报告日期，宁可报错也不静默失效）"
        )
    negative_terms = section.get("negative_terms", []) or []
    if not isinstance(negative_terms, (list, tuple)):
        raise ShapeConfigError(f"策略表 {kind}.negative_terms 必须是列表")

    window = int(section.get("context_window", 16))
    if window < 1:
        raise ShapeConfigError(f"策略表 {kind}.context_window 非法：{window}")

    score = float(_require(section, "score", kind))
    if not 0.0 <= score <= 1.0:
        raise ShapeConfigError(f"策略表 {kind}.score 越界：{score}")

    return BirthDateShape(
        kind=kind,
        label_zh=str(_require(section, "label_zh", kind)),
        entity=str(_require(section, "entity", kind)),
        score=score,
        separators=tuple(separator_items),
        chinese_format=bool(section.get("chinese_format", False)),
        context_window=window,
        context_terms=tuple(str(item) for item in context_terms),
        negative_terms=tuple(str(item) for item in negative_terms),
        enabled=bool(section.get("enabled", True)),
    )
