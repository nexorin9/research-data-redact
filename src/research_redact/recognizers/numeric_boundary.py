"""数字类歧义消解：剂量 / 金额 / 页码 / 床号 / 序号不得判为编号。

**为什么单独一层**：放射与检验报告里，住院号与下面这些数字在字面上几乎一样：

==========================  ==================================================
形似的数字                  它其实是什么
==========================  ==================================================
``30mL`` / ``0.5g``         剂量
``245000.00 元``            费用金额
``（本页为第 2 页）``        页码
``12床``                    床号
``第 3 次复查``              序号
``110101-19491231002``      连字符写法的证件号（被拆开的一段）
==========================  ==================================================

脱过头（把剂量金额当成住院号抹掉）与脱不到（把真住院号当成页码放过）**两头都是
事故**：前者让临床数据失真、科室不认这份材料；后者让患者身份进了交付物。源产品
（``analyzer_engine.py``）没有这一层 —— 它把「放行」判定放在**识别之后的结果层**
（``_remove_allow_list`` :423），而剂量 / 金额这类语义压根不在它的词表里。本轮把
这一层**前移到识别之前**：数字候选先过边界判定，不构成身份候选的压根不进入命中
列表。

四条规则（全部写在 ``policy/research.yaml`` 的 ``numeric_boundary`` 段）：

1. **剂量 / 金额** —— 紧邻剂量单位（mg / mL / 片 / 袋 / IU / 次）或货币符号
   （元 / ￥ / ¥）的数字，判为剂量 / 金额，**不判为编号**。这条不看位数：金额动辄
   六七位数，正是最像住院号的那一档。
2. **页码 / 床号 / 序号** —— 紧邻「页 / 床 / 第 / 序号」的数字判为页码 / 床号 /
   序号，**不判为住院号或检查号**。这条**只对短数字生效**（≤ 4 位）：页码床号本来
   就是一两位数，而六位以上的数字出现在「床位 90000001」这种句子里时，多半是编号
   而不是床号 —— 此时放过它等于漏脱。
3. **日期片段** —— 紧邻「年 / 月 / 日」的数字，以及**连字符数字串**里的每一段：
   - 三段及以上（ISO 写法日期 ``2026-01-05``）整串都是日期，不判为编号；
   - 两段且另一侧是 ≥ 4 位数字（分段写的证件号 ``110101-19491231002``）时，
     整串是一个复合标识，不判为编号；
   - 两段但另一侧只有 1–3 位数字（序号后缀 ``90000001-1``）时**不适用本条** ——
     前一段仍按编号判，否则真住院号会被放过（漏脱比脱过头更糟）。
4. **上下文要求** —— 住院号 / 检查号的命中，附近必须有编号类上下文词（住院号 /
   检查号 / 患者 …）；没有的话**降为告警档**：不改写正文（改写会脱过头），但进
   命中清单等人抽检（漏脱也留痕）。

**不变量**：命中原文不得进入任何配置或解释；本模块只产出「是不是身份候选」的
判定，不产出命中。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "CONTEXT_REQUIRED_LABELS",
    "NumericBoundary",
    "NumericBoundaryConfig",
    "NumericBoundaryConfigError",
    "load_numeric_boundary_config",
]


#: 策略表 ``numeric_boundary`` 段允许的键。出现未知道具键即报错 —— 拼错的键
#: 不会被静默忽略（否则「以为配了剂量单位、其实没配」会一直没人发现）。
_NUMERIC_BOUNDARY_KEYS: tuple[str, ...] = (
    "dose_units",
    "currency_marks",
    "page_markers",
    "bed_markers",
    "date_markers",
    "sequence_markers",
    "require_context",
    "window",
    "context_terms",
    "short_number_max_digits",
    "composite_min_digits",
)

#: 需要邻近上下文词才判定为身份号的实体类别（住院号 / 门诊号 / 检查号）。
CONTEXT_REQUIRED_LABELS: tuple[str, ...] = ("VISIT_NO", "EXAM_NO")

#: 数字与标记之间允许的间隔字符：空白与常见标点。
#: **不含换行** —— 标记必须与数字同一行才算「紧邻」；下一行出现的「页」与这一行
#: 的数字无关。
_GAP_CHARS = " \t　:：,，.。、#＃()（）[]【】/／—_"

#: 默认值：页码 / 床号 / 序号只对不超过该位数的数字生效。超过它就不可能是页码
#: 或床号 —— 一律继续按编号候选判（宁可多脱一次，也不能把真住院号当成床号放过）。
_DEFAULT_SHORT_NUMBER_MAX_DIGITS = 4

#: 默认值：连字符复合标识的另一侧至少要有该位数，才算「同一个复合标识的一段」。
_DEFAULT_COMPOSITE_MIN_DIGITS = 4

#: 小数部分（金额 245000.00 元 —— 数字本体是 245000，小数部分要一起跳过）。
_FRACTION_RE = re.compile(r"\.\d+")


class NumericBoundaryConfigError(ValueError):
    """数字类歧义消解配置非法（缺段 / 未知道具键 / 数值越界 / 词表非法）。"""


# --------------------------------------------------------------------- 配置


@dataclass(frozen=True)
class NumericBoundaryConfig:
    """数字类歧义消解的配置（全部来自策略表）。

    :param dose_units: 剂量单位（mg / mL / 片 / 袋 / IU / 次 …）。
    :param currency_marks: 货币符号（元 / ￥ / ¥ …）。
    :param page_markers: 页码标记（页 / 第 …）。
    :param bed_markers: 床号标记（床 …）。
    :param date_markers: 日期标记（年 / 月 / 日 …）。
    :param sequence_markers: 序号标记（序号 …）。
    :param require_context: 住院号 / 检查号是否必须有邻近上下文词。
    :param window: 上下文词的邻近窗口半径（命中区间前后各取多少个字符）。
    :param context_terms: 编号类上下文词表。
    :param short_number_max_digits: 页码 / 床号 / 序号只对不超过该位数的数字生效。
    :param composite_min_digits: 连字符复合标识另一侧至少要有多少位数字。
    """

    dose_units: tuple[str, ...] = ()
    currency_marks: tuple[str, ...] = ()
    page_markers: tuple[str, ...] = ()
    bed_markers: tuple[str, ...] = ()
    date_markers: tuple[str, ...] = ()
    sequence_markers: tuple[str, ...] = ()
    require_context: bool = True
    window: int = 16
    context_terms: tuple[str, ...] = ()
    short_number_max_digits: int = 4
    composite_min_digits: int = 4

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "NumericBoundaryConfig":
        """从策略表原始内容装配配置。

        :param raw: 策略表 YAML 解析结果（整份策略表，不只是 numeric_boundary 段）。
        :param source: 策略表来源（写进报错信息，让人知道该改哪个文件）。
        :raises NumericBoundaryConfigError: 缺段、出现未知道具键或取值非法。
        """
        if not isinstance(raw, Mapping):
            raise NumericBoundaryConfigError(f"策略表根节点必须是映射：{source}")
        if "numeric_boundary" not in raw:
            raise NumericBoundaryConfigError(
                f"策略表缺少 numeric_boundary 段：{source}"
                "（数字类歧义消解必须显式声明 —— 缺段不等于「本院没有这类数字」）"
            )
        section = raw["numeric_boundary"]
        if not isinstance(section, Mapping):
            raise NumericBoundaryConfigError("策略表 numeric_boundary 段必须是映射")
        unknown = sorted(set(section) - set(_NUMERIC_BOUNDARY_KEYS))
        if unknown:
            raise NumericBoundaryConfigError(
                f"策略表 numeric_boundary 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(sorted(_NUMERIC_BOUNDARY_KEYS))}）"
            )

        def _terms(key: str) -> tuple[str, ...]:
            items = section.get(key, []) or []
            if not isinstance(items, (list, tuple)):
                raise NumericBoundaryConfigError(
                    f"策略表 numeric_boundary.{key} 必须是列表"
                )
            values: list[str] = []
            for item in items:
                if not isinstance(item, str) or not item.strip():
                    raise NumericBoundaryConfigError(
                        f"策略表 numeric_boundary.{key} 含空值或非字符串：{item!r}"
                    )
                values.append(item.strip())
            return tuple(dict.fromkeys(values))

        window = section.get("window", 16)
        if isinstance(window, bool) or not isinstance(window, int) or window < 1:
            raise NumericBoundaryConfigError(
                f"策略表 numeric_boundary.window 非法：{window!r}"
            )

        require_context = section.get("require_context", True)
        if not isinstance(require_context, bool):
            raise NumericBoundaryConfigError(
                f"策略表 numeric_boundary.require_context 必须是布尔：{require_context!r}"
            )

        context_terms = _terms("context_terms")
        if require_context and not context_terms:
            raise NumericBoundaryConfigError(
                "策略表 numeric_boundary.context_terms 不能为空"
                "（要求上下文词却没有词表，会把全部编号判成告警档）"
            )

        short_max = section.get("short_number_max_digits", _DEFAULT_SHORT_NUMBER_MAX_DIGITS)
        if isinstance(short_max, bool) or not isinstance(short_max, int) or short_max < 1:
            raise NumericBoundaryConfigError(
                f"策略表 numeric_boundary.short_number_max_digits 非法：{short_max!r}"
            )

        composite_min = section.get("composite_min_digits", _DEFAULT_COMPOSITE_MIN_DIGITS)
        if (
            isinstance(composite_min, bool)
            or not isinstance(composite_min, int)
            or composite_min < 1
        ):
            raise NumericBoundaryConfigError(
                f"策略表 numeric_boundary.composite_min_digits 非法：{composite_min!r}"
            )

        return cls(
            dose_units=_terms("dose_units"),
            currency_marks=_terms("currency_marks"),
            page_markers=_terms("page_markers"),
            bed_markers=_terms("bed_markers"),
            date_markers=_terms("date_markers"),
            sequence_markers=_terms("sequence_markers"),
            require_context=require_context,
            window=window,
            context_terms=context_terms,
            short_number_max_digits=short_max,
            composite_min_digits=composite_min,
        )


#: 装载缓存：(策略表路径, 修改时间) → 数字类歧义消解配置
_CACHE: dict[tuple[str, float], NumericBoundaryConfig] = {}


def load_numeric_boundary_config(
    path: str | Path | None = None,
) -> NumericBoundaryConfig:
    """装载数字类歧义消解配置。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises NumericBoundaryConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise NumericBoundaryConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise NumericBoundaryConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    config = NumericBoundaryConfig.from_policy(raw, source=str(target))
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


# --------------------------------------------------------------------- 判定


class NumericBoundary:
    """数字候选的边界判定器。

    :param config: 配置；缺省取一份「不消歧」的默认配置。
    """

    def __init__(self, config: NumericBoundaryConfig | None = None) -> None:
        self.config = config or NumericBoundaryConfig()
        # 剂量单位大小写不敏感（mg / Mg / MG），其余标记原样比对
        self._dose_units = tuple(item.lower() for item in self.config.dose_units)

    # ---------------------------------------------------------------- 判定

    def classify(self, text: str, start: int, end: int) -> str | None:
        """判定一个数字候选的边界类别。

        :param text: 材料正文。
        :param start: 候选区间起点（含）。
        :param end: 候选区间终点（不含）。
        :return: 边界类别（``dose`` / ``amount`` / ``date`` / ``page`` / ``bed`` /
            ``sequence``），没有边界信号时返回 ``None``（照常按编号候选继续判）。
        """
        config = self.config
        raw = text[start:end]
        digit_count = sum(1 for char in raw if char.isdigit())
        left = text[:start]
        right = text[end:]
        right_stripped = self._strip_gap(self._strip_fraction(right))
        left_stripped = left.rstrip(_GAP_CHARS)

        # 1) 剂量：紧邻剂量单位（不看位数 —— 大剂量单位同样不像住院号）
        #    剂量单位大小写不敏感（mg / Mg / MG 同一写法）
        if self._starts_with(right_stripped.lower(), self._dose_units):
            return "dose"

        # 2) 金额：紧邻货币符号
        if self._starts_with(right_stripped, config.currency_marks):
            return "amount"

        # 3) 日期片段：紧邻年月日，或落在连字符数字串里（日期 / 分段写的复合标识）
        if self._starts_with(right_stripped, config.date_markers):
            return "date"
        parts, index = self._hyphen_run(text, start, end) or (None, 0)
        if parts is not None:
            if len(parts) >= 3:
                # ISO 写法日期（2026-01-05）：整串都是日期片段
                return "date"
            if len(parts) == 2:
                other = parts[1 - index]
                if len(other) >= config.composite_min_digits:
                    # 分段写的复合标识（110101-19491231002）：一段不是编号
                    return "date"

        # 4) 页码 / 床号 / 序号：只对短数字生效（见模块说明的理由）
        if digit_count <= config.short_number_max_digits:
            if self._starts_with(right_stripped, config.page_markers):
                return "page"
            if self._starts_with(right_stripped, config.bed_markers):
                return "bed"
            if self._ends_with(left_stripped, config.page_markers):
                return "page"
            if self._ends_with(left_stripped, config.sequence_markers):
                return "sequence"
            if self._ends_with(self._strip_joiners(left_stripped), config.bed_markers):
                return "bed"
        return None

    def has_context(self, text: str, start: int, end: int) -> bool:
        """命中附近是否有编号类上下文词。

        :param text: 材料正文。
        :param start: 候选区间起点（含）。
        :param end: 候选区间终点（不含）。
        """
        config = self.config
        if not config.require_context or not config.context_terms:
            return True
        low = max(0, start - config.window)
        high = min(len(text), end + config.window)
        window = text[low:high]
        return any(term in window for term in config.context_terms)

    def requires_context(self, label: str) -> bool:
        """某实体类别是否必须带邻近上下文词才算身份。"""
        return label in CONTEXT_REQUIRED_LABELS

    # ---------------------------------------------------------------- 内部

    @staticmethod
    def _hyphen_run(text: str, start: int, end: int) -> tuple[list[str], int] | None:
        """取出候选所在的「连字符数字串」，按连字符切成各段。

        候选可能落在整串的任意一段（``110101-19491231002`` 里的前半段与后半段
        都要挡住），所以先向两侧扫出整串，再切段，并记下候选落在第几段。

        :param text: 材料正文。
        :param start: 候选区间起点（含）。
        :param end: 候选区间终点（不含）。
        :return: ``(各段, 候选所在段的下标)``；不是连字符数字串时返回 ``None``。
        """
        begin = start
        while begin > 0 and (text[begin - 1].isdigit() or text[begin - 1] == "-"):
            begin -= 1
        finish = end
        while finish < len(text) and (text[finish].isdigit() or text[finish] == "-"):
            finish += 1
        raw_run = text[begin:finish]
        # 首尾的孤立连字符不属于数字串（「报告-2026-01-05」里的第一个连字符）
        leading = len(raw_run) - len(raw_run.lstrip("-"))
        run = raw_run.strip("-")
        begin += leading
        if "-" not in run:
            return None
        parts = run.split("-")
        if not all(part.isdigit() for part in parts):
            return None
        index = run[: max(0, start - begin)].count("-")
        return parts, index

    @staticmethod
    def _strip_fraction(text: str) -> str:
        """剥掉紧跟在数字后面的小数部分（金额 245000.00 元）。"""
        match = _FRACTION_RE.match(text)
        return text[match.end() :] if match else text

    @staticmethod
    def _strip_gap(text: str) -> str:
        """剥掉数字与标记之间的间隔字符（空白与标点）。"""
        return text.lstrip(_GAP_CHARS)

    @staticmethod
    def _strip_joiners(text: str) -> str:
        """剥掉标记后面的连接词（「床号」「床位」里的「号」「位」）。"""
        if text and text[-1] in ("号", "位"):
            return text[:-1]
        return text

    @staticmethod
    def _starts_with(text: str, markers: Sequence[str]) -> bool:
        """文本是否以某个标记开头（剂量单位按小写比对）。"""
        return any(marker and text.startswith(marker) for marker in markers)

    @staticmethod
    def _ends_with(text: str, markers: Sequence[str]) -> bool:
        """文本是否以某个标记结尾。"""
        return any(marker and text.endswith(marker) for marker in markers)
