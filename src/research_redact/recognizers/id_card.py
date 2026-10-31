"""身份证识别器（校验位形态）：GB 11643 加权校验位。

第三种形态的落地。前两种形态（正则 / 名单）都判不了身份证：

- **正则形态**只能看形状 —— 18 位数字确实稀有，但设备序列号、耗材条码、
  订单号同样可以是 18 位数字。按形状硬判，等于把一批**不是身份**的串当成
  身份证脱掉（脱过头），而报告里真身份证那一位被漏掉时，机构从产物里根本
  看不出来（漏脱更隐蔽）；
- **名单形态**（患者主索引）判的是「这段属于哪位患者」，身份证不在主索引里。

身份证自带**可验证的自校验结构**：GB 11643 规定 18 位居民身份证由
「6 位地址码 + 8 位出生日期码 + 3 位顺序码 + 1 位校验码」组成，校验码按
七段加权因子（7-9-10-5-8-4-2 循环）算出 —— 算对了才是身份证号，算不对
就不是。**校验位形态因此是身份证这类编号唯一诚实的判据**：正则给候选，
校验函数给真伪。

三条不可违反的纪律：

1. **校验位不通过 → 降为告警档，不判为身份** —— 它「长得像身份证但校验
   不过」是一个**事实**，得留在命中清单里供人工抽检，但不能算身份类残留
   （否则一批格式非法的设备号就能把整批研究数据拦下来，告警也就失去意义）。
2. **已判定不通过的候选不得被上下文词复活** —— 校验位不通过不是「证据不足」，
   是「已经判定不通过」；所以它带 ``metadata["boost_allowed"] = False``，
   邻近窗口里出现「身份证」三个字也不许把它抬成身份类。
3. **15 位旧版身份证号不判为身份证** —— 旧版 15 位**没有校验位**，无法验证；
   判成身份就是把一串没法验证的数字当成身份证脱掉。它降为告警档并写明
   「旧版、无校验位」，由人工抽检。

**不变量**：命中解释（``reason``）与 ``metadata`` 都不得含命中原文 ——
解释会原样写进逐处命中清单（全项目同一条红线）。因此连**期望的校验码**
也不写进解释：那是命中原文的一个字符。
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from ..models import RecognizerResult
from .base import ChecksumRecognizer
from .shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "GB11643_CHECK_CODES",
    "GB11643_WEIGHTS",
    "ID_CARD_ENTITY",
    "IdCardConfig",
    "IdCardConfigError",
    "IdCardRecognizer",
    "IdCardVerdict",
    "VerdictKind",
    "gb11643_check_char",
    "load_id_card_config",
    "validate_id_card",
]


#: 命中后给出的实体类别（与策略表 ``entities`` 段的键一致）。
ID_CARD_ENTITY = "ID_CARD"

#: GB 11643 校验码的加权因子：7-9-10-5-8-4-2 循环，共 17 位。
GB11643_WEIGHTS: tuple[int, ...] = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)

#: 加权和模 11 后的校验码表（余数 0→1，1→0，2→X，…）。
GB11643_CHECK_CODES: str = "10X98765432"

#: 18 位身份证候选：17 位数字 + 末位（数字或 X / x）。
_ID_CARD_18_PATTERN = r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])"

#: 15 位旧版身份证候选（无校验位）。边界约束保证它不会从 18 位号的中间
#: 切出来 —— 前后紧邻数字时一律不匹配。
_ID_CARD_15_PATTERN = r"(?<![0-9A-Za-z])\d{15}(?![0-9A-Za-z])"

#: ``recognizers.id_card`` 段允许的键。出现未知道具键即报错 ——
#: 拼错的键不会被静默忽略，否则「以为配了校验位、其实没配」没人会发现。
_CONFIG_KEYS: tuple[str, ...] = (
    "enabled",
    "confirm_score",
    "invalid_score",
    "legacy_score",
    "require_valid_birth_date",
)

#: 出生日期码的合法年份下限（身份证最早一批发于 1984 年，出生年份不会更早）。
_MIN_BIRTH_YEAR = 1900

#: 装载缓存：(策略表路径, 修改时间) → 识别器配置
_CACHE: dict[tuple[str, float], "IdCardConfig"] = {}


class IdCardConfigError(ValueError):
    """身份证识别器配置非法（缺段 / 未知道具键 / 数值越界 / 门槛关系不成立）。"""


class VerdictKind(str, enum.Enum):
    """一个身份证候选的判定结果。"""

    #: 18 位 + 出生日期合法 + 校验位通过 —— 判为身份类。
    VALID = "valid"
    #: 18 位 + 出生日期合法，但校验位对不上 —— 降为告警档。
    CHECKSUM_FAIL = "checksum_fail"
    #: 18 位 + 校验位对得上，但出生日期段不是合法日历日期 —— 降为告警档。
    BIRTH_DATE_INVALID = "birth_date_invalid"
    #: 15 位旧版号（无校验位，无法验证）—— 降为告警档。
    LEGACY_15 = "legacy_15"
    #: 结构就不对（长度或字符构成不合法）—— 不判为身份证。
    MALFORMED = "malformed"


@dataclass(frozen=True)
class IdCardVerdict:
    """一个候选的判定结论。

    :param kind: 判定结果。
    :param detail: 一句人话解释（**不含命中原文**，也不含期望校验码）。
    """

    kind: VerdictKind
    detail: str = ""


# --------------------------------------------------------------------- 校验


def gb11643_check_char(body17: str) -> str:
    """按 GB 11643 算出 17 位本体对应的校验码。

    :param body17: 17 位数字本体（6 位地址码 + 8 位出生日期码 + 3 位顺序码）。
    :return: 校验码（``0``-``9`` 或 ``X``）。
    :raises ValueError: 本体不是 17 位数字。
    """
    if len(body17) != 17 or not body17.isdigit():
        raise ValueError(f"GB 11643 本体必须是 17 位数字：{body17!r}")
    total = sum(
        int(char) * weight for char, weight in zip(body17, GB11643_WEIGHTS)
    )
    return GB11643_CHECK_CODES[total % 11]


def is_valid_birth_date(segment: str) -> bool:
    """出生日期码（``YYYYMMDD``）是否为合法日历日期。

    年份下限 1900、上限取当年 —— 出生日期不可能在未来，也不可能早到
    身份证制度之前（那类串是设备号或条码，不是身份证）。
    """
    if len(segment) != 8 or not segment.isdigit():
        return False
    year = int(segment[0:4])
    month = int(segment[4:6])
    day = int(segment[6:8])
    if not _MIN_BIRTH_YEAR <= year <= date.today().year:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def validate_id_card(
    candidate: str, *, require_valid_birth_date: bool = True
) -> IdCardVerdict:
    """判定一个身份证候选。

    判定顺序：**结构 → 出生日期 → 校验位**。先看结构与出生日期，是因为这两
    项不过就「压根不是身份证」，后面那个校验位算出来也没有意义。

    :param candidate: 候选串（18 位或 15 位）。
    :param require_valid_birth_date: 是否要求出生日期码是合法日历日期。
    :return: 判定结论（**不含命中原文**）。
    """
    text = candidate.strip()
    if len(text) == 15:
        if text.isdigit():
            return IdCardVerdict(
                VerdictKind.LEGACY_15, "15 位旧版身份证号（无校验位，无法验证）"
            )
        return IdCardVerdict(VerdictKind.MALFORMED, "15 位串含非数字字符")
    if len(text) != 18:
        return IdCardVerdict(
            VerdictKind.MALFORMED, "长度既不是 18 位也不是 15 位"
        )

    body = text[:17]
    check_char = text[17].upper()
    if not body.isdigit() or check_char not in "0123456789X":
        return IdCardVerdict(VerdictKind.MALFORMED, "不是合法的身份证号字符构成")

    if require_valid_birth_date and not is_valid_birth_date(body[6:14]):
        return IdCardVerdict(
            VerdictKind.BIRTH_DATE_INVALID, "身份证号出生日期段不是合法日期"
        )

    expected = gb11643_check_char(body)
    if expected != check_char:
        return IdCardVerdict(
            VerdictKind.CHECKSUM_FAIL,
            "GB 11643 校验位不通过（末位校验码与加权计算结果不一致）",
        )
    return IdCardVerdict(VerdictKind.VALID, "GB 11643 校验位通过")


# --------------------------------------------------------------------- 配置


@dataclass(frozen=True)
class IdCardConfig:
    """身份证识别器的配置（全部从策略表读）。

    :param confirm_score: 校验位通过时的分数（确认档）。
    :param invalid_score: 校验位不通过 / 出生日期非法时的分数（告警档）。
    :param legacy_score: 15 位旧号时的分数（告警档）。
    :param require_valid_birth_date: 是否要求出生日期码是合法日历日期。
    :param enabled: 是否启用。
    """

    confirm_score: float = 0.9
    invalid_score: float = 0.2
    legacy_score: float = 0.2
    require_valid_birth_date: bool = True
    enabled: bool = True

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "IdCardConfig":
        """从策略表原始内容装配配置（整份 YAML，不只是 ``recognizers`` 段）。

        :raises IdCardConfigError: 缺 ``recognizers.id_card`` 段、出现未知道具键、
            数值越界，或「降档分数不低于确认分数」—— 后者会让「校验位不通过
            降为告警档」这条纪律失效。
        """
        if not isinstance(raw, Mapping):
            raise IdCardConfigError(f"策略表根节点必须是映射：{source}")
        recognizers = raw.get("recognizers")
        if not isinstance(recognizers, Mapping):
            raise IdCardConfigError(f"策略表缺少 recognizers 段：{source}")
        section = recognizers.get("id_card")
        if not isinstance(section, Mapping):
            raise IdCardConfigError(f"策略表缺少 recognizers.id_card 段：{source}")
        unknown = sorted(set(section) - set(_CONFIG_KEYS))
        if unknown:
            raise IdCardConfigError(
                f"策略表 recognizers.id_card 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_CONFIG_KEYS)}）"
            )

        confirm = float(section.get("confirm_score", 0.9))
        invalid = float(section.get("invalid_score", 0.2))
        legacy = float(section.get("legacy_score", 0.2))
        for name, value in (
            ("confirm_score", confirm),
            ("invalid_score", invalid),
            ("legacy_score", legacy),
        ):
            if not 0.0 <= value <= 1.0:
                raise IdCardConfigError(
                    f"策略表 recognizers.id_card.{name} 越界：{value}"
                )
        if not invalid < confirm:
            raise IdCardConfigError(
                "策略表 recognizers.id_card 门槛关系不成立：要求 invalid_score"
                f"({invalid}) < confirm_score({confirm}) —— 校验位不通过的候选"
                " 必须落在告警档，不得判为身份"
            )
        if not legacy < confirm:
            raise IdCardConfigError(
                "策略表 recognizers.id_card 门槛关系不成立：要求 legacy_score"
                f"({legacy}) < confirm_score({confirm}) —— 15 位旧版号无法验证，"
                " 不得判为身份"
            )
        return cls(
            confirm_score=confirm,
            invalid_score=invalid,
            legacy_score=legacy,
            require_valid_birth_date=bool(
                section.get("require_valid_birth_date", True)
            ),
            enabled=bool(section.get("enabled", True)),
        )


def load_id_card_config(path: str | Path | None = None) -> IdCardConfig:
    """装载身份证识别器配置。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises IdCardConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise IdCardConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise IdCardConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    config = IdCardConfig.from_policy(raw, source=str(target))
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


# ----------------------------------------------------------------- 识别器


class IdCardRecognizer(ChecksumRecognizer):
    """身份证识别器（校验位形态）。

    继承 :class:`~research_redact.recognizers.base.ChecksumRecognizer`：正则只
    给候选、校验函数给真伪、校验不通过降为告警档且不得被上下文词复活 ——
    校验位形态的契约都在基类里；本类补上身份证特有的三件事：**15 位旧号**
    的单独处理、**出生日期**合法性校验，以及**可读解释**。

    :param config: 识别器配置；缺省从策略表装载。
    :param score_thresholds: 逐类别阈值覆盖（策略表
        ``thresholds.per_recognizer`` 优先于它）。
    """

    def __init__(
        self,
        recognizer_id: str = "id_card",
        name: str = "身份证校验位识别器",
        config: IdCardConfig | None = None,
        score_thresholds: Mapping[str, float] | None = None,
        available: bool = True,
    ) -> None:
        active = config if config is not None else load_id_card_config()
        super().__init__(
            recognizer_id=recognizer_id,
            name=name,
            pattern=_ID_CARD_18_PATTERN,
            label=ID_CARD_ENTITY,
            validator=lambda candidate: validate_id_card(candidate).kind
            is VerdictKind.VALID,
            base_score=active.confirm_score,
            invalid_score=active.invalid_score,
            score_thresholds=score_thresholds,
        )
        self.config = active
        self._legacy_pattern = re.compile(_ID_CARD_15_PATTERN)
        self._available = available
        # 本识别器自带门槛：确认档的判定门槛固定为 confirm_score，
        # 降档分数（invalid / legacy）低于它 —— 与全局阈值被谁调高调低无关。
        self.score_thresholds.setdefault(ID_CARD_ENTITY, active.confirm_score)

    def is_available(self) -> bool:
        """识别器被策略表关掉时返回 False —— 不产出任何命中。"""
        return self._available and self.config.enabled

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        """扫描文本，产出身份证候选的判定结果。

        18 位与 15 位分两路扫：18 位先判（结构完整、能校验），15 位旧号只判
        「像旧版号」这一件事，**不判为身份证**。
        """
        if not self.is_available():
            return []
        wanted = set(entities) if entities else None
        if wanted is not None and ID_CARD_ENTITY not in wanted:
            return []
        results: list[RecognizerResult] = []

        for match in self._compiled.finditer(text):
            start, end = match.span()
            if end <= start:
                continue
            verdict = validate_id_card(
                match.group(0),
                require_valid_birth_date=self.config.require_valid_birth_date,
            )
            if verdict.kind is VerdictKind.VALID:
                results.append(
                    RecognizerResult(
                        start=start,
                        end=end,
                        label=ID_CARD_ENTITY,
                        score=self.base_score,
                        reason="GB 11643 校验位通过（18 位身份证号）",
                        recognizer=self.id,
                        metadata={"verdict": verdict.kind.value, "id_length": 18},
                    )
                )
                continue
            results.append(
                RecognizerResult(
                    start=start,
                    end=end,
                    label=ID_CARD_ENTITY,
                    score=self.invalid_score,
                    reason=f"{verdict.detail}，按告警档处理",
                    recognizer=self.id,
                    metadata={
                        "verdict": verdict.kind.value,
                        "id_length": 18,
                        # 已判定「不是身份证」：邻近上下文词不得把它抬成身份类
                        "boost_allowed": False,
                    },
                )
            )

        for match in self._legacy_pattern.finditer(text):
            start, end = match.span()
            if end <= start:
                continue
            results.append(
                RecognizerResult(
                    start=start,
                    end=end,
                    label=ID_CARD_ENTITY,
                    score=self.config.legacy_score,
                    reason="15 位旧版身份证号（无校验位，无法验证），不判为身份证，按告警档处理",
                    recognizer=self.id,
                    metadata={
                        "verdict": VerdictKind.LEGACY_15.value,
                        "id_length": 15,
                        "boost_allowed": False,
                    },
                )
            )
        return results
