"""残留自检的分级口径（策略表 ``residual`` 段）。

残留自检要回答**两个不同**的问题：

1. **拦不拦**（阻断级）—— 产物里还留着患者身份吗？留着就不能交付。
2. **提不提**（提示级）—— 产物里还有没有「看着像编号、但并不是身份」的串？
   剂量、金额、页码、床号、设备号都长这样。把它们算成残留，真正的漏脱会被
   淹没 —— 值班的人扫一眼全是「30mL、128.50、第 2 页」，反而看不出那 3 处
   姓名还留着。

这两件事的口径不该写死在代码里：换一家医院、换一个院区，对「什么算身份」
的判断不一样（有的院区把设备号也当敏感信息，有的不当）。口径写在策略表的
``residual`` 段 —— **改 YAML 即改分级**，与本项目其余口径同一个纪律。

档位名沿用冲突裁决那套（``policy/research.yaml`` → ``conflicts.priority``）：
``identity``（身份类）/ ``encounter``（就诊编号类）/ ``generic``（通用数字类）。
策略表里没登记的类别按 ``unclassified`` 处理，默认**按身份类算**（宁可多拦
一批，也不让「新增识别器的类别没登记」变成一条永远查不出来的漏脱）。

**不变量**：本模块只产出**分级判断**，不接触任何患者数据 —— 它看的是档位名，
不是姓名、住院号。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..arbitration import TIER_ORDER

__all__ = [
    "SEVERITY_BLOCKING",
    "SEVERITY_HINT",
    "SEVERITY_IGNORE",
    "UNCLASSIFIED_TIER",
    "ResidualConfig",
    "ResidualConfigError",
    "load_residual_config",
]


#: 阻断级：命中即拦住这一批，不得投递。
SEVERITY_BLOCKING = "blocking"

#: 提示级：命中只提示，不阻断投递。
SEVERITY_HINT = "hint"

#: 不计入：既不阻断也不提示（如策略表里没登记、又被显式划为忽略的档位）。
SEVERITY_IGNORE = "ignore"

#: 策略表未登记档位的实体类别所用的标记名。
UNCLASSIFIED_TIER = "unclassified"

#: 策略表 ``residual`` 段允许出现的键。
_RESIDUAL_KEYS: tuple[str, ...] = (
    "blocking_tiers",
    "hint_tiers",
    "unclassified_is_blocking",
)

#: 出厂口径：身份类与就诊编号类阻断，通用数字类只提示。
_DEFAULT_BLOCKING: tuple[str, ...] = ("identity", "encounter")
_DEFAULT_HINT: tuple[str, ...] = ("generic",)


class ResidualConfigError(ValueError):
    """残留分级口径非法（未知道具键 / 未知档位 / 档位重复分派）。"""


@dataclass(frozen=True)
class ResidualConfig:
    """残留自检的分级口径。

    :param blocking_tiers: 阻断级档位（命中即拦住这一批）。
    :param hint_tiers: 提示级档位（命中只提示，不阻断）。
    :param unclassified_is_blocking: 未登记档位的实体类别是否按身份类处理。
    :param source: 策略表来源路径（写进报错信息，让人知道该改哪个文件）。
    """

    blocking_tiers: tuple[str, ...] = _DEFAULT_BLOCKING
    hint_tiers: tuple[str, ...] = _DEFAULT_HINT
    unclassified_is_blocking: bool = True
    source: str = ""

    @classmethod
    def from_policy(
        cls, raw: Any, source: str = "", *, require_section: bool = False
    ) -> "ResidualConfig":
        """从策略表 ``residual`` 段装配分级口径。

        :param raw: 策略表里的 ``residual`` 段（缺段时为 None）。
        :param source: 策略表来源路径。
        :param require_section: 段缺失时是否报错（缺省不报 —— 用出厂口径）。
        :raises ResidualConfigError: 段结构错 / 未知道具键 / 未知档位 /
            同一档位既阻断又提示。
        """
        if raw is None:
            if require_section:
                raise ResidualConfigError(f"策略表缺少 residual 段：{source}")
            return cls(source=source)
        if not isinstance(raw, Mapping):
            raise ResidualConfigError(f"策略表 residual 段必须是映射：{source}")
        unknown = sorted(set(raw) - set(_RESIDUAL_KEYS))
        if unknown:
            raise ResidualConfigError(
                f"策略表 residual 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_RESIDUAL_KEYS)}）"
            )

        known_tiers = set(TIER_ORDER)
        blocking = _read_tiers(
            raw.get("blocking_tiers", list(_DEFAULT_BLOCKING)),
            "blocking_tiers",
            known_tiers,
            source,
        )
        hint = _read_tiers(
            raw.get("hint_tiers", list(_DEFAULT_HINT)),
            "hint_tiers",
            known_tiers,
            source,
        )
        overlap = sorted(set(blocking) & set(hint))
        if overlap:
            raise ResidualConfigError(
                f"策略表 residual 里档位 {'、'.join(overlap)} 同时被分派为阻断级与提示级"
                f"（来源 {source}）—— 同一档位只能有一个去留"
            )
        flag = raw.get("unclassified_is_blocking", True)
        if not isinstance(flag, bool):
            raise ResidualConfigError(
                f"策略表 residual.unclassified_is_blocking 必须是布尔值：{flag!r}"
            )
        return cls(
            blocking_tiers=blocking,
            hint_tiers=hint,
            unclassified_is_blocking=flag,
            source=source,
        )

    def severity_of(self, tier: str) -> str:
        """某个档位在残留自检里的去留。

        :param tier: 档位名（``identity`` / ``encounter`` / ``generic`` /
            ``unclassified``）。
        :return: ``blocking``（阻断）/ ``hint``（只提示）/ ``ignore``（不计入）。
        """
        if tier in self.blocking_tiers:
            return SEVERITY_BLOCKING
        if tier in self.hint_tiers:
            return SEVERITY_HINT
        if tier == UNCLASSIFIED_TIER:
            return (
                SEVERITY_BLOCKING if self.unclassified_is_blocking else SEVERITY_HINT
            )
        return SEVERITY_IGNORE


def load_residual_config(path: str | None = None) -> ResidualConfig:
    """装载残留分级口径。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises ResidualConfigError: 策略表缺失、解析失败或配置非法。
    """
    from .table import PolicyTableError, load_policy_table

    try:
        table = load_policy_table(path)
    except PolicyTableError as exc:
        raise ResidualConfigError(str(exc)) from exc
    return table.residual


def _read_tiers(
    value: Any, key: str, known: set[str], source: str
) -> tuple[str, ...]:
    """读一个档位清单（去重、保序、校验档位名）。"""
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ResidualConfigError(
            f"策略表 residual.{key} 必须是列表：{value!r}（来源 {source}）"
        )
    tiers: list[str] = []
    for item in value:
        name = str(item).strip()
        if not name:
            raise ResidualConfigError(
                f"策略表 residual.{key} 含空档位名（来源 {source}）"
            )
        if name not in known:
            raise ResidualConfigError(
                f"策略表 residual.{key} 含未知档位：{name!r}"
                f"（可用：{'、'.join(sorted(known))}，来源 {source}）"
            )
        if name not in tiers:
            tiers.append(name)
    return tuple(tiers)
