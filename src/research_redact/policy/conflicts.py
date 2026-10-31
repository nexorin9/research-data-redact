"""冲突裁决规则（策略表装载）：把 YAML 装成统一裁决规则。

**裁决逻辑本身不在本模块** —— 跨识别器的重叠 / 包含 / 交叉 / 完全重合统一由
:mod:`research_redact.arbitration` 里的 :func:`arbitrate` 定案（源产品把这两
件事分成 ``analyzer_engine.py`` 的 ``remove_duplicates`` 与
``anonymizer_engine.py`` 的 ``_remove_conflicts_and_get_text_manipulation_data``
两处，本轮合并为一处）。本模块只负责两件事：

1. **从策略表装载规则** —— 档位优先级、默认档位、同类相邻合并开关；
2. **校验配置** —— 缺段 / 未知道具键 / 未知档位 / 实体类别没分配档位，
   一律抛 :class:`ConflictConfigError`，**不静默取默认值**。

规则集（档位优先 > 同级比分数 > 解释更完整者胜 > 同类先合并）与
:class:`~research_redact.arbitration.ArbitrationRules` 一致，
装配纪律见该模块文档字符串。

装配纪律：优先级表写在 ``policy/research.yaml`` 的 ``conflicts`` 段。配置非法
一律报错 —— 静默降级会让「以为按身份类优先处理了」与「实际没有」长期并存。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from ..arbitration import (
    ArbitrationError,
    ArbitrationResult,
    ArbitrationRules,
    TIER_ORDER,
    arbitrate,
)
from ..models import EntitySpan
from ..recognizers.shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "ConflictConfigError",
    "ConflictResolution",
    "ConflictResolutionError",
    "ConflictRules",
    "PRIORITY_TIERS",
    "load_conflict_rules",
    "resolve_conflicts",
]


class ConflictConfigError(ValueError):
    """冲突裁决配置非法（缺段 / 未知道具键 / 未知档位 / 实体类别没分配档位 …）。"""


#: 裁决未收敛时的异常（与统一裁决引擎共用同一个类型）。
ConflictResolutionError = ArbitrationError

#: 优先级档位：数值小 = 优先。档位名与 ``policy/research.yaml`` 的
#: ``conflicts.priority`` 取值一一对应。
PRIORITY_TIERS: dict[str, int] = dict(TIER_ORDER)

#: ``conflicts`` 段允许出现的键。
_CONFLICT_KEYS: tuple[str, ...] = (
    "merge_adjacent_same_label",
    "default_tier",
    "priority",
)

#: 装载缓存：(策略表路径, 修改时间) → 冲突裁决规则
_CACHE: dict[tuple[str, float], "ConflictRules"] = {}


# --------------------------------------------------------------------- 数据形状


@dataclass(frozen=True)
class ConflictRules(ArbitrationRules):
    """一次装载得到的冲突裁决规则。

    字段与 :class:`~research_redact.arbitration.ArbitrationRules` 一致
    （档位优先级 / 默认档位 / 同类相邻合并开关 / 来源路径），
    裁决的排序与取舍也由基类统一实现 —— 本模块不再另写一套。
    """


@dataclass(frozen=True)
class ConflictResolution(ArbitrationResult):
    """冲突裁决的结果：保留的区间（互不重叠）+ 被裁剪的区间（含原因）。"""


# --------------------------------------------------------------------- 装载


def load_conflict_rules(path: str | Path | None = None) -> ConflictRules:
    """装载冲突裁决规则。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises ConflictConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise ConflictConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConflictConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    rules = _build_rules(raw, source=str(target))
    _CACHE[key] = rules
    return rules


def _resolve_policy_path(path: str | Path | None) -> Path:
    """解析策略表路径：显式路径 → 环境变量 → 项目内默认。"""
    if path is not None:
        return Path(path)
    env_value = os.environ.get(POLICY_PATH_ENV)
    if env_value:
        return Path(env_value)
    return default_policy_path()


def _build_rules(raw: Any, source: str) -> ConflictRules:
    """把策略表原始内容装配成冲突裁决规则。"""
    if not isinstance(raw, Mapping):
        raise ConflictConfigError(f"策略表根节点必须是映射：{source}")
    if "conflicts" not in raw:
        raise ConflictConfigError(
            f"策略表缺少 conflicts 段：{source}"
            " —— 没有优先级表就不知道身份类与就诊编号类谁让谁"
        )
    section = raw["conflicts"]
    if not isinstance(section, Mapping):
        raise ConflictConfigError(f"策略表 conflicts 段必须是映射：{source}")
    unknown = sorted(set(section) - set(_CONFLICT_KEYS))
    if unknown:
        raise ConflictConfigError(
            f"策略表 conflicts 含未知道具键：{'、'.join(unknown)}"
            f"（可用：{'、'.join(_CONFLICT_KEYS)}）"
        )

    default_tier = str(section.get("default_tier", "generic")).strip()
    if default_tier not in PRIORITY_TIERS:
        raise ConflictConfigError(
            f"策略表 conflicts.default_tier 非法：{default_tier!r}"
            f"（可用：{'、'.join(PRIORITY_TIERS)}）"
        )

    priority_raw = section.get("priority", {}) or {}
    if not isinstance(priority_raw, Mapping):
        raise ConflictConfigError(f"策略表 conflicts.priority 必须是映射：{source}")
    priority: dict[str, str] = {}
    for entity, tier in priority_raw.items():
        name = str(entity).strip()
        if not name:
            raise ConflictConfigError("策略表 conflicts.priority 含空的实体类别名")
        tier_name = str(tier).strip()
        if tier_name not in PRIORITY_TIERS:
            raise ConflictConfigError(
                f"策略表 conflicts.priority.{name} 档位非法：{tier_name!r}"
                f"（可用：{'、'.join(PRIORITY_TIERS)}）"
            )
        priority[name] = tier_name

    _check_entities_declared(raw, priority, source)

    return ConflictRules(
        priority=priority,
        default_tier=default_tier,
        merge_adjacent_same_label=bool(section.get("merge_adjacent_same_label", True)),
        source=source,
    )


def _check_entities_declared(
    raw: Mapping[str, Any], priority: Mapping[str, str], source: str
) -> None:
    """策略表里声明了实体类别就必须分配优先级档位。

    漏分配会让新类别静默落到默认档（通用数字类）—— 一条没登记的身份类别
    可能因此输给就诊编号类，正是「以为脱干净了实际没有」的那类事故。
    """
    entities = raw.get("entities")
    if not isinstance(entities, Mapping):
        return
    missing = sorted(str(name) for name in entities if str(name) not in priority)
    if missing:
        raise ConflictConfigError(
            f"策略表 entities 声明了未分配优先级档位的实体类别：{'、'.join(missing)}"
            f"（来源 {source}）—— 请在 conflicts.priority 段补齐档位"
        )


# --------------------------------------------------------------------- 裁决


def resolve_conflicts(
    spans: Sequence[EntitySpan],
    *,
    text: str = "",
    rules: ConflictRules | None = None,
) -> ConflictResolution:
    """裁决互相冲突的实体区间，产出**互不重叠**的改写计划。

    底层是统一裁决引擎 :func:`research_redact.arbitration.arbitrate`
    （重叠 / 包含 / 交叉 / 完全重合一处定案），本函数保留为策略层入口。

    :param spans: 待裁决的实体区间（调用方只放**会被改写**的区间；白名单放行与
        告警档不参与裁决 —— 它们不改写正文，不该影响别人的边界）。
    :param text: 原文（判断两段之间是否只隔空白时要用）。
    :param rules: 裁决规则；缺省从策略表装载。
    :return: 保留的区间（互不重叠）+ 被丢弃 / 被裁剪的区间（含原因）。
    """
    active = rules or load_conflict_rules()
    result = arbitrate(spans, text=text, rules=active)
    return ConflictResolution(kept=result.kept, dropped=result.dropped)
