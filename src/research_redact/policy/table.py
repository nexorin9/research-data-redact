"""策略表：装载并校验 ``policy/research.yaml``。

对应源产品两处机制：

- ``presidio-analyzer/presidio_analyzer/analyzer_engine_provider.py`` 的
  **YAML 装配形态**（保留）：一份 YAML 装下阈值、识别器清单与配置；
- ``presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py`` 的
  **按实体类别取动作**（保留）：``AnonymizerEngine.anonymize``（:29-113）里
  那个 ``operators`` 字典，就是「实体类别 → 处置动作」表。

本项目把两段合成**一份**策略表，本模块只管四段：

===================  ==========================================================
段                   含义
===================  ==========================================================
``thresholds``       全局阈值 + 逐识别器阈值覆盖
``recognizers``      识别器名册：谁启用、谁关闭（task 22）
``entities``         实体类别 → 处置动作（replace / redact / keep /
                     hmac_pseudonym 一致代号 / hmac_restore 一致代号还原）
``allow_list``       白名单（exact / regex 两种匹配）
``context``          邻近窗口上下文词表（窗口半径与系数由上下文打分模块校验）
``pseudonymization`` 一致代号口径（方案名 / 前缀 / 摘要位数）
``profiles``         档位：一份策略表装下多套处置口径（默认档 / 一致代号档）
===================  ==========================================================

**装配器**（:func:`build_registry`）把这份策略表变成一张可用的识别器注册表：
识别器清单 → 逐识别器阈值 → 全局阈值 → 白名单 → 上下文词表，全部按本文件读。
对应源产品 ``analyzer_engine_provider.py`` 的 **YAML 装配形态**（保留）：一份
YAML 装下识别器清单与阈值，装配结果给分析引擎用。

编号形态（``number_shapes`` / ``contact_shapes``）与数值消歧
（``numeric_boundary``）由 ``recognizers/shapes.py`` 各自装载，不在本模块
重复校验；``recognizers`` 段的启停与逐项阈值覆盖由装配器（任务 22）接管。

**档位（``profiles``）**：默认档是「占位符替换」，一致代号档（``pseudonym``）
把两个身份绑定类切到 ``hmac_pseudonym`` —— 同一患者跨材料代号恒等。档内按键
浅合并：档里写了哪个类别就用档里的动作，没写的沿用默认档。用
``$RESEARCH_POLICY_PROFILE`` 选用；**档名写错即报错**，不静默退回默认档。

**核心纪律：配置非法即报错，不静默取默认值。**
脱敏产品里，「以为已经按本院写法识别过了、实际没生效」等于漏脱 —— 一个静默的
默认值比一次显式的报错危险得多。因此：

- 缺整段（``thresholds`` / ``entities`` / ``allow_list`` / ``context``）→ 报错；
- 阈值越界 → 报错；
- 处置动作名不在词表内 → 报错；
- 实体类别没有声明动作 → 报错；
- 白名单正则编译不过 → 报错；
- 出现未知道具键 → 报错（拼错的键不会被静默忽略）；
- 档位名不存在 → 报错（退回默认档 = 以为按一致代号档脱了、实际是占位符）。

**不变量**：策略表里不出现任何凭据、任何命中原文。
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from ..recognizers.shapes import POLICY_PATH_ENV, default_policy_path
from .dicom import DicomConfig, DicomConfigError
from .operators import KNOWN_OPERATOR_NAMES, RESERVED_OPERATOR_NAMES, ActionSpec
from .pseudonym import PseudonymConfig, PseudonymConfigError
from .residual_policy import ResidualConfig, ResidualConfigError

__all__ = [
    "CATALOG_NAMES",
    "CONTEXT_BOOST_ID",
    "POLICY_PROFILE_ENV",
    "PolicyTable",
    "PolicyTableError",
    "RECOGNIZER_IDS",
    "RecognizerCatalog",
    "UndeclaredEntityError",
    "build_registry",
    "load_policy_table",
]


class PolicyTableError(ValueError):
    """策略表非法（缺段 / 阈值越界 / 未知处置动作 / 未知道具键 …）。"""


class UndeclaredEntityError(PolicyTableError):
    """运行时：实体类别未在策略表声明。

    与「配置非法」分开：这一类不是策略表写错了，而是**新识别器产出了策略表
    还没登记的类别**。调用方据此把该处记为「保留原文（策略表未声明）」并留痕，
    而不是默认脱掉或默认放过。
    """


#: 策略表根节点允许出现的段。
#: 新增段必须在此登记 —— 否则「拼错的段名」会被静默忽略，而段名拼错往往意味着
#: 整段配置根本没生效（例如把 ``entities`` 写成 ``entity``）。
_ROOT_SECTIONS: tuple[str, ...] = (
    "version",
    "thresholds",
    "recognizers",
    "entities",
    "allow_list",
    "context",
    "numeric_boundary",
    "number_shapes",
    "contact_shapes",
    "conflicts",
    "columns",
    "pseudonymization",
    "profiles",
    "dicom",
    "residual",
)

#: 选用档位的环境变量名（与 .env.example 一一对应）。
POLICY_PROFILE_ENV = "RESEARCH_POLICY_PROFILE"

#: 档位内允许出现的「说明」键（不进策略表装配，只给人看）。
_PROFILE_META_KEYS: tuple[str, ...] = ("description",)

#: ``thresholds`` 段允许的键。
_THRESHOLD_KEYS: tuple[str, ...] = ("global", "per_recognizer")

#: ``entities`` 段每项允许的键。
_ENTITY_KEYS: tuple[str, ...] = ("action", "placeholder")

#: ``allow_list`` 段允许的键。
_ALLOW_LIST_KEYS: tuple[str, ...] = ("exact", "regex")

#: ``columns`` 段允许的键。
_COLUMN_KEYS: tuple[str, ...] = ("business_columns", "bound_columns", "content_columns")

#: 上下文词最短长度：1 个字的词切不出 n-gram，进了词表也不会生效。
_MIN_TERM_LENGTH = 2

#: 识别器名册：策略表 ``recognizers`` 段允许出现的**识别器**名。
#: 名字即注册表里的识别器 ID —— 逐识别器阈值覆盖（``thresholds.per_recognizer``）
#: 用的就是这套名字。
RECOGNIZER_IDS: tuple[str, ...] = (
    "labeled_field",
    "visit_no",
    "phone_birth",
    "id_card",
    "patient_index",
)

#: 上下文加分器的名字。它在同一个 ``recognizers`` 段里启停，但**不是**注册表里的
#: 识别器 —— 它不产出命中，只给命中加分 —— 因此不参与逐识别器阈值覆盖。
CONTEXT_BOOST_ID = "context_boost"

#: ``recognizers`` 段允许出现的全部名字。
CATALOG_NAMES: tuple[str, ...] = (*RECOGNIZER_IDS, CONTEXT_BOOST_ID)

#: 额外键由各自配置模块校验的识别器（``id_card`` / ``patient_index`` 的分段参数
#: 由那两个模块自己校验并报错，策略表装载层不重复）。
_SELF_CONFIGURED_RECOGNIZERS: tuple[str, ...] = ("id_card", "patient_index")

#: 其余识别器在 ``recognizers`` 段里只接受 ``enabled`` 一个键 —— 多出来的键
#: 一律按拼错处理（不被静默忽略）。
_PLAIN_RECOGNIZER_KEYS: tuple[str, ...] = ("enabled",)

#: 装载缓存：(策略表路径, 修改时间, 档位名) → 策略表
_CACHE: dict[tuple[str, float, str], "PolicyTable"] = {}


@dataclass(frozen=True)
class ColumnConfig:
    """列级策略段（``policy/research.yaml`` → ``columns``）。

    段的存在与否不影响主路径，只影响**结构化材料的按列处理**：

    - :param business_columns: 业务标识与说明列（申请单号 / 伦理批件号 / 材料 ID /
      材料类型 / 路径 / 材料技术内容列）—— 逐字保留，不识别不脱敏；
    - :param bound_columns: 患者绑定列（患者主索引主键）—— 身份锚定走 HIS 主索引
      读回的权威名单，不由此处的通用正则改写；
    - :param content_columns: 显式划为内容列的列名；为空表示「未列出的列一律按
      内容列处理」（默认方向是扫描，宁可多脱也不放过）。

    装配校验见 :func:`_build_columns`。
    """

    business_columns: tuple[str, ...] = ()
    bound_columns: tuple[str, ...] = ()
    content_columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecognizerCatalog:
    """识别器名册（策略表 ``recognizers`` 段的装配结果）。

    :param enabled: 识别器名 → 是否启用。**没出现在策略表里的识别器默认启用**
        （缺段 ≠ 全部禁用）；但名字写错会直接报错，不会被当成「没配」。
    """

    enabled: Mapping[str, bool] = field(default_factory=dict)

    def is_enabled(self, recognizer_id: str) -> bool:
        """某个识别器是否启用。"""
        return bool(self.enabled.get(recognizer_id, True))

    def disabled_names(self) -> tuple[str, ...]:
        """被关掉的识别器名（按策略表里的声明顺序）。"""
        return tuple(name for name, flag in self.enabled.items() if not flag)

    def enabled_names(self) -> tuple[str, ...]:
        """被打开的识别器名（按策略表里的声明顺序）。"""
        return tuple(name for name, flag in self.enabled.items() if flag)


@dataclass(frozen=True)
class PolicyTable:
    """一次装载得到的策略表。

    :param version: 策略表版本号（写进批次快照，见任务 36）。
    :param global_threshold: 全局阈值，低于它降为告警档。
    :param per_recognizer_thresholds: 逐识别器阈值覆盖。
    :param entity_actions: 实体类别 → 处置动作。
    :param allow_list_exact: 白名单精确项。
    :param allow_list_regex: 白名单正则项。
    :param context_terms: 邻近窗口上下文词表。
    :param columns: 列级策略段（结构化材料按列处理时用）。
    :param source: 策略表来源路径（写进报错信息，让人知道该改哪个文件）。
    :param catalog: 识别器名册（谁启用、谁关闭）。
    :param pseudonymization: 一致代号口径（方案名 / 前缀 / 摘要位数）。
    :param profile: 当前选用的档位名（空串 = 默认档）。
    :param dicom: DICOM tag 级去标识的处置口径（保留 / 清空 / 替换 / 私有 tag）。
    :param residual: 残留自检的分级口径（阻断级 / 提示级 / 未登记档位怎么算）。
    :param document: **生效配置**的原始内容（档位已合并到根节点）。策略表
        快照（task 36）靠它算出版本号 —— 版本号认的是「这份配置实际长什么样」，
        不是文件字节：改注释不改行为时版本号不变。
    """

    version: int = 1
    global_threshold: float = 0.5
    per_recognizer_thresholds: Mapping[str, float] = field(default_factory=dict)
    entity_actions: Mapping[str, ActionSpec] = field(default_factory=dict)
    allow_list_exact: tuple[str, ...] = ()
    allow_list_regex: tuple[str, ...] = ()
    context_terms: tuple[str, ...] = ()
    columns: ColumnConfig = field(default_factory=ColumnConfig)
    source: str = ""
    catalog: RecognizerCatalog = field(default_factory=RecognizerCatalog)
    pseudonymization: PseudonymConfig = field(default_factory=PseudonymConfig)
    profile: str = ""
    dicom: DicomConfig = field(default_factory=DicomConfig)
    residual: ResidualConfig = field(default_factory=ResidualConfig)
    document: Mapping[str, Any] = field(default_factory=dict)

    def action_for(self, entity: str) -> ActionSpec:
        """取某个实体类别的处置动作。

        :raises UndeclaredEntityError: 该类别未在策略表声明。
        """
        spec = self.entity_actions.get(entity)
        if spec is None:
            raise UndeclaredEntityError(
                f"实体类别未在策略表声明：{entity}（来源 {self.source}）"
                " —— 未声明的类别既不默认脱敏，也不默认放过，须补进策略表"
            )
        return spec

    def resolver(self) -> Callable[[str], ActionSpec]:
        """返回主路径用的解析函数（``redact_text`` 的 ``actions`` 参数）。"""
        return self.action_for

    def threshold_for(self, recognizer_id: str) -> float:
        """某个识别器的生效阈值：逐识别器覆盖优先，其次全局阈值。"""
        return self.per_recognizer_thresholds.get(recognizer_id, self.global_threshold)

    def recognizer_enabled(self, recognizer_id: str) -> bool:
        """某个识别器是否启用（策略表 ``recognizers`` 段的启停开关）。"""
        return self.catalog.is_enabled(recognizer_id)

    def entity_names(self) -> tuple[str, ...]:
        """已声明处置动作的实体类别（按声明顺序）。"""
        return tuple(self.entity_actions)


# --------------------------------------------------------------------- 装载


def load_policy_table(
    path: str | Path | None = None, profile: str | None = None
) -> PolicyTable:
    """装载策略表。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :param profile: 选用档位；缺省取 ``$RESEARCH_POLICY_PROFILE``（空串 = 默认档）。
    :raises PolicyTableError: 策略表缺失、结构不对、配置非法或档位不存在。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise PolicyTableError(f"策略表不存在：{target}")
    profile_name = profile if profile is not None else _resolve_profile(profile)
    # 缓存键必须带上档位名：同一份文件、不同档位，装出来的东西不一样。
    key = (str(target), target.stat().st_mtime, profile_name)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyTableError(f"策略表解析失败：{target}（{exc}）") from exc
    table = _build_table(raw, source=str(target), profile=profile_name)
    _CACHE[key] = table
    return table


def _resolve_profile(profile: str | None) -> str:
    """解析档位名：显式参数 → 环境变量 → 空串（默认档）。"""
    if profile is not None:
        return profile.strip()
    return (os.environ.get(POLICY_PROFILE_ENV) or "").strip()


def _resolve_policy_path(path: str | Path | None) -> Path:
    """解析策略表路径：显式路径 → 环境变量 → 项目内默认。"""
    if path is not None:
        return Path(path)
    env_value = os.environ.get(POLICY_PATH_ENV)
    if env_value:
        return Path(env_value)
    return default_policy_path()


# --------------------------------------------------------------------- 装配


def _build_table(
    raw: Any, source: str, profile: str = "", *, validate_profiles: bool = True
) -> PolicyTable:
    """把策略表原始内容装配成策略表对象。

    :param profile: 选用档位名；空串 = 默认档。档位内容按键浅合并到根节点上，
        合并后再走同一套装配与校验 —— 档位里的动作同样受「未知动作报错」
        「replace 必须给占位符」等规则约束。
    :param validate_profiles: 是否连带校验各档位（档位装配时关掉，避免自递归）。
    """
    if not isinstance(raw, Mapping):
        raise PolicyTableError(f"策略表根节点必须是映射：{source}")

    unknown = sorted(set(raw) - set(_ROOT_SECTIONS))
    if unknown:
        raise PolicyTableError(
            f"策略表含未知段：{'、'.join(unknown)}"
            f"（可用：{'、'.join(_ROOT_SECTIONS)}）"
        )

    if validate_profiles:
        _validate_profiles(raw, source)

    merged = _apply_profile(raw, profile, source)

    version = merged.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise PolicyTableError(f"策略表 version 非法：{version!r}")

    global_threshold, per_recognizer = _build_thresholds(merged, source)
    catalog = _build_recognizers(merged, source)
    entity_actions = _build_entities(merged, source)
    allow_exact, allow_regex = _build_allow_list(merged, source)
    context_terms = _build_context_terms(merged, source)
    columns = _build_columns(merged, source)
    pseudonymization = _build_pseudonymization(merged, source)
    dicom = _build_dicom(merged, source)
    residual = _build_residual(merged, source)

    return PolicyTable(
        version=version,
        global_threshold=global_threshold,
        per_recognizer_thresholds=per_recognizer,
        entity_actions=entity_actions,
        allow_list_exact=allow_exact,
        allow_list_regex=allow_regex,
        context_terms=context_terms,
        columns=columns,
        source=source,
        catalog=catalog,
        pseudonymization=pseudonymization,
        profile=profile,
        dicom=dicom,
        residual=residual,
        # 生效配置原样留一份：快照（task 36）据此算版本号、并落一份可重放的
        # 配置副本。深拷贝是必要的 —— 档位合并是浅合并，留着引用会被后续
        # 改动带偏。
        document=copy.deepcopy(dict(merged)),
    )


def _build_residual(raw: Mapping[str, Any], source: str) -> ResidualConfig:
    """装配残留自检分级口径段（``policy/research.yaml`` → ``residual``）。

    该段是**可选**的：缺段时用出厂口径（身份类与就诊编号类阻断、通用数字类
    只提示）。段一旦出现就逐项校验 —— 写错的键不会被静默忽略。
    """
    try:
        return ResidualConfig.from_policy(raw.get("residual"), source=source)
    except ResidualConfigError as exc:
        raise PolicyTableError(str(exc)) from exc


def _build_dicom(raw: Mapping[str, Any], source: str) -> DicomConfig:
    """装配 DICOM tag 级去标识段（``policy/research.yaml`` → ``dicom``）。

    该段是**可选**的：缺段时用出厂口径（保留必要 tag、清空身份 tag、清空私有
    tag）。段一旦出现就逐项校验 —— 写错的键不会被静默忽略。
    """
    try:
        return DicomConfig.from_policy(raw.get("dicom"), source=source)
    except DicomConfigError as exc:
        raise PolicyTableError(str(exc)) from exc


def _build_pseudonymization(raw: Mapping[str, Any], source: str) -> PseudonymConfig:
    """装配一致代号口径段。

    该段是**可选**的：缺段时用出厂口径（与 spec.md 4.2 一致）。段一旦出现就
    逐项校验 —— 写错的键不会被静默忽略。
    """
    try:
        return PseudonymConfig.from_policy(raw, source=source)
    except PseudonymConfigError as exc:
        raise PolicyTableError(str(exc)) from exc


# ------------------------------------------------------------------- 档位


def _validate_profiles(raw: Mapping[str, Any], source: str) -> None:
    """校验 ``profiles`` 段：每个档位都必须能装配成功。

    档位写错了却在选用时才报错，等于「默认档跑得好好的，一开档位就炸」——
    所以**装载时就逐个档位试装一遍**。
    """
    profiles = raw.get("profiles")
    if profiles is None:
        return
    if not isinstance(profiles, Mapping):
        raise PolicyTableError(f"策略表 profiles 段必须是映射：{source}")
    for name, body in profiles.items():
        label = str(name).strip()
        if not label:
            raise PolicyTableError(f"策略表 profiles 含空的档位名：{source}")
        if not isinstance(body, Mapping):
            raise PolicyTableError(f"策略表 profiles.{label} 必须是映射：{source}")
        unknown = sorted(
            set(body) - set(_ROOT_SECTIONS) - set(_PROFILE_META_KEYS) - {"profiles"}
        )
        if unknown:
            raise PolicyTableError(
                f"策略表 profiles.{label} 含未知段：{'、'.join(unknown)}"
                f"（可覆盖的段：{'、'.join(_ROOT_SECTIONS)}）"
            )
        for section, value in body.items():
            if section in _PROFILE_META_KEYS or section == "profiles":
                continue
            if not isinstance(value, Mapping):
                raise PolicyTableError(
                    f"策略表 profiles.{label}.{section} 必须是映射（档内按键浅合并）："
                    f"{source}"
                )
        # 试装一遍：档位里的动作同样受全套校验约束
        merged = _apply_profile(raw, label, source)
        _build_table(merged, source, profile=label, validate_profiles=False)


def _apply_profile(
    raw: Mapping[str, Any], profile: str, source: str
) -> dict[str, Any]:
    """把档位内容按键浅合并到根节点上，返回合并后的策略表原始内容。

    浅合并的含义：**段内按键覆盖**。``entities`` 段里档位写了
    ``PATIENT_NAME``，就用档位里那一条；没写的类别沿用默认档。

    :raises PolicyTableError: 档位不存在（**不静默退回默认档** —— 退回等于
        「以为按一致代号档脱了、实际脱成了占位符」）。
    """
    if not profile:
        return dict(raw)
    profiles = raw.get("profiles")
    if not isinstance(profiles, Mapping) or not profiles:
        raise PolicyTableError(
            f"策略表没有 profiles 段，无法选用档位「{profile}」：{source}"
        )
    body = profiles.get(profile)
    if body is None:
        available = "、".join(sorted(str(name) for name in profiles))
        raise PolicyTableError(
            f"策略表没有档位「{profile}」（可用：{available}）：{source}"
            " —— 档位名写错时退回默认档，等于以为按一致代号档脱了、实际脱成了占位符"
        )
    merged = dict(raw)
    for section, value in body.items():
        if section in _PROFILE_META_KEYS:
            continue
        base = raw.get(section)
        if isinstance(base, Mapping) and isinstance(value, Mapping):
            merged[section] = {**base, **value}
        else:
            merged[section] = value
    return merged


def _require_section(raw: Mapping[str, Any], name: str, source: str) -> Mapping[str, Any]:
    """取必填段；缺失或类型不对即报错。"""
    if name not in raw:
        raise PolicyTableError(f"策略表缺少 {name} 段：{source}")
    section = raw[name]
    if not isinstance(section, Mapping):
        raise PolicyTableError(f"策略表 {name} 段必须是映射：{source}")
    return section


def _reject_unknown(section: Mapping[str, Any], name: str, allowed: tuple[str, ...]) -> None:
    """出现未知道具键即报错（拼错的键不会被静默忽略）。"""
    unknown = sorted(set(section) - set(allowed))
    if unknown:
        raise PolicyTableError(
            f"策略表 {name} 含未知道具键：{'、'.join(unknown)}"
            f"（可用：{'、'.join(allowed)}）"
        )


def _check_threshold(value: Any, name: str) -> float:
    """阈值必须在 [0, 1] 之间。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyTableError(f"策略表 {name} 必须是数值：{value!r}")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise PolicyTableError(f"策略表 {name} 越界：{number}（要求 0 ≤ 阈值 ≤ 1）")
    return number


def _build_thresholds(
    raw: Mapping[str, Any], source: str
) -> tuple[float, dict[str, float]]:
    """装配阈值段。"""
    section = _require_section(raw, "thresholds", source)
    _reject_unknown(section, "thresholds", _THRESHOLD_KEYS)
    if "global" not in section:
        raise PolicyTableError(f"策略表 thresholds 缺少 global：{source}")
    global_threshold = _check_threshold(section["global"], "thresholds.global")

    per_section = section.get("per_recognizer", {}) or {}
    if not isinstance(per_section, Mapping):
        raise PolicyTableError(f"策略表 thresholds.per_recognizer 必须是映射：{source}")
    per_recognizer: dict[str, float] = {}
    for recognizer_id, value in per_section.items():
        key = str(recognizer_id).strip()
        if not key:
            raise PolicyTableError("策略表 thresholds.per_recognizer 含空的识别器名")
        if key not in RECOGNIZER_IDS:
            raise PolicyTableError(
                f"策略表 thresholds.per_recognizer 含未知识别器名：{key!r}"
                f"（可覆盖的识别器：{'、'.join(RECOGNIZER_IDS)}）"
                " —— 写错的名字若被静默忽略，这段阈值就等于没配"
            )
        per_recognizer[key] = _check_threshold(
            value, f"thresholds.per_recognizer.{key}"
        )
    return global_threshold, per_recognizer


def _build_recognizers(raw: Mapping[str, Any], source: str) -> RecognizerCatalog:
    """装配识别器名册段（``recognizers``）。

    该段是**可选**的：缺段时全部识别器启用（缺段 ≠ 全部禁用）。段存在时逐项校验：

    - 名字不在名册内 → 报错（拼错的名字若被静默忽略，「以为关了某识别器、
      实际还在跑」就会一直没人发现）；
    - ``enabled`` 不是布尔 → 报错（``enabled: "false"`` 是非空字符串，
      按真值处理 —— 看着像关掉了，实际还在脱）；
    - 简单识别器出现 ``enabled`` 以外的键 → 报错（键名拼错不被静默忽略）。

    :raises PolicyTableError: 段结构错、名字未知、``enabled`` 类型错或键名拼错。
    """
    section = raw.get("recognizers")
    if section is None:
        return RecognizerCatalog()
    if not isinstance(section, Mapping):
        raise PolicyTableError(f"策略表 recognizers 段必须是映射：{source}")

    enabled: dict[str, bool] = {}
    for recognizer_id, item in section.items():
        name = str(recognizer_id).strip()
        if not name:
            raise PolicyTableError(f"策略表 recognizers 含空的识别器名：{source}")
        if name not in CATALOG_NAMES:
            raise PolicyTableError(
                f"策略表 recognizers 含未知识别器名：{name!r}"
                f"（可用：{'、'.join(CATALOG_NAMES)}）：{source}"
            )
        if not isinstance(item, Mapping):
            raise PolicyTableError(
                f"策略表 recognizers.{name} 必须是映射（含 enabled 键）：{source}"
            )
        if name not in _SELF_CONFIGURED_RECOGNIZERS:
            _reject_unknown(item, f"recognizers.{name}", _PLAIN_RECOGNIZER_KEYS)
        flag = item.get("enabled", True)
        if not isinstance(flag, bool):
            raise PolicyTableError(
                f"策略表 recognizers.{name}.enabled 必须是布尔：{flag!r}"
                " —— 写成字符串会被当成真值，看着像关掉了、实际还在跑"
            )
        enabled[name] = flag
    return RecognizerCatalog(enabled=enabled)


def _build_entities(raw: Mapping[str, Any], source: str) -> dict[str, ActionSpec]:
    """装配「实体类别 → 处置动作」段。"""
    section = _require_section(raw, "entities", source)
    if not section:
        raise PolicyTableError(f"策略表 entities 段为空：{source}")

    actions: dict[str, ActionSpec] = {}
    for entity, item in section.items():
        name = str(entity).strip()
        if not name:
            raise PolicyTableError(f"策略表 entities 含空的实体类别名：{source}")
        if not isinstance(item, Mapping):
            raise PolicyTableError(
                f"策略表 entities.{name} 必须是映射（含 action 键）：{source}"
            )
        _reject_unknown(item, f"entities.{name}", _ENTITY_KEYS)
        if "action" not in item:
            raise PolicyTableError(
                f"策略表 entities.{name} 缺少处置动作（action）：{source}"
            )
        action = str(item["action"]).strip()
        if action not in KNOWN_OPERATOR_NAMES:
            raise PolicyTableError(
                f"策略表 entities.{name}.action 未知处置动作：{action!r}"
                f"（可用：{'、'.join(KNOWN_OPERATOR_NAMES)}）"
            )
        placeholder = str(item.get("placeholder", "") or "")
        if action == "replace" and not placeholder.strip():
            raise PolicyTableError(
                f"策略表 entities.{name} 声明 replace 动作但未给 placeholder：{source}"
            )
        if action != "replace" and placeholder.strip():
            raise PolicyTableError(
                f"策略表 entities.{name} 的 placeholder 只在 replace 动作下有意义：{source}"
            )
        actions[name] = ActionSpec(action=action, placeholder=placeholder)
    return actions


def _build_allow_list(
    raw: Mapping[str, Any], source: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """装配白名单段。"""
    section = _require_section(raw, "allow_list", source)
    _reject_unknown(section, "allow_list", _ALLOW_LIST_KEYS)

    exact_raw = section.get("exact", []) or []
    if not isinstance(exact_raw, (list, tuple)):
        raise PolicyTableError(f"策略表 allow_list.exact 必须是列表：{source}")
    exact: list[str] = []
    for item in exact_raw:
        if not isinstance(item, str) or not item.strip():
            raise PolicyTableError(f"策略表 allow_list.exact 含空值或非字符串：{item!r}")
        exact.append(item.strip())

    regex_raw = section.get("regex", []) or []
    if not isinstance(regex_raw, (list, tuple)):
        raise PolicyTableError(f"策略表 allow_list.regex 必须是列表：{source}")
    regex: list[str] = []
    for item in regex_raw:
        if not isinstance(item, str) or not item.strip():
            raise PolicyTableError(f"策略表 allow_list.regex 含空值或非字符串：{item!r}")
        pattern = item.strip()
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyTableError(
                f"策略表 allow_list.regex 正则编译不过：{pattern!r}（{exc}）"
            ) from exc
        regex.append(pattern)
    return tuple(exact), tuple(regex)


def _build_context_terms(raw: Mapping[str, Any], source: str) -> tuple[str, ...]:
    """装配邻近窗口上下文词表。

    窗口半径、n-gram 长度与加分系数由 ``recognizers/context_boost.py`` 校验
    （那边有更细的规则）；本模块只取词表，并保证词表本身是干净的非空字符串。
    """
    section = _require_section(raw, "context", source)
    terms_raw = section.get("terms", []) or []
    if not isinstance(terms_raw, (list, tuple)):
        raise PolicyTableError(f"策略表 context.terms 必须是列表：{source}")
    terms: list[str] = []
    for item in terms_raw:
        if not isinstance(item, str):
            raise PolicyTableError(f"策略表 context.terms 含非字符串：{item!r}")
        word = item.strip()
        if len(word) < _MIN_TERM_LENGTH:
            raise PolicyTableError(
                f"策略表 context.terms 含过短词：{item!r}"
                f"（至少 {_MIN_TERM_LENGTH} 个字，否则切不出 n-gram）"
            )
        terms.append(word)
    return tuple(dict.fromkeys(terms))


def _build_columns(raw: Mapping[str, Any], source: str) -> ColumnConfig:
    """装配列级策略段（``columns``）。

    该段是**可选**的：缺段时按结构性默认处理（申请单号 / 伦理批件号 /
    材料 ID / 材料类型 / 路径 / 材料技术内容列为业务列，患者主索引主键为
    绑定列），默认方向是**保守**的 —— 少脱总比脱错业务标识安全。

    段存在时三类列名都要写清，且**同一列不得出现在两类里**（角色冲突：
    一列既是「逐字保留」又是「要脱敏」，必然是配置写错了）。

    :raises PolicyTableError: 段结构错、列名非法或角色冲突。
    """
    if "columns" not in raw:
        return ColumnConfig()
    section = raw["columns"]
    if not isinstance(section, Mapping):
        raise PolicyTableError(f"策略表 columns 段必须是映射：{source}")
    _reject_unknown(section, "columns", _COLUMN_KEYS)

    parsed: dict[str, tuple[str, ...]] = {}
    for key in _COLUMN_KEYS:
        value = section.get(key, []) or []
        if not isinstance(value, (list, tuple)):
            raise PolicyTableError(f"策略表 columns.{key} 必须是列表：{source}")
        names: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise PolicyTableError(
                    f"策略表 columns.{key} 含空值或非字符串：{item!r}"
                )
            names.append(item.strip())
        parsed[key] = tuple(dict.fromkeys(names))

    clashes: list[str] = []
    for left_key, right_key in (
        ("business_columns", "bound_columns"),
        ("business_columns", "content_columns"),
        ("bound_columns", "content_columns"),
    ):
        for name in parsed[left_key]:
            if name in parsed[right_key]:
                clashes.append(f"{name}（{left_key} 与 {right_key}）")
    if clashes:
        raise PolicyTableError(
            f"策略表 columns 段列角色冲突：{'、'.join(clashes)}：{source}"
            " —— 同一列不得既是逐字保留的业务列，又是要脱敏的内容列"
        )

    return ColumnConfig(
        business_columns=parsed["business_columns"],
        bound_columns=parsed["bound_columns"],
        content_columns=parsed["content_columns"],
    )


def reserved_action_note(name: str) -> str:
    """预留挂载位的一句话说明（写进运维摘要）。"""
    return RESERVED_OPERATOR_NAMES.get(name, "")


# --------------------------------------------------------------------- 装配


def build_registry(table: PolicyTable | None = None, binding: Any = None) -> Any:
    """按策略表装配识别器注册表。

    这是**策略表 → 可用注册表**的那一段：识别器清单（谁启用）→ 逐识别器阈值
    覆盖 → 全局阈值 → 白名单 → 上下文词表，全部按 ``policy/research.yaml`` 读。
    装配器被主路径（:mod:`research_redact.daemon.pipeline`）与残留自检
    （:mod:`research_redact.audit.residual`）共用，因此**只有这一处**实现 ——
    两边各写一份，迟早会出现「主路径认了、残留自检没认」的漏脱。

    :param table: 已装载的策略表；缺省按 ``$RESEARCH_POLICY_FILE`` 装载。
    :param binding: 患者主索引权威名单（给 ``patient_index`` 名单识别器用）。
    :return: :class:`research_redact.recognizers.registry.RecognizerRegistry`。
    :raises PolicyTableError: 策略表非法（未知识别器名 / 阈值越界 / 未知处置动作）。

    .. note::
       这里的 import 是**延迟**的：``recognizers.assembly`` 需要
       ``policy.table`` 装载策略表，而本模块又要装出识别器 —— 顶层互相 import
       会成环。延迟 import 是断环的常规做法。
    """
    from ..recognizers.assembly import build_default_registry

    return build_default_registry(binding=binding, table=table)
