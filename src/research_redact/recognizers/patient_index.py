"""患者身份锚定：HIS 患者主索引读回 → 权威名单 → 名单形态识别器。

**为什么需要这一层**：参考实现的识别层只认**通用 PII 模式**（姓名长什么样、
号码长什么样），不绑定权威患者实体。医院场景里这不够：

- **同名不同人**：张某某可能有两位，按姓名脱敏会把两个人脱成同一个；
- **一人多号**：同一位患者两次住院有不同住院号，按号码脱敏会拆成两个人；
- **不认识的人**：报告里出现的姓名可能根本不在本批患者清单里。

患者身份因此以 **HIS 患者主索引主键**为准 —— 主键是院内唯一的患者标识，
一致代号（HMAC over 主键，任务 24）也建在它上面。本模块是「名单形态」
识别器的落地：名单条目从**申请单声明的主键**与**主索引读回的记录**两处装配，
不猜、不扩、不按姓名硬匹配。

**四条匹配纪律**（本模块的全部规则）：

1. **只用主键，或「归一化姓名 + 就诊号」组合** —— 单独一个姓名**不判为身份**，
   只降为告警档：报告里出现一个姓名，不等于它就是本批的那位患者（可能是同名的
   另一个人，也可能压根不在本批清单里）。告警档照常进命中清单，但不计入身份类
   残留统计，由人工抽检。
2. **同名异人不合并、不串号** —— 两个不同主键共享同一姓名时，各自按自己的
   就诊号绑定到自己的主键；两人就诊号都挨着这个姓名时**判为歧义**，不猜。
3. **一人多号归一** —— 同一主键的多个住院号命中同一患者，落到同一个身份键
   （主键）上：一致代号的取值输入唯一，同一患者跨材料恒等。
4. **名单为空或主索引不可达时，本识别器不产出任何命中** —— 不降级为「按姓名
   硬匹配」。批次由状态机置 ``suspended``（挂起等主索引恢复），**不按正则直接
   脱**：在不认识患者是谁的情况下脱敏，等于拿可能错配的身份去交付数据。

**与字段标签识别器的分工**（两者不冲突）：字段标签识别器判的是「这一段**是**
患者姓名字段」（结构信号），本模块判的是「这一段**属于哪位**患者」（归属
信号）。前者负责脱敏，后者负责绑定归属；单独姓名在本模块降为告警档，但它在
字段标签识别器那里仍是一次正常的姓名脱敏 —— 两件事，不是两套结论。

**不变量**：命中解释（``reason``）只写命中方式，不写姓名、主键或住院号 ——
解释会原样写进逐处命中清单（与全项目「清单不记原文」同一条红线）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from ..models import RecognizerResult
from .base import Recognizer, normalize_text, normalize_with_offsets
from .shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "ID_ENTITY",
    "MATCH_AMBIGUOUS",
    "MATCH_NAME_AND_VISIT",
    "MATCH_NAME_ONLY",
    "MATCH_PRIMARY_KEY",
    "NAME_ENTITY",
    "PatientIndexBinding",
    "PatientIndexConfig",
    "PatientIndexConfigError",
    "PatientIndexEntry",
    "PatientIndexRecognizer",
    "PatientIndexUnavailableError",
    "binding_from_client",
    "load_patient_index_binding",
    "load_patient_index_config",
]


#: 名单命中给出的实体类别（与策略表 ``entities`` 段的键一致）。
NAME_ENTITY = "PATIENT_NAME"
ID_ENTITY = "PATIENT_ID"

#: 命中方式（写进 ``metadata``，供下游区分「按什么绑定的」）。
MATCH_PRIMARY_KEY = "patient_id"
MATCH_NAME_AND_VISIT = "name+visit_no"
MATCH_NAME_ONLY = "name_only"
MATCH_AMBIGUOUS = "ambiguous"

#: ``recognizers.patient_index`` 段允许的键。出现未知道具键即报错 ——
#: 拼错的键不会被静默忽略，否则「以为配了邻近半径、其实没配」没人会发现。
_CONFIG_KEYS: tuple[str, ...] = (
    "enabled",
    "proximity_radius",
    "confirm_threshold",
    "composite_score",
    "primary_key_score",
    "name_only_score",
)

#: 装载缓存：(策略表路径, 修改时间) → 名单识别器配置
_CACHE: dict[tuple[str, float], "PatientIndexConfig"] = {}


class PatientIndexConfigError(ValueError):
    """名单识别器配置非法（缺段 / 未知道具键 / 数值越界 / 门槛关系不成立）。"""


class PatientIndexUnavailableError(RuntimeError):
    """患者主索引不可达（或名单为空）—— 批次须挂起，不得按正则直接脱。

    调用方据此把批次置 ``suspended``。**不降级**：主索引不可达时按姓名硬匹配，
    等于拿可能错配的身份去交付科研数据。
    """


# --------------------------------------------------------------------- 配置


@dataclass(frozen=True)
class PatientIndexConfig:
    """名单形态识别器的配置（全部从策略表读）。

    :param proximity_radius: 姓名与就诊号之间允许的最大间隔（字符数）。
    :param confirm_threshold: 本识别器判定「确认为身份」的门槛。单独姓名命中的
        分数必须低于它 —— 这是「单独姓名一律降为告警档」的结构性保证：不依赖
        全局阈值被谁调高调低。
    :param composite_score: 「姓名 + 就诊号」组合命中的分数。
    :param primary_key_score: 主键命中的分数。
    :param name_only_score: 单独姓名命中的分数（必须低于 ``confirm_threshold``）。
    :param enabled: 是否启用。
    """

    proximity_radius: int = 24
    confirm_threshold: float = 0.5
    composite_score: float = 0.9
    primary_key_score: float = 0.95
    name_only_score: float = 0.3
    enabled: bool = True

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "PatientIndexConfig":
        """从策略表原始内容装配配置（整份 YAML，不只是 ``recognizers`` 段）。

        :raises PatientIndexConfigError: 缺 ``recognizers.patient_index`` 段、
            出现未知道具键或数值关系不成立。
        """
        if not isinstance(raw, Mapping):
            raise PatientIndexConfigError(f"策略表根节点必须是映射：{source}")
        recognizers = raw.get("recognizers")
        if not isinstance(recognizers, Mapping):
            raise PatientIndexConfigError(f"策略表缺少 recognizers 段：{source}")
        section = recognizers.get("patient_index")
        if not isinstance(section, Mapping):
            raise PatientIndexConfigError(
                f"策略表缺少 recognizers.patient_index 段：{source}"
            )
        unknown = sorted(set(section) - set(_CONFIG_KEYS))
        if unknown:
            raise PatientIndexConfigError(
                f"策略表 recognizers.patient_index 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_CONFIG_KEYS)}）"
            )

        radius = section.get("proximity_radius", 24)
        if not isinstance(radius, int) or isinstance(radius, bool) or radius < 1:
            raise PatientIndexConfigError(
                f"策略表 recognizers.patient_index.proximity_radius 非法：{radius!r}"
            )

        confirm = float(section.get("confirm_threshold", 0.5))
        composite = float(section.get("composite_score", 0.9))
        primary = float(section.get("primary_key_score", 0.95))
        name_only = float(section.get("name_only_score", 0.3))
        for name, value in (
            ("confirm_threshold", confirm),
            ("composite_score", composite),
            ("primary_key_score", primary),
            ("name_only_score", name_only),
        ):
            if not 0.0 <= value <= 1.0:
                raise PatientIndexConfigError(
                    f"策略表 recognizers.patient_index.{name} 越界：{value}"
                )
        if not name_only < confirm <= composite:
            raise PatientIndexConfigError(
                "策略表 recognizers.patient_index 门槛关系不成立："
                f"要求 name_only_score({name_only}) < confirm_threshold({confirm})"
                f" ≤ composite_score({composite})"
                " —— 单独姓名必须落在告警档，不得判为身份"
            )
        if primary < composite:
            raise PatientIndexConfigError(
                "策略表 recognizers.patient_index.primary_key_score"
                f"({primary}) 不得低于 composite_score({composite})"
                " —— 主键是最强的身份证据"
            )
        return cls(
            proximity_radius=radius,
            confirm_threshold=confirm,
            composite_score=composite,
            primary_key_score=primary,
            name_only_score=name_only,
            enabled=bool(section.get("enabled", True)),
        )


def load_patient_index_config(path: str | Path | None = None) -> PatientIndexConfig:
    """装载名单识别器配置。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises PatientIndexConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise PatientIndexConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PatientIndexConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    config = PatientIndexConfig.from_policy(raw, source=str(target))
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


# ----------------------------------------------------------------- 名单条目


@dataclass(frozen=True)
class PatientIndexEntry:
    """权威名单里的一位患者。

    :param patient_id: 患者主索引主键（**权威身份标识**）。
    :param name: 主索引读回的姓名。
    :param visit_nos: 该患者在本批材料里出现过的就诊号（可多个）。
    """

    patient_id: str
    name: str = ""
    visit_nos: tuple[str, ...] = ()

    @property
    def normalized_name(self) -> str:
        """归一化姓名（NFKC + 去空白 + 小写），用于稳定比较。"""
        return normalize_text(self.name)

    @property
    def normalized_visit_nos(self) -> tuple[str, ...]:
        """归一化就诊号清单（去空白、去重、保序）。"""
        seen: list[str] = []
        for visit_no in self.visit_nos:
            key = normalize_text(visit_no)
            if key and key not in seen:
                seen.append(key)
        return tuple(seen)


@dataclass(frozen=True)
class PatientIndexBinding:
    """一次装配得到的权威名单。

    :param entries: 名单条目。
    :param available: 主索引是否读得到（不可达时为 False）。
    :param reason: 不可用或为空的原因（写进告警文案）。
    :param source: 名单来源（写进日志，便于定位是哪次读回）。
    :param excluded_patient_ids: 主索引读回了、但**不在本批声明清单里**的主键
        （这类患者不得进入本批脱敏 —— 批次只认申请单声明的那些人）。
    """

    entries: tuple[PatientIndexEntry, ...] = ()
    available: bool = True
    reason: str = ""
    source: str = ""
    excluded_patient_ids: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """名单是否为空。"""
        return not self.entries

    @property
    def usable(self) -> bool:
        """名单是否可用：读得到且非空。"""
        return self.available and bool(self.entries)

    @property
    def suspend_reason(self) -> str:
        """批次该挂起的原因（可用时为空串）。"""
        if not self.available:
            return self.reason or "患者主索引不可达：批次挂起等恢复（不得按正则直接脱）"
        if not self.entries:
            return self.reason or (
                "患者主索引名单为空：申请单声明的患者在主索引里查不到，批次挂起等人工核对"
            )
        return ""

    def patient_ids(self) -> tuple[str, ...]:
        """名单里的主键清单（按登记顺序）。"""
        return tuple(entry.patient_id for entry in self.entries)

    def entry_for(self, patient_id: str) -> PatientIndexEntry | None:
        """按主键取名单条目。"""
        for entry in self.entries:
            if entry.patient_id == patient_id:
                return entry
        return None

    def entries_for_name(self, name: str) -> tuple[PatientIndexEntry, ...]:
        """按姓名取名单条目（同名多人时返回全部 —— 这正是要消歧的场景）。"""
        key = normalize_text(name)
        if not key:
            return ()
        return tuple(entry for entry in self.entries if entry.normalized_name == key)

    def entry_for_visit_no(self, visit_no: str) -> PatientIndexEntry | None:
        """按就诊号取名单条目（一人多号时都落在同一条目上）。"""
        key = normalize_text(visit_no)
        if not key:
            return None
        for entry in self.entries:
            if key in entry.normalized_visit_nos:
                return entry
        return None

    def entries_by_name(self) -> dict[str, tuple[PatientIndexEntry, ...]]:
        """归一化姓名 → 该姓名的全部名单条目。"""
        grouped: dict[str, list[PatientIndexEntry]] = {}
        for entry in self.entries:
            key = entry.normalized_name
            if not key:
                continue
            grouped.setdefault(key, []).append(entry)
        return {key: tuple(items) for key, items in grouped.items()}


# --------------------------------------------------------------------- 装载


def _record_fields(record: Any) -> tuple[str, str, str]:
    """从一条主索引记录里取（主键, 就诊号, 姓名）。

    接受映射（``{"patient_id": ...}``）或带同名属性的对象 —— 出站客户端读回的
    :class:`~research_redact.outbound.patient_index_client.PatientIndexRecord`
    与测试用的映射都能直接进。
    """
    if isinstance(record, Mapping):
        get = record.get
    else:
        def get(key: str, default: Any = "") -> Any:
            return getattr(record, key, default)

    patient_id = str(get("patient_id", "") or "").strip()
    visit_no = str(get("visit_no", "") or "").strip()
    name = str(get("name", "") or "").strip()
    return patient_id, visit_no, name


def load_patient_index_binding(
    records: Iterable[Any] | Mapping[str, Any] = (),
    *,
    declared_patient_ids: Sequence[str] = (),
    available: bool = True,
    reason: str = "",
    source: str = "",
) -> PatientIndexBinding:
    """装配权威名单（**名单装载接口**）。

    两个来源合成一份名单：

    - **申请单声明的** ``declared_patient_ids``（本批涉及哪些患者）—— 名单只收
      这些人；主索引读回了不在清单里的患者，记进 ``excluded_patient_ids``，
      不进本批脱敏（批次只认申请单声明的那些人）。
    - **主索引读回的** ``records``（每位患者的姓名与就诊号）—— 一人多号在这里
      归到同一个主键下。

    :param records: 主索引记录（映射或对象序列）。
    :param declared_patient_ids: 申请单声明的患者主索引主键；为空表示不设限。
    :param available: 主索引是否读得到；不可达时名单为空且 ``available=False``。
    :param reason: 不可用 / 为空的原因。
    :param source: 名单来源（写进日志）。
    """
    items = list(records.values()) if isinstance(records, Mapping) else list(records)
    declared = tuple(
        dict.fromkeys(str(item).strip() for item in declared_patient_ids if str(item).strip())
    )

    by_patient: dict[str, dict[str, Any]] = {}
    for record in items:
        patient_id, visit_no, name = _record_fields(record)
        if not patient_id:
            continue
        slot = by_patient.setdefault(patient_id, {"name": "", "visit_nos": []})
        if name and not slot["name"]:
            slot["name"] = name
        if visit_no and visit_no not in slot["visit_nos"]:
            slot["visit_nos"].append(visit_no)

    entries: list[PatientIndexEntry] = []
    excluded: list[str] = []
    for patient_id, slot in by_patient.items():
        if declared and patient_id not in declared:
            excluded.append(patient_id)
            continue
        entries.append(
            PatientIndexEntry(
                patient_id=patient_id,
                name=str(slot["name"]),
                visit_nos=tuple(slot["visit_nos"]),
            )
        )

    return PatientIndexBinding(
        entries=tuple(entries),
        available=available,
        reason=reason,
        source=source,
        excluded_patient_ids=tuple(excluded),
    )


def binding_from_client(
    client: Any,
    visit_nos: Sequence[str],
    *,
    declared_patient_ids: Sequence[str] = (),
    source: str = "HIS 患者主索引",
) -> PatientIndexBinding:
    """从 HIS 主索引客户端读回名单；读不通时返回**不可用**的名单。

    读不通（通道挂起 / 连不上 / 响应不对）不抛异常，而是返回
    ``available=False`` 的名单 —— 调用方据此把批次置 ``suspended``，
    **不降级**为按姓名硬匹配。

    :param client: 主索引客户端（须有 ``lookup_many`` 方法）。
    :param visit_nos: 要查的就诊号清单。
    :param declared_patient_ids: 申请单声明的患者主索引主键。
    :param source: 名单来源（写进日志）。
    """
    try:
        records = client.lookup_many([item for item in visit_nos if str(item).strip()])
    except Exception as exc:  # 通道挂起 / 连不上 / 响应不对，一律挂起批次
        return PatientIndexBinding(
            entries=(),
            available=False,
            reason=f"患者主索引不可达：{type(exc).__name__}：{exc}",
            source=source,
        )
    return load_patient_index_binding(
        records,
        declared_patient_ids=declared_patient_ids,
        source=source,
    )


def require_binding(binding: PatientIndexBinding) -> None:
    """名单不可用（不可达 / 为空）时报错 —— 调用方据此把批次置 ``suspended``。

    :raises PatientIndexUnavailableError: 名单不可用。
    """
    if binding.usable:
        return
    raise PatientIndexUnavailableError(binding.suspend_reason)


# ----------------------------------------------------------------- 识别器


def _is_ascii_word(text: str) -> bool:
    """是否只由 ASCII 字母 / 数字 / 下划线 / 连字符组成。"""
    return bool(text) and all(
        char.isascii() and (char.isalnum() or char in "_-") for char in text
    )


def _find_occurrences(text: str, needle: str) -> list[tuple[int, int]]:
    """在归一化文本里找出全部出现位置（左闭右开）。

    纯 ASCII 的候选（住院号、主键）做**边界约束**：前后不得紧邻字母或数字，
    否则「90000001」会命中「900000012」这种更长的串，把别人的住院号认成自己
    的。中文姓名不做边界约束 —— 姓名天然紧邻中文正文（「患者张某某」）。
    """
    if not needle:
        return []
    bounded = _is_ascii_word(needle)
    found: list[tuple[int, int]] = []
    start = text.find(needle)
    while start != -1:
        end = start + len(needle)
        before = text[start - 1] if start > 0 else ""
        after = text[end] if end < len(text) else ""
        if not bounded or (
            not _is_word_char(before) and not _is_word_char(after)
        ):
            found.append((start, end))
        start = text.find(needle, start + 1)
    return found


def _is_word_char(char: str) -> bool:
    """是否是需要做边界约束的 ASCII 词字符。"""
    return bool(char) and char.isascii() and (char.isalnum() or char == "_")


def _gap_info(
    text: str,
    offsets: Sequence[int],
    a_start: int,
    a_end: int,
    b_start: int,
    b_end: int,
) -> tuple[int, int]:
    """两段之间的间隔（字符数）与间隔里的换行数。

    :return: ``(间隔字符数, 换行数)``；两段相接或交叠时为 ``(0, 0)``。
    """
    if b_start >= a_end:
        gap = b_start - a_end
        left, right = a_end - 1, b_start
    elif a_start >= b_end:
        gap = a_start - b_end
        left, right = b_end - 1, a_start
    else:
        return 0, 0
    original_left = offsets[left] + 1
    original_right = offsets[right]
    if original_right <= original_left:
        return gap, 0
    return gap, text[original_left:original_right].count("\n")


class PatientIndexRecognizer(Recognizer):
    """名单形态识别器：以 HIS 患者主索引读回的权威名单为准。

    命中三种方式：

    - **主键命中**（``patient_id``）：材料里出现患者主索引主键 → 确认档。
    - **姓名 + 就诊号组合**（``name+visit_no``）：姓名与该患者的就诊号挨着
      → 确认档，绑定到该主键。
    - **单独姓名**（``name_only``）与**同名歧义**（``ambiguous``）：分数低于
      门槛 → 告警档，**不判为身份**，等人工抽检。

    :param binding: 权威名单。
    :param config: 识别器配置；缺省取策略表里的配置。
    :param score_thresholds: 逐类别阈值覆盖（策略表 ``thresholds.per_recognizer``
        优先于它）。
    """

    id = "patient_index"
    name = "患者主索引名单识别器"

    def __init__(
        self,
        binding: PatientIndexBinding,
        *,
        config: PatientIndexConfig | None = None,
        score_thresholds: Mapping[str, float] | None = None,
    ) -> None:
        self._binding = binding
        self._config = config if config is not None else load_patient_index_config()
        self.score_thresholds = dict(score_thresholds or {})
        # 本识别器自带门槛：单独姓名必须落在门槛之下，与全局阈值无关。
        self.score_thresholds.setdefault(NAME_ENTITY, self._config.confirm_threshold)
        self.score_thresholds.setdefault(ID_ENTITY, self._config.confirm_threshold)
        self.supported_entities = (NAME_ENTITY, ID_ENTITY)

    @property
    def binding(self) -> PatientIndexBinding:
        """当前装配的权威名单。"""
        return self._binding

    @property
    def config(self) -> PatientIndexConfig:
        """当前识别器配置。"""
        return self._config

    def is_available(self) -> bool:
        """名单不可用（不可达 / 为空）时返回 False —— 不产出任何命中。"""
        return self._config.enabled and self._binding.usable

    # ------------------------------------------------------------------ 分析

    def analyze(
        self, text: str, entities: Sequence[str] | None = None
    ) -> list[RecognizerResult]:
        """扫描文本，产出名单命中。"""
        if not self.is_available():
            return []
        wanted = set(entities) if entities else None
        normalized, offsets = normalize_with_offsets(text)
        results: list[RecognizerResult] = []
        if wanted is None or ID_ENTITY in wanted:
            results.extend(self._primary_key_hits(normalized, offsets))
        if wanted is None or NAME_ENTITY in wanted:
            results.extend(self._name_hits(text, normalized, offsets))
        return results

    # -------------------------------------------------------------- 内部实现

    def _primary_key_hits(
        self, normalized: str, offsets: Sequence[int]
    ) -> list[RecognizerResult]:
        """主键命中：材料里出现患者主索引主键。"""
        results: list[RecognizerResult] = []
        for entry in self._binding.entries:
            needle = normalize_text(entry.patient_id)
            for start, end in _find_occurrences(normalized, needle):
                results.append(
                    RecognizerResult(
                        start=offsets[start],
                        end=offsets[end - 1] + 1,
                        label=ID_ENTITY,
                        score=self._config.primary_key_score,
                        reason="命中患者主索引主键（权威名单）",
                        recognizer=self.id,
                        metadata={
                            "patient_id": entry.patient_id,
                            "match_mode": MATCH_PRIMARY_KEY,
                        },
                    )
                )
        return results

    def _name_hits(
        self, text: str, normalized: str, offsets: Sequence[int]
    ) -> list[RecognizerResult]:
        """姓名命中：按就诊号绑定到主键；绑不上的降为告警档。

        **绑定以就诊号为准**：就诊号是主索引读回的权威值，它说这一段属于谁，
        姓名只是佐证 —— 所以候选姓名必须是**这位患者自己的姓名**，别的患者的
        就诊号不会把这段姓名绑过来（否则就串号了）。

        分配规则：按就诊号在正文里出现的先后，依次取**最近的、还没被占用的**
        姓名；间隔相同则先看换行数（同一行更像同一条记录），再按下单顺序
        （姓名在前就诊号在后是报告的常见写法）。绑上之后还要复查一次歧义：
        另一个患者的就诊号离得一样近 → 判为歧义，不猜。
        """
        results: list[RecognizerResult] = []
        by_name = self._binding.entries_by_name()
        radius = self._config.proximity_radius

        # 1) 姓名出现位置（按归一化姓名归类）
        name_occurrences: list[tuple[int, int, str]] = []
        for key in by_name:
            for span in _find_occurrences(normalized, key):
                name_occurrences.append((span[0], span[1], key))
        name_occurrences.sort()

        # 2) 就诊号出现位置（连同所属患者）
        visit_occurrences: list[tuple[int, int, PatientIndexEntry, str]] = []
        for entry in self._binding.entries:
            for visit_no in entry.normalized_visit_nos:
                for span in _find_occurrences(normalized, visit_no):
                    visit_occurrences.append((span[0], span[1], entry, visit_no))
        visit_occurrences.sort()

        # 3) 分配：每个就诊号取最近的、还没被占用的、属于这位患者的姓名
        bound: dict[int, tuple[int, PatientIndexEntry, str]] = {}
        used_names: set[int] = set()
        for visit_index, (visit_start, visit_end, entry, visit_no) in enumerate(
            visit_occurrences
        ):
            owner_name = entry.normalized_name
            if not owner_name:
                continue
            best: tuple[tuple[int, int, int], int] | None = None
            for name_index, (name_start, name_end, key) in enumerate(name_occurrences):
                if name_index in used_names or key != owner_name:
                    continue
                gap, newlines = _gap_info(
                    text, offsets, name_start, name_end, visit_start, visit_end
                )
                if gap > radius:
                    continue
                rank = (gap, newlines, 0 if name_start <= visit_end else 1)
                if best is None or rank < best[0]:
                    best = (rank, name_index)
            if best is None:
                continue
            used_names.add(best[1])
            bound[best[1]] = (visit_index, entry, visit_no)

        # 4) 产出命中
        for name_index, (name_start, name_end, key) in enumerate(name_occurrences):
            owners = by_name[key]
            hit = bound.get(name_index)
            if hit is None:
                results.append(
                    self._unbound_name_hit(name_start, name_end, offsets, owners)
                )
                continue
            visit_index, entry, visit_no = hit
            rivals = self._rivals(
                text,
                offsets,
                name_start,
                name_end,
                key,
                visit_occurrences,
                visit_index,
                entry,
                radius,
            )
            if rivals:
                results.append(
                    self._ambiguous_hit(name_start, name_end, offsets, owners, rivals)
                )
                continue
            gap, _newlines = _gap_info(
                text,
                offsets,
                name_start,
                name_end,
                visit_occurrences[visit_index][0],
                visit_occurrences[visit_index][1],
            )
            results.append(
                RecognizerResult(
                    start=offsets[name_start],
                    end=offsets[name_end - 1] + 1,
                    label=NAME_ENTITY,
                    score=self._config.composite_score,
                    reason=f"命中患者主索引（姓名 + 就诊号组合，间隔 {gap} 字符）",
                    recognizer=self.id,
                    metadata={
                        "patient_id": entry.patient_id,
                        "visit_no": visit_no,
                        "match_mode": MATCH_NAME_AND_VISIT,
                    },
                )
            )
        return results

    def _rivals(
        self,
        text: str,
        offsets: Sequence[int],
        name_start: int,
        name_end: int,
        name_key: str,
        visit_occurrences: Sequence[tuple[int, int, PatientIndexEntry, str]],
        bound_visit_index: int,
        bound_entry: PatientIndexEntry,
        radius: int,
    ) -> list[PatientIndexEntry]:
        """复查歧义：另一个患者的就诊号离这处姓名一样近。

        返回「同样近、但属于别的患者」的就诊号所属条目；为空表示绑定唯一。

        :param name_key: 这处姓名的归一化写法（竞品就诊号必须是同一姓名的）。
        """
        bound_visit = visit_occurrences[bound_visit_index]
        bound_key = _gap_info(
            text, offsets, name_start, name_end, bound_visit[0], bound_visit[1]
        )
        rivals: list[PatientIndexEntry] = []
        for index, (visit_start, visit_end, entry, _visit_no) in enumerate(
            visit_occurrences
        ):
            if index == bound_visit_index:
                continue
            if entry.patient_id == bound_entry.patient_id:
                continue  # 同一个患者的多号，不是歧义
            if entry.normalized_name != name_key:
                continue  # 别人的姓名，与这处无关
            gap, newlines = _gap_info(
                text, offsets, name_start, name_end, visit_start, visit_end
            )
            if gap > radius:
                continue
            if (gap, newlines) == bound_key:
                rivals.append(entry)
        return rivals

    def _ambiguous_hit(
        self,
        name_start: int,
        name_end: int,
        offsets: Sequence[int],
        owners: tuple[PatientIndexEntry, ...],
        rivals: Sequence[PatientIndexEntry],
    ) -> RecognizerResult:
        """歧义命中：两位同名患者的就诊号一样近 → 不归到任何人头上。"""
        candidates = sorted({entry.patient_id for entry in owners} | {
            entry.patient_id for entry in rivals
        })
        return RecognizerResult(
            start=offsets[name_start],
            end=offsets[name_end - 1] + 1,
            label=NAME_ENTITY,
            score=self._config.name_only_score,
            reason=(
                f"命中 {len(candidates)} 位同名患者（候选主键 {len(candidates)} 个），"
                "归属待人工确认，按告警档处理"
            ),
            recognizer=self.id,
            metadata={
                "candidate_patient_ids": candidates,
                "match_mode": MATCH_AMBIGUOUS,
                "boost_allowed": False,
            },
        )

    def _unbound_name_hit(
        self,
        name_start: int,
        name_end: int,
        offsets: Sequence[int],
        owners: tuple[PatientIndexEntry, ...],
    ) -> RecognizerResult:
        """绑不上的姓名：降为告警档。

        只有一位同名患者 → 记下这位患者，但**不判为身份**（没有就诊号佐证，
        报告里的这个姓名未必是他）；多位同名患者 → 记为歧义，不归到任何人头上。
        """
        start = offsets[name_start]
        end = offsets[name_end - 1] + 1
        if len(owners) == 1:
            return RecognizerResult(
                start=start,
                end=end,
                label=NAME_ENTITY,
                score=self._config.name_only_score,
                reason="命中患者主索引姓名（无就诊号佐证），按告警档处理",
                recognizer=self.id,
                metadata={
                    "patient_id": owners[0].patient_id,
                    "match_mode": MATCH_NAME_ONLY,
                    # 已判定「证据不足」：邻近上下文词不得把它抬成身份类
                    "boost_allowed": False,
                },
            )
        return RecognizerResult(
            start=start,
            end=end,
            label=NAME_ENTITY,
            score=self._config.name_only_score,
            reason=(
                f"命中 {len(owners)} 位同名患者（候选主键 {len(owners)} 个），"
                "归属待人工确认，按告警档处理"
            ),
            recognizer=self.id,
            metadata={
                "candidate_patient_ids": [entry.patient_id for entry in owners],
                "match_mode": MATCH_AMBIGUOUS,
                "boost_allowed": False,
            },
        )
