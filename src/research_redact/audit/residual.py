"""残留自检：对脱敏输出二次扫描身份类残留。

这是本轮的差异化关键一环 —— 源产品**没有**这一步：它识别一遍、改写一遍就
把结果交出去，从不回头看「改写后的产物里是不是还留着身份」。医院场景恰恰
不能这样：一份残留着患者姓名的科研材料一旦交到科研数据平台，伦理办的批件
范围就被打破了，而这种事故在事后**极难发现** —— 平台侧只看到「一份脱敏材料」。

本模块做的事，一句话：**把脱敏产物再当一次原材料扫一遍，分级报出来**。

四条纪律：

1. **分级，不是一刀切** —— 身份类（姓名 / 身份证 / 手机号 / 出生日期 / 患者
   编号）与就诊编号类（住院号 / 门诊号 / 检查号）残留 → **阻断投递并告警**；
   通用数字类（剂量、金额、页码、床号、设备号）残留 → **只提示，不阻断**。
   把通用数字类也当成残留，告警里全是「30mL、128.50、第 2 页」，真正的漏脱
   反而被淹没。分级口径写在策略表 ``residual`` 段（**改 YAML 即改分级**）。
2. **误报要抑制，且抑制要留痕** —— 占位符、一致代号、白名单放行区间都是
   **脱敏产物本身**，不是漏脱；它们被抑制时**记下处数与原因**，不静默丢弃。
   抑制了多少处，和残留了多少处一样要能核对 —— 「扫了 40 处、抑制 12 处、
   残留 0 处」才是一句能让人放心的话。
3. **按批次聚合计数，不逐处推送** —— 一批材料里漏了 5 处，是**一条**告警
   （5 处），不是 5 条推送。逐处推送会把值班的人淹掉。
4. **残留非 0 则该批次不得进入 delivered** —— 不是「提醒一下」，是拦住。
   拦截由 :attr:`ResidualReport.deliverable` 表达，投递侧必须先问它。

**不变量**：残留记录、告警文案与批次摘要**都不含命中原文** —— 只记材料 ID、
类别、位置、分数与一句解释，与逐处命中清单同一红线。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping, Protocol, Sequence, runtime_checkable

from ..models import SpanTier, utcnow
from ..policy.conflicts import ConflictRules, load_conflict_rules
from ..policy.pseudonym import PseudonymConfig, load_pseudonym_config
from ..policy.residual_policy import (
    SEVERITY_BLOCKING,
    SEVERITY_HINT,
    UNCLASSIFIED_TIER,
    ResidualConfig,
    load_residual_config,
)
from ..policy.table import PolicyTable, load_policy_table
from ..recognizers.registry import RecognizerRegistry
from .alerts import AlertNotifier, AlertSink, BatchAlert, PendingNotifier

__all__ = [
    "RESIDUAL_COUNTED_TIERS",
    "ResidualBlockedError",
    "ResidualChecker",
    "ResidualFinding",
    "ResidualReport",
    "ResidualScan",
    "ResidualSummarySink",
    "SUPPRESS_REASONS",
    "allow_list_matcher",
    "is_allow_listed",
    "placeholder_values",
    "pseudonym_pattern",
    "residual_tier",
    "scan_residual",
    "scan_residual_detailed",
]


#: 计入残留的档位：身份类（姓名 / 身份证 / 手机号 / 出生日期 / 患者编号）与
#: 就诊编号类（住院号 / 门诊号 / 检查号）。通用数字类不在其中。
RESIDUAL_COUNTED_TIERS: tuple[str, ...] = ("identity", "encounter")

#: 抑制原因（脱敏产物本身，不是漏脱）。留痕用，方便核对「扫了多少、抑制多少」。
SUPPRESS_REASONS: tuple[str, ...] = ("placeholder", "pseudonym", "allow_list")

#: 档位未登记时的标记：按身份类处理（宁可多拦，不放过）。
_UNCLASSIFIED_TIER = UNCLASSIFIED_TIER


class ResidualBlockedError(RuntimeError):
    """批次残留自检未通过 —— 不得投递。

    投递侧（task 12 的出站写）必须先过这道闸：残留未清零就发出去，等于把
    未脱干净的材料交给科研数据平台。
    """


@runtime_checkable
class ResidualSummarySink(Protocol):
    """批次级残留自检摘要的落点。

    与 :class:`~research_redact.audit.alerts.AlertSink` 分开：告警是「出了
    事」，摘要是「这一批扫过什么、结论是什么」—— **通过的批次也要留摘要**，
    否则事后没人说得清「这批当时到底脱干净了没有」。台账
    (:class:`~research_redact.audit.ledger.BatchLedger`) 实现本协议。
    """

    def record_residual_summary(self, report: "ResidualReport") -> None:
        """落一条批次级残留自检摘要。"""


def residual_tier(label: str, rules: ConflictRules | None = None) -> str:
    """某实体类别在残留自检里的档位。

    - ``identity`` / ``encounter`` —— 身份类与就诊编号类，**计入残留**；
    - ``generic`` —— 通用数字类（剂量 / 金额 / 页码 / 床号），不计入；
    - ``unclassified`` —— 策略表里没分配档位的类别：按身份类处理。

    未登记的类别按身份类处理是刻意的：宁可多拦一批，也不让「新增识别器的
    类别没在策略表登记」变成一条永远查不出来的漏脱。（这条默认值可在策略表
    ``residual.unclassified_is_blocking`` 里改。）

    :param label: 实体类别。
    :param rules: 冲突裁决规则（提供类别 → 档位映射）；缺省从策略表装载。
    """
    active = rules or load_conflict_rules()
    tier = active.priority.get(label)
    if tier is None:
        return _UNCLASSIFIED_TIER
    return tier


def placeholder_values(table: PolicyTable | None = None) -> tuple[str, ...]:
    """策略表里 ``replace`` 动作使用的占位符。

    占位符（如 ``<患者姓名>``）是脱敏**产物**的一部分，不是残留 —— 二次扫描
    命中占位符时按「已脱」处理，否则每次自检都会把占位符当成漏脱。
    """
    active = table or load_policy_table()
    return tuple(
        spec.placeholder for spec in active.entity_actions.values() if spec.placeholder
    )


def pseudonym_pattern(config: PseudonymConfig | None = None) -> re.Pattern[str]:
    """一致代号的形状（``P-`` + 十六进制摘要）。

    一致代号同样是脱敏**产物**，不是残留：脱敏副本里的「姓名：P-1a2b…」
    会被字段标签识别器当成一次姓名命中 —— 若不把它认作「已脱」，残留自检
    会把每个代号都报成漏脱，批次永远交付不出去。

    认作「已脱」的形状只可能是本系统自己写出去的代号（固定前缀 + 固定位数
    十六进制），真实身份串不会长这样，因此不会放过真正的漏脱。
    """
    active = config or load_pseudonym_config()
    return re.compile(
        rf"{re.escape(active.prefix)}[0-9a-f]{{{active.digest_length}}}"
    )


def allow_list_matcher(
    table: PolicyTable | None = None,
) -> tuple[frozenset[str], tuple[re.Pattern[str], ...]]:
    """白名单匹配器（精确项 + 正则项）。

    残留自检**自己**认一遍白名单，而不是指望识别层已经放过 —— 二次扫描是
    「换个角度看同一份产物」，它得有自己的判断依据。白名单放行区间里的串
    （上游占位值「未登记」、全零占位号、已打码编号、检验项目编码…）是
    **脱敏产物本身**，不是漏脱。
    """
    active = table or load_policy_table()
    exact = frozenset(active.allow_list_exact)
    patterns = tuple(
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
        for pattern in active.allow_list_regex
        if pattern
    )
    return exact, patterns


def is_allow_listed(
    value: str,
    exact: frozenset[str] | Sequence[str] = (),
    patterns: Sequence[re.Pattern[str]] = (),
) -> bool:
    """某个取值是否落在白名单放行区间内。"""
    if not value:
        return False
    if value in exact:
        return True
    return any(pattern.search(value) for pattern in patterns)


@dataclass(frozen=True)
class ResidualFinding:
    """一处残留（**不记命中原文**）。

    :param material_id: 材料 ID。
    :param label: 实体类别。
    :param start: 起止位置（脱敏副本内的偏移量）。
    :param end: 结束位置。
    :param score: 命中分数。
    :param reason: 一句解释（命中方式 + 档位），不含命中原文。
    :param recognizer: 产出该命中的识别器 ID。
    :param tier: 残留档位（``identity`` / ``encounter`` / ``generic`` /
        ``unclassified``）。
    :param severity: 去留（``blocking`` 阻断级 / ``hint`` 提示级）。
    """

    material_id: str
    label: str
    start: int
    end: int
    score: float
    reason: str
    recognizer: str = ""
    tier: str = "identity"
    severity: str = SEVERITY_BLOCKING

    @property
    def is_blocking(self) -> bool:
        """是否阻断级（身份类 / 就诊编号类残留）。"""
        return self.severity == SEVERITY_BLOCKING

    def to_dict(self) -> dict[str, object]:
        """转成可落盘 / 可展示的一行（不含原文）。"""
        return {
            "material_id": self.material_id,
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "score": round(float(self.score), 4),
            "reason": self.reason,
            "recognizer": self.recognizer,
            "tier": self.tier,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ResidualScan:
    """一次扫描的完整结果：**阻断级** + **提示级** + **抑制留痕**。

    :param findings: 阻断级残留（身份类 / 就诊编号类）。
    :param hints: 提示级残留（通用数字类 —— 只提示，不阻断）。
    :param suppressed: 被抑制的处数（按原因分：占位符 / 一致代号 / 白名单）。
    """

    findings: tuple[ResidualFinding, ...] = ()
    hints: tuple[ResidualFinding, ...] = ()
    suppressed: Mapping[str, int] = field(default_factory=dict)

    @property
    def suppressed_count(self) -> int:
        """被抑制的总处数。"""
        return sum(self.suppressed.values())


@dataclass(frozen=True)
class ResidualReport:
    """一次批次级残留自检结论。

    :param batch_no: 批次号（申请单号）。
    :param findings: 逐处阻断级残留（身份类，不含原文）。
    :param hints: 逐处提示级残留（通用数字类，不含原文）。
    :param suppressed: 被抑制的处数（按原因分）。
    :param scanned_materials: 本次扫过的材料 ID。
    :param created_at: 自检时间。
    """

    batch_no: str
    findings: tuple[ResidualFinding, ...] = ()
    hints: tuple[ResidualFinding, ...] = ()
    suppressed: Mapping[str, int] = field(default_factory=dict)
    scanned_materials: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)

    @property
    def identity_count(self) -> int:
        """阻断级残留处数（身份类 / 就诊编号类）。"""
        return len(self.findings)

    @property
    def blocking_count(self) -> int:
        """阻断级残留处数（与 :attr:`identity_count` 同义，两个名字都说得通）。"""
        return len(self.findings)

    @property
    def hint_count(self) -> int:
        """提示级残留处数（通用数字类 —— 只提示，不阻断）。"""
        return len(self.hints)

    @property
    def suppressed_count(self) -> int:
        """被抑制的总处数（脱敏产物本身，不是漏脱）。"""
        return sum(self.suppressed.values())

    @property
    def deliverable(self) -> bool:
        """该批次是否可以投递：**阻断级**残留为 0 才放行。

        提示级残留不拦投递 —— 通用数字类长得像编号但不是身份，拦下来只会
        让真正需要人工核对的漏脱被淹没。
        """
        return self.identity_count == 0

    @property
    def affected_materials(self) -> tuple[str, ...]:
        """有阻断级残留的材料 ID（去重后按字典序）。"""
        return tuple(sorted({finding.material_id for finding in self.findings}))

    @property
    def hint_materials(self) -> tuple[str, ...]:
        """有提示级残留的材料 ID（去重后按字典序）。"""
        return tuple(sorted({finding.material_id for finding in self.hints}))

    @property
    def labels(self) -> tuple[str, ...]:
        """涉及的实体类别（去重后按字典序）。"""
        return tuple(sorted({finding.label for finding in self.findings}))

    @property
    def summary(self) -> str:
        """一句人话结论（进告警文案与运维摘要，不含原文）。"""
        parts: list[str] = []
        if self.deliverable:
            parts.append(
                f"身份类残留 0 处（已扫 {len(self.scanned_materials)} 份材料）"
            )
        else:
            parts.append(
                f"身份类残留 {self.identity_count} 处"
                f"（涉及材料 {'、'.join(self.affected_materials)}；"
                f"类别 {'、'.join(self.labels)}）"
            )
        if self.hint_count:
            parts.append(
                f"通用数字类提示 {self.hint_count} 处（不阻断投递，"
                f"涉及材料 {'、'.join(self.hint_materials)}）"
            )
        if self.suppressed_count:
            detail = "、".join(
                f"{reason} {count} 处" for reason, count in sorted(self.suppressed.items())
            )
            parts.append(f"已脱产物抑制 {detail}")
        return (
            f"批次 {self.batch_no} 残留自检"
            f"{'通过' if self.deliverable else '未通过'}：" + "；".join(parts)
        )


def scan_residual_detailed(
    text: str,
    material_id: str,
    registry: RecognizerRegistry,
    rules: ConflictRules | None = None,
    placeholders: Sequence[str] = (),
    pseudonym: re.Pattern[str] | None = None,
    allow_list: tuple[frozenset[str], tuple[re.Pattern[str], ...]] | None = None,
    config: ResidualConfig | None = None,
) -> ResidualScan:
    """对一份脱敏副本二次扫描，分级返回阻断级 / 提示级 / 抑制留痕。

    扫描顺序（每一步都留痕，不静默丢弃）：

    1. **白名单放行区间** —— 命中即抑制（记 ``allow_list``）：这些是上游
       占位值与本院检验项目编码，属脱敏产物本身；
    2. **告警档** —— 分数不够的命中不计入残留（识别层已经留痕）；
    3. **占位符 / 一致代号** —— 本系统自己写出去的产物，命中即抑制
       （记 ``placeholder`` / ``pseudonym``）；
    4. **按档位分级** —— 身份类 / 就诊编号类 → 阻断级；通用数字类 → 提示级。

    :param text: 脱敏后的正文。
    :param material_id: 材料 ID。
    :param registry: 识别器注册表（与首次识别同一套识别器）。
    :param rules: 冲突裁决规则（提供类别 → 档位映射）；缺省从策略表装载。
    :param placeholders: 已知的占位符取值；命中占位符按「已脱」处理。
    :param pseudonym: 一致代号的形状；命中按「已脱」处理。
    :param allow_list: 白名单匹配器（精确项 + 正则项）；缺省从策略表装载。
    :param config: 残留分级口径；缺省从策略表装载。
    """
    active_rules = rules or load_conflict_rules()
    active_config = config or load_residual_config()
    known_placeholders = set(placeholders)
    allow_exact, allow_patterns = allow_list or allow_list_matcher()

    findings: list[ResidualFinding] = []
    hints: list[ResidualFinding] = []
    suppressed: dict[str, int] = {}

    def _suppress(reason: str) -> None:
        suppressed[reason] = suppressed.get(reason, 0) + 1

    for span in registry.analyze(text):
        if span.is_allowed:
            # 识别层已按白名单放行 —— 这里再记一次，留痕「这一处被放行了」
            _suppress("allow_list")
            continue
        if span.tier is not SpanTier.CONFIRMED:
            # 告警档不计入残留：分数不够的命中识别层已留痕，这里不重复计
            continue
        matched = text[span.start : span.end]
        if matched in known_placeholders:
            _suppress("placeholder")
            continue
        if pseudonym is not None and pseudonym.fullmatch(matched):
            _suppress("pseudonym")
            continue
        if is_allow_listed(matched, allow_exact, allow_patterns):
            _suppress("allow_list")
            continue
        tier = residual_tier(span.label, active_rules)
        severity = active_config.severity_of(tier)
        if severity not in (SEVERITY_BLOCKING, SEVERITY_HINT):
            continue
        finding = ResidualFinding(
            material_id=material_id,
            label=span.label,
            start=span.start,
            end=span.end,
            score=span.score,
            reason=f"{span.reason}；残留自检二次命中（{tier}）",
            recognizer=span.recognizer,
            tier=tier,
            severity=severity,
        )
        if severity == SEVERITY_BLOCKING:
            findings.append(finding)
        else:
            hints.append(finding)

    return ResidualScan(
        findings=_dedupe_by_region(findings),
        hints=_dedupe_by_region(hints),
        suppressed=suppressed,
    )


def scan_residual(
    text: str,
    material_id: str,
    registry: RecognizerRegistry,
    rules: ConflictRules | None = None,
    placeholders: Sequence[str] = (),
    pseudonym: re.Pattern[str] | None = None,
) -> tuple[ResidualFinding, ...]:
    """对一份脱敏副本二次扫描，返回**阻断级**残留。

    提示级与抑制留痕在 :func:`scan_residual_detailed` 里；要分级与抑制留痕
    请用那个。

    :param text: 脱敏后的正文。
    :param material_id: 材料 ID。
    :param registry: 识别器注册表（与首次识别同一套识别器）。
    :param rules: 冲突裁决规则（提供类别 → 档位映射）；缺省从策略表装载。
    :param placeholders: 已知的占位符取值；命中占位符按「已脱」处理。
    :param pseudonym: 一致代号的形状；命中按「已脱」处理。
    """
    return scan_residual_detailed(
        text,
        material_id,
        registry,
        rules=rules,
        placeholders=placeholders,
        pseudonym=pseudonym,
    ).findings


def _dedupe_by_region(findings: Sequence[ResidualFinding]) -> tuple[ResidualFinding, ...]:
    """同一段残留只算一处。

    同一段正文被两个识别器同时命中（不同实体类别）是**一处**漏脱，不是两处 ——
    计数按段算，抽检的人才知道「漏了哪几段」。同段多条时保留分数高的一条
    （与识别层去重同一套取舍）。
    """
    best: dict[tuple[int, int], ResidualFinding] = {}
    for finding in findings:
        key = (finding.start, finding.end)
        current = best.get(key)
        if current is None or finding.score > current.score:
            best[key] = finding
    return tuple(best[key] for key in sorted(best))


class ResidualChecker:
    """残留自检器：扫脱敏副本 → 批次级结论 → 拦投放行 + 告警 + 摘要落台账。

    :param registry: 识别器注册表；缺省用项目默认装配。
    :param rules: 冲突裁决规则（提供类别 → 档位映射）；缺省从策略表装载。
    :param table: 策略表（提供占位符取值与白名单）；缺省从策略表装载。
    :param config: 残留分级口径；缺省从策略表装载。
    :param allow_list: 白名单匹配器（精确项 + 正则项）；缺省从策略表装载。
        二次扫描**自己**认一遍白名单 —— 它是「换个角度看同一份产物」，得
        有自己的判断依据，不能指望识别层已经放过。
    :param sink: 批次告警落点；缺省不落盘（由调用方决定持久化到哪里）。
    :param notifier: 告警推送出口；缺省为「通道未配置」的通知器。
    :param summary_sink: 批次摘要落点（台账）；缺省不落盘。
    """

    def __init__(
        self,
        registry: RecognizerRegistry | None = None,
        rules: ConflictRules | None = None,
        table: PolicyTable | None = None,
        sink: AlertSink | None = None,
        notifier: AlertNotifier | None = None,
        config: ResidualConfig | None = None,
        summary_sink: ResidualSummarySink | None = None,
        allow_list: tuple[frozenset[str], tuple[re.Pattern[str], ...]] | None = None,
    ) -> None:
        self._registry = registry
        self._rules = rules
        self._table = table
        self._sink = sink
        self._notifier = notifier if notifier is not None else PendingNotifier()
        self._config = config
        self._summary_sink = summary_sink
        self._allow_list = allow_list
        self._last_alert: BatchAlert | None = None

    @property
    def last_alert(self) -> BatchAlert | None:
        """最近一次自检落下的告警（自检通过时为 None）。"""
        return self._last_alert

    @property
    def registry(self) -> RecognizerRegistry:
        """本次自检使用的识别器注册表。"""
        if self._registry is None:
            from ..recognizers.assembly import build_default_registry

            self._registry = build_default_registry()
        return self._registry

    @property
    def rules(self) -> ConflictRules:
        """本次自检使用的档位规则。"""
        if self._rules is None:
            self._rules = load_conflict_rules()
        return self._rules

    @property
    def table(self) -> PolicyTable:
        """本次自检使用的策略表（占位符、白名单、分级口径都从它读）。"""
        if self._table is None:
            self._table = load_policy_table()
        return self._table

    @property
    def config(self) -> ResidualConfig:
        """本次自检使用的分级口径（策略表 ``residual`` 段）。"""
        if self._config is None:
            self._config = self.table.residual
        return self._config

    @property
    def placeholders(self) -> tuple[str, ...]:
        """本次自检认定的占位符取值。"""
        return placeholder_values(self.table)

    @property
    def pseudonym(self) -> re.Pattern[str]:
        """本次自检认定的一致代号形状（命中按「已脱」处理）。"""
        return pseudonym_pattern(self.table.pseudonymization)

    @property
    def allow_list(self) -> tuple[frozenset[str], tuple[re.Pattern[str], ...]]:
        """本次自检认定的白名单放行区间。"""
        if self._allow_list is None:
            self._allow_list = allow_list_matcher(self.table)
        return self._allow_list

    # ------------------------------------------------------------------ 自检

    def scan_detailed(self, text: str, material_id: str) -> ResidualScan:
        """对一份脱敏副本二次扫描，返回分级结果与抑制留痕。"""
        return scan_residual_detailed(
            text,
            material_id,
            self.registry,
            rules=self.rules,
            placeholders=self.placeholders,
            pseudonym=self.pseudonym,
            allow_list=self.allow_list,
            config=self.config,
        )

    def scan(self, text: str, material_id: str) -> tuple[ResidualFinding, ...]:
        """对一份脱敏副本二次扫描，返回**阻断级**残留。"""
        return self.scan_detailed(text, material_id).findings

    def check_batch(
        self, batch_no: str, materials: Mapping[str, str]
    ) -> ResidualReport:
        """对一批脱敏副本做残留自检，按批次聚合计数。

        阻断级残留非 0 时：**该批次不得进入 delivered**
        （:attr:`ResidualReport.deliverable` 为 False），并落一条批次告警 +
        推送一次（**不逐处推送**）。

        无论通过与否，批次摘要都落一次到摘要落点（台账）—— 通过的批次也要
        留痕，否则事后没人说得清「这批当时到底脱干净了没有」。

        :param batch_no: 批次号（申请单号）。
        :param materials: 材料 ID → 脱敏后的正文。
        """
        findings: list[ResidualFinding] = []
        hints: list[ResidualFinding] = []
        suppressed: dict[str, int] = {}
        for material_id, text in materials.items():
            scan = self.scan_detailed(text, material_id)
            findings.extend(scan.findings)
            hints.extend(scan.hints)
            for reason, count in scan.suppressed.items():
                suppressed[reason] = suppressed.get(reason, 0) + count
        report = ResidualReport(
            batch_no=batch_no,
            findings=tuple(findings),
            hints=tuple(hints),
            suppressed=suppressed,
            scanned_materials=tuple(materials),
        )
        self._record_summary(report)
        if not report.deliverable:
            self._last_alert = self.raise_alert(report)
        else:
            self._last_alert = None
        return report

    # ------------------------------------------------------------------ 告警

    def raise_alert(self, report: ResidualReport) -> BatchAlert:
        """为未通过的批次落一条告警，并推送一次。

        推送**一次**（按批次聚合），不是每处残留推一条 —— 值班的人只需要
        知道「这批被拦下了、拦了几处」，逐处明细留在命中清单与自检报告里。

        提示级残留（通用数字类）**不推** —— 它不阻断投递，推出去只会淹没
        真正需要人处理的那一条。
        """
        message = (
            f"{report.summary} —— 该批次不得投递，请人工核对脱敏副本后重新处理"
        )
        pushed = bool(self._notifier.notify(message, batch_no=report.batch_no))
        alert = BatchAlert(
            batch_no=report.batch_no,
            code="residual_identity",
            level="warning",
            count=report.identity_count,
            message=message,
            material_ids=report.affected_materials,
            notified=pushed,
            notify_channel=getattr(self._notifier, "channel", ""),
            created_at=report.created_at,
        )
        if self._sink is not None:
            self._sink.record(alert)
        return alert

    # ------------------------------------------------------------------ 摘要

    def _record_summary(self, report: ResidualReport) -> None:
        """批次摘要落台账（通过与否都落）。"""
        if self._summary_sink is None:
            return
        self._summary_sink.record_residual_summary(report)
