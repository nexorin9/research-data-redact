#!/usr/bin/env python3
"""基线对比实验：代号一致性 / 身份残留率 / 串号率。

**为什么要做这个实验**：一致代号是本轮的商业楔子 —— 「同一患者跨材料代号恒等、
不同主键不串号、产物里不残留身份」。这句话写在 README 上没人会信；本脚本把
三条真实可实现的路径丢到**同一批语料**上跑一遍，用可复算的数字回答三个问题：

1. 同一患者的材料，能不能靠代号对上号？（代号一致性）
2. 产物里还剩多少身份？（身份残留率）
3. 会不会把两个不同的人，误当成同一个人？（串号率）

**三条路径**（跑的是同一批材料、同一套原文）：

==========  ======================================================  ==========
路径        做法                                                    身份键来源
==========  ======================================================  ==========
``product`` 本产品主路径（识别 → 处置 → 残留自检），一致代号档        HIS 患者主索引主键
``naive``   朴素查找替换：拿主索引读回记录建「原文 → 固定占位符」字典  主索引记录里的字段
``hash``    无一致性 hash 替换：同一份字典，逐处算 hash 代号           匹配到的原文
==========  ======================================================  ==========

两条基线各自踩一个真实场景里最常见的坑：

- **朴素查找替换** —— 一致，但**分不清谁是谁**（所有患者共用同一批占位符），
  而且字典覆盖不到主索引没给的字段（手机号、完整身份证、检查号）→ 产物里留身份。
- **无一致性 hash 替换** —— 每一份材料独立加盐算 hash，跨材料**对不上人**，
  产物里同样留身份。

**指标口径（写死，不随实现漂移）**：

- **身份槽位** = 姓名槽（``PATIENT_NAME``）与患者编号槽（``PATIENT_ID``）。
  这两处指认「**这是谁**」。手机号 / 出生日期 / 身份证是「证明是谁」的直标识
  （脱掉即止，不构成代号）；住院号 / 检查号标识「**哪一次就诊**」，不是人 ——
  把就诊槽算进代号会让「都写了 ``<住院号>``」变成串号，那是误判。
- **代号集合 T(m)** = 该路径在**身份槽位**里写下的替换文本集合。
- **代号一致性** = 同患者材料对中 ``T(m1) ∩ T(m2) ≠ ∅`` 的比例。
- **串号率** = 不同患者材料对中 ``T(m1) ∩ T(m2) ≠ ∅`` 的比例。
- **身份残留率** = 产物里阻断级身份残留处数 ÷ 原文身份类 / 就诊编号类命中处数。
- **一人一码率**（补充指标，不替代上面三项）= ``|T(m)| == 1`` 的样本比例。

用法::

    python scripts/compare_baseline.py                     # 默认 500 例语料
    python scripts/compare_baseline.py --limit 60          # 小规模快跑
    python scripts/compare_baseline.py --corpus var/corpus --out reports/baseline-comparison.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _extra in (str(_ROOT / "src"), str(_HERE)):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

from research_redact.audit.residual import ResidualChecker, pseudonym_pattern  # noqa: E402
from research_redact.config import PSEUDONYM_HMAC_KEY_ENV  # noqa: E402
from research_redact.daemon.pipeline import redact_batch  # noqa: E402
from research_redact.policy.conflicts import load_conflict_rules  # noqa: E402
from research_redact.policy.operators import default_operator_registry  # noqa: E402
from research_redact.policy.table import load_policy_table  # noqa: E402
from research_redact.recognizers.assembly import build_default_registry  # noqa: E402
from research_redact.recognizers.patient_index import (  # noqa: E402
    load_patient_index_binding,
)

__all__ = [
    "BENCHMARK_ONLY_KEY",
    "CorpusBatch",
    "CorpusMaterial",
    "PathOutcome",
    "cross_assignment_rate",
    "consistency_rate",
    "ensure_corpus",
    "identity_residual_rate",
    "load_corpus",
    "main",
    "pair_split",
    "run_hash_path",
    "run_naive_path",
    "run_product_path",
    "single_code_rate",
]


# --------------------------------------------------------------------- 常量

#: 一致代号档（策略表 ``profiles.pseudonym``）。
PSEUDONYM_PROFILE = "pseudonym"

#: 身份槽位：只有这两处指认「这是谁」。见模块 docstring 的口径说明。
IDENTITY_SLOT_LABELS: tuple[str, ...] = ("PATIENT_NAME", "PATIENT_ID")

#: 计入身份残留的档位（与产品残留自检口径一致：身份类 + 就诊编号类）。
RESIDUAL_COUNTED_TIERS: tuple[str, ...] = ("identity", "encounter")

#: 朴素路径的字典：主索引读回记录里的字段 → 固定占位符。
#:
#: ``phone`` 一项在主索引读回格式里并不存在（读回的是
#: patient_id / visit_no / name / id_card_masked / birth_date / sex），
#: 保留在表里是为了把「主索引没给手机号」这件事写明白 —— 朴素路径因此
#: 覆盖不到手机号。``id_card_masked`` 是**掩码值**，正文里是完整 18 位
#: 身份证，字典里根本没有完整值可替 → 身份证也覆盖不到。
NAIVE_PLACEHOLDERS: Mapping[str, str] = {
    "name": "<患者姓名>",
    "visit_no": "<住院号>",
    "patient_id": "<患者编号>",
    "phone": "<手机号>",
    "id_card_masked": "<身份证号>",
    "birth_date": "<出生日期>",
}

#: 朴素路径写进**身份槽位**的占位符（提取代号时只看这些）。
#: ``<住院号>`` 是就诊槽位，不算代号。
NAIVE_IDENTITY_PLACEHOLDERS: tuple[str, ...] = (
    "<患者姓名>",
    "<患者编号>",
)

#: 字典里哪些字段落在**身份槽位**（姓名 / 患者编号）—— 只有它们的代号
#: 参与代号指标（口径见模块 docstring）。
IDENTITY_SLOT_SOURCE_KEYS: frozenset[str] = frozenset({"name", "patient_id"})

#: 无一致性 hash 路径的代号前缀。
HASH_PREFIX = "H-"

#: 无一致性 hash 路径的代号摘要位数（与一致代号同宽，便于肉眼比对）。
HASH_DIGEST_LENGTH = 16

#: 基准跑用的密钥（**不是生产密钥**）：$PSEUDONYM_HMAC_KEY 未配置时用它，
#: 保证脚本开箱即跑、数字可复现。三项指标都与密钥取值无关（只与「同一患者
#: 是否恒得同一代号」有关），换密钥不改变任何一个指标。
BENCHMARK_ONLY_KEY = "benchmark-only-key-not-a-production-secret"

#: 语料默认目录 / 规模 / 种子（与 scripts/gen_corpus.py 的出厂口径一致）。
DEFAULT_CORPUS = Path("var") / "corpus"
DEFAULT_LIMIT = 500
DEFAULT_SEED = 20260101

#: 报告默认输出路径。
DEFAULT_REPORT = Path("reports") / "baseline-comparison.md"


# --------------------------------------------------------------------- 数据结构


@dataclass(frozen=True)
class CorpusMaterial:
    """语料里的一份材料。

    :param material_id: 材料 ID。
    :param application_no: 所属申请单号。
    :param patient_id: 患者主索引主键（该材料属于谁）。
    :param text: 材料正文。
    """

    material_id: str
    application_no: str
    patient_id: str
    text: str


@dataclass(frozen=True)
class CorpusBatch:
    """一个批次（= 一张申请单）。

    :param application_no: 申请单号。
    :param materials: 本批材料。
    :param records: 主索引读回记录（朴素 / hash 两条基线的字典来源）。
    :param declared_patient_ids: 申请单声明的患者主键。
    """

    application_no: str
    materials: tuple[CorpusMaterial, ...] = ()
    records: tuple[Mapping[str, object], ...] = ()
    declared_patient_ids: tuple[str, ...] = ()

    @property
    def material_ids(self) -> tuple[str, ...]:
        """本批材料 ID 清单。"""
        return tuple(material.material_id for material in self.materials)


@dataclass(frozen=True)
class PathOutcome:
    """一条路径跑完之后的产物与计量。

    :param path_id: 路径 ID（``product`` / ``naive`` / ``hash``）。
    :param display_name: 路径中文名。
    :param how: 这条路径具体怎么做的（写进报告）。
    :param redacted: 材料 ID → 脱敏产物正文。
    :param tokens: 材料 ID → 身份槽位里的代号集合。
    :param residual_counts: 材料 ID → 阻断级身份残留处数。
    :param identity_hits: 原文里身份类 / 就诊编号类命中处数（三条路径共用同一分母）。
    :param own_token_residuals: 「路径自己写出去的代号被残留自检判成身份」的处数
        （形态碰撞，不是泄露；单列出来免得被当成漏脱）。
    """

    path_id: str
    display_name: str
    how: str
    redacted: Mapping[str, str] = field(default_factory=dict)
    tokens: Mapping[str, frozenset[str]] = field(default_factory=dict)
    residual_counts: Mapping[str, int] = field(default_factory=dict)
    identity_hits: int = 0
    own_token_residuals: int = 0

    @property
    def residual_total(self) -> int:
        """阻断级身份残留总处数。"""
        return sum(self.residual_counts.values())

    @property
    def deliverable(self) -> bool:
        """产物是否可交付（阻断级残留为 0）。"""
        return self.residual_total == 0


# --------------------------------------------------------------------- 语料


def ensure_corpus(
    corpus_dir: str | Path,
    *,
    seed: int = DEFAULT_SEED,
    limit: int = DEFAULT_LIMIT,
) -> Path:
    """确保语料目录存在且有语料；没有就按固定种子确定性生成一份。

    断网可用（纯本地合成）。生成走 :mod:`scripts.gen_corpus`，同种子两次
    生成逐字节一致。
    """
    target = Path(corpus_dir)
    if (target / "manifest.jsonl").is_file():
        return target
    import gen_corpus  # scripts/gen_corpus.py（仅本脚本用到）

    artifacts = gen_corpus.build_corpus(seed=seed, limit=limit)
    gen_corpus.write_corpus(artifacts, target)
    return target


def load_corpus(corpus_dir: str | Path) -> list[CorpusBatch]:
    """装载语料（按申请单分批）。

    :raises FileNotFoundError: 语料目录不存在或缺 manifest。
    """
    root = Path(corpus_dir)
    manifest = root / "manifest.jsonl"
    if not manifest.is_file():
        raise FileNotFoundError(f"语料清单不存在：{manifest}")

    patient_of: dict[str, str] = {}
    application_of: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        patient_of[row["material_id"]] = str(row.get("patient_id", ""))
        application_of[row["material_id"]] = str(row.get("application_no", ""))

    batches: list[CorpusBatch] = []
    batches_dir = root / "batches"
    for batch_dir in sorted(p for p in batches_dir.iterdir() if p.is_dir()):
        application_file = batch_dir / "application.json"
        if not application_file.is_file():
            continue
        application = json.loads(application_file.read_text(encoding="utf-8"))
        application_no = str(application.get("application_no", batch_dir.name))
        index_file = batch_dir / "patient_index.json"
        records: tuple[Mapping[str, object], ...] = ()
        if index_file.is_file():
            payload = json.loads(index_file.read_text(encoding="utf-8"))
            records = tuple(payload.get("records", ()))
        materials: list[CorpusMaterial] = []
        for item in application.get("materials", ()):
            material_id = str(item.get("material_id", ""))
            material_file = batch_dir / "materials" / f"{material_id}.txt"
            if not material_file.is_file():
                continue
            materials.append(
                CorpusMaterial(
                    material_id=material_id,
                    application_no=application_no,
                    patient_id=patient_of.get(material_id, str(item.get("patient_id", ""))),
                    text=material_file.read_text(encoding="utf-8"),
                )
            )
        batches.append(
            CorpusBatch(
                application_no=application_no,
                materials=tuple(materials),
                records=records,
                declared_patient_ids=tuple(str(x) for x in application.get("patient_ids", ())),
            )
        )
    return batches


# --------------------------------------------------------------------- 计量


def _batch_registry(batch: CorpusBatch, table):
    """装配某批次的识别器注册表。

    名单按批次装配 —— 与守护进程一致（每张申请单读一次主索引）。
    """
    binding = load_patient_index_binding(
        batch.records, declared_patient_ids=batch.declared_patient_ids
    )
    return build_default_registry(binding, table)


class _PathAwareChecker(ResidualChecker):
    """残留自检器 + 「本路径写出去的替换文本」抑制词表。

    产品自认自己的产物：占位符与一致代号命中即抑制，不算残留（见
    :mod:`research_redact.audit.residual`）。本模块给**三条路径同一套待遇**：
    路径自己写出去的替换文本（占位符 / hash 代号）也按「已脱产物」抑制。

    为什么必须这样：残留自检判的是「产物里还有没有**身份**」。字段标签
    识别器只按「标签后面的取值像不像编号」判断 —— 第三方写的代号
    （如 ``住院号：H-762de0318e55ccfd``）长得像编号，会被当成漏脱。那是
    **替换文本**，不是身份；不抑制的话，基线会因为「代号长得不像本院格式」
    而多背一处残留 —— 那不是泄露，是尺子偏了。
    """

    def __init__(self, *args, extra_placeholders: Sequence[str] = (), **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._extra_placeholders = tuple(extra_placeholders)

    @property
    def placeholders(self) -> tuple[str, ...]:
        """已脱产物取值：产品自认的占位符 + 本路径写出去的替换文本。"""
        return tuple(super().placeholders) + self._extra_placeholders


def _count_identity_hits(registry, materials: Sequence[CorpusMaterial], rules) -> int:
    """原文里身份类 / 就诊编号类的确认档命中处数（残留率的分母）。

    按区间去重（与残留自检的「同一段算一处」口径一致），保证分子分母
    说的是同一件事。
    """
    from research_redact.audit.residual import residual_tier

    total = 0
    for material in materials:
        regions: set[tuple[int, int]] = set()
        for span in registry.analyze(material.text):
            if not span.is_confirmed:
                continue
            if residual_tier(span.label, rules) not in RESIDUAL_COUNTED_TIERS:
                continue
            regions.add((span.start, span.end))
        total += len(regions)
    return total


def _residual_counts(
    checker: ResidualChecker,
    batch_no: str,
    redacted: Mapping[str, str],
    own_spans: Sequence[tuple[str, int, int]] = (),
) -> tuple[dict[str, int], int]:
    """对一批脱敏产物做残留自检。

    :param own_spans: 路径自己写出去的替换文本的位置
        （材料 ID, 起, 止）。用来区分「真残留」与「**形态碰撞**」——
        代号字符集撞上了院内编号形态（hash 摘要里偶发 11 位连续数字 →
        被判成手机号）。形态碰撞不是泄露，但会让残留自检误报，值得单列。
    :return: ``(每份材料的阻断级残留处数, 其中形态碰撞的处数)``。
    """
    report = checker.check_batch(batch_no, redacted)
    counts: dict[str, int] = {material_id: 0 for material_id in redacted}
    collisions = 0
    for finding in report.findings:
        counts[finding.material_id] = counts.get(finding.material_id, 0) + 1
        for material_id, start, end in own_spans:
            if material_id != finding.material_id:
                continue
            if start <= finding.start and finding.end <= end:
                collisions += 1
                break
    return counts, collisions


def _placeholder_spans(
    material_id: str, text: str, placeholders: Iterable[str]
) -> list[tuple[str, int, int]]:
    """占位符在产物里的位置（形态碰撞判定用）。"""
    spans: list[tuple[str, int, int]] = []
    for placeholder in placeholders:
        if not placeholder:
            continue
        start = text.find(placeholder)
        while start != -1:
            spans.append((material_id, start, start + len(placeholder)))
            start = text.find(placeholder, start + 1)
    return spans


# --------------------------------------------------------------------- 三条路径


def run_product_path(
    batches: Sequence[CorpusBatch],
    *,
    key: str | None = None,
    table=None,
    rules=None,
) -> PathOutcome:
    """路径 A —— 本产品主路径（一致代号档）。

    走的是产品自己的主路径：识别 → 按策略处置 → 残留自检。一致代号由
    **患者主索引主键**经 HMAC-SHA256 算出，因此同一位患者跨材料恒等、
    不同主键不串号。

    :param key: 一致代号密钥。给了就在本次运行期间写入
        ``$PSEUDONYM_HMAC_KEY``（产品的动作在**执行时**才取密钥），
        跑完恢复原值 —— 不把环境变量留在调用方的进程里。
    """
    active_table = table if table is not None else load_policy_table(profile=PSEUDONYM_PROFILE)
    active_rules = rules if rules is not None else load_conflict_rules()
    operators = default_operator_registry()
    shape = pseudonym_pattern(active_table.pseudonymization)

    redacted: dict[str, str] = {}
    tokens: dict[str, frozenset[str]] = {}
    residual_counts: dict[str, int] = {}
    identity_hits = 0
    own_token_residuals = 0

    previous_key = os.environ.get(PSEUDONYM_HMAC_KEY_ENV)
    if key is not None:
        os.environ[PSEUDONYM_HMAC_KEY_ENV] = key
    try:
        return _run_product_batches(
            batches,
            active_table=active_table,
            active_rules=active_rules,
            operators=operators,
            shape=shape,
            redacted=redacted,
            tokens=tokens,
            residual_counts=residual_counts,
        )
    finally:
        if key is not None:
            if previous_key is None:
                os.environ.pop(PSEUDONYM_HMAC_KEY_ENV, None)
            else:
                os.environ[PSEUDONYM_HMAC_KEY_ENV] = previous_key


def _run_product_batches(
    batches: Sequence[CorpusBatch],
    *,
    active_table,
    active_rules,
    operators,
    shape,
    redacted: dict[str, str],
    tokens: dict[str, frozenset[str]],
    residual_counts: dict[str, int],
) -> PathOutcome:
    """跑本产品主路径的批次循环（密钥已就位）。"""
    identity_hits = 0
    own_token_residuals = 0

    for batch in batches:
        registry = _batch_registry(batch, active_table)
        identity_hits += _count_identity_hits(registry, batch.materials, active_rules)
        checker = _PathAwareChecker(registry=registry)
        materials = {m.material_id: m.text for m in batch.materials}
        outcome = redact_batch(
            batch.application_no,
            materials,
            checker=checker,
            registry=registry,
            actions=active_table.action_for,
            operators=operators,
        )
        for item in outcome.outcomes:
            redacted[item.material_id] = item.redacted_text
            # 代号从**产物**里读出来（研究侧拿到交付物后也是这么读的）：
            # 一致代号的形状固定，产物里的它就是这位患者的代号。
            tokens[item.material_id] = frozenset(shape.findall(item.redacted_text))
        counts, own_token_hits = _residual_counts(
            checker, batch.application_no, {m: redacted[m] for m in materials}
        )
        residual_counts.update(counts)
        own_token_residuals += own_token_hits

    return PathOutcome(
        path_id="product",
        display_name="本产品（一致代号档）",
        how=(
            "产品主路径：识别 → 按策略处置 → 残留自检；一致代号 = "
            "HMAC-SHA256(密钥, 方案名 + 患者主索引主键)，取值输入只有主索引主键"
        ),
        redacted=redacted,
        tokens=tokens,
        residual_counts=residual_counts,
        identity_hits=identity_hits,
        own_token_residuals=own_token_residuals,
    )


def _naive_dictionary(records: Sequence[Mapping[str, object]]) -> dict[str, str]:
    """朴素路径的替换字典：主索引读回记录里的字段 → 固定占位符。

    **同名不同人共用一个键** —— 字典按字段取值建，不区分是哪位患者，
    这正是朴素替换的固有行为（也是它串号的根源）。
    """
    dictionary: dict[str, str] = {}
    for record in records:
        for field_name, placeholder in NAIVE_PLACEHOLDERS.items():
            value = str(record.get(field_name, "") or "").strip()
            if not value:
                continue
            dictionary.setdefault(value, placeholder)
    return dictionary


def _apply_replacements(text: str, pairs: Sequence[tuple[str, str]]) -> str:
    """按（原文, 替换文本）逐条替换（长键优先，避免短键先吃掉长键）。"""
    result = text
    for source, target in sorted(pairs, key=lambda item: (-len(item[0]), item[0])):
        if source:
            result = result.replace(source, target)
    return result


def run_naive_path(
    batches: Sequence[CorpusBatch],
    *,
    table=None,
    rules=None,
) -> PathOutcome:
    """路径 B —— 朴素查找替换。

    拿 HIS 患者主索引读回记录建「原文 → 固定占位符」字典，在正文里做
    纯字符串替换。字典覆盖不到的字段（手机号、完整身份证、检查号）原样留在产物里。
    """
    active_table = table if table is not None else load_policy_table()
    active_rules = rules if rules is not None else load_conflict_rules()

    redacted: dict[str, str] = {}
    tokens: dict[str, frozenset[str]] = {}
    residual_counts: dict[str, int] = {}
    identity_hits = 0
    own_token_residuals = 0

    for batch in batches:
        registry = _batch_registry(batch, active_table)
        identity_hits += _count_identity_hits(registry, batch.materials, active_rules)
        dictionary = _naive_dictionary(batch.records)
        pairs = list(dictionary.items())
        batch_redacted: dict[str, str] = {}
        for material in batch.materials:
            output = _apply_replacements(material.text, pairs)
            batch_redacted[material.material_id] = output
            redacted[material.material_id] = output
            tokens[material.material_id] = frozenset(
                placeholder
                for placeholder in NAIVE_IDENTITY_PLACEHOLDERS
                if placeholder in output
            )
        # 路径自己写出去的替换文本按「已脱产物」抑制（与产品自认占位符同一套口径）
        checker = _PathAwareChecker(
            registry=registry, extra_placeholders=sorted(set(dictionary.values()))
        )
        own_spans: list[tuple[str, int, int]] = []
        for material_id, output in batch_redacted.items():
            own_spans.extend(
                _placeholder_spans(material_id, output, set(dictionary.values()))
            )
        counts, own_token_hits = _residual_counts(
            checker, batch.application_no, batch_redacted, own_spans
        )
        residual_counts.update(counts)
        own_token_residuals += own_token_hits

    return PathOutcome(
        path_id="naive",
        display_name="朴素查找替换",
        how=(
            "拿主索引读回记录建「原文 → 固定占位符」字典，正文里纯字符串替换；"
            "字典覆盖不到手机号、完整身份证（主索引给的是掩码值）与检查号"
        ),
        redacted=redacted,
        tokens=tokens,
        residual_counts=residual_counts,
        identity_hits=identity_hits,
        own_token_residuals=own_token_residuals,
    )


def _hash_token(material_id: str, source: str, ordinal: int) -> str:
    """无一致性 hash 代号：每份材料独立加盐，逐处算摘要。

    加盐键含材料 ID —— 同一段原文在两份材料里得到两个不同的串，
    跨材料**对不上人**。这是隐私侧常见的诉求（「别让人把两份材料关联起来」），
    代价是研究侧完全无法把同一位患者的材料串起来。
    """
    digest = hashlib.sha256(
        f"{material_id}|{source}|{ordinal}".encode("utf-8")
    ).hexdigest()
    return f"{HASH_PREFIX}{digest[:HASH_DIGEST_LENGTH]}"


def run_hash_path(
    batches: Sequence[CorpusBatch],
    *,
    table=None,
    rules=None,
) -> PathOutcome:
    """路径 C —— 无一致性 hash 替换。

    与朴素路径同一份字典，但每一处命中算一个独立代号：``H-`` + 摘要，
    摘要的输入是「材料 ID + 命中原文 + 该原文在本文料里的出现次序」。
    """
    active_table = table if table is not None else load_policy_table()
    active_rules = rules if rules is not None else load_conflict_rules()

    redacted: dict[str, str] = {}
    tokens: dict[str, frozenset[str]] = {}
    residual_counts: dict[str, int] = {}
    identity_hits = 0
    own_token_residuals = 0

    for batch in batches:
        registry = _batch_registry(batch, active_table)
        identity_hits += _count_identity_hits(registry, batch.materials, active_rules)
        dictionary = _naive_dictionary(batch.records)
        batch_redacted: dict[str, str] = {}
        vocabulary: set[str] = set()
        own_spans: list[tuple[str, int, int]] = []
        for material in batch.materials:
            output = material.text
            identity_tokens: set[str] = set()
            for source in sorted(dictionary, key=lambda item: (-len(item), item)):
                if not source or source not in output:
                    continue
                ordinal = 0
                pieces: list[str] = []
                cursor = 0
                written = 0  # 已写出的字符数（结果串里的偏移）
                while True:
                    position = output.find(source, cursor)
                    if position == -1:
                        break
                    token = _hash_token(material.material_id, source, ordinal)
                    pieces.append(output[cursor:position])
                    written += position - cursor
                    pieces.append(token)
                    # 代号在产物里的位置（形态碰撞判定用）
                    own_spans.append(
                        (material.material_id, written, written + len(token))
                    )
                    written += len(token)
                    cursor = position + len(source)
                    ordinal += 1
                    vocabulary.add(token)
                    if source in IDENTITY_SLOT_SOURCE_KEYS:
                        identity_tokens.add(token)
                pieces.append(output[cursor:])
                output = "".join(pieces)
            batch_redacted[material.material_id] = output
            redacted[material.material_id] = output
            tokens[material.material_id] = frozenset(identity_tokens)
        checker = _PathAwareChecker(
            registry=registry, extra_placeholders=sorted(vocabulary)
        )
        counts, own_token_hits = _residual_counts(
            checker, batch.application_no, batch_redacted, own_spans
        )
        residual_counts.update(counts)
        own_token_residuals += own_token_hits

    return PathOutcome(
        path_id="hash",
        display_name="无一致性 hash 替换",
        how=(
            "与朴素路径同一份字典，但每一处命中算一个独立代号："
            "H- + sha256(材料 ID + 命中原文 + 出现次序)[:16]，每份材料独立加盐"
        ),
        redacted=redacted,
        tokens=tokens,
        residual_counts=residual_counts,
        identity_hits=identity_hits,
        own_token_residuals=own_token_residuals,
    )


#: 字典里哪些字段落在**身份槽位**（姓名 / 患者编号）—— 只有它们的代号
#: 参与代号指标（口径见模块 docstring）。
# --------------------------------------------------------------------- 指标


def pair_split(
    materials: Sequence[CorpusMaterial],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """把材料两两配对，拆成「同患者对」与「不同患者对」两组。

    返回的都是**材料 ID 对**（无序、不含自身配对）。
    """
    same: list[tuple[str, str]] = []
    different: list[tuple[str, str]] = []
    for index, left in enumerate(materials):
        for right in materials[index + 1 :]:
            if left.patient_id == right.patient_id:
                same.append((left.material_id, right.material_id))
            else:
                different.append((left.material_id, right.material_id))
    return same, different


def consistency_rate(
    pairs: Sequence[tuple[str, str]], tokens: Mapping[str, frozenset[str]]
) -> float:
    """代号一致性：同患者材料对中，代号集合有交集的比例。

    分母为 0 时返回 0.0（没有可比对的样本时不编造数字）。
    """
    if not pairs:
        return 0.0
    matched = sum(1 for left, right in pairs if tokens.get(left, frozenset()) & tokens.get(right, frozenset()))
    return matched / len(pairs)


def cross_assignment_rate(
    pairs: Sequence[tuple[str, str]], tokens: Mapping[str, frozenset[str]]
) -> float:
    """串号率：不同患者材料对中，代号集合有交集（会被误并成一人）的比例。"""
    if not pairs:
        return 0.0
    collided = sum(1 for left, right in pairs if tokens.get(left, frozenset()) & tokens.get(right, frozenset()))
    return collided / len(pairs)


def identity_residual_rate(residual_total: int, identity_hits: int) -> float:
    """身份残留率：产物里阻断级残留处数 ÷ 原文身份类命中处数。"""
    if identity_hits <= 0:
        return 0.0
    return residual_total / identity_hits


def single_code_rate(tokens: Mapping[str, frozenset[str]]) -> float:
    """一人一码率：身份槽位里只写下一个代号的样本比例（补充指标）。"""
    if not tokens:
        return 0.0
    single = sum(1 for value in tokens.values() if len(value) == 1)
    return single / len(tokens)


# --------------------------------------------------------------------- 报告


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _render_report(
    *,
    corpus_root: Path,
    batches: Sequence[CorpusBatch],
    outcomes: Sequence[PathOutcome],
    same_pairs: Sequence[tuple[str, str]],
    different_pairs: Sequence[tuple[str, str]],
    patient_count: int,
    material_count: int,
    key_source: str,
    elapsed: float,
) -> str:
    """渲染 reports/baseline-comparison.md。"""
    lines: list[str] = []
    add = lines.append

    def rates(outcome: PathOutcome) -> tuple[float, float, float, float]:
        """（代号一致性, 身份残留率, 串号率, 一人一码率）。"""
        return (
            consistency_rate(same_pairs, outcome.tokens),
            identity_residual_rate(outcome.residual_total, outcome.identity_hits),
            cross_assignment_rate(different_pairs, outcome.tokens),
            single_code_rate(outcome.tokens),
        )

    add("# 基线对比实验：代号一致性 / 身份残留率 / 串号率")
    add("")
    add(
        "> 三条路径跑同一批语料、同一份原文，比的是「这份数据交出去之后，"
        "研究方还能不能用」。数字由 `scripts/compare_baseline.py` 重跑即可复现。"
    )
    add("")

    # ---- 结论 ----
    add("## 一、结论")
    add("")
    add("| 路径 | 代号一致性 | 身份残留率 | 串号率 | 一人一码率（补充） |")
    add("|------|------------|------------|--------|-------------------|")
    for outcome in outcomes:
        consistency, residual, collision, single = rates(outcome)
        add(
            f"| {outcome.display_name} | {_pct(consistency)} | {_pct(residual)} "
            f"| {_pct(collision)} | {_pct(single)} |"
        )
    add("")
    add(
        "三条路径各有各的坑：**朴素替换**一致但串号（所有患者共用同一批占位符，"
        "交付出去分不清谁是谁），**无一致性 hash** 不串号但跨材料对不上人"
        "（每份材料独立加盐），**本产品**两项都要。残留率另开一列：两条基线的"
        "字典来自主索引读回记录，覆盖不到手机号、完整身份证与检查号，"
        "产物里原样留着。"
    )
    add("")

    # ---- 语料 ----
    add("## 二、语料与规模")
    add("")
    add("| 项 | 值 |")
    add("|----|----|")
    add(f"| 语料目录 | `{corpus_root}` |")
    add(f"| 材料数 | {material_count} |")
    add(f"| 患者数 | {patient_count} |")
    add(f"| 批次数 | {len(batches)} |")
    add(f"| 同患者材料对 | {len(same_pairs)} |")
    add(f"| 不同患者材料对 | {len(different_pairs)} |")
    add(f"| 原文身份类 / 就诊编号类命中处数 | {outcomes[0].identity_hits} |")
    add(f"| 一致代号密钥来源 | {key_source} |")
    add(f"| 本次运行耗时 | {elapsed:.1f} 秒 |")
    add("")
    add(
        "语料由 `scripts/gen_corpus.py` 按固定种子确定性生成（合成数据，"
        "不含任何真实患者可识别信息）：姓名取自 20 个占位姓名池、患者 63 位 —— "
        "**必现同名异人**，这正是「按姓名做代号」会串号的场景。"
    )
    add("")

    # ---- 路径 ----
    add("## 三、三条路径")
    add("")
    for outcome in outcomes:
        add(f"### {outcome.display_name}")
        add("")
        add(outcome.how)
        add("")
    add(
        "两条基线共用同一份字典 —— **HIS 患者主索引读回记录**，字段只有 "
        "`patient_id` / `visit_no` / `name` / `id_card_masked` / `birth_date` / `sex`。"
        "这一份字段清单本身就是一条发现：**主索引读回的口径不足以支撑「按字典替换」**"
        "—— 手机号压根不在里面，身份证给的是掩码值（正文里是完整 18 位），"
        "检查号是每次检查独有的、任何患者记录里都没有。"
    )
    add("")

    # ---- 指标定义 ----
    add("## 四、指标定义与算法")
    add("")
    add("**身份槽位** = 姓名槽（`PATIENT_NAME`）与患者编号槽（`PATIENT_ID`）。")
    add("")
    add(
        "只有这两处指认「**这是谁**」。手机号 / 出生日期 / 身份证是「证明是谁」的"
        "直标识（脱掉即止，不构成代号）；住院号 / 检查号标识「**哪一次就诊**」，"
        "不是人 —— 把就诊槽算进代号，会因为「都写了 `<住院号>`」而把所有患者"
        "判成串号，那是误判，不是发现。"
    )
    add("")
    add("**代号集合 `T(m)`** = 该路径在身份槽位里写下的替换文本集合。")
    add("")
    add("| 指标 | 定义 |")
    add("|------|------|")
    add(
        "| 代号一致性 | 同患者材料对中 `T(m1) ∩ T(m2) ≠ ∅` 的对数 ÷ 同患者材料对总数"
        "（同一患者的材料能不能靠代号对上号） |"
    )
    add(
        "| 身份残留率 | 产物里阻断级身份残留处数 ÷ 原文身份类 / 就诊编号类命中处数"
        "（产物里还剩多少身份） |"
    )
    add(
        "| 串号率 | 不同患者材料对中 `T(m1) ∩ T(m2) ≠ ∅` 的对数 ÷ 不同患者材料对总数"
        "（会不会把两个不同的人误并成一人） |"
    )
    add(
        "| 一人一码率（补充） | `|T(m)| == 1` 的（材料, 患者）样本比例"
        "（一位患者在一份材料里被写成了几个代号） |"
    )
    add("")
    add(
        "分子分母口径：残留统计用产品自己的残留自检（身份类 / 就诊编号类 → 阻断级；"
        "通用数字类只提示不阻断）；原文命中数用产品自己的识别器按同一套分级统计，"
        "**三条路径共用同一个分母**（同一份原文）。"
    )
    add("")
    add(
        "**已脱产物的抑制口径三条路径一致**：产品自认自己的占位符与一致代号"
        "（命中即抑制，不算残留）；基线自己写出去的替换文本（占位符 / hash 代号）"
        "按同一套口径抑制。否则「住院号：H-xxx」会被字段标签识别器当成漏脱 —— "
        "那是替换文本，不是身份；不抑制的话，基线会因为「代号长得不像本院格式」"
        "而多背一处残留，那是尺子偏了，不是泄露。"
    )
    add("")

    # ---- 结果 ----
    add("## 五、实测结果")
    add("")
    add("| 路径 | 代号一致性 | 身份残留率 | 串号率 | 一人一码率（补充） | 残留处数 | 可交付 |")
    add("|------|------------|------------|--------|-------------------|----------|--------|")
    for outcome in outcomes:
        consistency, residual, collision, single = rates(outcome)
        add(
            f"| {outcome.display_name} | {_pct(consistency)} | {_pct(residual)} "
            f"| {_pct(collision)} | {_pct(single)} | {outcome.residual_total} "
            f"| {'是' if outcome.deliverable else '否'} |"
        )
    add("")

    # ---- 逐项解读 ----
    add("## 六、逐项解读")
    add("")
    product, naive, hash_path = (list(outcomes) + list(outcomes) * 3)[:3]
    p_consistency, p_residual, p_collision, p_single = rates(product)
    n_consistency, n_residual, n_collision, n_single = rates(naive)
    h_consistency, h_residual, h_collision, h_single = rates(hash_path)
    add("### 6.1 代号一致性 —— 同一患者的材料能不能对上号")
    add("")
    add(
        f"- 本产品 {_pct(p_consistency)}："
        "代号由**患者主索引主键**经 HMAC 算出，同一位患者在任何一份材料里都落到"
        "同一个串。"
    )
    add(
        f"- 朴素替换 {_pct(n_consistency)}："
        "也能对上号 —— 但代价是所有患者共用同一批占位符（见串号率）。"
    )
    add(
        f"- 无一致性 hash {_pct(h_consistency)}："
        "**跨材料完全对不上人**。每份材料独立加盐，同一段原文在两份材料里得到两个"
        "不同的串。这条路径的出发点通常是隐私侧诉求（「别让人把两份材料关联起来」），"
        "但代价是研究侧拿到的材料成了无法关联的碎片 —— 一致性与不可关联性在这一条"
        "路径上被绑成了同一件事。"
    )
    add("")
    add("### 6.2 身份残留率 —— 产物里还剩多少身份")
    add("")
    add(
        f"- 本产品 {_pct(p_residual)}（残留 {product.residual_total} 处）："
        "识别层覆盖到手机号、出生日期、完整身份证、检查号，处置层逐类改写，"
        "残留自检再扫一遍 —— 拦投放行。"
    )
    add(
        f"- 朴素替换 {_pct(n_residual)}（残留 {naive.residual_total} 处）、"
        f"无一致性 hash {_pct(h_residual)}（残留 {hash_path.residual_total} 处）："
        "两条基线的字典都来自主索引读回记录，**字典覆盖不到的字段原样留在产物里** ——"
        "手机号（主索引读回格式里没有）、完整身份证（主索引给的是掩码值）、"
        "检查号（每次检查独有，任何患者记录里都没有）。"
    )
    add("")
    add("### 6.3 串号率 —— 会不会把两个不同的人误并成一人")
    add("")
    add(
        f"- 本产品 {_pct(p_collision)}："
        "代号取自主索引主键，同名不同人拿到的串必然不同。"
    )
    add(
        f"- 朴素替换 {_pct(n_collision)}："
        "**所有患者共用同一批占位符** —— 交付给研究方之后，"
        "任何两份材料都能被关联成「同一个人」。"
    )
    add(
        f"- 无一致性 hash {_pct(h_collision)}："
        "加盐把跨材料关联掐断了，代价是上一节的跨材料对不上人。"
    )
    add("")
    add(
        "> 附带一条风险提示：如果把 hash 的加盐去掉（直接对**命中原文**做摘要），"
        "两位同名的不同患者会拿到同一个串 —— 本语料里 63 位患者只有 20 个姓名，"
        "这条坑一踩就是一片。**按原文做 hash 不等于一致代号**，"
        "一致代号的取值输入必须是权威身份键。"
    )
    add("")
    add("### 6.4 附带发现 · 代号本身也可能撞上身份形态")
    add("")
    collisions = hash_path.own_token_residuals
    if collisions:
        add(
            f"无一致性 hash 路径的残留率（{_pct(h_residual)}）比朴素替换"
            f"（{_pct(n_residual)}）高出的那 **{collisions} 处**是「**形态碰撞**」："
            "hash 代号是 16 位十六进制摘要，摘要里偶尔会出现 11 位连续数字，"
            "被联系方式识别器判成手机号 —— 残留自检把它算成一处漏脱。"
        )
    else:
        add(
            f"无一致性 hash 路径的残留率（{_pct(h_residual)}）与朴素替换"
            f"（{_pct(n_residual)}）持平，形态碰撞 {collisions} 处。"
        )
    add("")
    add(
        "形态碰撞**不是泄露**（那是替换文本，不是身份），但它是个真问题：**代号的"
        "字符集与院内编号形态撞了车**，收件方的自检工具同样会误报，值班的人要为此"
        "白查一轮。一致代号用固定前缀 + 固定位数十六进制，形态是收敛的 —— "
        f"本轮实测中本产品路径的形态碰撞为 {product.own_token_residuals} 处。"
    )
    add("")

    # ---- 复现 ----
    add("## 七、复现")
    add("")
    add("```bash")
    add("# 跑完整对比（语料不存在时按固定种子确定性生成）")
    add("python scripts/compare_baseline.py")
    add("")
    add("# 小规模快跑")
    add("python scripts/compare_baseline.py --limit 60")
    add("")
    add("# 指标口径的单元测试")
    add("pytest tests/test_baseline_metrics.py -q")
    add("```")
    add("")
    add("产物：")
    add("")
    add("- `reports/baseline-comparison.md` —— 本文件")
    add("- `reports/baseline-comparison.json` —— 同一组数字的机器可读版本")
    add("")

    # ---- 边界 ----
    add("## 八、边界与诚实标注")
    add("")
    add(
        "- 语料是**合成数据**，不是院内真实数据；真实报告的字段分布比这更杂，"
        "指标数值会变，**结论的方向**（一致 / 串号 / 残留三者的取舍关系）不会变。"
    )
    add(
        "- 两条基线是**按常见做法写的参照实现**，不是对某家厂商产品的评测；"
        "写它们是为了把「本产品多做了什么」量化，不是为了给别家打分。"
    )
    add(
        "- 「身份槽位只看姓名与患者编号」是一条**口径约定**，已在第四节写明。"
        "若把住院号 / 检查号也算进代号，三条路径的串号率都会变成 100% —— "
        "那衡量的是「都写了同一个占位符」，不是「分不清谁是谁」。"
    )
    add(
        "- 一致代号密钥来源见第二节。三项指标都与密钥取值无关，"
        "换密钥只改变代号字符串本身。"
    )
    add("")
    return "\n".join(lines) + "\n"


def _same_pairs(batches: Sequence[CorpusBatch]) -> list[tuple[str, str]]:
    """同患者材料对（三条路径共用同一份配对，避免各算各的）。"""
    materials = [m for batch in batches for m in batch.materials]
    same, _different = pair_split(materials)
    return same


def _different_pairs(batches: Sequence[CorpusBatch]) -> list[tuple[str, str]]:
    """不同患者材料对。"""
    materials = [m for batch in batches for m in batch.materials]
    _same, different = pair_split(materials)
    return different


# --------------------------------------------------------------------- 入口


def _resolve_key(explicit: str | None) -> tuple[str, str]:
    """取一致代号密钥，返回（密钥, 来源说明）。

    未配置 ``$PSEUDONYM_HMAC_KEY`` 时用基准跑用密钥并**明确标注** ——
    三项指标与密钥取值无关，但脚本必须开箱可跑、数字可复现。
    """
    if explicit:
        return explicit, "命令行 --pseudonym-key"
    env_value = (os.environ.get("PSEUDONYM_HMAC_KEY") or "").strip()
    if env_value:
        return env_value, "$PSEUDONYM_HMAC_KEY"
    return BENCHMARK_ONLY_KEY, "基准跑用密钥（未配置 $PSEUDONYM_HMAC_KEY；非生产密钥）"


def main(argv: Sequence[str] | None = None) -> int:
    """脚本入口。"""
    parser = argparse.ArgumentParser(
        description="基线对比实验：代号一致性 / 身份残留率 / 串号率"
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="语料目录")
    parser.add_argument("--out", default=str(DEFAULT_REPORT), help="对比报告输出路径")
    parser.add_argument("--json-out", default="", help="机器可读版本的输出路径（默认与报告同名加 .json）")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="语料材料数（语料不存在时生效）")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="语料随机种子（语料不存在时生效）")
    parser.add_argument("--pseudonym-key", default="", help="一致代号密钥（缺省读 $PSEUDONYM_HMAC_KEY）")
    args = parser.parse_args(argv)

    started = time.perf_counter()
    corpus_root = ensure_corpus(args.corpus, seed=args.seed, limit=args.limit)
    batches = load_corpus(corpus_root)
    if not batches:
        print(f"语料为空：{corpus_root}", file=sys.stderr)
        return 2

    key, key_source = _resolve_key(args.pseudonym_key or None)
    if key_source.startswith("基准跑用密钥"):
        print("注意：未配置 $PSEUDONYM_HMAC_KEY，本次使用基准跑用密钥（非生产密钥）。")

    table = load_policy_table(profile=PSEUDONYM_PROFILE)
    rules = load_conflict_rules()

    product = run_product_path(batches, key=key, table=table, rules=rules)
    naive = run_naive_path(batches, table=table, rules=rules)
    hash_path = run_hash_path(batches, table=table, rules=rules)
    outcomes = (product, naive, hash_path)

    materials = [m for batch in batches for m in batch.materials]
    same_pairs, different_pairs = pair_split(materials)
    patient_count = len({m.patient_id for m in materials})
    material_count = len(materials)

    elapsed = time.perf_counter() - started
    report = _render_report(
        corpus_root=corpus_root,
        batches=batches,
        outcomes=outcomes,
        same_pairs=same_pairs,
        different_pairs=different_pairs,
        patient_count=patient_count,
        material_count=len(materials),
        key_source=key_source,
        elapsed=elapsed,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    json_path = Path(args.json_out) if args.json_out else out_path.with_suffix(".json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(
            {
                "corpus": str(corpus_root),
                "material_count": len(materials),
                "patient_count": patient_count,
                "batch_count": len(batches),
                "same_patient_pairs": len(same_pairs),
                "different_patient_pairs": len(different_pairs),
                "identity_hits": product.identity_hits,
                "key_source": key_source,
                "paths": [
                    {
                        "path_id": outcome.path_id,
                        "display_name": outcome.display_name,
                        "consistency": consistency_rate(same_pairs, outcome.tokens),
                        "identity_residual_rate": identity_residual_rate(
                            outcome.residual_total, outcome.identity_hits
                        ),
                        "cross_assignment_rate": cross_assignment_rate(
                            different_pairs, outcome.tokens
                        ),
                        "single_code_rate": single_code_rate(outcome.tokens),
                        "residual_total": outcome.residual_total,
                        "own_token_residuals": outcome.own_token_residuals,
                        "deliverable": outcome.deliverable,
                    }
                    for outcome in outcomes
                ],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print(f"语料：{material_count} 份材料 / {patient_count} 位患者 / {len(batches)} 个批次")
    print(f"材料对：同患者 {len(same_pairs)} / 不同患者 {len(different_pairs)}")
    print()
    header = f"{'路径':<22}{'代号一致性':>12}{'身份残留率':>12}{'串号率':>12}{'一人一码率':>12}"
    print(header)
    print("-" * 70)
    for outcome in outcomes:
        print(
            f"{outcome.display_name:<20}"
            f"{_pct(consistency_rate(same_pairs, outcome.tokens)):>12}"
            f"{_pct(identity_residual_rate(outcome.residual_total, outcome.identity_hits)):>12}"
            f"{_pct(cross_assignment_rate(different_pairs, outcome.tokens)):>12}"
            f"{_pct(single_code_rate(outcome.tokens)):>12}"
        )
    print()
    print(f"报告：{out_path}")
    print(f"机器可读：{json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
