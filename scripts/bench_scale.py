#!/usr/bin/env python3
"""规模与性能基准：500 例材料的「识别 → 一致代号 → 残留自检」全链路实测。

**为什么要做这个基准**：README 上写「500 例材料 2 分钟内处理完」，那是**没人
验过的数字**。科研数据管理员不会因为一句承诺就把一批影像报告投进交付目录 ——
他们要的是「这批到底多久跑完、跑完占多少内存、会不会跑到一半被截断」。

本脚本把产品**真实主路径**放在真实规模的语料上跑一遍，产出三个可核对的数：

1. **耗时** —— 分阶段（识别 / 处置改写 / 残留自检）出耗时分位，不只给一个
   总数。守护进程是常驻的，总数决定「一批交付要等多久」，分位数决定
   **最慢的那份材料**会把一次批处理拖成什么样。
2. **峰值内存** —— 进程峰值 RSS（``getrusage``）+ Python 堆峰值
   （``tracemalloc``，单独一趟量，不污染计时）。
3. **条目数守恒** —— 识别产出的命中数与写进命中清单的条目数必须**逐份相等**。
   这一条是「无截断」的硬证据：清单条数少了，说明有命中在管道里被丢掉，
   那是漏脱，不是性能问题。

**验收阈值**（写在脚本里，不是写在报告里）：

- 500 例材料（每份 1–20 KB）跑完「识别 + 残留自检」总耗时 **≤ 120 秒**；
- 识别条目数 == 清单条目数（逐份相等，总数相等）；
- 每份材料都产出条目（没有一份被截成 0 条）。

**阈值超了怎么办**：不静默通过。报告里写明实测值、阈值与差距，脚本以非 0
退出码收场 —— CI 拦得住。

用法::

    python scripts/bench_scale.py                          # 默认 500 例语料
    python scripts/bench_scale.py --limit 60               # 小规模快跑
    python scripts/bench_scale.py --corpus var/corpus --out reports/performance.md
    python scripts/bench_scale.py --no-tracemalloc         # 只量进程峰值 RSS
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import resource
import sys
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _extra in (str(_ROOT / "src"), str(_HERE)):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

from compare_baseline import (  # noqa: E402
    BENCHMARK_ONLY_KEY,
    CorpusBatch,
    ensure_corpus,
    load_corpus,
)
from research_redact.audit.residual import ResidualChecker, pseudonym_pattern  # noqa: E402
from research_redact.config import PSEUDONYM_HMAC_KEY_ENV  # noqa: E402
from research_redact.daemon.pipeline import redact_text  # noqa: E402
from research_redact.policy.conflicts import load_conflict_rules  # noqa: E402
from research_redact.policy.operators import default_operator_registry  # noqa: E402
from research_redact.policy.table import load_policy_table  # noqa: E402
from research_redact.recognizers.assembly import build_default_registry  # noqa: E402
from research_redact.recognizers.patient_index import (  # noqa: E402
    load_patient_index_binding,
)

__all__ = [
    "MaterialSample",
    "ScaleBenchmark",
    "main",
    "machine_profile",
    "percentile",
    "run_benchmark",
]


# --------------------------------------------------------------------- 常量

#: 一致代号档（策略表 ``profiles.pseudonym``）—— 基准要量的是**含代号**的
#: 完整主路径，不是一致代号之前的半截路径。
PSEUDONYM_PROFILE = "pseudonym"

#: 语料默认目录 / 规模 / 种子（与 scripts/gen_corpus.py 的出厂口径一致）。
DEFAULT_CORPUS = Path("var") / "corpus"
DEFAULT_LIMIT = 500
DEFAULT_SEED = 20260101

#: 报告默认输出路径。
DEFAULT_REPORT = Path("reports") / "performance.md"

#: 验收阈值（秒）：500 例材料「识别 + 残留自检」总耗时上限。
DEFAULT_THRESHOLD_SECONDS = 120.0

#: 单份材料的体量区间（字节）—— 验收口径写的是「每份 1–20 KB」。
ACCEPTED_MIN_BYTES = 1024
ACCEPTED_MAX_BYTES = 20 * 1024


# --------------------------------------------------------------------- 数据结构


@dataclass(frozen=True)
class MaterialSample:
    """一份材料跑完一轮的实测。

    :param material_id: 材料 ID。
    :param application_no: 所属申请单号。
    :param size_bytes: 正文体量（字节）。
    :param spans: 识别产出的命中数。
    :param entries: 写进命中清单的条目数（应当与 ``spans`` 相等）。
    :param recognize_s: 识别耗时（秒）。
    :param redact_s: 脱敏总耗时（秒，**含**识别：内部会再扫一遍）。
    :param residual_s: 残留自检耗时（秒，含对脱敏副本的二次扫描）。
    :param pseudonym_codes: 这份材料里落下的一致代号个数（去重后）。
    :param blocking_residual: 这份材料的阻断级残留处数。
    """

    material_id: str
    application_no: str
    size_bytes: int
    spans: int
    entries: int
    recognize_s: float
    redact_s: float
    residual_s: float
    pseudonym_codes: int
    blocking_residual: int

    @property
    def rewrite_s(self) -> float:
        """处置改写耗时（冲突裁决 + 动作执行）= 脱敏总耗时 − 识别耗时。"""
        return max(0.0, self.redact_s - self.recognize_s)

    @property
    def conserved(self) -> bool:
        """这份材料的条目数是否守恒（识别数 == 清单数）。"""
        return self.spans == self.entries


@dataclass(frozen=True)
class ScaleBenchmark:
    """一轮基准跑完之后的全部计量。

    :param corpus_root: 语料目录。
    :param samples: 逐份材料的实测。
    :param batch_count: 批次数。
    :param patient_count: 患者数。
    :param recognize_s: 识别总耗时。
    :param redact_s: 脱敏总耗时（含识别）。
    :param residual_s: 残留自检总耗时。
    :param wall_s: 整轮墙钟耗时。
    :param peak_rss_bytes: 进程峰值 RSS。
    :param python_peak_bytes: Python 堆峰值（tracemalloc）。
    :param blocking_residual: 阻断级残留总处数。
    :param out_of_range: 体量落在 1–20 KB 之外的材料 ID。
    :param threshold_s: 验收阈值（秒）。
    :param key_source: 一致代号密钥来源说明。
    """

    corpus_root: Path
    samples: tuple[MaterialSample, ...] = ()
    batch_count: int = 0
    patient_count: int = 0
    recognize_s: float = 0.0
    redact_s: float = 0.0
    residual_s: float = 0.0
    wall_s: float = 0.0
    peak_rss_bytes: int = 0
    python_peak_bytes: int = 0
    blocking_residual: int = 0
    out_of_range: tuple[str, ...] = ()
    threshold_s: float = DEFAULT_THRESHOLD_SECONDS
    key_source: str = ""

    # ---- 总量 ----

    @property
    def material_count(self) -> int:
        """本次跑的材料数。"""
        return len(self.samples)

    @property
    def headline_s(self) -> float:
        """验收主指标：识别 + 残留自检总耗时（秒）。"""
        return self.recognize_s + self.residual_s

    @property
    def chain_s(self) -> float:
        """全链路耗时（秒）：识别 + 处置改写 + 残留自检。"""
        return self.redact_s + self.residual_s

    @property
    def rewrite_s(self) -> float:
        """处置改写总耗时（秒）。"""
        return max(0.0, self.redact_s - self.recognize_s)

    @property
    def span_total(self) -> int:
        """识别产出的命中总数。"""
        return sum(sample.spans for sample in self.samples)

    @property
    def entry_total(self) -> int:
        """写进命中清单的条目总数。"""
        return sum(sample.entries for sample in self.samples)

    @property
    def conserved(self) -> bool:
        """条目数是否守恒（逐份相等且总数相等）。"""
        return all(sample.conserved for sample in self.samples) and (
            self.span_total == self.entry_total
        )

    @property
    def every_material_hit(self) -> bool:
        """是否每份材料都产出了条目（没有一份被截成 0 条）。"""
        return all(sample.entries > 0 for sample in self.samples)

    @property
    def within_threshold(self) -> bool:
        """主指标是否在阈值内。"""
        return self.headline_s <= self.threshold_s

    @property
    def gap_s(self) -> float:
        """距阈值的余量（秒）；负数表示超出。"""
        return self.threshold_s - self.headline_s

    @property
    def total_bytes(self) -> int:
        """语料总体量（字节）。"""
        return sum(sample.size_bytes for sample in self.samples)

    @property
    def pseudonym_total(self) -> int:
        """一致代号落地的总次数（逐份材料内去重后相加）。"""
        return sum(sample.pseudonym_codes for sample in self.samples)


# --------------------------------------------------------------------- 计量工具


def percentile(values: Sequence[float], q: float) -> float:
    """最近秩法分位数。

    :param values: 样本序列（空序列返回 0.0）。
    :param q: 分位（0–1，如 0.95 表示 P95）。
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(q * len(ordered))
    index = min(max(rank - 1, 0), len(ordered) - 1)
    return float(ordered[index])


def statistics_median(values: Sequence[int]) -> float:
    """中位数（空序列返回 0.0）。"""
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _peak_rss_bytes() -> int:
    """进程峰值 RSS（字节）。

    ``getrusage`` 的 ``ru_maxrss`` 单位随平台不同：macOS 是字节，Linux 是
    KB。这里按平台换算，报告里只写字节。
    """
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(usage)
    return int(usage) * 1024


def _total_memory_bytes() -> int | None:
    """物理内存总量（字节）；取不到返回 None。"""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return None
    return int(pages) * int(page_size)


def machine_profile() -> dict[str, str]:
    """机器规格（写进报告，便于别人判断数字的可比性）。"""
    total_memory = _total_memory_bytes()
    return {
        "平台": platform.platform(),
        "机器架构": platform.machine(),
        "处理器": platform.processor() or "（系统未提供）",
        "CPU 逻辑核数": str(os.cpu_count() or 0),
        "物理内存": (
            f"{total_memory / (1024 ** 3):.1f} GiB"
            if total_memory
            else "（系统未提供）"
        ),
        "Python": platform.python_version(),
        "解释器": platform.python_implementation(),
    }


def _fmt_seconds(value: float) -> str:
    """秒 → 「1.28 秒」这样的展示串。"""
    if value >= 1.0:
        return f"{value:.2f} 秒"
    return f"{value * 1000:.1f} 毫秒"


def _fmt_mib(value: int) -> str:
    """字节 → MiB。"""
    return f"{value / (1024 ** 2):.1f} MiB"


# --------------------------------------------------------------------- 跑基准


def _measure_pass(
    batches: Sequence[CorpusBatch],
    *,
    limit: int | None,
    table,
    rules,
    operators,
    shape,
    key: str | None = None,
) -> tuple[list[MaterialSample], float, float, float, int]:
    """跑一趟全链路，逐份材料计量。

    每一份材料走的是产品真实主路径：识别 → 按策略处置（含一致代号）→
    残留自检。名单按批次装配 —— 与守护进程一致（每张申请单读一次主索引）。

    :param key: 一致代号密钥。给了就在本趟运行期间写入
        ``$PSEUDONYM_HMAC_KEY``（动作在**执行时**才取密钥），跑完恢复原值 ——
        不把环境变量留在调用方的进程里。
    :return: ``(逐份样本, 识别总耗时, 脱敏总耗时, 残留总耗时, 阻断级残留总数)``。
    """
    samples: list[MaterialSample] = []
    recognize_total = 0.0
    redact_total = 0.0
    residual_total = 0.0
    blocking_total = 0
    seen = 0

    previous_key = os.environ.get(PSEUDONYM_HMAC_KEY_ENV)
    if key is not None:
        os.environ[PSEUDONYM_HMAC_KEY_ENV] = key
    try:
        for batch in batches:
            binding = load_patient_index_binding(
                batch.records, declared_patient_ids=batch.declared_patient_ids
            )
            registry = build_default_registry(binding, table)
            checker = ResidualChecker(registry=registry)

            for material in batch.materials:
                if limit is not None and seen >= limit:
                    return (
                        samples,
                        recognize_total,
                        redact_total,
                        residual_total,
                        blocking_total,
                    )
                seen += 1

                started = time.perf_counter()
                spans = registry.analyze(material.text)
                recognize_s = time.perf_counter() - started

                started = time.perf_counter()
                outcome = redact_text(
                    material.text,
                    material.material_id,
                    registry=registry,
                    actions=table.action_for,
                    operators=operators,
                    rules=rules,
                )
                redact_s = time.perf_counter() - started

                started = time.perf_counter()
                report = checker.check_batch(
                    batch.application_no, {material.material_id: outcome.redacted_text}
                )
                residual_s = time.perf_counter() - started

                recognize_total += recognize_s
                redact_total += redact_s
                residual_total += residual_s

                blocking = sum(1 for finding in report.findings if finding.is_blocking)
                blocking_total += blocking

                samples.append(
                    MaterialSample(
                        material_id=material.material_id,
                        application_no=batch.application_no,
                        size_bytes=len(material.text.encode("utf-8")),
                        spans=len(spans),
                        entries=len(outcome.entries),
                        recognize_s=recognize_s,
                        redact_s=redact_s,
                        residual_s=residual_s,
                        pseudonym_codes=len(set(shape.findall(outcome.redacted_text))),
                        blocking_residual=blocking,
                    )
                )
    finally:
        if previous_key is None:
            os.environ.pop(PSEUDONYM_HMAC_KEY_ENV, None)
        else:
            os.environ[PSEUDONYM_HMAC_KEY_ENV] = previous_key

    return samples, recognize_total, redact_total, residual_total, blocking_total


def _resolve_key(explicit: str | None) -> tuple[str, str]:
    """取一致代号密钥，返回（密钥, 来源说明）。

    未配置 ``$PSEUDONYM_HMAC_KEY`` 时用基准跑用密钥并**明确标注** ——
    耗时与密钥取值无关（HMAC 只在处置阶段跑一次），但脚本必须开箱可跑。
    """
    if explicit:
        return explicit, "命令行 --pseudonym-key"
    env_value = (os.environ.get(PSEUDONYM_HMAC_KEY_ENV) or "").strip()
    if env_value:
        return env_value, f"${PSEUDONYM_HMAC_KEY_ENV}"
    return BENCHMARK_ONLY_KEY, "基准跑用密钥（未配置 $PSEUDONYM_HMAC_KEY；非生产密钥）"


def run_benchmark(
    *,
    corpus_dir: str | Path = DEFAULT_CORPUS,
    limit: int | None = DEFAULT_LIMIT,
    seed: int = DEFAULT_SEED,
    key: str | None = None,
    threshold_s: float = DEFAULT_THRESHOLD_SECONDS,
    measure_python_heap: bool = True,
) -> ScaleBenchmark:
    """跑一轮规模基准。

    :param corpus_dir: 语料目录（不存在则按固定种子确定性生成一份）。
    :param limit: 最多跑多少份材料（``None`` 表示全跑）。
    :param seed: 语料生成种子（语料已存在时不生效）。
    :param key: 一致代号密钥。
    :param threshold_s: 验收阈值（秒）。
    :param measure_python_heap: 是否额外跑一趟量 Python 堆峰值
        （``tracemalloc`` 有开销，单独一趟量，不污染计时那一趟）。
    """
    started = time.perf_counter()
    corpus_root = ensure_corpus(corpus_dir, seed=seed, limit=limit or DEFAULT_LIMIT)
    batches = load_corpus(corpus_root)

    table = load_policy_table(profile=PSEUDONYM_PROFILE)
    rules = load_conflict_rules()
    operators = default_operator_registry()
    shape = pseudonym_pattern(table.pseudonymization)

    active_key, key_source = _resolve_key(key)
    samples, recognize_s, redact_s, residual_s, blocking = _measure_pass(
        batches,
        limit=limit,
        table=table,
        rules=rules,
        operators=operators,
        shape=shape,
        key=active_key,
    )
    wall_s = time.perf_counter() - started

    python_peak = 0
    if measure_python_heap and samples:
        tracemalloc.start()
        try:
            _measure_pass(
                batches,
                limit=limit,
                table=table,
                rules=rules,
                operators=operators,
                shape=shape,
                key=active_key,
            )
            python_peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    out_of_range = tuple(
        sample.material_id
        for sample in samples
        if not (ACCEPTED_MIN_BYTES <= sample.size_bytes <= ACCEPTED_MAX_BYTES)
    )
    patients = {
        material.patient_id for batch in batches for material in batch.materials
    }
    # 限跑时只数**真正跑到**的批次 —— 报 50 张申请单、只跑了 20 份材料，
    # 报告会让人以为名单按 50 批装配过。
    touched_batches = len({sample.application_no for sample in samples})

    return ScaleBenchmark(
        corpus_root=Path(corpus_root),
        samples=tuple(samples),
        batch_count=touched_batches,
        patient_count=len(patients),
        recognize_s=recognize_s,
        redact_s=redact_s,
        residual_s=residual_s,
        wall_s=wall_s,
        peak_rss_bytes=_peak_rss_bytes(),
        python_peak_bytes=python_peak,
        blocking_residual=blocking,
        out_of_range=out_of_range,
        threshold_s=threshold_s,
        key_source=key_source,
    )


# --------------------------------------------------------------------- 报告


def _render_report(benchmark: ScaleBenchmark) -> str:
    """渲染 reports/performance.md。"""
    samples = benchmark.samples
    lines: list[str] = []
    add = lines.append

    recognize_times = [s.recognize_s for s in samples]
    rewrite_times = [s.rewrite_s for s in samples]
    residual_times = [s.residual_s for s in samples]
    sizes = [s.size_bytes for s in samples]

    verdict = "通过" if benchmark.within_threshold else "**未通过**"
    add("# 规模与性能基准：500 例材料的识别 → 一致代号 → 残留自检")
    add("")
    add(
        "> 数字由 `scripts/bench_scale.py` 在本机实跑得出（命令与参数见文末）；"
        "语料为 `scripts/gen_corpus.py` 固定种子合成的 **合成数据**，不含任何"
        "真实患者可识别信息。"
    )
    add("")

    # ---- 结论 ----
    add("## 一、结论")
    add("")
    add("| 验收项 | 阈值 | 实测 | 差距 | 结论 |")
    add("|--------|------|------|------|------|")
    add(
        f"| 识别 + 残留自检总耗时（{benchmark.material_count} 例） | "
        f"≤ {benchmark.threshold_s:.0f} 秒 | {_fmt_seconds(benchmark.headline_s)} | "
        f"{'+' if benchmark.gap_s >= 0 else ''}{benchmark.gap_s:.2f} 秒 | {verdict} |"
    )
    add(
        f"| 识别条目数 == 清单条目数 | 逐份相等 | "
        f"{benchmark.span_total} == {benchmark.entry_total} | — | "
        f"{'通过' if benchmark.conserved else '**未通过**'} |"
    )
    add(
        f"| 每份材料都产出条目 | 无 0 条 | "
        f"{sum(1 for s in samples if s.entries == 0)} 份为 0 | — | "
        f"{'通过' if benchmark.every_material_hit else '**未通过**'} |"
    )
    add(
        f"| 单份体量落在 1–20 KB | 全部命中 | "
        f"{len(benchmark.out_of_range)} 份越界 | — | "
        f"{'通过' if not benchmark.out_of_range else '**未通过**'} |"
    )
    add(
        f"| 身份类残留（阻断级） | 0 处 | {benchmark.blocking_residual} 处 | — | "
        f"{'通过' if benchmark.blocking_residual == 0 else '**未通过**'} |"
    )
    add("")
    if benchmark.within_threshold:
        add(
            f"主指标「识别 + 残留自检」实测 **{_fmt_seconds(benchmark.headline_s)}**，"
            f"阈值 {benchmark.threshold_s:.0f} 秒，**余量 {benchmark.gap_s:.2f} 秒**。"
            f"全链路（含处置改写）{_fmt_seconds(benchmark.chain_s)}。"
        )
    else:
        add(
            f"主指标「识别 + 残留自检」实测 **{_fmt_seconds(benchmark.headline_s)}**，"
            f"**超出阈值 {benchmark.threshold_s:.0f} 秒共 "
            f"{abs(benchmark.gap_s):.2f} 秒**（超出 "
            f"{benchmark.headline_s / benchmark.threshold_s:.1f} 倍）。"
            f"该批规模在当前机器上不达验收口径，不得按「已达标」发布。"
        )
    add("")

    # ---- 机器 ----
    add("## 二、机器规格")
    add("")
    add("| 项 | 值 |")
    add("|----|----|")
    for name, value in machine_profile().items():
        add(f"| {name} | {value} |")
    add("")

    # ---- 语料 ----
    add("## 三、语料与规模")
    add("")
    add("| 项 | 值 |")
    add("|----|----|")
    add(f"| 语料目录 | `{benchmark.corpus_root}` |")
    add(f"| 材料数 | {benchmark.material_count} |")
    add(f"| 批次数 | {benchmark.batch_count} |")
    add(f"| 患者数 | {benchmark.patient_count} |")
    add(f"| 语料总体量 | {benchmark.total_bytes / (1024 ** 2):.1f} MiB |")
    if sizes:
        add(f"| 单份体量最小 / 中位 / 最大 | {min(sizes)} B / {int(statistics_median(sizes))} B / {max(sizes)} B |")
    add(f"| 一致代号落地总次数 | {benchmark.pseudonym_total} |")
    add(f"| 一致代号密钥来源 | {benchmark.key_source} |")
    add("")
    add(
        "语料由 `scripts/gen_corpus.py` 按固定种子确定性生成：同种子两次生成"
        "逐字节一致。**注意语料规模与批次的关系** —— 500 份材料分摊在 50 张"
        "申请单上（每单 10 份），主索引名单按批次装配，与守护进程的真实节奏一致。"
    )
    add("")

    # ---- 耗时 ----
    add("## 四、耗时分位")
    add("")
    add("**逐份材料**（单位：毫秒；`p95` 决定最慢的那份材料把一次批处理拖成什么样）")
    add("")
    add("| 阶段 | P50 | P90 | P95 | P99 | 最大 | 合计 |")
    add("|------|-----|-----|-----|-----|------|------|")
    add(
        f"| 识别 | {_ms(percentile(recognize_times, 0.50))} | "
        f"{_ms(percentile(recognize_times, 0.90))} | "
        f"{_ms(percentile(recognize_times, 0.95))} | "
        f"{_ms(percentile(recognize_times, 0.99))} | "
        f"{_ms(max(recognize_times) if recognize_times else 0.0)} | "
        f"{_fmt_seconds(benchmark.recognize_s)} |"
    )
    add(
        f"| 处置改写（冲突裁决 + 动作执行） | {_ms(percentile(rewrite_times, 0.50))} | "
        f"{_ms(percentile(rewrite_times, 0.90))} | "
        f"{_ms(percentile(rewrite_times, 0.95))} | "
        f"{_ms(percentile(rewrite_times, 0.99))} | "
        f"{_ms(max(rewrite_times) if rewrite_times else 0.0)} | "
        f"{_fmt_seconds(benchmark.rewrite_s)} |"
    )
    add(
        f"| 残留自检（二次扫描） | {_ms(percentile(residual_times, 0.50))} | "
        f"{_ms(percentile(residual_times, 0.90))} | "
        f"{_ms(percentile(residual_times, 0.95))} | "
        f"{_ms(percentile(residual_times, 0.99))} | "
        f"{_ms(max(residual_times) if residual_times else 0.0)} | "
        f"{_fmt_seconds(benchmark.residual_s)} |"
    )
    add("")
    add("**整轮**")
    add("")
    add("| 口径 | 耗时 | 说明 |")
    add("|------|------|------|")
    add(
        f"| 识别 + 残留自检（**验收主指标**） | {_fmt_seconds(benchmark.headline_s)} | "
        f"阈值 {benchmark.threshold_s:.0f} 秒 |"
    )
    add(
        f"| 全链路（识别 + 处置改写 + 残留自检） | {_fmt_seconds(benchmark.chain_s)} | "
        f"守护进程一批交付的实际等待时间 |"
    )
    add(f"| 整轮墙钟（含语料装载与装配） | {_fmt_seconds(benchmark.wall_s)} | 含装配注册表与主索引名单 |")
    add("")

    # ---- 内存 ----
    add("## 五、峰值内存")
    add("")
    add("| 口径 | 值 | 说明 |")
    add("|----|----|------|")
    add(
        f"| 进程峰值 RSS | {_fmt_mib(benchmark.peak_rss_bytes)} | "
        f"`getrusage(RUSAGE_SELF).ru_maxrss`，含解释器与基准脚本自身 |"
    )
    if benchmark.python_peak_bytes:
        add(
            f"| Python 堆峰值 | {_fmt_mib(benchmark.python_peak_bytes)} | "
            f"`tracemalloc` 单独一趟量（带开销，不计入计时那一趟） |"
        )
    add("")
    add(
        "守护进程是**常驻**的：内存不随批次数线性增长 —— 每批用完的注册表与"
        "主索引名单随批次对象释放，峰值取决于单批材料的体量，而不是累计处理量。"
    )
    add("")

    # ---- 条目数守恒 ----
    add("## 六、条目数守恒（无截断）")
    add("")
    add("| 项 | 值 |")
    add("|----|----|")
    add(f"| 识别产出命中总数 | {benchmark.span_total} |")
    add(f"| 命中清单条目总数 | {benchmark.entry_total} |")
    add(
        f"| 逐份守恒（识别数 == 清单数） | "
        f"{'全部相等' if benchmark.conserved else '存在不等'} |"
    )
    add(
        f"| 每份材料条目数最小 / 中位 / 最大 | "
        f"{min((s.entries for s in samples), default=0)} / "
        f"{int(statistics_median([s.entries for s in samples])) if samples else 0} / "
        f"{max((s.entries for s in samples), default=0)} |"
    )
    add("")
    add(
        "「识别数 == 清单数」是**无截断**的硬证据：命中清单是交差产物，"
        "少一条就意味着有一处命中没进清单 —— 人工复核会漏看那一处。"
        "两者相等说明识别层产出的每一处命中都落进了清单（含告警档与白名单放行项）。"
    )
    add("")

    # ---- 复现 ----
    add("## 七、复现方式")
    add("")
    add("```bash")
    add("# 生成语料（固定种子，同种子两次生成逐字节一致）")
    add("python scripts/gen_corpus.py --limit 500 --seed 20260101 --out var/corpus")
    add("")
    add("# 跑基准并写报告")
    add("python scripts/bench_scale.py --corpus var/corpus --out reports/performance.md")
    add("")
    add("# 小规模快跑（调试用）")
    add("python scripts/bench_scale.py --limit 60")
    add("```")
    add("")
    add(
        "基准脚本**不静默通过**：主指标超出阈值时，报告写明实测值与差距，"
        "脚本以非 0 退出码收场。"
    )
    add("")

    return "\n".join(lines) + "\n"


def _ms(seconds: float) -> str:
    """秒 → 毫秒展示串。"""
    return f"{seconds * 1000:.2f}"


# --------------------------------------------------------------------- 入口


def main(argv: Sequence[str] | None = None) -> int:
    """脚本入口。"""
    parser = argparse.ArgumentParser(
        description="规模与性能基准：500 例材料的识别 → 一致代号 → 残留自检"
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="语料目录")
    parser.add_argument("--out", default=str(DEFAULT_REPORT), help="报告输出路径")
    parser.add_argument("--json-out", default="", help="机器可读输出路径（默认与报告同名加 .json）")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="最多跑多少份材料（0 = 全跑）")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="语料随机种子（语料不存在时生效）")
    parser.add_argument("--pseudonym-key", default="", help="一致代号密钥（缺省读 $PSEUDONYM_HMAC_KEY）")
    parser.add_argument(
        "--threshold-seconds",
        type=float,
        default=DEFAULT_THRESHOLD_SECONDS,
        help="验收阈值（秒），默认 120",
    )
    parser.add_argument(
        "--no-tracemalloc",
        action="store_true",
        help="不额外跑一趟量 Python 堆峰值（只保留进程峰值 RSS）",
    )
    args = parser.parse_args(argv)

    limit = args.limit if args.limit and args.limit > 0 else None
    benchmark = run_benchmark(
        corpus_dir=args.corpus,
        limit=limit,
        seed=args.seed,
        key=args.pseudonym_key or None,
        threshold_s=args.threshold_seconds,
        measure_python_heap=not args.no_tracemalloc,
    )
    if not benchmark.samples:
        print(f"语料为空：{benchmark.corpus_root}", file=sys.stderr)
        return 2

    report = _render_report(benchmark)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    json_path = Path(args.json_out) if args.json_out else out_path.with_suffix(".json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(
            {
                "corpus": str(benchmark.corpus_root),
                "material_count": benchmark.material_count,
                "batch_count": benchmark.batch_count,
                "patient_count": benchmark.patient_count,
                "total_bytes": benchmark.total_bytes,
                "recognize_s": round(benchmark.recognize_s, 4),
                "rewrite_s": round(benchmark.rewrite_s, 4),
                "residual_s": round(benchmark.residual_s, 4),
                "headline_s": round(benchmark.headline_s, 4),
                "chain_s": round(benchmark.chain_s, 4),
                "wall_s": round(benchmark.wall_s, 4),
                "threshold_s": benchmark.threshold_s,
                "within_threshold": benchmark.within_threshold,
                "gap_s": round(benchmark.gap_s, 4),
                "peak_rss_bytes": benchmark.peak_rss_bytes,
                "python_peak_bytes": benchmark.python_peak_bytes,
                "span_total": benchmark.span_total,
                "entry_total": benchmark.entry_total,
                "conserved": benchmark.conserved,
                "every_material_hit": benchmark.every_material_hit,
                "blocking_residual": benchmark.blocking_residual,
                "out_of_range": list(benchmark.out_of_range),
                "key_source": benchmark.key_source,
                "machine": machine_profile(),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        f"语料 {benchmark.material_count} 例 / {benchmark.batch_count} 批 / "
        f"{benchmark.patient_count} 位患者，"
        f"总 {benchmark.total_bytes / (1024 ** 2):.1f} MiB"
    )
    print(
        f"识别 + 残留自检 {benchmark.headline_s:.2f} 秒"
        f"（阈值 {benchmark.threshold_s:.0f} 秒，余量 {benchmark.gap_s:.2f} 秒）；"
        f"全链路 {benchmark.chain_s:.2f} 秒；"
        f"峰值 RSS {benchmark.peak_rss_bytes / (1024 ** 2):.1f} MiB"
    )
    print(
        f"条目数守恒：识别 {benchmark.span_total} == 清单 {benchmark.entry_total}"
        f"（{'守恒' if benchmark.conserved else '不守恒'}）；"
        f"阻断级身份残留 {benchmark.blocking_residual} 处"
    )
    print(f"报告：{out_path}（机器可读：{json_path}）")

    if not benchmark.within_threshold:
        print(
            f"未通过：主指标 {benchmark.headline_s:.2f} 秒超出阈值 "
            f"{benchmark.threshold_s:.0f} 秒共 {abs(benchmark.gap_s):.2f} 秒",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - 脚本入口
    raise SystemExit(main())
