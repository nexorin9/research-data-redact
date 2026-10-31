"""规模基准的守恒断言：识别条目数 == 命中清单条目数。

**为什么这一条要单独守**：命中清单是交差产物 —— 伦理办据此复核「这批脱敏
脱干净了没有」。清单里少一条，就有一处命中没进清单，人工复核会漏看那一处。
「能跑通」看不出这个问题（程序照样成功退出），只有把**识别数**与**清单数**
摆在一起对，才发现管道里悄悄丢东西。

本模块的断言分三层：

1. **逐份守恒** —— 每份材料：``len(registry.analyze(text)) == len(outcome.entries)``；
2. **总量守恒** —— 全部材料的识别数之和 == 清单条目数之和；
3. **无截断** —— 没有一份材料的条目数被截成 0，且条目数随语料规模成正比
   （两半语料的「每份条目数」落在同一量级 —— 有一批被截了，这个比值会塌）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_SCRIPTS = _ROOT / "scripts"
for _extra in (str(_SRC), str(_SCRIPTS)):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

import bench_scale  # noqa: E402
from research_redact.audit.residual import ResidualChecker  # noqa: E402
from research_redact.config import PSEUDONYM_HMAC_KEY_ENV  # noqa: E402
from research_redact.policy.conflicts import load_conflict_rules  # noqa: E402
from research_redact.policy.operators import default_operator_registry  # noqa: E402
from research_redact.policy.table import load_policy_table  # noqa: E402
from research_redact.recognizers.assembly import build_default_registry  # noqa: E402
from research_redact.recognizers.patient_index import (  # noqa: E402
    load_patient_index_binding,
)

#: 小规模批次跑多少份材料 —— 够验证守恒，又不至于让单测变慢。
SMALL_LIMIT = 12


@pytest.fixture(scope="module", autouse=True)
def _pseudonym_key():
    """基准跑用密钥（**不是生产密钥**）：一致代号动作在执行时才取密钥。

    跑完恢复原值 —— 不把环境变量留在调用方的进程里。
    """
    previous = os.environ.get(PSEUDONYM_HMAC_KEY_ENV)
    os.environ[PSEUDONYM_HMAC_KEY_ENV] = bench_scale.BENCHMARK_ONLY_KEY
    yield
    if previous is None:
        os.environ.pop(PSEUDONYM_HMAC_KEY_ENV, None)
    else:
        os.environ[PSEUDONYM_HMAC_KEY_ENV] = previous


@pytest.fixture(scope="module")
def small_corpus(tmp_path_factory):
    """一小批语料（复用出廠语料目录，不重复生成）。"""
    corpus_dir = _ROOT / "var" / "corpus"
    if not (corpus_dir / "manifest.jsonl").is_file():
        bench_scale.ensure_corpus(corpus_dir, seed=bench_scale.DEFAULT_SEED, limit=500)
    batches = bench_scale.load_corpus(corpus_dir)
    assert batches, "语料为空"
    return batches


@pytest.fixture(scope="module")
def policy_bundle():
    """策略表 / 冲突规则 / 动作注册表（与产品主路径同一套）。"""
    table = load_policy_table(profile=bench_scale.PSEUDONYM_PROFILE)
    return table, load_conflict_rules(), default_operator_registry()


def _run_small_batch(batches, policy_bundle, limit=SMALL_LIMIT):
    """跑一小批材料，返回 ``(样本列表, 识别总数, 清单总数)``。"""
    table, rules, operators = policy_bundle
    samples, recognize_s, redact_s, residual_s, blocking = bench_scale._measure_pass(
        batches,
        limit=limit,
        table=table,
        rules=rules,
        operators=operators,
        shape=bench_scale.pseudonym_pattern(table.pseudonymization),
        key=bench_scale.BENCHMARK_ONLY_KEY,
    )
    return samples, recognize_s, redact_s, residual_s, blocking


# --------------------------------------------------------------------- 守恒


def test_逐份识别条目数等于清单条目数(small_corpus, policy_bundle):
    """逐份材料：识别产出的命中数 == 写进命中清单的条目数。"""
    samples, *_ = _run_small_batch(small_corpus, policy_bundle)
    assert samples, "小批语料没跑出样本"
    for sample in samples:
        assert sample.spans == sample.entries, (
            f"{sample.material_id} 条目数不守恒：识别 {sample.spans} 处，"
            f"清单 {sample.entries} 条"
        )


def test_总量识别条目数等于清单条目数(small_corpus, policy_bundle):
    """全部材料合计：识别数 == 清单数。"""
    samples, *_ = _run_small_batch(small_corpus, policy_bundle)
    span_total = sum(sample.spans for sample in samples)
    entry_total = sum(sample.entries for sample in samples)
    assert span_total == entry_total
    assert span_total > 0, "小批语料一处命中都没有 —— 语料或识别层出了问题"


def test_没有材料被截成零条目(small_corpus, policy_bundle):
    """无截断：每份材料都产出条目。"""
    samples, *_ = _run_small_batch(small_corpus, policy_bundle)
    empty = [sample.material_id for sample in samples if sample.entries == 0]
    assert not empty, f"这些材料的条目被截成了 0 条：{empty}"


def test_条目数随语料规模成正比(small_corpus, policy_bundle):
    """条目数与语料规模成正比（两批语料的每份条目数落在同一量级）。

    口径：取**两张不同的申请单**（名单不同 → 装配不同），各取 6 份材料，
    算「每份材料平均条目数」，两个比值必须落在 0.5–2.0 之间。若某一批材料
    被截断，某一侧的均值会塌到接近 0，比值立刻越界。
    """
    table, rules, operators = policy_bundle
    half = SMALL_LIMIT // 2

    def run_batch(index: int):
        batch = small_corpus[index]
        trimmed = replace(batch, materials=batch.materials[:half])
        samples, *_ = bench_scale._measure_pass(
            [trimmed],
            limit=None,
            table=table,
            rules=rules,
            operators=operators,
            shape=bench_scale.pseudonym_pattern(table.pseudonymization),
            key=bench_scale.BENCHMARK_ONLY_KEY,
        )
        return samples

    first = run_batch(0)
    second = run_batch(1)
    assert first and second, "两批语料有一批是空的"
    assert len(first) == half and len(second) == half

    first_mean = sum(s.entries for s in first) / len(first)
    second_mean = sum(s.entries for s in second) / len(second)
    assert second_mean > 0
    ratio = first_mean / second_mean
    assert 0.5 <= ratio <= 2.0, (
        f"两批语料的每份条目数不在同一量级：前者 {first_mean:.2f}、"
        f"后者 {second_mean:.2f}（比值 {ratio:.2f}）—— 有一批可能被截断了"
    )


def test_识别层与清单层用的是同一套识别器(small_corpus, policy_bundle):
    """清单条目来自识别层的同一批命中，不是另一条路径凑出来的。"""
    table, rules, operators = policy_bundle
    batch = small_corpus[0]
    binding = load_patient_index_binding(
        batch.records, declared_patient_ids=batch.declared_patient_ids
    )
    registry = build_default_registry(binding, table)
    material = batch.materials[0]

    spans = registry.analyze(material.text)
    from research_redact.daemon.pipeline import redact_text

    outcome = redact_text(
        material.text,
        material.material_id,
        registry=registry,
        actions=table.action_for,
        operators=operators,
        rules=rules,
    )
    assert len(outcome.entries) == len(spans)
    # 清单条目逐条对得上识别命中（位置 + 类别），不是碰巧数量相等
    span_keys = {(span.start, span.end, span.label) for span in spans}
    entry_keys = {(entry.start, entry.end, entry.label) for entry in outcome.entries}
    assert entry_keys == span_keys


# --------------------------------------------------------------------- 基准脚本


def test_基准脚本跑小规模并写得出报告(tmp_path):
    """基准脚本自身可跑：跑一小批 → 写报告 → 报告里带实测数字。"""
    report_path = tmp_path / "performance.md"
    json_path = tmp_path / "performance.json"
    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS / "bench_scale.py"),
            "--limit",
            "8",
            "--out",
            str(report_path),
            "--json-out",
            str(json_path),
            "--no-tracemalloc",
        ],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert report_path.is_file() and json_path.is_file()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["material_count"] == 8
    assert payload["conserved"] is True
    assert payload["every_material_hit"] is True
    assert payload["within_threshold"] is True
    assert payload["headline_s"] >= 0

    report = report_path.read_text(encoding="utf-8")
    assert "规模与性能基准" in report
    assert "条目数守恒" in report
    # 阈值必须写在报告里 —— 数字离开阈值就没有意义
    assert "120" in report


def test_基准超阈值不静默通过(tmp_path):
    """阈值超了要报错并写明差距，不能悄悄过。"""
    report_path = tmp_path / "performance.md"
    json_path = tmp_path / "performance.json"
    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS / "bench_scale.py"),
            "--limit",
            "8",
            "--threshold-seconds",
            "0.000001",
            "--out",
            str(report_path),
            "--json-out",
            str(json_path),
            "--no-tracemalloc",
        ],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, "超阈值时脚本应当以非 0 退出码收场"
    assert "未通过" in result.stderr

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["within_threshold"] is False
    assert payload["gap_s"] < 0

    report = report_path.read_text(encoding="utf-8")
    assert "未通过" in report
    assert "超出阈值" in report


def test_基准计量口径与脚本常量一致():
    """验收阈值与体量区间写在脚本里，不是散在报告里。"""
    assert bench_scale.DEFAULT_THRESHOLD_SECONDS == 120.0
    assert bench_scale.ACCEPTED_MIN_BYTES == 1024
    assert bench_scale.ACCEPTED_MAX_BYTES == 20 * 1024
    assert bench_scale.DEFAULT_LIMIT == 500


def test_分位数口径():
    """分位数用最近秩法：P50 / P95 / 最大值都对得上人工构造的样本。"""
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert bench_scale.percentile(values, 0.50) == 5.0
    assert bench_scale.percentile(values, 0.95) == 10.0
    assert bench_scale.percentile(values, 0.99) == 10.0
    assert bench_scale.percentile([], 0.5) == 0.0
    assert bench_scale.statistics_median([1, 2, 3]) == 2.0
    assert bench_scale.statistics_median([1, 2, 3, 4]) == 2.5
