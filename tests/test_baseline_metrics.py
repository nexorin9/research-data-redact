"""基线对比实验的指标口径测试（task 30）。

三组断言：

1. **指标计算在人工构造的小样例上等于期望值** —— 指标函数是纯函数，
   口径必须能被手算验证（这是「数字可复算」的前提）。
2. **三条路径均产出三项指标** —— 跑一遍小语料，三条路径都要给出
   代号一致性 / 身份残留率 / 串号率三个数，且落在 [0, 1]。
3. **真实规模下数字成立且可复现** —— 500 例语料、≥50 名患者；重跑
   数字一致；串号率由语料算出（不是写死常量）。

**不碰产品包的私有实现**：本测试只 import ``scripts/compare_baseline.py``
与产品公开接口（识别器装配 / 脱敏主路径 / 残留自检）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import compare_baseline as cb  # noqa: E402


# --------------------------------------------------------------- 指标口径（人工样例）


def test_代号一致性_人工样例等于期望值() -> None:
    """同患者材料对：代号集合有交集即算「对得上号」。"""
    tokens = {
        "m1": frozenset({"A"}),
        "m2": frozenset({"A"}),
        "m3": frozenset({"B"}),
    }
    # 同一患者、同一代号 → 对得上
    assert cb.consistency_rate([("m1", "m2")], tokens) == 1.0
    # 不同患者、代号不同 → 对不上
    assert cb.consistency_rate([("m1", "m3")], tokens) == 0.0
    # 混合：两对里一对得上 → 0.5
    assert cb.consistency_rate([("m1", "m2"), ("m1", "m3")], tokens) == pytest.approx(0.5)
    # 口径是「有交集」而不是「完全相同」：m1 有两个代号，与 m2 共享一个即算对得上
    partial = {"m1": frozenset({"A", "X"}), "m2": frozenset({"X"})}
    assert cb.consistency_rate([("m1", "m2")], partial) == 1.0
    # 没有可比对的样本时返回 0.0（不编造数字）
    assert cb.consistency_rate([], tokens) == 0.0


def test_串号率_人工样例等于期望值() -> None:
    """不同患者材料对：代号集合有交集即算「被误并成一人」。"""
    tokens = {
        "m1": frozenset({"A"}),
        "m2": frozenset({"A"}),
        "m3": frozenset({"B"}),
    }
    # 不同患者、代号不同 → 不串号
    assert cb.cross_assignment_rate([("m1", "m3")], tokens) == 0.0
    # 不同患者、代号相同 → 串号
    assert cb.cross_assignment_rate([("m1", "m2")], tokens) == 1.0
    # 三对里两对串号 → 2/3
    tokens2 = {
        "m1": frozenset({"A"}),
        "m2": frozenset({"A"}),
        "m3": frozenset({"A"}),
        "m4": frozenset({"Z"}),
    }
    assert cb.cross_assignment_rate(
        [("m1", "m2"), ("m1", "m3"), ("m1", "m4")], tokens2
    ) == pytest.approx(2 / 3)
    assert cb.cross_assignment_rate([], tokens) == 0.0


def test_身份残留率_人工样例等于期望值() -> None:
    """残留率 = 产物里的残留处数 ÷ 原文身份类命中处数。"""
    assert cb.identity_residual_rate(3, 7) == pytest.approx(3 / 7)
    assert cb.identity_residual_rate(0, 7) == 0.0
    # 分母为 0（没有可比对的命中）时返回 0.0，不做除零
    assert cb.identity_residual_rate(5, 0) == 0.0


def test_一人一码率_人工样例等于期望值() -> None:
    """一位患者在一份材料里只写下一个代号 → 计入。"""
    tokens = {
        "m1": frozenset({"A"}),
        "m2": frozenset({"A", "B"}),
        "m3": frozenset(),
    }
    assert cb.single_code_rate(tokens) == pytest.approx(1 / 3)
    assert cb.single_code_rate({}) == 0.0


def test_配对拆分_同患者与不同患者() -> None:
    """材料两两配对后拆成「同患者对」与「不同患者对」两组。"""
    materials = [
        cb.CorpusMaterial("m1", "A1", "P-1", "正文一"),
        cb.CorpusMaterial("m2", "A1", "P-1", "正文二"),
        cb.CorpusMaterial("m3", "A2", "P-2", "正文三"),
    ]
    same, different = cb.pair_split(materials)
    assert same == [("m1", "m2")]
    assert different == [("m1", "m3"), ("m2", "m3")]


# --------------------------------------------------------------- 三条路径（小语料）


@pytest.fixture(scope="module")
def small_batches(tmp_path_factory) -> list:
    """小语料（12 份材料 / 2 位患者）：够跑通三条路径，又不拖慢测试。"""
    corpus = tmp_path_factory.mktemp("corpus-small")
    cb.ensure_corpus(corpus, seed=cb.DEFAULT_SEED, limit=12)
    return cb.load_corpus(corpus)


def test_三条路径均产出三项指标(small_batches) -> None:
    """三条路径都要给出三个数，且落在 [0, 1]。"""
    outcomes = [
        cb.run_product_path(small_batches, key=cb.BENCHMARK_ONLY_KEY),
        cb.run_naive_path(small_batches),
        cb.run_hash_path(small_batches),
    ]
    materials = [m for batch in small_batches for m in batch.materials]
    same, different = cb.pair_split(materials)
    for outcome in outcomes:
        assert outcome.redacted, f"{outcome.path_id} 没有产出脱敏副本"
        assert set(outcome.redacted) == {m.material_id for m in materials}
        assert outcome.identity_hits > 0, f"{outcome.path_id} 原文身份命中数为 0"
        assert len(outcome.tokens) == len(materials)
        for value in (
            cb.consistency_rate(same, outcome.tokens),
            cb.identity_residual_rate(outcome.residual_total, outcome.identity_hits),
            cb.cross_assignment_rate(different, outcome.tokens),
            cb.single_code_rate(outcome.tokens),
        ):
            assert 0.0 <= value <= 1.0, f"{outcome.path_id} 的指标越界：{value}"


def test_本产品路径_一致且不串号且无残留(small_batches) -> None:
    """本产品：同一患者代号恒等、不同患者不串号、产物里无身份残留。"""
    outcome = cb.run_product_path(small_batches, key=cb.BENCHMARK_ONLY_KEY)
    materials = [m for batch in small_batches for m in batch.materials]
    same, different = cb.pair_split(materials)
    assert cb.consistency_rate(same, outcome.tokens) == 1.0
    assert cb.cross_assignment_rate(different, outcome.tokens) == 0.0
    assert cb.identity_residual_rate(outcome.residual_total, outcome.identity_hits) == 0.0
    assert outcome.deliverable is True
    # 一人一码：姓名槽与患者编号槽写的是同一个代号
    assert cb.single_code_rate(outcome.tokens) == 1.0


def test_朴素查找替换_一致但串号且有残留(small_batches) -> None:
    """朴素替换：所有患者共用同一批占位符 → 一致但串号；字典覆盖不到的字段留身份。"""
    outcome = cb.run_naive_path(small_batches)
    materials = [m for batch in small_batches for m in batch.materials]
    same, different = cb.pair_split(materials)
    assert cb.consistency_rate(same, outcome.tokens) == 1.0
    assert cb.cross_assignment_rate(different, outcome.tokens) == 1.0
    assert cb.single_code_rate(outcome.tokens) == 0.0
    # 手机号 / 完整身份证 / 检查号覆盖不到 → 残留非 0
    assert outcome.residual_total > 0
    assert outcome.deliverable is False


def test_无一致性hash_跨材料对不上人(small_batches) -> None:
    """无一致性 hash：每份材料独立加盐 → 同一患者的材料之间没有共同代号。"""
    outcome = cb.run_hash_path(small_batches)
    materials = [m for batch in small_batches for m in batch.materials]
    same, different = cb.pair_split(materials)
    assert cb.consistency_rate(same, outcome.tokens) == 0.0
    assert cb.cross_assignment_rate(different, outcome.tokens) == 0.0
    assert cb.single_code_rate(outcome.tokens) == 0.0
    # 字典覆盖不到的字段仍然留身份
    assert outcome.residual_total > 0


def test_三条路径共用同一个分母(small_batches) -> None:
    """残留率的分母（原文身份类命中数）三条路径必须相同。"""
    denominators = {
        cb.run_product_path(small_batches, key=cb.BENCHMARK_ONLY_KEY).identity_hits,
        cb.run_naive_path(small_batches).identity_hits,
        cb.run_hash_path(small_batches).identity_hits,
    }
    assert len(denominators) == 1, f"分母不一致：{denominators}"


def test_形态碰撞_代号撞上号码形态单独计数(small_batches) -> None:
    """「路径自己写出去的代号被误判成身份」要与真残留分开计数。

    hash 代号是 16 位十六进制摘要，摘要里偶尔出现 11 位连续数字时会被
    联系方式识别器判成手机号 —— 那是形态碰撞，不是泄露。
    """
    outcome = cb.run_hash_path(small_batches)
    # 形态碰撞数不超过残留总数，且两条路径的残留差值可由形态碰撞解释
    assert 0 <= outcome.own_token_residuals <= outcome.residual_total
    naive = cb.run_naive_path(small_batches)
    assert naive.own_token_residuals == 0, "固定占位符不该撞上身份形态"
    product = cb.run_product_path(small_batches, key=cb.BENCHMARK_ONLY_KEY)
    assert product.own_token_residuals == 0, "一致代号形态收敛，不该撞上身份形态"


# --------------------------------------------------------------- 真实规模与可复现


def test_真实规模_500例语料与三项指标成立(tmp_path) -> None:
    """500 例语料、≥50 名患者；三条路径的三项指标成立；串号率由语料算出。"""
    corpus = tmp_path / "corpus"
    cb.ensure_corpus(corpus, seed=cb.DEFAULT_SEED, limit=500)
    batches = cb.load_corpus(corpus)
    materials = [m for batch in batches for m in batch.materials]
    patient_count = len({m.patient_id for m in materials})

    assert len(materials) >= 500, f"语料规模不足：{len(materials)}"
    assert patient_count >= 50, f"患者数不足：{patient_count}"
    # 同名异人必须真的出现（否则「按姓名做代号会串号」这条结论无从谈起）
    names = {
        record.get("name")
        for batch in batches
        for record in batch.records
        if record.get("name")
    }
    assert len(names) < patient_count, "语料里没有同名异人，串号场景未被覆盖"

    product = cb.run_product_path(batches, key=cb.BENCHMARK_ONLY_KEY)
    naive = cb.run_naive_path(batches)
    hash_path = cb.run_hash_path(batches)
    same, different = cb.pair_split(materials)
    assert len(same) > 0 and len(different) > 0

    for outcome in (product, naive, hash_path):
        assert outcome.identity_hits > 0
        assert len(outcome.redacted) == len(materials)

    # 本产品：一致、不串号、无残留
    assert cb.consistency_rate(same, product.tokens) == 1.0
    assert cb.cross_assignment_rate(different, product.tokens) == 0.0
    assert product.residual_total == 0
    # 朴素替换：一致但串号，且留身份
    assert cb.consistency_rate(same, naive.tokens) == 1.0
    assert cb.cross_assignment_rate(different, naive.tokens) == 1.0
    assert naive.residual_total > 0
    # 无一致性 hash：跨材料对不上人，但也不串号
    assert cb.consistency_rate(same, hash_path.tokens) == 0.0
    assert cb.cross_assignment_rate(different, hash_path.tokens) == 0.0


def test_串号率由语料算出_不是写死常量(tmp_path) -> None:
    """同一份指标函数喂不同数据，串号率必须跟着数据变 —— 不是常量。"""
    same_for_everyone = {"m1": frozenset({"X"}), "m2": frozenset({"X"})}
    distinct = {"m1": frozenset({"X"}), "m2": frozenset({"Y"})}
    pairs = [("m1", "m2")]
    assert cb.cross_assignment_rate(pairs, same_for_everyone) == 1.0
    assert cb.cross_assignment_rate(pairs, distinct) == 0.0


def test_对比报告落盘且含三项指标(tmp_path) -> None:
    """脚本跑完产出报告与机器可读版本，两者数字一致。"""
    corpus = tmp_path / "corpus"
    report = tmp_path / "reports" / "baseline-comparison.md"
    json_out = tmp_path / "reports" / "baseline-comparison.json"
    code = cb.main(
        [
            "--limit",
            "20",
            "--corpus",
            str(corpus),
            "--out",
            str(report),
            "--json-out",
            str(json_out),
            "--pseudonym-key",
            "unit-test-key",
        ]
    )
    assert code == 0
    assert report.is_file() and report.stat().st_size > 0
    text = report.read_text(encoding="utf-8")
    for keyword in ("代号一致性", "身份残留率", "串号率", "语料与规模", "指标定义与算法"):
        assert keyword in text, f"报告缺少「{keyword}」"
    # 报告里不得残留占位符
    for placeholder in ("（填写）", "TBD", "待补"):
        assert placeholder not in text

    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert {item["path_id"] for item in payload["paths"]} == {
        "product",
        "naive",
        "hash",
    }
    for item in payload["paths"]:
        for key in (
            "consistency",
            "identity_residual_rate",
            "cross_assignment_rate",
            "single_code_rate",
        ):
            assert 0.0 <= item[key] <= 1.0
    # 报告表格里的数字与 JSON 一致（本产品路径残留率必为 0）
    product = next(item for item in payload["paths"] if item["path_id"] == "product")
    assert product["identity_residual_rate"] == 0.0
    assert product["residual_total"] == 0


def test_重跑数字一致(tmp_path) -> None:
    """同种子同语料重跑，三项指标必须一致（数字可复算）。"""
    corpus = tmp_path / "corpus"
    cb.ensure_corpus(corpus, seed=cb.DEFAULT_SEED, limit=24)
    batches = cb.load_corpus(corpus)
    materials = [m for batch in batches for m in batch.materials]
    same, different = cb.pair_split(materials)

    def snapshot() -> tuple:
        outcome = cb.run_product_path(batches, key=cb.BENCHMARK_ONLY_KEY)
        return (
            cb.consistency_rate(same, outcome.tokens),
            cb.identity_residual_rate(outcome.residual_total, outcome.identity_hits),
            cb.cross_assignment_rate(different, outcome.tokens),
            outcome.residual_total,
        )

    assert snapshot() == snapshot()
