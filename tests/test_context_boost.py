"""邻近窗口上下文加分验收：窗口内升档 / 窗口外不动 / 相似度为 0 不动 / 封顶不越门槛。

对应源产品 ``analyzer_engine.py::_enhance_using_context``（:299-358）配
``LemmaContextAwareEnhancer``：源靠 spaCy lemma 找上下文词，本轮没有语言模型，
改用**字符 n-gram 邻近窗口**打分。

task 20 深化相似度定义：**Dice 系数 + 局部最佳对齐**（词在窗口里按 n-gram 锚点
对齐到各处，逐段算 Dice 取最大），并把相似度数值写进命中解释，供人工抽检。
"""

from __future__ import annotations

import time

import pytest

from research_redact.daemon.pipeline import build_default_registry, redact_text
from research_redact.models import RecognizerResult, SpanTier
from research_redact.recognizers.base import ChecksumRecognizer, PatternRecognizer
from research_redact.recognizers.context_boost import (
    ContextBoostConfig,
    ContextBooster,
    ContextConfigError,
    dice_similarity,
    load_context_config,
    ngram_set,
    term_similarity,
)
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

# 弱信号命中：分数低于门槛，需要靠邻近上下文抬上来
WEAK_SCORE = 0.4
GLOBAL_THRESHOLD = 0.5


def _weak_registry(
    booster: ContextBooster | None = None,
    threshold: float = GLOBAL_THRESHOLD,
    per_recognizer: dict[str, float] | None = None,
) -> RecognizerRegistry:
    """一个只会认出 8 位数字、且分数偏低的注册表。"""
    return RecognizerRegistry(
        [PatternRecognizer("weak", "弱信号识别器", {"VISIT_NO": r"(?<!\d)\d{8}(?!\d)"}, base_score=WEAK_SCORE)],
        RegistryConfig(
            global_threshold=threshold, per_recognizer_thresholds=per_recognizer or {}
        ),
        booster=booster,
    )


def _booster(**kwargs) -> ContextBooster:
    """上下文加分器：默认词表「住院号」，窗口半径 24。"""
    params = {
        "window_radius": 24,
        "ngram_sizes": (2, 3),
        "base_weight": 0.2,
        "max_boost": 0.2,
        "terms": ("住院号",),
    }
    params.update(kwargs)
    return ContextBooster(ContextBoostConfig(**params))


# ------------------------------------------------------- 窗口内低分命中被升档


def test_low_score_hit_inside_window_is_promoted():
    """邻近窗口内出现上下文词：低分命中被抬到门槛，成为确认档。"""
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze("住院号 12345678")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.CONFIRMED
    assert spans[0].score == pytest.approx(GLOBAL_THRESHOLD)
    assert "上下文词" in spans[0].reason
    assert "住院号" in spans[0].reason


def test_promoted_hit_reason_states_the_context_word():
    """升档后解释里写明是哪个上下文词抬上来的，供人工抽检。"""
    registry = _weak_registry(booster=_booster(terms=("住院号", "门诊号")))
    spans = registry.analyze("门诊号 12345678")
    assert spans[0].tier is SpanTier.CONFIRMED
    assert "门诊号" in spans[0].reason


# ------------------------------------------------------------ 窗口外一律不加分


def test_hit_outside_window_is_not_boosted():
    """上下文词在窗口之外：分数一字不动，仍是告警档。"""
    filler = "填" * 60
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze(f"住院号 {filler} 12345678")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert spans[0].score == pytest.approx(WEAK_SCORE)
    assert "上下文词" not in spans[0].reason


def test_window_radius_decides_whether_the_word_counts():
    """窗口半径可配：同一个文本，半径够大才加分。"""
    filler = "填" * 20
    text = f"住院号 {filler} 12345678"
    narrow = _weak_registry(booster=_booster(window_radius=8)).analyze(text)
    wide = _weak_registry(booster=_booster(window_radius=40)).analyze(text)
    assert narrow[0].tier is SpanTier.WARNING
    assert wide[0].tier is SpanTier.CONFIRMED


# ------------------------------------------------------------- 相似度为 0 不动


def test_zero_similarity_leaves_score_unchanged():
    """窗口里没有任何上下文词：相似度为 0，分数不变。"""
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze("编号 12345678")
    assert spans[0].score == pytest.approx(WEAK_SCORE)
    assert spans[0].tier is SpanTier.WARNING


def test_similarity_is_zero_when_term_absent():
    """相似度函数：词不在窗口里时为 0，完整出现时为 1。"""
    assert term_similarity("住院号 12345678", "住院号", (2, 3)) == pytest.approx(1.0)
    assert term_similarity("右肺下叶磨玻璃结节", "住院号", (2, 3)) == pytest.approx(0.0)


def test_ngram_set_splits_by_configured_sizes():
    """n-gram 集合按配置的长度切；过短的词切不出 n-gram。"""
    assert ngram_set("住院号", (2, 3)) == {"住院", "院号", "住院号"}
    assert ngram_set("住", (2, 3)) == set()


# ------------------------------------------------------------- 加分封顶不越门槛


def test_boost_never_exceeds_threshold():
    """加分封顶在门槛上：分数不会越过生效阈值。"""
    registry = _weak_registry(booster=_booster(base_weight=0.9, max_boost=0.9))
    spans = registry.analyze("住院号 12345678")
    assert spans[0].score == pytest.approx(GLOBAL_THRESHOLD)
    assert spans[0].score <= GLOBAL_THRESHOLD


def test_boost_does_not_jump_stricter_per_recognizer_threshold():
    """逐识别器阈值更严时：加分封顶在那个门槛上，绝不越过它。"""
    registry = _weak_registry(
        booster=_booster(base_weight=0.9, max_boost=0.9),
        threshold=GLOBAL_THRESHOLD,
        per_recognizer={"weak": 0.8},
    )
    spans = registry.analyze("住院号 12345678")
    # 抬到 0.8 即止：没有越过更严的逐识别器阈值（不是 0.9，也不是 1.0）
    assert spans[0].score == pytest.approx(0.8)
    assert spans[0].tier is SpanTier.CONFIRMED


def test_small_boost_does_not_reach_stricter_threshold():
    """加分不够时够不到更严的门槛：仍然是告警档，不靠上下文蒙混过关。"""
    registry = _weak_registry(
        booster=_booster(base_weight=0.2, max_boost=0.2),
        threshold=GLOBAL_THRESHOLD,
        per_recognizer={"weak": 0.8},
    )
    spans = registry.analyze("住院号 12345678")
    assert spans[0].score == pytest.approx(0.6)
    assert spans[0].tier is SpanTier.WARNING


def test_confirmed_hit_is_not_boosted():
    """已达门槛的命中不再加分：分数不会被推高，也不会被压回门槛。"""
    registry = RecognizerRegistry(
        [PatternRecognizer("strong", "强信号识别器", {"VISIT_NO": r"(?<!\d)\d{8}(?!\d)"}, base_score=0.9)],
        RegistryConfig(global_threshold=GLOBAL_THRESHOLD),
        booster=_booster(),
    )
    spans = registry.analyze("住院号 12345678")
    assert spans[0].score == pytest.approx(0.9)
    assert spans[0].tier is SpanTier.CONFIRMED


# ------------------------------------------------- 已判定不通过的不得被复活


def test_failed_checksum_is_not_revived_by_context():
    """校验位不通过的候选不是「证据不足」：邻近上下文不得把它抬成身份类。"""
    registry = RecognizerRegistry(
        [
            ChecksumRecognizer(
                "id_card",
                "身份证识别器",
                r"\d{17}[\dX]",
                "ID_CARD",
                validator=lambda value: False,
                base_score=0.9,
                invalid_score=0.2,
            )
        ],
        RegistryConfig(global_threshold=GLOBAL_THRESHOLD),
        booster=_booster(terms=("身份证",)),
    )
    spans = registry.analyze("身份证 11010519491231002X")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert spans[0].score == pytest.approx(0.2)


# --------------------------------------------------------- 词表与系数可调


def test_context_config_is_loaded_from_policy_file(tmp_path):
    """词表与加分系数写在策略表里：改 YAML 即可按院区调整。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(
        """
context:
  window_radius: 12
  ngram_sizes: [2, 3]
  base_weight: 0.4
  max_boost: 0.4
  terms: ["住院号", "门诊号"]
""".strip(),
        encoding="utf-8",
    )
    config = load_context_config(policy)
    assert config.window_radius == 12
    assert config.base_weight == pytest.approx(0.4)
    assert config.terms == ("住院号", "门诊号")

    registry = _weak_registry(booster=ContextBooster(config))
    spans = registry.analyze("住院号 12345678")
    assert spans[0].tier is SpanTier.CONFIRMED


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ("thresholds:\n  global: 0.5\n", "缺少 context 段"),
        ("context:\n  window_radius: 24\n  乱写: 1\n", "未知道具键"),
        ("context:\n  base_weight: 1.5\n", "base_weight 越界"),
        ("context:\n  max_boost: 2\n", "max_boost 越界"),
        ("context:\n  window_radius: 0\n", "window_radius 非法"),
        ("context:\n  ngram_sizes: []\n", "ngram_sizes 必须是非空列表"),
        ("context:\n  terms: ['住']\n", "过短词"),
    ],
)
def test_invalid_context_config_raises(tmp_path, section, message):
    """配置非法即报错，不静默取默认值。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(section.strip(), encoding="utf-8")
    with pytest.raises(ContextConfigError, match=message):
        load_context_config(policy)


# ------------------------------------------------------------------ 主路径


def test_default_registry_wires_context_boost_from_policy():
    """默认装配从策略表读上下文词表，主路径上的加分随策略表走。"""
    registry = build_default_registry()
    assert registry.booster is not None
    assert "住院号" in registry.boost_terms


def test_boosted_hit_reaches_the_manifest_without_raw_text():
    """升档后的命中进清单：解释写上下文词，不写命中原文与窗口正文。"""
    registry = _weak_registry(booster=_booster())
    outcome = redact_text("患者 张三 住院号 12345678", "M-上下文", registry=registry)
    assert outcome.entries[0].tier == "confirmed"
    assert "住院号" in outcome.entries[0].reason
    assert "12345678" not in outcome.entries[0].reason
    assert "张三" not in outcome.entries[0].reason


def test_booster_without_terms_does_nothing():
    """词表为空时不加分（配置缺项时的兜底行为：分数不动）。"""
    booster = ContextBooster(ContextBoostConfig(terms=()))
    result = RecognizerResult(
        start=0, end=8, label="VISIT_NO", score=WEAK_SCORE, reason="正则命中"
    )
    assert booster.boost("住院号 12345678", result, GLOBAL_THRESHOLD) is result


# ======================================================================
# task 20：相似度定义（Dice + 局部最佳对齐）、窗口半径与加分上限
# ======================================================================


# ------------------------------------------------- Dice 相似度本身的性质


def test_dice_similarity_is_one_for_identical_sets():
    """两个 n-gram 集合完全相同：Dice = 1.0。"""
    grams = ngram_set("住院号", (2, 3))
    assert dice_similarity(grams, set(grams)) == pytest.approx(1.0)


def test_dice_similarity_is_zero_for_disjoint_sets():
    """没有公共 n-gram：Dice = 0.0（不给 0.5 之类的默认值）。"""
    assert dice_similarity(ngram_set("住院号", (2, 3)), ngram_set("磨玻璃", (2, 3))) == 0.0


def test_dice_similarity_is_zero_when_a_set_is_empty():
    """任一集合为空：没有可比的东西，返回 0.0。"""
    assert dice_similarity(set(), ngram_set("住院号", (2, 3))) == 0.0


def test_dice_similarity_is_symmetric():
    """Dice 对称：左长右短与左短右长结果相同（不偏向长的一方）。"""
    left = ngram_set("住院号", (2, 3))
    right = ngram_set("住院号 12345678 检查项目", (2, 3))
    assert dice_similarity(left, right) == pytest.approx(dice_similarity(right, left))


def test_dice_similarity_grows_with_overlap():
    """公共 n-gram 越多：Dice 越高（0 < 部分 < 1）。"""
    term = ngram_set("住院号", (2, 3))
    partial = ngram_set("住院 号", (2, 3))
    full = ngram_set("住院号", (2, 3))
    low = dice_similarity(term, partial)
    high = dice_similarity(term, full)
    assert 0.0 < low < high == pytest.approx(1.0)


# -------------------------------------------------- 局部最佳对齐 Dice 语义


def test_term_similarity_is_full_when_term_appears_verbatim():
    """词原样出现在窗口里：局部最佳对齐 Dice = 1.0。"""
    assert term_similarity("住院号 12345678", "住院号", (2, 3)) == pytest.approx(1.0)


def test_term_similarity_degrades_when_term_is_broken():
    """词被打断（中间插了空格）：相似度下降但不为 0（按公共 n-gram 比例给分）。"""
    score = term_similarity("住院 号 12345678", "住院号", (2, 3))
    assert 0.0 < score < 1.0


def test_term_similarity_is_zero_when_term_absent():
    """词完全不在窗口里：相似度为 0.0。"""
    assert term_similarity("右肺下叶磨玻璃结节", "住院号", (2, 3)) == 0.0


def test_term_similarity_is_not_diluted_by_long_window():
    """整窗直接算 Dice 会把原样出现的词稀释掉；局部对齐不会。

    这是选「局部最佳对齐」的理由：同一份材料换个窗口半径，结论不能变。
    """
    short = term_similarity("住院号 12345678", "住院号", (2, 3))
    long = term_similarity("住院号 " + "填" * 200 + " 12345678", "住院号", (2, 3))
    assert short == pytest.approx(1.0)
    assert long == pytest.approx(short)


def test_ngram_sizes_are_configurable():
    """n-gram 长度可配：只取 2-gram 与取 2+3-gram 的对齐结果不同。"""
    term = "住院号"
    only_bigram = term_similarity("住院 号 12345678", term, (2,))
    both = term_similarity("住院 号 12345678", term, (2, 3))
    assert only_bigram != both


def test_window_radius_is_configurable():
    """窗口半径可配：同一个文本，半径够大才把上下文词算进窗口。"""
    text = "住院号 " + "填" * 20 + " 12345678"
    number_start = text.index("12345678")
    narrow = _booster(window_radius=8).window_for(
        text, number_start, number_start + 8
    )
    wide = _booster(window_radius=40).window_for(
        text, number_start, number_start + 8
    )
    assert "住院号" not in narrow
    assert "住院号" in wide


# ------------------------------------------------------- 解释可读（人工抽检）


def test_explanation_states_the_similarity_value():
    """命中解释写明相似度数值：人工抽检时能看出这条命中被抬了多少依据。"""
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze("住院号 12345678")
    assert "相似度 1.00" in spans[0].reason


def test_explanation_states_a_partial_similarity_value():
    """部分对齐时解释里的相似度不是满分（能看出依据不强）。"""
    booster = _booster(terms=("住院号",))
    result = RecognizerResult(
        start=5, end=13, label="VISIT_NO", score=WEAK_SCORE, reason="正则命中"
    )
    boosted = booster.boost("住院 号 12345678", result, GLOBAL_THRESHOLD)
    assert "相似度" in boosted.reason
    assert "相似度 1.00" not in boosted.reason


def test_boost_metadata_records_the_algorithm():
    """加分元数据写明算法与参数：出问题时能看出这条加分是怎么算的。"""
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze("住院号 12345678")
    boost_meta = spans[0].metadata["context_boost"]
    assert boost_meta["method"] == "dice_local_alignment"
    assert boost_meta["term"] == "住院号"
    assert boost_meta["similarity"] == pytest.approx(1.0)
    assert boost_meta["ngram_sizes"] == [2, 3]
    assert boost_meta["window_radius"] == 24


# --------------------------------------------------- 加分只升档，不改类别


def test_boost_keeps_the_entity_label():
    """上下文词只补充证据，不改写识别器的判定：实体类别原样保留。"""
    registry = _weak_registry(booster=_booster())
    spans = registry.analyze("住院号 12345678")
    assert spans[0].label == "VISIT_NO"
    assert spans[0].tier is SpanTier.CONFIRMED


def test_boost_only_raises_the_tier():
    """加分只升档：告警档 → 确认档，不会把确认档再抬高。"""
    booster = _booster()
    weak = RecognizerResult(
        start=4, end=12, label="VISIT_NO", score=WEAK_SCORE, reason="正则命中"
    )
    strong = RecognizerResult(
        start=4, end=12, label="VISIT_NO", score=0.9, reason="正则命中"
    )
    promoted = booster.boost("住院号 12345678", weak, GLOBAL_THRESHOLD)
    assert promoted.score == pytest.approx(GLOBAL_THRESHOLD)
    assert promoted.score >= weak.score
    unchanged = booster.boost("住院号 12345678", strong, GLOBAL_THRESHOLD)
    assert unchanged is strong


# ------------------------------------------------------------ 性能不失控


def test_boosting_a_batch_is_fast_enough_for_the_daemon():
    """加分是主路径上的常驻开销：500 条命中的加分不得成为瓶颈。"""
    booster = _booster(terms=("患者", "姓名", "住院号", "门诊号", "检查号"))
    unit = "患者姓名 张某某，住院号 90000001，门诊号 MZ123456，检查号 CHK0000001。"
    text = unit * 500
    results = [
        RecognizerResult(
            start=index * len(unit) + 13,
            end=index * len(unit) + 21,
            label="VISIT_NO",
            score=WEAK_SCORE,
            reason="正则命中",
        )
        for index in range(500)
    ]
    started = time.perf_counter()
    booster.boost_all(text, results, lambda result: GLOBAL_THRESHOLD)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"500 条命中加分耗时 {elapsed:.2f}s，超出守护进程预算"
