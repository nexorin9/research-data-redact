"""白名单机制与误伤回归语料库验收。

「脱过头」与「脱不到」两头都是事故：把剂量当住院号抹掉，临床数据就失真了；
把真住院号放过，患者身份就进了交付物。数字类歧义（剂量 / 金额 / 页码 / 床号）
由**识别之前**的消歧层挡掉（见 ``recognizers/numeric_boundary.py``），但**字段
位置上的非身份取值** —— 表单占位、模板默认值、上游系统占位号、检验项目编码 ——
只有白名单能挡：它们长得就像要脱的内容。

本任务验四件事：

1. **白名单放行** —— 命中白名单的区间一律放行：不替换、不计入残留统计，
   并在命中清单中记为「已放行」且附放行原因（**不记命中原文**）；
2. **误伤回归语料** —— ``fixtures/regression/corpus.jsonl`` 里的病名 / 药名 /
   科室名 / 检验项目名与形似编号的干扰项，跑完整主路径后**正文逐字不变**，
   且**身份类命中数为 0**（放行档与告警档都不算身份类）；
3. **白名单不越界** —— 真住院号 / 真检查号 / 真身份证仍必须被脱：
   白名单放行的是「确定不是身份」的取值，放宽了就等于漏脱；
4. **配置非法即报错** —— 白名单段缺段 / 正则编译不过 / 含空值一律报错。

**红线**：放行项的命中原文不得出现在命中清单里。放行档与确认档一样受这条
约束 —— 放行理由写「命中白名单（exact）」，不写被放行的是什么。
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from research_redact.audit.manifest import ManifestWriter, scan_for_raw_text
from research_redact.audit.residual import ResidualChecker, residual_tier
from research_redact.daemon.pipeline import build_default_registry, redact_text
from research_redact.models import SpanTier
from research_redact.policy.table import PolicyTableError, load_policy_table
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REGRESSION_DIR = PROJECT_ROOT / "fixtures" / "regression"
CORPUS_FILE = REGRESSION_DIR / "corpus.jsonl"
CONTROLS_FILE = REGRESSION_DIR / "negative_controls.jsonl"
POLICY_FILE = PROJECT_ROOT / "policy" / "research.yaml"

#: 放行动作在命中清单里的标记（与主路径一致）。
ALLOWED_ACTION = "keep（白名单放行）"

#: 计入「身份类」残留的档位（与残留自检同一套分档）。
IDENTITY_TIERS = ("identity", "encounter", "unclassified")


def _load_corpus(path: Path) -> list[dict]:
    """读回归语料（JSONL：一行一条）。"""
    entries: list[dict] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:  # pragma: no cover - 语料坏了要立刻知道
            raise AssertionError(f"{path.name} 第 {number} 行不是合法 JSON：{exc}") from exc
    return entries


def _identity_hits(outcome) -> list[tuple[str, str]]:
    """产物里被判为身份类的命中（确认档且档位属身份类）。

    放行档与告警档都不算：放行档是「确定不是身份」，告警档是「证据不足，
    不判定为身份」。
    """
    hits: list[tuple[str, str]] = []
    for entry in outcome.entries:
        if entry.tier != SpanTier.CONFIRMED.value:
            continue
        if residual_tier(entry.label) in IDENTITY_TIERS:
            hits.append((entry.label, entry.reason))
    return hits


def _minimal_policy(allow_list_body: str) -> str:
    """拼一份最小可用的策略表（只替换白名单段）。"""
    return (
        "version: 1\n"
        "thresholds:\n"
        "  global: 0.5\n"
        "  per_recognizer: {}\n"
        "entities:\n"
        "  PATIENT_NAME:\n"
        "    action: replace\n"
        '    placeholder: "<患者姓名>"\n'
        "allow_list:\n" + textwrap.indent(textwrap.dedent(allow_list_body).lstrip(), "  ") + "\n"
        "context:\n"
        "  terms:\n"
        "    - 姓名\n"
        "    - 住院号\n"
    )


# --------------------------------------------------------------------- 放行


def test_allow_list_exact_releases_placeholder_names():
    """姓名位置的非人名取值：白名单 exact 放行，正文逐字不变。"""
    registry = build_default_registry()
    for value in ("未登记", "待补", "待填", "本人", "新生儿", "匿名", "已故", "不详", "无名氏", "同上"):
        text = f"姓名：{value}"
        outcome = redact_text(text, "M-1", registry=registry)
        assert outcome.redacted_text == text, f"{value} 不该被改写"
        allowed = [entry for entry in outcome.entries if entry.tier == SpanTier.ALLOWED.value]
        assert len(allowed) == 1, f"{value} 应有且只有一条放行记录"
        assert allowed[0].action == ALLOWED_ACTION
        assert "白名单" in allowed[0].reason and "exact" in allowed[0].reason


def test_allow_list_regex_releases_system_placeholders():
    """系统占位值 / 全零占位号 / 掩码号：白名单 regex 放行。"""
    registry = build_default_registry()
    cases = (
        "住院号：NONE",
        "住院号：NULL",
        "住院号：PENDING",
        "住院号：TODO",
        "住院号：UNKNOWN",
        "检查号：NULL",
        "住院号：0000000",
        "门诊号：MZ000000",
        "住院号：XXXXXXX",
    )
    for text in cases:
        outcome = redact_text(text, "M-1", registry=registry)
        assert outcome.redacted_text == text, f"{text} 不该被改写"
        allowed = [entry for entry in outcome.entries if entry.tier == SpanTier.ALLOWED.value]
        assert len(allowed) == 1, f"{text} 应有且只有一条放行记录"
        assert allowed[0].action == ALLOWED_ACTION
        assert "白名单" in allowed[0].reason and "regex" in allowed[0].reason


def test_allow_list_releases_code_shaped_lab_item_code():
    """形似检查号的检验项目编码：白名单 regex 放行，不被当成检查号改写。"""
    registry = build_default_registry()
    text = "检查项目：血常规；检验项目编码：JC1234567890"
    outcome = redact_text(text, "M-1", registry=registry)
    assert outcome.redacted_text == text
    allowed = [entry for entry in outcome.entries if entry.tier == SpanTier.ALLOWED.value]
    assert len(allowed) == 1
    assert allowed[0].label == "EXAM_NO"
    assert "白名单" in allowed[0].reason


# ------------------------------------------------------------- 误伤回归语料


def test_regression_corpus_is_never_rewritten():
    """回归语料跑完整主路径：正文逐字不变，身份类命中数为 0。"""
    registry = build_default_registry()
    corpus = _load_corpus(CORPUS_FILE)
    failures: list[str] = []
    for entry in corpus:
        text = entry["text"]
        outcome = redact_text(text, entry["id"], registry=registry)
        if outcome.redacted_text != text:
            failures.append(f"{entry['id']}（{entry['category']}）被改写为 {outcome.redacted_text!r}")
        hits = _identity_hits(outcome)
        if hits:
            failures.append(f"{entry['id']}（{entry['category']}）出现身份类命中：{hits}")
    assert not failures, "误伤回归语料出问题：\n" + "\n".join(failures)


def test_regression_corpus_size_and_categories():
    """语料规模与类别覆盖：≥40 条，四类临床词与干扰项都要有。"""
    corpus = _load_corpus(CORPUS_FILE)
    assert len(corpus) >= 40, f"回归语料只有 {len(corpus)} 条，应 ≥40 条"
    categories: dict[str, int] = {}
    for entry in corpus:
        categories[entry["category"]] = categories.get(entry["category"], 0) + 1
    for name in ("病名", "药名", "科室名", "检验项目名", "干扰项"):
        assert categories.get(name, 0) >= 5, f"类别「{name}」只有 {categories.get(name, 0)} 条"
    ids = [entry["id"] for entry in corpus]
    assert len(set(ids)) == len(ids), "语料条目 ID 有重复"


def test_regression_corpus_covers_code_shaped_distractors():
    """语料里必须有形似身份证 / 住院号的干扰项，且它们不是身份类命中。"""
    registry = build_default_registry()
    corpus = _load_corpus(CORPUS_FILE)
    distractors = [entry for entry in corpus if entry["category"] == "干扰项"]
    assert len(distractors) >= 5
    code_shaped = 0
    for entry in distractors:
        outcome = redact_text(entry["text"], entry["id"], registry=registry)
        assert outcome.redacted_text == entry["text"]
        assert not _identity_hits(outcome), f"{entry['id']} 出现身份类命中"
        if any(
            span.tier in (SpanTier.ALLOWED.value, SpanTier.WARNING.value)
            for span in outcome.entries
        ):
            code_shaped += 1
    assert code_shaped >= 5, "形似编号的干扰项覆盖不足"


# ------------------------------------------------------- 放行记录的可见性


def test_allowed_records_are_visible_in_manifest_without_raw_text(tmp_path):
    """放行记录进命中清单：档位 / 动作 / 放行原因可见，且不含命中原文。"""
    registry = build_default_registry()
    text = "姓名：未登记；住院号：NONE；住院号：90000001"
    outcome = redact_text(text, "M-1", registry=registry)

    manifest_path = tmp_path / "manifest.jsonl"
    written = ManifestWriter(manifest_path).write(outcome.entries)
    assert written == len(outcome.entries)
    payload = manifest_path.read_text(encoding="utf-8")
    records = ManifestWriter.read(manifest_path)

    allowed = [record for record in records if record["tier"] == SpanTier.ALLOWED.value]
    assert len(allowed) == 2
    for record in allowed:
        assert record["action"] == ALLOWED_ACTION
        assert "白名单" in record["reason"]
    confirmed = [record for record in records if record["tier"] == SpanTier.CONFIRMED.value]
    assert len(confirmed) == 1 and confirmed[0]["label"] == "VISIT_NO"

    # 红线：放行项的命中原文不得出现在清单里（确认档由主路径的守卫把关，
    # 放行档在这里单独验）
    released_raw = ("未登记", "NONE")
    assert not scan_for_raw_text(payload, released_raw)


def test_allowed_items_are_not_counted_as_residual():
    """放行项不计入残留统计：放行了就不该再拦这批。

    两层都拦得住：**识别层**按白名单放行（不留命中），**残留自检**自己也认
    一遍白名单（task 28 起）—— 二次扫描是「换个角度看同一份产物」，不能
    指望识别层已经放过。抑制留痕可查：``suppressed["allow_list"]`` 有几处。
    """
    registry = build_default_registry()
    checker = ResidualChecker(registry=registry)
    text = "姓名：未登记 住院号：NONE"
    report = checker.check_batch("B-1", {"M-1": text})
    assert report.identity_count == 0
    assert report.deliverable is True
    assert report.suppressed.get("allow_list") == 2

    # 对照：识别层与残留层**都不**认白名单时，同样内容会被判成残留 ——
    # 说明拦住它的是白名单，不是「这条压根不产生命中」。
    stripped = RecognizerRegistry(
        registry.get_recognizers(),
        RegistryConfig(
            global_threshold=registry.config.global_threshold,
            per_recognizer_thresholds=dict(registry.config.per_recognizer_thresholds),
        ),
        booster=registry.booster,
    )
    bare = ResidualChecker(registry=stripped, allow_list=(frozenset(), ()))
    bare_report = bare.check_batch("B-1", {"M-1": text})
    assert bare_report.identity_count == 2
    assert bare_report.deliverable is False


# ------------------------------------------------------------ 白名单不越界


def test_allow_list_does_not_release_real_identifiers():
    """白名单不得放宽到把真身份一起放过。"""
    registry = build_default_registry()
    for entry in _load_corpus(CONTROLS_FILE):
        text = entry["text"]
        outcome = redact_text(text, entry["id"], registry=registry)
        assert outcome.redacted_text != text, f"{entry['id']} 被白名单放过了：{text}"
        labels = [item.label for item in outcome.entries if item.tier == SpanTier.CONFIRMED.value]
        assert entry["expect_label"] in labels, f"{entry['id']} 未命中 {entry['expect_label']}"


def test_project_policy_keeps_a_non_empty_allow_list():
    """本院策略表的白名单不得被清空 —— 清空等于误伤防线消失。"""
    table = load_policy_table(POLICY_FILE)
    assert table.allow_list_exact, "策略表 allow_list.exact 为空"
    assert table.allow_list_regex, "策略表 allow_list.regex 为空"
    assert "未登记" in table.allow_list_exact


# ------------------------------------------------------------ 配置校验


def test_allow_list_section_missing_raises(tmp_path):
    """缺白名单段即报错 —— 缺段不等于「本院没有这类取值」。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            version: 1
            thresholds:
              global: 0.5
              per_recognizer: {}
            entities:
              PATIENT_NAME:
                action: replace
                placeholder: "<患者姓名>"
            context:
              terms:
                - 姓名
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "allow_list" in str(excinfo.value)


def test_allow_list_invalid_regex_raises(tmp_path):
    """白名单正则编译不过即报错，并指出出错项。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(
        _minimal_policy(
            """
            exact: []
            regex:
              - "^(?:NONE|NULL"
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "allow_list.regex" in str(excinfo.value)


def test_allow_list_empty_value_raises(tmp_path):
    """白名单里出现空值即报错 —— 空串会把「所有空命中」都放行。"""
    policy = tmp_path / "research.yaml"
    policy.write_text(
        _minimal_policy(
            """
            exact:
              - "  "
            regex: []
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "allow_list.exact" in str(excinfo.value)
