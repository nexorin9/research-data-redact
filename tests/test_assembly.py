"""识别器注册表配置化装配、启停与逐项阈值覆盖的验收。

对应源产品 ``analyzer_engine_provider.py`` 的 **YAML 装配形态**（保留）：一份
YAML 装下识别器清单、逐识别器阈值、全局阈值与白名单，装配结果交给分析引擎
用。本轮把它落到项目内自有装配器上（不引 spaCy、不引语言模型）。

本任务验四件事：

1. **正常装配** —— 策略表里的识别器清单、逐识别器阈值、全局阈值、白名单、
   上下文词表，装出来就是注册表该有的样子；
2. **启停是真的启停** —— 被关掉的识别器**根本不注册**，一条命中都不产出
   （不是「产出了再过滤掉」）；
3. **逐项阈值覆盖真的生效** —— 覆盖后的门槛决定确认档 / 告警档；
4. **装配非法即报错** —— 未知识别器名 / 阈值越界 / YAML 结构错 / 未知处置
   动作，一律报错并指出出错项，**不静默取默认值**。

最后一条是本任务的安全底线：策略表里「以为关了某识别器、实际还在跑」或
「以为配了逐识别器阈值、实际没生效」，在脱敏产品里等于漏脱。
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from research_redact.daemon.pipeline import redact_text
from research_redact.models import SpanTier
from research_redact.policy.table import (
    CATALOG_NAMES,
    RECOGNIZER_IDS,
    PolicyTableError,
    build_registry,
    load_policy_table,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policy" / "research.yaml"

#: 逐个识别器关掉时，验证「命中数为 0」用的样例。
#: 每一行的正文只会被**该行指定的识别器**命中，关掉它就该归零 ——
#: 写成只带标签的正文会同时命中字段标签识别器，关掉一个另一个还在。
DISABLE_CASES = (
    ("labeled_field", "姓名：张某某", "PATIENT_NAME"),
    ("visit_no", "本次住院流水 90000001", "VISIT_NO"),
    ("phone_birth", "13800138000", "PHONE"),
    ("id_card", "身份证：110101194912310016", "ID_CARD"),
)


# --------------------------------------------------------------------- 夹具


def _base_raw() -> dict[str, Any]:
    """项目策略表的原始内容（作为改配置的底稿）。"""
    return yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))


def _set_path(raw: dict[str, Any], dotted: str, value: Any) -> None:
    """按点号路径改一个嵌套键（如 ``recognizers.visit_no.enabled``）。

    中间层不存在时自动补出来 —— 测「写错了名字」时需要能写出一个不存在的键。
    """
    parts = dotted.split(".")
    node: Any = raw
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _write_policy(tmp_path: Path, raw: dict[str, Any]) -> Path:
    """写一份策略表并返回路径。"""
    target = tmp_path / "research.yaml"
    target.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return target


def _policy_with(tmp_path: Path, **overrides: Any) -> Path:
    """以项目策略表为底稿改几处，写成一份新策略表。"""
    raw = _base_raw()
    for dotted, value in overrides.items():
        _set_path(raw, dotted.replace("__", "."), value)
    return _write_policy(tmp_path, raw)


def _registry(tmp_path: Path, **overrides: Any):
    """按改过的策略表装配一张注册表。"""
    policy = _policy_with(tmp_path, **overrides)
    return build_registry(load_policy_table(policy))


# ------------------------------------------------------------------ 正常装配


def test_策略表装配出识别器清单(tmp_path):
    """策略表里的识别器清单决定注册表里装哪几个识别器。"""
    registry = _registry(tmp_path)
    ids = {recognizer.id for recognizer in registry.get_recognizers()}
    assert ids == {"labeled_field", "visit_no", "phone_birth", "id_card"}, ids


def test_未给名单时名单识别器不装(tmp_path):
    """没给患者主索引名单就不装名单识别器 —— 名字装上也产不出命中。"""
    registry = _registry(tmp_path)
    assert "patient_index" not in {r.id for r in registry.get_recognizers()}


def test_阈值白名单与上下文词表都从策略表进注册表(tmp_path):
    """全局阈值、逐识别器阈值、白名单、上下文词表都按策略表装。"""
    registry = _registry(
        tmp_path,
        thresholds__global=0.4,
        thresholds__per_recognizer={"visit_no": 0.85},
        allow_list__exact=["示例医师"],
        allow_list__regex=["^示例\\d+$"],
    )
    assert registry.config.global_threshold == 0.4
    assert registry.config.per_recognizer_thresholds == {"visit_no": 0.85}
    assert "示例医师" in registry.config.allow_list_exact
    assert "^示例\\d+$" in registry.config.allow_list_regex
    assert registry.booster is not None
    assert "住院号" in registry.boost_terms


def test_名册里没写的识别器默认启用(tmp_path):
    """名册里没提的识别器照常启用 —— 「没写」不等于「关了」。"""
    raw = _base_raw()
    raw["recognizers"].pop("visit_no", None)
    raw["recognizers"].pop("phone_birth", None)
    policy = _write_policy(tmp_path, raw)
    registry = build_registry(load_policy_table(policy))
    ids = {recognizer.id for recognizer in registry.get_recognizers()}
    assert ids == {"labeled_field", "visit_no", "phone_birth", "id_card"}, ids


def test_缺名册段时名册按全部启用处理(tmp_path):
    """缺整段时，名册层按「全部启用」处理。

    注意：``id_card`` / ``patient_index`` 的分段参数就放在这一段里，那两个模块
    缺段会各自报错（task 18 / 17 的纪律）；本条只验**名册层**的默认语义。
    """
    raw = _base_raw()
    raw.pop("recognizers", None)
    policy = _write_policy(tmp_path, raw)
    table = load_policy_table(policy)
    assert table.recognizer_enabled("visit_no") is True
    assert table.recognizer_enabled("id_card") is True
    assert table.catalog.enabled == {}


# -------------------------------------------------------------------- 启停


@pytest.mark.parametrize(("recognizer_id", "text", "label"), DISABLE_CASES)
def test_禁用识别器后命中数为零(tmp_path, recognizer_id, text, label):
    """被关掉的识别器一条命中都不产出。"""
    registry = _registry(tmp_path, **{f"recognizers.{recognizer_id}.enabled": False})
    assert recognizer_id not in {r.id for r in registry.get_recognizers()}
    spans = registry.analyze(text)
    assert not [span for span in spans if span.label == label], spans


@pytest.mark.parametrize(("recognizer_id", "text", "label"), DISABLE_CASES)
def test_禁用识别器后主路径不改写该处(tmp_path, recognizer_id, text, label):
    """关掉识别器后，主路径不动那一段 —— 误伤多的识别器能临时停用。"""
    registry = _registry(tmp_path, **{f"recognizers.{recognizer_id}.enabled": False})
    outcome = redact_text(text, "M-1", registry=registry)
    assert outcome.redacted_text == text, outcome.redacted_text
    assert not [entry for entry in outcome.entries if entry.label == label]


def test_禁用一个识别器不影响其他识别器(tmp_path):
    """启停是**逐个**的：关掉一个不等于关掉一串。"""
    registry = _registry(tmp_path, **{"recognizers.visit_no.enabled": False})
    assert registry.analyze("姓名：张某某"), "字段标签识别器不该被牵连"
    assert registry.analyze("13800138000"), "手机号识别器不该被牵连"
    assert not registry.analyze("本次住院流水 90000001"), "住院号识别器应已停用"


def test_关闭上下文加分后不再加分(tmp_path):
    """上下文加分器也在名册里：关掉就没有加分器。"""
    registry = _registry(tmp_path, **{"recognizers.context_boost.enabled": False})
    assert registry.booster is None
    assert registry.boost_terms == ()


def test_禁用患者名单识别器后名单命中数为零(tmp_path):
    """名单识别器关掉后不产出命中 —— 不降级为按姓名硬匹配。"""
    raw = _base_raw()
    _set_path(raw, "recognizers.patient_index.enabled", False)
    policy = _write_policy(tmp_path, raw)
    registry = build_registry(load_policy_table(policy))
    assert "patient_index" not in {r.id for r in registry.get_recognizers()}


# -------------------------------------------------------- 逐项阈值覆盖生效


def test_逐识别器阈值覆盖决定确认档(tmp_path):
    """覆盖后的门槛生效：住院号识别器门槛抬到 0.9，0.7 分的命中降为告警档。"""
    registry = _registry(
        tmp_path, thresholds__per_recognizer={"visit_no": 0.9}
    )
    spans = registry.analyze("本次住院流水 90000001")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert "阈值 0.90" in spans[0].reason


def test_逐识别器阈值覆盖不影响其他识别器(tmp_path):
    """逐项覆盖是**逐个**的：只动住院号，不动姓名。"""
    registry = _registry(
        tmp_path, thresholds__per_recognizer={"visit_no": 0.9}
    )
    spans = registry.analyze("姓名：张某某")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.CONFIRMED


def test_逐识别器阈值覆盖后告警档不改写正文(tmp_path):
    """门槛抬高后命中降为告警档，主路径不改写那一段（改写的是确认档）。"""
    registry = _registry(
        tmp_path, thresholds__per_recognizer={"visit_no": 0.9}
    )
    text = "本次住院流水 90000001"
    outcome = redact_text(text, "M-1", registry=registry)
    assert outcome.redacted_text == text


# ---------------------------------------------------------------- 装配非法


def test_未知识别器名报错(tmp_path):
    """名册里写了不存在的识别器名即报错 —— 拼错的名字不被静默忽略。"""
    policy = _policy_with(tmp_path, **{"recognizers.vist_no.enabled": False})
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    message = str(excinfo.value)
    assert "vist_no" in message
    assert "未知识别器名" in message


def test_逐识别器阈值里的未知识别器名报错(tmp_path):
    """阈值覆盖写了不存在的识别器名同样报错 —— 否则这段阈值等于没配。"""
    policy = _policy_with(
        tmp_path, thresholds__per_recognizer={"visit_no_typo": 0.8}
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    message = str(excinfo.value)
    assert "visit_no_typo" in message
    assert "未知识别器名" in message


def test_逐识别器阈值越界报错(tmp_path):
    """阈值越界即报错，并指出出错项。"""
    policy = _policy_with(tmp_path, thresholds__per_recognizer={"visit_no": 1.8})
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "越界" in str(excinfo.value)
    assert "visit_no" in str(excinfo.value)


def test_全局阈值越界报错(tmp_path):
    """全局阈值越界即报错。"""
    policy = _policy_with(tmp_path, thresholds__global=1.8)
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "越界" in str(excinfo.value)


def test_YAML结构错报错(tmp_path):
    """YAML 解析不过即报错，不静默退回默认配置。"""
    target = tmp_path / "research.yaml"
    target.write_text("version: 1\nthresholds: [\n", encoding="utf-8")
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(target)
    assert "解析失败" in str(excinfo.value)


def test_未知处置动作报错(tmp_path):
    """实体类别声明了不存在的处置动作即报错。"""
    policy = _policy_with(
        tmp_path, entities__PATIENT_NAME={"action": "scramble"}
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    message = str(excinfo.value)
    assert "scramble" in message
    assert "未知处置动作" in message


def test_启停开关类型非法报错(tmp_path):
    """``enabled: "false"`` 是非空字符串（真值）—— 报错，不当成「已关闭」。"""
    policy = _policy_with(tmp_path, **{"recognizers.visit_no.enabled": "false"})
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    message = str(excinfo.value)
    assert "visit_no" in message
    assert "布尔" in message


def test_简单识别器多出未知键报错(tmp_path):
    """简单识别器只认 ``enabled``：多出来的键按拼错处理。"""
    policy = _policy_with(
        tmp_path, **{"recognizers.visit_no.enabled": True, "recognizers.visit_no.threshold": 0.9}
    )
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    message = str(excinfo.value)
    assert "threshold" in message
    assert "未知道具键" in message


def test_识别器名册段结构错报错(tmp_path):
    """名册段写成列表即报错。"""
    policy = _policy_with(tmp_path, recognizers=["visit_no"])
    with pytest.raises(PolicyTableError) as excinfo:
        load_policy_table(policy)
    assert "recognizers" in str(excinfo.value)


def test_名册里的识别器名都是名册内的名字():
    """名册常量与策略表实际写出来的名字一致（改错一处就会被这条抓住）。"""
    raw = _base_raw()
    declared = set(raw.get("recognizers", {}))
    assert declared <= set(CATALOG_NAMES), declared - set(CATALOG_NAMES)
    assert set(RECOGNIZER_IDS) <= set(CATALOG_NAMES)


def test_装配器与主路径共用同一份策略表(tmp_path):
    """装配器不另读一份文件：拿到的表就是主路径用的那张。"""
    raw = copy.deepcopy(_base_raw())
    _set_path(raw, "thresholds.global", 0.33)
    policy = _write_policy(tmp_path, raw)
    table = load_policy_table(policy)
    registry = build_registry(table)
    assert registry.config.global_threshold == table.global_threshold == 0.33
