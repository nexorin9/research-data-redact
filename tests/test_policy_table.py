"""策略表与处置动作框架验收。

对应源产品两处机制：

- ``analyzer_engine_provider.py`` 的 **YAML 装配形态**（保留）——
  一份 YAML 装下阈值与配置；
- ``anonymizer_engine.py::AnonymizerEngine.anonymize``（:29-113）的
  **按实体类别配动作**（保留）—— ``operators`` 字典即「实体类别 → 处置动作」表。

本任务验三件事：

1. **策略表能装、也能装对** —— 阈值、实体类别 → 动作、白名单、上下文词表
   都从 ``policy/research.yaml`` 读进来；
2. **配置非法即报错** —— 未知处置动作 / 阈值越界 / 实体类别没有动作 /
   白名单正则编译不过 / 未知道具键，一律报错并指出出错项，不静默取默认值；
3. **各动作各自生效** —— replace / redact / keep / hmac_pseudonym 在主路径上
   真的按策略表执行。

另有一条红线：**声明了却没落地的动作必须报错** —— 策略表能声明它，但实现
落地前执行必须明确报错，绝不静默退回「保留原文」。
（一致代号 ``hmac_pseudonym`` 已由 task 24 落地；还原动作 ``hmac_restore``
仍是预留挂载位，由 task 25 落地。）
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from research_redact.daemon.pipeline import build_default_registry, redact_text
from research_redact.models import SpanTier
from research_redact.policy.operators import (
    ActionSpec,
    KeepOperator,
    OperatorContext,
    OperatorError,
    OperatorNotFoundError,
    OperatorRegistry,
    OperatorUnavailableError,  # noqa: F401 —— 预留挂载位机制仍在（当前为空表）
    RedactOperator,
    ReplaceOperator,
    default_operator_registry,
)
from research_redact.policy.table import (
    PolicyTableError,
    UndeclaredEntityError,
    load_policy_table,
)
from research_redact.recognizers.base import PatternRecognizer
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_ROOT / "policy" / "research.yaml"


def _write_policy(tmp_path: Path, body: str) -> Path:
    """写一份临时策略表并返回路径。"""
    target = tmp_path / "research.yaml"
    target.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return target


def _minimal_policy(**entities) -> str:
    """拼一份最小可用的策略表（实体段可覆盖）。"""
    lines = [
        "version: 1",
        "thresholds:",
        "  global: 0.5",
        "  per_recognizer: {}",
        "entities:",
    ]
    for entity, item in entities.items():
        lines.append(f"  {entity}:")
        for key, value in item.items():
            lines.append(f"    {key}: {value}")
    lines += [
        "allow_list:",
        "  exact: []",
        "  regex: []",
        "context:",
        "  terms:",
        "    - 住院号",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- 策略表装载


def test_shipped_policy_table_loads():
    """随项目发布的策略表能装载：四段齐备，实体类别 → 动作映射可查。"""
    table = load_policy_table(POLICY_FILE)
    assert table.version == 1
    assert table.global_threshold == 0.5
    assert table.per_recognizer_thresholds == {}
    # 白名单段自 task 21 起不再是空壳：误伤回归语料靠它挡住「脱过头」。
    # 空表等于误伤防线消失，所以这里断言的是「有内容且含关键项」。
    assert table.allow_list_exact
    assert table.allow_list_regex
    assert "未登记" in table.allow_list_exact
    assert any("NONE" in pattern for pattern in table.allow_list_regex)
    assert "住院号" in table.context_terms
    assert set(table.entity_names()) >= {
        "PATIENT_NAME",
        "PATIENT_ID",
        "ID_CARD",
        "VISIT_NO",
        "EXAM_NO",
        "PHONE",
        "BIRTH_DATE",
        "DEVICE_ID",
    }


def test_entity_action_lookup_returns_spec():
    """按实体类别取动作：replace 带占位符，redact / keep 不带。"""
    table = load_policy_table(POLICY_FILE)
    name = table.action_for("PATIENT_NAME")
    assert name.action == "replace"
    assert name.placeholder == "<患者姓名>"
    assert table.action_for("ID_CARD") == ActionSpec("redact")
    assert table.action_for("DEVICE_ID") == ActionSpec("keep")


def test_resolver_is_the_same_lookup():
    """resolver() 给主路径用：行为与 action_for 一致。"""
    table = load_policy_table(POLICY_FILE)
    resolver = table.resolver()
    assert resolver("EXAM_NO").placeholder == "<检查号>"


def test_policy_table_drives_registry_thresholds_and_allow_list(tmp_path):
    """策略表的阈值与白名单真的进了识别引擎（不是各写一份）。"""
    policy = _write_policy(
        tmp_path,
        """
        version: 1
        thresholds:
          global: 0.4
          per_recognizer:
            visit_no: 0.9
        entities:
          VISIT_NO:
            action: replace
            placeholder: "<住院号>"
        allow_list:
          exact:
            - "12345678"
          regex:
            - "^9{8}$"
        context:
          terms:
            - 住院号
        """,
    )
    table = load_policy_table(policy)
    assert table.global_threshold == 0.4
    assert table.per_recognizer_thresholds == {"visit_no": 0.9}
    assert table.allow_list_exact == ("12345678",)
    assert table.allow_list_regex == ("^9{8}$",)
    assert table.threshold_for("visit_no") == 0.9
    assert table.threshold_for("other") == 0.4


# ------------------------------------------------------------- 非法配置报错


def test_unknown_action_raises(tmp_path):
    """未知处置动作报错并指出出错项，不静默取默认动作。"""
    policy = _write_policy(
        tmp_path,
        _minimal_policy(VISIT_NO={"action": "shred"}),
    )
    with pytest.raises(PolicyTableError, match="未知处置动作"):
        load_policy_table(policy)


def test_threshold_out_of_range_raises(tmp_path):
    """阈值越界报错。"""
    policy = _write_policy(
        tmp_path,
        """
        version: 1
        thresholds:
          global: 1.8
        entities:
          VISIT_NO:
            action: replace
            placeholder: "<住院号>"
        allow_list:
          exact: []
          regex: []
        context:
          terms:
            - 住院号
        """,
    )
    with pytest.raises(PolicyTableError, match="越界"):
        load_policy_table(policy)


def test_entity_without_action_raises(tmp_path):
    """实体类别没有声明处置动作报错（不默认放行、也不默认脱掉）。"""
    policy = _write_policy(
        tmp_path,
        _minimal_policy(VISIT_NO={"placeholder": "<住院号>"}),
    )
    with pytest.raises(PolicyTableError, match="缺少处置动作"):
        load_policy_table(policy)


def test_entity_section_missing_raises(tmp_path):
    """缺整段报错：entities 段缺失不得当成「本院没有这类实体」。"""
    policy = _write_policy(
        tmp_path,
        """
        version: 1
        thresholds:
          global: 0.5
        allow_list:
          exact: []
          regex: []
        context:
          terms:
            - 住院号
        """,
    )
    with pytest.raises(PolicyTableError, match="缺少 entities 段"):
        load_policy_table(policy)


def test_replace_without_placeholder_raises(tmp_path):
    """replace 动作缺占位符报错。"""
    policy = _write_policy(tmp_path, _minimal_policy(VISIT_NO={"action": "replace"}))
    with pytest.raises(PolicyTableError, match="placeholder"):
        load_policy_table(policy)


def test_placeholder_on_non_replace_action_raises(tmp_path):
    """非 replace 动作带占位符报错（配置笔误不静默忽略）。"""
    policy = _write_policy(
        tmp_path, _minimal_policy(VISIT_NO={"action": "redact", "placeholder": '"<x>"'})
    )
    with pytest.raises(PolicyTableError, match="placeholder"):
        load_policy_table(policy)


def test_invalid_allow_list_regex_raises(tmp_path):
    """白名单正则编译不过报错。"""
    policy = _write_policy(
        tmp_path,
        """
        version: 1
        thresholds:
          global: 0.5
        entities:
          VISIT_NO:
            action: replace
            placeholder: "<住院号>"
        allow_list:
          exact: []
          regex:
            - "([0-9"
        context:
          terms:
            - 住院号
        """,
    )
    with pytest.raises(PolicyTableError, match="正则编译不过"):
        load_policy_table(policy)


def test_unknown_root_section_raises(tmp_path):
    """未知道具键报错：段名拼错（如 entities 写成 entity）不得静默忽略。"""
    policy = _write_policy(
        tmp_path,
        """
        version: 1
        thresholds:
          global: 0.5
        entity:
          VISIT_NO:
            action: replace
            placeholder: "<住院号>"
        allow_list:
          exact: []
          regex: []
        context:
          terms:
            - 住院号
        """,
    )
    with pytest.raises(PolicyTableError, match="未知段"):
        load_policy_table(policy)


def test_missing_policy_file_raises(tmp_path):
    """策略表不存在报错，不退回内置默认值。"""
    with pytest.raises(PolicyTableError, match="不存在"):
        load_policy_table(tmp_path / "nope.yaml")


# --------------------------------------------------------- 三种动作各自生效


def _registry_for(label: str, pattern: str = r"(?<!\d)\d{8}(?!\d)") -> RecognizerRegistry:
    """只认一个类别的注册表。"""
    return RecognizerRegistry(
        [PatternRecognizer("probe", "探针识别器", {label: pattern}, base_score=0.9)],
        RegistryConfig(global_threshold=0.5),
    )


def test_replace_action_writes_placeholder():
    """replace 动作：写入策略表给的占位符。"""
    table = load_policy_table(POLICY_FILE)
    outcome = redact_text(
        "住院号 12345678",
        "M-1",
        registry=_registry_for("VISIT_NO"),
        actions=table.resolver(),
    )
    assert outcome.redacted_text == "住院号 <住院号>"
    assert outcome.entries[0].action == "replace"


def test_redact_action_clears_segment():
    """redact 动作：整段清空，不留任何痕迹。"""
    table = load_policy_table(POLICY_FILE)
    outcome = redact_text(
        "身份证 11010519491231002X",
        "M-2",
        registry=_registry_for("ID_CARD", r"(?<!\d)\d{17}[\dX](?!\d)"),
        actions=table.resolver(),
    )
    assert outcome.redacted_text == "身份证 "
    assert outcome.entries[0].action == "redact"


def test_keep_action_leaves_text_untouched():
    """keep 动作：保留原文，且不计入改写条数。"""
    table = load_policy_table(POLICY_FILE)
    outcome = redact_text(
        "设备号 12345678",
        "M-3",
        registry=_registry_for("DEVICE_ID"),
        actions=table.resolver(),
    )
    assert outcome.redacted_text == "设备号 12345678"
    assert outcome.entries[0].action == "keep"
    assert outcome.rewritten == 0


def test_five_actions_run_through_operator_registry(monkeypatch):
    """动作注册表：五种动作的执行结果各自正确。

    一致代号（``hmac_pseudonym``）与其还原侧（``hmac_restore``）**成对登记** ——
    脱敏侧登记的对照槽位，还原侧才取得到。
    """
    monkeypatch.setenv("PSEUDONYM_HMAC_KEY", "test-only-hmac-key-0123456789abcdef")
    registry = default_operator_registry()
    assert set(registry.names()) == {
        "replace",
        "redact",
        "keep",
        "hmac_pseudonym",
        "hmac_restore",
    }
    assert registry.get("replace").apply("张三", OperatorContext(placeholder="<姓名>")) == "<姓名>"
    assert registry.get("redact").apply("张三", OperatorContext()) == ""
    assert registry.get("keep").apply("张三", OperatorContext()) == "张三"
    code = registry.get("hmac_pseudonym").apply(
        "张三", OperatorContext(entity_id="P-1001", material_id="M-1")
    )
    assert re.fullmatch(r"P-[0-9a-f]{16}", code)
    # 还原侧取回的就是脱敏侧登记的那一段原文
    assert (
        registry.get("hmac_restore").apply(
            code, OperatorContext(material_id="M-1", occurrence=0)
        )
        == "张三"
    )


def test_replace_without_placeholder_is_an_error():
    """replace 动作缺占位符报错（不留空白蒙混过关）。"""
    registry = default_operator_registry()
    with pytest.raises(OperatorError, match="占位符"):
        registry.get("replace").apply("张三", OperatorContext())


def test_operator_registry_rejects_duplicate_registration():
    """同名动作重复登记报错，不静默覆盖。"""
    registry = OperatorRegistry()
    registry.register(KeepOperator())
    with pytest.raises(OperatorError, match="重复登记"):
        registry.register(KeepOperator())


def test_unknown_operator_name_raises():
    """未登记的动作名报错。"""
    with pytest.raises(OperatorNotFoundError, match="未登记"):
        default_operator_registry().get("shred")


# --------------------------------------------------- 预留挂载位与未声明类别


def test_reserved_mount_point_can_be_declared_in_policy(tmp_path):
    """一致代号可被策略表声明（task 24 落地后实现已就位，装载与执行都不报错）。"""
    policy = _write_policy(
        tmp_path, _minimal_policy(PATIENT_NAME={"action": "hmac_pseudonym"})
    )
    table = load_policy_table(policy)
    assert table.action_for("PATIENT_NAME").action == "hmac_pseudonym"


def test_declared_restore_action_without_mapping_raises_instead_of_keeping_raw_text(
    tmp_path,
):
    """声明了还原动作、但对照索引里没有对应条目时，必须报错中止。

    **不静默退回「保留原文」** —— 留着原文就等于没脱；宁可整批停下。
    （还原动作 ``hmac_restore`` 已由 task 25 落地；一致代号 ``hmac_pseudonym``
    由 task 24 落地。）
    """
    policy = _write_policy(
        tmp_path, _minimal_policy(PATIENT_NAME={"action": "hmac_restore"})
    )
    table = load_policy_table(policy)
    with pytest.raises(OperatorError, match="查不到原文"):
        redact_text(
            "姓名 12345678",
            "M-4",
            registry=_registry_for("PATIENT_NAME"),
            actions=table.resolver(),
        )


def test_undeclared_entity_is_recorded_not_silently_dropped():
    """策略表没声明的类别：保留原文，但在清单里留痕（不静默脱、不静默放）。"""
    outcome = redact_text(
        "设备号 12345678",
        "M-5",
        registry=_registry_for("DEVICE_SERIAL"),
    )
    assert outcome.redacted_text == "设备号 12345678"
    assert len(outcome.entries) == 1
    assert "策略表未声明" in outcome.entries[0].action
    assert outcome.rewritten == 0


def test_action_for_undeclared_entity_raises():
    """未声明类别在策略表层面显式报错（区别于「配置非法」）。"""
    table = load_policy_table(POLICY_FILE)
    with pytest.raises(UndeclaredEntityError, match="未在策略表声明"):
        table.action_for("DEVICE_SERIAL")


# --------------------------------------------------------------- 主路径联动


def test_default_registry_uses_policy_thresholds():
    """默认装配的阈值来自策略表，而不是写死在代码里。"""
    table = load_policy_table(POLICY_FILE)
    registry = build_default_registry()
    assert registry.config.global_threshold == table.global_threshold
    assert registry.config.allow_list_exact == table.allow_list_exact


def test_shipped_policy_keeps_clinical_content_untouched():
    """策略表驱动下：身份串被处置，病名与药名原样保留。"""
    text = "姓名：张某某 住院号：90000001 右肺下叶磨玻璃结节 盐酸氨溴索口服液 30mL"
    outcome = redact_text(text, "M-6", registry=build_default_registry())
    assert "张某某" not in outcome.redacted_text
    assert "90000001" not in outcome.redacted_text
    assert "<患者姓名>" in outcome.redacted_text
    assert "<住院号>" in outcome.redacted_text
    for kept in ("右肺下叶磨玻璃结节", "盐酸氨溴索口服液", "30mL"):
        assert kept in outcome.redacted_text
    assert outcome.entries[0].tier == SpanTier.CONFIRMED.value
