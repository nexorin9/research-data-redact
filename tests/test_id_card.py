"""身份证校验位识别器验收：正例判为身份、反例降告警、旧版号不判身份、反例不计入残留。

本测试盯住「校验位形态」这一条纪律的五件事：

1. **正例判为身份** —— 18 位 + 出生日期合法 + GB 11643 校验位通过 → 确认档；
2. **反例降为告警档** —— 校验位对不上（长度对、校验码错）→ 告警档，**不判为
   身份**，也不计入身份类残留统计；
3. **15 位旧版号不判为身份证** —— 旧版号没有校验位、无法验证，降为告警档并写明
   「旧版、无校验位」，由人工抽检；
4. **已判定不通过的候选不得被上下文词复活** —— 旁边就写着「身份证」三个字，
   也不许把它抬成身份类（校验位不通过是「已经判定不通过」，不是「证据不足」）；
5. **清单不含原文** —— 命中解释与命中清单里不得出现身份证号本身（连期望的
   校验码也不写：那是命中原文的一个字符）。

另加两条边界：**脏值不产生身份命中**（空串 / 非数字串 / 位数不对的串），
以及**主路径已装配**（身份证走「整段清空」动作，脱敏产物里不留痕迹）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research_redact.audit.residual import ResidualChecker
from research_redact.daemon.pipeline import redact_text
from research_redact.models import SpanTier
from research_redact.recognizers.assembly import build_default_registry
from research_redact.recognizers.id_card import (
    ID_CARD_ENTITY,
    IdCardConfig,
    IdCardConfigError,
    IdCardRecognizer,
    VerdictKind,
    gb11643_check_char,
    load_id_card_config,
    validate_id_card,
)

#: 正反例语料（fixtures/id_card_cases.json，全部为合成样例）
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "id_card_cases.json"


def _cases() -> dict:
    """读语料文件。"""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _group(name: str) -> list[dict]:
    """取某一组样例。"""
    return list(_cases()[name])


def _values(name: str) -> list[str]:
    """取某一组样例的取值（跳过空值）。"""
    return [item["value"] for item in _group(name) if item["value"]]


def _id_card_spans(text: str) -> list:
    """默认装配下，只留身份证命中的区间。"""
    return [
        span
        for span in build_default_registry().analyze(text)
        if span.label == ID_CARD_ENTITY
    ]


# --------------------------------------------------------------- 语料本身的正确性


def test_语料规模满足要求() -> None:
    """正例 ≥4（含末位 X）、校验位错误反例 ≥4、15 位旧号 ≥2，且含空串与脏值。"""
    cases = _cases()
    assert len(cases["valid"]) >= 4
    assert len(cases["checksum_invalid"]) >= 4
    assert len(cases["legacy_15"]) >= 2
    assert cases["dirty"], "脏值边界样例不能为空"
    raw_values = [item["value"] for item in cases["dirty"]]
    assert None in raw_values, "脏值里应有空值"
    assert "" in raw_values, "脏值里应有空串"
    assert any("X" in item["value"] for item in cases["valid"]), "正例里应有末位 X 的样例"


def test_正例样例确实通过校验位() -> None:
    """语料里的每个正例，按 GB 11643 算出来都得对得上（否则语料本身是错的）。"""
    for item in _group("valid"):
        verdict = validate_id_card(item["value"])
        assert verdict.kind is VerdictKind.VALID, f"{item['note']}：{verdict.detail}"


def test_反例样例确实校验位不通过() -> None:
    """语料里的每个反例，判定都必须是「校验位不通过」。"""
    for item in _group("checksum_invalid"):
        verdict = validate_id_card(item["value"])
        assert verdict.kind is VerdictKind.CHECKSUM_FAIL, item["note"]


def test_校验码计算与国标一致() -> None:
    """加权因子与校验码表：17 位本体 → 校验码。

    国标常引的示例号 ``11010519491231002X`` 算出来末位正是 ``X``；
    末位为纯数字的 ``110101194912310016`` 算出来正是 ``6``。
    """
    assert gb11643_check_char("11010519491231002") == "X"
    assert gb11643_check_char("11010119491231001") == "6"
    assert gb11643_check_char("00000000000000000") == "1"
    with pytest.raises(ValueError):
        gb11643_check_char("123")


# ------------------------------------------------------------------- 正例与反例


def test_正例判为确认档() -> None:
    """正例 → ID_CARD 确认档。"""
    for value in _values("valid"):
        spans = _id_card_spans(f"身份证：{value}")
        assert len(spans) == 1, f"{value} 应命中 1 次"
        span = spans[0]
        assert span.label == ID_CARD_ENTITY
        assert span.tier is SpanTier.CONFIRMED
        assert span.score >= 0.9
        assert span.counts_as_residual


def test_末位X大小写等价() -> None:
    """末位校验码大写 X 与小写 x 是同一个号，都判为确认档。"""
    upper = "12010319891123988X"
    lower = "12010319891123988x"
    for value in (upper, lower):
        spans = _id_card_spans(f"身份证：{value}")
        assert len(spans) == 1
        assert spans[0].tier is SpanTier.CONFIRMED
    assert validate_id_card(upper).kind is VerdictKind.VALID
    assert validate_id_card(lower).kind is VerdictKind.VALID


def test_校验位错误的反例降为告警档() -> None:
    """反例 → 告警档，不判为身份。"""
    for value in _values("checksum_invalid"):
        spans = _id_card_spans(f"身份证：{value}")
        assert len(spans) == 1, f"{value} 应命中 1 次"
        span = spans[0]
        assert span.tier is SpanTier.WARNING, f"{value} 应降为告警档"
        assert not span.counts_as_residual
        assert "校验位" in span.reason


def test_15位旧号不判为身份证() -> None:
    """15 位旧版号无校验位，无法验证 → 告警档并写明原因。"""
    for value in _values("legacy_15"):
        spans = _id_card_spans(f"身份证号：{value}")
        assert len(spans) == 1, f"{value} 应命中 1 次"
        span = spans[0]
        assert span.tier is SpanTier.WARNING
        assert not span.counts_as_residual
        assert "旧版" in span.reason
        assert "无法验证" in span.reason


def test_出生日期非法降为告警档() -> None:
    """校验位对得上但出生日期段不是合法日期 → 告警档。"""
    for value in _values("birth_date_invalid"):
        verdict = validate_id_card(value)
        assert verdict.kind is VerdictKind.BIRTH_DATE_INVALID
        spans = _id_card_spans(f"身份证：{value}")
        assert len(spans) == 1
        assert spans[0].tier is SpanTier.WARNING
        assert not spans[0].counts_as_residual


def test_脏值不判为身份() -> None:
    """脏值（空串 / 非数字 / 位数不对）不得产生任何身份类命中。"""
    for item in _group("dirty"):
        value = item["value"] or ""
        spans = _id_card_spans(f"患者资料 {value}")
        for span in spans:
            assert span.tier is not SpanTier.CONFIRMED, item["note"]
        assert validate_id_card(value).kind is not VerdictKind.VALID, item["note"]


def test_位数不对的串不被切出18位来判() -> None:
    """19 位串不得从中间切出 18 位判成身份证。"""
    value = "1101011949123100166"
    spans = _id_card_spans(f"设备号 {value}")
    assert not any(span.tier is SpanTier.CONFIRMED for span in spans)


def test_身份证不被顺带判成住院号() -> None:
    """18 位身份证不应同时命中 VISIT_NO（形状约束不切长串）。"""
    value = "110101194912310016"
    spans = build_default_registry().analyze(f"身份证：{value}")
    assert [span.label for span in spans] == [ID_CARD_ENTITY]


# ------------------------------------------------------------------- 残留统计


def test_反例不计入身份类残留() -> None:
    """反例降为告警档 → 不进身份类残留统计；正例进。"""
    checker = ResidualChecker()
    invalid = "110101194912310010"
    findings = checker.scan(f"身份证：{invalid}", "M-1")
    assert findings == (), "校验位不通过的串不得计入身份类残留"

    valid = "110101194912310016"
    findings = checker.scan(f"身份证：{valid}", "M-1")
    assert len(findings) == 1
    assert findings[0].label == ID_CARD_ENTITY
    assert findings[0].tier == "identity"


def test_反例的残留自检不拦投放行() -> None:
    """一批材料里只有校验位不通过的串 → 残留自检通过，批次可投递。"""
    checker = ResidualChecker()
    report = checker.check_batch(
        "KY20260001",
        {"M-1": "身份证：110101194912310010", "M-2": "设备号 1101011949123100166"},
    )
    assert report.identity_count == 0
    assert report.deliverable is True


# --------------------------------------------------------------- 上下文不得复活


def test_邻近上下文词不得把反例抬成身份类() -> None:
    """「身份证」三个字就在旁边，也不许把校验位不通过的候选抬成确认档。"""
    value = "110101194912310010"
    spans = _id_card_spans(f"身份证：{value}")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING
    assert spans[0].metadata.get("boost_allowed") is False


def test_旧版号同样不得被上下文词抬成身份类() -> None:
    """15 位旧号带「身份证号」标签时，仍是告警档。"""
    value = "110101491231001"
    spans = _id_card_spans(f"身份证号：{value}")
    assert len(spans) == 1
    assert spans[0].tier is SpanTier.WARNING


# ------------------------------------------------------------------- 不含原文


def test_命中解释不含身份证原文() -> None:
    """解释与 metadata 都不得出现身份证号本身（期望校验码也不写）。"""
    for value in _values("valid") + _values("checksum_invalid") + _values("legacy_15"):
        for span in _id_card_spans(f"身份证：{value}"):
            assert value not in span.reason
            assert value[-1] not in span.reason.replace("X", "") or value[-1].isdigit()
            assert value not in json.dumps(span.metadata, ensure_ascii=False)


def test_命中清单不含身份证原文() -> None:
    """主路径产出的命中清单里不得出现身份证号。"""
    value = "110101194912310016"
    outcome = redact_text(f"身份证：{value}\n科别：呼吸内科\n", "M-1")
    dumped = json.dumps(
        [entry.to_dict() for entry in outcome.entries], ensure_ascii=False
    )
    assert value not in dumped


# ------------------------------------------------------------------- 配置纪律


def _policy(**overrides) -> dict:
    """造一份只含 recognizers.id_card 的策略表。"""
    section = {
        "enabled": True,
        "confirm_score": 0.9,
        "invalid_score": 0.2,
        "legacy_score": 0.2,
        "require_valid_birth_date": True,
    }
    section.update(overrides)
    return {"recognizers": {"id_card": section}}


def test_配置非法时报错并指出出错项() -> None:
    """未知道具键 / 分数越界 / 降档分数不低于确认分数 —— 一律报错。"""
    with pytest.raises(IdCardConfigError, match="未知道具键"):
        IdCardConfig.from_policy(_policy(bogus_key=1))
    with pytest.raises(IdCardConfigError, match="confirm_score"):
        IdCardConfig.from_policy(_policy(confirm_score=1.8))
    with pytest.raises(IdCardConfigError, match="门槛关系不成立"):
        IdCardConfig.from_policy(_policy(invalid_score=0.95))
    with pytest.raises(IdCardConfigError, match="门槛关系不成立"):
        IdCardConfig.from_policy(_policy(legacy_score=0.9))
    with pytest.raises(IdCardConfigError, match="recognizers.id_card"):
        IdCardConfig.from_policy({"recognizers": {}})
    with pytest.raises(IdCardConfigError, match="recognizers"):
        IdCardConfig.from_policy({})


def test_默认配置可从策略表装载() -> None:
    """策略表里的 id_card 段能被装出来，且降档分数低于确认分数。"""
    config = load_id_card_config()
    assert config.confirm_score > config.invalid_score
    assert config.confirm_score > config.legacy_score
    assert config.enabled is True
    assert config.require_valid_birth_date is True


def test_识别器被关掉后不产出任何命中() -> None:
    """策略表关掉 id_card → 该识别器不产出命中。"""
    config = IdCardConfig(enabled=False)
    recognizer = IdCardRecognizer(config=config)
    assert recognizer.is_available() is False
    assert recognizer.analyze("身份证：110101194912310016") == []


# ------------------------------------------------------------------- 主路径接线


def test_默认装配已含身份证识别器() -> None:
    """主路径的注册表里装上了身份证识别器。"""
    registry = build_default_registry()
    assert any(item.id == "id_card" for item in registry.get_recognizers())


def test_主路径把身份证整段清空() -> None:
    """策略表里 ID_CARD 走 redact 动作 → 脱敏产物里不留痕迹。"""
    value = "110101194912310016"
    outcome = redact_text(f"身份证：{value}\n科别：呼吸内科\n", "M-1")
    assert value not in outcome.redacted_text
    assert "呼吸内科" in outcome.redacted_text
    entries = [entry for entry in outcome.entries if entry.label == ID_CARD_ENTITY]
    assert len(entries) == 1
    assert entries[0].action == "redact"
    assert entries[0].tier == SpanTier.CONFIRMED.value


def test_主路径对反例不改写正文() -> None:
    """校验位不通过的串不判为身份 → 正文不改写，但清单里留痕。"""
    value = "110101194912310010"
    outcome = redact_text(f"身份证：{value}\n", "M-1")
    assert value in outcome.redacted_text
    entries = [entry for entry in outcome.entries if entry.label == ID_CARD_ENTITY]
    assert len(entries) == 1
    assert entries[0].tier == SpanTier.WARNING.value
    assert entries[0].action.startswith("none")
