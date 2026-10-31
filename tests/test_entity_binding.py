"""患者身份锚定验收：同名异人不串号、一人多号归一、单独姓名降告警、主索引不可达不命中。

本测试盯住「患者身份以 HIS 患者主索引主键为准」这条纪律的六件事：

1. **主键命中**：材料里出现患者主索引主键 → 绑定到该主键；
2. **姓名 + 就诊号组合**：绑得上 → 确认档 + 落到该主键；
3. **同名异人不合并、不串号**：两个主键共享同一姓名时，各自按自己的就诊号绑定，
   谁都不占对方的身份；
4. **一人多号归一**：同一主键的多个住院号 → 同一个身份键，一致代号的取值输入唯一；
5. **单独姓名降告警档**：只有姓名没有就诊号佐证 → 不判为身份，且**邻近上下文
   词不得把它抬成确认档**（「姓名」两个字就在旁边）；
6. **主索引不可达 / 名单为空 → 不产出任何命中**，并由批次状态机把批次置
   ``suspended``（**不降级**为按正则直接脱）。

另加两条红线：命中解释与命中清单**不含命中原文**；名单只收申请单声明的患者。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.pipeline import redact_text
from research_redact.daemon.state_machine import BatchState
from research_redact.ingest.application import load_json_application
from research_redact.models import SpanTier
from research_redact.policy.operators import (
    OperatorRegistry,
    RedactOperator,
    ReplaceOperator,
)
from research_redact.recognizers.assembly import build_default_registry
from research_redact.recognizers.context_boost import ContextBooster, load_context_config
from research_redact.recognizers.patient_index import (
    ID_ENTITY,
    MATCH_AMBIGUOUS,
    MATCH_NAME_AND_VISIT,
    MATCH_NAME_ONLY,
    MATCH_PRIMARY_KEY,
    NAME_ENTITY,
    PatientIndexBinding,
    PatientIndexConfig,
    PatientIndexRecognizer,
    PatientIndexUnavailableError,
    binding_from_client,
    load_patient_index_binding,
    require_binding,
)
from research_redact.recognizers.registry import RecognizerRegistry, RegistryConfig

#: 合成样例里的身份串：命中清单与解释里都不该出现它们
IDENTITY_STRINGS = ("张某某", "90000001", "90000002", "P-1001", "P-1002")

#: 一份齐备的申请单（主索引不可达 → 挂起 用）
APPLICATION = {
    "application_no": "KY20260001",
    "ethics_approval_no": "EC-2026-0001",
    "patient_ids": ["P-1001", "P-1002"],
    "materials": [
        {
            "material_id": "M-1",
            "kind": "report_text",
            "path": "materials/M-1.txt",
            "patient_id": "P-1001",
        }
    ],
}


def _record(patient_id: str, visit_no: str, name: str) -> dict[str, str]:
    """一条主索引记录（与出站客户端读回的结构同形）。"""
    return {"patient_id": patient_id, "visit_no": visit_no, "name": name}


def _binding(*records: dict[str, str]) -> PatientIndexBinding:
    """按记录装配名单。"""
    return load_patient_index_binding(records)


def _registry(binding: PatientIndexBinding) -> RecognizerRegistry:
    """只装名单识别器的注册表（把其他形态的干扰排除掉）。"""
    return RecognizerRegistry(
        [PatientIndexRecognizer(binding, config=PatientIndexConfig())],
        RegistryConfig(global_threshold=0.5),
    )


def _boosted_registry(binding: PatientIndexBinding) -> RecognizerRegistry:
    """名单识别器 + 邻近上下文加分器（验证单独姓名不会被抬成确认档）。"""
    return RecognizerRegistry(
        [PatientIndexRecognizer(binding, config=PatientIndexConfig())],
        RegistryConfig(global_threshold=0.5),
        booster=ContextBooster(load_context_config()),
    )


# ------------------------------------------------------------------ 名单装配


def test_一人多号在名单里归到同一个主键():
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1001", "90000002", "张某某"),
    )
    assert binding.patient_ids() == ("P-1001",)
    entry = binding.entry_for("P-1001")
    assert entry is not None
    assert entry.visit_nos == ("90000001", "90000002")
    assert binding.entry_for_visit_no("90000001") is entry
    assert binding.entry_for_visit_no("90000002") is entry
    assert binding.entry_for("P-9999") is None


def test_名单只收申请单声明的患者():
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1002", "90000002", "李某某"),
    )
    scoped = load_patient_index_binding(
        [
            _record("P-1001", "90000001", "张某某"),
            _record("P-1002", "90000002", "李某某"),
        ],
        declared_patient_ids=["P-1001"],
    )
    assert scoped.patient_ids() == ("P-1001",)
    assert scoped.excluded_patient_ids == ("P-1002",)
    assert binding.patient_ids() == ("P-1001", "P-1002")


def test_主索引不可达时装配出不可用名单():
    class _BrokenClient:
        def lookup_many(self, visit_nos):
            raise RuntimeError("连接被拒绝")

    binding = binding_from_client(
        _BrokenClient(), ["90000001"], declared_patient_ids=["P-1001"]
    )
    assert binding.available is False
    assert binding.usable is False
    assert binding.is_empty is True
    assert "患者主索引不可达" in binding.suspend_reason
    with pytest.raises(PatientIndexUnavailableError):
        require_binding(binding)


# ------------------------------------------------------------------ 命中规则


def test_主键命中绑定到该主键():
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    spans = _registry(binding).analyze('{"patient_id": "P-1001", "kind": "report_text"}')
    hits = [span for span in spans if span.label == ID_ENTITY]
    assert len(hits) == 1
    assert hits[0].is_confirmed
    assert hits[0].metadata["patient_id"] == "P-1001"
    assert hits[0].metadata["match_mode"] == MATCH_PRIMARY_KEY


def test_姓名加就诊号组合绑定到该主键():
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    text = "受检者姓名：张某某  住院号：90000001  科室：呼吸内科\n"
    spans = _registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 1
    assert hits[0].is_confirmed
    assert hits[0].metadata["patient_id"] == "P-1001"
    assert hits[0].metadata["match_mode"] == MATCH_NAME_AND_VISIT
    assert hits[0].metadata["visit_no"] == "90000001"


def test_同名异人不合并不串号():
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1002", "90000002", "张某某"),
    )
    text = (
        "受检者姓名：张某某  住院号：90000001  科室：呼吸内科\n"
        "受检者姓名：张某某  住院号：90000002  科室：呼吸内科\n"
    )
    spans = _registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 2, "两位同名患者各产出一处命中，不得合并成一处"
    assert [hit.metadata["patient_id"] for hit in hits] == ["P-1001", "P-1002"]
    assert hits[0].start != hits[1].start
    assert all(hit.is_confirmed for hit in hits)
    # 不串号：两个主键落在两段不同的正文上
    assert text[hits[0].start : hits[0].end] == "张某某"
    assert text[hits[1].start : hits[1].end] == "张某某"
    assert hits[0].metadata["patient_id"] != hits[1].metadata["patient_id"]


def test_一人多号归一到同一身份键():
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1001", "90000002", "张某某"),
    )
    text = (
        "受检者姓名：张某某  住院号：90000001  科室：呼吸内科\n"
        "受检者姓名：张某某  住院号：90000002  科室：呼吸内科\n"
    )
    spans = _registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 2
    assert {hit.metadata["patient_id"] for hit in hits} == {"P-1001"}
    # 一致代号的取值输入唯一：两处命中的身份键相同
    assert hits[0].metadata["patient_id"] == hits[1].metadata["patient_id"]


def test_单独姓名降告警档不判为身份():
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    text = "受检者姓名：张某某  科室：呼吸内科\n"
    spans = _registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 1
    assert hits[0].is_warning
    assert not hits[0].counts_as_residual
    assert hits[0].metadata["match_mode"] == MATCH_NAME_ONLY
    assert "告警档" in hits[0].reason


def test_单独姓名不被邻近上下文词抬成确认档():
    """「姓名」两个字就在旁边 —— 加分器不得把它抬成身份类。"""
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    text = "受检者姓名：张某某  科室：呼吸内科\n"
    spans = _boosted_registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 1
    assert hits[0].is_warning, "单独姓名必须留在告警档（上下文加分被显式禁用）"


def test_就诊号单独出现不判为身份():
    """名单匹配只认主键或「姓名 + 就诊号」；光有住院号不算身份命中。"""
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    text = "住院号：90000001  科室：呼吸内科\n"
    spans = _registry(binding).analyze(text)
    assert spans == []


def test_名单为空时不产出任何命中():
    binding = PatientIndexBinding(entries=(), available=True)
    assert binding.usable is False
    recognizer = PatientIndexRecognizer(binding, config=PatientIndexConfig())
    assert recognizer.is_available() is False
    assert recognizer.analyze("姓名：张某某 住院号：90000001") == []


def test_主索引不可达时不产出任何命中():
    binding = PatientIndexBinding(
        entries=(), available=False, reason="患者主索引不可达：连接被拒绝"
    )
    recognizer = PatientIndexRecognizer(binding, config=PatientIndexConfig())
    assert recognizer.is_available() is False
    assert recognizer.analyze("姓名：张某某 住院号：90000001") == []
    # 整张注册表也不产出该识别器的命中
    registry = RecognizerRegistry(
        [PatientIndexRecognizer(binding, config=PatientIndexConfig())],
        RegistryConfig(global_threshold=0.5),
    )
    assert registry.analyze("姓名：张某某 住院号：90000001") == []


def test_同名多患者且无法消歧时判为歧义不猜():
    """两个同名患者的就诊号一样挨着这个姓名 → 判歧义，不归到任何人头上。"""
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1002", "90000002", "张某某"),
    )
    text = "90000001 张某某 90000002\n"
    spans = _registry(binding).analyze(text)
    hits = [span for span in spans if span.label == NAME_ENTITY]
    assert len(hits) == 1
    assert hits[0].is_warning
    assert hits[0].metadata["match_mode"] == MATCH_AMBIGUOUS
    assert hits[0].metadata["candidate_patient_ids"] == ["P-1001", "P-1002"]


# --------------------------------------------------------------- 主路径接线


class _RecordingReplace(ReplaceOperator):
    """记录动作上下文的 replace 动作（用来核对身份键确实传到了动作层）。"""

    name = "replace"

    def __init__(self) -> None:
        self.contexts: list[object] = []

    def apply(self, source, context):
        self.contexts.append(context)
        return super().apply(source, context)


def test_主路径把身份键交给处置动作():
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    recorder = _RecordingReplace()
    operators = OperatorRegistry([recorder, RedactOperator()])
    text = "受检者姓名：张某某  住院号：90000001  科室：呼吸内科\n"
    outcome = redact_text(
        text,
        "M-1",
        registry=build_default_registry(binding),
        operators=operators,
    )
    assert "张某某" not in outcome.redacted_text
    assert "90000001" not in outcome.redacted_text
    name_contexts = [
        ctx for ctx in recorder.contexts if getattr(ctx, "label", "") == NAME_ENTITY
    ]
    assert name_contexts, "姓名这一处应当走 replace 动作"
    assert name_contexts[0].entity_id == "P-1001", "身份键必须传到动作层（一致代号的取值输入）"


def test_一人多号在主路径上共用同一身份键():
    binding = _binding(
        _record("P-1001", "90000001", "张某某"),
        _record("P-1001", "90000002", "张某某"),
    )
    recorder = _RecordingReplace()
    operators = OperatorRegistry([recorder, RedactOperator()])
    registry = build_default_registry(binding)
    keys: list[str] = []
    for visit_no in ("90000001", "90000002"):
        text = f"受检者姓名：张某某  住院号：{visit_no}  科室：呼吸内科\n"
        redact_text(text, f"M-{visit_no}", registry=registry, operators=operators)
        keys.extend(
            ctx.entity_id
            for ctx in recorder.contexts
            if getattr(ctx, "label", "") == NAME_ENTITY
        )
    assert keys, "两处姓名都应绑定到主键"
    assert set(keys) == {"P-1001"}, "同一患者跨材料必须共用一个身份键"


def test_命中清单与解释不含命中原文():
    binding = _binding(_record("P-1001", "90000001", "张某某"))
    text = "受检者姓名：张某某  住院号：90000001  科室：呼吸内科\n"
    outcome = redact_text(text, "M-1", registry=build_default_registry(binding))
    payload = json.dumps(
        [entry.to_dict() for entry in outcome.entries], ensure_ascii=False
    )
    for secret in IDENTITY_STRINGS:
        assert secret not in payload, f"命中清单混入了原文：{secret}"


# --------------------------------------------------------- 主索引不可达 → 挂起


def test_主索引不可达时批次置挂起(tmp_path: Path):
    application = tmp_path / "application.json"
    application.write_text(
        json.dumps(APPLICATION, ensure_ascii=False), encoding="utf-8"
    )
    intake = load_json_application(application)
    with BatchLedger(tmp_path / "ledger.db") as ledger:
        ledger.apply_intake(intake)
        record = ledger.apply_recognition(
            intake.application_no,
            material_count=1,
            recognized_material_count=1,
            patient_index_reachable=False,
        )
        assert record.batch_state is BatchState.SUSPENDED
        assert "主索引" in record.failure_reason
        alerts = ledger.alerts(intake.application_no)
        assert any(alert.code == "patient_index_unreachable" for alert in alerts)
        for secret in IDENTITY_STRINGS:
            assert secret not in json.dumps(
                [alert.to_dict() for alert in alerts], ensure_ascii=False
            )
