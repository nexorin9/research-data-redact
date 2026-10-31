"""批次状态机与 SQLite 台账验收。

状态机是本轮工作流的骨架：科研材料不是「一份文件」，而是**一张申请单、
一个伦理批件、一个批次**。批次能不能交付，取决于它走到哪一步、有没有被授权。
这一层一旦松了，后面所有「不降级」「不静默放行」的承诺都是空话。

本测试盯六件事：

1. **10 个状态全在**，主路径（detected → recognized → pseudonymized → delivered）
   走得通；
2. **非法迁移被拒且状态未被推进** —— 不推进是重点：台账里不能留下一条
   「其实没走成」的迁移记录；
3. **旁路态不得被自动跳过** —— blocked / suspended / pending_delivery 只能由
   规定事件迁出。绕过 suspended 去脱敏，等于在没有权威身份的情况下按正则硬脱；
4. **缺伦理批件号 → blocked**，并落一条告警；
5. **主索引不可达 → suspended**，并落一条告警（**不降级**为按正则直接脱）；
6. **台账真的落库** —— 状态、幂等键、产物路径、失败原因、当前步骤、回执、
   访问留痕、迁移时间线，且**不含患者原文**。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research_redact.audit.alerts import BatchAlert
from research_redact.audit.ledger import BatchLedger, default_ledger_path
from research_redact.daemon.state_machine import (
    BatchEvent,
    BatchState,
    IllegalTransitionError,
    StateMachine,
    TransitionContext,
    TransitionRejectedError,
    default_state_machine,
    intake_event,
    recognition_event,
)
from research_redact.ingest.application import load_json_application

#: 合成样例里的身份串：台账任何一行都不该出现它们
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")

#: 齐备的申请单（补齐后重新投递时用同一份）
COMPLETE_APPLICATION = {
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

#: 缺伦理批件号的申请单（缺授权范围）
BLOCKED_APPLICATION = {
    "application_no": "KY20260002",
    "patient_ids": ["P-1001"],
    "materials": [
        {
            "material_id": "M-1",
            "kind": "report_text",
            "path": "materials/M-1.txt",
            "patient_id": "P-1001",
        }
    ],
}


def _write_application(tmp_path: Path, payload: dict) -> Path:
    """把申请单写成 JSON 文件，返回路径。"""
    target = tmp_path / "application.json"
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return target


@pytest.fixture()
def ledger(tmp_path: Path):
    """临时台账（用完即弃，不碰项目 var/）。"""
    with BatchLedger(tmp_path / "ledger.db") as instance:
        yield instance


@pytest.fixture()
def machine() -> StateMachine:
    """默认状态机。"""
    return default_state_machine()


# --------------------------------------------------------------- 状态与迁移表


def test_ten_states_defined_and_all_reachable(machine: StateMachine) -> None:
    """10 个状态全在，且每个都在迁移表里出现过。"""
    assert len(BatchState) == 10
    expected = {
        "detected",
        "recognized",
        "pseudonymized",
        "delivered",
        "restore_pending",
        "restored",
        "restore_rejected",
        "blocked",
        "suspended",
        "pending_delivery",
    }
    assert {state.value for state in BatchState} == expected
    assert set(state.value for state in machine.states()) == expected


def test_happy_path_walks_from_detected_to_delivered(machine: StateMachine) -> None:
    """主路径走得通：detected → recognized → pseudonymized → delivered。"""
    result = machine.transition(
        None, BatchEvent.APPLICATION_DETECTED, TransitionContext()
    )
    assert result.target is BatchState.DETECTED

    result = machine.transition(
        BatchState.DETECTED,
        BatchEvent.APPLICATION_VALIDATED,
        TransitionContext(
            ethics_approval_no="EC-2026-0001",
            material_count=1,
        ),
    )
    assert result.target is BatchState.RECOGNIZED

    result = machine.transition(
        BatchState.RECOGNIZED,
        BatchEvent.RECOGNITION_COMPLETED,
        TransitionContext(
            material_count=1,
            recognized_material_count=1,
            patient_index_reachable=True,
        ),
    )
    assert result.target is BatchState.PSEUDONYMIZED

    result = machine.transition(
        BatchState.PSEUDONYMIZED,
        BatchEvent.DELIVERY_SUCCEEDED,
        TransitionContext(residual_count=0, platform_delivered=True),
    )
    assert result.target is BatchState.DELIVERED
    assert result.description


def test_illegal_transition_raises_and_names_allowed_events(
    machine: StateMachine,
) -> None:
    """非法迁移抛明确错误，并说清该状态允许哪些事件。"""
    with pytest.raises(IllegalTransitionError) as excinfo:
        machine.transition(
            BatchState.DETECTED,
            BatchEvent.DELIVERY_SUCCEEDED,
            TransitionContext(),
        )
    message = str(excinfo.value)
    assert "非法迁移" in message
    assert "detected" in message
    assert "application_validated" in message


def test_guard_rejection_raises_distinct_error(machine: StateMachine) -> None:
    """守卫拒绝与非法迁移是两类错误，调用方的处置不同。"""
    with pytest.raises(TransitionRejectedError) as excinfo:
        machine.transition(
            BatchState.DETECTED,
            BatchEvent.APPLICATION_VALIDATED,
            TransitionContext(ethics_approval_no=None, material_count=1),
        )
    assert "缺伦理批件号" in str(excinfo.value)


# ------------------------------------------------------------------- 旁路态


@pytest.mark.parametrize(
    ("bypass_state", "forbidden_event"),
    [
        (BatchState.BLOCKED, BatchEvent.APPLICATION_VALIDATED),
        (BatchState.BLOCKED, BatchEvent.RECOGNITION_COMPLETED),
        (BatchState.SUSPENDED, BatchEvent.RECOGNITION_COMPLETED),
        (BatchState.SUSPENDED, BatchEvent.DELIVERY_SUCCEEDED),
        (BatchState.PENDING_DELIVERY, BatchEvent.DELIVERY_SUCCEEDED),
        (BatchState.PENDING_DELIVERY, BatchEvent.DELIVERY_FAILED),
    ],
)
def test_bypass_states_reject_skips(
    machine: StateMachine, bypass_state: BatchState, forbidden_event: BatchEvent
) -> None:
    """旁路态不得被自动跳过：只有规定事件能迁出。"""
    with pytest.raises(IllegalTransitionError):
        machine.transition(bypass_state, forbidden_event, TransitionContext())


def test_bypass_states_have_only_explicit_escape_hatches(machine: StateMachine) -> None:
    """旁路态的出口都是**明确的恢复事件**，不得被自动跳过。

    ``suspended`` 有两条出口：主索引恢复（``PATIENT_INDEX_RESTORED``）与
    对照索引恢复（``INDEX_STORE_RESTORED``）—— 两条都要「故障已排除」才
    走，且各自有守卫：故障没排除时迁出仍被拒。
    """
    assert machine.outgoing_events(BatchState.BLOCKED) == (
        BatchEvent.APPLICATION_REPAIRED,
    )
    assert set(machine.outgoing_events(BatchState.SUSPENDED)) == {
        BatchEvent.PATIENT_INDEX_RESTORED,
        BatchEvent.INDEX_STORE_RESTORED,
    }
    assert machine.outgoing_events(BatchState.PENDING_DELIVERY) == (
        BatchEvent.DELIVERY_RETRIED,
    )
    # 两条出口都不是「自动跳过」：故障未排除时迁出被拒
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.SUSPENDED,
            BatchEvent.PATIENT_INDEX_RESTORED,
            TransitionContext(patient_index_reachable=False),
        )
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.SUSPENDED,
            BatchEvent.INDEX_STORE_RESTORED,
            TransitionContext(index_store_reachable=False),
        )


def test_blocked_exits_only_by_repair(machine: StateMachine) -> None:
    """补齐批件号后重新投递，才从阻断迁出。"""
    result = machine.transition(
        BatchState.BLOCKED,
        BatchEvent.APPLICATION_REPAIRED,
        TransitionContext(
            ethics_approval_no="EC-2026-0001",
            material_count=1,
        ),
    )
    assert result.target is BatchState.RECOGNIZED


def test_suspended_exits_only_when_index_restored(machine: StateMachine) -> None:
    """主索引恢复可达，批次才回到识别前一步。"""
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.SUSPENDED,
            BatchEvent.PATIENT_INDEX_RESTORED,
            TransitionContext(patient_index_reachable=False),
        )
    result = machine.transition(
        BatchState.SUSPENDED,
        BatchEvent.PATIENT_INDEX_RESTORED,
        TransitionContext(patient_index_reachable=True),
    )
    assert result.target is BatchState.RECOGNIZED


def test_pending_delivery_exits_only_by_successful_retry(
    machine: StateMachine,
) -> None:
    """重投成功才从等重投迁出。"""
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.PENDING_DELIVERY,
            BatchEvent.DELIVERY_RETRIED,
            TransitionContext(residual_count=0, platform_delivered=False),
        )
    result = machine.transition(
        BatchState.PENDING_DELIVERY,
        BatchEvent.DELIVERY_RETRIED,
        TransitionContext(residual_count=0, platform_delivered=True),
    )
    assert result.target is BatchState.DELIVERED


def test_recognition_guard_refuses_when_index_unreachable(
    machine: StateMachine,
) -> None:
    """主索引不可达时不得进入代号化 —— 这就是「不降级为按正则直接脱」。"""
    with pytest.raises(TransitionRejectedError) as excinfo:
        machine.transition(
            BatchState.RECOGNIZED,
            BatchEvent.RECOGNITION_COMPLETED,
            TransitionContext(
                material_count=1,
                recognized_material_count=1,
                patient_index_reachable=False,
            ),
        )
    assert "主索引不可达" in str(excinfo.value)


def test_residual_blocks_delivery(machine: StateMachine) -> None:
    """身份类残留非 0 时不得进入 delivered。"""
    with pytest.raises(TransitionRejectedError) as excinfo:
        machine.transition(
            BatchState.PSEUDONYMIZED,
            BatchEvent.DELIVERY_SUCCEEDED,
            TransitionContext(residual_count=3, platform_delivered=True),
        )
    assert "残留" in str(excinfo.value)


# ------------------------------------------------------------------- 还原分支


def test_restore_requires_two_distinct_approvers(machine: StateMachine) -> None:
    """单人授权不得还原；两人不得同一人。"""
    with pytest.raises(TransitionRejectedError) as excinfo:
        machine.transition(
            BatchState.RESTORE_PENDING,
            BatchEvent.RESTORE_APPROVED,
            TransitionContext(approver_a="伦理办甲", approver_b=None),
        )
    assert "授权人 B" in str(excinfo.value)

    with pytest.raises(TransitionRejectedError) as excinfo:
        machine.transition(
            BatchState.RESTORE_PENDING,
            BatchEvent.RESTORE_APPROVED,
            TransitionContext(approver_a="伦理办甲", approver_b="伦理办甲"),
        )
    assert "同一人" in str(excinfo.value) or "兼任" in str(excinfo.value)

    result = machine.transition(
        BatchState.RESTORE_PENDING,
        BatchEvent.RESTORE_APPROVED,
        TransitionContext(approver_a="伦理办甲", approver_b="信息科乙"),
    )
    assert result.target is BatchState.RESTORED


def test_restore_expired_and_out_of_scope_are_rejected(
    machine: StateMachine,
) -> None:
    """过期与超范围都不得执行还原。"""
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.RESTORE_PENDING,
            BatchEvent.RESTORE_APPROVED,
            TransitionContext(
                approver_a="伦理办甲",
                approver_b="信息科乙",
                authorization_expired=True,
            ),
        )
    with pytest.raises(TransitionRejectedError):
        machine.transition(
            BatchState.RESTORE_PENDING,
            BatchEvent.RESTORE_APPROVED,
            TransitionContext(
                approver_a="伦理办甲",
                approver_b="信息科乙",
                scope_ok=False,
            ),
        )


def test_restore_pending_holds_when_second_approver_missing(
    machine: StateMachine,
) -> None:
    """缺第二授权人时原地挂起（自环），不降级为单人还原。"""
    result = machine.transition(
        BatchState.RESTORE_PENDING,
        BatchEvent.RESTORE_AUTHORIZATION_PENDING,
        TransitionContext(approver_a="伦理办甲", approver_b=None),
    )
    assert result.target is BatchState.RESTORE_PENDING


# ------------------------------------------------------------------ 台账：阻断


def test_missing_ethics_blocks_batch_and_alerts(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """缺伦理批件号 → blocked，并落一条告警（不降级放行）。"""
    intake = load_json_application(_write_application(tmp_path, BLOCKED_APPLICATION))
    assert intake.is_blocked

    record = ledger.apply_intake(intake)
    assert record.state == BatchState.BLOCKED.value
    assert "ethics_approval_no" in record.failure_reason

    alerts = ledger.alerts(record.batch_no)
    assert len(alerts) == 1
    assert alerts[0].code == "application_blocked"
    assert alerts[0].level == "error"
    assert "不降级放行" in alerts[0].message
    # 告警尚未推送出去 —— 如实记 notified=False
    assert alerts[0].notified is False
    assert alerts[0].notify_channel == "pending"


def test_blocked_batch_can_be_repaired_then_released(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """补齐批件号重新投递后，同一批次才从 blocked 迁到 recognized。"""
    blocked = ledger.apply_intake(
        load_json_application(_write_application(tmp_path, BLOCKED_APPLICATION))
    )
    assert blocked.state == BatchState.BLOCKED.value

    fixed_payload = dict(BLOCKED_APPLICATION)
    fixed_payload["ethics_approval_no"] = "EC-2026-0002"
    fixed = tmp_path / "fixed.json"
    fixed.write_text(json.dumps(fixed_payload, ensure_ascii=False), encoding="utf-8")

    repaired = ledger.apply_intake(load_json_application(fixed))
    assert repaired.batch_no == blocked.batch_no
    assert repaired.state == BatchState.RECOGNIZED.value
    assert repaired.ethics_approval_no == "EC-2026-0002"
    # 时间线上留了「阻断 → 补齐后重新投递」两笔
    events = [item.event for item in ledger.timeline(blocked.batch_no)]
    assert events == [
        BatchEvent.APPLICATION_DETECTED.value,
        BatchEvent.APPLICATION_BLOCKED.value,
        BatchEvent.APPLICATION_REPAIRED.value,
    ]


# ------------------------------------------------------------- 台账：挂起


def test_patient_index_unreachable_suspends_batch_and_alerts(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """主索引不可达 → suspended，并落告警；不得按正则直接脱。"""
    intake = load_json_application(_write_application(tmp_path, COMPLETE_APPLICATION))
    record = ledger.apply_intake(intake)
    assert record.state == BatchState.RECOGNIZED.value

    suspended = ledger.apply_recognition(
        record.batch_no,
        material_count=1,
        recognized_material_count=0,
        patient_index_reachable=False,
    )
    assert suspended.state == BatchState.SUSPENDED.value
    assert "主索引不可达" in suspended.failure_reason

    alerts = ledger.alerts(record.batch_no)
    assert [alert.code for alert in alerts] == ["patient_index_unreachable"]
    assert "不得按正则直接脱" in alerts[0].message


def test_suspended_batch_cannot_skip_to_pseudonymized(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """挂起后不得跳过等待直接代号化。"""
    intake = load_json_application(_write_application(tmp_path, COMPLETE_APPLICATION))
    record = ledger.apply_intake(intake)
    ledger.apply_recognition(
        record.batch_no,
        material_count=1,
        recognized_material_count=0,
        patient_index_reachable=False,
    )

    with pytest.raises(IllegalTransitionError):
        ledger.advance(
            record.batch_no,
            BatchEvent.RECOGNITION_COMPLETED,
            TransitionContext(
                material_count=1,
                recognized_material_count=1,
                patient_index_reachable=True,
            ),
        )
    # 状态未被推进
    assert ledger.get_batch(record.batch_no).state == BatchState.SUSPENDED.value


def test_suspended_batch_resumes_after_index_restored(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """主索引恢复后批次回到 recognized，可继续处理。"""
    intake = load_json_application(_write_application(tmp_path, COMPLETE_APPLICATION))
    record = ledger.apply_intake(intake)
    ledger.apply_recognition(
        record.batch_no,
        material_count=1,
        recognized_material_count=0,
        patient_index_reachable=False,
    )
    resumed = ledger.advance(
        record.batch_no,
        BatchEvent.PATIENT_INDEX_RESTORED,
        TransitionContext(patient_index_reachable=True),
    )
    assert resumed.state == BatchState.RECOGNIZED.value


# ----------------------------------------------------------- 台账：落库与留痕


def test_ledger_persists_state_key_artifacts_and_steps(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """状态、幂等键、产物路径、失败原因、当前步骤都落库。"""
    intake = load_json_application(_write_application(tmp_path, COMPLETE_APPLICATION))
    record = ledger.apply_intake(intake)

    ledger.set_idempotency_key(record.batch_no, "idem-KY20260001-abc123")
    ledger.set_artifacts(
        record.batch_no,
        {"redacted": "/var/outbox/KY20260001/M-1.txt", "manifest": "/var/outbox/KY20260001/manifest.jsonl"},
    )
    ledger.set_current_step(record.batch_no, "deliver")
    ledger.complete_step(record.batch_no, "intake")

    stored = ledger.get_batch(record.batch_no)
    assert stored is not None
    assert stored.state == BatchState.RECOGNIZED.value
    assert stored.idempotency_key == "idem-KY20260001-abc123"
    assert stored.artifacts["redacted"].endswith("M-1.txt")
    assert stored.current_step == "deliver"
    assert stored.completed_steps == ("intake",)
    assert stored.ethics_approval_no == "EC-2026-0001"
    assert stored.material_ids == ("M-1",)


def test_ledger_records_receipts_and_access_log(ledger: BatchLedger) -> None:
    """回执与访问留痕都落库，且可按批次查回。"""
    ledger.open_batch("KY20260003", ethics_approval_no="EC-2026-0003")
    ledger.record_receipt(
        "RC-1",
        "KY20260003",
        "delivery",
        {"application_no": "KY20260003", "material_count": 2},
        platform_receipt_id="DS-7788",
    )
    ledger.record_access("KY20260003", "科研数据管理员甲", "restore_request", "申请还原 2 例")

    receipts = ledger.receipts("KY20260003")
    assert len(receipts) == 1
    assert receipts[0].kind == "delivery"
    assert receipts[0].payload["material_count"] == 2
    assert receipts[0].platform_receipt_id == "DS-7788"

    trail = ledger.access_log("KY20260003")
    assert len(trail) == 1
    assert trail[0].actor == "科研数据管理员甲"
    assert trail[0].operation == "restore_request"


def test_ledger_implements_alert_sink(ledger: BatchLedger) -> None:
    """台账实现 AlertSink 协议，可直接接管告警落点。"""
    ledger.open_batch("KY20260004")
    ledger.record(
        BatchAlert(
            batch_no="KY20260004",
            code="residual_identity",
            level="warning",
            count=3,
            message="批次 KY20260004 残留自检未通过：身份类残留 3 处",
            material_ids=("M-1",),
            notified=False,
            notify_channel="pending",
        )
    )
    alerts = ledger.alerts("KY20260004")
    assert len(alerts) == 1
    assert alerts[0].code == "residual_identity"
    assert alerts[0].count == 3
    assert alerts[0].material_ids == ("M-1",)


def test_timeline_records_every_transition(tmp_path: Path, ledger: BatchLedger) -> None:
    """批次时间线按序记录每一步迁移（供 task 40 的 status 子命令渲染）。"""
    intake = load_json_application(_write_application(tmp_path, COMPLETE_APPLICATION))
    record = ledger.apply_intake(intake)
    ledger.apply_recognition(
        record.batch_no,
        material_count=1,
        recognized_material_count=1,
        patient_index_reachable=True,
    )
    ledger.advance(
        record.batch_no,
        BatchEvent.DELIVERY_SUCCEEDED,
        TransitionContext(residual_count=0, platform_delivered=True),
    )

    timeline = ledger.timeline(record.batch_no)
    assert [item.target_state for item in timeline] == [
        BatchState.DETECTED.value,
        BatchState.RECOGNIZED.value,
        BatchState.PSEUDONYMIZED.value,
        BatchState.DELIVERED.value,
    ]
    assert [item.event for item in timeline] == [
        BatchEvent.APPLICATION_DETECTED.value,
        BatchEvent.APPLICATION_VALIDATED.value,
        BatchEvent.RECOGNITION_COMPLETED.value,
        BatchEvent.DELIVERY_SUCCEEDED.value,
    ]
    assert all(item.reason for item in timeline)


def test_ledger_rejects_advance_on_unknown_batch(ledger: BatchLedger) -> None:
    """批次不存在时不得凭空迁移。"""
    with pytest.raises(IllegalTransitionError):
        ledger.advance("KY-不存在", BatchEvent.APPLICATION_VALIDATED, TransitionContext())


def test_ledger_contains_no_patient_identifiers(
    tmp_path: Path, ledger: BatchLedger
) -> None:
    """台账任何一行都不含患者身份串。"""
    leaky = dict(COMPLETE_APPLICATION)
    leaky["materials"] = [
        {
            "material_id": "M-1",
            "kind": "report_text",
            "path": "materials/M-1.txt",
            "patient_id": "P-1001",
            "note": "姓名：张某某 住院号：90000001 手机号：13800138000",
        }
    ]
    path = tmp_path / "leaky.json"
    path.write_text(json.dumps(leaky, ensure_ascii=False), encoding="utf-8")
    intake = load_json_application(path)
    record = ledger.apply_intake(intake)
    ledger.apply_recognition(
        record.batch_no,
        material_count=1,
        recognized_material_count=1,
        patient_index_reachable=True,
    )
    ledger.record_receipt(
        "RC-2", record.batch_no, "delivery", {"material_count": 1}
    )
    ledger.record_access(record.batch_no, "科研数据管理员甲", "run", "跑批")

    dump = json.dumps(
        {
            "batches": [ledger.get_batch(record.batch_no).__dict__],
            "timeline": [item.__dict__ for item in ledger.timeline(record.batch_no)],
            "receipts": [item.__dict__ for item in ledger.receipts(record.batch_no)],
            "access": [item.__dict__ for item in ledger.access_log(record.batch_no)],
            "alerts": [item.to_dict() for item in ledger.alerts(record.batch_no)],
        },
        ensure_ascii=False,
        default=str,
    )
    for identity in IDENTITY_STRINGS:
        assert identity not in dump


def test_default_ledger_path_is_under_project_var() -> None:
    """默认台账落在项目 var/ 下（运行时数据，不进版本库）。"""
    path = default_ledger_path()
    assert path.name == "ledger.sqlite3"
    assert path.parent.name == "var"


def test_default_ledger_path_honours_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """台账路径可由 $RESEARCH_LEDGER_DB 覆盖（守护进程与 CLI 不同工作目录时用）。"""
    monkeypatch.setenv("RESEARCH_LEDGER_DB", str(tmp_path / "custom.sqlite3"))
    assert default_ledger_path() == tmp_path / "custom.sqlite3"


# ------------------------------------------------------------------ 事件判定


def test_intake_and_recognition_event_helpers() -> None:
    """入站与识别阶段的事件判定。"""
    assert (
        intake_event(ethics_approval_no="EC-1", missing_fields=())
        is BatchEvent.APPLICATION_VALIDATED
    )
    assert (
        intake_event(ethics_approval_no=None, missing_fields=())
        is BatchEvent.APPLICATION_BLOCKED
    )
    assert (
        intake_event(ethics_approval_no="EC-1", missing_fields=["materials[0].path"])
        is BatchEvent.APPLICATION_BLOCKED
    )
    assert (
        recognition_event(patient_index_reachable=True)
        is BatchEvent.RECOGNITION_COMPLETED
    )
    assert (
        recognition_event(patient_index_reachable=False)
        is BatchEvent.PATIENT_INDEX_UNREACHABLE
    )
