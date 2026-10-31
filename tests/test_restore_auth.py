"""受控还原的授权闸门验收。

还原是本系统唯一能把原文「拿回来」的路径，所以授权闸门必须比脱敏更严。
本测试盯住七件事：

1. **双人授权**才放行，缺第二授权人**挂起**（原地等签字），**不降级为单人**；
2. **同一人不得兼任**两方授权人；
3. **授权人必须在名单内**（名单为空 = 无人可授权）；
4. **授权必须有时效**：没截止时间的不放行，过期的拒绝；
5. **范围受限**：请求的材料超出授权范围或不在本批已交付清单内，一律拒绝；
6. **拒绝必留痕**：访问留痕 + 回执 + 批次状态三样齐备，且**不含原文**；
7. **拒绝即不还原**：被拒时不产出任何还原件。

拒绝与挂起是两回事，本测试分开盯：挂起是可以补齐的（等签字），拒绝是结论性
的。混成一个「失败」，事后查不出「到底是没人签还是签了不生效」。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.state_machine import (
    BatchEvent,
    BatchState,
    TransitionContext,
)
from research_redact.models import RestoreAuthorization
from research_redact.restore.authority import (
    CODE_APPROVER_NOT_REGISTERED,
    CODE_AUTHORIZATION_EXPIRED,
    CODE_AUTHORIZATION_WINDOW_MISSING,
    CODE_MISSING_APPROVER_A,
    CODE_MISSING_APPROVER_B,
    CODE_SAME_APPROVER,
    CODE_SCOPE_VIOLATION,
    ApproverRegistry,
    AuthorityValidator,
    authorize_window,
)
from research_redact.restore.service import (
    InMemoryMappingIndex,
    RestoreService,
)

#: 固定时钟：授权时效的判定不依赖真实时间
FIXED_NOW = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)

#: 本院授权名单
APPROVERS = ("张主任", "李质控", "王干事")

#: 已脱敏正文（本测试只验授权闸门，正文里没有代号）
REDACTED_TEXT = "患者身份已替换为代号，诊断与剂量原样保留。"

#: 身份串：台账、回执、留痕里都不该出现
IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")


class RecordingPlatform:
    """科研数据平台协议替身（只在测试层）。

    产品代码里是真实 HTTP 客户端（``outbound/research_platform_client.py``）；
    这里只记录还原回执的调用，避免测试碰真实端点。
    """

    def __init__(self, *, fail: Exception | None = None) -> None:
        self.calls: list[dict] = []
        self._fail = fail

    def record_restore_audit(self, **kwargs):
        if self._fail is not None:
            raise self._fail
        self.calls.append(kwargs)
        return SimpleNamespace(
            restore_audit_id="RA-9001",
            dataset_id=kwargs.get("dataset_id", ""),
            restore_request_id=kwargs.get("restore_request_id", ""),
        )


@pytest.fixture()
def ledger(tmp_path: Path):
    """临时台账（用完即弃，不碰项目 var/）。"""
    with BatchLedger(tmp_path / "ledger.db") as instance:
        yield instance


@pytest.fixture()
def delivered_batch(ledger: BatchLedger) -> str:
    """把一个批次推进到 ``delivered``，并落一条交付回执。"""
    batch_no = "KY20260001"
    ledger.open_batch(
        batch_no,
        ethics_approval_no="EC-2026-0001",
        patient_ids=("P-1001",),
        material_ids=("M-1",),
    )
    ledger.advance(
        batch_no,
        BatchEvent.APPLICATION_VALIDATED,
        TransitionContext(ethics_approval_no="EC-2026-0001", material_count=1),
        reason="申请单齐备",
    )
    ledger.advance(
        batch_no,
        BatchEvent.RECOGNITION_COMPLETED,
        TransitionContext(material_count=1, recognized_material_count=1),
        reason="识别完成",
    )
    ledger.advance(
        batch_no,
        BatchEvent.DELIVERY_SUCCEEDED,
        TransitionContext(residual_count=0, platform_delivered=True),
        reason="平台已回执",
    )
    ledger.record_receipt(
        receipt_id="KY20260001.fingerprint",
        batch_no=batch_no,
        kind="delivery",
        payload={"dataset_id": "DS-9001", "application_no": batch_no},
        platform_receipt_id="DS-9001",
    )
    return batch_no


def _authorization(**overrides) -> RestoreAuthorization:
    """构造一份双人、在时效内的还原授权（可逐项覆盖）。"""
    granted_at, expires_at = authorize_window(now=FIXED_NOW, ttl=timedelta(hours=24))
    data = {
        "request_id": "2026-0001",
        "dataset_id": "DS-9001",
        "approver_a": "张主任",
        "approver_b": "李质控",
        "scope": ("M-1",),
        "reason": "伦理核查需要核对第 3 例",
        "granted_at": granted_at,
        "expires_at": expires_at,
    }
    data.update(overrides)
    return RestoreAuthorization(**data)


def _service(ledger: BatchLedger, *, platform=None, approvers=APPROVERS) -> RestoreService:
    """装配一个还原服务（授权名单固定，时钟固定）。"""
    validator = AuthorityValidator(
        ApproverRegistry.from_names(approvers),
        now_fn=lambda: FIXED_NOW,
    )
    return RestoreService(
        index=InMemoryMappingIndex(),
        ledger=ledger,
        platform=platform,
        validator=validator,
        now_fn=lambda: FIXED_NOW,
    )


# --------------------------------------------------------------- 放行分支


def test_双人授权通过并产出还原回执(ledger, delivered_batch) -> None:
    """双人 + 在时效内 + 范围相符 → 放行，产出还原回执并推进状态。"""
    platform = RecordingPlatform()
    service = _service(ledger, platform=platform)

    outcome = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )

    assert outcome.succeeded
    assert outcome.approver_a == "张主任"
    assert outcome.approver_b == "李质控"
    assert outcome.receipt is not None
    assert outcome.receipt.receipt_id == "RR-2026-0001"

    # 批次状态：delivered → restore_pending → restored
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORED

    # 还原回执落台账（kind=restore）
    receipts = [item for item in ledger.receipts(delivered_batch) if item.kind == "restore"]
    assert len(receipts) == 1
    payload = receipts[0].payload
    assert payload["approver_a"] == "张主任"
    assert payload["approver_b"] == "李质控"
    assert payload["dataset_id"] == "DS-9001"
    assert payload["scope"] == ["M-1"]

    # 平台侧还原回执确实被调用了一次，字段与 spec.md 一致
    assert len(platform.calls) == 1
    call = platform.calls[0]
    assert call["restore_request_id"] == "2026-0001"
    assert call["dataset_id"] == "DS-9001"
    assert call["approver_a"] == "张主任"
    assert call["approver_b"] == "李质控"
    assert call["scope"] == ("M-1",)
    assert set(call) == {
        "restore_request_id",
        "dataset_id",
        "approver_a",
        "approver_b",
        "scope",
        "reason",
        "granted_at",
        "expires_at",
        "result_summary",
    }

    # 访问留痕：谁、何时、还原了哪些材料
    access = ledger.access_log(delivered_batch)
    assert any(item.operation == "restore_executed" for item in access)


# --------------------------------------------------------------- 挂起分支


def test_单人授权挂起不降级为单人(ledger, delivered_batch) -> None:
    """缺第二授权人 → 挂起（restore_pending 自环），不还原、不放行。"""
    platform = RecordingPlatform()
    service = _service(ledger, platform=platform)

    outcome = service.execute(
        _authorization(approver_b=""),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )

    assert outcome.pending
    assert outcome.status == "pending"
    assert outcome.code == CODE_MISSING_APPROVER_B
    assert outcome.restored == {}
    assert platform.calls == []

    # 批次停在 restore_pending —— 没有「推进到 restored」
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORE_PENDING

    # 留痕记的是「挂起等签字」，不是「失败」
    access = ledger.access_log(delivered_batch)
    assert any(item.operation == "restore_authorization_pending" for item in access)
    assert not any(item.operation == "restore_executed" for item in access)

    # 只有挂起回执，没有还原回执
    kinds = {item.kind for item in ledger.receipts(delivered_batch)}
    assert "restore_pending" in kinds
    assert "restore" not in kinds


def test_受理请求本身不还原只建待办(ledger, delivered_batch) -> None:
    """只填了授权人 A 的请求：受理为待办，不推进到 restored。"""
    service = _service(ledger)
    outcome = service.request(
        _authorization(approver_b=""),
        batch_no=delivered_batch,
        allowed_scope=("M-1",),
    )
    assert outcome.status == "requested"
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORE_PENDING


# --------------------------------------------------------------- 拒绝分支


def test_两位授权人同一人被拒(ledger, delivered_batch) -> None:
    """同一人兼任两方授权人 → 拒绝，批次转 restore_rejected。"""
    service = _service(ledger)
    outcome = service.execute(
        _authorization(approver_b="张主任"),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_SAME_APPROVER
    assert outcome.restored == {}
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORE_REJECTED


def test_授权人不在名单被拒(ledger, delivered_batch) -> None:
    """授权人 B 不在名单 → 拒绝（不是挂起：名单外的签字不算数）。"""
    service = _service(ledger)
    outcome = service.execute(
        _authorization(approver_b="院外人士"),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_APPROVER_NOT_REGISTERED


def test_授权名单为空时任何人不得通过(ledger, delivered_batch) -> None:
    """名单为空 = 无人可授权；不得默认放行。"""
    service = _service(ledger, approvers=())
    outcome = service.execute(
        _authorization(),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_APPROVER_NOT_REGISTERED


def test_过期授权被拒(ledger, delivered_batch) -> None:
    """授权已过截止时间 → 拒绝。"""
    service = _service(ledger)
    expired = authorize_window(
        now=FIXED_NOW - timedelta(days=2), ttl=timedelta(hours=1)
    )
    outcome = service.execute(
        _authorization(granted_at=expired[0], expires_at=expired[1]),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_AUTHORIZATION_EXPIRED


def test_未设时效的授权被拒(ledger, delivered_batch) -> None:
    """没有截止时间的授权 = 无限期授权 = 不放行。"""
    service = _service(ledger)
    outcome = service.execute(
        _authorization(expires_at=None),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_AUTHORIZATION_WINDOW_MISSING


def test_超范围材料被拒(ledger, delivered_batch) -> None:
    """请求还原的材料不在本批已交付清单内 → 拒绝。"""
    service = _service(ledger)
    outcome = service.execute(
        _authorization(scope=("M-1", "M-9")),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT, "M-9": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_SCOPE_VIOLATION
    assert outcome.restored == {}
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.RESTORE_REJECTED


def test_缺授权人A的请求被拒且不建待办(ledger, delivered_batch) -> None:
    """无人授权的请求连待办都不该建：批次停在 delivered。"""
    service = _service(ledger)
    outcome = service.request(
        _authorization(approver_a=""),
        batch_no=delivered_batch,
        allowed_scope=("M-1",),
    )
    assert outcome.rejected
    assert outcome.code == CODE_MISSING_APPROVER_A
    record = ledger.get_batch(delivered_batch)
    assert record is not None
    assert record.batch_state is BatchState.DELIVERED


def test_被拒后不产出任何还原件(ledger, delivered_batch, tmp_path: Path) -> None:
    """拒绝即不还原：输出目录里不得出现还原件。"""
    service = _service(ledger)
    output_dir = tmp_path / "restore"
    outcome = service.execute(
        _authorization(approver_b="张主任"),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
        output_dir=output_dir,
    )
    assert outcome.rejected
    assert not output_dir.exists() or list(output_dir.iterdir()) == []


# --------------------------------------------------------------- 留痕纪律


def test_拒绝与回执留痕不含原文(ledger, delivered_batch) -> None:
    """回执、访问留痕、告警里都不含任何命中原文。"""
    service = _service(ledger)
    service.execute(
        _authorization(approver_b="张主任"),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    payload = json.dumps(
        [item.payload for item in ledger.receipts(delivered_batch)], ensure_ascii=False
    )
    payload += json.dumps(
        [
            {"actor": item.actor, "operation": item.operation, "detail": item.detail}
            for item in ledger.access_log(delivered_batch)
        ],
        ensure_ascii=False,
    )
    payload += json.dumps(
        [item.to_dict() for item in ledger.alerts(delivered_batch)], ensure_ascii=False
    )
    for secret in IDENTITY_STRINGS:
        assert secret not in payload


def test_拒绝分支留下访问留痕与回执(ledger, delivered_batch) -> None:
    """被拒也要留痕：不然事后查不出「谁试过还原」。"""
    service = _service(ledger)
    service.execute(
        _authorization(approver_b="张主任"),
        batch_no=delivered_batch,
        materials={"M-1": REDACTED_TEXT},
        allowed_scope=("M-1",),
    )
    operations = [item.operation for item in ledger.access_log(delivered_batch)]
    assert "restore_rejected" in operations
    kinds = {item.kind for item in ledger.receipts(delivered_batch)}
    assert "restore_rejected" in kinds
