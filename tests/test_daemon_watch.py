"""守护进程：目录投递触发处理、兜底扫描不重复处理已完批次、投递退避超次。

对应 task 11 的三条验收：

1. 投递目录里放一份申请单 → 守护进程**自动**跑完脱敏并产出脱敏副本与命中
   清单（不需要有人敲命令）。
2. 兜底扫描会把交付目录整个扫一遍，但**已交付的批次不会被重复处理**。
3. 投递遇到 5xx → 指数退避重试；重试超次 → 批次挂 ``pending_delivery``、
   落持久告警并推送（**不静默丢弃**）。

另外覆盖：守护进程常驻入口能跑一轮、缺伦理批件号的批次被阻断、企微推送
通道未配置时如实记为「没推出去」。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research_redact.audit.alerts import RecordingNotifier
from research_redact.audit.ledger import BatchLedger
from research_redact.audit.manifest import ManifestWriter
from research_redact.audit.residual import ResidualChecker
from research_redact.daemon.__main__ import run
from research_redact.daemon.queue import DeliveryError, DeliveryQueue
from research_redact.daemon.runner import BatchRunner
from research_redact.daemon.settings import DaemonSettings
from research_redact.daemon.state_machine import BatchState
from research_redact.daemon.watcher import InboxWatcher
from research_redact.outbound.notifier import WeComNotifier, build_notifier

# 合成的放射报告样例（自造数据，与任何真实患者无关）
MATERIAL_TEXT = """市第一人民医院  放射科检查报告
姓名：张某某      性别：男      年龄：64岁
住院号：90000001   科别：呼吸内科
检查号：CHK0000001  床位：12床
出生日期：1949-12-31  手机号：13800138000
检查所见：
  右肺下叶见磨玻璃结节，大小约 8mm，边界尚清晰。
诊断意见：
  1、2 型糖尿病
建议：
  1、餐后服用盐酸氨溴索口服液 30mL 每日 3 次
（本页为第 2 页）
报告日期：2026-01-05    报告医师：示例医师
"""

IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")


class _FakeClock:
    """可控单调时钟（退避重试的测试要靠它把时间往前拨）。"""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _write_inbox(root: Path, *, application_no: str = "KY20260001", ethics: str = "EC-2026-0001") -> Path:
    """在 ``root`` 下造一份可处理的交付目录。"""
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": application_no,
        "ethics_approval_no": ethics,
        "patient_ids": ["P-1001"],
        "materials": [
            {
                "material_id": "M-1",
                "kind": "report_text",
                "path": "materials/report_001.txt",
                "patient_id": "P-1001",
            }
        ],
    }
    (application_dir / "application.json").write_text(
        json.dumps(application, ensure_ascii=False), encoding="utf-8"
    )
    (application_dir / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT, encoding="utf-8"
    )
    return inbox


def _build(tmp_path: Path, **kwargs) -> tuple[InboxWatcher, BatchRunner, BatchLedger, Path]:
    """装配监听器 / 处理器 / 台账（产物与告警都落在临时目录里）。"""
    inbox = _write_inbox(tmp_path, **kwargs)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    checker = ResidualChecker(sink=_jsonl_sink(tmp_path / "alerts.jsonl"))
    runner = BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        checker=checker,
    )
    return InboxWatcher(inbox), runner, ledger, inbox


def _jsonl_sink(path: Path):
    from research_redact.audit.alerts import JsonlAlertSink

    return JsonlAlertSink(path)


# --------------------------------------------------------------------- 场景 1


def test_目录投递触发一次处理(tmp_path: Path) -> None:
    """目录里一放申请单，守护进程就自动跑完脱敏并落产物。"""
    watcher, runner, ledger, _ = _build(tmp_path)

    events = watcher.poll()
    assert len(events) == 1
    assert events[0].application_no == "KY20260001"

    result = runner.process(events[0], via_event=True)
    assert result.processed is True
    assert result.deliverable is True
    assert result.entries > 0

    # 脱敏副本落盘：身份串被替换 / 清空，病名与剂量原样保留
    redacted = Path(result.artifacts["M-1"]).read_text(encoding="utf-8")
    for secret in IDENTITY_STRINGS:
        assert secret not in redacted
    assert "右肺下叶见磨玻璃结节" in redacted
    assert "30mL" in redacted

    # 命中清单落盘，且**不含命中原文**
    entries = ManifestWriter.read(result.artifacts["manifest"])
    assert len(entries) == result.entries
    payload = json.dumps(entries, ensure_ascii=False)
    for secret in IDENTITY_STRINGS:
        assert secret not in payload

    # 批次状态推进到「已代号化」（投递由队列负责）
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.batch_state is BatchState.PSEUDONYMIZED
    assert record.material_ids == ("M-1",)


def test_事件轮询只报变化过的申请单(tmp_path: Path) -> None:
    """内容没动就不重复报事件；材料补齐后再报一次。"""
    watcher, runner, ledger, inbox = _build(tmp_path)

    assert len(watcher.poll()) == 1
    assert watcher.poll() == ()  # 没有变化 → 没有事件

    runner.process(watcher.applications()[0], via_event=True)

    # 补一份材料 → 目录签名变了 → 再报一次事件
    (inbox / "KY20260001" / "materials" / "report_002.txt").write_text(
        MATERIAL_TEXT, encoding="utf-8"
    )
    changed = watcher.poll()
    assert len(changed) == 1
    assert changed[0].application_no == "KY20260001"


def test_缺伦理批件号的批次被阻断(tmp_path: Path) -> None:
    """缺批件号即阻断，不降级放行。"""
    watcher, runner, ledger, _ = _build(tmp_path, ethics="")
    result = runner.process(watcher.poll()[0], via_event=True)

    assert result.skipped is True
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.batch_state is BatchState.BLOCKED
    alerts = ledger.alerts("KY20260001")
    assert any(alert.code == "application_blocked" for alert in alerts)


# --------------------------------------------------------------------- 场景 2


def test_兜底扫描不重复处理已完批次(tmp_path: Path) -> None:
    """已交付的批次：兜底扫描看得见，但不再处理一遍。"""
    watcher, runner, ledger, _ = _build(tmp_path)
    delivered = _make_deliverer()
    queue = DeliveryQueue(deliver=delivered, ledger=ledger, notifier=RecordingNotifier())

    result = runner.process(watcher.poll()[0], via_event=True)
    outcome = queue.submit(result.batch_no, result.payload)
    assert outcome.delivered is True

    record = ledger.get_batch("KY20260001")
    assert record.batch_state is BatchState.DELIVERED

    # 兜底扫描仍然能看见这份申请单 —— 但处理器判定它不该再处理
    assert len(watcher.applications()) == 1
    processable, reason = runner.is_processable("KY20260001")
    assert processable is False
    assert "delivered" in reason

    # 再跑一次处理：跳过，不动状态、不重跑脱敏
    again = runner.process(watcher.applications()[0], via_event=False)
    assert again.skipped is True
    assert ledger.get_batch("KY20260001").batch_state is BatchState.DELIVERED


def test_守护进程跑一轮_处理一次_再跑不再处理(tmp_path: Path) -> None:
    """常驻入口跑一轮：处理一次；再跑一轮：兜底扫描不重复处理。"""
    inbox = _write_inbox(tmp_path)
    settings = DaemonSettings(
        delivery_dir=inbox,
        output_dir=tmp_path / "outbox",
        ledger_path=tmp_path / "ledger.sqlite3",
        alert_ledger_path=tmp_path / "alerts.jsonl",
        poll_interval=0.01,
        heartbeat_interval=0.01,
    )
    delivered = _make_deliverer()

    first = run(settings, cycles=1, deliver=delivered)
    assert first["processed"] == 1
    assert first["delivered"] == 1

    second = run(settings, cycles=1, deliver=delivered)
    assert second["processed"] == 0
    assert second["delivered"] == 0
    assert second["skipped"] >= 1

    # 只外发过一次
    assert delivered.calls == ["KY20260001"]


def test_进程重启后补投未交付批次(tmp_path: Path) -> None:
    """上一轮没交付的批次，重启后重新进队列补投（不静默丢掉）。"""
    inbox = _write_inbox(tmp_path)
    settings = DaemonSettings(
        delivery_dir=inbox,
        output_dir=tmp_path / "outbox",
        ledger_path=tmp_path / "ledger.sqlite3",
        alert_ledger_path=tmp_path / "alerts.jsonl",
        poll_interval=0.01,
        heartbeat_interval=0.01,
    )

    def failing(batch_no: str, payload) -> bool:
        raise DeliveryError("科研数据平台暂时不可用", status=503)

    first = run(settings, cycles=1, deliver=failing)
    assert first["processed"] == 1
    assert first["delivered"] == 0

    # 批次停在「已代号化、尚未交付」
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    assert ledger.get_batch("KY20260001").batch_state is BatchState.PSEUDONYMIZED
    ledger.close()

    attempts: list[str] = []

    def working(batch_no: str, payload) -> bool:
        attempts.append(batch_no)
        return True

    second = run(settings, cycles=1, deliver=working)
    assert attempts == ["KY20260001"]
    assert second["delivered"] == 1
    # 补投后不再重跑脱敏
    assert second["processed"] == 0


# --------------------------------------------------------------------- 场景 3


def test_投递5xx后退避重试且超次挂起(tmp_path: Path) -> None:
    """平台 5xx → 退避重试；超次 → pending_delivery + 持久告警 + 推送。"""
    watcher, runner, ledger, _ = _build(tmp_path)
    notifier = RecordingNotifier()
    clock = _FakeClock()
    attempts: list[str] = []

    def failing(batch_no: str, payload) -> bool:
        attempts.append(batch_no)
        raise DeliveryError("科研数据平台暂时不可用", status=503)

    queue = DeliveryQueue(
        deliver=failing,
        ledger=ledger,
        notifier=notifier,
        max_retries=2,
        backoff_base=2.0,
        clock=clock,
    )

    result = runner.process(watcher.poll()[0], via_event=True)
    assert result.deliverable is True

    # 第 1 次：立刻试，退避 2s
    outcome = queue.submit(result.batch_no, result.payload)
    assert outcome.delivered is False
    assert outcome.attempts == 1
    assert outcome.next_attempt_in == 2.0
    assert queue.run_due() == ()  # 还没到点，不重试

    # 第 2 次：退避 4s
    clock.advance(2.0)
    outcome = queue.run_due()[0]
    assert outcome.attempts == 2
    assert outcome.next_attempt_in == 4.0

    # 第 3 次：超次 → 挂起
    clock.advance(4.0)
    outcome = queue.run_due()[0]
    assert outcome.exhausted is True
    assert outcome.delivered is False
    assert len(attempts) == 3

    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert record.batch_state is BatchState.PENDING_DELIVERY

    # 落了一条持久告警（不静默丢弃）
    alerts = ledger.alerts("KY20260001")
    exhausted = [alert for alert in alerts if alert.code == "delivery_exhausted"]
    assert len(exhausted) == 1
    assert exhausted[0].level == "error"
    assert exhausted[0].notified is True
    assert exhausted[0].notify_channel == "recording"

    # 推送内容说清了「挂起等重投」
    assert notifier.messages
    batch_no, message = notifier.messages[-1]
    assert batch_no == "KY20260001"
    assert "挂起" in message

    # 告警文案不含任何命中原文
    for secret in IDENTITY_STRINGS:
        assert secret not in exhausted[0].message
        assert secret not in message


def test_投递通道未配置时批次挂起而不是假装交付(tmp_path: Path) -> None:
    """没有投递客户端 → 明确失败并挂起，不静默改指本地替身。"""
    watcher, runner, ledger, _ = _build(tmp_path)
    queue = DeliveryQueue(ledger=ledger, notifier=RecordingNotifier())

    result = runner.process(watcher.poll()[0], via_event=True)
    outcome = queue.submit(result.batch_no, result.payload)

    assert outcome.delivered is False
    assert outcome.attempts == 1
    assert "未配置" in outcome.reason or "尚未接入" in outcome.reason
    record = ledger.get_batch("KY20260001")
    assert record.batch_state is BatchState.PSEUDONYMIZED  # 还没超次，仍在队列里


# --------------------------------------------------------------------- 推送通道


class _FakeResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> dict:
        return self._body


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    def post(self, url: str, json: dict):
        self.calls.append((url, json))
        return self.response


def test_企微推送_成功与失败都要如实返回() -> None:
    ok_client = _FakeClient(_FakeResponse(200, {"errcode": 0, "errmsg": "ok"}))
    notifier = WeComNotifier("https://example.invalid/hook", client=ok_client)
    assert notifier.configured is True
    assert notifier.notify("批次 KY20260001 投递退避超次，已挂起等重投", batch_no="KY20260001") is True
    url, body = ok_client.calls[0]
    assert url == "https://example.invalid/hook"
    assert body["msgtype"] == "text"
    assert "KY20260001" in body["text"]["content"]

    # HTTP 200 但 errcode 非 0 —— 企业微信侧的失败，不能当成功
    err_client = _FakeClient(_FakeResponse(200, {"errcode": 93000, "errmsg": "invalid webhook url"}))
    failing = WeComNotifier("https://example.invalid/hook", client=err_client)
    assert failing.notify("x", batch_no="KY20260001") is False

    # 5xx 同样不算推出去
    http_client = _FakeClient(_FakeResponse(502, {}))
    failing2 = WeComNotifier("https://example.invalid/hook", client=http_client)
    assert failing2.notify("x", batch_no="KY20260001") is False


def test_推送通道未配置时如实记为未推送() -> None:
    notifier = build_notifier("")
    assert notifier.channel == "pending"
    assert notifier.notify("x", batch_no="KY20260001") is False


# --------------------------------------------------------------------- 辅助


def _make_deliverer():
    class _Deliverer:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def deliver(self, batch_no: str, payload) -> bool:
            self.calls.append(batch_no)
            return True

    return _Deliverer()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
