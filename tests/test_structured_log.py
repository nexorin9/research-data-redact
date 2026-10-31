"""结构化运行日志、心跳与批次时间线（task 40）。

覆盖三件信息科真正靠它们排查问题的事：

1. **日志字段齐备** —— 每条日志都带齐 8 个标准字段（时间 / 级别 / 事件 /
   批次号 / 材料数 / 状态 / 耗时 / 错误码），不适用时写 ``null`` 而不是缺字段；
   日志**不含命中原文**（与命中清单同一条红线）。
2. **心跳在测试周期内出现** —— 心跳带进程存活、待投递队列长度与最近批次状态，
   运维看一眼就知道进程还在干活还是卡住了。
3. **时间线按序记录每一步迁移** —— 每一道状态迁移都带时间戳与原因，落在台账里，
   可按批次导出，CLI ``status`` 与守护进程看的是同一份。
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon import ops
from research_redact.daemon.__main__ import run
from research_redact.daemon.settings import DaemonSettings
from research_redact.logging_setup import (
    STANDARD_FIELDS,
    Stopwatch,
    StructuredLogger,
    build_record,
    describe_error,
    emit,
    error_code_for,
)

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


def _write_inbox(root: Path, *, application_no: str = "KY20260001") -> Path:
    """在 ``root`` 下造一份可处理的交付目录。"""
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": application_no,
        "ethics_approval_no": "EC-2026-0001",
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


def _settings(tmp_path: Path, inbox: Path, **overrides) -> DaemonSettings:
    """守护进程配置（全部落临时目录）。"""
    base = {
        "delivery_dir": inbox,
        "output_dir": tmp_path / "outbox",
        "ledger_path": tmp_path / "ledger.sqlite3",
        "alert_ledger_path": tmp_path / "alerts.jsonl",
        "poll_interval": 0.01,
        "heartbeat_interval": 0.01,
    }
    base.update(overrides)
    return DaemonSettings(**base)


def _deliver_ok(batch_no: str, payload) -> bool:
    """投递出口替身（只测试层用；产品代码走真实客户端）。"""
    return True


def _records(captured: str) -> list[dict]:
    """把捕获到的输出解析成日志记录（跳过不是 JSON 的行）。"""
    out: list[dict] = []
    for line in captured.splitlines():
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            out.append(json.loads(text))
        except json.JSONDecodeError:
            continue
    return out


def _by_event(records: list[dict], event: str) -> list[dict]:
    return [item for item in records if item.get("event") == event]


# --------------------------------------------------------------------- 日志字段


def test_标准字段恒定存在_不适用写null() -> None:
    """8 个标准字段每条都在；不适用时写 null，而不是缺这个键。"""
    assert STANDARD_FIELDS == (
        "ts",
        "level",
        "event",
        "batch_no",
        "materials",
        "state",
        "duration_ms",
        "error_code",
    )
    record = build_record("some_event")
    for field in STANDARD_FIELDS:
        assert field in record, f"标准字段缺失：{field}"
    assert record["event"] == "some_event"
    assert record["batch_no"] is None
    assert record["materials"] is None
    assert record["duration_ms"] is None
    assert record["error_code"] is None
    # 时间是 ISO 8601（UTC），可解析
    from datetime import datetime

    assert datetime.fromisoformat(record["ts"]) is not None


def test_日志输出一行一条JSON_字段齐备() -> None:
    """一条日志 = 一行 JSON；标准字段齐备，额外字段追加在后面。"""
    stream = io.StringIO()
    logger = StructuredLogger(stream)
    written = logger.emit(
        "batch_processed",
        batch_no="KY20260001",
        materials=3,
        state="pseudonymized",
        duration_ms=12.5,
        entries=7,
    )
    assert written["batch_no"] == "KY20260001"
    assert written["materials"] == 3
    assert written["state"] == "pseudonymized"
    assert written["duration_ms"] == 12.5
    assert written["entries"] == 7

    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    for field in STANDARD_FIELDS:
        assert field in parsed
    assert parsed["entries"] == 7


def test_额外字段不能覆盖标准字段() -> None:
    """标准字段由具名参数决定；额外字段只往后追加，不会顶掉标准字段。"""
    record = build_record("evt", level="error", batch_no="A", extra="x")
    assert record["level"] == "error"
    assert record["batch_no"] == "A"
    assert record["extra"] == "x"
    assert list(record)[: len(STANDARD_FIELDS)] == list(STANDARD_FIELDS)


def test_耗时测量可用() -> None:
    """Stopwatch 给出毫秒级耗时。"""
    with Stopwatch() as watch:
        sum(range(10000))
    assert watch.ms >= 0


def test_错误码按异常分类() -> None:
    """错误码：出站异常用自带类别，其余按异常类型兜底。"""

    class _Boom(RuntimeError):
        pass

    assert error_code_for(_Boom("x")) == "internal_error"

    class _WithCategory(RuntimeError):
        category = "timeout"

    assert error_code_for(_WithCategory("x")) == "timeout"
    assert "_Boom" in describe_error(_Boom("boom"))


def test_模块级emit走默认出口(capsys: pytest.CaptureFixture) -> None:
    """模块级 emit 写 stdout（一行一条 JSON）。"""
    emit("unit_test_event", batch_no="KY-X")
    captured = capsys.readouterr()
    records = _records(captured.out)
    assert len(records) == 1
    assert records[0]["event"] == "unit_test_event"
    assert records[0]["batch_no"] == "KY-X"


# --------------------------------------------------------------------- 守护进程日志


def test_守护进程日志带齐批次材料状态耗时(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """守护进程跑一轮：batch_processed 日志带批次号、材料数、状态与耗时。"""
    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    run(settings, cycles=1, deliver=_deliver_ok)

    captured = capsys.readouterr()
    records = _records(captured.out)
    processed = _by_event(records, "batch_processed")
    assert len(processed) == 1
    entry = processed[0]
    for field in STANDARD_FIELDS:
        assert field in entry, f"标准字段缺失：{field}"
    assert entry["batch_no"] == "KY20260001"
    assert entry["materials"] == 1
    assert entry["state"] == "pseudonymized"
    assert isinstance(entry["duration_ms"], (int, float))
    assert entry["duration_ms"] >= 0
    assert entry["entries"] == 5


def test_守护进程日志不含命中原文(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """日志不含患者身份串（与命中清单同一条红线）。"""
    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    run(settings, cycles=1, deliver=_deliver_ok)

    captured = capsys.readouterr()
    for raw in IDENTITY_STRINGS:
        assert raw not in captured.out, f"日志里漏出了身份串：{raw}"


def test_心跳在测试周期内出现并带队列与最近批次状态(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """心跳按固定间隔打，带进程存活、队列长度与最近批次状态。"""
    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox, heartbeat_interval=0.01)
    run(settings, cycles=2, deliver=_deliver_ok)

    captured = capsys.readouterr()
    records = _records(captured.out)
    beats = _by_event(records, "heartbeat")
    assert beats, "测试周期内没有出现心跳"
    beat = beats[-1]
    for field in STANDARD_FIELDS:
        assert field in beat
    assert beat["level"] == "info"
    # 队列长度（待投递队列）与最近批次状态都报出来
    assert isinstance(beat["queue"], int)
    assert "pending_batches" in beat
    assert beat["batch_no"] == "KY20260001"
    # 第一拍报的是「在飞」时的状态，第二拍批次已交付 —— 心跳跟着批次走
    assert beats[0]["state"] == "pseudonymized"
    assert beat["state"] == "delivered"
    # 进程存活标记：起止事件都打出来了
    assert _by_event(records, "daemon_started")
    assert _by_event(records, "daemon_stopped")


def test_批次报错时日志带错误码(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """处理抛异常：batch_error 日志带错误码与错误级别，进程不退出。"""
    from research_redact.daemon.runner import BatchRunner
    from research_redact.ingest.application import BlockedApplicationError

    def _raise(self, application, *, via_event=False):
        raise BlockedApplicationError("缺伦理批件号：该批次不得交付")

    monkeypatch.setattr(BatchRunner, "process", _raise)

    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    summary = run(settings, cycles=1, deliver=_deliver_ok)

    captured = capsys.readouterr()
    records = _records(captured.out)
    errors = _by_event(records, "batch_error")
    assert errors, "处理抛错应当打出 batch_error 日志"
    entry = errors[0]
    assert entry["level"] == "error"
    assert entry["error_code"] == "application_blocked"
    assert entry["batch_no"] == "KY20260001"
    assert isinstance(entry["duration_ms"], (int, float))
    assert entry["error"]
    # 守护进程不因为一份坏材料就退出
    assert summary["errors"] >= 1
    assert _by_event(records, "daemon_stopped")


# --------------------------------------------------------------------- 批次时间线


def test_时间线按序记录每一步迁移(tmp_path: Path) -> None:
    """每一道状态迁移都落流水，带时间戳与原因，且按发生顺序排列。"""
    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    run(settings, cycles=1, deliver=_deliver_ok)

    ledger = BatchLedger(settings.ledger_path)
    try:
        timeline = ledger.timeline("KY20260001")
    finally:
        ledger.close()

    assert timeline, "时间线为空"
    states = [item.target_state for item in timeline]
    assert states == ["detected", "recognized", "pseudonymized", "delivered"]
    # 时间戳不倒流
    stamps = [item.created_at for item in timeline]
    assert stamps == sorted(stamps)
    # 每一步都带事件名
    events = [item.event for item in timeline]
    assert events == [
        "application_detected",
        "application_validated",
        "recognition_completed",
        "delivery_succeeded",
    ]
    # 每一步都记了原因（时间线不是空的壳）
    for item in timeline:
        assert item.reason, f"迁移 {item.event} 没记原因"


def test_时间线可按批次导出(tmp_path: Path) -> None:
    """导出 JSON：步骤数、时间戳、原因都在，且不含患者原文。"""
    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    run(settings, cycles=1, deliver=_deliver_ok)

    ledger = BatchLedger(settings.ledger_path)
    try:
        target = ops.export_timeline(ledger, "KY20260001", tmp_path / "out" / "timeline.json")
    finally:
        ledger.close()

    assert target.is_file()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["batch_no"] == "KY20260001"
    assert payload["steps"] == 4
    assert len(payload["timeline"]) == 4
    assert [step["target_state"] for step in payload["timeline"]] == [
        "detected",
        "recognized",
        "pseudonymized",
        "delivered",
    ]
    for step in payload["timeline"]:
        assert step["created_at"]
        assert step["event"]
    raw = target.read_text(encoding="utf-8")
    for identity in IDENTITY_STRINGS:
        assert identity not in raw


def test_cli_status打印时间线并可导出(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """CLI status 与守护进程共用同一份排版；--export-timeline 导出同一个时间线。"""
    from research_redact.cli import main

    inbox = _write_inbox(tmp_path)
    settings = _settings(tmp_path, inbox)
    run(settings, cycles=1, deliver=_deliver_ok)

    export_path = tmp_path / "out" / "timeline.json"
    code = main(
        [
            "status",
            "--batch",
            "KY20260001",
            "--ledger",
            str(settings.ledger_path),
            "--export-timeline",
            str(export_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert "时间线（4 步）" in captured.out
    assert "detected" in captured.out
    assert "delivered" in captured.out
    assert "时间线已导出" in captured.out
    assert export_path.is_file()
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    assert payload["steps"] == 4


def test_cli_status导出必须指定批次(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """不指定批次就不导出（并给出明确原因 + 非 0 退出码）。"""
    from research_redact.cli import main

    code = main(
        [
            "status",
            "--ledger",
            str(tmp_path / "ledger.sqlite3"),
            "--export-timeline",
            str(tmp_path / "timeline.json"),
        ]
    )
    assert code != 0
    captured = capsys.readouterr()
    assert "--batch" in captured.err
