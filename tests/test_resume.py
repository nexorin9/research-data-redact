"""断点续跑与崩溃恢复。

科研交付是**长链条**：管理员投材料 → 守护进程脱敏 → 残留自检 → 交平台 →
平台回执。链条中间任何一环都可能断电、被 kill、机器重启。这一组测试盯住
两件事：

1. **识别完成后崩溃 → 续跑不重跑识别** —— 守护进程重启后从最后一步接上，
   复用上一轮的脱敏产物。重跑识别不只是白跑一遍：一致代号取自进程内的
   对照索引，重跑会拿到另一组代号，同一患者在前后两批材料里对不上。
2. **投递成功后回执未落库 → 数据集创建计数仍为 1** —— 平台侧**已经有**
   这个数据集了（崩在「平台收下」与「回执落库」之间）。续跑以**同一把幂等键**
   确认交付，平台按键去重，不会产生第二个数据集。

外加三条「续跑不许凑合」的守卫：源材料变了 / 产物被动过 / 投递记录没登记全，
任何一条成立都**重跑识别**，不拿旧产物交差。
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

import research_redact.daemon.runner as runner_module
from research_redact.audit.alerts import JsonlAlertSink
from research_redact.audit.ledger import BatchLedger
from research_redact.audit.residual import ResidualChecker
from research_redact.daemon.__main__ import run
from research_redact.daemon.queue import DeliveryQueue
from research_redact.daemon.runner import BatchRunner
from research_redact.daemon.settings import DaemonSettings
from research_redact.daemon.state_machine import BatchState
from research_redact.daemon.watcher import InboxApplication, InboxWatcher
from research_redact.outbound.research_platform_client import ResearchPlatformClient

PLATFORM_BASE = "https://research-data.example.internal"
PLATFORM_TOKEN = "platform-token-xyz"
KEY_ID = "key-2026-10"

#: 合成放射报告样例（自造数据，与任何真实患者无关）。
MATERIAL_TEXT = """市第一人民医院  放射科检查报告
姓名：张某某      性别：男      年龄：64岁
住院号：90000001   科别：呼吸内科
检查号：CHK0000001  床位：12床
出生日期：1949-12-31  手机号：13800138000
检查所见：
  右肺下叶见磨玻璃结节，大小约 8mm，边界尚清晰。
诊断意见：
  1、2 型糖尿病
（本页为第 2 页）
报告日期：2026-01-05    报告医师：示例医师
"""

#: 交付体与幂等键里绝不该出现的患者原文。
RAW_TEXT_SAMPLES = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")

#: 投递产物里**允许**出现的材料键片段：spec.md 把材料键定义成「申请单号-院内
#: 检查号-材料序号」三元组，检查号是材料键的一部分（业务关联键，不是命中原文）。
#: 正文里的检查号早已被替换成占位符 —— 这里只放行材料键里那一处。
DELIVERY_KEY_SAMPLES = ("CHK0000001",)

#: 扫投递产物（载荷 / 告警文案 / 清单行）用的患者原文口径。
DELIVERY_RAW_TEXT_SAMPLES = tuple(
    sample for sample in RAW_TEXT_SAMPLES if sample not in DELIVERY_KEY_SAMPLES
)


class IdempotentPlatform:
    """科研数据平台协议替身：**按 Idempotency-Key 去重**。

    平台侧契约（spec.md「最小数据格式与字段要求」）：同一把键重放 = 同一次
    交付，返回同一个 ``dataset_id``，**不产生第二个数据集**。

    这一层是平台的职责；本测试要盯的是**客户端**：同一批材料必须始终带
    同一把键 —— 键变了，平台就会当成新的一批再收一次。
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.datasets: dict[str, str] = {}
        self.created = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = request.headers.get("idempotency-key", "")
        if key not in self.datasets:
            self.created += 1
            self.datasets[key] = f"DS-{self.created:04d}"
        dataset_id = self.datasets[key]
        return httpx.Response(
            200,
            json={
                "dataset_id": dataset_id,
                "application_no": "KY20260001",
                "material_count": 1,
                "receipt_id": f"RC-{dataset_id}",
                "accepted_at": "2026-10-31T08:00:00Z",
            },
        )

    @property
    def calls(self) -> int:
        return len(self.requests)

    def keys(self) -> list[str]:
        """历次请求的 Idempotency-Key。"""
        return [request.headers.get("idempotency-key", "") for request in self.requests]


def _write_inbox(root: Path, *, application_no: str = "KY20260001") -> Path:
    """在 ``root`` 下造一份可处理的交付目录（一份申请单 + 一份材料）。"""
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    application = {
        "application_no": application_no,
        "ethics_approval_no": "EC-2026-0001",
        "patient_ids": ["P-1001"],
        "materials": [
            {
                "material_id": "KY20260001-CHK0000001-01",
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


def _checker(tmp_path: Path, ledger: BatchLedger) -> ResidualChecker:
    """残留自检器（告警落临时目录，批次摘要落台账）。"""
    return ResidualChecker(
        sink=JsonlAlertSink(tmp_path / "alerts.jsonl"),
        summary_sink=ledger,
    )


def _runner(tmp_path: Path, ledger: BatchLedger) -> BatchRunner:
    """批次处理器（产物落临时目录）。"""
    return BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        checker=_checker(tmp_path, ledger),
    )


def _client(platform: IdempotentPlatform, ledger: BatchLedger) -> ResearchPlatformClient:
    """科研数据平台客户端（协议替身只在测试层）。"""
    return ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=httpx.Client(transport=httpx.MockTransport(platform)),
        ledger=ledger,
        key_id=KEY_ID,
        # 崩溃恢复路径要等「另一个执行者」交完；测试里把等待压到 0.2 秒。
        idempotency_wait_seconds=0.2,
        idempotency_poll_seconds=0.05,
    )


@pytest.fixture()
def redaction_calls(monkeypatch):
    """数一数脱敏主路径真跑了几次（识别有没有被重跑）。"""
    calls: list[str] = []
    original = runner_module.redact_batch

    def counting(*args, **kwargs):
        calls.append(str(args[0]) if args else str(kwargs.get("batch_no", "")))
        return original(*args, **kwargs)

    monkeypatch.setattr(runner_module, "redact_batch", counting)
    return calls


def _settings(tmp_path: Path, inbox: Path) -> DaemonSettings:
    return DaemonSettings(
        delivery_dir=inbox,
        output_dir=tmp_path / "outbox",
        ledger_path=tmp_path / "ledger.sqlite3",
        alert_ledger_path=tmp_path / "alerts.jsonl",
        poll_interval=0.01,
        heartbeat_interval=0.01,
    )


# ------------------------------------------------------- 场景 1：识别后崩溃


def test_识别完成后崩溃续跑不重跑识别(tmp_path: Path, redaction_calls) -> None:
    """崩在识别之后：续跑复用上一轮的脱敏产物，**不重跑识别**。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    # 第一轮：识别 + 处置 + 残留自检 + 落产物，全部做完（崩在投递之前）
    first = runner.process(application, via_event=True)
    assert first.processed is True
    assert first.deliverable is True
    assert first.resumed is False
    assert len(redaction_calls) == 1

    manifest_before = Path(first.artifacts["manifest"]).read_text(encoding="utf-8")
    redacted_before = Path(first.artifacts["KY20260001-CHK0000001-01"]).read_text(encoding="utf-8")

    # 重启：新的台账连接 + 新的处理器（= 另一个进程）
    ledger2 = BatchLedger(tmp_path / "ledger.sqlite3")
    runner2 = _runner(tmp_path, ledger2)
    second = runner2.process(application, via_event=True)

    # 识别没有重跑
    assert len(redaction_calls) == 1
    # 走的是续跑路径，产物原样复用
    assert second.resumed is True
    assert second.deliverable is True
    assert second.skipped is False
    assert second.entries == first.entries
    assert Path(second.artifacts["manifest"]).read_text(encoding="utf-8") == manifest_before
    assert Path(second.artifacts["KY20260001-CHK0000001-01"]).read_text(encoding="utf-8") == redacted_before
    # 批次身份不变：同一批材料 = 同一把幂等键
    assert second.payload["idempotency_key"] == first.payload["idempotency_key"]
    assert second.payload["material_fingerprint"] == first.payload["material_fingerprint"]
    assert second.payload["materials"] == first.payload["materials"]

    # 复用旧产物这件事要留痕
    accesses = ledger2.access_log("KY20260001")
    assert any(item.operation == "batch_resumed" for item in accesses)

    # 留痕与载荷里都没有患者原文
    for item in accesses:
        for secret in RAW_TEXT_SAMPLES:
            assert secret not in item.detail
    blob = json.dumps(second.payload, ensure_ascii=False)
    for secret in DELIVERY_RAW_TEXT_SAMPLES:
        assert secret not in blob
    ledger.close()
    ledger2.close()


def test_守护进程重启后补投不重跑识别(tmp_path: Path, redaction_calls) -> None:
    """崩在「识别完成、还没投递」：守护进程重启后直接补投，识别只跑过一次。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    result = runner.process(application, via_event=True)
    assert result.deliverable is True
    assert len(redaction_calls) == 1
    ledger.close()

    # 重启守护进程：启动即补投上一轮没交付的批次
    platform = IdempotentPlatform()
    client = _client(platform, BatchLedger(tmp_path / "ledger.sqlite3"))
    summary = run(
        _settings(tmp_path, inbox),
        cycles=1,
        deliver=client.deliver,
    )

    assert summary["delivered"] == 1
    assert summary["processed"] == 0  # 没有重跑识别
    assert len(redaction_calls) == 1
    assert platform.calls == 1
    assert platform.keys() == [result.payload["idempotency_key"]]


def test_崩在投递登记之前要重跑识别(tmp_path: Path, redaction_calls) -> None:
    """崩在「产物已落盘、幂等键还没登记」：记录交不出完整交付体 → 重跑识别。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    # 模拟崩溃：产物已落盘，幂等键登记时炸掉
    original = ledger.set_idempotency_key

    def crashing(batch_no: str, key: str) -> None:
        raise RuntimeError("模拟崩溃：幂等键登记前进程被杀")

    ledger.set_idempotency_key = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        runner.process(application, via_event=True)
    ledger.set_idempotency_key = original  # type: ignore[method-assign]

    assert len(redaction_calls) == 1
    # 记录不完整：产物在，但幂等键没登记，状态还停在「已校验」
    partial = ledger.get_batch("KY20260001")
    assert partial is not None
    assert partial.batch_state is BatchState.RECOGNIZED
    assert partial.idempotency_key == ""
    assert partial.artifacts.get("manifest")

    # 重启：补投路径跳过记录不完整的批次，兜底扫描接手重跑
    platform = IdempotentPlatform()
    client = _client(platform, BatchLedger(tmp_path / "ledger.sqlite3"))
    summary = run(_settings(tmp_path, inbox), cycles=1, deliver=client.deliver)

    assert len(redaction_calls) == 2  # 记录不完整 → 重跑识别补齐
    assert summary["delivered"] == 1
    assert platform.calls == 1
    delivered = BatchLedger(tmp_path / "ledger.sqlite3").get_batch("KY20260001")
    assert delivered is not None
    assert delivered.batch_state is BatchState.DELIVERED
    ledger.close()


def test_源材料变了不复用旧产物(tmp_path: Path, redaction_calls) -> None:
    """管理员换了材料内容 → 指纹变了 → 是新的一批，重跑识别，不复用旧产物。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    first = runner.process(application, via_event=True)
    assert len(redaction_calls) == 1

    # 换掉源材料（同批号、同材料 ID、内容不同）
    (inbox / "KY20260001" / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT.replace("示例医师", "示例医师乙"), encoding="utf-8"
    )

    ledger2 = BatchLedger(tmp_path / "ledger.sqlite3")
    runner2 = _runner(tmp_path, ledger2)
    second = runner2.process(application, via_event=True)

    assert len(redaction_calls) == 2  # 重跑了
    assert second.resumed is False
    assert second.payload["idempotency_key"] != first.payload["idempotency_key"]
    ledger.close()
    ledger2.close()


def test_产物被动过不复用旧产物(tmp_path: Path, redaction_calls) -> None:
    """磁盘上的脱敏副本被改过 → 摘要对不上 → 重跑识别，不拿被改过的产物交。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    first = runner.process(application, via_event=True)
    assert len(redaction_calls) == 1

    # 手工改一下产物（摘要对不上了）
    target = Path(first.artifacts["KY20260001-CHK0000001-01"])
    target.write_text(target.read_text(encoding="utf-8") + "\n（手工补注）\n", encoding="utf-8")

    ledger2 = BatchLedger(tmp_path / "ledger.sqlite3")
    runner2 = _runner(tmp_path, ledger2)
    second = runner2.process(application, via_event=True)

    assert len(redaction_calls) == 2  # 重跑了
    assert second.resumed is False
    # 重跑后的产物是干净的：手工补注不在里面
    assert "手工补注" not in Path(second.artifacts["KY20260001-CHK0000001-01"]).read_text(encoding="utf-8")
    ledger.close()
    ledger2.close()


# --------------------------------------------------- 场景 2：投递后回执未落库


def test_投递后崩溃时数据集创建计数仍为1(tmp_path: Path) -> None:
    """崩在「平台已收下、回执未落库」：续跑以同一把键确认交付，数据集仍是 1 个。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    result = runner.process(application, via_event=True)
    payload = result.payload
    key = payload["idempotency_key"]

    platform = IdempotentPlatform()
    client = _client(platform, ledger)

    # 模拟崩溃：平台收下了，回执落库时进程被杀
    def crashing(*args, **kwargs):
        raise RuntimeError("模拟崩溃：平台已收下，回执未落库")

    ledger.record_receipt = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        client.deliver("KY20260001", payload)

    # 平台侧已经有这个数据集了；本地没有回执
    assert platform.created == 1
    assert ledger.get_receipt(key) is None
    claim = ledger.get_idempotency_key(key)
    assert claim is not None
    assert claim.is_delivered is False

    # 重启：新台账连接 + 新客户端，补投
    ledger2 = BatchLedger(tmp_path / "ledger.sqlite3")
    client2 = _client(platform, ledger2)
    queue = DeliveryQueue(deliver=client2.deliver, ledger=ledger2)
    outcome = queue.submit("KY20260001", payload)

    assert outcome.delivered is True
    # 数据集创建计数仍是 1 —— 平台按同一把键去重了
    assert platform.created == 1
    # 两次请求带的是同一把幂等键（键变了平台就会当成新的一批）
    assert platform.calls == 2
    assert platform.keys() == [key, key]
    # 回执补落下来了，幂等键标成已交付
    receipt = ledger2.get_receipt(key)
    assert receipt is not None
    assert receipt.payload["dataset_id"] == "DS-0001"
    assert ledger2.get_idempotency_key(key).is_delivered is True
    assert ledger2.get_batch("KY20260001").batch_state is BatchState.DELIVERED
    ledger.close()
    ledger2.close()


def test_回执已落库时复用回执不重复外发(tmp_path: Path) -> None:
    """崩在「回执已落库、认领标记还没标已交付」：复用回执，一个请求都不多发。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    result = runner.process(application, via_event=True)
    payload = result.payload
    key = payload["idempotency_key"]

    platform = IdempotentPlatform()
    client = _client(platform, ledger)

    def crashing(*args, **kwargs):
        raise RuntimeError("模拟崩溃：回执已落库，认领标记未更新")

    ledger.mark_idempotency_delivered = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        client.deliver("KY20260001", payload)

    # 回执在，认领还是「已认领未交付」
    assert ledger.get_receipt(key) is not None
    assert ledger.get_idempotency_key(key).is_delivered is False
    assert platform.created == 1

    # 重启补投：复用已有回执，不再外发
    ledger2 = BatchLedger(tmp_path / "ledger.sqlite3")
    client2 = _client(platform, ledger2)
    queue = DeliveryQueue(deliver=client2.deliver, ledger=ledger2)
    outcome = queue.submit("KY20260001", payload)

    assert outcome.delivered is True
    assert platform.calls == 1  # 没有第二次外发
    assert platform.created == 1
    # 认领状态被补齐成已交付
    assert ledger2.get_idempotency_key(key).is_delivered is True
    assert ledger2.get_batch("KY20260001").batch_state is BatchState.DELIVERED
    ledger.close()
    ledger2.close()


def test_台账里的步骤记录可续跑(tmp_path: Path) -> None:
    """台账记着每批次走到哪一步 —— 续跑判定的依据就在这里。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    runner.process(application, via_event=True)
    record = ledger.get_batch("KY20260001")
    assert record is not None
    assert "redact" in record.completed_steps
    assert "residual_check" in record.completed_steps
    assert "payload" in record.completed_steps
    assert record.current_step in ("intake", "recognize", "residual_check", "")
    ledger.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
