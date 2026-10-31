"""并发与重放防护。

科研交付是**事件驱动**的：管理员把申请单放进交付目录（守护进程捡起来）、
运维人员在 CLI 上点一次 run、进程重启后补投、兜底扫描再扫一遍 —— 同一批
材料可能从几个方向同时被触发。这一组测试盯住三件事：

1. **同批次并发处理互斥** —— 两个执行者（守护进程 + 运维 CLI，各持一张台账
   连接，等价于两个进程）同时处理同一批材料时，脱敏主路径**只跑一次**，
   外发**只发生一次**。跑两次的后果不是「慢一点」：一致代号会分叉、命中
   清单会翻倍、科研数据平台上会多一个数据集，而伦理办那边只看到一次交付。
2. **重复材料按材料 ID 去重并告警** —— 申请单里同一个材料 ID 出现两次时，
   只脱一次（**不重复替换**），并点名告警；静默去重等于替人决定哪一行才是
   对的。
3. **重放防护** —— 同一批材料被重放处理时，命中清单**不翻倍**：同一
   (批次, 材料 ID, 起点, 实体类别) 只记一条。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import httpx
import pytest

import research_redact.daemon.runner as runner_module
from research_redact.audit.alerts import JsonlAlertSink
from research_redact.audit.ledger import BatchLedger
from research_redact.audit.manifest import ManifestWriter
from research_redact.audit.residual import ResidualChecker
from research_redact.daemon.locks import BatchLock
from research_redact.daemon.runner import BatchRunner
from research_redact.daemon.watcher import InboxWatcher
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

#: 重复材料 ID 时被丢弃的那一份（内容里有个一眼能认出来的标记）。
DUPLICATE_MATERIAL_TEXT = """（重复材料 ID 的第二份副本：按首次出现去重后不应出现在产物里）
姓名：张某某      住院号：90000002
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

    替身只在测试层；产品代码跑的是真实 httpx 客户端。
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


def _write_inbox(
    root: Path,
    *,
    application_no: str = "KY20260001",
    duplicate_material: bool = False,
) -> Path:
    """在 ``root`` 下造一份可处理的交付目录（一份申请单 + 一份材料）。

    :param duplicate_material: 是否在材料清单里再塞一份**材料 ID 相同**的
        副本（模拟管理员复制了行）。
    """
    inbox = root / "inbox"
    application_dir = inbox / application_no
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    materials = [
        {
            "material_id": "KY20260001-CHK0000001-01",
            "kind": "report_text",
            "path": "materials/report_001.txt",
            "patient_id": "P-1001",
        }
    ]
    if duplicate_material:
        materials.append(
            {
                "material_id": "KY20260001-CHK0000001-01",
                "kind": "report_text",
                "path": "materials/report_002.txt",
                "patient_id": "P-1001",
            }
        )
    application = {
        "application_no": application_no,
        "ethics_approval_no": "EC-2026-0001",
        "patient_ids": ["P-1001"],
        "materials": materials,
    }
    (application_dir / "application.json").write_text(
        json.dumps(application, ensure_ascii=False), encoding="utf-8"
    )
    (application_dir / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT, encoding="utf-8"
    )
    if duplicate_material:
        (application_dir / "materials" / "report_002.txt").write_text(
            DUPLICATE_MATERIAL_TEXT, encoding="utf-8"
        )
    return inbox


def _checker(tmp_path: Path, ledger: BatchLedger) -> ResidualChecker:
    """残留自检器（告警落临时目录，批次摘要落台账）。"""
    return ResidualChecker(
        sink=JsonlAlertSink(tmp_path / "alerts.jsonl"),
        summary_sink=ledger,
    )


def _runner(tmp_path: Path, ledger: BatchLedger, *, lock_timeout: float = 10.0):
    """批次处理器（产物落临时目录）。"""
    return BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
        checker=_checker(tmp_path, ledger),
        lock_timeout=lock_timeout,
    )


def _client(platform: IdempotentPlatform, ledger: BatchLedger) -> ResearchPlatformClient:
    """科研数据平台客户端（协议替身只在测试层）。"""
    return ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=httpx.Client(transport=httpx.MockTransport(platform)),
        ledger=ledger,
        key_id=KEY_ID,
        idempotency_wait_seconds=10.0,
        idempotency_poll_seconds=0.02,
    )


@pytest.fixture()
def redaction_calls(monkeypatch):
    """数一数脱敏主路径真跑了几次（识别有没有被重复跑）。"""
    calls: list[str] = []
    original = runner_module.redact_batch

    def counting(*args, **kwargs):
        calls.append(str(args[0]) if args else str(kwargs.get("batch_no", "")))
        return original(*args, **kwargs)

    monkeypatch.setattr(runner_module, "redact_batch", counting)
    return calls


def _manifest_lines(path: str | Path) -> list[dict]:
    """读回命中清单（JSONL，一行一条命中）。

    走产品的 :meth:`ManifestWriter.read` —— 批次级清单的第一行是**清单头**
    （记这一批用哪一版策略脱的，task 36），它不是命中条目，读清单时按标记
    键跳过。条数口径不变：读出来几条就是几处命中。
    """
    return ManifestWriter.read(path)


# ------------------------------------------------------- 场景 1：同批次并发互斥


def test_并发触发同一批次只处理一次且只外发一次(tmp_path: Path, redaction_calls) -> None:
    """两个执行者同时处理同一批材料：脱敏只跑一次，外发只发生一次。"""
    inbox = _write_inbox(tmp_path)
    platform = IdempotentPlatform()
    barrier = threading.Barrier(2)
    results: list[object] = []
    errors: list[Exception] = []

    def worker() -> None:
        ledger = BatchLedger(tmp_path / "ledger.sqlite3")
        try:
            runner = _runner(tmp_path, ledger)
            client = _client(platform, ledger)
            application = InboxWatcher(inbox).applications()[0]
            barrier.wait(timeout=30)
            result = runner.process(application, via_event=True)
            results.append(result)
            if result.deliverable:
                client.deliver(result.batch_no, result.payload)
        except Exception as exc:  # 线程里的异常要带回主线程断言
            errors.append(exc)
        finally:
            ledger.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, f"并发处理抛错：{errors}"
    assert len(results) == 2

    # 脱敏主路径只跑了一次 —— 第二个执行者复用上一轮的产物
    assert len(redaction_calls) == 1
    resumed = [item for item in results if item.resumed]
    fresh = [item for item in results if not item.resumed]
    assert len(fresh) == 1
    assert len(resumed) == 1

    # 两边看到的产物是同一份
    fresh_result = fresh[0]
    resumed_result = resumed[0]
    assert fresh_result.entries == resumed_result.entries
    assert (
        Path(fresh_result.artifacts["manifest"]).read_text(encoding="utf-8")
        == Path(resumed_result.artifacts["manifest"]).read_text(encoding="utf-8")
    )

    # 外发只发生一次：平台只收到一个请求、只建了一个数据集
    assert platform.calls == 1
    assert platform.created == 1

    # 命中清单没有重复行
    rows = _manifest_lines(fresh_result.artifacts["manifest"])
    keys = [(row["material_id"], row["start"], row["label"]) for row in rows]
    assert len(keys) == len(set(keys))

    # 台账里这一批只交过一次
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    receipts = ledger.receipts("KY20260001")
    assert len(receipts) == 1
    assert ledger.idempotency_keys("KY20260001")[0].is_delivered is True
    ledger.close()


def test_抢不到批次锁时复用已有产物不重复脱敏(tmp_path: Path, redaction_calls) -> None:
    """另一个执行者正拿着锁：这一轮跳过，产物复用，不重复脱敏。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger, lock_timeout=0.0)
    application = InboxWatcher(inbox).applications()[0]

    # 手动把批次锁占住（= 另一个执行者正在处理这一批）
    lock = BatchLock(runner._lock_path("KY20260001"), timeout=1.0)
    assert lock.acquire().acquired is True
    try:
        result = runner.process(application, via_event=True)
    finally:
        lock.release()

    assert result.skipped is True
    assert result.concurrent is True
    assert result.processed is False
    assert "另一执行者" in result.note
    assert len(redaction_calls) == 0  # 一次识别都没跑
    ledger.close()


def test_批次锁互斥且释放后可再获取(tmp_path: Path) -> None:
    """锁本身：第二个持有者拿不到锁，放掉之后能拿到。"""
    path = tmp_path / "locks" / "KY20260001.lock"
    first = BatchLock(path, timeout=1.0)
    outcome = first.acquire()
    assert outcome.acquired is True
    assert outcome.waited_seconds >= 0

    second = BatchLock(path, timeout=0.0)
    blocked = second.acquire()
    assert blocked.acquired is False
    # 拿不到锁必须说清是谁在占着（进程内锁或文件锁拦下的，理由不同）
    assert "执行者" in blocked.reason
    # 拿不到锁时能看到持有者是谁（进程号）
    assert blocked.holder.get("pid") == os.getpid()

    first.release()
    third = BatchLock(path, timeout=1.0)
    assert third.acquire().acquired is True
    third.release()

    # 锁文件里只有进程号、主机与时刻 —— 不含任何患者原文
    payload = path.read_text(encoding="utf-8")
    for secret in RAW_TEXT_SAMPLES:
        assert secret not in payload


# ------------------------------------------------- 场景 2：重复材料去重并告警


def test_重复材料按材料ID去重并告警(tmp_path: Path, redaction_calls) -> None:
    """申请单里材料 ID 重复：只脱一次（不重复替换），并点名告警。"""
    inbox = _write_inbox(tmp_path, duplicate_material=True)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    result = runner.process(application, via_event=True)

    assert result.processed is True
    assert result.deliverable is True
    assert result.duplicates == ("KY20260001-CHK0000001-01",)
    assert "材料 ID 重复" in result.note

    # 只处理了一份材料（不重复替换）
    assert result.payload["material_count"] == 1
    assert list(result.payload["material_ids"]) == ["KY20260001-CHK0000001-01"]
    assert len(result.payload["materials"]) == 1

    # 产物里是**首次出现**的那一份；被丢弃的那份没混进来
    redacted = Path(result.artifacts["KY20260001-CHK0000001-01"]).read_text(encoding="utf-8")
    assert "第二份副本" not in redacted
    assert "90000002" not in redacted

    # 有告警：点名重复的材料 ID
    alerts = [item for item in ledger.alerts("KY20260001") if item.code == "duplicate_material_id"]
    assert len(alerts) == 1
    assert alerts[0].level == "warning"
    assert alerts[0].material_ids == ("KY20260001-CHK0000001-01",)
    assert "KY20260001-CHK0000001-01" in alerts[0].message
    for secret in DELIVERY_RAW_TEXT_SAMPLES:
        assert secret not in alerts[0].message

    # 命中清单里没有重复行
    rows = _manifest_lines(result.artifacts["manifest"])
    keys = [(row["material_id"], row["start"], row["label"]) for row in rows]
    assert len(keys) == len(set(keys))
    assert {row["material_id"] for row in rows} == {"KY20260001-CHK0000001-01"}
    ledger.close()


def test_材料ID去重留首次出现的行(tmp_path: Path) -> None:
    """去重口径：留首次出现的那一行，其余点名丢弃。"""
    from research_redact.ingest.application import dedupe_material_rows, load_application

    inbox = _write_inbox(tmp_path, duplicate_material=True)
    intake = load_application(inbox / "KY20260001" / "application.json")
    plan = dedupe_material_rows(intake.rows)

    assert len(intake.rows) == 2  # 申请单里确实是两行
    assert len(plan.rows) == 1  # 去重后只剩一份
    assert plan.duplicates == ("KY20260001-CHK0000001-01",)
    assert plan.rows[0].path == "materials/report_001.txt"  # 首次出现优先
    assert plan.dropped and "materials[1].path" in plan.dropped[0]


# ------------------------------------------------------- 场景 3：重放防护


def test_重放同一批材料命中清单不翻倍(tmp_path: Path, redaction_calls) -> None:
    """崩在「产物已落盘、状态还没推进」后重放：清单行数不变，不多一行。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    # 第一次：模拟崩在登记批次身份那一步（清单已经落盘，状态还在 recognized）
    original = ledger.complete_step

    def crashing(batch_no: str, step: str) -> None:
        raise RuntimeError("模拟崩溃：产物已落盘，状态还没推进")

    ledger.complete_step = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        runner.process(application, via_event=True)
    ledger.complete_step = original  # type: ignore[method-assign]

    manifest_path = tmp_path / "outbox" / "KY20260001" / "manifest.jsonl"
    first_rows = _manifest_lines(manifest_path)
    assert first_rows  # 第一轮确实落了清单
    record = ledger.get_batch("KY20260001")
    assert record is not None
    scope = record.material_fingerprint
    assert scope

    # 第二次：重放同一批材料 → 识别重跑，但清单**不翻倍**
    second = runner.process(application, via_event=True)
    assert second.processed is True
    second_rows = _manifest_lines(manifest_path)
    assert len(second_rows) == len(first_rows)
    assert second_rows == first_rows

    # 台账里的清单条目也只有一份（唯一约束挡住了重复写入）
    recorded = ledger.manifest_entries("KY20260001", scope)
    assert len(recorded) == len(first_rows)
    keys = [(row["material_id"], row["start"], row["label"]) for row in recorded]
    assert len(keys) == len(set(keys))

    # 命中清单里不含任何命中原文
    payload = manifest_path.read_text(encoding="utf-8")
    for secret in DELIVERY_RAW_TEXT_SAMPLES:
        assert secret not in payload
    ledger.close()


def test_材料集合变了就是新的一批清单不混(tmp_path: Path) -> None:
    """材料换了 → 批次身份变了 → 新的一批有自己的清单，不被旧范围的记录挡住。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = _runner(tmp_path, ledger)
    application = InboxWatcher(inbox).applications()[0]

    first = runner.process(application, via_event=True)
    assert first.processed is True
    manifest_path = Path(first.artifacts["manifest"])
    first_rows = _manifest_lines(manifest_path)
    first_scope = ledger.get_batch("KY20260001").material_fingerprint

    # 换掉源材料内容（同一批号、同一材料 ID）→ 指纹变 → 新的一批
    (inbox / "KY20260001" / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT.replace("示例医师", "示例医师乙"), encoding="utf-8"
    )
    second = runner.process(application, via_event=True)
    assert second.processed is True
    second_scope = ledger.get_batch("KY20260001").material_fingerprint
    assert second_scope != first_scope

    # 新范围的清单条数 = 新一轮的命中数（旧的记录没混进来）
    fresh = ledger.manifest_entries("KY20260001", second_scope)
    assert len(fresh) == second.entries
    assert len(ledger.manifest_entries("KY20260001", first_scope)) == len(first_rows)
    ledger.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
