"""幂等键与重投防护。

科研交付是**事件驱动**的：管理员把申请单放进交付目录、守护进程捡起来、平台
5xx 退避重试、守护进程重启补投、人工在运维 CLI 上再点一次 deliver —— 一次
交付可能从四个方向被触发。没有幂等键，这四条路会交出四个数据集，伦理办那边
对不上账。

这一组测试盯住三件事：

1. **同批重投不产生第二次真实外发** —— 幂等键认领走 ``INSERT OR IGNORE``，
   第二个执行者复用已有回执就返回成功，一个请求都不多发。
2. **材料集合变化视为新批次投递** —— 材料新增 / 删改 → 指纹变 → 幂等键变 →
   当成新的一批交出去，不被误判成重复批次而丢掉。
3. **并发两次投递只外发一次** —— 守护进程与运维 CLI 同时触发同一批时，
   只有一个能拿到「首次认领」。

外加两条纪律：请求头里的 ``Idempotency-Key`` 与台账里记的幂等键**必须一致**；
幂等键与指纹**不含任何患者原文**。
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.__main__ import _pending_deliveries
from research_redact.daemon.queue import DeliveryQueue
from research_redact.daemon.runner import BatchRunner
from research_redact.daemon.state_machine import BatchState
from research_redact.daemon.watcher import InboxApplication, InboxWatcher
from research_redact.idempotency import (
    compute_idempotency_key,
    material_set_fingerprint,
)
from research_redact.outbound.research_platform_client import (
    ResearchPlatformClient,
    material_fingerprint,
)

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


class Recorder:
    """记录所有出站请求的协议替身（测试层专用）。"""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append(request)
            count = len(self.requests)
        return httpx.Response(
            200,
            json={
                "dataset_id": f"DS-{count:04d}",
                "application_no": "KY20260001",
                "material_count": 1,
                "receipt_id": f"RC-{count:04d}",
                "accepted_at": "2026-10-31T08:00:00Z",
            },
        )

    @property
    def calls(self) -> int:
        return len(self.requests)

    def keys(self) -> list[str]:
        """历次请求的 Idempotency-Key。"""
        return [request.headers.get("idempotency-key", "") for request in self.requests]

    def bodies(self) -> list[dict]:
        return [json.loads(r.content.decode("utf-8")) for r in self.requests]


def _client(recorder: Recorder, ledger: BatchLedger | None = None) -> ResearchPlatformClient:
    return ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=httpx.Client(transport=httpx.MockTransport(recorder)),
        ledger=ledger,
        key_id=KEY_ID,
    )


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


def _add_material(inbox: Path, material_id: str, filename: str) -> None:
    """给交付目录补一份材料（材料集合变了 → 指纹变 → 新的一批）。"""
    application_dir = inbox / "KY20260001"
    (application_dir / "materials" / filename).write_text(
        MATERIAL_TEXT.replace("报告医师：示例医师", "报告医师：示例医师甲"),
        encoding="utf-8",
    )
    application = json.loads(
        (application_dir / "application.json").read_text(encoding="utf-8")
    )
    application["materials"].append(
        {
            "material_id": material_id,
            "kind": "report_text",
            "path": f"materials/{filename}",
            "patient_id": "P-1001",
        }
    )
    (application_dir / "application.json").write_text(
        json.dumps(application, ensure_ascii=False), encoding="utf-8"
    )


def _build(tmp_path: Path) -> tuple[InboxApplication, BatchRunner, BatchLedger, Path]:
    """装配交付目录 / 处理器 / 台账。"""
    inbox = _write_inbox(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = BatchRunner(output_dir=tmp_path / "outbox", ledger=ledger)
    application = InboxWatcher(inbox).applications()[0]
    return application, runner, ledger, inbox


# --------------------------------------------------------------------- 键本身


def test_幂等键由申请单号与材料集合指纹算得():
    fingerprint = material_set_fingerprint(
        [{"material_id": "KY20260001-CHK0000001-01", "source_sha256": "a" * 64}]
    )
    key = compute_idempotency_key("KY20260001", fingerprint)

    assert key == f"KY20260001.{fingerprint[:32]}"
    # 键里只有申请单号与摘要，不含任何患者原文
    for sample in RAW_TEXT_SAMPLES:
        assert sample not in key
        assert sample not in fingerprint


def test_材料集合指纹与顺序无关但与内容有关():
    items = [
        {"material_id": "KY20260001-CHK0000001-01", "source_sha256": "a" * 64},
        {"material_id": "KY20260001-CHK0000002-02", "source_sha256": "b" * 64},
    ]
    fingerprint = material_set_fingerprint(items)

    # 顺序变了仍是同一批材料
    assert material_set_fingerprint(list(reversed(items))) == fingerprint
    # 内容变了 → 指纹变了 → 不会被误判成重复批次
    changed = [items[0], {**items[1], "source_sha256": "c" * 64}]
    assert material_set_fingerprint(changed) != fingerprint
    # 材料少了 → 也是不同的集合
    assert material_set_fingerprint(items[:1]) != fingerprint


def test_摘要优先取源文件_没有才退回交付副本():
    """批次身份跟着**原始材料**走：源文件摘要在前，交付副本摘要在后。"""
    items = [{"material_id": "KY20260001-CHK0000001-01", "sha256": "b" * 64, "source_sha256": "a" * 64}]
    assert material_set_fingerprint(items) == material_set_fingerprint(
        [{"material_id": "KY20260001-CHK0000001-01", "source_sha256": "a" * 64}]
    )
    # 没有源摘要时退回交付副本摘要
    assert material_set_fingerprint(
        [{"material_id": "KY20260001-CHK0000001-01", "sha256": "b" * 64}]
    ) == material_set_fingerprint([{"material_id": "KY20260001-CHK0000001-01", "source_sha256": "b" * 64}])


# ------------------------------------------------------------- 台账的唯一约束


def test_台账以幂等键为唯一约束(tmp_path):
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")

    first = ledger.claim_idempotency_key("KY20260001.aaaa", "KY20260001", fingerprint="f1")
    second = ledger.claim_idempotency_key("KY20260001.aaaa", "KY20260001", fingerprint="f1")
    other = ledger.claim_idempotency_key("KY20260001.bbbb", "KY20260001", fingerprint="f2")

    assert first.is_new is True
    assert second.is_new is False  # 同一把键只能认领一次
    assert other.is_new is True  # 不同的键 = 不同的一批

    records = ledger.idempotency_keys("KY20260001")
    assert len(records) == 2
    assert {r.idempotency_key for r in records} == {"KY20260001.aaaa", "KY20260001.bbbb"}
    ledger.close()


def test_交付失败时释放认领让下一次能重新认领(tmp_path):
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")

    claim = ledger.claim_idempotency_key("KY20260001.aaaa", "KY20260001")
    assert claim.is_new is True

    ledger.release_idempotency_key("KY20260001.aaaa")
    again = ledger.claim_idempotency_key("KY20260001.aaaa", "KY20260001")
    assert again.is_new is True  # 释放之后能重新认领（不占着键）

    # 已交付的键不能释放 —— 释放了就会再交一次
    ledger.mark_idempotency_delivered("KY20260001.aaaa", dataset_id="DS-1")
    ledger.release_idempotency_key("KY20260001.aaaa")
    assert ledger.get_idempotency_key("KY20260001.aaaa") is not None
    assert ledger.get_idempotency_key("KY20260001.aaaa").is_delivered is True
    ledger.close()


# --------------------------------------------------------------- 同批重投防护


def test_同批重投不产生第二次真实外发(tmp_path):
    """同一批材料投两次：平台只收到一个请求，第二���复用已有回执。"""
    application, runner, ledger, _ = _build(tmp_path)
    recorder = Recorder()

    result = runner.process(application, via_event=True)
    assert result.deliverable is True
    key = result.payload["idempotency_key"]

    client = _client(recorder, ledger)
    assert client.deliver("KY20260001", result.payload) is True
    assert recorder.calls == 1

    # 再投一次（守护进程重启补投 / 运维 CLI 再点一次 deliver）
    assert client.deliver("KY20260001", result.payload) is True
    assert recorder.calls == 1  # 没有第二次真实外发

    # 复用的是同一份回执
    receipts = ledger.receipts("KY20260001")
    assert len(receipts) == 1
    assert receipts[0].receipt_id == key
    assert receipts[0].payload["dataset_id"] == "DS-0001"
    ledger.close()


def test_请求头幂等键与台账幂等键一致(tmp_path):
    """事后核得出「这一批交过一次」：请求头、台账、回执三处对得上。"""
    application, runner, ledger, _ = _build(tmp_path)
    recorder = Recorder()

    result = runner.process(application, via_event=True)
    client = _client(recorder, ledger)
    client.deliver("KY20260001", result.payload)

    record = ledger.get_batch("KY20260001")
    assert record.idempotency_key == result.payload["idempotency_key"]
    assert recorder.keys() == [record.idempotency_key]
    assert ledger.get_receipt(record.idempotency_key) is not None
    # 交付体里的材料摘要与幂等键算出来的指纹是同一份口径
    assert material_fingerprint(result.payload["materials"]) == result.payload[
        "material_fingerprint"
    ]
    ledger.close()


def test_幂等键与交付体不含患者原文(tmp_path):
    application, runner, ledger, _ = _build(tmp_path)
    recorder = Recorder()

    result = runner.process(application, via_event=True)
    client = _client(recorder, ledger)
    client.deliver("KY20260001", result.payload)

    blob = result.payload["idempotency_key"] + json.dumps(
        result.payload, ensure_ascii=False
    )
    for sample in DELIVERY_RAW_TEXT_SAMPLES:
        assert sample not in blob
    # 请求头里同样没有原文
    for key in recorder.keys():
        for sample in RAW_TEXT_SAMPLES:
            assert sample not in key
    ledger.close()


# --------------------------------------------------------------- 材料集合变化


def test_材料集合变化视为新批次投递(tmp_path):
    """材料补齐 → 指纹变 → 幂等键变 → 当成新的一批交出去，不被当成重复丢掉。"""
    application, runner, ledger, inbox = _build(tmp_path)
    recorder = Recorder()
    client = _client(recorder, ledger)
    queue = DeliveryQueue(deliver=client.deliver, ledger=ledger)

    result = runner.process(application, via_event=True)
    first_key = result.payload["idempotency_key"]
    assert queue.submit(result.batch_no, result.payload).delivered is True
    assert recorder.calls == 1
    # 批次已交付 —— 这时补材料属于「同一批号的新材料集合」，不是重复投递
    assert ledger.get_batch("KY20260001").batch_state is BatchState.DELIVERED

    # 补一份材料 → 材料集合变了
    _add_material(inbox, "KY20260001-CHK0000002-02", "report_002.txt")
    again = runner.process(application, via_event=True)

    assert again.skipped is False
    assert again.deliverable is True
    second_key = again.payload["idempotency_key"]
    assert second_key != first_key  # 指纹变了 → 幂等键变了 → 不是同一批

    # 新的一批照常交付（不被误判成重复批次丢掉）
    assert client.deliver("KY20260001", again.payload) is True
    assert recorder.calls == 2
    assert recorder.keys() == [first_key, second_key]
    assert recorder.keys()[0] != recorder.keys()[1]

    # 平台侧收到的两份交付体材料数不同（一份 1 份材料，一份 2 份材料）
    assert recorder.bodies()[0]["material_count"] == 1
    assert recorder.bodies()[1]["material_count"] == 2
    ledger.close()


def test_材料没变时重复投递不重跑脱敏也不重复外发(tmp_path):
    """材料没变 → 指纹没变 → 复用已有产物与回执。"""
    application, runner, ledger, _ = _build(tmp_path)
    recorder = Recorder()
    client = _client(recorder, ledger)
    queue = DeliveryQueue(deliver=client.deliver, ledger=ledger)

    result = runner.process(application, via_event=True)
    assert queue.submit(result.batch_no, result.payload).delivered is True
    assert ledger.get_batch("KY20260001").batch_state is BatchState.DELIVERED

    # 同一份申请单再投一次：批次已交付且材料没变 → 跳过（不重跑脱敏）
    again = runner.process(application, via_event=True)
    assert again.skipped is True
    assert "delivered" in again.note
    assert recorder.calls == 1

    # 再投一次也一样：复用已有回执，不产生第二次外发
    assert client.deliver("KY20260001", result.payload) is True
    assert recorder.calls == 1
    ledger.close()


# ------------------------------------------------------------------- 并发防护


def test_并发两次投递只外发一次(tmp_path):
    """守护进程与运维 CLI 同时触发同一批：平台只收到一个请求。"""
    application, runner, ledger, _ = _build(tmp_path)
    recorder = Recorder()

    result = runner.process(application, via_event=True)
    payload = result.payload
    ledger_path = tmp_path / "ledger.sqlite3"

    def deliver_once() -> bool:
        # 两个执行者 = 两个进程 = 两份台账连接（SQLite 层面的唯一约束生效）
        local_ledger = BatchLedger(ledger_path)
        try:
            client = _client(recorder, local_ledger)
            return client.deliver("KY20260001", payload)
        finally:
            local_ledger.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: deliver_once(), range(2)))

    assert results == [True, True]
    assert recorder.calls == 1  # 只外发了一次

    # 台账里这把键只认领过一次，且已交付
    key = payload["idempotency_key"]
    claim = ledger.get_idempotency_key(key)
    assert claim is not None
    assert claim.is_delivered is True
    ledger.close()


# ------------------------------------------------------------- 重启补投的键


def test_守护进程重启补投用同一把幂等键(tmp_path):
    """重启后的补投必须用当初那把键，否则平台会当成新的一批再收一次。"""
    application, runner, ledger, _ = _build(tmp_path)

    result = runner.process(application, via_event=True)
    key = result.payload["idempotency_key"]

    # 批次停在「已代号化、尚未交付」——守护进程重启后从这里补投
    pending = _pending_deliveries(ledger)
    assert len(pending) == 1
    batch_no, payload = pending[0]
    assert batch_no == "KY20260001"
    assert payload["idempotency_key"] == key
    # 补投载荷里带着材料清单（不重跑脱敏也不丢材料）
    assert len(payload["materials"]) == 1
    assert payload["materials"][0]["material_id"] == "KY20260001-CHK0000001-01"
    ledger.close()


def test_补投载荷的材料摘要与初次交付一致(tmp_path):
    """补投时材料摘要不能变 —— 变了平台侧就核不出「同一批材料」。"""
    application, runner, ledger, _ = _build(tmp_path)

    result = runner.process(application, via_event=True)
    _, payload = _pending_deliveries(ledger)[0]

    assert payload["materials"] == result.payload["materials"]
    ledger.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
