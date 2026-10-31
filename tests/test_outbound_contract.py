"""出站对接层的协议契约测试。

这一组测试盯住三件事：

1. **请求长得对不对** —— 方法、URL、鉴权头、幂等键、请求体字段，逐项对着
   spec.md「最小数据格式与字段要求」核。
2. **凭据是不是从环境变量来的** —— 代码里不得有硬编码密钥，缺配置时**不外发**。
3. **缺端点时是不是挂起** —— 通道置挂起并告警，**不指向本地替身**。

**协议替身只出现在本测试层**：产品代码跑的是真的 ``httpx`` 客户端，这里只是
把传输层换成 ``httpx.MockTransport``，好把请求原样抓下来逐字段核对。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from research_redact.audit.ledger import BatchLedger
from research_redact.config import (
    CHANNEL_HIS,
    CHANNEL_RESEARCH,
    CHANNEL_WECOM,
    CHANNEL_STATUS_READY,
    CHANNEL_STATUS_SUSPENDED,
    CHANNEL_STATUS_UNAUTHENTICATED,
    OutboundConfig,
)
from research_redact.outbound.errors import ChannelSuspendedError
from research_redact.outbound.notifier import WeComNotifier, build_batch_message
from research_redact.outbound.patient_index_client import (
    PatientIndexClient,
    PatientIndexError,
)
from research_redact.outbound.research_platform_client import (
    ResearchPlatformClient,
    build_idempotency_key,
    material_fingerprint,
)

HIS_BASE = "https://his.example.internal"
HIS_TOKEN = "his-token-abc"
PLATFORM_BASE = "https://research-data.example.internal"
PLATFORM_TOKEN = "platform-token-xyz"
WECOM_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=stub"

#: 交付体里绝不该出现的患者原文（静态扫描用）。
#:
#: 注意 **不含** 检查号 ``CHK0000001``：spec.md 把 ``material_id`` 定义成
#: 「申请单号 + 院内检查号 + 材料序号」三元组，检查号是材料键的一部分（业务
#: 关联键，不是命中原文）。正文里的检查号早已被替换成 ``<检查号>``；交付体
#: 的材料键仍带原值 —— 这处张力记在 ``discoveries.md``（交付前把检查号换成
#: 一致代号），本轮出站层按 spec.md 的字段规范原样透传。
RAW_TEXT_SAMPLES = ("张某某", "90000001", "1949-12-31", "13800138000", "110101")


# --------------------------------------------------------------------- 替身


class Recorder:
    """记录所有出站请求的协议替身。"""

    def __init__(self, responses: dict[str, httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._responses = responses or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for fragment, response in self._responses.items():
            if fragment in str(request.url):
                return response
        return httpx.Response(200, json={"errcode": 0})

    @property
    def calls(self) -> int:
        return len(self.requests)

    def last(self) -> httpx.Request:
        return self.requests[-1]

    def body(self, index: int = -1) -> dict:
        return json.loads(self.requests[index].content.decode("utf-8"))


def _client(recorder: Recorder) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(recorder))


def _payload(tmp_path: Path) -> dict:
    """一份典型的投递载荷（脱敏副本 + 命中清单已在本地暂存）。"""
    first = tmp_path / "M-1.txt"
    second = tmp_path / "M-2.csv"
    manifest = tmp_path / "manifest.jsonl"
    for target in (first, second, manifest):
        target.write_text("占位内容", encoding="utf-8")
    return {
        "application_no": "KY20260001",
        "ethics_approval_no": "EC-2026-0001",
        "patient_ids": ["P-1001", "P-1002"],
        "material_count": 2,
        "materials": [
            {
                "material_id": "KY20260001-CHK0000001-01",
                "kind": "report_text",
                "sha256": "a" * 64,
                "path": str(first),
            },
            {
                "material_id": "KY20260001-CHK0000002-02",
                "kind": "table",
                "sha256": "b" * 64,
                "path": str(second),
            },
        ],
        "manifest_path": str(manifest),
    }


# ------------------------------------------------------------- HIS 主索引（读）


def test_患者主索引查询方法地址与鉴权头都符合规范():
    recorder = Recorder(
        {
            "/api/v1/patient-index": httpx.Response(
                200,
                json={
                    "patient_id": "P-1001",
                    "visit_no": "90000001",
                    "name": "张某某",
                    "id_card_masked": "110101********001X",
                    "birth_date": "1949-12-31",
                    "sex": "男",
                },
            )
        }
    )
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    record = client.lookup("90000001")

    request = recorder.last()
    assert request.method == "GET"
    assert str(request.url) == f"{HIS_BASE}/api/v1/patient-index?visit_no=90000001"
    assert request.headers["Authorization"] == f"Bearer {HIS_TOKEN}"
    assert request.headers["Accept"] == "application/json"
    # 响应体六个字段逐项落到记录上
    assert record.patient_id == "P-1001"
    assert record.visit_no == "90000001"
    assert record.name == "张某某"
    assert record.id_card_masked == "110101********001X"
    assert record.birth_date == "1949-12-31"
    assert record.sex == "男"


def test_患者主索引返回非2xx时抛错且带状态码():
    recorder = Recorder({"/api/v1/patient-index": httpx.Response(503, json={})})
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    with pytest.raises(PatientIndexError) as excinfo:
        client.lookup("90000001")

    assert excinfo.value.status == 503
    assert excinfo.value.kind == "http_status"
    assert excinfo.value.retryable is True


def test_患者主索引响应缺patient_id时判为结构错误():
    recorder = Recorder(
        {"/api/v1/patient-index": httpx.Response(200, json={"visit_no": "90000001"})}
    )
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    with pytest.raises(PatientIndexError) as excinfo:
        client.lookup("90000001")

    assert excinfo.value.kind == "payload"
    assert "patient_id" in str(excinfo.value)


# ------------------------------------------------------- 科研数据平台（写）：交付


def test_数据集交付方法地址鉴权头与幂等键都符合规范(tmp_path):
    recorder = Recorder(
        {
            "/api/v1/datasets": httpx.Response(
                200,
                json={
                    "dataset_id": "DS-7788",
                    "application_no": "KY20260001",
                    "material_count": 2,
                    "receipt_id": "RC-0001",
                    "accepted_at": "2026-10-31T08:00:00Z",
                },
            )
        }
    )
    payload = _payload(tmp_path)
    client = ResearchPlatformClient(
        PLATFORM_BASE, PLATFORM_TOKEN, client=_client(recorder), key_id="key-2026-10"
    )

    body = client.build_dataset_body(payload)
    key = client.idempotency_key_for(
        payload["application_no"], payload["materials"]
    )
    receipt = client.create_dataset(body, idempotency_key=key)

    request = recorder.last()
    assert request.method == "POST"
    assert str(request.url) == f"{PLATFORM_BASE}/api/v1/datasets"
    assert request.headers["Authorization"] == f"Bearer {PLATFORM_TOKEN}"
    assert request.headers["Idempotency-Key"] == key
    assert key.startswith("KY20260001.")

    # 交付体字段逐项对着 spec.md 核
    sent = recorder.body()
    assert set(sent) == {
        "application_no",
        "ethics_approval_no",
        "dataset_name",
        "material_count",
        "materials",
        "pseudonymization",
        "manifest_uri",
    }
    assert sent["application_no"] == "KY20260001"
    assert sent["ethics_approval_no"] == "EC-2026-0001"
    assert sent["dataset_name"] == "科研脱敏交付 KY20260001"
    assert sent["material_count"] == 2
    assert sent["pseudonymization"] == {
        "scheme": "hmac-sha256",
        "key_id": "key-2026-10",
    }
    assert sent["manifest_uri"].endswith("manifest.jsonl")

    for item in sent["materials"]:
        assert set(item) == {"material_id", "kind", "sha256", "storage_uri"}
    assert [item["kind"] for item in sent["materials"]] == ["report_text", "table"]

    # 平台回了回执才算交付完成
    assert receipt.dataset_id == "DS-7788"
    assert receipt.material_count == 2
    assert receipt.receipt_id == "RC-0001"


def test_交付体不含任何患者原文(tmp_path):
    recorder = Recorder(
        {"/api/v1/datasets": httpx.Response(200, json={"dataset_id": "DS-7788"})}
    )
    payload = _payload(tmp_path)
    client = ResearchPlatformClient(
        PLATFORM_BASE, PLATFORM_TOKEN, client=_client(recorder), key_id="key-2026-10"
    )
    client.deliver(payload["application_no"], payload)

    raw = recorder.last().content.decode("utf-8")
    for sample in RAW_TEXT_SAMPLES:
        assert sample not in raw
    # 材料键按 spec.md 的三元组原样透传（申请单号 + 检查号 + 序号）
    assert "KY20260001-CHK0000001-01" in raw


def test_交付成功后幂等键与平台回执落进台账(tmp_path):
    recorder = Recorder(
        {
            "/api/v1/datasets": httpx.Response(
                200,
                json={
                    "dataset_id": "DS-7788",
                    "application_no": "KY20260001",
                    "material_count": 2,
                    "receipt_id": "RC-0001",
                },
            )
        }
    )
    payload = _payload(tmp_path)
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    ledger.open_batch(
        "KY20260001",
        ethics_approval_no="EC-2026-0001",
        patient_ids=["P-1001", "P-1002"],
        material_ids=["KY20260001-CHK0000001-01", "KY20260001-CHK0000002-02"],
    )
    client = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        ledger=ledger,
        key_id="key-2026-10",
    )

    assert client.deliver("KY20260001", payload) is True

    record = ledger.get_batch("KY20260001")
    expected_key = build_idempotency_key(
        "KY20260001", material_fingerprint(payload["materials"])
    )
    # 请求头里的幂等键与台账里的一致 —— 事后核得出「这一批交过一次」
    assert record.idempotency_key == expected_key
    assert recorder.last().headers["Idempotency-Key"] == expected_key
    receipts = ledger.receipts("KY20260001")
    assert len(receipts) == 1
    assert receipts[0].kind == "delivery"
    assert receipts[0].platform_receipt_id == "RC-0001"
    ledger.close()


def test_材料集合指纹与顺序无关但与内容有关(tmp_path):
    payload = _payload(tmp_path)
    materials = payload["materials"]
    fingerprint = material_fingerprint(materials)
    # 顺序变了仍是同一批材料
    assert material_fingerprint(list(reversed(materials))) == fingerprint
    # 内容变了 → 指纹变了 → 不会被误判成重复批次
    changed = [dict(materials[0]), {**materials[1], "sha256": "c" * 64}]
    assert material_fingerprint(changed) != fingerprint


# ------------------------------------------------------ 科研数据平台（写）：还原


def test_还原回执方法地址与请求体字段都符合规范():
    recorder = Recorder(
        {
            "/restore-audit": httpx.Response(
                200,
                json={
                    "restore_audit_id": "RA-0001",
                    "dataset_id": "DS-7788",
                    "restore_request_id": "RR-2026-0001",
                    "recorded_at": "2026-10-31T09:00:00Z",
                },
            )
        }
    )
    client = ResearchPlatformClient(
        PLATFORM_BASE, PLATFORM_TOKEN, client=_client(recorder), key_id="key-2026-10"
    )

    receipt = client.record_restore_audit(
        restore_request_id="RR-2026-0001",
        dataset_id="DS-7788",
        approver_a="科研数据管理员甲",
        approver_b="信息科乙",
        scope=["KY20260001-CHK0000001-01"],
        reason="伦理核查要求换回原文",
        granted_at="2026-10-31T08:30:00Z",
        expires_at="2026-10-31T18:30:00Z",
        result_summary="已还原 1 份材料",
    )

    request = recorder.last()
    assert request.method == "POST"
    assert str(request.url) == (
        f"{PLATFORM_BASE}/api/v1/datasets/DS-7788/restore-audit"
    )
    assert request.headers["Authorization"] == f"Bearer {PLATFORM_TOKEN}"

    sent = recorder.body()
    assert set(sent) == {
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
    assert sent["scope"] == ["KY20260001-CHK0000001-01"]
    assert sent["approver_a"] != sent["approver_b"]

    assert receipt.restore_audit_id == "RA-0001"
    assert receipt.dataset_id == "DS-7788"


# ------------------------------------------------------- 真实 HTTP 往返（不注入客户端）


def test_不注入客户端也能把交付体按真实协议发出去(tmp_path):
    """产品代码自己建 httpx 客户端，走一次真的 socket 往返。

    前面的用例用 ``MockTransport`` 抓请求；这一组起一个真的本地 HTTP 服务，
    证明「产品代码原样跑」时请求也是这个形状 —— 不是只有测试替身下才对。
    """
    received: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received["path"] = self.path
            received["headers"] = {k.lower(): v for k, v in self.headers.items()}
            received["body"] = json.loads(body.decode("utf-8"))
            payload = json.dumps(
                {"dataset_id": "DS-7788", "receipt_id": "RC-0001"}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            """别把访问日志刷进 pytest 输出。"""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        payload = _payload(tmp_path)
        client = ResearchPlatformClient(base, PLATFORM_TOKEN, key_id="key-2026-10")
        assert client.deliver("KY20260001", payload) is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    headers = received["headers"]
    assert received["path"] == "/api/v1/datasets"
    assert headers["authorization"] == f"Bearer {PLATFORM_TOKEN}"
    assert headers["idempotency-key"].startswith("KY20260001.")
    body = received["body"]
    assert body["application_no"] == "KY20260001"
    assert body["material_count"] == 2
    assert body["pseudonymization"]["key_id"] == "key-2026-10"
    for sample in RAW_TEXT_SAMPLES:
        assert sample not in json.dumps(body, ensure_ascii=False)


# ----------------------------------------------------------------- 企业微信（推）


def test_企微推送地址与请求体格式符合群机器人规范():
    recorder = Recorder()
    notifier = WeComNotifier(WECOM_WEBHOOK, client=_client(recorder))

    message = build_batch_message(
        "KY20260001",
        state="pending_delivery",
        title="投递退避超次",
        reason="科研数据平台返回 HTTP 503",
        pending_hint="请执行 deliver 重投",
    )
    assert notifier.notify(message, batch_no="KY20260001") is True

    request = recorder.last()
    assert request.method == "POST"
    assert str(request.url) == WECOM_WEBHOOK
    body = recorder.body()
    assert body["msgtype"] == "text"
    assert "KY20260001" in body["text"]["content"]
    assert "pending_delivery" in body["text"]["content"]
    assert "待处理" in body["text"]["content"]


# -------------------------------------------------------- 缺配置：挂起并告警


def test_三个通道都从环境变量读凭据(monkeypatch):
    monkeypatch.setenv("HIS_BASE_URL", HIS_BASE)
    monkeypatch.setenv("HIS_API_TOKEN", HIS_TOKEN)
    monkeypatch.setenv("RESEARCH_DATA_BASE_URL", PLATFORM_BASE)
    monkeypatch.setenv("RESEARCH_DATA_TOKEN", PLATFORM_TOKEN)
    monkeypatch.setenv("WECOM_WEBHOOK_URL", WECOM_WEBHOOK)
    monkeypatch.setenv("PSEUDONYM_KEY_ID", "key-2026-10")

    config = OutboundConfig.from_env()

    assert config.his.base_url == HIS_BASE
    assert config.his.token == HIS_TOKEN
    assert config.research.base_url == PLATFORM_BASE
    assert config.research.token == PLATFORM_TOKEN
    assert config.wecom.base_url == WECOM_WEBHOOK
    assert config.pseudonym_key_id == "key-2026-10"
    assert config.his.status == CHANNEL_STATUS_READY
    assert config.research.status == CHANNEL_STATUS_READY
    assert config.wecom.status == CHANNEL_STATUS_READY
    assert config.suspended_channels() == ()


def test_缺端点时通道置挂起并产生告警(monkeypatch):
    for name in (
        "HIS_BASE_URL",
        "HIS_API_TOKEN",
        "RESEARCH_DATA_BASE_URL",
        "RESEARCH_DATA_TOKEN",
        "WECOM_WEBHOOK_URL",
    ):
        monkeypatch.delenv(name, raising=False)

    config = OutboundConfig.from_env()

    assert config.his.status == CHANNEL_STATUS_SUSPENDED
    assert config.research.status == CHANNEL_STATUS_SUSPENDED
    assert config.wecom.status == CHANNEL_STATUS_SUSPENDED
    assert {channel.name for channel in config.suspended_channels()} == {
        CHANNEL_HIS,
        CHANNEL_RESEARCH,
        CHANNEL_WECOM,
    }

    alerts = config.alerts("KY20260001")
    assert len(alerts) == 3
    assert {alert.code for alert in alerts} == {"outbound_channel_suspended"}
    assert {alert.level for alert in alerts} == {"error"}
    for alert in alerts:
        assert "挂起" in alert.message
        assert "本地替身" in alert.message


def test_缺端点时三个客户端都不发请求(monkeypatch):
    for name in (
        "HIS_BASE_URL",
        "HIS_API_TOKEN",
        "RESEARCH_DATA_BASE_URL",
        "RESEARCH_DATA_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    recorder = Recorder()

    his = PatientIndexClient(client=_client(recorder))
    platform = ResearchPlatformClient(client=_client(recorder), key_id="key-2026-10")

    assert his.configured is False
    assert platform.configured is False
    assert his.status == CHANNEL_STATUS_SUSPENDED
    assert platform.status == CHANNEL_STATUS_SUSPENDED

    with pytest.raises(ChannelSuspendedError) as his_excinfo:
        his.lookup("90000001")
    assert his_excinfo.value.channel == CHANNEL_HIS

    with pytest.raises(ChannelSuspendedError) as platform_excinfo:
        platform.deliver("KY20260001", {"application_no": "KY20260001"})
    assert platform_excinfo.value.channel == CHANNEL_RESEARCH

    # 一个请求都没发出去 —— 「没配置」不是「换个地方假装成功」
    assert recorder.calls == 0


def test_端点配了但令牌没配时状态是未认证而不是静默放行(monkeypatch):
    monkeypatch.setenv("HIS_BASE_URL", HIS_BASE)
    monkeypatch.delenv("HIS_API_TOKEN", raising=False)

    config = OutboundConfig.from_env()

    assert config.his.status == CHANNEL_STATUS_UNAUTHENTICATED
    assert config.his.configured is False
    assert "HIS_API_TOKEN" in config.his.reason


def test_客户端不把令牌写进可打印的快照(monkeypatch):
    monkeypatch.setenv("HIS_BASE_URL", HIS_BASE)
    monkeypatch.setenv("HIS_API_TOKEN", HIS_TOKEN)

    config = OutboundConfig.from_env()

    for item in config.describe():
        assert "token" not in item
        assert HIS_TOKEN not in json.dumps(item, ensure_ascii=False)
