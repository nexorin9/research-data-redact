"""出站重试、错误分类与通道挂起告警。

对应 task 37 的四条验收：

1. **5xx → 退避重试 → 成功**（重试发生在真实客户端代码里，请求发两次）；
2. **4xx → 不重试**，直接报错（请求只发一次 —— 重试只是把同一个错再犯一遍）；
3. **超时 → 归类为 timeout**（可重试），重试耗尽后按类别报错；
4. **端点缺失 → 通道置挂起并告警**，一个请求都不发，不指向本地替身。

另加：错误分类 → **批次状态与告警级别**的映射（401/403 鉴权失败、端点未配置、
请求体校验不过、服务端错误），以及队列据分类决定「退避重试」还是「当场挂起」。
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from research_redact.audit.alerts import RecordingNotifier
from research_redact.audit.ledger import BatchLedger
from research_redact.daemon.queue import DeliveryQueue
from research_redact.daemon.runner import BatchRunner
from research_redact.daemon.state_machine import BatchState
from research_redact.daemon.watcher import InboxWatcher
from research_redact.outbound.channels import CHANNEL_HIS, CHANNEL_RESEARCH
from research_redact.outbound.errors import ChannelSuspendedError
from research_redact.outbound.failures import (
    FailureCategory,
    classify_exception,
    classify_status,
    decide_failure,
)
from research_redact.outbound.patient_index_client import (
    PatientIndexClient,
    PatientIndexError,
)
from research_redact.outbound.research_platform_client import (
    PlatformError,
    ResearchPlatformClient,
)
from research_redact.outbound.retry import RetryPolicy

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
（本页为第 2 页）
报告日期：2026-01-05    报告医师：示例医师
"""

IDENTITY_STRINGS = ("张某某", "90000001", "CHK0000001", "1949-12-31", "13800138000")


# --------------------------------------------------------------------- 替身


class _FakeClock:
    """可控单调时钟（队列退避重试的测试要靠它把时间往前拨）。"""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeResponse:
    """最小响应对象（只要状态码与 JSON 体）。"""

    def __init__(self, status_code: int, body: object | None = None) -> None:
        self.status_code = status_code
        self._body = {} if body is None else body

    def json(self) -> object:
        return self._body


class _ScriptedClient:
    """按剧本依次返回响应或抛异常的 httpx 替身。

    剧本用完以后继续返回 200 —— 让「重试几次」这件事由调用次数说了算。
    """

    def __init__(self, script: list[object]) -> None:
        self.script = list(script)
        self.calls: list[tuple[str, dict, dict]] = []

    def _next(self, url: str, headers: dict, payload: dict) -> object:
        self.calls.append((url, dict(headers), dict(payload)))
        item = self.script.pop(0) if self.script else _FakeResponse(200, {})
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, url: str, headers: dict | None = None, json: dict | None = None):
        return self._next(url, headers or {}, json or {})

    def get(self, url: str, headers: dict | None = None, params: dict | None = None):
        return self._next(url, headers or {}, params or {})


def _policy(max_retries: int = 2) -> tuple[RetryPolicy, list[float]]:
    """造一个不真等（把退避秒数记下来）的重试策略。"""
    delays: list[float] = []
    policy = RetryPolicy(
        max_retries=max_retries,
        backoff_base=0.5,
        backoff_max=10.0,
        sleep=delays.append,
    )
    return policy, delays


def _platform(client: _ScriptedClient, **kwargs) -> ResearchPlatformClient:
    """装配一个科研数据平台客户端（端点与令牌都配好）。"""
    policy, delays = _policy(kwargs.pop("max_retries", 2))
    client_ = ResearchPlatformClient(
        base_url="https://research.example.invalid",
        token="token-research",
        client=client,
        key_id="key-2026-10",
        retry_policy=policy,
        **kwargs,
    )
    client_.delays = delays  # type: ignore[attr-defined]
    return client_


def _payload() -> dict:
    """投递载荷（守护进程组装的形状：材料带本机路径，字段更少）。"""
    return {
        "application_no": "KY20260001",
        "ethics_approval_no": "EC-2026-0001",
        "materials": [
            {
                "material_id": "KY20260001-CHK0000001-01",
                "kind": "report_text",
                "sha256": "0" * 64,
                "path": "/tmp/M-1.txt",
            }
        ],
        "manifest_path": "/tmp/manifest.jsonl",
    }


def _body() -> dict:
    """交付体（``POST /api/v1/datasets`` 的请求体形状，按 spec.md 字段规范）。

    客户端在**外发前**按字段规范校验这份请求体 —— 校验不过一个请求都不发，
    所以这里给的就是一份字段齐全的合规交付体。
    """
    return {
        "application_no": "KY20260001",
        "ethics_approval_no": "EC-2026-0001",
        "dataset_name": "科研脱敏交付 KY20260001",
        "material_count": 1,
        "materials": [
            {
                "material_id": "KY20260001-CHK0000001-01",
                "kind": "report_text",
                "sha256": "0" * 64,
                "storage_uri": "file:///tmp/M-1.txt",
            }
        ],
        "pseudonymization": {"scheme": "hmac-sha256", "key_id": "key-2026-10"},
        "manifest_uri": "file:///tmp/manifest.jsonl",
    }


# ------------------------------------------------------------- 1. 5xx 退避


def test_5xx退避后成功且请求发两次() -> None:
    """平台先回 503：客户端退避重试，第二次成功 —— 不必把整批挂起。"""
    client = _ScriptedClient([_FakeResponse(503, {}), _FakeResponse(200, {"dataset_id": "DS-1"})])
    platform = _platform(client)

    receipt = platform.create_dataset(_body(), idempotency_key="KY20260001.abc")

    assert receipt.dataset_id == "DS-1"
    assert len(client.calls) == 2
    # 退避间隔按指数拉开：第 1 次失败后等 0.5s
    assert platform.delays == [0.5]
    # 重试时**同一把幂等键** —— 平台按键去重，不会产生第二个数据集
    keys = {call[1].get("Idempotency-Key") for call in client.calls}
    assert keys == {"KY20260001.abc"}


def test_5xx退避超次后按服务端错误归类() -> None:
    """连续 5xx：退避重试 2 次（共 3 次尝试）后报错，归类为 server_error。"""
    client = _ScriptedClient([_FakeResponse(503, {}), _FakeResponse(503, {}), _FakeResponse(503, {})])
    platform = _platform(client)

    with pytest.raises(PlatformError) as excinfo:
        platform.create_dataset(_body(), idempotency_key="KY20260001.abc")

    error = excinfo.value
    assert len(client.calls) == 3  # 1 次 + 2 次退避重试
    assert platform.delays == [0.5, 1.0]  # 指数退避
    assert error.category is FailureCategory.SERVER_ERROR
    assert error.status == 503
    assert error.retryable is True
    decision = error.decision
    assert decision.alert_code == "outbound_server_error"
    assert decision.alert_level == "error"
    assert decision.batch_state == "pending_delivery"


# ------------------------------------------------------------- 2. 4xx 不重试


def test_4xx不重试直接报错() -> None:
    """平台回 400：请求本身不对，重试只是把同一个错再犯一遍 —— 只发一次。"""
    client = _ScriptedClient([_FakeResponse(400, {})])
    platform = _platform(client)

    with pytest.raises(PlatformError) as excinfo:
        platform.create_dataset(_body(), idempotency_key="KY20260001.abc")

    error = excinfo.value
    assert len(client.calls) == 1
    assert platform.delays == []
    assert error.category is FailureCategory.REQUEST_REJECTED
    assert error.status == 400
    assert error.retryable is False
    decision = error.decision
    assert decision.alert_code == "outbound_request_rejected"
    assert decision.alert_level == "error"
    assert decision.batch_state == "pending_delivery"


def test_401鉴权失败不重试且单独归类() -> None:
    """令牌无效：归类 auth_failed，不重试，等人换令牌后重投。"""
    for status in (401, 403):
        client = _ScriptedClient([_FakeResponse(status, {})])
        platform = _platform(client)

        with pytest.raises(PlatformError) as excinfo:
            platform.create_dataset(_body(), idempotency_key="KY20260001.abc")

        error = excinfo.value
        assert len(client.calls) == 1
        assert platform.delays == []
        assert error.category is FailureCategory.AUTH_FAILED
        assert error.retryable is False
        assert error.decision.alert_code == "outbound_auth_failed"
        assert error.decision.alert_level == "error"


# ------------------------------------------------------------- 3. 超时归类


def test_超时归类为timeout并退避重试() -> None:
    """主索引超时：归类 timeout（可重试），退避后成功。"""
    timeout = httpx.ConnectTimeout(
        "timed out", request=httpx.Request("GET", "https://his.example.invalid")
    )
    client = _ScriptedClient(
        [timeout, _FakeResponse(200, {"patient_id": "P-1001", "visit_no": "90000001"})]
    )
    policy, delays = _policy()
    index = PatientIndexClient(
        base_url="https://his.example.invalid",
        token="token-his",
        client=client,
        retry_policy=policy,
    )

    record = index.lookup("90000001")

    assert record.patient_id == "P-1001"
    assert len(client.calls) == 2
    assert delays == [0.5]


def test_超时重试耗尽后按timeout归类且批次挂起() -> None:
    """连续超时：归类 timeout，批次应落到 suspended（身份锚定不可信）。"""
    timeout = httpx.ConnectTimeout(
        "timed out", request=httpx.Request("GET", "https://his.example.invalid")
    )
    client = _ScriptedClient([timeout, timeout, timeout])
    policy, delays = _policy()
    index = PatientIndexClient(
        base_url="https://his.example.invalid",
        token="token-his",
        client=client,
        retry_policy=policy,
    )

    with pytest.raises(PatientIndexError) as excinfo:
        index.lookup("90000001")

    error = excinfo.value
    assert len(client.calls) == 3
    assert delays == [0.5, 1.0]
    assert error.category is FailureCategory.TIMEOUT
    assert error.kind == "unreachable"  # 状态机据此把批次挂起
    assert error.retryable is True
    decision = error.decision
    assert decision.alert_code == "outbound_timeout"
    assert decision.alert_level == "warning"
    assert decision.batch_state == "suspended"


def test_连不上归类为connection_error() -> None:
    """连不上与超时分开归类，但都归到「可重试」。"""
    refused = httpx.ConnectError(
        "refused", request=httpx.Request("GET", "https://his.example.invalid")
    )
    assert classify_exception(refused) is FailureCategory.CONNECTION_ERROR
    assert classify_exception(
        httpx.ReadTimeout("t", request=httpx.Request("GET", "https://x.invalid"))
    ) is FailureCategory.TIMEOUT


# ------------------------------------------------- 4. 端点缺失 → 通道挂起


def test_端点缺失时通道挂起且一个请求都不发(monkeypatch) -> None:
    """端点或令牌没配：通道置挂起并告警，**不指向本地替身**。"""
    for name in ("HIS_BASE_URL", "HIS_API_TOKEN", "RESEARCH_DATA_BASE_URL", "RESEARCH_DATA_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    client = _ScriptedClient([])
    index = PatientIndexClient(client=client)
    platform = ResearchPlatformClient(client=client, key_id="key-2026-10")

    assert index.status == "suspended"
    assert platform.status == "suspended"

    with pytest.raises(ChannelSuspendedError) as index_exc:
        index.lookup("90000001")
    assert index_exc.value.category is FailureCategory.ENDPOINT_UNCONFIGURED
    assert index_exc.value.retryable is False
    assert index_exc.value.decision.alert_code == "outbound_channel_suspended"
    assert index_exc.value.decision.alert_level == "error"

    with pytest.raises(ChannelSuspendedError) as platform_exc:
        platform.deliver("KY20260001", _payload())
    assert platform_exc.value.category is FailureCategory.ENDPOINT_UNCONFIGURED

    # 一个请求都没发出去 —— 「没配置」不是「换个地方假装成功」
    assert client.calls == []


def test_未配置通道的告警落进台账(monkeypatch) -> None:
    """通道挂起这件事必须落在台账里，不能只写在日志里。"""
    for name in ("HIS_BASE_URL", "HIS_API_TOKEN", "RESEARCH_DATA_BASE_URL", "RESEARCH_DATA_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    from research_redact.config import OutboundConfig

    alerts = OutboundConfig.from_env().alerts("KY20260001")
    codes = {alert.code for alert in alerts}
    assert "outbound_channel_suspended" in codes
    for alert in alerts:
        assert alert.level == "error"
        assert "本地替身" in alert.message


# ------------------------------------------------------- 分类 → 状态与级别


def test_错误分类到批次状态与告警级别的映射() -> None:
    """分类口径写死在这里：改分类就要改这张表。"""
    cases = [
        # (类别, 通道, 可重试, 批次状态, 告警级别, 告警码)
        (FailureCategory.AUTH_FAILED, CHANNEL_RESEARCH, False, "pending_delivery", "error", "outbound_auth_failed"),
        (FailureCategory.ENDPOINT_UNCONFIGURED, CHANNEL_RESEARCH, False, "pending_delivery", "error", "outbound_channel_suspended"),
        (FailureCategory.REQUEST_REJECTED, CHANNEL_RESEARCH, False, "pending_delivery", "error", "outbound_request_rejected"),
        (FailureCategory.PAYLOAD_INVALID, CHANNEL_RESEARCH, False, "pending_delivery", "error", "outbound_payload_invalid"),
        (FailureCategory.RESPONSE_INVALID, CHANNEL_RESEARCH, False, "pending_delivery", "error", "outbound_response_invalid"),
        (FailureCategory.SERVER_ERROR, CHANNEL_RESEARCH, True, "pending_delivery", "error", "outbound_server_error"),
        (FailureCategory.TIMEOUT, CHANNEL_RESEARCH, True, "pending_delivery", "warning", "outbound_timeout"),
        (FailureCategory.CONNECTION_ERROR, CHANNEL_RESEARCH, True, "pending_delivery", "warning", "outbound_unreachable"),
        (FailureCategory.CONNECTION_ERROR, CHANNEL_HIS, True, "suspended", "warning", "outbound_unreachable"),
        (FailureCategory.SERVER_ERROR, CHANNEL_HIS, True, "suspended", "error", "outbound_server_error"),
        (FailureCategory.AUTH_FAILED, CHANNEL_HIS, False, "suspended", "error", "outbound_auth_failed"),
    ]
    for category, channel, retryable, state, level, code in cases:
        decision = decide_failure(category, channel=channel)
        assert decision.retryable is retryable, category
        assert decision.batch_state == state, (category, channel)
        assert decision.alert_level == level, category
        assert decision.alert_code == code, category


def test_状态码分类口径() -> None:
    """2xx 不是失败；401/403 鉴权；4xx 请求被拒；5xx 服务端错误。"""
    assert classify_status(200) is None
    assert classify_status(204) is None
    assert classify_status(401) is FailureCategory.AUTH_FAILED
    assert classify_status(403) is FailureCategory.AUTH_FAILED
    assert classify_status(400) is FailureCategory.REQUEST_REJECTED
    assert classify_status(404) is FailureCategory.REQUEST_REJECTED
    assert classify_status(422) is FailureCategory.REQUEST_REJECTED
    assert classify_status(500) is FailureCategory.SERVER_ERROR
    assert classify_status(503) is FailureCategory.SERVER_ERROR
    assert classify_status(0) is FailureCategory.CONNECTION_ERROR


# ---------------------------------------------------------- 请求体校验不过


def test_请求体校验不过时不外发() -> None:
    """交付体缺 key_id：本地校验不过，**请求根本没发出去**。"""
    client = _ScriptedClient([])
    platform = ResearchPlatformClient(
        base_url="https://research.example.invalid",
        token="token-research",
        client=client,
        key_id="",
    )

    with pytest.raises(PlatformError) as excinfo:
        platform.deliver("KY20260001", _payload())

    error = excinfo.value
    assert error.category is FailureCategory.PAYLOAD_INVALID
    assert error.retryable is False
    assert error.decision.alert_code == "outbound_payload_invalid"
    assert client.calls == []


def test_响应结构不对不当成成功() -> None:
    """回执缺 dataset_id：不能当成交付成功。"""
    client = _ScriptedClient([_FakeResponse(200, {"application_no": "KY20260001"})])
    platform = _platform(client)

    with pytest.raises(PlatformError) as excinfo:
        platform.create_dataset(_body(), idempotency_key="KY20260001.abc")

    assert excinfo.value.category is FailureCategory.RESPONSE_INVALID
    assert excinfo.value.retryable is False


# ------------------------------------------------------------- 队列层处置


def _build_batch(tmp_path: Path) -> tuple[BatchRunner, BatchLedger]:
    """跑出一批已代号化的批次（供队列投递用）。"""
    inbox = tmp_path / "inbox"
    application_dir = inbox / "KY20260001"
    (application_dir / "materials").mkdir(parents=True, exist_ok=True)
    (application_dir / "application.json").write_text(
        json.dumps(
            {
                "application_no": "KY20260001",
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
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (application_dir / "materials" / "report_001.txt").write_text(
        MATERIAL_TEXT, encoding="utf-8"
    )
    ledger = BatchLedger(tmp_path / "ledger.sqlite3")
    runner = BatchRunner(
        output_dir=tmp_path / "outbox",
        ledger=ledger,
    )
    watcher = InboxWatcher(inbox)
    events = watcher.poll()
    assert events, "投递目录里的申请单应当被监听到"
    runner.process(events[0], via_event=True)
    return runner, ledger


def test_队列对不可重试的失败当场挂起(tmp_path: Path) -> None:
    """平台回 400：队列**不再退避重试**，当场挂起并按分类给告警码。"""
    runner, ledger = _build_batch(tmp_path)
    attempts: list[str] = []

    def rejecting(batch_no: str, payload) -> bool:
        attempts.append(batch_no)
        raise PlatformError(
            "对端拒绝请求：请求内容不合规",
            status=400,
            category=FailureCategory.REQUEST_REJECTED,
        )

    queue = DeliveryQueue(
        deliver=rejecting, ledger=ledger, notifier=RecordingNotifier(), max_retries=2
    )

    outcome = queue.submit("KY20260001", {})

    assert outcome.delivered is False
    assert outcome.exhausted is True
    assert outcome.attempts == 1  # 只试了一次：不退避重试
    assert len(attempts) == 1
    assert ledger.get_batch("KY20260001").batch_state is BatchState.PENDING_DELIVERY
    alerts = ledger.alerts("KY20260001")
    rejected = [alert for alert in alerts if alert.code == "outbound_request_rejected"]
    assert len(rejected) == 1
    assert rejected[0].level == "error"
    # 告警文案不含任何命中原文
    for secret in IDENTITY_STRINGS:
        assert secret not in rejected[0].message


def test_队列对可重试的失败仍退避重试并在超次后挂起(tmp_path: Path) -> None:
    """平台 5xx：队列照旧退避重试，超次挂起（告警码仍是 delivery_exhausted）。"""
    runner, ledger = _build_batch(tmp_path)
    attempts: list[str] = []

    def failing(batch_no: str, payload) -> bool:
        attempts.append(batch_no)
        raise PlatformError(
            "对端服务端错误（5xx）：可退避重试",
            status=503,
            category=FailureCategory.SERVER_ERROR,
        )

    clock = _FakeClock()
    queue = DeliveryQueue(
        deliver=failing,
        ledger=ledger,
        notifier=RecordingNotifier(),
        max_retries=2,
        backoff_base=2.0,
        clock=clock,
    )

    first = queue.submit("KY20260001", {})
    assert first.delivered is False
    assert first.exhausted is False
    assert first.attempts == 1
    assert first.next_attempt_in == 2.0
    assert queue.run_due() == ()  # 还没到点，不重试

    clock.advance(2.0)
    second = queue.run_due()[0]
    assert second.exhausted is False
    assert second.attempts == 2
    assert second.next_attempt_in == 4.0

    clock.advance(4.0)
    third = queue.run_due()[0]
    assert third.exhausted is True
    assert third.attempts == 3
    assert len(attempts) == 3
    assert ledger.get_batch("KY20260001").batch_state is BatchState.PENDING_DELIVERY
    alerts = ledger.alerts("KY20260001")
    exhausted = [alert for alert in alerts if alert.code == "delivery_exhausted"]
    assert len(exhausted) == 1
    assert exhausted[0].level == "error"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
