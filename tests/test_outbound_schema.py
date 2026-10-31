"""出站字段规范校验层（task 38）。

这一组测试盯住一件事：**校验不过就不外发**。

平台按 spec.md 的字段规范接收交付物。少一个字段、类型错一个、材料类型写错
一个、材料键不是三段式 —— 平台要么拒收（批次挂起等人重投），要么**收下一份
半成品**（材料挂不上批次、命中清单找不到）。后者更麻烦：东西已经交出去了，
对不上却没人知道。

所以断言分两层：

1. **校验层本身**：四类反例（缺字段 / 类型错 / 枚举越界 / 材料键不是三段式）
   都要报出**具体字段与期望**；
2. **接线**：校验不过时**外发客户端调用次数为 0** —— 不是「先发出去试试」。

另外守住两条老规矩：失败类别是 ``payload_invalid``（不重试 —— 重试只是把同
一个错再犯一遍），错误文案**不回显取值**（报错会进告警、进台账，患者原文不
能从报错里漏出去）。
"""

from __future__ import annotations

import json

import httpx
import pytest

from research_redact.outbound.failures import FailureCategory
from research_redact.outbound.patient_index_client import (
    PatientIndexClient,
    PatientIndexError,
)
from research_redact.outbound.research_platform_client import (
    PlatformError,
    ResearchPlatformClient,
)
from research_redact.outbound.schemas import (
    DatasetRequest,
    OutboundPayloadError,
    validate_dataset_request,
    validate_patient_index_response,
    validate_restore_audit_request,
)

PLATFORM_BASE = "https://research-data.example.internal"
PLATFORM_TOKEN = "platform-token-xyz"
HIS_BASE = "https://his.example.internal"
HIS_TOKEN = "his-token-abc"


# --------------------------------------------------------------------- 替身


class Recorder:
    """记录所有出站请求的协议替身（只出现在本测试层）。"""

    def __init__(self, responses: dict[str, httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._responses = responses or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for fragment, response in self._responses.items():
            if fragment in str(request.url):
                return response
        return httpx.Response(200, json={"dataset_id": "DS-7788", "receipt_id": "RC-1"})

    @property
    def calls(self) -> int:
        return len(self.requests)

    def body(self, index: int = -1) -> dict:
        return json.loads(self.requests[index].content.decode("utf-8"))


def _client(recorder: Recorder) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(recorder))


# ------------------------------------------------------------------ 样例报文


def _body() -> dict:
    """一份**合规**的交付体（spec.md 字段规范：顶层 7 项、材料项 4 项）。"""
    return {
        "application_no": "KY20260001",
        "ethics_approval_no": "EC-2026-0001",
        "dataset_name": "科研脱敏交付 KY20260001",
        "material_count": 1,
        "materials": [
            {
                "material_id": "KY20260001-CHK0000001-01",
                "kind": "report_text",
                "sha256": "a" * 64,
                "storage_uri": "file:///tmp/outbox/M-1.txt",
            }
        ],
        "pseudonymization": {"scheme": "hmac-sha256", "key_id": "key-2026-10"},
        "manifest_uri": "file:///tmp/outbox/manifest.jsonl",
    }


def _restore_body() -> dict:
    """一份**合规**的还原回执体（固定 9 项）。"""
    return {
        "restore_request_id": "RR-2026-0001",
        "dataset_id": "DS-7788",
        "approver_a": "科研数据管理员甲",
        "approver_b": "信息科乙",
        "scope": ["KY20260001-CHK0000001-01"],
        "reason": "伦理核查要求换回原文",
        "granted_at": "2026-10-31T08:30:00Z",
        "expires_at": "2026-10-31T18:30:00Z",
        "result_summary": "已还原 1 份材料",
    }


def _with(**overrides) -> dict:
    """在合规交付体上覆盖若干字段。"""
    body = _body()
    body.update(overrides)
    return body


def _with_material(**overrides) -> dict:
    """在合规交付体上覆盖材料项的若干字段。"""
    body = _body()
    material = dict(body["materials"][0])
    material.update(overrides)
    body["materials"] = [material]
    return body


# ------------------------------------------------------------------ 校验层


def test_合规交付体通过校验():
    """正例：字段齐全的交付体校验通过，且模型能原样转回报文。"""
    model = validate_dataset_request(_body())

    assert isinstance(model, DatasetRequest)
    dumped = model.model_dump()
    assert set(dumped) == {
        "application_no",
        "ethics_approval_no",
        "dataset_name",
        "material_count",
        "materials",
        "pseudonymization",
        "manifest_uri",
    }
    assert dumped["materials"][0]["material_id"] == "KY20260001-CHK0000001-01"
    assert dumped["pseudonymization"] == {"scheme": "hmac-sha256", "key_id": "key-2026-10"}


def test_缺字段时报出具体字段名():
    """反例一：缺字段 —— 错误信息点名是哪个字段缺了。"""
    body = _body()
    body.pop("ethics_approval_no")

    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(body)

    error = excinfo.value
    assert "ethics_approval_no" in str(error)
    assert "必填字段缺失" in str(error)
    assert error.fields == ("ethics_approval_no",)


def test_类型错时报出具体字段与期望():
    """反例二：类型错 —— 材料数写成字符串，报「必须是整数」。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with(material_count="2"))

    error = excinfo.value
    assert "material_count" in str(error)
    assert "必须是整数" in str(error)

    # 布尔值不算整数（True 会被当成 1 混进去）
    with pytest.raises(OutboundPayloadError) as bool_excinfo:
        validate_dataset_request(_with(material_count=True))
    assert "material_count" in str(bool_excinfo.value)


def test_材料类型枚举越界时报出允许的四个取值():
    """反例三：枚举越界 —— 材料类型不是四值之一，报出允许值。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with_material(kind="video"))

    error = excinfo.value
    assert "materials[0].kind" in str(error)
    for allowed in ("report_text", "report_json", "table", "dicom"):
        assert allowed in str(error)


def test_材料键不是三段式时报出三段式要求():
    """反例四：材料键不是「申请单号-检查号-序号」三元组，报出形状要求。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with_material(material_id="M-1"))

    error = excinfo.value
    assert "materials[0].material_id" in str(error)
    assert "三段式" in str(error)

    # 序号段不是数字，同样不放行
    with pytest.raises(OutboundPayloadError) as seq_excinfo:
        validate_dataset_request(
            _with_material(material_id="KY20260001-CHK0000001-末份")
        )
    assert "材料序号段必须是数字" in str(seq_excinfo.value)


def test_材料数与清单条数对不上时拒收():
    """声明 2 份、清单 1 份 —— 半成品，不放行。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with(material_count=2))

    assert "material_count" in str(excinfo.value)
    assert "对不上" in str(excinfo.value)


def test_摘要与清单位置不合法时拒收():
    """摘要不是 64 位十六进制、命中清单位置为空 —— 都不放行。"""
    with pytest.raises(OutboundPayloadError) as sha_excinfo:
        validate_dataset_request(_with_material(sha256="abc"))
    assert "sha256" in str(sha_excinfo.value)

    with pytest.raises(OutboundPayloadError) as uri_excinfo:
        validate_dataset_request(_with(manifest_uri=""))
    assert "manifest_uri" in str(uri_excinfo.value)


def test_一致代号方案只能是hmac_sha256且密钥版本号不能空():
    """方案名写错、密钥版本号为空 —— 事后说不清这批代号用的哪把密钥。"""
    with pytest.raises(OutboundPayloadError) as scheme_excinfo:
        validate_dataset_request(
            _with(pseudonymization={"scheme": "md5", "key_id": "key-2026-10"})
        )
    assert "scheme" in str(scheme_excinfo.value)

    with pytest.raises(OutboundPayloadError) as key_excinfo:
        validate_dataset_request(
            _with(pseudonymization={"scheme": "hmac-sha256", "key_id": ""})
        )
    assert "key_id" in str(key_excinfo.value)


def test_报文字段之外的字段不放行():
    """多一个字段就是「这不是我们约定的报文」—— 不放行。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with(unknown_field="x"))

    assert "unknown_field" in str(excinfo.value)


def test_校验不过时错误信息不回显取值也不含患者原文():
    """错误文案会进告警、进台账 —— 不许把取值（患者原文）带出去。"""
    body = _with_material(material_id="张某某")

    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(body)

    message = str(excinfo.value)
    assert "张某某" not in message
    assert "90000001" not in message


def test_校验失败归类为payload_invalid且不重试():
    """本地校验失败不重试：重试只是把同一个错再犯一遍。"""
    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_dataset_request(_with(ethics_approval_no=""))

    error = excinfo.value
    assert error.category is FailureCategory.PAYLOAD_INVALID
    assert error.retryable is False
    assert error.decision.alert_code == "outbound_payload_invalid"


# ------------------------------------------------------------------ 接线


def test_交付体校验不过时外发调用次数为零():
    """接线一：交付体不过 —— 一个请求都不发。"""
    recorder = Recorder()
    platform = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        key_id="key-2026-10",
    )

    with pytest.raises(PlatformError) as excinfo:
        platform.create_dataset(
            _with_material(material_id="M-1"), idempotency_key="KY20260001.abc"
        )

    error = excinfo.value
    assert error.category is FailureCategory.PAYLOAD_INVALID
    assert error.retryable is False
    assert "三段式" in str(error)
    assert recorder.calls == 0


def test_整批投递时字段不过同样不外发():
    """接线二：走整批投递（守护进程那条路）也一样不外发。"""
    recorder = Recorder()
    platform = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        key_id="key-2026-10",
    )
    payload = {
        "application_no": "KY20260001",
        "ethics_approval_no": "EC-2026-0001",
        "materials": [
            {
                "material_id": "M-1",
                "kind": "report_text",
                "sha256": "a" * 64,
                "path": "/tmp/M-1.txt",
            }
        ],
        "manifest_path": "/tmp/manifest.jsonl",
    }

    with pytest.raises(PlatformError) as excinfo:
        platform.deliver("KY20260001", payload)

    assert excinfo.value.category is FailureCategory.PAYLOAD_INVALID
    assert recorder.calls == 0


def test_还原回执校验不过时不外发():
    """接线三：还原回执缺第二授权人 —— 不外发（单人还原不留回执）。"""
    recorder = Recorder()
    platform = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        key_id="key-2026-10",
    )

    with pytest.raises(PlatformError) as excinfo:
        platform.record_restore_audit(
            restore_request_id="RR-2026-0001",
            dataset_id="DS-7788",
            approver_a="科研数据管理员甲",
            approver_b="",
            scope=["KY20260001-CHK0000001-01"],
        )

    assert excinfo.value.category is FailureCategory.PAYLOAD_INVALID
    assert "approver_b" in str(excinfo.value)
    assert recorder.calls == 0


def test_合规报文照常外发且字段不多不少():
    """接线四：合规报文照发 —— 校验层不能挡住正常交付。"""
    recorder = Recorder()
    platform = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        key_id="key-2026-10",
    )

    receipt = platform.create_dataset(
        _body(), idempotency_key="KY20260001.abc"
    )

    assert receipt.dataset_id == "DS-7788"
    assert recorder.calls == 1
    sent = recorder.body()
    assert set(sent) == set(_body())
    assert sent["materials"][0]["storage_uri"] == "file:///tmp/outbox/M-1.txt"


def test_还原回执合规时照常外发():
    """接线五：还原回执的 9 个字段不多不少地发出去。"""
    recorder = Recorder(
        {
            "/restore-audit": httpx.Response(
                200, json={"restore_audit_id": "RA-0001", "dataset_id": "DS-7788"}
            )
        }
    )
    platform = ResearchPlatformClient(
        PLATFORM_BASE,
        PLATFORM_TOKEN,
        client=_client(recorder),
        key_id="key-2026-10",
    )
    body = _restore_body()

    receipt = platform.record_restore_audit(
        restore_request_id=body["restore_request_id"],
        dataset_id=body["dataset_id"],
        approver_a=body["approver_a"],
        approver_b=body["approver_b"],
        scope=body["scope"],
        reason=body["reason"],
        granted_at=body["granted_at"],
        expires_at=body["expires_at"],
        result_summary=body["result_summary"],
    )

    assert receipt.restore_audit_id == "RA-0001"
    assert recorder.calls == 1
    sent = recorder.body()
    assert set(sent) == set(body)
    assert sent["scope"] == ["KY20260001-CHK0000001-01"]


# ------------------------------------------------------------- 主索引响应体


def test_主索引响应缺patient_id判为结构错误():
    """响应体不合规 —— 不能当成成功（身份锚定不了）。"""
    recorder = Recorder(
        {"/api/v1/patient-index": httpx.Response(200, json={"visit_no": "90000001"})}
    )
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    with pytest.raises(PatientIndexError) as excinfo:
        client.lookup("90000001")

    error = excinfo.value
    assert error.kind == "payload"
    assert "patient_id" in str(error)
    assert error.retryable is False


def test_主索引响应字段类型不对判为结构错误():
    """住院号不是字符串 —— 结构不对，不当成成功。"""
    recorder = Recorder(
        {
            "/api/v1/patient-index": httpx.Response(
                200, json={"patient_id": "P-1001", "visit_no": 90000001}
            )
        }
    )
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    with pytest.raises(PatientIndexError) as excinfo:
        client.lookup("90000001")

    assert excinfo.value.kind == "payload"


def test_主索引响应允许多余字段但主键必须齐():
    """院内系统字段口径不一：多余字段放过，主键不能少。"""
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
                    "院内自定义字段": "whatever",
                },
            )
        }
    )
    client = PatientIndexClient(HIS_BASE, HIS_TOKEN, client=_client(recorder))

    record = client.lookup("90000001")

    assert record.patient_id == "P-1001"
    assert record.visit_no == "90000001"
    assert record.name == "张某某"


def test_主索引响应校验入口可直接调用():
    """校验层是独立能力：业务代码也能直接用它把关。"""
    model = validate_patient_index_response(
        {"patient_id": "P-1001", "visit_no": "90000001"}
    )
    assert model.patient_id == "P-1001"
    assert model.name == ""


def test_还原回执校验入口可直接调用():
    """还原回执的字段规范同样有独立入口。"""
    model = validate_restore_audit_request(_restore_body())
    assert model.dataset_id == "DS-7788"
    assert model.scope == ["KY20260001-CHK0000001-01"]

    with pytest.raises(OutboundPayloadError) as excinfo:
        validate_restore_audit_request({**_restore_body(), "scope": "不是列表"})
    assert "scope" in str(excinfo.value)
