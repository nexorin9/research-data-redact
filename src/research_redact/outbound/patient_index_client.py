"""出站读：HIS 患者主索引（患者身份的权威来源）。

**为什么必须有这一层**：本项目的患者身份以 HIS 患者主索引主键为准 ——
同名的人靠主键区分，同一个人的多个住院号靠主索引归一。只按姓名硬匹配，
会把两个同名的患者串成一个人。查不到主索引时，批次置 ``suspended``，
**不降级**为「按正则直接脱」（那是拿错人身份去交付数据）。

接口规范（spec.md「最小数据格式与字段要求」）：

- ``GET {HIS_BASE_URL}/api/v1/patient-index?visit_no=<住院号>``
- 请求头 ``Authorization: Bearer $HIS_API_TOKEN``
- 响应体 ``{patient_id, visit_no, name, id_card_masked, birth_date, sex}``

**只读**：本客户端不向 HIS 写入任何东西。

**不静默降级**：端点或令牌没配时，调用直接抛
:class:`~research_redact.outbound.errors.ChannelSuspendedError`，**不发请求**，
也不改指本地替身。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import httpx

from ..config import (
    CHANNEL_HIS,
    HIS_API_TOKEN_ENV,
    HIS_BASE_URL_ENV,
    ChannelConfig,
    OutboundConfig,
)
from .errors import OutboundError
from .failures import FailureCategory, classify_status, decide_failure
from .retry import RetryPolicy, call_with_retry
from .schemas import OutboundPayloadError, validate_patient_index_response

__all__ = [
    "PATIENT_INDEX_PATH",
    "PatientIndexClient",
    "PatientIndexError",
    "PatientIndexRecord",
]

logger = logging.getLogger(__name__)

#: 患者主索引查询路径（拼在 $HIS_BASE_URL 之后）。
PATIENT_INDEX_PATH = "/api/v1/patient-index"

#: 出站失败类别 → 状态机看的 ``kind``。
#:
#: ``unreachable``（连不上 / 超时）让批次挂起等主索引恢复；``http_status``
#: （对端报错）按处理失败处理；``payload``（响应结构不对）同样不当成功。
_KIND_BY_CATEGORY: dict[FailureCategory, str] = {
    FailureCategory.CONNECTION_ERROR: "unreachable",
    FailureCategory.TIMEOUT: "unreachable",
    FailureCategory.ENDPOINT_UNCONFIGURED: "unreachable",
    FailureCategory.SERVER_ERROR: "http_status",
    FailureCategory.AUTH_FAILED: "http_status",
    FailureCategory.REQUEST_REJECTED: "http_status",
    FailureCategory.RESPONSE_INVALID: "payload",
    FailureCategory.PAYLOAD_INVALID: "payload",
    FailureCategory.CLIENT_ERROR: "payload",
}


class PatientIndexError(OutboundError):
    """患者主索引查询失败。

    :param kind: 失败类别 —— ``unreachable``（连不上）、``http_status``、
        ``payload``（响应结构不对）。批次状态机据此把「连不上」映射成
        ``patient_index_unreachable``（挂起），把「响应不对」映射成处理失败。
    :param category: 出站失败类别（:mod:`research_redact.outbound.failures`）；
        与 ``kind`` 并行：``kind`` 给状态机看，``category`` 给重试与告警裁决看。
    """

    def __init__(
        self,
        message: str,
        *,
        kind: str = "unreachable",
        status: int = 0,
        retryable: bool | None = None,
        category: FailureCategory | str | None = None,
    ) -> None:
        super().__init__(
            message,
            status=status,
            channel=CHANNEL_HIS,
            retryable=retryable,
            category=category,
        )
        self.kind = kind


@dataclass(frozen=True)
class PatientIndexRecord:
    """主索引读回的一条患者记录。

    ``patient_id`` 是本项目的患者权威标识：一致代号（HMAC）以它为输入，
    同名异人靠它区分。
    """

    patient_id: str
    visit_no: str
    name: str = ""
    id_card_masked: str = ""
    birth_date: str = ""
    sex: str = ""

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PatientIndexRecord":
        """从响应体装配记录。

        :raises PatientIndexError: 响应缺少 ``patient_id``（kind=``payload``）。
        """
        patient_id = str(payload.get("patient_id") or "").strip()
        if not patient_id:
            raise PatientIndexError(
                "患者主索引响应缺少 patient_id 字段：无法锚定患者身份",
                kind="payload",
                status=200,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            )
        return cls(
            patient_id=patient_id,
            visit_no=str(payload.get("visit_no") or "").strip(),
            name=str(payload.get("name") or "").strip(),
            id_card_masked=str(payload.get("id_card_masked") or "").strip(),
            birth_date=str(payload.get("birth_date") or "").strip(),
            sex=str(payload.get("sex") or "").strip(),
        )


class PatientIndexClient:
    """HIS 患者主索引客户端。

    :param base_url: 端点覆盖（缺省取 ``$HIS_BASE_URL``）。
    :param token: 令牌覆盖（缺省取 ``$HIS_API_TOKEN``）。
    :param timeout: 单次调用超时（秒）。
    :param client: 预置的 httpx 客户端（测试用协议替身走这里）。
    :param config: 出站配置快照；缺省按环境变量装配。
    """

    #: 通道名。
    channel = CHANNEL_HIS
    #: 查询路径。
    path = PATIENT_INDEX_PATH

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        *,
        timeout: float | None = None,
        client: Any | None = None,
        config: OutboundConfig | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._config = config if config is not None else OutboundConfig.from_env()
        base = (base_url if base_url is not None else self._config.his.base_url).strip()
        bearer = (token if token is not None else self._config.his.token).strip()
        missing: list[str] = []
        if not base:
            missing.append(HIS_BASE_URL_ENV)
        if not bearer:
            missing.append(HIS_API_TOKEN_ENV)
        self._channel = ChannelConfig(
            name=CHANNEL_HIS,
            base_url=base,
            token=bearer,
            missing_env=tuple(missing),
            timeout=timeout if timeout is not None else self._config.his.timeout,
        )
        self._client = client
        # 出站重试策略：连接错误 / 超时 / 5xx 退避重试（≤2 次），4xx 不重试。
        self._retry_policy = (
            retry_policy if retry_policy is not None else RetryPolicy()
        )

    # ------------------------------------------------------------------ 判定

    @property
    def configured(self) -> bool:
        """通道是否已就绪（端点 + 令牌齐备）。"""
        return self._channel.configured

    @property
    def status(self) -> str:
        """通道状态：``ready`` / ``suspended`` / ``unauthenticated``。"""
        return self._channel.status

    @property
    def reason(self) -> str:
        """通道未就绪的原因（写进告警文案）。"""
        return self._channel.reason

    def url_for(self, visit_no: str) -> str:
        """拼出实际请求 URL（测试与日志用）。"""
        return f"{self._channel.base_url.rstrip('/')}{self.path}"

    # ------------------------------------------------------------------ 查询

    def lookup(self, visit_no: str) -> PatientIndexRecord:
        """按住院号查一次患者主索引。

        :param visit_no: 住院号 / 就诊号。
        :raises ChannelSuspendedError: 通道未配置（**不发请求**）。
        :raises PatientIndexError: 连不上、对端报错或响应结构不对。
        """
        self._channel.require()
        key = (visit_no or "").strip()
        if not key:
            raise PatientIndexError(
                "住院号为空：不发起主索引查询",
                kind="payload",
                retryable=False,
            )

        url = self.url_for(key)
        headers = {
            "Authorization": f"Bearer {self._channel.token}",
            "Accept": "application/json",
        }
        params = {"visit_no": key}
        response = self._request(url, headers=headers, params=params)
        status = getattr(response, "status_code", 0)
        if status < 200 or status >= 300:
            # 重试层已经按分类处理过非 2xx；走到这里说明客户端返回了非标准
            # 响应对象 —— 仍按分类报错，不当成成功。
            category = classify_status(status) or FailureCategory.RESPONSE_INVALID
            raise self._build_error(
                f"HIS 患者主索引返回 HTTP {status}", category, status
            )
        try:
            payload = response.json()
        except Exception as exc:
            raise PatientIndexError(
                f"HIS 患者主索引响应不是合法 JSON：{type(exc).__name__}",
                kind="payload",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            ) from exc
        if not isinstance(payload, Mapping):
            raise PatientIndexError(
                "HIS 患者主索引响应不是 JSON 对象",
                kind="payload",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            )
        try:
            validated = validate_patient_index_response(payload, channel=CHANNEL_HIS)
        except OutboundPayloadError as exc:
            raise PatientIndexError(
                f"HIS 患者主索引响应未通过字段规范校验：{exc}",
                kind="payload",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            ) from exc
        return PatientIndexRecord.from_payload(validated.model_dump())

    def lookup_many(self, visit_nos: Iterable[str]) -> dict[str, PatientIndexRecord]:
        """批量查询（按住院号去重后逐个查）。

        返回 ``{住院号: 记录}``；查不到的那些**不进结果**，由调用方决定是
        挂起批次还是跳过 —— 本客户端不替调用方做业务判断。
        """
        records: dict[str, PatientIndexRecord] = {}
        for visit_no in dict.fromkeys(v for v in visit_nos if (v or "").strip()):
            record = self.lookup(visit_no)
            records[visit_no] = record
        return records

    # ------------------------------------------------------------------ 内部

    def _request(
        self, url: str, *, headers: Mapping[str, str], params: Mapping[str, str]
    ) -> Any:
        """发一次 GET；按错误分类决定退避重试还是直接报错。

        重试**落在客户端里**：主索引偶发超时 / 5xx 就地退避重试，4xx 与鉴权
        失败**不重试**。主索引不可达最终会抛
        :class:`PatientIndexError`（kind=``unreachable``），由批次状态机把
        批次置 ``suspended`` —— **不降级**为按正则直接脱。
        """
        return call_with_retry(
            lambda: self._send(url, headers=headers, params=params),
            policy=self._retry_policy,
            channel=CHANNEL_HIS,
            build_error=self._build_error,
            on_retry=self._note_retry,
        )

    def _send(
        self, url: str, *, headers: Mapping[str, str], params: Mapping[str, str]
    ) -> Any:
        """真正发一次请求（异常交给重试层归类）。"""
        if self._client is not None:
            return self._client.get(url, headers=dict(headers), params=dict(params))
        with httpx.Client(timeout=self._channel.timeout) as client:
            return client.get(url, headers=dict(headers), params=dict(params))

    def _build_error(
        self, message: str, category: FailureCategory, status: int
    ) -> PatientIndexError:
        """把重试层给出的失败类别收口成 :class:`PatientIndexError`。"""
        decision = decide_failure(category, channel=CHANNEL_HIS)
        return PatientIndexError(
            message,
            kind=_KIND_BY_CATEGORY.get(category, "http_status"),
            status=status,
            category=category,
            retryable=decision.retryable,
        )

    def _note_retry(self, attempt: int, decision, delay: float) -> None:
        """退避重试前记一笔。"""
        logger.warning(
            "HIS 患者主索引出站调用第 %s 次失败（%s），%.1fs 后重试",
            attempt,
            decision.alert_code,
            delay,
        )
