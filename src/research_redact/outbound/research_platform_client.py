"""出站写：科研数据平台（数据集交付 + 还原回执）。

这是本项目**真正改变业务状态**的一层：脱敏产物不是躺在本地目录里就算完，
它要交到科研数据平台上、平台回了回执才算交付完成。

接口规范（spec.md「最小数据格式与字段要求」）：

- ``POST {RESEARCH_DATA_BASE_URL}/api/v1/datasets``
  请求头 ``Authorization: Bearer $RESEARCH_DATA_TOKEN`` +
  ``Idempotency-Key: <批次幂等键>``
  体：``{application_no, ethics_approval_no, dataset_name, material_count,
  materials:[{material_id, kind, sha256, storage_uri}],
  pseudonymization:{scheme, key_id}, manifest_uri}``
- ``POST {RESEARCH_DATA_BASE_URL}/api/v1/datasets/{dataset_id}/restore-audit``
  体：``{restore_request_id, dataset_id, approver_a, approver_b, scope, reason,
  granted_at, expires_at, result_summary}``

**幂等键** = 申请单号 + 材料集合指纹（材料 ID 与文件 sha256 排序后哈希，
算法见 :mod:`research_redact.idempotency`）。同一批材料重投 → 同一个键 →
台账认领表只认领一次 → **不产生第二次真实外发**，直接复用已有回执；
材料集合变了 → 指纹变 → 视为新批次，不会被误判成重复。

**不静默降级**：端点或令牌没配时直接抛
:class:`~research_redact.outbound.errors.ChannelSuspendedError`，**不发请求**，
也不改指本地替身。请求体里**不含任何患者原文** —— 只含材料 ID、类别、
sha256 与存储位置。
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import httpx

from ..config import (
    CHANNEL_RESEARCH,
    RESEARCH_DATA_BASE_URL_ENV,
    RESEARCH_DATA_TOKEN_ENV,
    ChannelConfig,
    OutboundConfig,
)
from ..idempotency import compute_idempotency_key, material_set_fingerprint
from .errors import OutboundError
from .failures import FailureCategory, classify_status, decide_failure
from .retry import RetryPolicy, call_with_retry
from .schemas import (
    OutboundPayloadError,
    validate_dataset_request,
    validate_restore_audit_request,
)

__all__ = [
    "DATASETS_PATH",
    "DatasetReceipt",
    "MaterialEntry",
    "PSEUDONYM_SCHEME",
    "PlatformError",
    "ResearchPlatformClient",
    "RestoreAuditReceipt",
    "build_idempotency_key",
    "file_sha256",
    "material_fingerprint",
]

logger = logging.getLogger(__name__)

#: 数据集交付路径（拼在 $RESEARCH_DATA_BASE_URL 之后）。
DATASETS_PATH = "/api/v1/datasets"

#: 还原回执路径后缀（拼在 ``/datasets/{dataset_id}`` 之后）。
RESTORE_AUDIT_SUFFIX = "/restore-audit"

#: 一致代号方案名（写进交付体的 ``pseudonymization.scheme``）。
PSEUDONYM_SCHEME = "hmac-sha256"


class PlatformError(OutboundError):
    """科研数据平台调用失败。

    :param category: 出站失败类别（:mod:`research_redact.outbound.failures`）；
        给了就以它为准（重试与否、告警码、批次状态都由它裁决）。
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        retryable: bool | None = None,
        category: FailureCategory | str | None = None,
    ) -> None:
        super().__init__(
            message,
            status=status,
            channel=CHANNEL_RESEARCH,
            retryable=retryable,
            category=category,
        )


@dataclass(frozen=True)
class MaterialEntry:
    """交付体里的一份材料（**不含正文，不含患者原文**）。"""

    material_id: str
    kind: str
    sha256: str
    storage_uri: str

    def to_dict(self) -> dict[str, str]:
        """转成交付体里的材料项。"""
        return {
            "material_id": self.material_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "storage_uri": self.storage_uri,
        }


@dataclass(frozen=True)
class DatasetReceipt:
    """平台侧交付回执。"""

    dataset_id: str
    application_no: str = ""
    material_count: int = 0
    receipt_id: str = ""
    accepted_at: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RestoreAuditReceipt:
    """平台侧还原回执。"""

    restore_audit_id: str
    dataset_id: str
    restore_request_id: str
    recorded_at: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------- 幂等键


def file_sha256(path: str | Path) -> str:
    """文件内容的 sha256（十六进制）—— 交付体的完整性锚点。

    分块读，不把整份材料读进内存 —— 影像材料可能不小。
    """
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def material_fingerprint(materials: Iterable[Mapping[str, Any]]) -> str:
    """材料集合指纹：材料 ID 与文件 sha256 排序后哈希。

    排序的意义：材料在清单里的顺序变了（管理员重排目录），指纹不变 ——
    那是同一批材料，不该重新交付。

    摘要取哪个文件见 :mod:`research_redact.idempotency`：优先取**源文件**
    摘要（``source_sha256``），没有才退回交付副本摘要（``sha256``）。
    """
    return material_set_fingerprint(materials)


def build_idempotency_key(application_no: str, fingerprint: str) -> str:
    """批次幂等键 = 申请单号 + 材料集合指纹。"""
    return compute_idempotency_key(application_no, fingerprint)


# --------------------------------------------------------------------- 客户端


class ResearchPlatformClient:
    """科研数据平台客户端（出站写）。

    :param base_url: 端点覆盖（缺省取 ``$RESEARCH_DATA_BASE_URL``）。
    :param token: 令牌覆盖（缺省取 ``$RESEARCH_DATA_TOKEN``）。
    :param timeout: 单次调用超时（秒）。
    :param client: 预置的 httpx 客户端（测试用协议替身走这里）。
    :param config: 出站配置快照；缺省按环境变量装配。
    :param ledger: 批次台账；给了就把幂等键与交付回执落进台账，并按幂等键
        做重投防护（同一把键只外发一次）。
    :param key_id: 一致代号密钥版本号（缺省取 ``$PSEUDONYM_KEY_ID``）。
    :param idempotency_wait_seconds: 遇到「另一个执行者正在交付同一批材料」
        时，最多等多久（秒）再判定为冲突。
    :param idempotency_poll_seconds: 等待期间的轮询间隔（秒）。
    """

    #: 通道名。
    channel = CHANNEL_RESEARCH
    #: 数据集交付路径。
    path = DATASETS_PATH

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        *,
        timeout: float | None = None,
        client: Any | None = None,
        config: OutboundConfig | None = None,
        ledger: Any | None = None,
        key_id: str | None = None,
        storage_base: str | None = None,
        idempotency_wait_seconds: float = 10.0,
        idempotency_poll_seconds: float = 0.05,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._config = config if config is not None else OutboundConfig.from_env()
        base = (
            base_url if base_url is not None else self._config.research.base_url
        ).strip()
        bearer = (token if token is not None else self._config.research.token).strip()
        missing: list[str] = []
        if not base:
            missing.append(RESEARCH_DATA_BASE_URL_ENV)
        if not bearer:
            missing.append(RESEARCH_DATA_TOKEN_ENV)
        self._channel = ChannelConfig(
            name=CHANNEL_RESEARCH,
            base_url=base,
            token=bearer,
            missing_env=tuple(missing),
            timeout=timeout if timeout is not None else self._config.research.timeout,
        )
        self._client = client
        self._ledger = ledger
        self._key_id = (
            key_id if key_id is not None else self._config.pseudonym_key_id
        ).strip()
        self._storage_base = (
            storage_base if storage_base is not None else self._config.storage_base
        ).strip()
        self._idempotency_wait_seconds = max(0.0, float(idempotency_wait_seconds))
        self._idempotency_poll_seconds = max(
            0.01, float(idempotency_poll_seconds)
        )
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

    def dataset_url(self) -> str:
        """数据集交付的实际 URL。"""
        return f"{self._channel.base_url.rstrip('/')}{self.path}"

    def restore_audit_url(self, dataset_id: str) -> str:
        """还原回执的实际 URL。"""
        return (
            f"{self._channel.base_url.rstrip('/')}{self.path}"
            f"/{dataset_id}{RESTORE_AUDIT_SUFFIX}"
        )

    # -------------------------------------------------------------- 请求体组装

    def storage_uri(self, path: str) -> str:
        """产物路径 → 交付体里的存储位置。

        配了 ``$RESEARCH_DATA_STORAGE_BASE`` 就用那个基地址（平台从共享暂存
        区或对象存储取件）；没配就是本机暂存路径的 ``file://`` URI —— **如实
        写出来**，不假装件已经上了对象存储。
        """
        if self._storage_base:
            return f"{self._storage_base.rstrip('/')}/{Path(path).name}"
        return Path(path).resolve().as_uri()

    def build_material_entries(self, payload: Mapping[str, Any]) -> list[MaterialEntry]:
        """按投递载荷组装材料清单。

        载荷里的 ``materials`` 每项形如
        ``{material_id, kind, sha256, path}``；``path`` 是本机暂存的脱敏副本。
        """
        entries: list[MaterialEntry] = []
        for item in payload.get("materials", []) or []:
            if not isinstance(item, Mapping):
                continue
            material_id = str(item.get("material_id") or "").strip()
            if not material_id:
                continue
            entries.append(
                MaterialEntry(
                    material_id=material_id,
                    kind=str(item.get("kind") or "").strip(),
                    sha256=str(item.get("sha256") or "").strip(),
                    storage_uri=self.storage_uri(str(item.get("path") or "")),
                )
            )
        return entries

    def build_dataset_body(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """按 spec.md 字段规范组装交付请求体。

        :raises PlatformError: 一致代号密钥版本号未配置 —— 交付体里必须有
            ``pseudonymization.key_id``，缺了就**不外发**（事后没人说得清
            这批代号是用哪把密钥生成的）。
        """
        application_no = str(payload.get("application_no") or "").strip()
        ethics_approval_no = str(payload.get("ethics_approval_no") or "").strip()
        materials = self.build_material_entries(payload)
        manifest_path = str(payload.get("manifest_path") or "").strip()
        key_id = self._key_id or str(
            (payload.get("pseudonymization") or {}).get("key_id") or ""
        ).strip()
        if not key_id:
            raise PlatformError(
                "一致代号密钥版本号未配置（$PSEUDONYM_KEY_ID）：不外发，"
                "交付体必须写明 pseudonymization.key_id",
                category=FailureCategory.PAYLOAD_INVALID,
                retryable=False,
            )
        return {
            "application_no": application_no,
            "ethics_approval_no": ethics_approval_no,
            "dataset_name": f"科研脱敏交付 {application_no}",
            "material_count": len(materials),
            "materials": [entry.to_dict() for entry in materials],
            "pseudonymization": {"scheme": PSEUDONYM_SCHEME, "key_id": key_id},
            "manifest_uri": self.storage_uri(manifest_path) if manifest_path else "",
        }

    def idempotency_key_for(
        self, application_no: str, materials: Iterable[Mapping[str, Any]]
    ) -> str:
        """按申请单号与材料集合算出幂等键。"""
        return build_idempotency_key(application_no, material_fingerprint(materials))

    # -------------------------------------------------------------- 字段规范

    def _validate_dataset_body(self, body: Mapping[str, Any]) -> Any:
        """按字段规范校验交付体 —— **校验不过就不外发**。

        :raises PlatformError: 字段不过（失败类别 ``payload_invalid``，不重试）。
        """
        try:
            return validate_dataset_request(body, channel=CHANNEL_RESEARCH)
        except OutboundPayloadError as exc:
            raise PlatformError(
                f"科研数据平台交付请求体未通过字段规范校验：{exc}",
                category=FailureCategory.PAYLOAD_INVALID,
                retryable=False,
            ) from exc

    def _validate_restore_body(self, body: Mapping[str, Any]) -> Any:
        """按字段规范校验还原回执体 —— **校验不过就不外发**。

        :raises PlatformError: 字段不过（失败类别 ``payload_invalid``，不重试）。
        """
        try:
            return validate_restore_audit_request(body, channel=CHANNEL_RESEARCH)
        except OutboundPayloadError as exc:
            raise PlatformError(
                f"科研数据平台还原回执请求体未通过字段规范校验：{exc}",
                category=FailureCategory.PAYLOAD_INVALID,
                retryable=False,
            ) from exc

    def resolve_idempotency_key(
        self, application_no: str, payload: Mapping[str, Any]
    ) -> str:
        """本次交付用的幂等键。

        载荷里带了 ``idempotency_key`` 就用它（守护进程按**源文件集合**算好的
        批次身份）；没有就按载荷里的材料清单现算 —— 两条路径算出来的是同一把
        键：源文件摘要在前、交付副本摘要在后，指纹算法只有一份。
        """
        explicit = str(payload.get("idempotency_key") or "").strip()
        if explicit:
            return explicit
        return self.idempotency_key_for(
            application_no, payload.get("materials", []) or []
        )

    # ------------------------------------------------------------------ 交付

    def create_dataset(
        self, body: Mapping[str, Any], *, idempotency_key: str
    ) -> DatasetReceipt:
        """POST 数据集交付，返回平台回执。

        **先校验后外发**：请求体按 spec.md 的字段规范逐字段校验（必填 / 类型 /
        枚举 / 材料键三段式），校验不过就**一个请求都不发** —— 半成品交出去，
        平台挂不上批次，比不交还麻烦。

        :raises ChannelSuspendedError: 通道未配置（**不发请求**）。
        :raises PlatformError: 字段规范校验不过、网络失败、对端报错或响应结构不对。
        """
        self._channel.require()
        validated = self._validate_dataset_body(body)
        url = self.dataset_url()
        headers = {
            "Authorization": f"Bearer {self._channel.token}",
            "Accept": "application/json",
            "Idempotency-Key": idempotency_key,
        }
        response = self._post(url, headers=headers, body=validated.model_dump())
        status = getattr(response, "status_code", 0)
        if status < 200 or status >= 300:
            # 重试层已经按分类处理过非 2xx；走到这里说明客户端返回了非标准
            # 响应对象 —— 仍按分类报错，**不当成成功**。
            category = classify_status(status) or FailureCategory.RESPONSE_INVALID
            raise self._build_error(
                f"科研数据平台交付返回 HTTP {status}", category, status
            )
        payload = self._json(response, status)
        dataset_id = str(payload.get("dataset_id") or "").strip()
        if not dataset_id:
            raise PlatformError(
                "科研数据平台交付响应缺少 dataset_id：无法确认交付结果",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            )
        return DatasetReceipt(
            dataset_id=dataset_id,
            application_no=str(payload.get("application_no") or "").strip(),
            material_count=int(payload.get("material_count") or 0),
            receipt_id=str(payload.get("receipt_id") or "").strip(),
            accepted_at=str(payload.get("accepted_at") or "").strip(),
            raw=dict(payload),
        )

    def deliver(self, batch_no: str, payload: Mapping[str, Any]) -> bool:
        """把一个批次交到科研数据平台（待投递队列的投递出口）。

        **幂等**：同一批材料只会真正外发一次。

        - 台账里有这把幂等键、且已交付 → **复用已有回执**，直接返回成功，
          不再发第二个请求；
        - 台账里有这把幂等键、但还没交付（另一个执行者正在交）→ 等它交完
          再复用回执；
        - 没有这把键 → 认领它，然后**唯一一次**外发。

        **崩溃恢复**（认领在、回执不在）：上一次执行者可能崩在「平台已收下、
        回执还没落库」那一步 —— 平台侧**已经有这个数据集**了。等不到别的
        执行者交完（等的就是那个已经不在了的执行者）时，用**同一把幂等键**
        再确认一次：平台按 ``Idempotency-Key`` 去重，返回的是同一个数据集，
        **不会产生第二个数据集**，本地把回执补落下来。

        这条恢复路径成立的前提是平台侧遵守 ``Idempotency-Key`` 契约（同键
        重放 = 同一次交付）—— 本客户端**每次请求都带同一把键**（键由申请单号
        与材料集合指纹算出，见 :mod:`research_redact.idempotency`）。

        成功返回 True；失败抛 :class:`PlatformError`（带 ``status`` 与
        ``retryable``），由队列决定退避重试还是挂起。

        :param batch_no: 批次号（申请单号）。
        :param payload: 投递载荷（``daemon.runner`` 组装）。
        """
        # 通道没配就到此为止：既不组装请求体，也不发请求。
        self._channel.require()
        body = self.build_dataset_body(payload)
        application_no = str(body.get("application_no") or batch_no)
        key = self.resolve_idempotency_key(application_no, payload)
        materials = payload.get("materials", []) or []
        fingerprint = material_fingerprint(materials)
        material_ids = tuple(
            str(item.get("material_id") or "")
            for item in materials
            if isinstance(item, Mapping)
        )

        if self._ledger is None:
            # 没有台账就无从判定重复：按普通外发处理（临时脚本与单测用）。
            self.create_dataset(body, idempotency_key=key)
            return True

        self._ledger.set_idempotency_key(batch_no, key)
        deadline = time.monotonic() + self._idempotency_wait_seconds
        while True:
            claim = self._ledger.claim_idempotency_key(
                key,
                batch_no,
                fingerprint=fingerprint,
                material_ids=material_ids,
            )
            if claim.is_new:
                # 认领成功 —— 这一次就是**唯一一次**真实外发。
                try:
                    receipt = self.create_dataset(body, idempotency_key=key)
                except Exception:
                    # 交付失败：释放认领，让下一次重投能重新认领（不占着键）。
                    self._ledger.release_idempotency_key(key)
                    raise
                self._record_delivery(batch_no, application_no, key, receipt)
                logger.info(
                    "科研数据平台已回执（批次 %s）：dataset_id=%s 材料数=%s 幂等键=%s",
                    batch_no,
                    receipt.dataset_id,
                    receipt.material_count,
                    key,
                )
                return True

            # 键已经有人认领 —— 先看有没有交付回执可复用。
            existing = self._ledger.get_receipt(key)
            if existing is not None:
                # 回执在 → 复用，不重复外发。顺手把认领状态补成「已交付」：
                # 上一次可能崩在「回执已落库」与「认领标记已交付」之间，
                # 状态补齐，重投才不会再去等一个已经交完的执行者。
                self._ledger.mark_idempotency_delivered(
                    key,
                    dataset_id=str(existing.payload.get("dataset_id", "")),
                    receipt_id=existing.platform_receipt_id or "",
                )
                logger.info(
                    "幂等键 %s 已有交付回执（批次 %s，dataset_id=%s）："
                    "复用已有产物与回执，不重复外发",
                    key,
                    batch_no,
                    existing.payload.get("dataset_id", ""),
                )
                return True
            if time.monotonic() >= deadline:
                # 认领在、回执不在：上一次执行者可能崩在「平台已收下、回执
                # 未落库」那一步。以**同一把幂等键**再确认一次 —— 平台按键
                # 去重，返回同一个数据集，不会产生第二个数据集。
                logger.info(
                    "幂等键 %s 已认领但无回执（批次 %s）：以同一把幂等键确认交付"
                    "（上一次可能崩在平台收下之后、回执落库之前）",
                    key,
                    batch_no,
                )
                receipt = self.create_dataset(body, idempotency_key=key)
                self._record_delivery(batch_no, application_no, key, receipt)
                return True
            time.sleep(self._idempotency_poll_seconds)

    def _record_delivery(
        self,
        batch_no: str,
        application_no: str,
        key: str,
        receipt: DatasetReceipt,
    ) -> None:
        """把一次交付的回执落进台账，并把幂等键标成已交付。

        回执 ID **就是幂等键** —— 事后核「这一批交过一次」时，回执、幂等键、
        请求头三处对得上。
        """
        self._ledger.record_receipt(
            receipt_id=key,
            batch_no=batch_no,
            kind="delivery",
            payload={
                "dataset_id": receipt.dataset_id,
                "application_no": application_no,
                "material_count": receipt.material_count,
                "accepted_at": receipt.accepted_at,
            },
            platform_receipt_id=receipt.receipt_id or receipt.dataset_id,
        )
        self._ledger.mark_idempotency_delivered(
            key,
            dataset_id=receipt.dataset_id,
            receipt_id=receipt.receipt_id or receipt.dataset_id,
        )

    # ------------------------------------------------------------------ 还原

    def record_restore_audit(
        self,
        *,
        restore_request_id: str,
        dataset_id: str,
        approver_a: str,
        approver_b: str,
        scope: Sequence[str] = (),
        reason: str = "",
        granted_at: str = "",
        expires_at: str = "",
        result_summary: str = "",
    ) -> RestoreAuditReceipt:
        """POST 还原回执（把一次受控还原的事实落到平台侧）。

        请求体字段按 spec.md 固定为 9 项，**不含任何还原出来的原文**；外发前
        按字段规范逐字段校验（校验不过就**一个请求都不发**）。
        """
        self._channel.require()
        body = {
            "restore_request_id": restore_request_id,
            "dataset_id": dataset_id,
            "approver_a": approver_a,
            "approver_b": approver_b,
            "scope": list(scope),
            "reason": reason,
            "granted_at": granted_at,
            "expires_at": expires_at,
            "result_summary": result_summary,
        }
        validated = self._validate_restore_body(body)
        url = self.restore_audit_url(dataset_id)
        headers = {
            "Authorization": f"Bearer {self._channel.token}",
            "Accept": "application/json",
        }
        response = self._post(url, headers=headers, body=validated.model_dump())
        status = getattr(response, "status_code", 0)
        if status < 200 or status >= 300:
            category = classify_status(status) or FailureCategory.RESPONSE_INVALID
            raise self._build_error(
                f"科研数据平台还原回执返回 HTTP {status}", category, status
            )
        payload = self._json(response, status)
        return RestoreAuditReceipt(
            restore_audit_id=str(
                payload.get("restore_audit_id") or payload.get("receipt_id") or ""
            ).strip(),
            dataset_id=str(payload.get("dataset_id") or dataset_id).strip(),
            restore_request_id=str(
                payload.get("restore_request_id") or restore_request_id
            ).strip(),
            recorded_at=str(payload.get("recorded_at") or "").strip(),
            raw=dict(payload),
        )

    # ------------------------------------------------------------------ 内部

    def _post(
        self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Any:
        """发一次 POST；按错误分类决定退避重试还是直接报错。

        重试**落在客户端里**：平台抖一下（5xx / 超时 / 连不上）就地退避重试，
        4xx 与鉴权失败**不重试** —— 请求本身不对，重试只是把同一个错再犯一遍。
        每一次重试都带**同一把** ``Idempotency-Key``，平台按键去重，重试不会
        产生第二个数据集。
        """
        return call_with_retry(
            lambda: self._send(url, headers=headers, body=body),
            policy=self._retry_policy,
            channel=CHANNEL_RESEARCH,
            build_error=self._build_error,
            on_retry=self._note_retry,
        )

    def _send(
        self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Any:
        """真正发一次请求（异常交给重试层归类）。"""
        if self._client is not None:
            return self._client.post(url, headers=dict(headers), json=dict(body))
        with httpx.Client(timeout=self._channel.timeout) as client:
            return client.post(url, headers=dict(headers), json=dict(body))

    def _build_error(
        self, message: str, category: FailureCategory, status: int
    ) -> PlatformError:
        """把重试层给出的失败类别收口成 :class:`PlatformError`。"""
        decision = decide_failure(category, channel=CHANNEL_RESEARCH)
        return PlatformError(
            message,
            status=status,
            category=category,
            retryable=decision.retryable,
        )

    def _note_retry(self, attempt: int, decision, delay: float) -> None:
        """退避重试前记一笔（说明重试了几次、为什么重试）。"""
        logger.warning(
            "科研数据平台出站调用第 %s 次失败（%s），%.1fs 后重试（幂等键不变）",
            attempt,
            decision.alert_code,
            delay,
        )

    @staticmethod
    def _json(response: Any, status: int) -> Mapping[str, Any]:
        """解析响应体；不是合法 JSON 对象就报错（**不当成成功**）。"""
        try:
            payload = response.json()
        except Exception as exc:
            raise PlatformError(
                f"科研数据平台响应不是合法 JSON：{type(exc).__name__}",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            ) from exc
        if not isinstance(payload, Mapping):
            raise PlatformError(
                "科研数据平台响应不是 JSON 对象",
                status=status,
                category=FailureCategory.RESPONSE_INVALID,
                retryable=False,
            )
        return payload
