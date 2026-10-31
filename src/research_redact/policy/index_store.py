"""对照索引的加密存储与访问留痕。

**为什么索引比交付物还危险**：交付物里躺着的是**代号**（不可逆）；对照索引
里躺着的是**原文** —— 姓名、住院号、身份证，一张「代号 ↔ 原文」的反查表。
拿到这张表，任何一个代号都能换回是哪位患者。所以三件事必须同时成立：

1. **加密落盘** —— 索引文件用 AES-256-GCM 加密，密钥只从环境变量读；
2. **与交付物分离** —— 索引放在 ``var/index/``，交付物在 ``var/outbox/``；
   交付物被拷走、被上传、当作附件发出去时，索引不会跟着走；
3. **访问留痕** —— 解密、查询、写入每次都留一条「谁、何时、做了什么、条数」。

**三条纪律**：

1. **密钥缺失即报错** —— ``$INDEX_ENCRYPTION_KEY`` 没配时可由
   ``$PSEUDONYM_HMAC_KEY`` 派生（**明确标注派生来源**：此时索引密钥与一致
   代号密钥同源，密钥分离度下降，运维要看得见这件事）。两者都没配就报错
   中止，**绝不退回内置默认密钥** —— 那等于把索引公开。
2. **索引不可达 = 批次挂起** —— 索引文件缺失 / 解密失败时报明确错误，并把
   批次置 ``suspended``；**不重建空索引放行**：空索引会让还原件「看着像
   原文、其实少了一段」，比还原失败危险得多。
3. **留痕不含原文** —— 访问留痕只记谁、何时、操作与条数；不记姓名、住院号、
   身份证，也**不记代号本身**（代号进了留痕就等于给了反查的半把钥匙）。

**与既有模块的关系**：本模块实现 :class:`~research_redact.policy.mapping.
OccurrenceMappingIndex` 协议，与进程内索引（``PseudonymMappingIndex``）
**同接口、不同落点** —— 一致代号动作（``hmac_pseudonym``）与其还原侧
（``hmac_restore``）挂上去即可，业务层不感知差别。

**不变量**：本模块不碰正文；文件里的原文只在解密后的内存里存在，落盘一律
是密文；任何一次解密 / 查询 / 写入都留痕。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import PSEUDONYM_HMAC_KEY_ENV
from ..models import utcnow
from ..paths import project_root
from .mapping import (
    MappingIndexUnavailableError,
    OccurrenceMappingIndex,
    TokenOccurrence,
    token_pattern,
)
from .pseudonym import PseudonymConfig

__all__ = [
    "DEFAULT_INDEX_FILE",
    "EncryptedIndexStore",
    "INDEX_ENCRYPTION_KEY_ENV",
    "INDEX_STORE_PATH_ENV",
    "IndexDecryptError",
    "IndexFileMissingError",
    "IndexKeyError",
    "IndexStoreError",
    "IndexUnavailableError",
    "JsonlAccessTrail",
    "KEY_SOURCE_DERIVED",
    "KEY_SOURCE_EXPLICIT",
    "OPERATION_DECRYPT",
    "OPERATION_LOOKUP",
    "OPERATION_RECORD",
    "OPERATION_RESET",
    "OPERATION_WRITE",
    "AccessTrail",
    "default_index_path",
    "load_index_store",
    "resolve_index_key",
    "suspend_unreachable_batch",
]


#: 对照索引加密密钥的环境变量（专用密钥，优先使用）。
INDEX_ENCRYPTION_KEY_ENV = "INDEX_ENCRYPTION_KEY"

#: 对照索引文件路径的环境变量（与 .env.example 一致）。
INDEX_STORE_PATH_ENV = "RESEARCH_INDEX_FILE"

#: 索引文件默认名（放在 ``var/index/`` 下，与交付物目录分离）。
DEFAULT_INDEX_FILE = "pseudonym_index.enc"

#: 密钥来源：专用索引密钥。
KEY_SOURCE_EXPLICIT = "index_encryption_key"
#: 密钥来源：由一致代号密钥派生（**密钥分离度下降，必须看得见**）。
KEY_SOURCE_DERIVED = "derived_from_pseudonym_key"

# 访问留痕里的操作名。
OPERATION_DECRYPT = "index_decrypt"
OPERATION_LOOKUP = "index_lookup"
OPERATION_RECORD = "index_record"
OPERATION_WRITE = "index_write"
OPERATION_RESET = "index_reset"

#: 文件头（魔数）：格式不对就报错，不猜。
_MAGIC = b"RDRIDX01"
#: AES-GCM nonce 长度（字节）。
_NONCE_SIZE = 12
#: 文件头长度（魔数 + nonce）。
_HEADER_SIZE = len(_MAGIC) + _NONCE_SIZE
#: HKDF 盐值（固定应用盐：真正的秘密是主密钥）。
_SALT = b"research-redact/index-store/v1"
#: HKDF info（用途标签：索引密钥与一致代号密钥即使同源也不混用）。
_INFO = b"aes-256-gcm"
#: 索引文件格式版本。
_FORMAT_VERSION = 1
#: 槽位键分隔符（材料 ID 与代号之间；两者都不含该字符）。
_SLOT_SEP = "\x1f"


# --------------------------------------------------------------------- 错误


class IndexStoreError(RuntimeError):
    """对照索引存储相关错误基类。"""


class IndexKeyError(IndexStoreError):
    """索引加密密钥缺失。

    **不退回内置默认密钥** —— 那等于把索引公开；无密钥可用时报错中止，
    由人把环境变量配上。
    """


class IndexUnavailableError(IndexStoreError, MappingIndexUnavailableError):
    """对照索引**不可达**（文件缺失 / 解密失败 / 存储故障）。

    与「查得到但没有这一条」（缺项）分开：不可达是「根本没查成」，
    两者都可能导致还原件残缺，所以两者都必须报错中止。
    """


class IndexFileMissingError(IndexUnavailableError):
    """对照索引文件不存在。

    **不重建空索引放行** —— 空索引会让还原件少一段却看不出来。
    """


class IndexDecryptError(IndexUnavailableError):
    """对照索引解密失败（密钥不匹配 / 文件被改动 / 内容损坏）。"""


# --------------------------------------------------------------------- 留痕


@runtime_checkable
class AccessTrail(Protocol):
    """访问留痕落点。

    :class:`~research_redact.audit.ledger.BatchLedger` 实现同一协议
    （``access_log`` 表）；没有台账时用 :class:`JsonlAccessTrail` 落本地文件。
    """

    def record_access(
        self, batch_no: str, actor: str, operation: str, detail: str = ""
    ) -> None:
        """落一条访问留痕（谁、何时、对哪一批做了什么）。"""


class JsonlAccessTrail:
    """本地 JSONL 访问留痕（没有台账时的落点）。

    :param path: 留痕文件路径。
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record_access(
        self, batch_no: str, actor: str, operation: str, detail: str = ""
    ) -> None:
        """追加一条留痕（一行一条 JSON）。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {
                "batch_no": batch_no,
                "actor": actor,
                "operation": operation,
                "detail": detail,
                "at": utcnow().isoformat(),
            },
            ensure_ascii=False,
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def entries(self) -> list[dict[str, Any]]:
        """读回落点里的全部留痕（按写入顺序）。"""
        if not self.path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if text:
                rows.append(json.loads(text))
        return rows


# --------------------------------------------------------------------- 路径


def _project_root() -> Path:
    """项目根目录（向上找带 ``policy/`` 的那一层）。

    实现已挪到 :func:`research_redact.paths.project_root` —— 只看 ``policy/``
    会把包目录 ``src/research_redact/`` 认成项目根，相对路径会落到
    ``src/research_redact/var/`` 里（既不是 ``.env.example`` 写的那个位置，
    也不在 ``.gitignore`` 覆盖的运行时目录里）。
    """
    return project_root()


def _resolve_path(value: str | Path) -> Path:
    """相对路径按项目根解析（守护进程与 CLI 可能不在同一工作目录）。"""
    target = Path(value)
    if target.is_absolute():
        return target
    return _project_root() / target


def default_index_path(env: Mapping[str, str] | None = None) -> Path:
    """对照索引文件路径。

    环境变量 ``$RESEARCH_INDEX_FILE`` 优先（相对路径按项目根解析），
    缺省落在 ``var/index/pseudonym_index.enc`` —— **与交付物目录分离**。
    """
    source = os.environ if env is None else env
    value = (source.get(INDEX_STORE_PATH_ENV) or "").strip()
    if value:
        return _resolve_path(value)
    return _project_root() / "var" / "index" / DEFAULT_INDEX_FILE


# --------------------------------------------------------------------- 密钥


def resolve_index_key(env: Mapping[str, str] | None = None) -> tuple[bytes, str]:
    """解析索引加密密钥（返回「密钥 + 来源」）。

    优先 ``$INDEX_ENCRYPTION_KEY``（专用密钥，与一致代号密钥分离）；
    没有就由 ``$PSEUDONYM_HMAC_KEY`` 派生，**并明确标注派生来源** ——
    这时一把密钥管两件事，密钥分离度下降，运维必须看得见。

    :raises IndexKeyError: 两个凭据位都没配 —— **不退回内置默认密钥**。
    """
    source = os.environ if env is None else env
    explicit = (source.get(INDEX_ENCRYPTION_KEY_ENV) or "").strip()
    if explicit:
        return explicit.encode("utf-8"), KEY_SOURCE_EXPLICIT
    master = (source.get(PSEUDONYM_HMAC_KEY_ENV) or "").strip()
    if master:
        return master.encode("utf-8"), KEY_SOURCE_DERIVED
    raise IndexKeyError(
        f"未配置 ${INDEX_ENCRYPTION_KEY_ENV}，且 ${PSEUDONYM_HMAC_KEY_ENV} 也未配置："
        "对照索引无法加密落盘 —— 不得退回内置默认密钥（那等于把索引公开）"
    )


def _derive_aes_key(master: bytes) -> bytes:
    """主密钥 → AES-256 密钥（HKDF-SHA256）。"""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_SALT,
        info=_INFO,
    ).derive(master)


# --------------------------------------------------------------------- 存储


@dataclass(frozen=True)
class IndexStoreInfo:
    """索引存储的一句话快照（**不含密钥**）。"""

    path: str
    key_source: str
    derived: bool
    entry_count: int

    def describe(self) -> str:
        """人话说明（写进运维摘要与告警文案）。"""
        source = (
            "专用索引密钥 $INDEX_ENCRYPTION_KEY"
            if self.key_source == KEY_SOURCE_EXPLICIT
            else "由 $PSEUDONYM_HMAC_KEY 派生（与一致代号密钥同源，密钥分离度下降）"
        )
        return f"对照索引：{self.path}；密钥来源：{source}；条目 {self.entry_count} 条"


class EncryptedIndexStore:
    """加密落盘的对照索引（代号 ↔ 原文），并对每次访问留痕。

    实现 :class:`~research_redact.policy.mapping.OccurrenceMappingIndex`
    协议，与进程内索引同接口：一致代号动作与其还原侧挂上去即可。

    :param path: 索引文件路径（与交付物目录分离）。
    :param key: 主密钥字节。
    :param key_source: 密钥来源（见 :data:`KEY_SOURCE_EXPLICIT` /
        :data:`KEY_SOURCE_DERIVED`）。
    :param trail: 访问留痕落点；缺省用本地 JSONL 文件。
    :param ledger: 批次台账（给了就作为留痕落点，并用于挂起批次）。
    :param batch_no: 本索引对应的批次号（写进留痕）。
    :param actor: 操作人（写进留痕；缺省 ``system``）。
    :param config: 一致代号口径（扫正文形状时用；缺省按策略表读）。
    """

    def __init__(
        self,
        *,
        path: str | Path,
        key: bytes,
        key_source: str = KEY_SOURCE_EXPLICIT,
        trail: AccessTrail | None = None,
        ledger: Any | None = None,
        batch_no: str = "",
        actor: str = "system",
        config: PseudonymConfig | None = None,
    ) -> None:
        if not key:
            raise IndexKeyError("对照索引密钥为空：不得退回内置默认密钥")
        self._path = Path(path)
        self._master_key = bytes(key)
        self._key_source = key_source
        self._ledger = ledger
        self._trail = trail if trail is not None else (ledger or JsonlAccessTrail(
            self._path.parent / "index-access.jsonl"
        ))
        self._batch_no = str(batch_no or "")
        self._actor = str(actor or "system")
        self._config = config
        self._entries: dict[tuple[str, str], list[str]] = {}
        self._created_at = utcnow().isoformat()

    # ------------------------------------------------------------------ 属性

    @property
    def path(self) -> Path:
        """索引文件路径。"""
        return self._path

    @property
    def key_source(self) -> str:
        """密钥来源。"""
        return self._key_source

    @property
    def derived(self) -> bool:
        """密钥是否由一致代号密钥派生（分离度下降，须在摘要里看得见）。"""
        return self._key_source == KEY_SOURCE_DERIVED

    @property
    def batch_no(self) -> str:
        """本索引对应的批次号。"""
        return self._batch_no

    def bind_batch(self, batch_no: str) -> None:
        """把索引绑到某个批次（后续访问留痕按批次记）。

        守护进程一份索引要服务多个批次（每个批次处理前登记一次）——
        不绑批次的话，留痕里全是空批次号，事后查不出「谁在什么时候动过
        哪一批的对照关系」。
        """
        self._batch_no = str(batch_no or "")

    @property
    def config(self) -> PseudonymConfig:
        """一致代号口径（按需装载）。"""
        if self._config is None:
            from .pseudonym import load_pseudonym_config

            self._config = load_pseudonym_config()
        return self._config

    def info(self) -> IndexStoreInfo:
        """快照（**不含密钥**）。"""
        return IndexStoreInfo(
            path=str(self._path),
            key_source=self._key_source,
            derived=self.derived,
            entry_count=len(self),
        )

    def __len__(self) -> int:
        """已登记的对照条数。"""
        return sum(len(bucket) for bucket in self._entries.values())

    # ------------------------------------------------------------- 协议实现

    def record_occurrence(self, material_id: str, token: str, original: str) -> int:
        """登记一条对照，返回它是该代号在本材料中的第几次出现。

        登记顺序即出现顺序 —— 调用方必须按正文顺序登记。
        """
        key = (str(material_id or ""), str(token))
        bucket = self._entries.setdefault(key, [])
        bucket.append(str(original))
        self._log_access(
            OPERATION_RECORD,
            f"登记对照：材料 {material_id or '（未标注）'} 第 {len(bucket)} 处；"
            f"索引累计 {len(self)} 条",
        )
        return len(bucket) - 1

    def lookup_occurrence(
        self, material_id: str, token: str, occurrence: int
    ) -> str | None:
        """取某一处代号的原文；查不到返回 None（**不得返回空串冒充命中**）。"""
        bucket = self._entries.get((str(material_id or ""), str(token)))
        hit = None
        if bucket and 0 <= occurrence < len(bucket):
            hit = bucket[occurrence]
        self._log_access(
            OPERATION_LOOKUP,
            f"查询对照：材料 {material_id or '（未标注）'} 第 {occurrence + 1} 处；"
            f"命中 {1 if hit is not None else 0} 条",
        )
        return hit

    def find_occurrences(
        self, text: str, material_id: str
    ) -> tuple[TokenOccurrence, ...]:
        """在正文里找出全部代号及其出现次序（按出现顺序）。"""
        pattern = token_pattern(self.config)
        counters: dict[str, int] = {}
        found: list[TokenOccurrence] = []
        for match in pattern.finditer(text):
            token = match.group(0)
            occurrence = counters.get(token, 0)
            counters[token] = occurrence + 1
            found.append(
                TokenOccurrence(
                    token=token,
                    start=match.start(),
                    end=match.end(),
                    occurrence=occurrence,
                )
            )
        return tuple(found)

    def reset_material(self, material_id: str) -> None:
        """清空某份材料的全部槽位（重新脱敏同一份材料前必须先清）。"""
        target = str(material_id or "")
        removed = 0
        for key in [key for key in self._entries if key[0] == target]:
            removed += len(self._entries.pop(key))
        self._log_access(
            OPERATION_RESET,
            f"清空材料槽位：材料 {target or '（未标注）'}；清掉 {removed} 条；"
            f"索引累计 {len(self)} 条",
        )

    def originals(self, material_id: str, token: str) -> tuple[str, ...]:
        """某个代号在某份材料里的全部原文（按出现顺序）。"""
        return tuple(self._entries.get((str(material_id or ""), str(token)), ()))

    def tokens(self, material_id: str | None = None) -> tuple[str, ...]:
        """已登记的全部代号（按首次登记顺序；给了材料 ID 则只看该材料）。"""
        found: list[str] = []
        for (scope, token) in self._entries:
            if material_id is not None and scope != str(material_id or ""):
                continue
            if token not in found:
                found.append(token)
        return tuple(found)

    # ------------------------------------------------------------------ 落盘

    def load(self) -> int:
        """解密并载入索引文件。

        :raises IndexFileMissingError: 文件不存在 —— **不重建空索引放行**。
        :raises IndexDecryptError: 解密失败（密钥不匹配 / 文件被改动）。
        """
        if not self._path.is_file():
            self._log_access(
                OPERATION_DECRYPT,
                f"解密对照索引失败：文件不存在（{self._path}）—— 不重建空索引放行",
            )
            raise IndexFileMissingError(
                f"对照索引文件不存在：{self._path} —— 不得重建空索引放行"
                "（还原件会缺段却看不出来），批次须挂起等索引恢复"
            )
        raw = self._path.read_bytes()
        if len(raw) < _HEADER_SIZE or not raw.startswith(_MAGIC):
            self._log_access(
                OPERATION_DECRYPT,
                f"解密对照索引失败：文件格式不对（{self._path}）",
            )
            raise IndexDecryptError(
                f"对照索引文件格式不对：{self._path}（不是本系统写出的索引文件）"
            )
        nonce = raw[len(_MAGIC) : _HEADER_SIZE]
        cipher = raw[_HEADER_SIZE:]
        try:
            plain = self._cipher().decrypt(nonce, cipher, _MAGIC)
        except InvalidTag as exc:
            self._log_access(
                OPERATION_DECRYPT,
                f"解密对照索引失败：密钥不匹配或文件已被改动（{self._path}）",
            )
            raise IndexDecryptError(
                f"对照索引解密失败：{self._path}"
                "（密钥不匹配或文件已被改动；不得重建空索引放行）"
            ) from exc
        try:
            data = json.loads(plain.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._log_access(
                OPERATION_DECRYPT, f"解密对照索引失败：内容损坏（{self._path}）"
            )
            raise IndexDecryptError(
                f"对照索引内容解析失败：{self._path}（文件已损坏）"
            ) from exc
        self._entries = _entries_from_payload(data)
        self._created_at = str(data.get("created_at") or self._created_at)
        self._log_access(
            OPERATION_DECRYPT,
            f"解密对照索引：条目 {len(self)} 条（{self._path}）",
        )
        return len(self)

    def save(self) -> Path:
        """把索引加密落盘（原子写：先写临时文件再替换）。"""
        payload = json.dumps(
            {
                "version": _FORMAT_VERSION,
                "key_source": self._key_source,
                "created_at": self._created_at,
                "updated_at": utcnow().isoformat(),
                "entries": {
                    f"{material}{_SLOT_SEP}{token}": list(bucket)
                    for (material, token), bucket in self._entries.items()
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        nonce = os.urandom(_NONCE_SIZE)
        cipher = self._cipher().encrypt(nonce, payload, _MAGIC)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_bytes(_MAGIC + nonce + cipher)
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover - 平台不支持时忽略
            pass
        tmp.replace(self._path)
        self._log_access(
            OPERATION_WRITE,
            f"落盘对照索引：条目 {len(self)} 条（{self._path}）",
        )
        return self._path

    # ------------------------------------------------------------------ 可用性

    def require_available(
        self,
        *,
        ledger: Any | None = None,
        batch_no: str | None = None,
    ) -> int:
        """确保索引可达；不可达时把批次挂起并报错中止。

        :param ledger: 批次台账；缺省用装配时给的。
        :param batch_no: 批次号；缺省用装配时给的。
        :raises IndexFileMissingError / IndexDecryptError: 索引不可达 ——
            **批次已置 suspended，不重建空索引放行**。
        """
        try:
            return self.load()
        except IndexStoreError as exc:
            target_ledger = ledger if ledger is not None else self._ledger
            target_batch = batch_no if batch_no is not None else self._batch_no
            if target_ledger is not None and target_batch:
                suspend_unreachable_batch(
                    target_ledger, target_batch, str(exc), actor=self._actor
                )
            raise

    # ------------------------------------------------------------------ 内部

    def _cipher(self) -> AESGCM:
        """按主密钥派生 AES-GCM 密钥。"""
        return AESGCM(_derive_aes_key(self._master_key))

    def _log_access(self, operation: str, detail: str) -> None:
        """落一条访问留痕（**不含原文，也不含代号**）。"""
        if self._trail is None:
            return
        self._trail.record_access(
            self._batch_no, self._actor, operation, detail
        )


def _entries_from_payload(data: Any) -> dict[tuple[str, str], list[str]]:
    """解密后的载荷 → 槽位字典。"""
    if not isinstance(data, Mapping):
        raise IndexDecryptError("对照索引载荷格式不对（根节点不是映射）")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, Mapping):
        raise IndexDecryptError("对照索引载荷格式不对（缺 entries 段）")
    entries: dict[tuple[str, str], list[str]] = {}
    for slot, originals in raw_entries.items():
        material, _, token = str(slot).partition(_SLOT_SEP)
        if not isinstance(originals, Sequence) or isinstance(originals, (str, bytes)):
            raise IndexDecryptError(
                f"对照索引载荷格式不对（槽位 {material} 的取值不是列表）"
            )
        entries[(material, token)] = [str(item) for item in originals]
    return entries


# --------------------------------------------------------------------- 装配


def load_index_store(
    *,
    env: Mapping[str, str] | None = None,
    path: str | Path | None = None,
    ledger: Any | None = None,
    batch_no: str = "",
    actor: str = "system",
    config: PseudonymConfig | None = None,
) -> EncryptedIndexStore:
    """按环境变量装配加密对照索引。

    :param env: 环境变量映射；缺省读 ``os.environ``。
    :param path: 索引文件路径；缺省按 ``$RESEARCH_INDEX_FILE`` 解析。
    :param ledger: 批次台账（给了就作为留痕落点，并用于挂起批次）。
    :param batch_no: 批次号。
    :param actor: 操作人。
    :raises IndexKeyError: 密钥凭据位没配 —— **不退回内置默认密钥**。
    """
    source = os.environ if env is None else env
    key, key_source = resolve_index_key(source)
    target = Path(path) if path is not None else default_index_path(source)
    trail: AccessTrail
    if ledger is not None:
        trail = ledger
    else:
        trail = JsonlAccessTrail(target.parent / "index-access.jsonl")
    return EncryptedIndexStore(
        path=target,
        key=key,
        key_source=key_source,
        trail=trail,
        ledger=ledger,
        batch_no=batch_no,
        actor=actor,
        config=config,
    )


def suspend_unreachable_batch(
    ledger: Any,
    batch_no: str,
    reason: str,
    *,
    actor: str = "system",
) -> Any | None:
    """对照索引不可达 → 把批次置 ``suspended``。

    **不重建空索引放行**：索引不可达意味着还原件可能缺段，批次必须挂起等
    索引恢复，而不是「建个空索引继续跑」。

    状态不允许挂起时（批次已不在可挂起的阶段）**不强行改状态** ——
    只留一条访问留痕说明为什么没挂上，异常照旧向上抛。

    :return: 更新后的批次记录；状态不允许挂起时返回 ``None``。
    """
    from ..daemon.state_machine import (
        BatchEvent,
        IllegalTransitionError,
        TransitionContext,
        TransitionRejectedError,
    )

    context = TransitionContext(index_store_reachable=False)
    try:
        return ledger.advance(
            batch_no,
            BatchEvent.INDEX_STORE_UNREACHABLE,
            context,
            reason=reason,
            current_step="index_store",
        )
    except (IllegalTransitionError, TransitionRejectedError) as exc:
        ledger.record_access(
            batch_no,
            actor,
            "index_store_suspend_failed",
            f"对照索引不可达但批次未能挂起：{exc}",
        )
        return None
