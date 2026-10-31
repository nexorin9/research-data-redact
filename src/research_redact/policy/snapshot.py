"""策略表版本快照：把「这批是用哪一版策略脱的」钉死，事后可复现。

**为什么要有这一层**：策略表（``policy/research.yaml``）是活的 —— 科室反馈某个
识别器误伤多，改一行阈值；信息科统一白名单，改一条正则；伦理办要求某类实体
一律保留，改一条处置动作。改完之后**上一批是怎么脱出来的**就说不清了。

没有快照时的事故场景：伦理办三个月后抽检一批材料，问「这一批当时用的是哪版
策略、按哪版算出来的」。台账里只有产物路径与命中清单，命中清单里有「分数
0.55 告警档」这样的行 —— 而 0.55 算确认档还是告警档，取决于当时的全局阈值。
**阈值一改，这行记录就再也解释不清了。**

所以本模块给每一批留一份**冻结的策略快照**：

- ``var/snapshots/<批次号>/policy.yaml`` —— 生效配置的完整副本（档位已合并）。
  这份文件**本身就是一份合法的策略表**：把它喂回 ``load_policy_table()``，
  装出来的注册表与当时逐字一致 —— 重放靠它，不靠记忆。
- ``var/snapshots/<批次号>/snapshot.json`` —— 版本号、来源、摘要（全局阈值 /
  逐识别器阈值 / 白名单摘要 / 上下文词表），给人看的。

**版本号 = 生效配置的 sha256**：同一份配置永远算出同一个版本号；配置改了
（哪怕只改一个阈值），版本号必变。版本号跟着批次写进台账与命中清单头 ——
事后一眼就能对上是哪一版。

**红线：快照里不得出现任何密钥或凭据。** 策略表里理论上不该有凭据，但
「有人图省事把令牌写进 YAML」这种事一旦发生，快照就会把它复制到磁盘上、
复制到备份里、复制到别人能读的地方。因此落盘前有一道**凭据闸**：键名命中
敏感词、值命中当前进程里已配置的任何凭据、值长得像 Bearer 令牌 / 私钥 ——
一律**拒绝落盘并报错**，不留半份快照。

**不变量**

1. 快照只装**配置**，不装患者数据 —— 命中原文永远不进快照；
2. 版本号只认**生效配置**（档位合并后的结果），不认文件字节 —— 改注释不改
   行为时版本号不变（行为没变，就不该让人重新复核一遍）；
3. 快照写不出 / 含凭据 → **报错中止**，不落半份、不静默跳过（没有快照的
   批次不可复现，不该照常交付）。
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

import yaml

from .table import PolicyTable

__all__ = [
    "CREDENTIAL_ENV_NAMES",
    "CredentialLeakError",
    "META_FILE_NAME",
    "POLICY_FILE_NAME",
    "POLICY_VERSION_DIGITS",
    "POLICY_VERSION_PREFIX",
    "PolicySnapshot",
    "SNAPSHOT_DIR_ENV",
    "SENSITIVE_KEY_NAMES",
    "SnapshotError",
    "assert_no_credentials",
    "capture_snapshot",
    "canonical_json",
    "default_snapshot_dir",
    "effective_policy_document",
    "load_snapshot",
    "policy_digest",
    "policy_version",
    "read_snapshot_meta",
    "snapshot_dir_for",
    "snapshot_policy_path",
    "summarize_document",
]


#: 环境变量：快照目录（.env.example 里的 ``RESEARCH_SNAPSHOT_DIR``）。
SNAPSHOT_DIR_ENV = "RESEARCH_SNAPSHOT_DIR"

#: 快照目录里的两个文件名。
POLICY_FILE_NAME = "policy.yaml"
META_FILE_NAME = "snapshot.json"

#: 版本号前缀（``pol-`` + 16 位十六进制）。
POLICY_VERSION_PREFIX = "pol-"

#: 版本号保留的十六进制位数（64 位熵 —— 区分策略版本绰绰有余）。
POLICY_VERSION_DIGITS = 16

#: 不得出现在策略表 / 快照里的**键名**（小写精确匹配）。
#:
#: 注意 ``key_id`` 不在其中 —— 那是一致代号的密钥**版本号**，是标识不是秘密，
#: 交付体里本来就要带着它。
SENSITIVE_KEY_NAMES: frozenset[str] = frozenset(
    {
        "token",
        "api_token",
        "access_token",
        "refresh_token",
        "api_key",
        "secret",
        "secret_key",
        "client_secret",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "private_key",
        "encryption_key",
        "hmac_key",
        "index_key",
        "authorization",
        "bearer",
    }
)

#: 不得出现在快照里的**环境变量**（它们的取值本身也不许出现）。
CREDENTIAL_ENV_NAMES: tuple[str, ...] = (
    "HIS_API_TOKEN",
    "RESEARCH_DATA_TOKEN",
    "PSEUDONYM_HMAC_KEY",
    "INDEX_ENCRYPTION_KEY",
    "WECOM_WEBHOOK_URL",
)

#: 凭据值的最小长度：太短的值（如空串、单字符）不做比对，免得把
#: 随处可见的普通字符当成泄漏。
_MIN_SECRET_LENGTH = 4


class SnapshotError(RuntimeError):
    """快照写不出 / 读不回（目录不可写、快照缺失、版本对不上 …）。"""


class CredentialLeakError(SnapshotError):
    """快照里出现了密钥或凭据 —— **拒绝落盘**。"""


# --------------------------------------------------------------------- 数据


@dataclass(frozen=True)
class PolicySnapshot:
    """一份策略快照（批次 × 策略版本）。

    :param batch_no: 批次号（申请单号）。
    :param policy_version: 策略版本号（``pol-`` + 16 位十六进制）。
    :param policy_sha256: 生效配置的完整 sha256。
    :param profile: 当时选用的档位名（空串 = 默认档）。
    :param source: 策略表来源路径（当时的文件）。
    :param source_sha256: 策略表**文件**的 sha256（原始字节，含注释）。
    :param captured_at: 快照时刻（ISO 8601）。
    :param directory: 快照目录。
    :param policy_path: 生效配置副本路径（可喂回 ``load_policy_table()``）。
    :param meta_path: 摘要文件路径。
    :param summary: 摘要（全局阈值 / 逐识别器阈值 / 白名单摘要 / 上下文词表）。
    """

    batch_no: str
    policy_version: str = ""
    policy_sha256: str = ""
    profile: str = ""
    source: str = ""
    source_sha256: str = ""
    captured_at: str = ""
    directory: Path = field(default_factory=Path)
    policy_path: Path = field(default_factory=Path)
    meta_path: Path = field(default_factory=Path)
    summary: Mapping[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------- 装配


def effective_policy_document(table: PolicyTable) -> dict[str, Any]:
    """策略表的**生效配置**（档位已合并、``profiles`` 段已剥离）。

    为什么要剥掉 ``profiles``：档位内容已经被合并进根节点了，留着 ``profiles``
    只会让快照里出现「另一套用不上的档位」，重放时反而可能选错档。剥掉之后
    这份文件就是**唯一且完整**的生效配置。

    :param table: 已装载的策略表。
    """
    document = copy.deepcopy(dict(getattr(table, "document", None) or {}))
    document.pop("profiles", None)
    return document


def canonical_json(document: Mapping[str, Any]) -> str:
    """配置的**规范 JSON**（键排序、无多余空白）—— 算哈希的输入。

    规范化是版本号稳定的前提：同一份配置，无论 YAML 里的键怎么排、缩进怎么
    写，算出来的哈希必须一样。
    """
    return json.dumps(
        document,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def policy_digest(document: Mapping[str, Any]) -> str:
    """生效配置的 sha256（完整 64 位十六进制）。"""
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


def policy_version(document: Mapping[str, Any]) -> str:
    """策略版本号：``pol-`` + sha256 前 16 位。

    同一个配置永远算出同一个版本号；配置一改（哪怕只改一个阈值），版本号必变。
    """
    return POLICY_VERSION_PREFIX + policy_digest(document)[:POLICY_VERSION_DIGITS]


def summarize_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """给快照摘要用的汇总（人看的那一份）。

    摘要里放的是**配置**（阈值、白名单、上下文词表），不是患者数据 —— 白名单
    与上下文词表都是本院写法，放进快照正是为了「事后看得懂当时按什么写的」。
    """
    thresholds = document.get("thresholds") or {}
    per_section = thresholds.get("per_recognizer") or {}
    allow_section = document.get("allow_list") or {}
    context_section = document.get("context") or {}
    entities = document.get("entities") or {}
    recognizers = document.get("recognizers") or {}

    exact = [str(item) for item in (allow_section.get("exact") or [])]
    regex = [str(item) for item in (allow_section.get("regex") or [])]
    terms = [str(item) for item in (context_section.get("terms") or [])]

    return {
        "policy_version_field": document.get("version"),
        "global_threshold": thresholds.get("global"),
        "per_recognizer_thresholds": {
            str(key): value for key, value in per_section.items()
        },
        "recognizers": {
            str(key): (
                value.get("enabled", True) if isinstance(value, Mapping) else value
            )
            for key, value in recognizers.items()
        },
        "entity_actions": {
            str(key): (dict(value) if isinstance(value, Mapping) else value)
            for key, value in entities.items()
        },
        "allow_list": {
            "exact": exact,
            "regex": regex,
            "exact_count": len(exact),
            "regex_count": len(regex),
            "sha256": policy_digest({"exact": exact, "regex": regex}),
        },
        "context_terms": terms,
        "context_term_count": len(terms),
        "sections": sorted(str(key) for key in document),
    }


# ----------------------------------------------------------------- 凭据闸


def assert_no_credentials(
    document: Mapping[str, Any], env: Mapping[str, str] | None = None
) -> None:
    """快照里不得出现任何密钥或凭据 —— 命中即报错。

    三道检查：

    1. **键名**：出现 ``token`` / ``secret`` / ``password`` 之类的键 → 报错
       （``key_id`` 不算 —— 那是密钥版本号，不是秘密）；
    2. **取值**：当前进程里已配置的凭据（``$PSEUDONYM_HMAC_KEY`` 等）的**取值**
       出现在配置里 → 报错；
    3. **形状**：取值长得像 Bearer 令牌或私钥 → 报错。

    :raises CredentialLeakError: 命中任一条。
    """
    environment = os.environ if env is None else env
    payload = canonical_json(document)

    for name in CREDENTIAL_ENV_NAMES:
        value = (environment.get(name) or "").strip()
        if len(value) >= _MIN_SECRET_LENGTH and value in payload:
            raise CredentialLeakError(
                f"策略表里出现了 ${name} 的取值 —— 快照不得含任何凭据，"
                "请把凭据留在环境变量里、只把配置写进策略表"
            )

    for key, value in _walk(document):
        path = str(key).strip().lower()
        # 键名既看整条路径，也看最后一段 —— 嵌在段里的敏感键（``entities.
        # PATIENT_NAME.api_token``）同样要拦下来。
        leaf = path.rsplit(".", 1)[-1]
        if path in SENSITIVE_KEY_NAMES or leaf in SENSITIVE_KEY_NAMES:
            raise CredentialLeakError(
                f"策略表里出现了敏感键「{key}」—— 快照不得含任何凭据"
            )
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("Bearer ") or "-----BEGIN" in text:
                raise CredentialLeakError(
                    f"策略表的「{key}」取值长得像令牌 / 私钥 —— 快照不得含任何凭据"
                )


def _walk(node: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """遍历配置里的每个键值对（键名带路径，便于报错时说清是哪一段）。"""
    if isinstance(node, Mapping):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path, value
            yield from _walk(value, path)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            path = f"{prefix}[{index}]"
            yield path, value
            yield from _walk(value, path)


# --------------------------------------------------------------------- 落盘


def default_snapshot_dir(
    ledger: Any = None, output_dir: str | Path | None = None
) -> Path:
    """快照目录默认路径。

    **跟着台账走**（与批次锁同一个道理）：守护进程与运维 CLI 用同一张台账
    —— 快照目录也就落在台账旁边，两边看到的是同一份快照。台账是内存库
    （测试场景）时退回产物目录。

    环境变量 ``$RESEARCH_SNAPSHOT_DIR`` 优先 —— 部署时想把快照放到别处
    （独立磁盘、加密卷）就用它。

    :param ledger: 批次台账（用来定目录）。
    :param output_dir: 产物目录（台账是内存库时的退路）。
    """
    env_value = os.environ.get(SNAPSHOT_DIR_ENV)
    if env_value:
        return Path(env_value)
    ledger_path = getattr(ledger, "path", None)
    if ledger_path is not None and str(ledger_path) != ":memory:":
        return Path(ledger_path).parent / "snapshots"
    if output_dir is not None:
        return Path(output_dir) / ".snapshots"
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "policy").is_dir():
            return parent / "var" / "snapshots"
    root = here.parents[3] if len(here.parents) > 3 else here.parent
    return root / "var" / "snapshots"


def snapshot_dir_for(batch_no: str, snapshot_dir: str | Path | None = None) -> Path:
    """某个批次的快照目录（``<快照根>/<批次号>``）。"""
    root = Path(snapshot_dir) if snapshot_dir is not None else default_snapshot_dir()
    return root / _safe_name(batch_no)


def snapshot_policy_path(
    batch_no: str, snapshot_dir: str | Path | None = None
) -> Path:
    """某个批次的生效配置副本路径（``policy.yaml``）。"""
    return snapshot_dir_for(batch_no, snapshot_dir) / POLICY_FILE_NAME


def capture_snapshot(
    batch_no: str,
    table: PolicyTable,
    snapshot_dir: str | Path | None = None,
) -> PolicySnapshot:
    """给一个批次留一份策略快照（**落生产**：批次不留下快照就不可复现）。

    :param batch_no: 批次号（申请单号）。
    :param table: 本次生效的策略表。
    :param snapshot_dir: 快照根目录；缺省 :func:`default_snapshot_dir`。
    :return: 快照元信息。
    :raises CredentialLeakError: 配置里含凭据 —— **不落半份**，直接报错。
    :raises SnapshotError: 快照写不出（目录不可写等）。
    """
    document = effective_policy_document(table)
    assert_no_credentials(document)

    digest = policy_digest(document)
    version = POLICY_VERSION_PREFIX + digest[:POLICY_VERSION_DIGITS]
    directory = snapshot_dir_for(batch_no, snapshot_dir)
    policy_path = directory / POLICY_FILE_NAME
    meta_path = directory / META_FILE_NAME

    payload = yaml.safe_dump(
        document,
        allow_unicode=True,
        sort_keys=True,
        default_flow_style=False,
    )
    # 落盘前再扫一遍**序列化结果**：dump 过程不该引入凭据，但多扫一遍不花钱。
    _assert_text_has_no_credentials(payload)

    try:
        directory.mkdir(parents=True, exist_ok=True)
        temp_path = policy_path.with_name(POLICY_FILE_NAME + ".tmp")
        temp_path.write_text(payload, encoding="utf-8")
        temp_path.replace(policy_path)
    except OSError as exc:
        raise SnapshotError(
            f"批次 {batch_no} 的策略快照写不出（{directory}）：{exc}"
            " —— 没有快照的批次不可复现，不得照常交付"
        ) from exc

    meta = {
        "batch_no": batch_no,
        "policy_version": version,
        "policy_sha256": digest,
        "profile": table.profile,
        "source": table.source,
        "source_sha256": _file_sha256(table.source),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "policy_file": POLICY_FILE_NAME,
        "summary": summarize_document(document),
    }
    try:
        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise SnapshotError(
            f"批次 {batch_no} 的策略快照摘要写不出（{meta_path}）：{exc}"
        ) from exc

    return PolicySnapshot(
        batch_no=batch_no,
        policy_version=version,
        policy_sha256=digest,
        profile=table.profile,
        source=table.source,
        source_sha256=meta["source_sha256"],
        captured_at=meta["captured_at"],
        directory=directory,
        policy_path=policy_path,
        meta_path=meta_path,
        summary=meta["summary"],
    )


def read_snapshot_meta(path: str | Path) -> dict[str, Any]:
    """读回快照摘要文件。

    :raises SnapshotError: 文件不存在或不是合法 JSON。
    """
    target = Path(path)
    if not target.is_file():
        raise SnapshotError(f"策略快照摘要不存在：{target}")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"策略快照摘要读不出来：{target}（{exc}）") from exc
    if not isinstance(payload, dict):
        raise SnapshotError(f"策略快照摘要结构不对：{target}")
    return payload


def load_snapshot(
    batch_no: str, snapshot_dir: str | Path | None = None
) -> PolicySnapshot:
    """读回某批次的策略快照。

    :raises SnapshotError: 快照缺失或摘要读不出来。
    """
    directory = snapshot_dir_for(batch_no, snapshot_dir)
    meta = read_snapshot_meta(directory / META_FILE_NAME)
    return PolicySnapshot(
        batch_no=str(meta.get("batch_no", batch_no)),
        policy_version=str(meta.get("policy_version", "")),
        policy_sha256=str(meta.get("policy_sha256", "")),
        profile=str(meta.get("profile", "")),
        source=str(meta.get("source", "")),
        source_sha256=str(meta.get("source_sha256", "")),
        captured_at=str(meta.get("captured_at", "")),
        directory=directory,
        policy_path=directory / POLICY_FILE_NAME,
        meta_path=directory / META_FILE_NAME,
        summary=dict(meta.get("summary") or {}),
    )


# --------------------------------------------------------------------- 内部


def _assert_text_has_no_credentials(text: str) -> None:
    """扫一段文本里有没有当前进程里已配置的凭据取值。"""
    for name in CREDENTIAL_ENV_NAMES:
        value = (os.environ.get(name) or "").strip()
        if len(value) >= _MIN_SECRET_LENGTH and value in text:
            raise CredentialLeakError(
                f"序列化后的快照里出现了 ${name} 的取值 —— 快照不得含任何凭据"
            )


def _file_sha256(path: str) -> str:
    """文件 sha256；读不到就留空串（不编造）。"""
    if not path:
        return ""
    target = Path(path)
    try:
        return hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError:
        return ""


def _safe_name(value: str) -> str:
    """把批次号变成安全的目录名（路径分隔符与控制字符一律换掉）。"""
    cleaned = "".join(
        char if (char.isalnum() or char in "-_.") else "_" for char in value.strip()
    )
    return cleaned or "unnamed"
