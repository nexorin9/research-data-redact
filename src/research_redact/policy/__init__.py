"""policy 子包：策略层。

三件套：

- ``operators.py``：处置动作框架 —— 实体类别命中之后，这一段正文**怎么改写**。
  ``replace`` / ``redact`` / ``keep`` 三种确定性动作 + 一致代号
  （``hmac_pseudonym``）与其还原侧（``hmac_restore``）成对挂载。
- ``table.py``：策略表装载与校验 —— 读 ``policy/research.yaml``，
  把「实体类别 → 处置动作」「阈值」「识别器名册（启停）」「白名单」「上下文词表」
  装配成可用的对象；``build_registry`` 再把策略表装成一张识别器注册表。
  配置非法即报错，不静默取默认值。
- ``conflicts.py``：冲突区间裁决 —— 两段命中互相重叠时只由一处负责改写，
  被裁掉的一方留痕进命中清单（身份类优先于就诊编号类）。
- ``mapping.py``：对照索引（代号 ↔ 原文）—— 一致代号可逆性的底座；
  按「材料 + 代号 + 第几次出现」分槽，同一代号对应多段原文时也不串号。
- ``index_store.py``：对照索引的**加密落盘与访问留痕**（与交付物分离存放、
  密钥分离、索引不可达即挂起批次）。

对外主路径用法：``load_policy_table().resolver()`` 给出「类别 → 动作」的解析
函数，交给 :func:`research_redact.daemon.pipeline.redact_text` 的 ``actions``
参数；守护进程与运维 CLI 共用同一条主路径。
"""

from .conflicts import (
    ConflictConfigError,
    ConflictResolution,
    ConflictResolutionError,
    ConflictRules,
    PRIORITY_TIERS,
    load_conflict_rules,
    resolve_conflicts,
)
from .index_store import (
    EncryptedIndexStore,
    IndexDecryptError,
    IndexFileMissingError,
    IndexKeyError,
    IndexStoreError,
    IndexUnavailableError,
    JsonlAccessTrail,
    KEY_SOURCE_DERIVED,
    KEY_SOURCE_EXPLICIT,
    default_index_path,
    load_index_store,
    resolve_index_key,
    suspend_unreachable_batch,
)
from .mapping import (
    MappingIndexError,
    MappingIndexUnavailableError,
    OccurrenceMappingIndex,
    PseudonymMappingIndex,
    TokenNotFoundError,
    TokenOccurrence,
)
from .operators import (
    ActionSpec,
    KeepOperator,
    KNOWN_OPERATOR_NAMES,
    Operator,
    OperatorContext,
    OperatorError,
    OperatorNotFoundError,
    OperatorRegistry,
    OperatorUnavailableError,
    PseudonymOperator,
    RESERVED_OPERATOR_NAMES,
    RedactOperator,
    ReplaceOperator,
    RestoreOperator,
    RestoreTextResult,
    RestoreTokenNotFoundError,
    default_operator_registry,
)
from .table import (
    CATALOG_NAMES,
    CONTEXT_BOOST_ID,
    RECOGNIZER_IDS,
    PolicyTable,
    PolicyTableError,
    RecognizerCatalog,
    UndeclaredEntityError,
    build_registry,
    load_policy_table,
)

__all__ = [
    "ActionSpec",
    "CATALOG_NAMES",
    "CONTEXT_BOOST_ID",
    "ConflictConfigError",
    "ConflictResolution",
    "ConflictResolutionError",
    "ConflictRules",
    "EncryptedIndexStore",
    "IndexDecryptError",
    "IndexFileMissingError",
    "IndexKeyError",
    "IndexStoreError",
    "IndexUnavailableError",
    "JsonlAccessTrail",
    "KEY_SOURCE_DERIVED",
    "KEY_SOURCE_EXPLICIT",
    "KeepOperator",
    "KNOWN_OPERATOR_NAMES",
    "MappingIndexError",
    "MappingIndexUnavailableError",
    "OccurrenceMappingIndex",
    "Operator",
    "OperatorContext",
    "OperatorError",
    "OperatorNotFoundError",
    "OperatorRegistry",
    "OperatorUnavailableError",
    "PRIORITY_TIERS",
    "PolicyTable",
    "PolicyTableError",
    "PseudonymMappingIndex",
    "PseudonymOperator",
    "RECOGNIZER_IDS",
    "RecognizerCatalog",
    "RESERVED_OPERATOR_NAMES",
    "RedactOperator",
    "ReplaceOperator",
    "RestoreOperator",
    "RestoreTextResult",
    "RestoreTokenNotFoundError",
    "TokenNotFoundError",
    "TokenOccurrence",
    "UndeclaredEntityError",
    "build_registry",
    "default_index_path",
    "default_operator_registry",
    "load_conflict_rules",
    "load_index_store",
    "load_policy_table",
    "resolve_conflicts",
    "resolve_index_key",
    "suspend_unreachable_batch",
]
