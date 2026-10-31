"""recognizers 子包：识别层。

对外四件套：

- ``Recognizer``（``base.py``）：识别器基类与三种形态
  （正则匹配 / 校验位验证 / 权威名单匹配）。
- ``LabeledFieldRecognizer``（``labeled_field.py``）：字段标签驱动形态 ——
  标签（姓名 / 住院号 / 检查号…）与它后面的值绑定。
- ``RecognizerRegistry``（``registry.py``）：装配 + 阈值 + 去重 + 白名单。
- ``EntitySpan`` / ``SpanTier``（``models.py``）：裁决后的实体区间与档位。
"""

from ..models import EntitySpan, RecognizerResult, SpanTier
from .base import (
    AuthorityEntry,
    ChecksumRecognizer,
    ListRecognizer,
    PatternRecognizer,
    Recognizer,
    normalize_text,
    normalize_with_offsets,
)
from .id_card import (
    GB11643_CHECK_CODES,
    GB11643_WEIGHTS,
    ID_CARD_ENTITY,
    IdCardConfig,
    IdCardConfigError,
    IdCardRecognizer,
    IdCardVerdict,
    VerdictKind,
    gb11643_check_char,
    load_id_card_config,
    validate_id_card,
)
from .labeled_field import DEFAULT_FIELDS, FieldSpec, LabeledFieldRecognizer
from .numeric_boundary import (
    CONTEXT_REQUIRED_LABELS,
    NumericBoundary,
    NumericBoundaryConfig,
    NumericBoundaryConfigError,
    load_numeric_boundary_config,
)
from .registry import RecognizerRegistry, RegistryConfig

__all__ = [
    "AuthorityEntry",
    "CONTEXT_REQUIRED_LABELS",
    "ChecksumRecognizer",
    "DEFAULT_FIELDS",
    "EntitySpan",
    "FieldSpec",
    "GB11643_CHECK_CODES",
    "GB11643_WEIGHTS",
    "ID_CARD_ENTITY",
    "IdCardConfig",
    "IdCardConfigError",
    "IdCardRecognizer",
    "IdCardVerdict",
    "LabeledFieldRecognizer",
    "ListRecognizer",
    "NumericBoundary",
    "NumericBoundaryConfig",
    "NumericBoundaryConfigError",
    "PatternRecognizer",
    "Recognizer",
    "RecognizerRegistry",
    "RecognizerResult",
    "RegistryConfig",
    "SpanTier",
    "VerdictKind",
    "gb11643_check_char",
    "load_id_card_config",
    "load_numeric_boundary_config",
    "normalize_text",
    "normalize_with_offsets",
    "validate_id_card",
]
