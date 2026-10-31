"""restore 子包：受控还原（授权闸门 + 执行 + 回执 + 留痕）。

对外只暴露三样东西：

- :class:`~research_redact.restore.authority.AuthorityValidator` —— 授权裁决
  （双人 / 名单 / 时效 / 范围）；
- :class:`~research_redact.restore.service.RestoreService` —— 执行还原；
- :class:`~research_redact.restore.service.MappingIndex` —— 对照索引协议
  （代号 ↔ 原文）。
"""

from __future__ import annotations

from .authority import (
    APPROVER_LIST_ENV,
    ApproverRegistry,
    AuthorityDecision,
    AuthorityValidator,
    DEFAULT_AUTHORIZATION_TTL,
    authorize_window,
    default_authority_validator,
)
from .service import (
    DEFAULT_TOKEN_PATTERN,
    InMemoryMappingIndex,
    MappingIndex,
    RestoreExecutionError,
    RestoreOutcome,
    RestoreService,
    RestoreServiceError,
    RestoreStateError,
)

__all__ = [
    "APPROVER_LIST_ENV",
    "ApproverRegistry",
    "AuthorityDecision",
    "AuthorityValidator",
    "DEFAULT_AUTHORIZATION_TTL",
    "DEFAULT_TOKEN_PATTERN",
    "InMemoryMappingIndex",
    "MappingIndex",
    "RestoreExecutionError",
    "RestoreOutcome",
    "RestoreService",
    "RestoreServiceError",
    "RestoreStateError",
    "authorize_window",
    "default_authority_validator",
]
