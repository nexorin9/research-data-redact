"""还原的授权闸门：双人、名单、时效、范围。

脱敏是「往外送」，还原是「把原文拿回来」—— 后者的风险高一个量级：一份
脱敏副本出去之后，能不能凭一个口令就换回姓名与住院号，决定了整套系统是
「可核查的科研交付」还是「一个随时可被撬开的保险箱」。所以还原的第一道
闸不是技术，是**授权**。

**四条硬规矩**（缺一条就不放行）：

1. **双人** —— 授权人 A 与 B 都在授权名单内、且不是同一人。缺第二授权人
   **挂起**（原地等签字），**不降级为单人还原**：一个人既申请又批，等于
   没批。
2. **名单** —— 授权人必须在本院授权名单内（``$RESTORE_AUTHORIZER_LIST``）。
   名单为空 = 无人可授权，此时任何还原请求都不得通过（不是「白名单为空
   就都算通过」）。
3. **时效** —— 授权必须带截止时间。没有截止时间的授权 = 无限期授权 =
   不放行；已过期的授权一律拒绝。
4. **范围** —— 授权必须限定可还原的材料集合，且请求的材料必须落在
   「授权范围 ∩ 本批已交付材料」之内。超范围即拒。

**三种裁决结果**（不是两种）：

- ``approved`` —— 放行，可以执行还原；
- ``pending`` —— **挂起**：只差第二授权人签字，批次停在 ``restore_pending``；
- ``rejected`` —— 拒绝：批次转 ``restore_rejected`` 并留痕。

把「挂起」和「拒绝」分开是刻意的：挂起是可以补齐的（等签字），拒绝是
结论性的（补不齐或不该做）。两者都不还原，但留痕与状态各不相同 ——
混成一个「失败」，事后查不出「到底是没人签还是签了不生效」。

本模块只做判定，**不碰任何患者原文**：它看的是名单、计数与时间。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable, Mapping, Sequence

from ..models import RestoreAuthorization, utcnow

__all__ = [
    "APPROVER_LIST_ENV",
    "ApproverRegistry",
    "AuthorityDecision",
    "AuthorityValidator",
    "CODE_APPROVER_NOT_REGISTERED",
    "CODE_AUTHORIZATION_EXPIRED",
    "CODE_AUTHORIZATION_WINDOW_MISSING",
    "CODE_MISSING_APPROVER_A",
    "CODE_MISSING_APPROVER_B",
    "CODE_SAME_APPROVER",
    "CODE_SCOPE_MISSING",
    "CODE_SCOPE_VIOLATION",
    "DEFAULT_AUTHORIZATION_TTL",
    "REJECTION_CODES",
    "authorize_window",
    "default_authority_validator",
]


#: 环境变量：可授权还原的人员名单（逗号分隔，中英文逗号都认）。
#: 名单为空 = 无人可授权 —— 此时任何还原请求都不得通过。
APPROVER_LIST_ENV = "RESTORE_AUTHORIZER_LIST"

#: 授权默认时效（24 小时）。授权窗口没有截止时间 = 无限期授权 = 不放行。
DEFAULT_AUTHORIZATION_TTL = timedelta(hours=24)


# --------------------------------------------------------------------- 裁决码

#: 还原请求没有授权人 A —— 无人授权，不得进入还原流程。
CODE_MISSING_APPROVER_A = "missing_approver_a"
#: 缺授权人 B —— **挂起**（不是拒绝）：等第二授权人签字。
CODE_MISSING_APPROVER_B = "missing_approver_b"
#: 授权人不在本院授权名单内。
CODE_APPROVER_NOT_REGISTERED = "approver_not_registered"
#: 两位授权人是同一人 —— 双人授权不得由一人兼任。
CODE_SAME_APPROVER = "same_approver"
#: 授权未设时效 —— 无限期授权不放行。
CODE_AUTHORIZATION_WINDOW_MISSING = "authorization_window_missing"
#: 授权已过期。
CODE_AUTHORIZATION_EXPIRED = "authorization_expired"
#: 授权没有限定材料范围。
CODE_SCOPE_MISSING = "scope_missing"
#: 请求的材料超出授权范围，或不在本批已交付材料内。
CODE_SCOPE_VIOLATION = "scope_violation"

#: 全部裁决码（供 CLI / 告警按码分流）。
REJECTION_CODES: tuple[str, ...] = (
    CODE_MISSING_APPROVER_A,
    CODE_MISSING_APPROVER_B,
    CODE_APPROVER_NOT_REGISTERED,
    CODE_SAME_APPROVER,
    CODE_AUTHORIZATION_WINDOW_MISSING,
    CODE_AUTHORIZATION_EXPIRED,
    CODE_SCOPE_MISSING,
    CODE_SCOPE_VIOLATION,
)


# --------------------------------------------------------------------- 名单


@dataclass(frozen=True)
class ApproverRegistry:
    """可授权还原的人员名单。

    :param approvers: 授权人标识（工号 / 姓名，按院内既有写法）。
    """

    approvers: tuple[str, ...] = ()

    @classmethod
    def from_names(cls, names: Iterable[str]) -> "ApproverRegistry":
        """从名字清单装配（去空白、去重、保持顺序）。"""
        seen: list[str] = []
        for name in names:
            text = str(name).strip()
            if text and text not in seen:
                seen.append(text)
        return cls(tuple(seen))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ApproverRegistry":
        """从环境变量装配名单（``$RESTORE_AUTHORIZER_LIST``，逗号分隔）。

        读不到就是空名单 —— **不是**「默认全员可授权」。
        """
        source = os.environ if env is None else env
        raw = str(source.get(APPROVER_LIST_ENV, "") or "")
        return cls.from_names(raw.replace("，", ",").split(","))

    def contains(self, name: str) -> bool:
        """该授权人是否在名单内。"""
        return str(name).strip() in self.approvers

    def describe(self) -> str:
        """一句人话说明（写进告警与 CLI 摘要，**不含患者数据**）。"""
        if not self.approvers:
            return "授权名单为空：当前无人可授权还原"
        return f"授权名单 {len(self.approvers)} 人"

    def __len__(self) -> int:
        return len(self.approvers)

    def __iter__(self):
        return iter(self.approvers)

    def __bool__(self) -> bool:
        return bool(self.approvers)


# --------------------------------------------------------------------- 裁决


@dataclass(frozen=True)
class AuthorityDecision:
    """一次授权裁决的结论。

    :param approved: 是否放行。
    :param pending: 是否挂起（只差第二授权人签字）。
    :param code: 裁决码（挂起 / 拒绝都有码，便于按码分流）。
    :param reason: 一句人话说明（写进留痕与回执，**不含患者原文**）。
    :param approver_a: 授权人 A。
    :param approver_b: 授权人 B（挂起时为空）。
    :param scope: 裁决通过的还原范围（材料 ID 清单）。
    :param expires_at: 授权截止时间。
    """

    approved: bool
    pending: bool
    code: str
    reason: str
    approver_a: str = ""
    approver_b: str = ""
    scope: tuple[str, ...] = ()
    expires_at: datetime | None = None

    @property
    def rejected(self) -> bool:
        """是否被拒绝（既没放行也没挂起）。"""
        return not self.approved and not self.pending

    def to_dict(self) -> dict[str, object]:
        """转成可落盘的字典（**不含患者原文**）。"""
        return {
            "approved": self.approved,
            "pending": self.pending,
            "code": self.code,
            "reason": self.reason,
            "approver_a": self.approver_a,
            "approver_b": self.approver_b,
            "scope": list(self.scope),
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
        }


class AuthorityValidator:
    """授权裁决器：双人 + 名单 + 时效 + 范围。

    :param registry: 授权人名单；缺省按环境变量装配。
    :param now_fn: 取当前时间的方式（测试可注入固定时钟）。
    :param default_ttl: 生成授权窗口时的默认时效（供 :func:`authorize_window` 使用）。
    """

    def __init__(
        self,
        registry: ApproverRegistry | None = None,
        *,
        now_fn: Callable[[], datetime] = utcnow,
        default_ttl: timedelta = DEFAULT_AUTHORIZATION_TTL,
    ) -> None:
        self.registry = registry if registry is not None else ApproverRegistry.from_env()
        self._now = now_fn
        self.default_ttl = default_ttl

    def validate(
        self,
        authorization: RestoreAuthorization,
        *,
        allowed_scope: Sequence[str] = (),
        requested_scope: Sequence[str] | None = None,
    ) -> AuthorityDecision:
        """裁决一份还原授权。

        :param authorization: 待裁决的授权。
        :param allowed_scope: 本批**已交付**的材料 ID 清单（空 = 不校验这一层）。
        :param requested_scope: 本次实际要还原的材料 ID；缺省取 ``authorization.scope``。
        :return: 裁决结论（放行 / 挂起 / 拒绝）。
        """
        approver_a = str(authorization.approver_a or "").strip()
        approver_b = str(authorization.approver_b or "").strip()

        # 1. 授权人 A —— 没有它就没有「授权」这回事
        if not approver_a:
            return self._reject(
                CODE_MISSING_APPROVER_A,
                "还原请求缺授权人 A：无人授权不得进入还原流程",
                approver_a=approver_a,
            )
        if not self.registry.contains(approver_a):
            return self._reject(
                CODE_APPROVER_NOT_REGISTERED,
                f"授权人 A 不在授权名单内：{approver_a}（{self.registry.describe()}）",
                approver_a=approver_a,
            )

        # 2. 授权人 B —— 缺则**挂起**，不降级为单人
        if not approver_b:
            return AuthorityDecision(
                approved=False,
                pending=True,
                code=CODE_MISSING_APPROVER_B,
                reason="还原缺授权人 B：不得单人还原，须挂起等待第二授权人签字",
                approver_a=approver_a,
                approver_b="",
                scope=(),
                expires_at=authorization.expires_at,
            )
        if not self.registry.contains(approver_b):
            return self._reject(
                CODE_APPROVER_NOT_REGISTERED,
                f"授权人 B 不在授权名单内：{approver_b}（{self.registry.describe()}）",
                approver_a=approver_a,
                approver_b=approver_b,
            )

        # 3. 不得同一人兼任
        if approver_a == approver_b:
            return self._reject(
                CODE_SAME_APPROVER,
                "两位授权人相同：双人授权不得由一人兼任",
                approver_a=approver_a,
                approver_b=approver_b,
            )

        # 4. 时效 —— 无限期授权不放行
        expires_at = authorization.expires_at
        if expires_at is None:
            return self._reject(
                CODE_AUTHORIZATION_WINDOW_MISSING,
                "还原授权未设时效：不得执行没有截止时间的授权",
                approver_a=approver_a,
                approver_b=approver_b,
            )
        if self._now() > expires_at:
            return self._reject(
                CODE_AUTHORIZATION_EXPIRED,
                f"还原授权已过期（截止 {expires_at.isoformat()}）：不得执行",
                approver_a=approver_a,
                approver_b=approver_b,
                expires_at=expires_at,
            )

        # 5. 范围 —— 授权必须限定材料，且请求不得越界
        scope = tuple(
            dict.fromkeys(
                str(item).strip() for item in authorization.scope if str(item).strip()
            )
        )
        if not scope:
            return self._reject(
                CODE_SCOPE_MISSING,
                "还原授权未限定材料范围：不得执行范围不明的还原",
                approver_a=approver_a,
                approver_b=approver_b,
                expires_at=expires_at,
            )
        requested = tuple(
            dict.fromkeys(
                str(item).strip()
                for item in (
                    authorization.scope if requested_scope is None else requested_scope
                )
                if str(item).strip()
            )
        )
        if requested_scope is not None:
            outside = [item for item in requested if item not in scope]
            if outside:
                return self._reject(
                    CODE_SCOPE_VIOLATION,
                    "请求还原的材料超出授权范围：" + "、".join(outside),
                    approver_a=approver_a,
                    approver_b=approver_b,
                    expires_at=expires_at,
                )
        if allowed_scope:
            not_delivered = [item for item in requested if item not in set(allowed_scope)]
            if not_delivered:
                return self._reject(
                    CODE_SCOPE_VIOLATION,
                    "请求还原的材料不在本批已交付清单内："
                    + "、".join(not_delivered),
                    approver_a=approver_a,
                    approver_b=approver_b,
                    expires_at=expires_at,
                )
        return AuthorityDecision(
            approved=True,
            pending=False,
            code="approved",
            reason="双人授权齐备、授权在时效内、范围相符",
            approver_a=approver_a,
            approver_b=approver_b,
            scope=scope,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------ 内部

    def _reject(
        self,
        code: str,
        reason: str,
        *,
        approver_a: str = "",
        approver_b: str = "",
        expires_at: datetime | None = None,
    ) -> AuthorityDecision:
        """构造一个拒绝结论。"""
        return AuthorityDecision(
            approved=False,
            pending=False,
            code=code,
            reason=reason,
            approver_a=approver_a,
            approver_b=approver_b,
            scope=(),
            expires_at=expires_at,
        )


def authorize_window(
    now: datetime | None = None,
    ttl: timedelta = DEFAULT_AUTHORIZATION_TTL,
) -> tuple[datetime, datetime]:
    """给一份还原授权定出授权窗口（起止时间）。

    调用方（CLI 的 ``restore-request``、院内的授权流程）用这对时间构造
    :class:`~research_redact.models.RestoreAuthorization`；**授权窗口由调用方
    显式给出**，服务层不代填 —— 代填等于「谁都能给自己开一个 24 小时窗口」。

    :param now: 授权生效时间；缺省取当前 UTC 时间。
    :param ttl: 有效期。
    :return: ``(granted_at, expires_at)``。
    """
    start = now if now is not None else utcnow()
    return start, start + ttl


def default_authority_validator() -> AuthorityValidator:
    """默认裁决器：名单按环境变量装配，时效用默认 24 小时。"""
    return AuthorityValidator()
