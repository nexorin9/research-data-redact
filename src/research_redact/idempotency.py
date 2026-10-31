"""幂等键：申请单号 + 材料集合指纹。

**为什么需要这一层**：科研材料交付出去以后，最怕的是「同一批材料被交了两次」。
科研数据平台上多出一个数据集，伦理办那边看到的却是「交付了一次」—— 对不上账，
追不回来。而科研交付是**事件驱动**的：管理员把申请单放进交付目录、守护进程
捡起来、平台 5xx 退避重试、守护进程重启补投、人工在运维 CLI 上再点一次
deliver —— 一次交付可能从四个方向被触发。没有幂等键，这四条路会交出四个
数据集。

**幂等键怎么算**::

    材料集合指纹 = sha256(排序后的「材料 ID:源文件 sha256」用 | 串起来)
    幂等键       = 申请单号 + "." + 指纹前 32 位

两条口径说明：

1. **材料 ID 与文件摘要都要进指纹** —— 只用材料 ID 的话，管理员把材料内容
   换掉（同一批号、同一材料 ID）会被误判成重复批次，旧产物直接被复用，
   新内容永远交不出去。
2. **排序后再哈希** —— 管理员重排目录里的材料顺序，那是同一批材料，
   指纹不该变。

**摘要取哪个文件**：优先取**源文件**摘要（``source_sha256``），没有才退回
交付副本摘要（``sha256``）。用源文件摘要做批次身份，含义是「这批原始材料
还是那一批吗」；交付副本摘要是「这次脱敏出来的内容一样吗」，两者在材料
没动时一致，材料动了则源文件摘要先变 —— 批次身份应当跟着**原始材料**走。

**不含患者原文**：指纹是摘要，键里只有申请单号与摘要 —— 不含姓名、住院号、
身份证等任何原文。
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "DIGEST_FIELDS",
    "IDEMPOTENCY_KEY_SEPARATOR",
    "compute_idempotency_key",
    "material_set_fingerprint",
]

#: 幂等键两段之间的分隔符。
IDEMPOTENCY_KEY_SEPARATOR = "."

#: 摘要字段的取值优先级：先源文件摘要，后交付副本摘要。
DIGEST_FIELDS: tuple[str, ...] = ("source_sha256", "sha256")

#: 幂等键里带进指纹的长度（十六进制位）。
_FINGERPRINT_PREFIX_LEN = 32


def material_set_fingerprint(
    items: Iterable[Mapping[str, Any]],
    *,
    digest_fields: Sequence[str] = DIGEST_FIELDS,
) -> str:
    """材料集合指纹：材料 ID 与文件 sha256 排序后哈希。

    :param items: 材料项（每项至少有 ``material_id``；摘要字段按
        ``digest_fields`` 的优先级取，取不到就落空串）。
    :param digest_fields: 摘要字段的取值优先级。
    :return: 十六进制指纹。

    **顺序无关**：材料项顺序变了指纹不变（同一批材料）。
    **内容有关**：任何一个材料的 ID 或摘要变了，指纹就变（不是同一批了）。
    """
    parts: list[str] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        material_id = str(item.get("material_id") or "").strip()
        digest = ""
        for field in digest_fields:
            value = str(item.get(field) or "").strip()
            if value:
                digest = value
                break
        parts.append(f"{material_id}:{digest}")
    parts.sort()
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def compute_idempotency_key(application_no: str, fingerprint: str) -> str:
    """批次幂等键 = 申请单号 + 材料集合指纹。

    :param application_no: 申请单号（批次号）。
    :param fingerprint: 材料集合指纹。
    :return: 幂等键（``<申请单号>.<指纹前 32 位>``）。

    这个键同时是**台账里的唯一约束**与**对外的 Idempotency-Key 头值** ——
    一处算、处处用，两边对得上。
    """
    return f"{application_no}{IDEMPOTENCY_KEY_SEPARATOR}{fingerprint[:_FINGERPRINT_PREFIX_LEN]}"
