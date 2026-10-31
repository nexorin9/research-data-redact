"""断点续跑：识别已经跑完的批次，从最后一步接上，**不重跑识别**。

**为什么需要这一层**：科研交付是**长链条** —— 管理员把材料放进交付目录、
守护进程脱敏、残留自检、交平台、平台回执。链条中间任何一环都可能断电、
被 kill、机器重启。守护进程重启后如果「从头再来」，代价不只是白跑一遍：
**一致代号会变**（代号取自进程内的对照索引，重启后索引是空的，重跑会拿到
另一组代号），同一患者在前后两批材料里的代号对不上，平台侧核不出来，
伦理办对不上账。

所以批次的每一步都要**落进台账**，重启后从最后一步接上。

**四条纪律**：

1. **只接得上有据可查的批次** —— 台账里没有「脱敏已完成」的步骤记录、产物
   不在磁盘上、产物摘要对不上、源材料已经变了 —— 任何一条不成立就**重跑
   识别**，不拿旧产物凑合交。
2. **源材料变了就是新的一批** —— 材料集合指纹对不上（管理员换了材料、补了
   材料）→ 不能复用旧产物，按新集合重新脱敏。
3. **产物摘要对不上就不复用** —— 续跑交出去的是磁盘上那份脱敏副本；它被动过
   （手工编辑、别的进程覆盖）就不能直接交，重新脱敏。
4. **续跑要留痕** —— 复用旧产物这件事写进访问留痕（谁、何时、复用了哪一批），
   事后说得清「这一批的脱敏是哪一次跑的」。

**步骤台账**：批次表里的 ``current_step``（当前步骤）与 ``completed_steps``
（已完成步骤集合）是续跑判定的依据：

============  ======================================================
步骤          含义
============  ======================================================
``intake``    申请单校验完成（伦理批件号与材料清单齐备）
``redact``    识别与处置完成，脱敏副本与命中清单已落盘，批次身份已登记
``residual_check``  残留自检通过，可进入投递
``payload``   投递载荷已组装并交给投递通道
============  ======================================================

**不变量**：本模块只读摘要、路径与计数，**不碰任何患者原文** —— 续跑复用的
是磁盘上已经脱过的副本，命中清单也不重写。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .state_machine import BatchState

__all__ = [
    "RESUME_STEPS",
    "STEP_INTAKE",
    "STEP_PAYLOAD",
    "STEP_REDACT",
    "STEP_RESIDUAL",
    "ResumePlan",
    "artifacts_intact",
    "material_set_matches",
    "plan_resume",
]


#: 申请单校验完成。
STEP_INTAKE = "intake"

#: 识别与处置完成，脱敏副本与命中清单已落盘，批次身份（指纹 / 幂等键）已登记。
STEP_REDACT = "redact"

#: 残留自检通过。
STEP_RESIDUAL = "residual_check"

#: 投递载荷已组装并交给投递通道。
STEP_PAYLOAD = "payload"

#: 一个批次的步骤顺序。
RESUME_STEPS: tuple[str, ...] = (STEP_INTAKE, STEP_REDACT, STEP_RESIDUAL, STEP_PAYLOAD)


@dataclass(frozen=True)
class ResumePlan:
    """续跑计划：这一批能从哪一步接上。

    :param batch_no: 批次号（申请单号）。
    :param artifacts: 产物路径（材料 ID → 脱敏副本路径；另含 ``manifest``）。
    :param material_entries: 交付体的材料清单（材料 ID / 类别 / 摘要 / 路径）。
    :param fingerprint: 材料集合指纹（源文件摘要口径）。
    :param idempotency_key: 批次幂等键（申请单号 + 材料集合指纹）。
    :param residual_known: 残留自检是否已有结论（True = 沿用上一轮，不重扫）。
    :param reason: 一句人话说明（写进留痕与运维摘要）。
    """

    batch_no: str
    artifacts: Mapping[str, str] = field(default_factory=dict)
    material_entries: tuple[Mapping[str, str], ...] = ()
    fingerprint: str = ""
    idempotency_key: str = ""
    residual_known: bool = False
    reason: str = ""


def artifacts_intact(
    artifacts: Mapping[str, str],
    material_entries: tuple[Mapping[str, str], ...] | list[Mapping[str, str]],
) -> bool:
    """产物是否还在、还是不是交付时登记的那一份。

    两条判定：

    1. **文件都在** —— 产物目录被清过、磁盘换了，续跑就没有东西可交；
    2. **摘要对得上** —— 每份材料的当前 sha256 与登记时的一致：产物被改过
       （手工编辑、别的进程覆盖）就不能直接交出去。

    :param artifacts: 产物路径表。
    :param material_entries: 交付体的材料清单（带登记时的摘要）。
    """
    if not artifacts:
        return False
    for path in artifacts.values():
        if not path:
            return False
        if not Path(path).is_file():
            return False
    from ..outbound.research_platform_client import file_sha256

    for entry in material_entries:
        material_id = str(entry.get("material_id") or "").strip()
        path = str(entry.get("path") or "").strip()
        recorded = str(entry.get("sha256") or "").strip()
        if not material_id or not path:
            continue
        if not recorded:
            # 没登记摘要（老批次 / 登记时算不出来）→ 只看文件在不在
            continue
        try:
            current = file_sha256(path)
        except OSError:
            return False
        if current != recorded:
            return False
    return True


def material_set_matches(
    material_entries: tuple[Mapping[str, str], ...] | list[Mapping[str, str]],
    source_digests: Mapping[str, str],
) -> bool:
    """源材料还是不是登记时那一份。

    管理员换了材料的内容（同一批号、同一材料 ID）→ 指纹变 → **是新的一批**，
    不能复用旧产物（那样交出去的是上一版的脱敏结果）。补材料同理。

    :param material_entries: 交付体的材料清单（带登记时的源文件摘要）。
    :param source_digests: 当前源文件摘要（材料 ID → sha256）。
    """
    if not source_digests:
        return False
    for entry in material_entries:
        material_id = str(entry.get("material_id") or "").strip()
        recorded = str(entry.get("source_sha256") or "").strip()
        if not material_id or not recorded:
            continue
        if source_digests.get(material_id, "") != recorded:
            return False
    return True


def plan_resume(
    record: Any,
    *,
    source_digests: Mapping[str, str] | None = None,
) -> ResumePlan | None:
    """判定一个批次能不能从「识别已完成」处接上。

    判定不通过时返回 ``None`` —— 调用方按「没跑过识别」处理（重跑）。

    :param record: 批次台账记录（:class:`~research_redact.audit.ledger.BatchRecord`）。
    :param source_digests: 当前源文件摘要（材料 ID → sha256）；给了就额外核对
        「源材料还是不是登记时那一份」。
    """
    if record is None:
        return None
    if record.batch_state is not BatchState.PSEUDONYMIZED:
        return None
    if STEP_REDACT not in tuple(record.completed_steps):
        return None
    artifacts = dict(record.artifacts or {})
    if not artifacts or not artifacts.get("manifest"):
        return None
    entries = tuple(dict(item) for item in (record.material_entries or ()))
    if not entries:
        return None
    if not artifacts_intact(artifacts, entries):
        return None
    if source_digests is not None and not material_set_matches(entries, source_digests):
        return None

    fingerprint = str(record.material_fingerprint or "").strip()
    if not fingerprint:
        from ..idempotency import material_set_fingerprint

        fingerprint = material_set_fingerprint(entries)
    idempotency_key = str(record.idempotency_key or "").strip()
    if not idempotency_key:
        from ..idempotency import compute_idempotency_key

        idempotency_key = compute_idempotency_key(record.batch_no, fingerprint)

    return ResumePlan(
        batch_no=record.batch_no,
        artifacts=artifacts,
        material_entries=entries,
        fingerprint=fingerprint,
        idempotency_key=idempotency_key,
        residual_known=STEP_RESIDUAL in tuple(record.completed_steps),
        reason=(
            "识别已在上轮完成，本次复用脱敏产物（不重跑识别）"
            if STEP_RESIDUAL in tuple(record.completed_steps)
            else "识别已在上轮完成，本次复用脱敏产物并重新做残留自检"
        ),
    )
