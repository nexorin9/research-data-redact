"""对照索引（代号 ↔ 原文）：一致代号可逆性的底座。

**为什么不能用「代号 → 原文」一张单值表**：一致代号建在**患者身份**上 ——
同一位患者在正文里的不同位置会以不同形态出现（姓名一处、住院号一处、
主索引主键一处），三处拿到的是**同一个代号**，对应的却是**三段不同的原文**。
单值表只能留住一段，另外两段会被后来的写入覆盖 —— 还原出来的那一份必然
有一处张冠李戴，而「还原件看着像原文、其实有一处串号」比不还原危险得多
（交差的人会拿它当原文对账）。

所以本索引按**「材料 + 代号 + 第几次出现」**分槽：

.. code-block:: text

    还原件 = 正文里第 k 次出现的代号 → 索引里 (材料, 代号, k) 槽位的原文

脱敏时按正文顺序登记（还原计划按起点排序，登记顺序即出现顺序），还原时按
出现顺序取回 —— 两边的次序天然对齐。

**三条纪律**：

1. **不可达 ≠ 缺项** —— 索引查不到（不可达 / 缺项）一律报错中止，
   **绝不静默跳过**：跳过会产出一份「看着像原文、其实少了一段」的还原件。
2. **登记顺序即出现顺序** —— 登记必须按正文顺序发生；重新脱敏同一份材料时
   先清空该材料的槽位（:meth:`PseudonymMappingIndex.reset_material`），
   否则上一轮的旧原文会留在槽位里，还原时取到过期的那一份。
3. **索引与交付物分离** —— 本模块只管「怎么记、怎么取」；**加密落盘与访问
   留痕**由 ``policy/index_store.py``（task 26）接管，业务层不感知差异。

**不变量**：本模块不碰正文、不落原文；槽位里的原文只在本进程内存在。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .pseudonym import PseudonymConfig, load_pseudonym_config

__all__ = [
    "MappingIndexError",
    "MappingIndexUnavailableError",
    "OccurrenceMappingIndex",
    "PseudonymMappingIndex",
    "TokenNotFoundError",
    "TokenOccurrence",
    "token_pattern",
]


class MappingIndexError(RuntimeError):
    """对照索引相关错误基类。"""


class MappingIndexUnavailableError(MappingIndexError):
    """对照索引**不可达**（索引文件缺失 / 解密失败 / 存储故障）。

    不可达与缺项是两回事：不可达是「根本没查成」，缺项是「查了，没有这一
    条」。两种都可能导致还原件残缺，所以两种都必须报错中止。
    """


class TokenNotFoundError(MappingIndexError):
    """对照索引**缺项**：这个代号查不到原文。"""


@dataclass(frozen=True)
class TokenOccurrence:
    """正文里的一处代号。

    :param token: 代号文本。
    :param start: 在正文中的起始位置。
    :param end: 在正文中的结束位置。
    :param occurrence: 该代号在本文本中的第几次出现（从 0 起，按出现顺序）。
    """

    token: str
    start: int
    end: int
    occurrence: int


@runtime_checkable
class OccurrenceMappingIndex(Protocol):
    """按「材料 + 代号 + 第几次出现」记的对照索引协议。

    业务层只认这三个方法；具体实现可换（进程内表 / 加密文件 / 数据库）。
    """

    def record_occurrence(self, material_id: str, token: str, original: str) -> int:
        """登记一条对照，返回它是该代号在本材料中的第几次出现。"""

    def lookup_occurrence(
        self, material_id: str, token: str, occurrence: int
    ) -> str | None:
        """取某一处代号的原文；查不到返回 None（不得返回空串冒充命中）。"""

    def find_occurrences(self, text: str, material_id: str) -> tuple[TokenOccurrence, ...]:
        """在正文里找出全部代号及其出现次序（按出现顺序）。"""


def token_pattern(config: PseudonymConfig | None = None) -> re.Pattern[str]:
    """一致代号的形状正则（按口径生成）。

    与 :func:`research_redact.audit.residual.pseudonym_pattern` 同一口径
    （前缀 + 固定位数十六进制），但这里多了**边界守卫** —— 代号前后若紧邻
    字母数字或连字符，说明它只是更长串里的一段，不能当成一处代号。
    """
    active = config if config is not None else load_pseudonym_config()
    return re.compile(
        rf"(?<![0-9A-Za-z-]){re.escape(active.prefix)}"
        rf"[0-9a-f]{{{active.digest_length}}}(?![0-9A-Za-z-])"
    )


class PseudonymMappingIndex:
    """一致代号的对照索引（代号 ↔ 原文），按出现次序分槽。

    :param config: 一致代号口径；缺省按策略表 ``pseudonymization`` 段读
        （只在需要扫描正文形状时才装载，未启用一致代号的批次不必配）。
    """

    def __init__(self, config: PseudonymConfig | None = None) -> None:
        self._config = config
        self._entries: dict[tuple[str, str], list[str]] = {}

    # ------------------------------------------------------------------ 属性

    @property
    def config(self) -> PseudonymConfig:
        """一致代号口径（按需装载）。"""
        if self._config is None:
            self._config = load_pseudonym_config()
        return self._config

    def __len__(self) -> int:
        """已登记的对照条数。"""
        return sum(len(bucket) for bucket in self._entries.values())

    # ------------------------------------------------------------------ 登记

    def record_occurrence(self, material_id: str, token: str, original: str) -> int:
        """登记一条对照（代号 → 原文），返回它是该代号在本材料中的第几次出现。

        登记顺序即出现顺序 —— 调用方必须按正文顺序登记（脱敏计划按起点排序，
        天然满足）。
        """
        key = (str(material_id or ""), str(token))
        bucket = self._entries.setdefault(key, [])
        bucket.append(str(original))
        return len(bucket) - 1

    def reset_material(self, material_id: str) -> None:
        """清空某份材料的全部槽位。

        重新脱敏同一份材料（补齐材料后重投）时必须先清：否则上一轮的旧原文
        留在槽位里，还原时按次序取到的是过期的那一份。
        """
        target = str(material_id or "")
        for key in [key for key in self._entries if key[0] == target]:
            del self._entries[key]

    # ------------------------------------------------------------------ 查询

    def lookup_occurrence(
        self, material_id: str, token: str, occurrence: int
    ) -> str | None:
        """取某一处代号的原文；查不到返回 None。"""
        bucket = self._entries.get((str(material_id or ""), str(token)))
        if not bucket or occurrence < 0 or occurrence >= len(bucket):
            return None
        return bucket[occurrence]

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
