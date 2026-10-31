"""处置动作（operator）框架：实体类别 → 这一段正文怎么改写。

源产品的处置形态在 ``presidio_anonymizer/operators/`` 下（``replace`` /
``redact`` / ``hash`` / ``encrypt`` …），由 ``AnonymizerEngine.anonymize``
（:29-113）按实体类别取用，并通过 ``add_anonymizer``（:115-122）挂载新动作。
本轮把这一段搬进医院语境，三处刻意不同：

1. **动作清单收敛为四种确定性动作** —— ``replace``（替换为固定占位符）、
   ``redact``（整段清空）、``keep``（保留原文）、``hmac_pseudonym``（一致代号）。
   ``hash`` / ``encrypt`` 这类「看着更安全、实际无法核对也无法还原」的动作
   不进本轮：科研交付要求的是**可交差、可复现、可受控还原**，不是看起来
   不可逆。一致代号（``hmac_pseudonym``）是本轮**新建**的第四种动作 ——
   源产品的 hash / encrypt 逐文档独立计算，同一患者跨材料会拿到不同串。
2. **扩展点保留，成对挂载** —— :meth:`OperatorRegistry.register` 就是
   ``add_anonymizer`` 的对应物；还原动作（``hmac_restore``）挂在源产品
   ``deanonymize_engine.py::add_deanonymizer`` 的对应位置上。一致代号
   （``hmac_pseudonym``）与其还原侧（``hmac_restore``）**成对登记、共用同一份
   对照索引** —— 脱敏侧写进去的槽位，还原侧才取得到；两侧不配对就会得到
   「脱得出去、还原不回来」的产品。
3. **动作与实体类别解耦** —— 「哪个类别用什么动作」由策略表
   （``policy/research.yaml`` → :mod:`research_redact.policy.table`）决定，
   本模块只管「动作怎么执行」。一致代号档（``profiles.pseudonym``）就是把
   两个身份绑定类切到 ``hmac_pseudonym`` 的那份档位。

**不变量**：动作实现不持有命中原文；占位符等替换文本由策略表给出，
动作只负责把原文改写成它。
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..config import PSEUDONYM_HMAC_KEY_ENV, PSEUDONYM_KEY_ID_ENV
from .mapping import (
    OccurrenceMappingIndex,
    PseudonymMappingIndex,
    TokenNotFoundError,
)
from .pseudonym import (
    PseudonymConfig,
    PseudonymIdentityError,
    Pseudonymizer,
    load_pseudonym_config,
)

__all__ = [
    "ActionSpec",
    "IMPLEMENTED_OPERATOR_NAMES",
    "KeepOperator",
    "KNOWN_OPERATOR_NAMES",
    "Operator",
    "OperatorContext",
    "OperatorError",
    "OperatorNotFoundError",
    "OperatorRegistry",
    "OperatorUnavailableError",
    "PseudonymOperator",
    "RESERVED_OPERATOR_NAMES",
    "RedactOperator",
    "ReplaceOperator",
    "RestoreOperator",
    "RestoreTextResult",
    "RestoreTokenNotFoundError",
    "default_operator_registry",
]


class OperatorError(RuntimeError):
    """处置动作执行出错（缺占位符、动作名拼错、重复登记 …）。"""


class OperatorNotFoundError(OperatorError):
    """动作名未登记 —— 拼错了，或策略表引用了一个不存在的动作。"""


class OperatorUnavailableError(OperatorError):
    """动作名是预留挂载位，但实现尚未落地。"""


#: 本轮**已落地**的动作名（可执行）。
#:   ``replace`` / ``redact`` / ``keep`` —— 三种确定性动作（task 6）
#:   ``hmac_pseudonym`` —— 一致代号（task 24，HMAC-SHA256 over 患者主索引主键）
#:   ``hmac_restore`` —— 一致代号的还原侧（task 25，按代号反查对照索引回填原文）
IMPLEMENTED_OPERATOR_NAMES: tuple[str, ...] = (
    "replace",
    "redact",
    "keep",
    "hmac_pseudonym",
    "hmac_restore",
)

#: 预留挂载位：动作名先登记，实现随后落地 ——
#: 名字先登记，是为了让策略表**现在**就能声明它（声明 = 挂载位已就位），
#: 而执行时若实现未落地则明确报错 —— 声明了就必须能用。
#: 本轮已无预留动作：一致代号与其还原侧都已落地（task 24 / task 25）。
RESERVED_OPERATOR_NAMES: dict[str, str] = {}

#: 已知动作名词表：本轮已实现的四种 + 预留挂载位。
#: 策略表引用词表外的动作名即报错（不静默取默认动作）。
KNOWN_OPERATOR_NAMES: tuple[str, ...] = (
    *IMPLEMENTED_OPERATOR_NAMES,
    *RESERVED_OPERATOR_NAMES,
)


@dataclass(frozen=True)
class OperatorContext:
    """动作执行上下文。

    :param label: 实体类别（如 ``PATIENT_NAME``）。
    :param placeholder: ``replace`` 动作写入的占位符（由策略表给出）。
    :param entity_id: 患者主索引主键 —— 一致代号按它取值。
    :param material_id: 材料 ID —— 一致代号据此把对照登记到本材料的槽位，
        还原侧据此取回（同名材料之间不串槽）。
    :param occurrence: 该代号在本文本中的第几次出现（从 0 起）—— 还原侧按它
        取回对应的那一段原文（同一代号在正文里可能对应多段不同原文）。
    :param extra: 附加上下文。
    """

    label: str = ""
    placeholder: str = ""
    entity_id: str = ""
    material_id: str = ""
    occurrence: int = 0
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionSpec:
    """一个实体类别的处置动作。

    :param action: 动作名（``replace`` / ``redact`` / ``keep`` …）。
    :param placeholder: ``replace`` 时写入的占位符；其余动作为空。
    """

    action: str
    placeholder: str = ""


class Operator:
    """处置动作基类。

    子类实现 :meth:`apply`，把命中原文改写成产物文本。
    """

    #: 动作名（策略表按这个名字引用）。
    name = ""

    def apply(self, source: str, context: OperatorContext) -> str:
        """把命中原文改写成产物文本。

        :param source: 命中原文（只在内存中过一遍，不落盘、不进清单）。
        :param context: 执行上下文。
        """
        raise NotImplementedError

    def describe(self) -> str:
        """一句话说明这个动作做什么（写进 CLI 摘要与运维文档）。"""
        return self.name


class ReplaceOperator(Operator):
    """替换为固定占位符（如 ``<患者姓名>``）。

    占位符由策略表按实体类别给出 —— 同一动作服务多个类别，占位符不同。
    """

    name = "replace"

    def apply(self, source: str, context: OperatorContext) -> str:
        if not context.placeholder:
            raise OperatorError(
                "replace 动作缺少占位符：策略表未给该实体类别声明 placeholder"
            )
        return context.placeholder

    def describe(self) -> str:
        return "replace（替换为占位符）"


class RedactOperator(Operator):
    """整段清空（不留任何痕迹）。"""

    name = "redact"

    def apply(self, source: str, context: OperatorContext) -> str:
        return ""

    def describe(self) -> str:
        return "redact（整段清空）"


class KeepOperator(Operator):
    """保留原文（明确判定为不需要脱的类别）。"""

    name = "keep"

    def apply(self, source: str, context: OperatorContext) -> str:
        return source

    def describe(self) -> str:
        return "keep（保留原文）"


class PseudonymOperator(Operator):
    """一致代号：按患者主索引主键算出**跨材料恒等**的代号。

    与 ``replace`` 的根本差别：``replace`` 写的是固定占位符（同一批里每一处
    都一样，看不出谁是谁）；一致代号是**每一位患者一个稳定代号** —— 同一
    患者在姓名处、住院号处、主键处都替换成同一个串，不同患者拿到不同串。
    交付给科研数据平台后，跨材料对得上人，又对不上人是谁。

    两条硬纪律：

    - **缺密钥即报错** —— 不降级为无密钥哈希（无密钥哈希等于密钥公开）；
    - **身份键绑不上即报错** —— 不知道这处属于谁，就不给代号；既不按姓名
      硬匹配兜底，也不退回占位符充数（那就不是一致代号了）。

    密钥与密钥版本号从环境变量读（``$PSEUDONYM_HMAC_KEY`` /
    ``$PSEUDONYM_KEY_ID``），密钥**不写进任何交付体**。

    :param key: 显式给定密钥；缺省在执行时从环境变量读。
    :param key_id: 显式给定密钥版本号；缺省在执行时从环境变量读。
    :param config: 一致代号口径；缺省按策略表 ``pseudonymization`` 段读。
    :param mapping_index: 对照索引；给了就把「代号 ↔ 原文」登记进去 ——
        **还原侧靠它取回原文**，不给则这份代号还原不回来（登记与还原成对）。
    """

    name = "hmac_pseudonym"

    def __init__(
        self,
        *,
        key: str | None = None,
        key_id: str | None = None,
        config: PseudonymConfig | None = None,
        mapping_index: OccurrenceMappingIndex | None = None,
    ) -> None:
        self._key = key
        self._key_id = key_id
        self._config = config
        self._mapping_index = mapping_index

    def apply(self, source: str, context: OperatorContext) -> str:
        """把这处命中替换成该患者的一致代号。

        :param source: 命中原文（只在内存中过一遍，不落盘、不进清单）。
        :param context: 执行上下文；``entity_id`` 必须是患者主索引主键。
        :raises PseudonymIdentityError: 这处命中没有绑定患者主索引主键。
        :raises PseudonymKeyError: 密钥未配置。
        """
        identity = (context.entity_id or "").strip()
        if not identity:
            raise PseudonymIdentityError(
                f"实体类别 {context.label or '未标注'} 的这处命中没有绑定"
                "患者主索引主键，无法生成一致代号"
                " —— 不得按姓名硬匹配兜底，也不得退回占位符充数"
            )
        token = self._resolve().pseudonymize(identity)
        if self._mapping_index is not None:
            # 登记顺序即正文顺序（替换计划按起点排序）—— 还原侧按同样次序取回。
            self._mapping_index.record_occurrence(
                context.material_id, token, source
            )
        return token

    def _resolve(self) -> Pseudonymizer:
        """按需装配生成器（密钥在**执行时**才取，避免未启用时也要配密钥）。"""
        key = self._key if self._key is not None else os.environ.get(
            PSEUDONYM_HMAC_KEY_ENV, ""
        )
        key_id = self._key_id if self._key_id is not None else os.environ.get(
            PSEUDONYM_KEY_ID_ENV, ""
        )
        config = self._config if self._config is not None else load_pseudonym_config()
        return Pseudonymizer(key, key_id=key_id, config=config)

    def describe(self) -> str:
        return "hmac_pseudonym（一致代号：HMAC-SHA256 over 患者主索引主键）"


class RestoreTokenNotFoundError(OperatorError, TokenNotFoundError):
    """还原动作查不到原文（对照索引缺项）。

    **不静默跳过** —— 跳过会产出一份「看着像原文、其实少了一段」的还原件，
    交差的人会拿它当原文对账。宁可整批停下等人补齐索引。
    """


@dataclass(frozen=True)
class RestoreTextResult:
    """一次正文级还原的结果。

    :param text: 还原后的正文。
    :param replaced: 回填的代号处数（0 = 没有可还原的代号）。
    :param reason: 一句人话说明（**不含原文**）。
    """

    text: str
    replaced: int = 0
    reason: str = ""


class RestoreOperator(Operator):
    """一致代号的**还原侧**：按代号反查对照索引，回填原文。

    与脱敏侧 ``hmac_pseudonym`` 成对挂载（共用同一份对照索引）——
    脱敏时写进去的槽位，还原时才取得到。两侧不配对，产品就变成「脱得出去、
    还原不回来」。

    **源产品的对应物**：``deanonymize_engine.py::DeanonymizeEngine.deanonymize``
    （:813-830）用 operator 留下的密文反解原文；``add_deanonymizer``
    （:837-844）是挂载还原动作的扩展点。本模块保留这两点，改的是「谁来批」
    —— 授权与回执在 :mod:`research_redact.restore.service`（task 13）那一层，
    本模块只管「怎么把代号换回原文」。

    三条纪律：

    1. **对照索引不可达 = 报错中止** —— 查都没查成，不能当成「没有可还原的
       代号」悄悄返回原文；
    2. **按出现次序取回** —— 同一代号在正文里可能对应多段不同原文（姓名一处、
       住院号一处），按「第几次出现」取回才对得上位置；
    3. **已还原的文本不二次还原** —— 把还原件再送一次还原是幂等的空操作，
       不是把原文又换一遍。

    :param index: 对照索引；缺省不可用（执行时报错，不静默跳过）。
    """

    name = "hmac_restore"

    def __init__(self, *, index: OccurrenceMappingIndex | None = None) -> None:
        self._index = index
        self._restored: dict[str, str] = {}

    # ------------------------------------------------------------------ 动作

    def apply(self, source: str, context: OperatorContext) -> str:
        """把一处代号换回原文。

        :param source: 代号文本。
        :param context: 执行上下文；``material_id`` 与 ``occurrence`` 决定取回
            哪一段原文。
        :raises RestoreTokenNotFoundError: 对照索引里查不到这一处代号。
        :raises MappingIndexUnavailableError: 对照索引不可达（由索引抛出）。
        """
        index = self._require_index()
        original = index.lookup_occurrence(
            context.material_id, source, context.occurrence
        )
        if original is None:
            raise RestoreTokenNotFoundError(
                f"材料 {context.material_id or '未标注'} 的第 "
                f"{context.occurrence + 1} 处代号在对照索引里查不到原文"
                " —— 不得静默跳过，请先补齐对照索引再还原"
            )
        return original

    def restore_text(self, text: str, material_id: str = "") -> RestoreTextResult:
        """把一份脱敏正文里的代号逐处换回原文。

        按**出现顺序**逐处替换（位置替换，长度变化不影响其它位置）。

        :param text: 脱敏后的正文。
        :param material_id: 材料 ID —— 取回的是这份材料自己的槽位。
        :raises RestoreTokenNotFoundError: 对照索引缺项。
        :raises MappingIndexUnavailableError: 对照索引不可达。
        """
        digest = _digest(text)
        if self._restored.get(str(material_id or "")) == digest:
            return RestoreTextResult(
                text=text,
                replaced=0,
                reason="该材料已还原（幂等保护：不再二次还原）",
            )
        index = self._require_index()
        occurrences = index.find_occurrences(text, material_id)
        if not occurrences:
            return RestoreTextResult(
                text=text,
                replaced=0,
                reason="正文内无待还原代号（未使用一致代号档，或已还原）",
            )
        pieces: list[str] = []
        cursor = 0
        for occurrence in occurrences:
            original = self.apply(
                occurrence.token,
                OperatorContext(
                    label="PSEUDONYM",
                    material_id=material_id,
                    occurrence=occurrence.occurrence,
                ),
            )
            pieces.append(text[cursor : occurrence.start])
            pieces.append(original)
            cursor = occurrence.end
        pieces.append(text[cursor:])
        restored = "".join(pieces)
        self._restored[str(material_id or "")] = _digest(restored)
        return RestoreTextResult(
            text=restored,
            replaced=len(occurrences),
            reason=f"已还原 {len(occurrences)} 处代号",
        )

    def describe(self) -> str:
        return "hmac_restore（一致代号还原：按代号反查对照索引回填原文）"

    # ------------------------------------------------------------------ 内部

    def _require_index(self) -> OccurrenceMappingIndex:
        """取对照索引；未装配即报错（不静默跳过）。"""
        if self._index is None:
            raise OperatorError(
                "还原动作未装配对照索引：无法把代号换回原文"
                " —— 不得静默跳过（还原件会缺段）"
            )
        return self._index


def _digest(text: str) -> str:
    """正文摘要（用于「已还原」判定；不落盘、不进清单）。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OperatorRegistry:
    """动作注册表：动作名 → 动作实现。

    对应源产品 ``AnonymizerEngine.add_anonymizer``（:115-122）的挂载点。

    :param operators: 初始动作清单。
    :param mapping_index: 对照索引（一致代号与其还原侧共用）。主路径按它清空
        「本材料」的旧槽位 —— 同一份材料重新脱敏时，旧原文不得留在槽位里。
    """

    def __init__(
        self,
        operators: Iterable[Operator] | None = None,
        *,
        mapping_index: OccurrenceMappingIndex | None = None,
    ) -> None:
        self._operators: dict[str, Operator] = {}
        self.mapping_index = mapping_index
        for operator in operators or ():
            self.register(operator)

    def register(self, operator: Operator) -> None:
        """登记一个动作；同名重复登记即报错（不静默覆盖）。"""
        if not operator.name:
            raise OperatorError("动作必须声明 name")
        if operator.name in self._operators:
            raise OperatorError(f"动作名重复登记：{operator.name}")
        self._operators[operator.name] = operator

    def get(self, name: str) -> Operator:
        """取动作实现。

        :raises OperatorNotFoundError: 动作名未登记（拼错或不存在的动作）。
        :raises OperatorUnavailableError: 动作名是预留挂载位，实现尚未落地 ——
            此时**不得**退回「保留原文」，那等于把声明过的脱敏悄悄放过。
        """
        operator = self._operators.get(name)
        if operator is not None:
            return operator
        if name in RESERVED_OPERATOR_NAMES:
            raise OperatorUnavailableError(
                f"处置动作「{name}」尚未落地：{RESERVED_OPERATOR_NAMES[name]}"
                " —— 声明了就必须能用，不能静默降级为保留原文"
            )
        raise OperatorNotFoundError(f"未登记的处置动作：{name}")

    def has(self, name: str) -> bool:
        """动作是否已落地（可执行）。"""
        return name in self._operators

    def names(self) -> tuple[str, ...]:
        """已登记的动作名（按登记顺序）。"""
        return tuple(self._operators)

    def describe(self) -> dict[str, str]:
        """动作名 → 一句话说明（写进运维摘要）。"""
        return {name: operator.describe() for name, operator in self._operators.items()}


def default_operator_registry(
    *, mapping_index: OccurrenceMappingIndex | None = None
) -> OperatorRegistry:
    """本轮内置的动作注册表：三种确定性动作 + 一致代号 + 一致代号的还原侧。

    一致代号（``hmac_pseudonym``）与还原侧（``hmac_restore``）**成对登记、
    共用同一份对照索引** —— 脱敏侧登记的槽位，还原侧才取得到。

    一致代号的**密钥在执行时才取** —— 没启用这个动作的批次不会因为「没配
    密钥」而跑不起来；一旦策略表真的声明了它，缺密钥就报错中止，不降级。

    :param mapping_index: 对照索引；缺省新建一份进程内索引（脱敏与还原在
        同一进程内完成时够用；加密持久化版本由 task 26 接管）。
    """
    index = mapping_index if mapping_index is not None else PseudonymMappingIndex()
    return OperatorRegistry(
        [
            ReplaceOperator(),
            RedactOperator(),
            KeepOperator(),
            PseudonymOperator(mapping_index=index),
            RestoreOperator(index=index),
        ],
        mapping_index=index,
    )
