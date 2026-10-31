"""识别器装配：把策略表与形态约束装配成识别器注册表。

对应源产品 ``analyzer_engine_provider.py`` 的 **YAML 装配形态**（保留）：
一份 YAML 装下识别器清单、逐识别器阈值、全局阈值与白名单，装配结果给分析
引擎用。本轮把它落到项目内自有装配器上（不引 spaCy、不引语言模型）。

为什么单独成模块：装配器被**识别层**（:mod:`research_redact.audit.residual`
的残留自检）与**主路径**（:mod:`research_redact.daemon.pipeline`）共用，
放进主路径里会让审计层反过来 import 主路径，形成环。

本轮已落地的识别器形态：

- **字段标签驱动**（``labeled_field``）：标签 + 分隔符 + 值；
- **正则形态 · 就诊编号**（``visit_no``）：住院号 / 门诊号 / 检查号，形状约束
  由策略表驱动；
- **正则形态 · 联系方式**（``phone_birth``）：手机号 + 出生日期；
- **校验位形态 · 身份证**（``id_card``，task 18）：GB 11643 加权校验位，
  校验不过降为告警档；
- **名单形态 · 患者身份**（``patient_index``，task 17）：以 HIS 患者主索引
  读回的权威名单为准，绑定「这段属于哪位患者」。

识别之后再挂**邻近窗口上下文加分**（``context_boost``）：窗口内出现
「住院号 / 姓名」等上下文词时，低分命中被抬到门槛附近；加分封顶在门槛上，
窗口外的命中一律不动。

**启停与逐项阈值覆盖**（task 22）：策略表 ``recognizers`` 段是**识别器名册** ——
谁启用、谁关闭；``thresholds.per_recognizer`` 是逐识别器的门槛覆盖。装配器
按这两处读，不再在代码里写死清单。被关掉的识别器**根本不注册**，因此一条
命中都不会产出 —— 不是「产出了再过滤掉」。

阈值与白名单取自**策略表**（``policy/research.yaml``）：全局阈值、逐识别器
阈值覆盖、白名单都在同一份文件里换院区。策略表 / 形态约束 / 上下文配置
非法时**报错**，不静默取默认值。
"""

from __future__ import annotations

from ..policy.table import CONTEXT_BOOST_ID, PolicyTable, load_policy_table
from .base import Recognizer
from .context_boost import ContextBooster, load_context_config
from .id_card import IdCardRecognizer, load_id_card_config
from .labeled_field import LabeledFieldRecognizer
from .patient_index import (
    PatientIndexBinding,
    PatientIndexRecognizer,
    load_patient_index_config,
)
from .phone_birth import PhoneBirthRecognizer
from .registry import RecognizerRegistry, RegistryConfig
from .shapes import load_shapes
from .visit_no import VisitNoRecognizer

__all__ = ["build_default_registry"]


def build_default_registry(
    binding: PatientIndexBinding | None = None,
    table: PolicyTable | None = None,
) -> RecognizerRegistry:
    """装配本轮已落地的识别器。

    装配顺序 = 策略表给定的顺序：识别器清单（启停）→ 逐识别器阈值覆盖 →
    全局阈值 → 白名单 → 上下文词表。

    :param binding: 患者主索引权威名单。给了就装上名单形态识别器 —— 名单为空
        或主索引不可达时，该识别器**不产出任何命中**（不降级为按姓名硬匹配），
        由批次状态机把批次置 ``suspended``。不给则不装（默认路径与既有行为
        完全一致）。
    :param table: 已装载的策略表；缺省按 ``$RESEARCH_POLICY_FILE`` 装载。
    """
    active_table = table if table is not None else load_policy_table()
    # 各识别器自己的配置一律从**同一份**策略表读（表格的 source 就是它的路径）：
    # 混着读两份文件，装出来的注册表会有一半配置对不上号 —— 这正是
    # 「以为按本院写法识别了、实际没生效」的那类事故。
    source = active_table.source or None
    shapes = load_shapes(source)
    recognizers: list[Recognizer] = []

    if active_table.recognizer_enabled("labeled_field"):
        recognizers.append(LabeledFieldRecognizer())
    if active_table.recognizer_enabled("visit_no"):
        recognizers.append(VisitNoRecognizer(shapes=shapes.number_shapes))
    if active_table.recognizer_enabled("phone_birth"):
        recognizers.append(
            PhoneBirthRecognizer(
                phone_shapes=shapes.phone_shapes,
                birth_date_shapes=shapes.birth_date_shapes,
            )
        )
    if active_table.recognizer_enabled("id_card"):
        recognizers.append(IdCardRecognizer(config=load_id_card_config(source)))
    if binding is not None and active_table.recognizer_enabled("patient_index"):
        recognizers.append(
            PatientIndexRecognizer(
                binding, config=load_patient_index_config(source)
            )
        )

    booster: ContextBooster | None = None
    if active_table.recognizer_enabled(CONTEXT_BOOST_ID):
        booster = ContextBooster(load_context_config(source))

    return RecognizerRegistry(
        recognizers,
        RegistryConfig(
            global_threshold=active_table.global_threshold,
            per_recognizer_thresholds=dict(active_table.per_recognizer_thresholds),
            allow_list_exact=active_table.allow_list_exact,
            allow_list_regex=active_table.allow_list_regex,
        ),
        booster=booster,
    )
