"""列级策略：一份结构化材料（申请单 JSON / xlsx）按**列**处理。

对应源产品 ``presidio-analyzer/presidio_analyzer/batch_analyzer_engine.py::
BatchAnalyzerEngine.analyze_dict`` 的 ``keys_to_skip`` 机制（**保留**）：
源产品按**键**跳过不识别的列，本项目按**列**跳过 —— 同一份机制，换到医院
语境下的名字。

三类列：

``business``（业务标识与说明列）
    申请单号、伦理批件号、材料 ID、材料类型、材料路径、材料技术内容列。
    **逐字保留**，不识别、不脱敏 —— 交付回执按申请单号与平台台账对账，
    脱掉它等于把这一批变成「谁都对不上」。

``bound``（患者绑定列）
    患者主索引主键。身份锚定走 HIS 主索引读回的权威名单（task 17），
    **不由通用正则改写** —— 正则改出来的号对不上主索引，一致代号
    （task 24）也就无从谈起。

``content``（内容列）
    可能夹带患者身份的自由文本列（备注、摘要、报告摘录）。**按列扫描
    脱敏**，走主路径（识别 → 处置 → 清单）。

**不变量**

1. 业务列与绑定列在脱敏产物里**逐字保留**；
2. 内容列的命中逐条进清单（清单只记位置 / 类别 / 分数 / 解释，不记原文）；
3. 判定只看列名，不看列里的内容 —— 同一列在同一批次里的角色是稳定的，
   否则「这一格脱了、下一格没脱」这种事没法复现。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from ..policy.table import ColumnConfig

__all__ = [
    "ColumnPolicy",
    "ColumnRole",
    "DEFAULT_BOUND_COLUMNS",
    "DEFAULT_BUSINESS_COLUMNS",
]


class ColumnRole(str, enum.Enum):
    """一列在脱敏流程中的角色。"""

    #: 业务标识与说明列 —— 逐字保留。
    BUSINESS = "business"
    #: 患者绑定列 —— 身份锚定走主索引，不由通用正则改写。
    BOUND = "bound"
    #: 内容列 —— 按列扫描脱敏。
    CONTENT = "content"


#: 结构性业务列：任何申请单都有这些列，逐字保留。
#: 「材料技术内容列」列在这里 —— 它描述材料本身（部位、序列、次数），
#: 是交付说明的一部分，不是患者身份数据。
DEFAULT_BUSINESS_COLUMNS: tuple[str, ...] = (
    "application_no",
    "ethics_approval_no",
    "material_id",
    "kind",
    "path",
    "material_content",
)

#: 结构性绑定列：患者主索引主键。
DEFAULT_BOUND_COLUMNS: tuple[str, ...] = ("patient_id",)


@dataclass(frozen=True)
class ColumnPolicy:
    """列角色判定表。

    :param business_columns: 业务标识与说明列（逐字保留）。
    :param bound_columns: 患者绑定列（身份锚定走主索引）。
    :param content_columns: 显式划为内容列的列名；为空表示「未列出的列一律
        按内容列处理」。
    """

    business_columns: tuple[str, ...] = DEFAULT_BUSINESS_COLUMNS
    bound_columns: tuple[str, ...] = DEFAULT_BOUND_COLUMNS
    content_columns: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, config: ColumnConfig | None) -> "ColumnPolicy":
        """由策略表的 ``columns`` 段装配列策略。

        结构性默认列**永远生效**（少脱总比脱错业务标识安全）；策略表在此
        之上追加本院特有的业务列 / 绑定列，并可把某一列显式划为内容列 ——
        医院确实把患者身份粘进了业务列时，把该列写进 ``content_columns``
        即可，不必改代码。
        """
        if config is None:
            return cls()
        content = tuple(config.content_columns)
        business = tuple(
            name
            for name in dict.fromkeys(DEFAULT_BUSINESS_COLUMNS + config.business_columns)
            if name not in content
        )
        bound = tuple(
            name
            for name in dict.fromkeys(DEFAULT_BOUND_COLUMNS + config.bound_columns)
            if name not in content
        )
        return cls(
            business_columns=business,
            bound_columns=bound,
            content_columns=content,
        )

    def classify(self, column: str) -> ColumnRole:
        """判定一列的角色。

        判定顺序：显式内容列 → 业务列 → 绑定列 → 内容列（默认）。

        :param column: 列名（首尾空白会被去掉）。
        """
        name = str(column).strip()
        if name in self.content_columns:
            return ColumnRole.CONTENT
        if name in self.business_columns:
            return ColumnRole.BUSINESS
        if name in self.bound_columns:
            return ColumnRole.BOUND
        return ColumnRole.CONTENT

    def describe(self) -> dict[str, list[str]]:
        """列角色的可读摘要（写进运维摘要与文档）。"""
        return {
            "business_columns": list(self.business_columns),
            "bound_columns": list(self.bound_columns),
            "content_columns": list(self.content_columns),
        }
