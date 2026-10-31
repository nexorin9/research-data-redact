"""DICOM tag 级去标识的配置口径（策略表 ``dicom`` 段）。

对应源产品 ``presidio-image-redactor`` 图像涂除主路径的**另一半**：源产品走
OCR + bbox 像素填充，本轮只做 tag 级 —— 身份 tag 清空、私有 tag 一律清空、
必要 tag 保留。三类处置口径全部从策略表读，各院按自己的留存要求改 YAML 即可，
不必改代码。

三类处置（对应策略表 ``dicom`` 段）：

============  ==========================================================
处置          含义
============  ==========================================================
``keep``      值逐字保留（tag 与值都不动）—— 必要 tag：检查号 / 序列号 /
              设备信息
``clear``     值置空（tag 保留、值变零长度）—— 身份 tag：姓名 / 患者编号 /
              出生日期 / 医师 / 机构 …
``replace``   值替换为指定取值（tag 保留）—— 例如把患者编号换成一致代号
============  ==========================================================

**私有 tag 一律清空**：厂商私有区（奇数组）里的内容不可预知 —— 本院的 RIS
导出可能把住院号写进私有 tag，不清掉就等于「按标准清了、实际上没清」。

**默认方向**：标准 tag 默认 ``keep``（不在处置表里的不动）。把
``default_action`` 改成 ``clear`` 即切成 **PS3.15 白名单口径**：不在保留表里的
标准 tag 一律清空 —— 更保守，代价是研究可用性下降。

**纪律**：配置非法即报错（未知道具键 / 同名 tag 出现在两类处置里 / tag 名不像
DICOM 关键字 / 默认动作取值非法），不静默取默认值。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

__all__ = [
    "DEFAULT_ACTIONS",
    "DicomConfig",
    "DicomConfigError",
]

#: 允许的默认动作取值。
DEFAULT_ACTIONS: tuple[str, ...] = ("keep", "clear")

#: ``dicom`` 段允许出现的键。
_DICOM_KEYS: tuple[str, ...] = (
    "enabled",
    "keep_tags",
    "clear_tags",
    "replace_tags",
    "clear_private_tags",
    "default_action",
    "mark_identity_removed",
    "deidentification_method",
)

#: DICOM 关键字的形状：首字母大写、其余字母数字。
_KEYWORD_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]*$")

#: 去标识方法名的长度上限（LO 值域 64 字符）。
_METHOD_MAX_LENGTH = 64


class DicomConfigError(ValueError):
    """DICOM 处置段配置非法（未知道具键 / 处置冲突 / tag 名不合法）。"""


@dataclass(frozen=True)
class DicomConfig:
    """DICOM tag 级去标识的处置口径。

    :param enabled: 是否启用 DICOM 处理。关掉后 DICOM 材料**原样透传**
        （并在清单里留痕「未处理」），不静默假装脱过。
    :param keep_tags: 保留（值逐字不动）的 tag 关键字。
    :param clear_tags: 清空（值置零长度）的 tag 关键字。
    :param replace_tags: 替换（值换成给定取值）的 tag 关键字 → 取值。
    :param clear_private_tags: 是否清空全部私有 tag（奇数组）。默认清空。
    :param default_action: 未列入处置表的标准 tag 的默认动作
        （``keep`` 保留 / ``clear`` 清空）。
    :param mark_identity_removed: 是否写入 ``PatientIdentityRemoved`` 与
        ``DeidentificationMethod`` 两个去标识标记 tag（DICOM 标准做法）。
    :param deidentification_method: 去标识方法名（写进 ``(0012,0063)``）。
    """

    enabled: bool = True
    keep_tags: tuple[str, ...] = ()
    clear_tags: tuple[str, ...] = ()
    replace_tags: Mapping[str, str] = field(default_factory=dict)
    clear_private_tags: bool = True
    default_action: str = "keep"
    mark_identity_removed: bool = True
    deidentification_method: str = "ResearchRedact tag-level de-identification"

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "DicomConfig":
        """从策略表 ``dicom`` 段装配处置口径。

        :param raw: 段内容（映射）。
        :param source: 来源路径（写进报错信息，让人知道该改哪个文件）。
        :raises DicomConfigError: 段结构错 / 未知道具键 / 处置冲突 / tag 名非法。
        """
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise DicomConfigError(f"策略表 dicom 段必须是映射：{source}")
        unknown = sorted(set(raw) - set(_DICOM_KEYS))
        if unknown:
            raise DicomConfigError(
                f"策略表 dicom 段含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_DICOM_KEYS)}）：{source}"
            )

        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise DicomConfigError(
                f"策略表 dicom.enabled 必须是布尔：{enabled!r}：{source}"
            )

        keep_tags = _tag_list(raw.get("keep_tags", ()), "dicom.keep_tags", source)
        clear_tags = _tag_list(raw.get("clear_tags", ()), "dicom.clear_tags", source)

        replace_raw = raw.get("replace_tags", {}) or {}
        if not isinstance(replace_raw, Mapping):
            raise DicomConfigError(f"策略表 dicom.replace_tags 必须是映射：{source}")
        replace_tags: dict[str, str] = {}
        for keyword, value in replace_raw.items():
            name = str(keyword).strip()
            _check_keyword(name, f"dicom.replace_tags.{keyword}", source)
            if not isinstance(value, str):
                raise DicomConfigError(
                    f"策略表 dicom.replace_tags.{name} 的替换取值必须是字符串："
                    f"{value!r}：{source}"
                )
            replace_tags[name] = value

        # 同一个 tag 不能既保留又清空：写了就报错，不静默按某一边执行 ——
        # 「以为清了、实际留着」与「以为留着、实际清了」都是事故。
        clashes: list[str] = []
        for left, right in (
            (keep_tags, clear_tags),
            (keep_tags, tuple(replace_tags)),
            (clear_tags, tuple(replace_tags)),
        ):
            for name in left:
                if name in right:
                    clashes.append(name)
        if clashes:
            raise DicomConfigError(
                f"策略表 dicom 段同一 tag 出现在多类处置里：{'、'.join(sorted(set(clashes)))}"
                f"：{source} —— 同一 tag 不得既是保留项又是清空项"
            )

        clear_private = raw.get("clear_private_tags", True)
        if not isinstance(clear_private, bool):
            raise DicomConfigError(
                f"策略表 dicom.clear_private_tags 必须是布尔：{clear_private!r}：{source}"
            )

        default_action = str(raw.get("default_action", "keep")).strip()
        if default_action not in DEFAULT_ACTIONS:
            raise DicomConfigError(
                f"策略表 dicom.default_action 取值非法：{default_action!r}"
                f"（可用：{'、'.join(DEFAULT_ACTIONS)}）：{source}"
            )

        mark = raw.get("mark_identity_removed", True)
        if not isinstance(mark, bool):
            raise DicomConfigError(
                f"策略表 dicom.mark_identity_removed 必须是布尔：{mark!r}：{source}"
            )

        method = str(
            raw.get("deidentification_method", "ResearchRedact tag-level de-identification")
        ).strip()
        if not method:
            raise DicomConfigError(f"策略表 dicom.deidentification_method 不得为空：{source}")
        if len(method) > _METHOD_MAX_LENGTH:
            raise DicomConfigError(
                f"策略表 dicom.deidentification_method 超长（{len(method)} > "
                f"{_METHOD_MAX_LENGTH} 字符，DICOM LO 值域上限）：{source}"
            )

        return cls(
            enabled=enabled,
            keep_tags=keep_tags,
            clear_tags=clear_tags,
            replace_tags=replace_tags,
            clear_private_tags=clear_private,
            default_action=default_action,
            mark_identity_removed=mark,
            deidentification_method=method,
        )


def _tag_list(raw: Any, name: str, source: str) -> tuple[str, ...]:
    """取一个 tag 关键字列表，逐项校验形状。"""
    if not isinstance(raw, (list, tuple)):
        raise DicomConfigError(f"策略表 {name} 必须是列表：{source}")
    names: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise DicomConfigError(f"策略表 {name} 含非字符串：{item!r}：{source}")
        keyword = item.strip()
        _check_keyword(keyword, name, source)
        names.append(keyword)
    return tuple(dict.fromkeys(names))


def _check_keyword(keyword: str, name: str, source: str) -> None:
    """tag 关键字必须像 DICOM 关键字（``PatientName``），不是随手写的别名。"""
    if not _KEYWORD_PATTERN.match(keyword):
        raise DicomConfigError(
            f"策略表 {name} 含非法 tag 名：{keyword!r}：{source}"
            " —— 须写标准字典关键字（如 PatientName / PatientID）"
        )
