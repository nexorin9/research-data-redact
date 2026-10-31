"""构造最小 DICOM 测试样例（显式 / 隐式 VR 小端）。

样例是**人工构造的边界样例**，只作单测夹具 —— 不是语料来源，也不是真实院内
数据。构造器与被测模块的解析器是同一套 DICOM 规则（标准字典键名匹配 +
VR 长度规则），因此样例一旦与真实设备导出的结构有出入，单测会先报错。

样例里刻意埋了三类东西：

1. **身份 tag**（姓名 / 患者编号 / 出生日期 / 申请医师 / 机构名）—— 该清空；
2. **私有 tag**（奇数组 0009）—— 里面藏着一个住院号，用来验证「私有区一律
   清空」这条硬规则；
3. **必要 tag**（检查号 / 序列号 / 设备信息）—— 该保留且逐字不变。
"""

from __future__ import annotations

import struct

__all__ = [
    "EXTENDED_LENGTH_VRS",
    "build_dicom",
    "build_dicom_implicit",
    "element",
    "sequence",
]

#: 长度字段为 4 字节的 VR。
EXTENDED_LENGTH_VRS = frozenset(
    {"OB", "OW", "OF", "OD", "OL", "OV", "SQ", "UT", "UN", "UC", "UR"}
)

#: 像素烧录旗标：源里写着 YES —— 本轮不做像素涂除，这个 tag 原样保留。
BURNED_IN_ANNOTATION = b"YES"


def _pad(value: bytes, vr: str) -> bytes:
    """取值补齐到偶数长度（UI 用 NULL 补，其余用空格）。"""
    if len(value) % 2 == 0:
        return value
    return value + (b"\x00" if vr == "UI" else b" ")


def element(group: int, number: int, vr: str, value: bytes) -> bytes:
    """构造一个显式 VR 小端元素。"""
    payload = _pad(value, vr)
    tag = struct.pack("<HH", group, number)
    if vr in EXTENDED_LENGTH_VRS:
        return tag + vr.encode("ascii") + b"\x00\x00" + struct.pack("<I", len(payload)) + payload
    return tag + vr.encode("ascii") + struct.pack("<H", len(payload)) + payload


def sequence(group: int, number: int, items: list[bytes]) -> bytes:
    """构造一个显式 VR 小端序列（每个条目用显式长度）。"""
    body = b"".join(
        struct.pack("<HHI", 0xFFFE, 0xE000, len(item)) + item for item in items
    )
    return (
        struct.pack("<HH", group, number)
        + b"SQ"
        + b"\x00\x00"
        + struct.pack("<I", len(body))
        + body
    )


def _meta(transfer_syntax: str) -> bytes:
    """文件元信息组（组 0002，永远显式 VR 小端）。"""
    body = b"".join(
        [
            element(0x0002, 0x0001, "OB", b"\x00\x01"),
            element(0x0002, 0x0002, "UI", b"1.2.840.10008.5.1.4.1.1.2"),
            element(0x0002, 0x0003, "UI", b"1.2.826.0.1.3680043.8.498.1"),
            element(0x0002, 0x0010, "UI", transfer_syntax.encode("ascii")),
            element(0x0002, 0x0012, "UI", b"1.2.826.0.1.3680043.8.498.2"),
        ]
    )
    return element(0x0002, 0x0000, "UL", struct.pack("<I", len(body))) + body


def build_dicom(
    dataset: list[bytes],
    transfer_syntax: str = "1.2.840.10008.1.2.1",
    preamble: bool = True,
) -> bytes:
    """拼一份显式 VR 小端的 DICOM 文件。

    :param dataset: 数据集元素（用 :func:`element` / :func:`sequence` 构造）。
    :param transfer_syntax: 传输语法 UID。
    :param preamble: 是否带 128 字节前导 + ``DICM``。
    """
    head = b"\x00" * 128 + b"DICM" if preamble else b""
    return head + _meta(transfer_syntax) + b"".join(dataset)


def build_dicom_implicit(
    dataset: list[tuple[int, int, bytes]],
    transfer_syntax: str = "1.2.840.10008.1.2",
) -> bytes:
    """拼一份隐式 VR 小端的 DICOM 文件（元素只给 tag 与取值）。

    隐式 VR 下 VR 由标准字典推断 —— 被测模块的字典里没有的 tag 按 ``UN``
    处理，长度字段一律 4 字节。
    """
    body = b"".join(
        struct.pack("<HHI", group, number, len(_pad(value, "UN"))) + _pad(value, "UN")
        for group, number, value in dataset
    )
    return b"\x00" * 128 + b"DICM" + _meta(transfer_syntax) + body
