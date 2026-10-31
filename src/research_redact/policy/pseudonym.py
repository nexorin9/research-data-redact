"""一致代号：同一患者跨材料代号恒等、不同主键不串号。

**源产品没有这个能力。** 它的 hash / encrypt operator 逐文档独立计算 ——
同一段身份在两份材料里会得到两个不同的串，跨材料对不上，等于没脱。本模块是
本轮新建的「权威身份键 → 稳定代号」映射：

.. code-block:: text

    代号 = 前缀 + HMAC-SHA256(密钥, 方案名 + "|" + 归一化后的患者主索引主键)[:N]

四条纪律：

1. **取值输入只有患者主索引主键** —— 归一化（去空格 / 全半角折叠 / 大小写）
   之后与方案名拼接做 HMAC。**不把命中处的匹配文本拼进去**：同一位患者在
   不同材料里会以不同形态出现（姓名处 / 住院号处 / 主键处），把匹配文本拼
   进去，同一位患者就会在不同材料里拿到不同代号 —— 那就不叫一致代号了。
   拼接的两段因此固定为「方案名 + 归一化后的主键」。
2. **缺密钥即报错，绝不降级为无密钥哈希** —— 无密钥哈希等于把密钥公开
   （拿到姓名的人都能算出这位患者的代号），比脱敏更糟。
3. **代号不含原文片段** —— 姓名、住院号、身份证**不参与计算**，因此不可能
   出现在代号里；代号只是「前缀 + 十六进制摘要」。
4. **身份键绑不上即报错** —— 一致代号必须建立在权威身份上。这处命中绑不到
   患者主索引主键（主索引未读回 / 该患者不在本批清单里）时，中止并报错：
   既不按姓名硬匹配兜底，也不退回占位符（那就不是一致代号了）。

**与交付体的关系**：``$PSEUDONYM_KEY_ID`` 记的密钥版本号随交付体一起发给
科研数据平台（``pseudonymization.key_id``）—— 事后要重算或换密钥时，靠它
说清楚「这一批是用哪一版密钥算出来的」。

**不变量**：本模块不碰正文、不落原文；代号是纯函数（同样的主键 → 同样的
代号），换密钥则整批代号随之改变（这一点由 ``key_id`` 标注在交付体里）。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..config import PSEUDONYM_HMAC_KEY_ENV, PSEUDONYM_KEY_ID_ENV
from ..recognizers.shapes import POLICY_PATH_ENV, default_policy_path

__all__ = [
    "DEFAULT_DIGEST_LENGTH",
    "DEFAULT_PREFIX",
    "DEFAULT_SCHEME",
    "PSEUDONYM_SCHEME",
    "PseudonymConfig",
    "PseudonymConfigError",
    "PseudonymError",
    "PseudonymIdentityError",
    "PseudonymKeyError",
    "Pseudonymizer",
    "load_pseudonym_config",
    "normalize_identity",
]


#: 一致代号方案名（写进交付体的 ``pseudonymization.scheme``）。
#: 科研数据平台按这个名字判断这批数据用的是哪套代号口径。
PSEUDONYM_SCHEME = "hmac-sha256"

#: 出厂口径：方案名 / 代号前缀 / 摘要位数。与 spec.md「核心机制规格 4.2」一致。
DEFAULT_SCHEME = PSEUDONYM_SCHEME
DEFAULT_PREFIX = "P-"
DEFAULT_DIGEST_LENGTH = 16

#: 摘要位数下限 / 上限：太短会撞码（16 位十六进制 = 64 位摘要已足够），
#: 太长则代号不像代号、进了正文也认不出来。
_MIN_DIGEST_LENGTH = 8
_MAX_DIGEST_LENGTH = 64

#: ``pseudonymization`` 段允许的键。出现未知道具键即报错 ——
#: 拼错的键不会被静默忽略，否则「以为配了、实际没配」没人会发现。
_CONFIG_KEYS: tuple[str, ...] = ("scheme", "prefix", "digest_length")

#: 装载缓存：(策略表路径, 修改时间) → 一致代号口径
_CACHE: dict[tuple[str, float], "PseudonymConfig"] = {}


class PseudonymError(RuntimeError):
    """一致代号出错（缺密钥 / 身份键绑不上 / 口径配置非法）。"""


class PseudonymKeyError(PseudonymError):
    """一致代号密钥缺失或为空。

    **不降级为无密钥哈希** —— 那等于把密钥公开，拿到姓名的人就能反推这位
    患者的代号，一致代号随即失去意义。
    """


class PseudonymIdentityError(PseudonymError):
    """这处命中没有绑定患者主索引主键，无法生成一致代号。

    一致代号必须建立在权威身份上：绑不上就是「不知道这是谁」，此时中止，
    不按姓名硬匹配兜底，也不退回占位符充数。
    """


class PseudonymConfigError(ValueError):
    """一致代号口径配置非法（缺段结构错 / 未知道具键 / 数值越界）。"""


# --------------------------------------------------------------------- 口径


@dataclass(frozen=True)
class PseudonymConfig:
    """一致代号的口径参数（全部从策略表读）。

    :param scheme: 方案名，写进交付体 ``pseudonymization.scheme``。
    :param prefix: 代号前缀（``P-``）。
    :param digest_length: 摘要截取位数（十六进制字符数）。
    """

    scheme: str = DEFAULT_SCHEME
    prefix: str = DEFAULT_PREFIX
    digest_length: int = DEFAULT_DIGEST_LENGTH

    @classmethod
    def from_policy(cls, raw: Any, source: str = "") -> "PseudonymConfig":
        """从策略表原始内容装配口径（整份 YAML，不只是 ``pseudonymization`` 段）。

        该段是**可选**的：缺段时用出厂口径（与 spec.md 4.2 一致）。段一旦出现
        就逐项校验 —— 写错的键不会被静默忽略。

        :raises PseudonymConfigError: 段结构错、未知道具键或数值越界。
        """
        if not isinstance(raw, Mapping):
            raise PseudonymConfigError(f"策略表根节点必须是映射：{source}")
        section = raw.get("pseudonymization")
        if section is None:
            return cls()
        if not isinstance(section, Mapping):
            raise PseudonymConfigError(
                f"策略表 pseudonymization 段必须是映射：{source}"
            )
        unknown = sorted(set(section) - set(_CONFIG_KEYS))
        if unknown:
            raise PseudonymConfigError(
                f"策略表 pseudonymization 含未知道具键：{'、'.join(unknown)}"
                f"（可用：{'、'.join(_CONFIG_KEYS)}）"
            )

        scheme = str(section.get("scheme", DEFAULT_SCHEME) or "").strip()
        if not scheme:
            raise PseudonymConfigError(
                f"策略表 pseudonymization.scheme 不得为空：{source}"
            )
        prefix = section.get("prefix", DEFAULT_PREFIX)
        if not isinstance(prefix, str):
            raise PseudonymConfigError(
                f"策略表 pseudonymization.prefix 必须是字符串：{prefix!r}"
            )
        digest_length = section.get("digest_length", DEFAULT_DIGEST_LENGTH)
        if isinstance(digest_length, bool) or not isinstance(digest_length, int):
            raise PseudonymConfigError(
                f"策略表 pseudonymization.digest_length 必须是整数：{digest_length!r}"
            )
        if not _MIN_DIGEST_LENGTH <= digest_length <= _MAX_DIGEST_LENGTH:
            raise PseudonymConfigError(
                f"策略表 pseudonymization.digest_length 越界：{digest_length}"
                f"（要求 {_MIN_DIGEST_LENGTH}–{_MAX_DIGEST_LENGTH}）"
            )
        return cls(scheme=scheme, prefix=prefix, digest_length=digest_length)


def load_pseudonym_config(path: str | Path | None = None) -> PseudonymConfig:
    """装载一致代号口径。

    :param path: 策略表路径；缺省取 ``$RESEARCH_POLICY_FILE``，再缺省取项目内的
        ``policy/research.yaml``。
    :raises PseudonymConfigError: 策略表缺失、结构不对或配置非法。
    """
    target = _resolve_policy_path(path)
    if not target.is_file():
        raise PseudonymConfigError(f"策略表不存在：{target}")
    key = (str(target), target.stat().st_mtime)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PseudonymConfigError(f"策略表解析失败：{target}（{exc}）") from exc
    config = PseudonymConfig.from_policy(raw, source=str(target))
    _CACHE[key] = config
    return config


def _resolve_policy_path(path: str | Path | None) -> Path:
    """解析策略表路径：显式路径 → 环境变量 → 项目内默认。"""
    if path is not None:
        return Path(path)
    env_value = os.environ.get(POLICY_PATH_ENV)
    if env_value:
        return Path(env_value)
    return default_policy_path()


# ----------------------------------------------------------------- 归一化


def normalize_identity(value: str) -> str:
    """归一化身份键：NFKC（全角折半角）+ 去空白 + 小写。

    归一化的意义是**同一个主键只有一种写法**：主索引读回 ``P-1001``、材料里
    写成 ``Ｐ-１００１`` 或 `` p-1001 ``，归一化后是同一个键，代号才恒等。
    """
    if not value:
        return ""
    return "".join(unicodedata.normalize("NFKC", value).split()).lower()


# ----------------------------------------------------------------- 生成器


class Pseudonymizer:
    """按患者主索引主键生成一致代号。

    :param key: HMAC 密钥（建议 ≥32 字节）。为空即报错，不降级。
    :param key_id: 密钥版本号（写进交付体 ``pseudonymization.key_id``）。
    :param config: 口径参数；缺省按策略表 ``pseudonymization`` 段读。

    .. note::
       实例是**纯函数**：同一个主键永远得到同一个代号；换密钥则整批代号改变
       （所以密钥版本号必须随交付体一起交付 —— 事后得说清楚这批是哪版算的）。
    """

    def __init__(
        self,
        key: str,
        *,
        key_id: str = "",
        config: PseudonymConfig | None = None,
    ) -> None:
        if not key or not key.strip():
            raise PseudonymKeyError(
                f"未配置 ${PSEUDONYM_HMAC_KEY_ENV}：一致代号无法生成"
                " —— 不得降级为无密钥哈希（无密钥哈希等于密钥公开）"
            )
        self._key = key.strip().encode("utf-8")
        self._key_id = (key_id or "").strip()
        self._config = config if config is not None else load_pseudonym_config()

    # ------------------------------------------------------------------ 属性

    @property
    def scheme(self) -> str:
        """方案名（写进交付体 ``pseudonymization.scheme``）。"""
        return self._config.scheme

    @property
    def key_id(self) -> str:
        """密钥版本号（写进交付体 ``pseudonymization.key_id``）。"""
        return self._key_id

    @property
    def prefix(self) -> str:
        """代号前缀。"""
        return self._config.prefix

    # ------------------------------------------------------------------ 计算

    def pseudonymize(self, patient_id: str) -> str:
        """算出这位患者的一致代号。

        :param patient_id: 患者主索引主键（**权威身份标识**）。
        :raises PseudonymIdentityError: 主键为空 —— 不知道这是谁就不给代号。
        """
        identity = normalize_identity(patient_id)
        if not identity:
            raise PseudonymIdentityError(
                "患者主索引主键为空：无法生成一致代号"
                " —— 不知道这一段属于谁，就不能给它一个稳定代号"
            )
        message = f"{self._config.scheme}|{identity}".encode("utf-8")
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        return f"{self._config.prefix}{digest[: self._config.digest_length]}"

    def describe(self) -> str:
        """一句话说明（写进运维摘要，**不含密钥**）。"""
        version = self._key_id or "未标注"
        return (
            f"一致代号（HMAC-SHA256 over 患者主索引主键，方案 {self.scheme}，"
            f"密钥版本 {version}）"
        )

    # ------------------------------------------------------------------ 装配

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        config: PseudonymConfig | None = None,
    ) -> "Pseudonymizer":
        """按环境变量装配（密钥与密钥版本号都从环境变量读）。

        :raises PseudonymKeyError: 密钥未配置 —— **不降级为无密钥哈希**。
        """
        source = os.environ if env is None else env
        key = (source.get(PSEUDONYM_HMAC_KEY_ENV) or "").strip()
        if not key:
            raise PseudonymKeyError(
                f"未配置 ${PSEUDONYM_HMAC_KEY_ENV}：一致代号无法生成"
                " —— 不得降级为无密钥哈希（无密钥哈希等于密钥公开）"
            )
        key_id = (source.get(PSEUDONYM_KEY_ID_ENV) or "").strip()
        return cls(key, key_id=key_id, config=config)
