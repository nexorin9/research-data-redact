#!/usr/bin/env python3
"""可选下载公开去标识化语料（拿不到就降级到合成语料，不中断流程）。

**为什么要有这条路径**：合成语料是默认路径，但它是我们自己造的 —— 形态受
自己的词表约束。公开去标识化语料能带来**我们没想到的写法**（真实病历里的
千奇百怪），是误伤回归最有价值的补充。所以这里给一条「能下就下」的旁路。

**纪律三条**

1. **校验 sha256**：候选源声明了哈希就必须对上；对不上就换下一个候选，
   绝不「下载了就当对」—— 换了内容还沿用旧哈希，指标就不可复现了。
2. **记来源与许可**：来源 URL、观测到的 sha256、许可、抓取时间全部写进
   ``SOURCE.md``，事后能说清这批语料是从哪来的、能不能再分发。
3. **拿不到就降级，不中断**：网络不通、URL 失效、哈希对不上 —— 一律降级到
   合成语料集，把降级原因打印出来并写进 ``DEGRADED.json``，**退出码仍是 0**：
   这一步是「可选增强」，失败不该把整条取数流程带崩。

**候选源清单**在 ``scripts/public_sources.json``。清单里的条目默认 **全部
禁用** —— sha256 必须由运营方在可信下载后核对填入；写一个没核对过的哈希比
不写更危险（永远对不上，还要让人以为做过校验）。运营方用 ``--url`` +
``--sha256`` 也能临时指定。

用法::

    # 看看候选源清单
    python scripts/fetch_public_set.py --list-sources

    # 走候选源清单（全部禁用时会直接降级到合成语料）
    python scripts/fetch_public_set.py --out var/public-set

    # 临时指定一个源（可选强校验 sha256）
    python scripts/fetch_public_set.py --url https://example.org/deid.jsonl \\
        --sha256 <hex> --name "某公开去标识化集" --license "CC-BY-4.0" \\
        --out var/public-set
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

_SCRIPTS = Path(__file__).resolve().parent
_PROJECT = _SCRIPTS.parent
if str(_PROJECT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT / "src"))
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from gen_corpus import DEFAULT_SEED, build_corpus, write_corpus  # noqa: E402

__all__ = [
    "FetchOutcome",
    "PublicSource",
    "fetch_public_set",
    "load_sources",
    "main",
]


#: 默认候选源清单（相对脚本目录）。
DEFAULT_SOURCE_FILE = _SCRIPTS / "public_sources.json"

#: 默认输出目录。
DEFAULT_OUT = Path("var") / "public-set"

#: 可当作「材料」的文本后缀（二进制件与影像件一律跳过 —— 当作文本读会读坏）。
TEXT_SUFFIXES: frozenset[str] = frozenset(
    {".txt", ".json", ".jsonl", ".csv", ".tsv", ".md", ".xml"}
)

#: 压缩包内只取这些后缀。
ARCHIVE_TEXT_SUFFIXES: frozenset[str] = frozenset({".txt", ".json", ".jsonl", ".csv", ".tsv"})


@dataclass(frozen=True)
class PublicSource:
    """一个公开去标识化语料候选源。

    :param name: 源名称（写进 ``SOURCE.md``）。
    :param url: 下载地址。
    :param license: 许可声明。
    :param sha256: 期望 sha256；空串表示未固定（只记录观测值，不做强校验）。
    :param note: 备注。
    :param enabled: 是否启用。禁用条目会被跳过（并在降级原因里说明）。
    """

    name: str
    url: str
    license: str = ""
    sha256: str = ""
    note: str = ""
    enabled: bool = True


@dataclass(frozen=True)
class FetchOutcome:
    """一次取数的结果。

    :param ok: 是否成功拿到公开集。
    :param degraded: 是否降级到了合成语料。
    :param reason: 降级原因（成功时为空串）。
    :param source: 命中的候选源（降级时为 None）。
    :param observed_sha256: 实际观测到的 sha256。
    :param material_count: 取到的材料份数。
    :param out_dir: 输出目录。
    :param attempts: 每个候选源的尝试记录（源名 → 失败原因）。
    """

    ok: bool
    degraded: bool
    reason: str = ""
    source: PublicSource | None = None
    observed_sha256: str = ""
    material_count: int = 0
    out_dir: Path = field(default_factory=Path)
    attempts: tuple[tuple[str, str], ...] = ()

    def summary(self) -> str:
        """一句人话摘要（写日志、打印都用它）。"""
        if self.ok and not self.degraded:
            name = self.source.name if self.source else "公开集"
            return f"公开集已获取：{name}（材料 {self.material_count} 份）"
        return f"公开集不可用，已降级到合成语料集（降级原因：{self.reason}）"


# ---------------------------------------------------------------------------
# 候选源清单
# ---------------------------------------------------------------------------


def load_sources(path: str | Path = DEFAULT_SOURCE_FILE) -> tuple[PublicSource, ...]:
    """读候选源清单。

    清单文件缺失或损坏**不算失败** —— 返回空清单，由调用方降级（原因写清
    「候选源清单读不出来」）。
    """
    target = Path(path)
    if not target.is_file():
        return ()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ()
    entries = raw.get("sources") if isinstance(raw, Mapping) else None
    if not isinstance(entries, list):
        return ()
    sources: list[PublicSource] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        url = str(entry.get("url", "")).strip()
        if not url:
            continue
        sources.append(
            PublicSource(
                name=str(entry.get("name", "未命名公开集")).strip() or "未命名公开集",
                url=url,
                license=str(entry.get("license", "")).strip(),
                sha256=str(entry.get("sha256", "")).strip(),
                note=str(entry.get("note", "")).strip(),
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return tuple(sources)


# ---------------------------------------------------------------------------
# 下载与校验
# ---------------------------------------------------------------------------


def _download(url: str, timeout: float) -> bytes:
    """下载一个 URL 的内容。

    用 ``httpx``（项目依赖）而不是 urllib —— 超时与连接错误语义更清楚，
    错误分类也统一。

    :raises RuntimeError: 下载失败（连接不通 / 超时 / HTTP 状态码非 2xx）。
    """
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx 是项目依赖
        raise RuntimeError(f"httpx 不可用：{exc}") from exc

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.content
    except Exception as exc:  # 网络异常族：连接不通 / 超时 / DNS 失败 / 状态码错
        raise RuntimeError(f"{type(exc).__name__}：{exc}") from exc


def _sha256_hex(payload: bytes) -> str:
    """字节流的 sha256（十六进制）。"""
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# 落盘
# ---------------------------------------------------------------------------


def _write_materials(materials: Sequence[tuple[str, bytes]], out_dir: Path) -> list[Path]:
    """把材料写进 ``<out>/materials/``，返回落盘路径清单。"""
    target = out_dir / "materials"
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in materials:
        safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
        path = target / safe
        if not path.suffix:
            path = path.with_suffix(".txt")
        path.write_bytes(payload)
        written.append(path)
    return written


def _materials_from_payload(payload: bytes, filename: str, limit: int) -> list[tuple[str, bytes]]:
    """从下载内容里拆出材料（按文件类型分派）。

    - ``.zip`` / ``.tar.gz``：取其中的文本件，**二进制件与影像件跳过**；
    - ``.jsonl``：一行一份材料；
    - ``.json``：数组 → 每元素一份；带 ``text`` / ``content`` 字段的对象 → 取该字段；
    - ``.txt`` / ``.csv`` 等：整份就是一份材料。
    """
    suffix = Path(filename).suffix.lower()
    materials: list[tuple[str, bytes]] = []

    if suffix == ".zip":
        import io

        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in sorted(archive.infolist(), key=lambda item: item.filename):
                if info.is_dir() or Path(info.filename).suffix.lower() not in ARCHIVE_TEXT_SUFFIXES:
                    continue
                materials.append((info.filename, archive.read(info)))
    elif suffix in (".tar.gz", ".tgz", ".tar"):
        import io

        mode = "r:gz" if suffix != ".tar" else "r:"
        with tarfile.open(fileobj=io.BytesIO(payload), mode=mode) as archive:
            for member in sorted(archive.getmembers(), key=lambda item: item.name):
                if not member.isfile():
                    continue
                if Path(member.name).suffix.lower() not in ARCHIVE_TEXT_SUFFIXES:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                materials.append((member.name, handle.read()))
    elif suffix == ".jsonl":
        text = payload.decode("utf-8", errors="replace")
        for index, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            materials.append((f"line-{index:05d}.json", line.encode("utf-8")))
    elif suffix == ".json":
        try:
            data = json.loads(payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            for index, item in enumerate(data, start=1):
                materials.append(
                    (f"item-{index:05d}.json", json.dumps(item, ensure_ascii=False).encode("utf-8"))
                )
        elif isinstance(data, Mapping):
            body = data.get("text") or data.get("content")
            if isinstance(body, str):
                materials.append(("content.txt", body.encode("utf-8")))
            else:
                materials.append(("content.json", payload))
        else:
            materials.append(("content.json", payload))
    else:
        materials.append((Path(filename).name or "material.txt", payload))

    if limit > 0:
        materials = materials[:limit]
    return materials


def _render_source_md(
    source: PublicSource,
    *,
    observed_sha256: str,
    verified: bool,
    material_count: int,
    fetched_at: str,
) -> str:
    """来源说明（写进 ``SOURCE.md``）—— 事后能说清这批语料的出处与许可。"""
    return f"""# 公开去标识化语料来源

| 项目 | 内容 |
|------|------|
| 名称 | {source.name} |
| 下载地址 | {source.url} |
| 许可 | {source.license or "（来源未声明许可 —— 分发前须自行确认）"} |
| 声明的 sha256 | {source.sha256 or "（未固定 —— 本次只记录观测值）"} |
| 观测到的 sha256 | `{observed_sha256}` |
| 是否强校验通过 | {"是" if verified else "否（未固定哈希，只记录观测值）"} |
| 材料份数 | {material_count} |
| 抓取时间（UTC） | {fetched_at} |
| 备注 | {source.note or "（无）"} |

## 说明

本目录材料来自**公开去标识化**语料集。是否含可直接标识到个人的残余标识，
由发布方与接收方各自按本地合规要求判断；本项目只做**再脱敏**，不替代
数据提供方的去标识化义务。

抓取脚本：`scripts/fetch_public_set.py`（可重跑；校验与降级逻辑见脚本头注释）。
"""


def fetch_public_set(
    *,
    out_dir: str | Path = DEFAULT_OUT,
    sources: Sequence[PublicSource] = (),
    url: str = "",
    sha256: str = "",
    name: str = "",
    license_: str = "",
    timeout: float = 15.0,
    limit: int = 0,
    seed: int = DEFAULT_SEED,
) -> FetchOutcome:
    """取一份公开去标识化语料；拿不到就降级到合成语料。

    :param out_dir: 输出目录。
    :param sources: 候选源清单（``url`` 非空时忽略）。
    :param url: 直接指定一个下载地址。
    :param sha256: 期望 sha256（给了就强校验）。
    :param name: 直接指定时的源名称。
    :param license_: 直接指定时的许可声明。
    :param timeout: 单次下载超时（秒）。
    :param limit: 最多取多少份材料（0 = 不限）。
    :param seed: 降级到合成语料时用的种子。
    """
    target = Path(out_dir)
    attempts: list[tuple[str, str]] = []

    candidates: list[PublicSource] = []
    if url:
        candidates.append(
            PublicSource(
                name=name or "命令行指定的公开集",
                url=url,
                license=license_,
                sha256=sha256,
                note="由 --url / --sha256 直接指定",
            )
        )
    else:
        candidates.extend(source for source in sources if source.enabled)
        disabled = [source.name for source in sources if not source.enabled]
        if disabled:
            attempts.append(
                (
                    "候选源清单",
                    f"已禁用条目未尝试（sha256 须先核对填入）：{'、'.join(disabled)}",
                )
            )

    for source in candidates:
        try:
            payload = _download(source.url, timeout)
        except RuntimeError as exc:
            attempts.append((source.name, f"下载失败：{exc}"))
            continue
        observed = _sha256_hex(payload)
        if source.sha256 and observed.lower() != source.sha256.lower():
            attempts.append(
                (
                    source.name,
                    f"sha256 不匹配（声明 {source.sha256[:12]}… / 实际 {observed[:12]}…）",
                )
            )
            continue
        try:
            materials = _materials_from_payload(payload, source.url, limit)
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
            attempts.append((source.name, f"解包失败：{exc}"))
            continue
        if not materials:
            attempts.append((source.name, "下载成功但没拆出任何文本材料"))
            continue

        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        _write_materials(materials, target)
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        (target / "SOURCE.md").write_text(
            _render_source_md(
                source,
                observed_sha256=observed,
                verified=bool(source.sha256),
                material_count=len(materials),
                fetched_at=fetched_at,
            ),
            encoding="utf-8",
        )
        (target / "fetch_log.json").write_text(
            json.dumps(
                {
                    "ok": True,
                    "degraded": False,
                    "source": {
                        "name": source.name,
                        "url": source.url,
                        "license": source.license,
                        "declared_sha256": source.sha256,
                    },
                    "observed_sha256": observed,
                    "sha256_verified": bool(source.sha256),
                    "material_count": len(materials),
                    "fetched_at": fetched_at,
                    "attempts": [{"source": n, "reason": r} for n, r in attempts],
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return FetchOutcome(
            ok=True,
            degraded=False,
            source=source,
            observed_sha256=observed,
            material_count=len(materials),
            out_dir=target,
            attempts=tuple(attempts),
        )

    # ---- 全部候选失败 → 降级到合成语料 -----------------------------------
    reason = "；".join(f"{n}：{r}" for n, r in attempts) or "没有可用候选源"
    synthetic_dir = target / "synthetic"
    artifacts = build_corpus(seed=seed, limit=limit if limit > 0 else 500)
    write_corpus(artifacts, synthetic_dir)
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (target / "DEGRADED.json").write_text(
        json.dumps(
            {
                "ok": False,
                "degraded": True,
                "reason": reason,
                "fallback": "合成语料（scripts/gen_corpus.py）",
                "fallback_dir": str(synthetic_dir),
                "seed": seed,
                "fetched_at": fetched_at,
                "attempts": [{"source": n, "reason": r} for n, r in attempts],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return FetchOutcome(
        ok=False,
        degraded=True,
        reason=reason,
        material_count=len(artifacts.materials),
        out_dir=synthetic_dir,
        attempts=tuple(attempts),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        prog="fetch_public_set.py",
        description="可选下载公开去标识化语料；拿不到就降级到合成语料，不中断流程",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="输出目录")
    parser.add_argument(
        "--source-file", type=Path, default=DEFAULT_SOURCE_FILE, help="候选源清单"
    )
    parser.add_argument("--url", default="", help="直接指定下载地址（给了就跳过清单）")
    parser.add_argument("--sha256", default="", help="期望 sha256（给了就强校验）")
    parser.add_argument("--name", default="", help="源名称（配合 --url 用）")
    parser.add_argument("--license", dest="license_", default="", help="许可声明")
    parser.add_argument("--timeout", type=float, default=15.0, help="单次下载超时（秒）")
    parser.add_argument("--limit", type=int, default=0, help="最多取多少份材料（0 = 不限）")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="降级时合成语料的种子")
    parser.add_argument(
        "--list-sources", action="store_true", help="只打印候选源清单后退出"
    )
    args = parser.parse_args(argv)

    if args.list_sources:
        sources = load_sources(args.source_file)
        if not sources:
            print(f"候选源清单为空或读不出来：{args.source_file}")
            return 0
        print(f"候选源清单（{args.source_file}）：")
        for source in sources:
            state = "启用" if source.enabled else "禁用"
            print(f"  [{state}] {source.name} —— {source.url}")
            print(f"         许可：{source.license or '未声明'}；sha256：{source.sha256 or '未固定'}")
            if source.note:
                print(f"         备注：{source.note}")
        return 0

    outcome = fetch_public_set(
        out_dir=args.out,
        sources=load_sources(args.source_file),
        url=args.url,
        sha256=args.sha256,
        name=args.name,
        license_=args.license_,
        timeout=args.timeout,
        limit=args.limit,
        seed=args.seed,
    )
    print(outcome.summary())
    if outcome.degraded:
        print(f"降级原因：{outcome.reason}")
        print(f"降级产物：{outcome.out_dir}")
        for name, reason in outcome.attempts:
            print(f"  尝试 {name} —— {reason}")
    else:
        print(f"材料目录：{outcome.out_dir}")
        print(f"观测 sha256：{outcome.observed_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
