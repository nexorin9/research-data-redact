"""项目根目录解析：相对路径按项目根解析。

守护进程与运维 CLI 可能不在同一工作目录下跑（一个从 systemctl 起，一个由
值班的人在终端敲），所以「相对路径」必须有一个**唯一**的锚点 —— 项目根目录。

判据是「同时含 ``policy/`` 与 ``src/`` 的那一层」：只看 ``policy/`` 会把
包目录 ``src/research_redact/`` 认成项目根，相对路径就会落到
``src/research_redact/var/`` 里 —— 既不是 ``.env.example`` 写的那个位置，
也不在 ``.gitignore`` 覆盖的运行时目录里，事后清理时还会被当成源码目录。
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["project_root"]


def project_root() -> Path:
    """项目根目录（相对路径按它解析）。

    找不到（源码被单独安装、不带 ``policy/`` 与 ``src/``）时退回带
    ``pyproject.toml`` 的那一层，再退不到就用包目录的上一级。
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "policy").is_dir() and (parent / "src").is_dir():
            return parent
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return here.parents[2] if len(here.parents) > 2 else here.parent
