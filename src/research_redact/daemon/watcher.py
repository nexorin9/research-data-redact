"""科研交付目录监听：新增 / 修改事件 + 定时兜底扫描。

科研数据管理员的交付动作是「把一批材料放进交付目录」—— 这是一次**文件系统
事件**，不是一个 API 调用。所以本轮的产品形态是**事件驱动守护**：进程常驻，
盯着交付目录，材料一落盘就自动跑完脱敏与交付。

两条发现路径，各管各的：

- **事件轮询**（:meth:`InboxWatcher.poll`）：目录**新增**或内容**有改动**时
  触发。签名 = 目录下所有文件的「相对路径 + 大小 + 修改时间」摘要，改一个
  字节签名就变。管理员补齐材料、修正申请单，都会重新触发一次。
- **定时兜底扫描**（:meth:`InboxWatcher.applications`）：不看签名，把交付目录
  下所有申请单都摆出来，由调用方按台账状态判断要不要处理。守护进程刚起来、
  上一次投递中途崩了、有人手工改了台账 —— 兜底扫描负责把这些漏网的捡回来。

**去重由台账状态负责，不由监听器负责**：监听器只管「看见了什么」，「该不该
再处理一遍」由 :mod:`research_redact.daemon.runner` 按批次状态判断。已交付
的批次不会被兜底扫描重复处理。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "APPLICATION_FILENAME",
    "InboxApplication",
    "InboxWatcher",
]

#: 申请单文件名：交付目录里每个申请目录下的这份文件是批次的唯一入口。
APPLICATION_FILENAME = "application.json"


@dataclass(frozen=True)
class InboxApplication:
    """交付目录里的一份申请单。

    :param application_no: 申请单号 = 批次号。
    :param directory: 申请目录（``inbox/<申请单号>/``）。
    :param application_file: 申请单文件路径。
    :param signature: 目录内容摘要（内容变了签名就变）。
    """

    application_no: str
    directory: Path
    application_file: Path
    signature: str


class InboxWatcher:
    """交付目录监听器。

    :param inbox: 交付目录根（``$RESEARCH_DELIVERY_DIR``）。
    :param application_filename: 申请单文件名；缺省 ``application.json``。
    """

    def __init__(
        self,
        inbox: str | Path,
        *,
        application_filename: str = APPLICATION_FILENAME,
    ) -> None:
        self.inbox = Path(inbox)
        self.application_filename = application_filename
        self._seen: dict[str, str] = {}

    def applications(self) -> tuple[InboxApplication, ...]:
        """兜底扫描：交付目录下所有申请单（不看去重签名）。"""
        if not self.inbox.is_dir():
            return ()
        found: list[InboxApplication] = []
        for entry in sorted(self.inbox.iterdir()):
            if not entry.is_dir():
                continue
            application_file = entry / self.application_filename
            if not application_file.is_file():
                continue
            found.append(
                InboxApplication(
                    application_no=entry.name,
                    directory=entry,
                    application_file=application_file,
                    signature=_signature(entry),
                )
            )
        return tuple(found)

    def poll(self) -> tuple[InboxApplication, ...]:
        """事件轮询：返回**新增**或**内容有改动**的申请单。

        看过一份申请单就记住它的签名；签名变了才算事件。返回的申请单同时
        被记为「已看见」—— 下次轮询不会重复报同一份没动过的申请单。
        """
        changed: list[InboxApplication] = []
        for application in self.applications():
            if self._seen.get(application.application_no) != application.signature:
                changed.append(application)
                self._seen[application.application_no] = application.signature
        return tuple(changed)

    def prime(self) -> tuple[InboxApplication, ...]:
        """把当前目录内容记成「已看见」，**不**产生事件。

        守护进程启动时调用：启动前就躺在目录里的申请单不是「刚落盘的事件」，
        由兜底扫描按台账状态接手。少了这一步，进程一重启就会把历史批次
        当成新事件重跑一遍 —— 重复脱敏、重复投递。
        """
        applications = self.applications()
        for application in applications:
            self._seen[application.application_no] = application.signature
        return applications

    def forget(self, application_no: str) -> None:
        """忘掉一个申请单（下次轮询会把它当成新事件重新报出来）。"""
        self._seen.pop(application_no, None)


def _signature(directory: Path) -> str:
    """目录内容摘要：相对路径 + 文件大小 + 修改时间。

    只看这三样就够：内容改了大小会变；等长内容原地改写靠修改时间；新增 /
    删除文件靠路径集合。摘要算法稳定 —— 同一份目录两次算出来必须一致。
    """
    digest = hashlib.sha256()
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        try:
            stat = path.stat()
        except OSError:  # pragma: no cover - 目录在扫描途中被删
            continue
        digest.update(str(path.relative_to(directory)).encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b"\x00")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()
