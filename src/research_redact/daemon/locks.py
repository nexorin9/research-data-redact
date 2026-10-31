"""批次互斥锁：同一批次同一时刻只允许一个执行者处理。

科研交付是**事件驱动**的：管理员把申请单放进交付目录（守护进程捡起来）、
运维人员在 CLI 上点一次 run、人工在 CLI 上点一次 deliver —— 一次交付可能
从几个方向同时被触发。两个执行者同时对同一批材料跑脱敏，后果不是「慢一点」：

- **一致代号会变**：代号取自进程内的对照索引，两个进程各算各的，同一患者在
  两份产物里代号不同，平台侧核不出来，伦理办对不上账；
- **命中清单会翻倍**：同一处命中写两遍，交差时数不清；
- **外发会多一次**：两个执行者各交一份，平台上多一个数据集，伦理办那边只
  看到一次交付。

所以同一批次的处理必须**互斥**：一个执行者拿着锁跑，另一个执行者要么等它
跑完（然后复用已有结果），要么直接跳过（复用已有产物与回执）。

**实现**：文件锁（``fcntl.flock``）+ 进程内互斥锁（``threading.Lock``）。
文件锁管跨进程，进程内锁管同进程多线程 —— 两把都拿到才算拿到批次。
（``flock`` 绑在**文件描述符**上，同一进程用两个 ``open()`` 拿到的是两个
描述符，彼此仍然互斥，所以单靠文件锁也够；进程内锁是额外的保险，也让
「拿不到锁」这件事在本进程内可判定。）

**锁文件里写什么**：持有者信息（进程号、主机、批次号、拿锁时刻）。拿不到锁
的一方能据此告诉人「这一批正被哪个进程处理着」—— 不静默降级，也不假装
批次不存在。

**不变量**

1. 锁**不保护业务状态**，只保护「这一批的处理」这一段临界区；
2. 释放锁时**只清空文件内容、不删文件** —— 删文件会有竞态（另一个进程可能
   正拿着同一个 inode 的锁）；
3. 锁文件里**不含任何患者原文**，只有进程号、主机名与批次号。
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

try:  # pragma: no cover - 平台差异
    import fcntl
except ImportError:  # pragma: no cover - 非 POSIX 平台
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_LOCK_TIMEOUT",
    "BatchLock",
    "LockOutcome",
    "default_lock_dir",
]

#: 拿不到锁时的默认等待时长（秒）。等不到就跳过这一轮，让兜底扫描或下
#: 一轮事件再来 —— 一直占着不放会把整条流水线堵住。
DEFAULT_LOCK_TIMEOUT = 30.0

#: 抢锁时的轮询间隔（秒）。
_POLL_INTERVAL = 0.05

#: 进程内互斥锁表：锁文件路径 → 线程锁。
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


@dataclass(frozen=True)
class LockOutcome:
    """一次抢锁的结果。

    :param acquired: 是否拿到锁。
    :param path: 锁文件路径。
    :param waited_seconds: 等了多久。
    :param holder: 锁持有者信息（锁没拿到时是**当前**持有者的信息；拿到时是
        自己的）。
    :param reason: 没拿到锁的原因（人话，进运维摘要与告警文案）。
    """

    acquired: bool
    path: Path
    waited_seconds: float = 0.0
    holder: Mapping[str, object] = field(default_factory=dict)
    reason: str = ""


def default_lock_dir(ledger: Any = None, output_dir: str | Path | None = None) -> Path:
    """批次锁的默认目录。

    **跟着台账走**：守护进程与运维 CLI 用同一张台账 —— 锁目录也就落在台账
    旁边，两边看到的锁是同一把。台账是内存库（测试场景）时退回产物目录。

    :param ledger: 批次台账。
    :param output_dir: 产物目录。
    """
    ledger_path = getattr(ledger, "path", None)
    if ledger_path is not None and str(ledger_path) != ":memory:":
        return Path(ledger_path).parent / "locks"
    if output_dir is not None:
        return Path(output_dir) / ".locks"
    return Path("var") / "locks"


class BatchLock:
    """批次级互斥锁（文件锁 + 进程内锁）。

    :param path: 锁文件路径。
    :param timeout: 最多等多久（秒）；0 表示不等待。
    :param poll_interval: 抢锁时的轮询间隔（秒）。

    用法::

        lock = BatchLock(path, timeout=5.0)
        outcome = lock.acquire()
        if not outcome.acquired:
            ...  # 另一执行者正在处理，或已处理完可复用
        try:
            ...
        finally:
            lock.release()
    """

    def __init__(
        self,
        path: str | Path,
        *,
        timeout: float = DEFAULT_LOCK_TIMEOUT,
        poll_interval: float = _POLL_INTERVAL,
    ) -> None:
        self.path = Path(path)
        self.timeout = max(0.0, float(timeout))
        self.poll_interval = max(0.01, float(poll_interval))
        self._thread_lock = _thread_lock_for(self.path)
        self._thread_held = False
        self._handle = None
        self._outcome: LockOutcome | None = None

    # ------------------------------------------------------------------ 抢锁

    def acquire(self) -> LockOutcome:
        """抢锁。

        :return: 抢锁结果（``acquired=False`` 时 ``reason`` 写明原因）。
        """
        started = time.monotonic()
        deadline = started + self.timeout

        # ---- 第一把：进程内互斥（同进程多线程）----
        remaining = max(0.0, deadline - time.monotonic())
        if not self._thread_lock.acquire(timeout=remaining):
            outcome = LockOutcome(
                acquired=False,
                path=self.path,
                waited_seconds=time.monotonic() - started,
                holder=self._read_holder(),
                reason="同一进程内已有执行者正在处理本批次",
            )
            self._outcome = outcome
            return outcome
        self._thread_held = True

        # ---- 第二把：文件锁（跨进程）----
        if fcntl is None:  # pragma: no cover - 非 POSIX 平台退化为进程内锁
            outcome = LockOutcome(
                acquired=True,
                path=self.path,
                waited_seconds=time.monotonic() - started,
                holder=self._write_holder(),
                reason="本平台无文件锁，仅进程内互斥",
            )
            self._outcome = outcome
            return outcome

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    handle.close()
                    self._release_thread_lock()
                    outcome = LockOutcome(
                        acquired=False,
                        path=self.path,
                        waited_seconds=time.monotonic() - started,
                        holder=self._read_holder(),
                        reason="另一个执行者正持有本批次的处理锁",
                    )
                    self._outcome = outcome
                    return outcome
                time.sleep(self.poll_interval)

        self._handle = handle
        outcome = LockOutcome(
            acquired=True,
            path=self.path,
            waited_seconds=time.monotonic() - started,
            holder=self._write_holder(),
            reason="已取得批次处理锁",
        )
        self._outcome = outcome
        return outcome

    def release(self) -> None:
        """放锁（没拿到锁时是空操作）。"""
        handle = self._handle
        if handle is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:  # pragma: no cover - 释放失败也不能吞掉业务结果
                pass
            try:
                # 清空持有者信息，但**不删文件** —— 删了会有竞态。
                handle.seek(0)
                handle.truncate(0)
            except OSError:  # pragma: no cover
                pass
            try:
                handle.close()
            except OSError:  # pragma: no cover
                pass
            self._handle = None
        self._release_thread_lock()

    @property
    def acquired(self) -> bool:
        """当前是否持有锁。"""
        return self._handle is not None or self._thread_held

    @property
    def outcome(self) -> LockOutcome | None:
        """最近一次抢锁的结果。"""
        return self._outcome

    def __enter__(self) -> "BatchLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    # ------------------------------------------------------------------ 内部

    def _release_thread_lock(self) -> None:
        if self._thread_held:
            self._thread_held = False
            self._thread_lock.release()

    def _write_holder(self) -> dict[str, object]:
        """把持有者信息写进锁文件。"""
        holder = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "acquired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        if self._handle is not None:
            try:
                self._handle.seek(0)
                self._handle.truncate(0)
                self._handle.write(json.dumps(holder, ensure_ascii=False) + "\n")
                self._handle.flush()
            except OSError:  # pragma: no cover - 写不进去不影响互斥本身
                pass
        return holder

    def _read_holder(self) -> dict[str, object]:
        """读锁文件里的持有者信息（读不出来就返回空）。"""
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return {}
        if not raw:
            return {}
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}


def _thread_lock_for(path: Path) -> threading.Lock:
    """取（并登记）某个锁文件路径对应的进程内互斥锁。"""
    key = str(path)
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _THREAD_LOCKS[key] = lock
        return lock
