# SPDX-License-Identifier: 0BSD
"""PidFd: a file descriptor that refers to a process.

A pidfd is a stable reference to a task: unlike a raw pid it cannot be
recycled, so signaling through it cannot hit an unrelated process. The
descriptor becomes readable (POLLIN) once the task exits and turns into
a zombie, and reports POLLHUP once it is reaped. waitid(2) with idtype
P_PIDFD reaps a child through it.

Kernel references: pidfd_open(2), pidfd_send_signal(2), pidfd_getfd(2),
waitid(2), linux/pidfd.h.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from types import TracebackType

from . import _syscall
from ._syscall import SigInfo

__all__ = [
    "OpenFlag",
    "PidFd",
    "SigInfo",
    "SignalFlag",
    "WaitCode",
    "WaitFlag",
    "WaitResult",
    "pidfd_send_signal",
]


class OpenFlag(IntFlag):
    """Flags for pidfd_open(2), mirroring linux/pidfd.h.

    NONBLOCK makes wait() fail with EAGAIN instead of blocking while the
    task is still running (Linux 5.10+). THREAD pins the fd to a single
    thread instead of the thread-group leader (Linux 6.9+).
    """

    NONBLOCK = 0o4000  # O_NONBLOCK
    THREAD = 0o200  # O_EXCL


class SignalFlag(IntFlag):
    """Scope flags for pidfd_send_signal(2), Linux 6.9+."""

    THREAD = 1 << 0
    THREAD_GROUP = 1 << 1
    PROCESS_GROUP = 1 << 2


class WaitFlag(IntFlag):
    """Option bits for waitid(2), mirroring linux/wait.h.

    At least one of WEXITED, WSTOPPED or WCONTINUED is required.
    """

    WNOHANG = 0x00000001
    WSTOPPED = 0x00000002
    WEXITED = 0x00000004
    WCONTINUED = 0x00000008
    WNOWAIT = 0x01000000


class WaitCode(IntEnum):
    """si_code values the kernel reports in a SIGCHLD siginfo (CLD_*)."""

    CLD_EXITED = 1
    CLD_KILLED = 2
    CLD_DUMPED = 3
    CLD_TRAPPED = 4
    CLD_STOPPED = 5
    CLD_CONTINUED = 6


@dataclass(frozen=True)
class WaitResult:
    """The fields waitid(2) fills into the siginfo_t for a child.

    code holds a WaitCode (CLD_*) value. Its meaning for status is that
    of waitpid(2): an exit status when code is CLD_EXITED, a signal
    number for CLD_KILLED/CLD_DUMPED/CLD_STOPPED/CLD_CONTINUED. A result
    with signo 0 means the call returned without an event, which only
    happens when WNOHANG was requested.
    """

    pid: int
    uid: int
    signo: int
    code: int
    status: int


class PidFd:
    """A pidfd file descriptor referring to a process.

    Obtain one with open() or wrap an existing descriptor in the
    constructor. Instances own their fd: close() is idempotent and the
    context manager closes on exit.
    """

    def __init__(self, fd: int) -> None:
        self._fd = -1  # keeps __del__ safe when validation fails
        if fd < 0:
            raise ValueError(f"fd must not be negative: {fd}")
        self._fd = fd

    @classmethod
    def open(cls, pid: int, flags: OpenFlag | int = 0) -> PidFd:
        """Open a pidfd for pid via pidfd_open(2) (Linux 5.3+)."""
        return cls(_syscall.pidfd_open(int(pid), int(flags)))

    def fileno(self) -> int:
        """Return the underlying descriptor, or -1 once closed."""
        return self._fd

    @property
    def closed(self) -> bool:
        """Whether close() has released the descriptor."""
        return self._fd < 0

    def _check_open(self) -> int:
        if self._fd < 0:
            raise ValueError("pidfd is closed")
        return self._fd

    def close(self) -> None:
        """Close the descriptor. Safe to call more than once."""
        if self._fd >= 0:
            fd, self._fd = self._fd, -1
            os.close(fd)

    def detach(self) -> int:
        """Release the descriptor without closing it.

        Returns the raw fd and marks the PidFd closed, transferring
        ownership of the descriptor to the caller.
        """
        fd = self._check_open()
        self._fd = -1
        return fd

    def signal(
        self,
        sig: int,
        siginfo: SigInfo | None = None,
        flags: SignalFlag | int = 0,
    ) -> None:
        """Send sig to the referenced process via pidfd_send_signal(2).

        siginfo=None selects the same implicit fields kill(2) supplies.
        Pass a populated SigInfo for rt_sigqueueinfo(2)-style delivery,
        where si_code must be a negative SI_* value such as SI_QUEUE
        when the target is not the caller. flags accepts the SignalFlag
        bits on Linux 6.9+. 0 is the only value older kernels allow.
        ESRCH means the task is already gone
        and reaped, never that the pid was recycled.
        """
        _syscall.pidfd_send_signal(self._check_open(), int(sig), siginfo, int(flags))

    def wait(self, flags: WaitFlag | int = WaitFlag.WEXITED) -> WaitResult:
        """waitid(P_PIDFD) on the referenced child (Linux 5.4+).

        The pidfd must refer to a child of the caller, otherwise the
        kernel answers ECHILD. A pidfd opened with OpenFlag.NONBLOCK
        fails with EAGAIN while the child is still running. On a
        blocking pidfd add WaitFlag.WNOHANG for a poll-style call that
        returns a WaitResult with signo 0.
        """
        info = SigInfo()
        _syscall.waitid(_syscall.P_PIDFD, self._check_open(), info, int(flags))
        return WaitResult(
            pid=info.si_pid,
            uid=info.si_uid,
            signo=info.si_signo,
            code=info.si_code,
            status=info.si_status,
        )

    def getfd(self, targetfd: int, flags: int = 0) -> int:
        """Duplicate targetfd of the referenced process into our fd table.

        The returned fd shares the open file description with the
        target's fd and has close-on-exec set. Access is governed by a
        PTRACE_MODE_ATTACH_REALCREDS ptrace check (see ptrace(2)): under
        yama ptrace_scope that typically means the target must be a
        descendant, or the caller needs CAP_SYS_PTRACE.
        """
        return _syscall.pidfd_getfd(self._check_open(), int(targetfd), int(flags))

    def __enter__(self) -> PidFd:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __index__(self) -> int:
        return self._check_open()

    def __repr__(self) -> str:
        state = self._fd if self._fd >= 0 else "closed"
        return f"PidFd(fd={state})"

    def __del__(self) -> None:
        with contextlib.suppress(OSError):
            self.close()


def pidfd_send_signal(fd: int | PidFd, sig: int, flags: SignalFlag | int = 0) -> None:
    """Send sig through a pidfd without wrapping it in PidFd first."""
    raw = fd.fileno() if isinstance(fd, PidFd) else int(fd)
    _syscall.pidfd_send_signal(raw, int(sig), None, int(flags))
