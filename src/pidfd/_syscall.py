# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for the pidfd syscalls and waitid(2).

glibc has no wrappers for pidfd_open, pidfd_send_signal or pidfd_getfd,
so all four calls go through libc's syscall(2). The numbers differ per
architecture for waitid only. The three pidfd calls share the common
numbering on every supported arch.

Kernel references: pidfd_open(2), pidfd_send_signal(2), pidfd_getfd(2),
waitid(2), asm/unistd*.h, asm-generic/unistd.h.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import sys
from typing import NoReturn

from .errors import PidFdError, UnsupportedError

P_PIDFD = 3


class _SigChld(ctypes.Structure):
    """The _sifields._sigchld member of the kernel siginfo_t."""

    _fields_ = [
        ("si_pid", ctypes.c_int32),
        ("si_uid", ctypes.c_uint32),
        ("si_status", ctypes.c_int32),
        ("si_utime", ctypes.c_long),
        ("si_stime", ctypes.c_long),
    ]


class _SiFields(ctypes.Union):
    """union __sifields, padded so the whole siginfo stays writable."""

    _fields_ = [
        ("sigchld", _SigChld),
        ("pad", ctypes.c_byte * 128),
    ]


class SigInfo(ctypes.Structure):
    """The kernel siginfo_t used by waitid(2) and pidfd_send_signal(2).

    Only the SIGCHLD member of union __sifields is decoded. The rest is
    padding. The buffer is deliberately larger than the kernel's
    128-byte siginfo_t so waitid's user access check always succeeds.
    """

    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("_sifields", _SiFields),
    ]

    @property
    def si_pid(self) -> int:
        return int(self._sifields.sigchld.si_pid)

    @si_pid.setter
    def si_pid(self, value: int) -> None:
        self._sifields.sigchld.si_pid = value

    @property
    def si_uid(self) -> int:
        return int(self._sifields.sigchld.si_uid)

    @si_uid.setter
    def si_uid(self, value: int) -> None:
        self._sifields.sigchld.si_uid = value

    @property
    def si_status(self) -> int:
        return int(self._sifields.sigchld.si_status)

    @si_status.setter
    def si_status(self, value: int) -> None:
        self._sifields.sigchld.si_status = value


_libc: ctypes.CDLL | None = None
_numbers: tuple[int, int, int, int] | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("pidfds are only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc


def _syscall_numbers() -> tuple[int, int, int, int]:
    """Return (pidfd_open, pidfd_send_signal, pidfd_getfd, waitid)."""
    global _numbers
    if _numbers is not None:
        return _numbers
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            # The x32 ABI carries different numbers and a differently
            # aligned siginfo_t. Reject it rather than call the wrong
            # syscall.
            raise UnsupportedError("the x32 ABI is not supported")
        _numbers = (434, 424, 438, 247)
    elif machine in ("i386", "i486", "i586", "i686", "x86"):
        _numbers = (434, 424, 438, 284)
    elif machine in ("aarch64", "arm64", "riscv32", "riscv64", "loongarch64"):
        _numbers = (434, 424, 438, 95)
    elif machine in ("armv6l", "armv7l", "arm"):
        _numbers = (434, 424, 438, 280)
    elif machine.startswith("ppc"):
        _numbers = (434, 424, 438, 272)
    elif machine.startswith("s390"):
        _numbers = (434, 424, 438, 281)
    else:
        raise UnsupportedError(f"no pidfd syscall numbers for architecture {machine}")
    return _numbers


def _raise_errno(err: int) -> NoReturn:
    if err == errno.ENOSYS:
        raise UnsupportedError(err, os.strerror(err))
    raise PidFdError(err, os.strerror(err))


def _call(nr: int, *args: object) -> int:
    ret = int(_get_libc().syscall(nr, *args))
    if ret == -1:
        _raise_errno(ctypes.get_errno())
    return ret


def pidfd_open(pid: int, flags: int = 0) -> int:
    """Open a pidfd for pid and return the new file descriptor."""
    return _call(_syscall_numbers()[0], pid, flags)


def pidfd_send_signal(
    pidfd: int, sig: int, info: SigInfo | None, flags: int = 0
) -> None:
    """Send sig to the process the pidfd refers to."""
    ref = ctypes.byref(info) if info is not None else None
    _call(_syscall_numbers()[1], pidfd, sig, ref, flags)


def pidfd_getfd(pidfd: int, targetfd: int, flags: int = 0) -> int:
    """Duplicate targetfd from the pidfd's process into our fd table."""
    return _call(_syscall_numbers()[2], pidfd, targetfd, flags)


def waitid(idtype: int, upid: int, info: SigInfo, options: int) -> int:
    """waitid(2) filling info. The rusage argument stays NULL."""
    return _call(_syscall_numbers()[3], idtype, upid, ctypes.byref(info), options, 0)
