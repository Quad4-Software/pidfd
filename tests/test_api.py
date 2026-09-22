# SPDX-License-Identifier: 0BSD
"""Mocked-syscall tests: marshalling, decoding and errno passthrough."""

import ctypes
import errno
import os
import platform
import signal
import sys
from types import SimpleNamespace

import pytest

from pidfd import (
    OpenFlag,
    PidFd,
    PidFdError,
    SigInfo,
    SignalFlag,
    UnsupportedError,
    WaitCode,
    WaitFlag,
    WaitResult,
    _syscall,
    pidfd_send_signal,
)


def test_constants_match_kernel_headers() -> None:
    assert _syscall.P_PIDFD == 3
    assert int(OpenFlag.NONBLOCK) == 0o4000  # O_NONBLOCK
    assert int(OpenFlag.THREAD) == 0o200  # O_EXCL
    assert int(SignalFlag.THREAD) == 1
    assert int(SignalFlag.THREAD_GROUP) == 2
    assert int(SignalFlag.PROCESS_GROUP) == 4
    assert int(WaitFlag.WNOHANG) == 1
    assert int(WaitFlag.WSTOPPED) == 2
    assert int(WaitFlag.WEXITED) == 4
    assert int(WaitFlag.WCONTINUED) == 8
    assert int(WaitFlag.WNOWAIT) == 0x01000000
    assert [code.value for code in WaitCode] == [1, 2, 3, 4, 5, 6]


def test_siginfo_layout() -> None:
    # union __sifields follows si_signo/si_errno/si_code. It is 8-byte
    # aligned on 64-bit (offset 16) and 4-byte aligned on 32-bit
    # (offset 12), matching the kernel siginfo_t.
    offset = SigInfo._sifields.offset
    assert offset == (16 if ctypes.sizeof(ctypes.c_void_p) == 8 else 12)
    assert ctypes.sizeof(SigInfo) >= 128
    info = SigInfo()
    info.si_pid = 4242
    info.si_uid = 1000
    info.si_status = 7
    assert (info.si_pid, info.si_uid, info.si_status) == (4242, 1000, 7)


def test_syscall_numbers_per_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = {
        "x86_64": (434, 424, 438, 247),
        "amd64": (434, 424, 438, 247),
        "i686": (434, 424, 438, 284),
        "aarch64": (434, 424, 438, 95),
        "riscv64": (434, 424, 438, 95),
        "loongarch64": (434, 424, 438, 95),
        "armv7l": (434, 424, 438, 280),
        "ppc64le": (434, 424, 438, 272),
        "s390x": (434, 424, 438, 281),
    }
    for machine, numbers in expected.items():
        monkeypatch.setattr(_syscall, "_numbers", None)
        monkeypatch.setattr(platform, "machine", lambda m=machine: m)
        assert _syscall._syscall_numbers() == numbers, machine
    monkeypatch.setattr(_syscall, "_numbers", None)
    monkeypatch.setattr(platform, "machine", lambda: "mips64")
    with pytest.raises(UnsupportedError):
        _syscall._syscall_numbers()


def test_x32_abi_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_numbers", None)
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(ctypes, "sizeof", lambda t: 4)
    with pytest.raises(UnsupportedError, match="x32"):
        _syscall._syscall_numbers()


def test_get_libc_rejects_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_libc", None)
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(UnsupportedError):
        _syscall._get_libc()


def test_raise_errno_maps_enosys() -> None:
    with pytest.raises(UnsupportedError):
        _syscall._raise_errno(errno.ENOSYS)
    with pytest.raises(PidFdError) as excinfo:
        _syscall._raise_errno(errno.EPERM)
    assert excinfo.value.errno == errno.EPERM


def test_call_surfaces_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = SimpleNamespace(syscall=lambda *args: -1)
    monkeypatch.setattr(_syscall, "_get_libc", lambda: libc)
    ctypes.set_errno(errno.EBADF)
    with pytest.raises(PidFdError) as excinfo:
        _syscall.pidfd_open(os.getpid())
    assert excinfo.value.errno == errno.EBADF


def test_pidfd_open_marshals(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_call(nr: int, *args: object) -> int:
        calls.args = (nr, *args)
        return 42

    monkeypatch.setattr(_syscall, "_call", fake_call)
    assert _syscall.pidfd_open(1234, 0o4000) == 42
    nr, pid, flags = calls.args
    assert nr == _syscall._syscall_numbers()[0]
    assert (pid, flags) == (1234, 0o4000)


def test_pidfd_send_signal_marshals(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=[])

    def fake_call(nr: int, *args: object) -> int:
        calls.args = (nr, *args)
        return 0

    monkeypatch.setattr(_syscall, "_call", fake_call)
    _syscall.pidfd_send_signal(7, signal.SIGTERM, None, 0)
    nr, pidfd, sig, ref, flags = calls.args
    assert nr == _syscall._syscall_numbers()[1]
    assert (pidfd, sig, flags) == (7, signal.SIGTERM, 0)
    assert ref is None

    info = SigInfo()
    _syscall.pidfd_send_signal(7, signal.SIGTERM, info, 1)
    _, _, _, ref, flags = calls.args
    assert ref._obj is info
    assert flags == 1


def test_pidfd_getfd_marshals(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_call(nr: int, *args: object) -> int:
        calls.args = (nr, *args)
        return 33

    monkeypatch.setattr(_syscall, "_call", fake_call)
    assert _syscall.pidfd_getfd(7, 0, 0) == 33
    nr, pidfd, targetfd, flags = calls.args
    assert nr == _syscall._syscall_numbers()[2]
    assert (pidfd, targetfd, flags) == (7, 0, 0)


def test_waitid_marshals(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_call(nr: int, *args: object) -> int:
        calls.args = (nr, *args)
        return 0

    monkeypatch.setattr(_syscall, "_call", fake_call)
    info = SigInfo()
    _syscall.waitid(3, 9, info, 4)
    nr, idtype, upid, ref, options, rusage = calls.args
    assert nr == _syscall._syscall_numbers()[3]
    assert (idtype, upid, options, rusage) == (3, 9, 4, 0)
    assert ref._obj is info


def test_open_returns_pidfd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "pidfd_open", lambda pid, flags: 9)
    pf = PidFd.open(1234, OpenFlag.NONBLOCK)
    assert pf.fileno() == 9
    assert pf.detach() == 9  # hand the fake fd back without closing it


def test_wait_decodes_siginfo(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_waitid(idtype: int, upid: int, info: SigInfo, options: int) -> int:
        assert idtype == _syscall.P_PIDFD
        info.si_signo = signal.SIGCHLD
        info.si_code = int(WaitCode.CLD_KILLED)
        info.si_pid = 4242
        info.si_uid = 1000
        info.si_status = signal.SIGKILL
        return 0

    monkeypatch.setattr(_syscall, "waitid", fake_waitid)
    pf = PidFd(9)
    result = pf.wait(WaitFlag.WEXITED)
    pf.detach()
    assert result == WaitResult(
        pid=4242,
        uid=1000,
        signo=signal.SIGCHLD,
        code=int(WaitCode.CLD_KILLED),
        status=signal.SIGKILL,
    )


def test_signal_passes_siginfo(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake(pidfd: int, sig: int, info: SigInfo | None, flags: int) -> None:
        calls.args = (pidfd, sig, info, flags)

    monkeypatch.setattr(_syscall, "pidfd_send_signal", fake)
    pf = PidFd(9)
    pf.signal(signal.SIGUSR1)
    assert calls.args == (9, signal.SIGUSR1, None, 0)
    info = SigInfo()
    pf.signal(signal.SIGUSR1, siginfo=info, flags=SignalFlag.THREAD)
    assert calls.args == (9, signal.SIGUSR1, info, 1)
    pf.detach()


def test_getfd_returns_new_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "pidfd_getfd", lambda pidfd, fd, flags: 33)
    pf = PidFd(9)
    assert pf.getfd(0) == 33
    pf.detach()


def test_send_signal_convenience(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake(pidfd: int, sig: int, info: SigInfo | None, flags: int) -> None:
        calls.args = (pidfd, sig, info, flags)

    monkeypatch.setattr(_syscall, "pidfd_send_signal", fake)
    pf = PidFd(9)
    pidfd_send_signal(pf, signal.SIGTERM)
    assert calls.args == (9, signal.SIGTERM, None, 0)
    pf.detach()
    pidfd_send_signal(11, signal.SIGTERM)
    assert calls.args == (11, signal.SIGTERM, None, 0)


def test_close_only_closes_once() -> None:
    fd = os.open("/dev/null", os.O_RDONLY)
    pf = PidFd(fd)
    pf.close()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)
    pf.close()  # idempotent
    pf.close()


def test_del_closes_fd() -> None:
    fd = os.dup(0)
    PidFd(fd)
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)


def test_repr() -> None:
    pf = PidFd(9)
    assert repr(pf) == "PidFd(fd=9)"
    assert pf.detach() == 9
    assert repr(pf) == "PidFd(fd=closed)"
    with pytest.raises(ValueError, match="closed"):
        pf.detach()


def test_errors_carry_errno() -> None:
    err = PidFdError(errno.EACCES, "denied")
    assert err.errno == errno.EACCES
    assert isinstance(err, OSError)
    assert isinstance(UnsupportedError(errno.ENOSYS, "x"), PidFdError)
