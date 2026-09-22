# SPDX-License-Identifier: 0BSD
"""Tests against the running kernel.

Each test spawns a real child process, opens a pidfd for it and checks
signaling, polling, waiting and fd duplication against the kernel. All
children are reaped before the test ends.
"""

import contextlib
import errno
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import pidfd
from pidfd import (
    OpenFlag,
    PidFd,
    PidFdError,
    SigInfo,
    WaitCode,
    WaitFlag,
    _syscall,
    pidfd_send_signal,
)

from .conftest import requires_linux

SLEEPY = [sys.executable, "-c", "import time; time.sleep(60)"]


def _spawn(argv: list[str] | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(argv or SLEEPY, stdin=subprocess.DEVNULL)


def _reap(proc: subprocess.Popen[bytes], pf: PidFd | None) -> None:
    """Kill the child, reap it through the pidfd when given, and wait."""
    proc.kill()
    if pf is not None:
        with contextlib.suppress(OSError):
            pf.wait()
    proc.wait()


@requires_linux
def test_open_self() -> None:
    pf = PidFd.open(os.getpid())
    try:
        assert pf.fileno() > 0
        assert not pf.closed
        assert int(pf) == pf.fileno()
        assert repr(pf) == f"PidFd(fd={pf.fileno()})"
    finally:
        pf.close()
    assert pf.closed
    assert pf.fileno() == -1
    assert repr(pf) == "PidFd(fd=closed)"
    pf.close()  # double close is a no-op


@requires_linux
def test_open_nonexistent_pid() -> None:
    with pytest.raises(PidFdError) as excinfo:
        PidFd.open(2**30)
    assert excinfo.value.errno == errno.ESRCH


@requires_linux
def test_open_invalid_pid() -> None:
    with pytest.raises(PidFdError) as excinfo:
        PidFd.open(-5)
    assert excinfo.value.errno == errno.EINVAL
    with pytest.raises(PidFdError) as excinfo:
        PidFd.open(0)
    assert excinfo.value.errno == errno.EINVAL


@requires_linux
def test_open_bad_flags() -> None:
    with pytest.raises(PidFdError) as excinfo:
        PidFd.open(os.getpid(), 1 << 20)
    assert excinfo.value.errno == errno.EINVAL


@requires_linux
def test_open_nonblock_flag() -> None:
    with PidFd.open(os.getpid(), OpenFlag.NONBLOCK) as pf:
        assert not os.get_blocking(pf.fileno())
    with PidFd.open(os.getpid()) as pf:
        assert os.get_blocking(pf.fileno())


@requires_linux
def test_ctor_rejects_negative_fd() -> None:
    with pytest.raises(ValueError, match="negative"):
        PidFd(-3)


@requires_linux
def test_wrap_existing_fd() -> None:
    fd = _syscall.pidfd_open(os.getpid(), 0)
    pf = PidFd(fd)
    pf.close()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)


@requires_linux
def test_ops_on_closed_raise() -> None:
    pf = PidFd.open(os.getpid())
    pf.close()
    with pytest.raises(ValueError, match="closed"):
        pf.signal(signal.SIGKILL)
    with pytest.raises(ValueError, match="closed"):
        pf.wait()
    with pytest.raises(ValueError, match="closed"):
        pf.getfd(0)
    with pytest.raises(ValueError, match="closed"):
        int(pf)


@requires_linux
def test_poll_readable_after_exit() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            proc.kill()
            poller = select.poll()
            poller.register(pf.fileno(), select.POLLIN)
            events = poller.poll(10000)
            assert events, "pidfd never became readable"
            assert events[0][1] & select.POLLIN
            pf.wait()
    finally:
        _reap(proc, None)


@requires_linux
def test_signal_kills_child() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            pf.signal(signal.SIGKILL)
            result = pf.wait()
            assert result.signo == signal.SIGCHLD
            assert result.pid == proc.pid
            assert result.uid == os.getuid()
            assert result.code == WaitCode.CLD_KILLED
            assert result.status == signal.SIGKILL
    finally:
        _reap(proc, None)


@requires_linux
def test_wait_reports_exit_status() -> None:
    proc = _spawn([sys.executable, "-c", "import sys; sys.exit(42)"])
    try:
        with PidFd.open(proc.pid) as pf:
            result = pf.wait()
            assert result.signo == signal.SIGCHLD
            assert result.pid == proc.pid
            assert result.code == WaitCode.CLD_EXITED
            assert result.status == 42
    finally:
        _reap(proc, None)


@requires_linux
def test_wait_wnohang_on_running_child() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            result = pf.wait(WaitFlag.WEXITED | WaitFlag.WNOHANG)
            assert result.signo == 0
            assert result.pid == 0
    finally:
        _reap(proc, None)


@requires_linux
def test_wait_nonblock_pidfd_raises_eagain() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid, OpenFlag.NONBLOCK) as pf:
            with pytest.raises(PidFdError) as excinfo:
                pf.wait()
            assert excinfo.value.errno == errno.EAGAIN
    finally:
        _reap(proc, None)


@requires_linux
def test_wait_non_child_raises_echild() -> None:
    with PidFd.open(os.getpid()) as pf:
        with pytest.raises(PidFdError) as excinfo:
            pf.wait(WaitFlag.WEXITED | WaitFlag.WNOHANG)
        assert excinfo.value.errno == errno.ECHILD


@requires_linux
def test_signal_reaped_process_raises_esrch() -> None:
    proc = _spawn([sys.executable, "-c", "pass"])
    try:
        with PidFd.open(proc.pid) as pf:
            pf.wait()
            with pytest.raises(PidFdError) as excinfo:
                pf.signal(signal.SIGKILL)
            assert excinfo.value.errno == errno.ESRCH
    finally:
        _reap(proc, None)


@requires_linux
def test_signal_bad_flags() -> None:
    with PidFd.open(os.getpid()) as pf:
        with pytest.raises(PidFdError) as excinfo:
            pf.signal(signal.SIGTERM, flags=1 << 3)
        assert excinfo.value.errno == errno.EINVAL


@requires_linux
def test_signal_with_siginfo() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            info = SigInfo()
            info.si_signo = signal.SIGKILL
            info.si_code = -1  # SI_QUEUE: si_code must be negative
            info.si_pid = os.getpid()
            info.si_uid = os.getuid()
            pf.signal(signal.SIGKILL, siginfo=info)
            result = pf.wait()
            assert result.code == WaitCode.CLD_KILLED
    finally:
        _reap(proc, None)


@requires_linux
def test_pidfd_send_signal_convenience() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            pidfd_send_signal(pf, signal.SIGKILL)
            result = pf.wait()
            assert result.code == WaitCode.CLD_KILLED
    finally:
        _reap(proc, None)


@requires_linux
def test_pidfd_send_signal_raw_fd() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            pidfd_send_signal(pf.fileno(), signal.SIGKILL)
            result = pf.wait()
            assert result.code == WaitCode.CLD_KILLED
    finally:
        _reap(proc, None)


@requires_linux
def test_pidfd_send_signal_proc_fd() -> None:
    proc = _spawn()
    try:
        fd = os.open(f"/proc/{proc.pid}", os.O_RDONLY | os.O_DIRECTORY)
        try:
            pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
        proc.wait(timeout=10)
        assert proc.returncode == -signal.SIGKILL
    finally:
        _reap(proc, None)


@requires_linux
def test_getfd() -> None:
    proc = _spawn()
    try:
        with PidFd.open(proc.pid) as pf:
            try:
                dup = pf.getfd(0)
            except PidFdError as exc:
                if exc.errno == errno.EPERM:
                    pytest.skip(f"ptrace access denied: {exc}")
                raise
            try:
                assert Path(f"/proc/self/fd/{dup}").readlink() == Path("/dev/null")
            finally:
                os.close(dup)
            with pytest.raises(PidFdError) as excinfo:
                pf.getfd(9999)
            assert excinfo.value.errno == errno.EBADF
    finally:
        _reap(proc, None)


def test_version_format() -> None:
    major, minor, patch = pidfd.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0


def test_all_exports_resolve() -> None:
    for name in pidfd.__all__:
        assert getattr(pidfd, name) is not None, name
