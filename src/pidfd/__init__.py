# SPDX-License-Identifier: 0BSD
"""Python bindings for Linux pidfds.

A pidfd is a file descriptor referring to a process. It is a stable
handle: signaling through it can never hit a recycled pid, it becomes
pollable-readable when the task exits, and it can be waited on with
waitid(2) or used to duplicate the task's file descriptors with
pidfd_getfd(2). Everything goes through raw syscalls via ctypes. There
are no runtime dependencies.

Kernel references: pidfd_open(2), pidfd_send_signal(2), pidfd_getfd(2),
waitid(2).
"""

from .errors import PidFdError, UnsupportedError
from .pidfd import (
    OpenFlag,
    PidFd,
    SigInfo,
    SignalFlag,
    WaitCode,
    WaitFlag,
    WaitResult,
    pidfd_send_signal,
)

__version__ = "0.1.0"

__all__ = [
    "OpenFlag",
    "PidFd",
    "PidFdError",
    "SigInfo",
    "SignalFlag",
    "UnsupportedError",
    "WaitCode",
    "WaitFlag",
    "WaitResult",
    "__version__",
    "pidfd_send_signal",
]
