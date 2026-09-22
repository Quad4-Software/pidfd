# SPDX-License-Identifier: 0BSD
"""Exception types raised by pidfd."""


class PidFdError(OSError):
    """A pidfd syscall failed."""


class UnsupportedError(PidFdError):
    """The running kernel or architecture lacks the requested pidfd feature."""
