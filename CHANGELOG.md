# Changelog

## [0.1.0] - Unreleased

Initial release.

- PidFd class wrapping pidfd_open(2), with fileno(), close(), detach(),
  context manager support and OpenFlag bits (NONBLOCK, THREAD).
- signal() via pidfd_send_signal(2) with optional SigInfo and the
  SignalFlag scope bits, plus the pidfd_send_signal() module-level
  convenience.
- wait() via the raw waitid(2) syscall with idtype P_PIDFD, returning a
  typed WaitResult. WaitFlag and WaitCode enums cover the linux/wait.h
  constants.
- getfd() via pidfd_getfd(2) for duplicating another process's file
  descriptors under the PTRACE_MODE_ATTACH_REALCREDS rules.
- SigInfo ctypes model of the kernel siginfo_t for waitid output and
  signal input.
- Per-architecture syscall numbers for x86_64, i386, aarch64, riscv,
  loongarch64, arm, powerpc and s390. Unknown arches and the x32 ABI
  raise UnsupportedError.
- Typed errors: PidFdError and UnsupportedError carry the kernel errno.
