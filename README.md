# pidfd

[![CI](https://github.com/Quad4-Software/pidfd/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/pidfd/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/pidfd/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/pidfd/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/pidfd/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/pidfd)
[![PyPI](https://img.shields.io/pypi/v/pidfd.svg)](https://pypi.org/project/pidfd/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Dependency-free Python bindings for Linux pidfds. A pidfd is a file
descriptor referring to a process: a stable handle that can never hit a
recycled pid, becomes readable when the task exits, can be waited on
with waitid(2), and can duplicate the task's file descriptors with
pidfd_getfd(2). Everything goes through pidfd_open(2),
pidfd_send_signal(2), pidfd_getfd(2) and waitid(2) via ctypes. There
are no runtime dependencies.

Requires Python 3.10+ and Linux.

## Install

    pip install pidfd

## Usage

```python
import select, signal, subprocess
from pidfd import PidFd, WaitCode

proc = subprocess.Popen(["sleep", "30"])
with PidFd.open(proc.pid) as pf:
    # poll(2) reports the fd readable once the task is a zombie
    pf.signal(signal.SIGKILL)

    poller = select.poll()
    poller.register(pf.fileno(), select.POLLIN)
    poller.poll()

    result = pf.wait()  # waitid(P_PIDFD)
    assert result.code == WaitCode.CLD_KILLED
```

`PidFd.open(pid, OpenFlag.NONBLOCK)` makes `wait()` fail with EAGAIN
instead of blocking. `pf.getfd(fd)` duplicates one of the target's open
fds (ptrace access rules apply).

## Development

    uv sync --group dev
    make check

License: 0BSD. Quad4 Software, https://quad4.io
