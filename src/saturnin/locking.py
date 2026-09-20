"""Cooperative file locking for concurrent board access.

Several squads run in parallel worktrees against the same board, so a plain
read-modify-write is a lost update waiting to happen. Every mutation takes an
exclusive ``flock`` on a sidecar lock file; readers take a shared one.
"""

from __future__ import annotations

import errno
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DEFAULT_TIMEOUT = 10.0

try:  # pragma: no cover - platform dependent
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None  # type: ignore[assignment]


class LockTimeout(RuntimeError):
    """Raised when a lock could not be acquired in time."""


@contextmanager
def file_lock(
    path: Path, *, exclusive: bool = True, timeout: float = DEFAULT_TIMEOUT
) -> Iterator[None]:
    """Lock ``path`` (a ``.lock`` sidecar is created next to it).

    Falls back to a no-op when the platform has no ``fcntl``; the atomic
    ``os.replace`` in :mod:`saturnin.board` still prevents torn files.
    """
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:  # pragma: no cover - platform dependent
        yield
        return
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    handle = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(handle, mode | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):  # pragma: no cover
                    raise
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"could not lock {path.name} within {timeout}s; "
                        "another squad is probably mid-write"
                    ) from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        os.close(handle)
