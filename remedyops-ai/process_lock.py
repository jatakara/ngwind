"""Fail-closed cross-process serialization for the local sandbox state.

Linux/POSIX advisory flock only. Every cooperating worker must use the same
state directory on a filesystem that provides reliable flock semantics.
This is not a distributed lock or a substitute for fencing tokens.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import threading


class RemediationLockBusy(RuntimeError):
    """Another worker owns the sandbox mutation lock."""


class RemediationLockError(RuntimeError):
    """The lock could not be safely established; block mutations."""


class InterProcessLock:
    """Serialize local threads and processes around a shared state directory.

    Non-reentrant: a handler must acquire it once at its outermost boundary.
    The kernel releases flock when the owning process exits or is killed.
    """

    def __init__(self, state_dir: Path):
        self._path = Path(state_dir) / ".remedyops.lock"
        self._thread_lock = threading.Lock()
        self._fd: int | None = None

    def __enter__(self):
        self._thread_lock.acquire()
        fd = None
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            fd = os.open(self._path, flags, 0o600)
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise RemediationLockError("Unsafe sandbox lock file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fd = fd
            return self
        except BlockingIOError as exc:
            raise RemediationLockBusy("Sandbox mutation already in progress") from exc
        except RemediationLockError:
            raise
        except OSError as exc:
            raise RemediationLockError("Sandbox lock unavailable") from exc
        finally:
            if self._fd is None:
                if fd is not None:
                    os.close(fd)
                self._thread_lock.release()

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
                self._thread_lock.release()
        return False
