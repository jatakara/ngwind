"""Atomic, sandbox-only replacement of a known configuration file.

This helper does not provide multi-host fencing or preserve ACLs/SELinux labels.
Only use for files owned by the sandbox process on a local POSIX filesystem.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import tempfile


class AtomicConfigError(RuntimeError):
    """The replacement was rejected or could not be made durable."""


def atomic_replace_config(target: Path, payload: bytes, expected_hash: str) -> None:
    """Atomically replace a regular sandbox file after a SHA-256 precondition.

    The caller must hold the shared mutation lock and persist a recovery intent
    first. A raised error may occur *after* rename; the caller must leave that
    intent unresolved for manual inspection, never assume the old file survived.
    """
    target = Path(target)
    if not isinstance(payload, bytes):
        raise AtomicConfigError("Payload must be bytes")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise AtomicConfigError("Invalid expected SHA-256")
    temp_path = None
    try:
        before = os.lstat(target)  # Never follow a symlink.
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
        ):
            raise AtomicConfigError("Unsafe sandbox target")
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise AtomicConfigError("Target changed before verification")
            actual = hashlib.sha256(stream.read()).hexdigest()
        if not hmac.compare_digest(actual, expected_hash):
            raise AtomicConfigError("Target changed since planning")
        current = os.lstat(target)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise AtomicConfigError("Target replaced during verification")

        fd, name = tempfile.mkstemp(prefix=".remedyops-config-", dir=target.parent)
        temp_path = Path(name)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(before.st_mode))
            os.fchown(stream.fileno(), before.st_uid, before.st_gid)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

        # A crash before rename leaves the old file intact; after rename, the
        # new complete file is visible. Directory fsync persists the rename.
        os.replace(temp_path, target)
        temp_path = None
        dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if not hmac.compare_digest(
            hashlib.sha256(target.read_bytes()).hexdigest(),
            hashlib.sha256(payload).hexdigest(),
        ):
            raise AtomicConfigError("Post-write content verification failed")
    except (OSError, ValueError) as exc:
        raise AtomicConfigError("Atomic sandbox replacement failed") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
