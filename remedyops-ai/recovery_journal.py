"""Durable, sandbox-only remediation intent journal.

An unresolved intent blocks further writes until a human investigates.
This module detects interrupted operations; it never auto-restores files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FINISHED = frozenset({"applied", "verification_failed_rolled_back", "rolled_back"})
_OUTCOMES = _FINISHED | {"rollback_failed"}


class RecoveryJournalError(RuntimeError):
    """Journal integrity or state-transition failure; fail closed."""


def _check_id(change_id: str) -> None:
    if not isinstance(change_id, str) or not _HEX32.fullmatch(change_id):
        raise RecoveryJournalError("Invalid change identifier")


def _journal_path(state_dir: Path, change_id: str) -> Path:
    _check_id(change_id)
    return Path(state_dir) / f"journal-{change_id}.json"


def _atomic_durable_write(path: Path, payload: bytes) -> None:
    """Write mode-0600 file and fsync file + parent directory."""
    tmp = None
    try:
        fd, name = tempfile.mkstemp(prefix=".remedyops-journal-", dir=path.parent)
        tmp = Path(name)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        tmp = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def write_durable_state(path: Path, data: bytes) -> None:
    """Durably create/replace a private state record (not a target config).

    Refuse symlinks, special files, and hardlinked records. The state
    directory must remain private to the controller; this is not a
    distributed transaction or a defense against a hostile local writer.
    """
    path = Path(path)
    if path.is_symlink():
        raise RecoveryJournalError("Unsafe state record symlink")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise RecoveryJournalError("Unsafe state record")
    _atomic_durable_write(path, data)


def write_durable_backup(path: Path, data: bytes) -> None:
    """Persist a backup before recording an intent or modifying a target."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise RecoveryJournalError("Backup already exists")
    _atomic_durable_write(path, data)


def record_intent(
    state_dir: Path, change_id: str, finding_id: str, before_hash: str, after_hash: str,
    operation: str = "apply",
) -> None:
    if operation not in {"apply", "rollback"}:
        raise RecoveryJournalError("Invalid journal operation")
    path = _journal_path(state_dir, change_id)
    if path.exists() or path.is_symlink():
        raise RecoveryJournalError("Journal already exists")
    if not isinstance(finding_id, str) or not re.fullmatch(r"[A-Z0-9-]{1,32}", finding_id):
        raise RecoveryJournalError("Invalid finding identifier")
    if not all(isinstance(v, str) and _HEX64.fullmatch(v) for v in (before_hash, after_hash)):
        raise RecoveryJournalError("Invalid content hash")
    obj = {
        "version": 1,
        "change_id": change_id,
        "finding_id": finding_id,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "status": "prepared",
        "operation": operation,
    }
    _atomic_durable_write(path, json.dumps(obj, sort_keys=True).encode("utf-8"))


def _load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise RecoveryJournalError("Unsafe or missing journal file")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise RecoveryJournalError("Unreadable journal") from exc
    if not isinstance(obj, dict) or obj.get("version") != 1:
        raise RecoveryJournalError("Unsupported journal format")
    cid = obj.get("change_id")
    _check_id(cid)
    if path.name != f"journal-{cid}.json":
        raise RecoveryJournalError("Journal filename mismatch")
    operation = obj.get("operation", "apply")  # Historical journals had no operation.
    if operation not in {"apply", "rollback"}:
        raise RecoveryJournalError("Invalid journal operation")
    valid = ({"prepared", "rolled_back"} if operation == "rollback" else
             {"prepared", "applied", "verification_failed_rolled_back", "rollback_failed"})
    if obj.get("status") not in valid:
        raise RecoveryJournalError("Invalid journal status")
    if not isinstance(obj.get("finding_id"), str):
        raise RecoveryJournalError("Missing finding identifier")
    for field in ("before_hash", "after_hash"):
        value = obj.get(field)
        if not isinstance(value, str) or not _HEX64.fullmatch(value):
            raise RecoveryJournalError("Invalid journal hash")
    return obj


def record_outcome(state_dir: Path, change_id: str, status: str) -> None:
    if status not in _OUTCOMES:
        raise RecoveryJournalError("Unsupported remediation outcome")
    path = _journal_path(state_dir, change_id)
    obj = _load(path)
    if obj["status"] != "prepared":
        raise RecoveryJournalError("Journal is not prepared")
    if (obj.get("operation", "apply") == "rollback") != (status == "rolled_back"):
        raise RecoveryJournalError("Journal operation/outcome mismatch")
    obj["status"] = status
    _atomic_durable_write(path, json.dumps(obj, sort_keys=True).encode("utf-8"))


def unresolved_changes(state_dir: Path) -> list[dict[str, str]]:
    """Detect interrupted or failed operations without modifying targets."""
    pending = []
    for path in sorted(Path(state_dir).glob("journal-*.json")):
        obj = _load(path)  # Corruption must raise, never silently disappear.
        if obj["status"] not in _FINISHED:
            pending.append({
                "change_id": obj["change_id"],
                "finding_id": obj["finding_id"],
                "status": obj["status"],
            })
    return pending
