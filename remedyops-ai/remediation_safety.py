"""Sandbox-only verified restoration after a failed remediation check.

Never invoke this module against production hosts or arbitrary remote paths.
"""

import hashlib
import hmac
import os
from pathlib import Path
import stat
import tempfile


def restore_backup_after_verification_failure(
    target: Path, backup: Path, expected_before_hash: str
) -> str:
    """Restore known-good bytes or return an explicit failure status.

    Uses a same-directory temporary file and atomic rename to avoid leaving a
    partially restored file. A successful return means the resulting bytes
    matched the recorded SHA-256 at the time of verification, not that a
    broader service health check passed.
    """
    temp_path = None
    try:
        if target.is_symlink() or backup.is_symlink() or not target.is_file():
            return "rollback_failed"
        original = backup.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        if not hmac.compare_digest(digest, expected_before_hash):
            return "rollback_failed"

        original_mode = stat.S_IMODE(target.stat().st_mode)
        fd, name = tempfile.mkstemp(prefix=".remedyops-restore-", dir=target.parent)
        temp_path = Path(name)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), original_mode)
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target)
        temp_path = None
        restored = hashlib.sha256(target.read_bytes()).hexdigest()
        if not hmac.compare_digest(restored, expected_before_hash):
            return "rollback_failed"
        return "verification_failed_rolled_back"
    except (OSError, ValueError):
        return "rollback_failed"
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
