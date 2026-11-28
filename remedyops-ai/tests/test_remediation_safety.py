"""Unit tests for sandbox-only verified rollback. No remote connections."""
import hashlib

import remediation_safety as safety


def digest(data):
    return hashlib.sha256(data).hexdigest()


def make_files(tmp_path):
    target = tmp_path / "config.conf"
    backup = tmp_path / "backup.bin"
    target.write_bytes(b"changed=yes\n")
    backup.write_bytes(b"changed=no\n")
    return target, backup


def test_verified_restoration(tmp_path):
    target, backup = make_files(tmp_path)
    target.chmod(0o640)
    result = safety.restore_backup_after_verification_failure(
        target, backup, digest(backup.read_bytes())
    )
    assert result == "verification_failed_rolled_back"
    assert target.read_bytes() == b"changed=no\n"
    assert (target.stat().st_mode & 0o777) == 0o640


def test_corrupted_backup_does_not_modify_target(tmp_path):
    target, backup = make_files(tmp_path)
    result = safety.restore_backup_after_verification_failure(target, backup, digest(b"other"))
    assert result == "rollback_failed"
    assert target.read_bytes() == b"changed=yes\n"


def test_missing_backup_returns_failure(tmp_path):
    target, backup = make_files(tmp_path)
    backup.unlink()
    assert safety.restore_backup_after_verification_failure(target, backup, digest(b"changed=no\n")) == "rollback_failed"


def test_symlink_target_is_rejected(tmp_path):
    target, backup = make_files(tmp_path)
    linked = tmp_path / "linked.conf"
    linked.symlink_to(target)
    assert safety.restore_backup_after_verification_failure(linked, backup, digest(backup.read_bytes())) == "rollback_failed"
    assert target.read_bytes() == b"changed=yes\n"


def test_failed_atomic_replace_reports_failure_and_cleans_temp(tmp_path, monkeypatch):
    target, backup = make_files(tmp_path)
    def fail_replace(*_args):
        raise OSError("simulated failure")
    monkeypatch.setattr(safety.os, "replace", fail_replace)
    result = safety.restore_backup_after_verification_failure(target, backup, digest(backup.read_bytes()))
    assert result == "rollback_failed"
    assert target.read_bytes() == b"changed=yes\n"
    assert list(tmp_path.glob(".remedyops-restore-*")) == []


def test_automatic_restore_rejects_failed_postwrite_verification(tmp_path, monkeypatch):
    target, backup = make_files(tmp_path)
    expected = digest(backup.read_bytes())
    observed = []

    def reject(path, expected_hash):
        observed.append((path, expected_hash, path.read_bytes()))
        return False

    monkeypatch.setattr(safety, "verify_restored_bytes", reject)
    result = safety.restore_backup_after_verification_failure(target, backup, expected)
    assert result == "rollback_failed"
    assert observed == [(target, expected, b"changed=no\n")]
    assert list(tmp_path.glob(".remedyops-restore-*")) == []


def test_backup_hardlink_rejected(tmp_path):
    target, backup = make_files(tmp_path)
    import os
    os.link(backup, tmp_path / "alias.bin")
    assert safety.restore_backup_after_verification_failure(
        target, backup, digest(b"changed=no\n")
    ) == "rollback_failed"
    assert target.read_bytes() == b"changed=yes\n"
    assert not list(tmp_path.glob(".remedyops-restore-*"))


def test_backup_fifo_rejected_without_blocking(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path
    target, backup = make_files(tmp_path)
    backup.unlink()
    os.mkfifo(backup)
    code = (
        "from pathlib import Path; import sys; "
        "from remediation_safety import restore_backup_after_verification_failure as restore; "
        "assert restore(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]) == 'rollback_failed'"
    )
    subprocess.run(
        [sys.executable, "-c", code, str(target), str(backup), digest(b"changed=no\n")],
        cwd=Path(safety.__file__).parent, timeout=5, check=True,
    )
    assert target.read_bytes() == b"changed=yes\n"
    assert not list(tmp_path.glob(".remedyops-restore-*"))


def test_unverified_restore_temp_stays_private(tmp_path, monkeypatch):
    target, backup = make_files(tmp_path)
    target.chmod(0o644)
    real_open = safety.os.open
    observed = []

    def inspect_open(path, *args, **kwargs):
        if path == backup:
            temps = list(tmp_path.glob(".remedyops-restore-*"))
            assert len(temps) == 1
            observed.append(temps[0].stat().st_mode & 0o777)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(safety.os, "open", inspect_open)
    assert safety.restore_backup_after_verification_failure(
        target, backup, digest(b"wrong")
    ) == "rollback_failed"
    assert observed == [0o600]
    assert target.read_bytes() == b"changed=yes\n"
    assert not list(tmp_path.glob(".remedyops-restore-*"))
