"""Post-rollback verification regression tests; no remote hosts involved."""

import hashlib

from remediation_safety import verify_restored_bytes


def test_matching_restored_bytes_are_accepted(tmp_path):
    target = tmp_path / "config"
    target.write_bytes(b"audit_enabled=yes\n")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    assert verify_restored_bytes(target, digest)


def test_mismatched_restored_bytes_fail_closed(tmp_path):
    target = tmp_path / "config"
    target.write_bytes(b"audit_enabled=no\n")
    expected = hashlib.sha256(b"audit_enabled=yes\n").hexdigest()
    assert not verify_restored_bytes(target, expected)


def test_missing_target_fails_closed(tmp_path):
    assert not verify_restored_bytes(tmp_path / "missing", "0" * 64)


def test_symlink_target_fails_closed(tmp_path):
    actual = tmp_path / "actual"
    actual.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(actual)
    assert not verify_restored_bytes(link, hashlib.sha256(b"safe").hexdigest())


def test_hardlinked_target_fails_closed(tmp_path):
    target = tmp_path / "config"
    target.write_bytes(b"safe")
    (tmp_path / "alias").hardlink_to(target)
    assert not verify_restored_bytes(target, hashlib.sha256(b"safe").hexdigest())


def test_directory_target_fails_closed(tmp_path):
    assert not verify_restored_bytes(tmp_path, hashlib.sha256(b"").hexdigest())


def test_non_ascii_expected_digest_fails_closed(tmp_path):
    target = tmp_path / "config"
    target.write_bytes(b"safe")
    assert not verify_restored_bytes(target, "\u00e9" * 64)


def test_in_place_mutation_during_verification_fails_closed(tmp_path, monkeypatch):
    """Metadata change during descriptor read must not report success."""
    import os
    from types import SimpleNamespace
    import remediation_safety

    target = tmp_path / "config"
    target.write_bytes(b"safe")
    expected = hashlib.sha256(b"safe").hexdigest()
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(fd):
        nonlocal calls
        calls += 1
        current = real_fstat(fd)
        if calls == 2:
            values = {name: getattr(current, name) for name in (
                "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
            )}
            values["st_mtime_ns"] += 1
            return SimpleNamespace(**values)
        return current

    monkeypatch.setattr(remediation_safety.os, "fstat", changing_fstat)
    assert not verify_restored_bytes(target, expected)
    assert calls == 2


def test_target_path_replaced_during_hashing_fails_closed(tmp_path, monkeypatch):
    """Hashing the original inode must not validate a replacement pathname."""
    import os
    import remediation_safety

    target = tmp_path / "config"
    target.write_bytes(b"safe")
    expected = hashlib.sha256(b"safe").hexdigest()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"safe")
    real_fstat = os.fstat
    calls = 0

    def swap_after_read(fd):
        nonlocal calls
        calls += 1
        result = real_fstat(fd)
        if calls == 2:
            os.replace(replacement, target)
        return result

    monkeypatch.setattr(remediation_safety.os, "fstat", swap_after_read)
    assert not verify_restored_bytes(target, expected)
    assert calls == 2


def test_target_path_changed_to_symlink_during_hashing_fails_closed(tmp_path, monkeypatch):
    """A post-open symlink swap cannot be accepted as a verified restore."""
    import os
    import remediation_safety

    target = tmp_path / "config"
    target.write_bytes(b"safe")
    expected = hashlib.sha256(b"safe").hexdigest()
    real_fstat = os.fstat
    calls = 0

    def swap_to_symlink(fd):
        nonlocal calls
        calls += 1
        result = real_fstat(fd)
        if calls == 2:
            target.unlink()
            target.symlink_to(tmp_path / "elsewhere")
        return result

    monkeypatch.setattr(remediation_safety.os, "fstat", swap_to_symlink)
    assert not verify_restored_bytes(target, expected)
    assert calls == 2
