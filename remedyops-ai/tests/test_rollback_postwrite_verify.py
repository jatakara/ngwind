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
