"""Local sandbox atomic-write regression tests; no network or production access."""
import hashlib
import os

import pytest

import atomic_config as atomic


def digest(value):
    return hashlib.sha256(value).hexdigest()


def test_atomic_write_preserves_mode_and_exact_bytes(tmp_path):
    target = tmp_path / "config.conf"
    target.write_bytes(b"old=yes\n")
    target.chmod(0o640)
    atomic.atomic_replace_config(target, b"new=no\n", digest(b"old=yes\n"))
    assert target.read_bytes() == b"new=no\n"
    assert target.stat().st_mode & 0o777 == 0o640
    assert list(tmp_path.glob(".remedyops-config-*")) == []


def test_stale_precondition_does_not_overwrite(tmp_path):
    target = tmp_path / "config.conf"
    target.write_bytes(b"modified=externally\n")
    with pytest.raises(atomic.AtomicConfigError):
        atomic.atomic_replace_config(target, b"desired=yes\n", digest(b"old=yes\n"))
    assert target.read_bytes() == b"modified=externally\n"


def test_symlink_target_does_not_modify_outside_file(tmp_path):
    outside = tmp_path / "outside.conf"
    outside.write_bytes(b"untouched\n")
    link = tmp_path / "config.conf"
    link.symlink_to(outside)
    with pytest.raises(atomic.AtomicConfigError):
        atomic.atomic_replace_config(link, b"changed\n", digest(b"untouched\n"))
    assert outside.read_bytes() == b"untouched\n"


def test_hardlinked_target_is_rejected(tmp_path):
    target = tmp_path / "config.conf"
    target.write_bytes(b"original\n")
    os.link(target, tmp_path / "alias.conf")
    with pytest.raises(atomic.AtomicConfigError):
        atomic.atomic_replace_config(target, b"new\n", digest(b"original\n"))
    assert target.read_bytes() == b"original\n"


def test_failed_rename_preserves_original_and_cleans_temp(tmp_path, monkeypatch):
    target = tmp_path / "config.conf"
    target.write_bytes(b"original\n")

    def fail_rename(*_args):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(atomic.os, "replace", fail_rename)
    with pytest.raises(atomic.AtomicConfigError):
        atomic.atomic_replace_config(target, b"new\n", digest(b"original\n"))
    assert target.read_bytes() == b"original\n"
    assert list(tmp_path.glob(".remedyops-config-*")) == []


def test_interruption_before_rename_preserves_original(tmp_path, monkeypatch):
    target = tmp_path / "config.conf"
    target.write_bytes(b"original\n")

    def interrupt(*_args):
        raise KeyboardInterrupt("simulated interruption before rename")

    monkeypatch.setattr(atomic.os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        atomic.atomic_replace_config(target, b"new\n", digest(b"original\n"))
    assert target.read_bytes() == b"original\n"
    assert list(tmp_path.glob(".remedyops-config-*")) == []


def test_directory_fsync_failure_is_not_reported_as_success(tmp_path, monkeypatch):
    target = tmp_path / "config.conf"
    target.write_bytes(b"original\n")
    original_fsync = atomic.os.fsync
    calls = 0

    def fail_directory_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated directory sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(atomic.os, "fsync", fail_directory_fsync)
    with pytest.raises(atomic.AtomicConfigError):
        atomic.atomic_replace_config(target, b"new\n", digest(b"original\n"))
    # The rename may already have succeeded. Caller must keep journal prepared.
    assert target.read_bytes() == b"new\n"
    assert list(tmp_path.glob(".remedyops-config-*")) == []
