"""Rollback backup read security tests: no production targets."""
import os
import pytest
from backup_safety import read_private_backup, UnsafeBackupError

def test_valid_backup(tmp_path):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"safe")
    assert read_private_backup(p) == b"safe"

def test_symlink_rejected(tmp_path):
    outside = tmp_path / "secret"
    outside.write_bytes(b"private")
    link = tmp_path / "backup.bin"
    link.symlink_to(outside)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(link)

def test_hardlink_rejected(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    link = tmp_path / "backup.bin"
    os.link(source, link)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(link)

def test_oversize_rejected(tmp_path):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"x" * 17)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p, max_bytes=16)

def test_writable_directory_rejected(tmp_path):
    tmp_path.chmod(0o777)
    p = tmp_path / "backup.bin"
    p.write_bytes(b"data")
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p)

def test_directory_as_backup_rejected(tmp_path):
    with pytest.raises(UnsafeBackupError):
        read_private_backup(tmp_path)

@pytest.mark.parametrize("mode", [0o622, 0o646, 0o666])
def test_writable_backup_inode_rejected(tmp_path, mode):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"untrusted replacement")
    p.chmod(mode)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p)

@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_nonwritable_backup_inode_allowed(tmp_path, mode):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"trusted")
    p.chmod(mode)
    assert read_private_backup(p) == b"trusted"
