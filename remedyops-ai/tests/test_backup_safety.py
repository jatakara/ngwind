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


def test_foreign_owned_backup_inode_rejected(tmp_path, monkeypatch):
    """Simulate foreign ownership without chown/root privileges."""
    import stat
    from types import SimpleNamespace
    import backup_safety
    p = tmp_path / "backup.bin"
    p.write_bytes(b"private")
    original = backup_safety.os.fstat
    uid = os.geteuid()

    def foreign_file(fd):
        st = original(fd)
        if stat.S_ISREG(st.st_mode):
            return SimpleNamespace(st_mode=st.st_mode, st_nlink=st.st_nlink,
                                   st_size=st.st_size, st_uid=uid + 1)
        return st

    monkeypatch.setattr(backup_safety.os, "fstat", foreign_file)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p)


def test_foreign_owned_backup_directory_rejected(tmp_path, monkeypatch):
    """A safe file inside an untrusted parent is not accepted."""
    import stat
    from types import SimpleNamespace
    import backup_safety
    p = tmp_path / "backup.bin"
    p.write_bytes(b"private")
    original = backup_safety.os.fstat
    uid = os.geteuid()

    def foreign_directory(fd):
        st = original(fd)
        if stat.S_ISDIR(st.st_mode):
            return SimpleNamespace(st_mode=st.st_mode, st_uid=uid + 1)
        return st

    monkeypatch.setattr(backup_safety.os, "fstat", foreign_directory)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p)


@pytest.mark.parametrize("limit", [-1, True, "100"])
def test_invalid_backup_limit_rejected(tmp_path, limit):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"data")
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p, max_bytes=limit)



def test_backup_modified_during_read_rejected(tmp_path, monkeypatch):
    """Deterministically simulate a metadata change between the two fstat calls."""
    import stat
    import backup_safety
    p = tmp_path / "backup.bin"
    p.write_bytes(b"trusted")
    original = backup_safety.os.fstat
    regular_calls = 0

    def modified_between_checks(fd):
        nonlocal regular_calls
        st = original(fd)
        if stat.S_ISREG(st.st_mode):
            regular_calls += 1
            if regular_calls == 2:
                os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
                return original(fd)
        return st

    monkeypatch.setattr(backup_safety.os, "fstat", modified_between_checks)
    with pytest.raises(UnsafeBackupError):
        read_private_backup(p)
    assert regular_calls == 2


def test_unchanged_backup_remains_readable(tmp_path):
    p = tmp_path / "backup.bin"
    p.write_bytes(b"trusted")
    assert read_private_backup(p) == b"trusted"
