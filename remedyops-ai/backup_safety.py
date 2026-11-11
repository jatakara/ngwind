"""Descriptor-based reads of private rollback backups (Linux/POSIX only)."""
import os
import stat


class UnsafeBackupError(OSError):
    """Backup cannot be read safely."""


def read_private_backup(path, max_bytes=1024 * 1024):
    """Reject links, special files, oversized content and untrusted ownership.

    The directory and backup must be owned by this process's effective UID.
    This intentionally fails closed for root-owned backups read by non-root
    processes; migration requires an explicitly reviewed ownership policy.
    """
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "geteuid")):
        raise UnsafeBackupError("Required POSIX safety features unavailable")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise UnsafeBackupError("Invalid backup size limit")
    parent = os.fspath(path.parent)
    owner = os.geteuid()
    try:
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        getattr(os, "O_CLOEXEC", 0))
        try:
            ds = os.fstat(directory)
            if (not stat.S_ISDIR(ds.st_mode) or ds.st_mode & 0o022
                    or ds.st_uid != owner):
                raise UnsafeBackupError("Untrusted backup directory")
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                         getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                        or st.st_mode & 0o022 or st.st_uid != owner
                        or st.st_size > max_bytes):
                    raise UnsafeBackupError("Unsafe backup inode")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    content = stream.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise UnsafeBackupError("Oversized backup")
                # Detect in-place writes during the read. This is best-effort:
                # ownership/permissions and a trusted checksum remain essential.
                after = os.fstat(fd)
                if (after.st_dev != st.st_dev or after.st_ino != st.st_ino
                        or after.st_size != st.st_size
                        or after.st_mtime_ns != st.st_mtime_ns
                        or after.st_ctime_ns != st.st_ctime_ns):
                    raise UnsafeBackupError("Backup changed while reading")
                return content
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    except OSError as exc:
        raise UnsafeBackupError("Backup unavailable or unsafe") from exc
