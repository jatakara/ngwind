"""Descriptor-based reads of private rollback backups (Linux/POSIX only)."""
import os
import stat

class UnsafeBackupError(OSError):
    """Backup cannot be read safely."""

def read_private_backup(path, max_bytes=1024 * 1024):
    """Reject links, special files, oversized content and unsafe directories."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise UnsafeBackupError("O_NOFOLLOW unavailable")
    parent = os.fspath(path.parent)
    try:
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            ds = os.fstat(directory)
            if not stat.S_ISDIR(ds.st_mode) or ds.st_mode & 0o022:
                raise UnsafeBackupError("Writable backup directory")
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > max_bytes:
                    raise UnsafeBackupError("Unsafe backup inode")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    content = stream.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise UnsafeBackupError("Oversized backup")
                return content
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    except OSError as exc:
        raise UnsafeBackupError("Backup unavailable or unsafe") from exc
