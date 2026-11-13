"""Immutable local snapshot for validating and transferring the same package bytes.

Integrate with the GUI upload workflow: stage -> inspect_archive(snapshot) ->
scp(snapshot) -> sha256_file(snapshot) -> remote sha256sum. Never SCP the source.
"""
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile

MAX_PACKAGE_BYTES = 8 * 1024**3

class SnapshotError(ValueError):
    pass

@contextmanager
def package_snapshot(source):
    source = Path(source)
    if not source.is_file() or source.is_symlink():
        raise SnapshotError("Package must be a regular, non-symlink file")
    if source.stat().st_size > MAX_PACKAGE_BYTES:
        raise SnapshotError("Package exceeds size limit")
    with tempfile.TemporaryDirectory(prefix="omniesol-upload-") as directory:
        snapshot = Path(directory) / "package.snapshot"
        with source.open("rb") as src, snapshot.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        if snapshot.stat().st_size > MAX_PACKAGE_BYTES:
            raise SnapshotError("Snapshot exceeds size limit")
        yield snapshot
