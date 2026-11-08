"""Additional read-only archive policy checks for Windows-to-RHEL transfers.

This module does not extract archives and must not authorize deployment.
"""
from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from artifact_preflight import ArtifactError, _safe_name, MAX_FILES, MAX_UNCOMPRESSED, MAX_RATIO


def inspect_archive_policy(source: str | Path) -> dict:
    """Reject ambiguous paths, encrypted ZIPs and suspicious gzip TAR metadata.

    Path comparisons are case-insensitive to prevent collisions when inspecting
    archives on Windows. Directory entries are not counted as payload files.
    """
    path = Path(source)
    if not path.is_file():
        raise ArtifactError("Archive not found")
    filename = path.name.lower()
    if not (filename.endswith(".zip") or filename.endswith((".tar.gz", ".tgz"))):
        raise ArtifactError("Unsupported archive extension")

    entries: dict[str, bool] = {}
    total = 0
    files = 0

    def register(raw: str, is_dir: bool, size: int) -> None:
        nonlocal total, files
        canonical = _safe_name(raw)
        if raw.endswith("/") and not is_dir:
            raise ArtifactError("Inconsistent directory marker")
        key = canonical.casefold()
        if key in entries:
            raise ArtifactError("Duplicate or case-colliding path")
        if size < 0:
            raise ArtifactError("Negative member size")
        entries[key] = is_dir
        if not is_dir:
            files += 1
            total += size
        if len(entries) > MAX_FILES or total > MAX_UNCOMPRESSED:
            raise ArtifactError("Archive exceeds safety limits")

    try:
        if filename.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.flag_bits & 0x1:
                        raise ArtifactError("Encrypted ZIP entry is not supported")
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise ArtifactError("ZIP symlink not supported")
                    if not (member.is_dir() or stat.S_ISREG(mode) or mode == 0):
                        raise ArtifactError("Unsupported ZIP entry type")
                    if not member.is_dir() and member.file_size > 0:
                        if member.compress_size == 0 or member.file_size > MAX_RATIO * member.compress_size:
                            raise ArtifactError("Excessive ZIP compression ratio")
                    register(member.filename, member.is_dir(), 0 if member.is_dir() else member.file_size)
        else:
            with tarfile.open(path, "r:gz") as archive:
                for member in archive:
                    if not (member.isfile() or member.isdir()):
                        raise ArtifactError("TAR links or special files not supported")
                    register(member.name, member.isdir(), 0 if member.isdir() else member.size)
            # This is only a coarse archive-level heuristic, not a decompression
            # or CPU limit. A safe extractor must enforce limits independently.
            compressed = path.stat().st_size
            if total > 0 and (compressed == 0 or total > MAX_RATIO * compressed):
                raise ArtifactError("Excessive TAR archive expansion ratio")
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise ArtifactError("Unreadable archive") from exc

    for key, is_dir in entries.items():
        parts = PurePosixPath(key).parts
        for i in range(1, len(parts)):
            ancestor = "/".join(parts[:i])
            if ancestor in entries and not entries[ancestor]:
                raise ArtifactError("File conflicts with descendant path")
        if is_dir:
            continue
        # A file must not be an ancestor of another file or directory.
        prefix = key + "/"
        if any(other.startswith(prefix) for other in entries):
            raise ArtifactError("File conflicts with descendant path")

    return {
        "status": "validated_metadata_only",
        "entry_count": len(entries),
        "file_count": files,
        "uncompressed_bytes": total,
        "windows_case_collision_checked": True,
        "encrypted_zip_rejected": True,
        "tar_ratio_heuristic_checked": filename.endswith((".tar.gz", ".tgz")),
    }
