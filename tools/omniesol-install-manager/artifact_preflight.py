"""Read-only package preflight for OmniEsol Installation Manager.

Never extract an untrusted archive during preflight. All checks are local.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 20000
MAX_UNCOMPRESSED = 8 * 1024**3
MAX_RATIO = 200
SUPPORTED = (".zip", ".tar.gz", ".tgz")
_DRIVE = re.compile(r"^[a-zA-Z]:")


class ArtifactError(ValueError):
    """Package is invalid or cannot be safely processed."""


def _safe_name(name: str) -> str:
    if not name or "\\x00" in name or "\\\\" in name or _DRIVE.match(name):
        raise ArtifactError("Invalid archive member name")
    if name.startswith("/") or name.startswith("//"):
        raise ArtifactError("Absolute member path")
    path = PurePosixPath(name)
    if any(part in (".", "..") for part in name.split("/")):
        raise ArtifactError("Traversal or ambiguous member path")
    if not path.parts:
        raise ArtifactError("Empty member path")
    return str(path)


def inspect_archive(path: str | Path, required: tuple[str, ...] = ()) -> dict:
    """Validate ZIP/TAR.GZ metadata and return a redaction-safe manifest."""
    source = Path(path)
    if not source.is_file() or not source.name.lower().endswith(SUPPORTED):
        raise ArtifactError("Expected an existing ZIP or TAR.GZ")
    seen: set[str] = set()
    files = 0
    total = 0

    def add(name: str, size: int, compressed: int | None = None) -> None:
        nonlocal files, total
        safe = _safe_name(name)
        if safe in seen:
            raise ArtifactError("Duplicate archive member")
        seen.add(safe)
        if size < 0:
            raise ArtifactError("Negative member size")
        files += 1
        total += size
        if files > MAX_FILES or total > MAX_UNCOMPRESSED:
            raise ArtifactError("Archive exceeds safety limits")
        if compressed is not None and size > 0:
            if compressed == 0 or size > MAX_RATIO * compressed:
                raise ArtifactError("Excessive compression ratio")

    try:
        if source.name.lower().endswith(".zip"):
            with zipfile.ZipFile(source) as archive:
                for info in archive.infolist():
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise ArtifactError("ZIP symlink not allowed")
                    if not (info.is_dir() or stat.S_ISREG(mode) or mode == 0):
                        raise ArtifactError("Unsupported ZIP member type")
                    add(info.filename, 0 if info.is_dir() else info.file_size,
                        None if info.is_dir() else info.compress_size)
        else:
            with tarfile.open(source, "r:gz") as archive:
                for info in archive:
                    if not (info.isfile() or info.isdir()):
                        raise ArtifactError("TAR links/devices/special files not allowed")
                    add(info.name, 0 if info.isdir() else info.size)
    except (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise ArtifactError("Unreadable archive") from exc

    missing = sorted(set(required) - seen)
    if missing:
        raise ArtifactError("Missing required files: " + ", ".join(missing))
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "schema_version": 1,
        "filename": source.name,
        "sha256": digest.hexdigest(),
        "file_count": files,
        "uncompressed_bytes": total,
        "required_files_checked": sorted(set(required)),
        "status": "validated_metadata_only",
    }


def save_manifest(manifest: dict, destination: str | Path) -> None:
    """Write a local JSON manifest without storing credentials."""
    target = Path(destination)
    if target.exists():
        raise ArtifactError("Refusing to overwrite existing manifest")
    with target.open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\\n")
