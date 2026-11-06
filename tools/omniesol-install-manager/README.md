# OmniEsol Installation Manager — artifact preflight (2026-11-07)

This is a standalone, read-only Python 3.11+ module, **not** a complete Windows GUI installation manager. The prior MVP v0.1 archive is not committed here and integration is pending.

## Usage

```python
from artifact_preflight import inspect_archive, save_manifest
manifest = inspect_archive("erp10-package.tar.gz", required=("erp.sh",))
save_manifest(manifest, "manifest.json")
```

Run tests from this directory: `python -m unittest -v test_artifact_preflight.py`.

Checks: path traversal, absolute paths, duplicate entries, TAR symlinks/hardlinks/devices, ZIP Unix symlinks, archive member count, aggregate uncompressed size, ZIP per-entry compression ratio, expected file presence, SHA-256 of source file. **Metadata-only**: does not extract or execute package contents.

Security limitations: TAR gzip ratio is not checked; archive contents are not read or malware-scanned; ZIP encrypted entries are not explicitly rejected; file size caps are defaults and may need adjustment. Do not treat this validation as authorization to deploy. Use a dedicated extraction implementation with the same checks plus no-follow filesystem semantics and strict destination isolation.

Next: integrate into GUI package-selection flow, verify against actual supplied apinstaller archive and its file manifest, add CI on Windows and Linux, handle file/dir name collisions and compression limits before extraction is permitted.
