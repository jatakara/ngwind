"""Read-only assessment for the provided legacy ERP10 apinstaller TAR.GZ.

This module never extracts files, executes shell code or prints credentials.
A clean audit is not approval to install: legacy execution is always disabled.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_ARCHIVE_BYTES = 2 * 1024**3
MAX_MEMBERS = 25000
MAX_SCRIPT_BYTES = 2 * 1024**2
REQUIRED = (
    'erp.sh', 'nginx/nginx.conf', 'nginx/nginx_443.conf',
    'redis/sh/redis_18086.sh',
    'was/tomcat-8085/bin/startup.sh',
    'was/tomcat-8080/bin/startup.sh',
    'was/tomcat-8089/bin/startup.sh',
)
PRODUCTION_DEPENDENCIES = (
    'nginx/nginx_upstream.conf',
    'nginx/nginx_upstream_443.conf',
    'nginx/nginx_upstream_check_module-master/check_1.16.1+.patch',
)


class BundleAuditError(ValueError):
    """Untrusted bundle failed structural parsing or resource limits."""


def audit_legacy_bundle(path: str | Path) -> dict:
    """Scan legacy distribution without extraction. Never returns secret values."""
    path = Path(path)
    if not path.is_file() or not (path.name.lower().endswith('.tar.gz') or path.name.lower().endswith('.tgz')):
        raise BundleAuditError('Select an existing TAR.GZ/TGZ legacy installer')
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise BundleAuditError('Archive exceeds 2GiB audit limit')
    members_seen: set[str] = set()
    count = 0
    erp_script: bytes | None = None
    findings: list[dict[str, str]] = []

    def add(code: str, severity: str, note: str) -> None:
        findings.append({'code': code, 'severity': severity, 'description': note})

    try:
        with tarfile.open(path, mode='r|gz') as archive:
            for member in archive:
                count += 1
                if count > MAX_MEMBERS:
                    raise BundleAuditError('Archive contains too many entries')
                raw_name = member.name
                segments = PurePosixPath(raw_name).parts
                if (raw_name.startswith('/') or '\\' in raw_name or
                        '..' in segments or not segments):
                    raise BundleAuditError('Unsafe archive member path')
                normalized = str(PurePosixPath(raw_name))
                if normalized in members_seen:
                    raise BundleAuditError('Duplicate archive member path')
                members_seen.add(normalized)
                if member.issym() or member.islnk():
                    # Read-only warning. Extraction is NOT permitted.
                    add('ARCHIVE_LINK', 'warning', 'Archive contains symbolic/hard links')
                elif not (member.isfile() or member.isdir()):
                    add('SPECIAL_ENTRY', 'warning', 'Archive contains non-regular entries')
                if normalized == 'erp.sh':
                    if not member.isfile() or member.size > MAX_SCRIPT_BYTES:
                        raise BundleAuditError('Invalid legacy entry script')
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise BundleAuditError('Unable to read legacy entry script')
                    erp_script = stream.read(MAX_SCRIPT_BYTES + 1)
                    if len(erp_script) > MAX_SCRIPT_BYTES:
                        raise BundleAuditError('Legacy entry script exceeds audit limit')
    except (tarfile.TarError, OSError, EOFError, UnicodeError) as exc:
        raise BundleAuditError('Archive could not be safely inspected') from exc

    for entry in REQUIRED:
        if entry not in members_seen:
            add('REQUIRED_MISSING', 'blocker', f'Missing required installer asset: {entry}')
    for entry in PRODUCTION_DEPENDENCIES:
        if entry not in members_seen:
            add('PRODUCTION_ASSET_MISSING', 'blocker', f'Missing referenced production asset: {entry}')
    if erp_script is None:
        add('ENTRY_SCRIPT_MISSING', 'blocker', 'Legacy erp.sh is missing')
    else:
        text = erp_script.decode('utf-8', errors='replace')
        if re.search(r'(?m)^\s*DBPASSWORD=\$DBPASSWORD\s*$', text):
            add('PLAINTEXT_PASSWORD', 'blocker', 'DB password is written to inventory.ini')
        if re.search(r'echo\s+["\x27]?DB PASSWORD.*\$DBPASSWORD', text):
            add('PASSWORD_ECHO', 'blocker', 'DB password is printed to terminal')
        if re.search(r'(?m)^\s*source\s+["\x27]?\$?\{?SCRIPT_DIR.*inventory\.ini', text):
            add('EXECUTABLE_INVENTORY', 'blocker', 'Untrusted inventory.ini is sourced as shell code')
        if 'rm -rf' in text:
            add('RECURSIVE_DELETE', 'warning', 'Legacy script uses recursive deletion')
        if re.search(r'\bchown\s+-R\b', text):
            add('RECURSIVE_CHOWN', 'warning', 'Legacy script uses recursive ownership changes')
    # A read-only audit does not certify an installation artifact, even if clean.
    blocked = any(f['severity'] == 'blocker' for f in findings)
    return {
        'schema': 'omniesol-legacy-audit-v1',
        'status': 'BLOCKED' if blocked else 'REVIEW_REQUIRED',
        'execution_allowed': False,
        'entry_count': count,
        'finding_count': len(findings),
        'findings': findings,
        'scope': 'local static audit only; no extraction, SSH, or installation',
    }
