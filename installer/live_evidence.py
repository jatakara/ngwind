"""Read-only SSH evidence collector for OmniEsol; never opens install gate."""
import hashlib
import json
import re
from datetime import datetime, timezone

REMOTE_READ_ONLY = """set -eu
printf 'HOSTNAME='; hostname
printf 'OS_ID='; sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"'
printf 'OS_VERSION='; sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n 1 | tr -d '"'
printf 'KERNEL='; uname -r
printf 'CPU='; nproc
printf 'MEM_KB='; awk '/^MemTotal:/ {print $2}' /proc/meminfo
printf 'ROOT_FS='; findmnt -n -o SOURCE,FSTYPE,TARGET /
printf 'TIME_SYNC='; timedatectl show -p NTPSynchronized --value 2>/dev/null || printf 'unknown\\n'
"""
FIELDS = {'HOSTNAME', 'OS_ID', 'OS_VERSION', 'KERNEL', 'CPU', 'MEM_KB', 'ROOT_FS', 'TIME_SYNC'}
SAFE_VALUE = re.compile(r'^[A-Za-z0-9_.:/,=+@() -]{1,250}$')


class EvidenceError(ValueError):
    pass


def parse_output(raw):
    if not isinstance(raw, str) or len(raw) > 8192:
        raise EvidenceError('Unexpected SSH response length')
    values = {}
    for line in raw.splitlines():
        if '=' not in line:
            raise EvidenceError('Unexpected SSH response line')
        key, value = line.split('=', 1)
        if key not in FIELDS or key in values or not SAFE_VALUE.fullmatch(value):
            raise EvidenceError('Unexpected SSH response field')
        values[key] = value
    if values.keys() != FIELDS:
        raise EvidenceError('Incomplete SSH evidence')
    if not values['CPU'].isdigit() or not values['MEM_KB'].isdigit():
        raise EvidenceError('Invalid resource readings')
    if values['TIME_SYNC'] not in ('yes', 'no', 'unknown'):
        raise EvidenceError('Invalid time synchronization reading')
    return values


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()


def collect(manifest, server_id, target, ssh_exec):
    matched = [s for s in manifest.get('servers', []) if isinstance(s, dict) and s.get('id') == server_id]
    if len(matched) != 1:
        raise EvidenceError('Server ID missing or ambiguous')
    server = matched[0]
    if target.host != server.get('ip'):
        raise EvidenceError('SSH target differs from approved inventory IP')
    values = parse_output(ssh_exec(target, REMOTE_READ_ONLY, timeout=45))
    checks = {
        'hostname_matches': values['HOSTNAME'].lower() == str(server.get('hostname', '')).lower(),
        'cpu_meets_declared': int(values['CPU']) >= server.get('vcpu', float('inf')),
        'ram_meets_declared': int(values['MEM_KB']) >= server.get('ram_gb', float('inf')) * 1024**2 * 0.95,
        'ntp_synchronized': values['TIME_SYNC'] == 'yes',
    }
    return {
        'schema': 'omniesol-live-evidence-v1', 'server_id': server_id,
        'inventory_sha256': manifest_digest(manifest),
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'transport': 'ssh-strict-host-key',
        'command_sha256': hashlib.sha256(REMOTE_READ_ONLY.encode()).hexdigest(),
        'observations': values, 'checks': checks,
        'g2_status': 'PARTIAL' if all(checks.values()) else 'FAILED',
        'installation_gate': 'HOLD',
        'limitations': 'No firewall path, DNS resolution, NFS read/write, BMC, signed provenance or G3 approval verification',
    }


def verify_record(manifest, record):
    if record.get('schema') != 'omniesol-live-evidence-v1' or record.get('inventory_sha256') != manifest_digest(manifest):
        return False
    if record.get('command_sha256') != hashlib.sha256(REMOTE_READ_ONLY.encode()).hexdigest():
        return False
    if record.get('transport') != 'ssh-strict-host-key' or record.get('installation_gate') != 'HOLD':
        return False
    try:
        values = record['observations']
        parsed = parse_output('\n'.join(f'{k}={v}' for k, v in values.items()))
        return parsed == values and record.get('g2_status') in ('PARTIAL', 'FAILED')
    except (EvidenceError, TypeError, AttributeError):
        return False
