"""Strict, non-interactive Windows OpenSSH command construction.

No shell=True, no password authentication, no trust-on-first-use.
Callers must provision and verify known_hosts out of band.
"""
from __future__ import annotations
import ipaddress
import re
from pathlib import Path

_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def validate_target(host: str, port: int, user: str) -> None:
    if not isinstance(host, str) or not host or any(c.isspace() for c in host):
        raise ValueError("invalid host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST.fullmatch(host) or ".." in host or host.startswith("-"):
            raise ValueError("invalid host")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid port")
    if not isinstance(user, str) or not _USER.fullmatch(user):
        raise ValueError("invalid user")


def ssh_argv(host: str, port: int, user: str, key: str, known_hosts: str,
             remote_command: str) -> list[str]:
    validate_target(host, port, user)
    for name, value in (("key", key), ("known_hosts", known_hosts)):
        if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
            raise ValueError(f"invalid {name} path")
        if not Path(value).is_file():
            raise ValueError(f"{name} file missing")
    # Only fixed, pre-reviewed commands are accepted; do not concatenate user input.
    allowed = {
        "os-release": "cat /etc/os-release",
        "hostname": "hostname",
        "memory": "cat /proc/meminfo",
        "disk": "df -Pk",
    }
    if remote_command not in allowed:
        raise ValueError("remote command not allowlisted")
    return [
        "ssh", "-F", "none", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=none",
        "-o", "UpdateHostKeys=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10",
        "-i", key, "-p", str(port), "--",
        f"{user}@{host}", allowed[remote_command],
    ]
