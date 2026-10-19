"""Read-only SSH diagnostics for registered RHEL servers.

Only allowlisted fixed commands are run; no arbitrary command input.
Credentials are never stored in the database.
"""
from dataclasses import dataclass
from pathlib import Path
import ipaddress, os, socket
import paramiko

COMMANDS = {
    "os_release": "cat /etc/os-release",
    "kernel": "uname -r",
    "uptime": "uptime",
    "selinux": "getenforce",
    "sshd_effective": "sshd -T",
}
@dataclass
class Diagnostic:
    host: str
    port: int
    username: str
    key_path: str
    known_hosts_path: str

def check_host(host, port):
    """Return validated socket addresses; reject any DNS answer outside the allowlist."""
    networks = os.environ.get("REMEDYOPS_ALLOWED_CIDRS", "")
    if not networks.strip():
        raise ValueError("REMEDYOPS_ALLOWED_CIDRS must be configured")
    try:
        cidrs = [ipaddress.ip_network(x.strip(), strict=False)
                 for x in networks.split(",") if x.strip()]
    except ValueError as exc:
        raise ValueError("Invalid approved CIDR configuration") from exc
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Host DNS resolution failed") from exc
    if not addresses:
        raise ValueError("Host DNS resolution returned no addresses")
    for family, _kind, _proto, _name, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("Unsupported address family")
        ip = ipaddress.ip_address(sockaddr[0])
        if not any(ip in net for net in cidrs):
            raise ValueError("Host outside approved CIDRs")
    return addresses

def diagnose(d:Diagnostic):
    check_host(d.host)
    if not Path(d.known_hosts_path).is_file():
        raise ValueError("Known-hosts file missing; pin the server host key first")
    if not Path(d.key_path).is_file():
        raise ValueError("SSH key file missing")
    client=paramiko.SSHClient()
    client.load_host_keys(d.known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(hostname=d.host,port=d.port,username=d.username,
                       key_filename=d.key_path,look_for_keys=False,
                       allow_agent=False,timeout=5,auth_timeout=5,banner_timeout=5)
        output={}
        for name,cmd in COMMANDS.items():
            stdin,stdout,stderr=client.exec_command(cmd,timeout=10)
            data=stdout.read(65536).decode("utf-8","replace")
            err=stderr.read(2048).decode("utf-8","replace")
            output[name]={"exit_code":stdout.channel.recv_exit_status(),
                          "stdout":data,"stderr":err}
        return output
    finally:
        client.close()
