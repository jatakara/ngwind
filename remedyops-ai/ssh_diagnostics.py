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

def check_host(host):
    """Prevent accidental connections to unapproved hosts; explicit CIDR allowlist required."""
    networks=os.environ.get("REMEDYOPS_ALLOWED_CIDRS","")
    if not networks.strip():
        raise ValueError("REMEDYOPS_ALLOWED_CIDRS must be configured")
    try:
        addresses=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
        ips={ipaddress.ip_address(item[4][0]) for item in addresses}
        cidrs=[ipaddress.ip_network(x.strip(),strict=False) for x in networks.split(",") if x.strip()]
        if not ips or any(not any(ip in net for net in cidrs) for ip in ips):
            raise ValueError("Host outside approved CIDRs")
    except socket.gaierror as exc:
        raise ValueError("Host DNS resolution failed") from exc

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
