import socket
from unittest.mock import Mock
import ssh_diagnostics as ssh

def test_address_pinning(monkeypatch):
    monkeypatch.setenv("REMEDYOPS_ALLOWED_CIDRS", "10.0.0.0/8")
    address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.1.1.2", 2222))
    monkeypatch.setattr(ssh.socket, "getaddrinfo", Mock(return_value=[address]))
    assert ssh.check_host("server.example", 2222) == [address]
