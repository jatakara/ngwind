import socket
from unittest.mock import Mock
import ssh_diagnostics as ssh

def test_ssh_uses_pinned_socket(monkeypatch, tmp_path):
    monkeypatch.setenv("REMEDYOPS_ALLOWED_CIDRS", "10.0.0.0/8")
    address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.1.1.2", 2222))
    lookup = Mock(return_value=[address])
    monkeypatch.setattr(ssh.socket, "getaddrinfo", lookup)
    raw = Mock()
    monkeypatch.setattr(ssh.socket, "socket", Mock(return_value=raw))
    client = Mock()
    monkeypatch.setattr(ssh.paramiko, "SSHClient", Mock(return_value=client))
    monkeypatch.setattr(ssh, "COMMANDS", {})
    key = tmp_path / "key"
    hosts = tmp_path / "known_hosts"
    key.write_text("test")
    hosts.write_text("test")
    result = ssh.diagnose(ssh.Diagnostic("server.example", 2222, "testuser", str(key), str(hosts)))
    assert result == {}
    lookup.assert_called_once()
    raw.connect.assert_called_once_with(("10.1.1.2", 2222))
    assert client.connect.call_args.kwargs["hostname"] == "server.example"
    assert client.connect.call_args.kwargs["sock"] is raw
    raw.close.assert_called_once()
