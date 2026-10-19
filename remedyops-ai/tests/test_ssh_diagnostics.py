"""Offline regression tests for SSH CIDR validation."""
import socket
from unittest.mock import Mock
import pytest
import ssh_diagnostics as ssh

def addr(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 2222))

def test_all_dns_answers_must_be_approved(monkeypatch):
    monkeypatch.setenv("REMEDYOPS_ALLOWED_CIDRS", "10.0.0.0/8")
    monkeypatch.setattr(ssh.socket, "getaddrinfo",
                        lambda *args, **kwargs: [addr("10.0.0.8"), addr("203.0.113.4")])
    with pytest.raises(ValueError, match="outside approved"):
        ssh.check_host("server.example", 2222)

def test_missing_allowlist_fails_closed(monkeypatch):
    monkeypatch.delenv("REMEDYOPS_ALLOWED_CIDRS", raising=False)
    lookup = Mock(side_effect=AssertionError("should not resolve"))
    monkeypatch.setattr(ssh.socket, "getaddrinfo", lookup)
    with pytest.raises(ValueError, match="must be configured"):
        ssh.check_host("server.example", 2222)
    lookup.assert_not_called()
