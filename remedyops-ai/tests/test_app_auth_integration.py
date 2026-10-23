"""Integration tests against the real RemedyOps FastAPI application.

The application is imported from an isolated temporary directory, with its own
SQLite database and sandbox files. No SSH endpoint is called.
"""

import importlib.util
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    source = Path(__file__).resolve().parents[1]
    sandbox = tmp_path / "isolated_app"
    sandbox.mkdir()
    for name in ("app.py", "index.html"):
        shutil.copy2(source / name, sandbox / name)

    monkeypatch.syspath_prepend(str(source))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.delenv("REMEDYOPS_ENABLE_SSH_DIAGNOSTICS", raising=False)

    spec = importlib.util.spec_from_file_location(
        f"remedyops_app_test_{uuid.uuid4().hex}", sandbox / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as test_client:
        yield test_client


def test_unconfigured_api_denied_even_from_testclient(client, monkeypatch):
    monkeypatch.delenv("REMEDYOPS_API_TOKEN", raising=False)
    response = client.get("/api/dashboard")
    assert response.status_code == 503
    assert response.json() == {"detail": "API token not configured"}
    assert response.headers["cache-control"] == "no-store"


def test_unconfigured_write_denied_without_side_effect(client, monkeypatch):
    monkeypatch.delenv("REMEDYOPS_API_TOKEN", raising=False)
    payload = {"name": "test", "host": "192.0.2.10", "username": "operator"}
    response = client.post("/api/assets", json=payload)
    assert response.status_code == 503

    monkeypatch.setenv("REMEDYOPS_API_TOKEN", "expected")
    assets = client.get("/api/assets", headers={"X-API-Token": "expected"})
    assert assets.status_code == 200
    assert assets.json() == []


def test_wrong_token_denied_even_with_forwarded_headers(client, monkeypatch):
    monkeypatch.setenv("REMEDYOPS_API_TOKEN", "expected")
    response = client.get(
        "/api/dashboard",
        headers={"X-API-Token": "incorrect", "X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 401


def test_correct_token_allows_read_only_dashboard(client, monkeypatch):
    monkeypatch.setenv("REMEDYOPS_API_TOKEN", "expected")
    response = client.get("/api/dashboard", headers={"X-API-Token": "expected"})
    assert response.status_code == 200
    assert "assets" in response.json()


def test_ui_is_accessible_without_api_token(client, monkeypatch):
    monkeypatch.delenv("REMEDYOPS_API_TOKEN", raising=False)
    assert client.get("/").status_code == 200
