"""HTTP tests for the API authentication middleware."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_guard import install_auth_guard


def make_client():
    app = FastAPI()

    @app.get("/api/ping")
    def ping():
        return {"ok": True}

    install_auth_guard(app)
    return TestClient(app)


def test_missing_configuration(monkeypatch):
    monkeypatch.delenv("REMEDYOPS_API_TOKEN", raising=False)
    with make_client() as client:
        assert client.get("/api/ping").status_code == 503


def test_incorrect_token(monkeypatch):
    monkeypatch.setenv("REMEDYOPS_API_TOKEN", "expected")
    with make_client() as client:
        assert client.get("/api/ping").status_code == 401


def test_correct_token(monkeypatch):
    monkeypatch.setenv("REMEDYOPS_API_TOKEN", "expected")
    with make_client() as client:
        response = client.get("/api/ping", headers={"X-API-Token": "expected"})
        assert response.status_code == 200
