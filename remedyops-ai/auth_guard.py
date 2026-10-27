"""Fail-closed authentication for the RemedyOps API.

All /api endpoints require a configured token, independent of the client's
network address or reverse-proxy headers. The static UI is not an API endpoint.
"""

import hmac
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def api_auth_failure(path: str, expected_token: str, supplied_token: str) -> tuple[int, str] | None:
    """Return an HTTP denial decision or None when the request is permitted."""
    if path != "/api" and not path.startswith("/api/"):
        return None
    if not expected_token:
        return (503, "API token not configured")
    if not hmac.compare_digest(supplied_token, expected_token):
        return (401, "Unauthorized")
    return None


def install_auth_guard(app: FastAPI) -> None:
    """Install one middleware enforcing token authentication for every API route."""
    @app.middleware("http")
    async def api_guard(request: Request, call_next):
        denial = api_auth_failure(
            request.url.path,
            os.environ.get("REMEDYOPS_API_TOKEN", ""),
            request.headers.get("X-API-Token", ""),
        )
        if denial is not None:
            status, detail = denial
            return JSONResponse(
                {"detail": detail},
                status_code=status,
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)
