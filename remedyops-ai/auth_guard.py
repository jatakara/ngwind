"""Fail-closed authentication decision for RemedyOps API requests.

Keep the decision independent of FastAPI so denial cases can be unit-tested
without starting a server or touching the remediation sandbox.
"""

import hmac


def api_auth_failure(path: str, expected_token: str, supplied_token: str) -> tuple[int, str] | None:
    """Return (HTTP status, detail) when access must be denied, else None.

    Non-API paths may serve the static UI; all /api endpoints require a token.
    Never infer trust from the request's source address or proxy headers.
    """
    if path != "/api" and not path.startswith("/api/"):
        return None
    if not expected_token:
        return (503, "API token not configured")
    if not hmac.compare_digest(supplied_token, expected_token):
        return (401, "Unauthorized")
    return None
