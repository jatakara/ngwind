"""Redact common secrets from diagnostic output. Defense in depth only."""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|"
    r"credential|masterauth|requirepass|authorization", re.I
)
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"masterauth|requirepass)\b\s*(?:[:=]\s*|\s+))"
    r"(\x22[^\x22\r\n]*\x22|'[^'\r\n]*'|[^\s,;#]+)"
)
_AUTH_HEADER = re.compile(r"(?im)(\bAuthorization\s*:\s*)[^\r\n]+")
_URL_AUTH = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/@:]+:)[^\s/@]+@", re.I)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.S,
)


def redact_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("redact_text expects str")
    value = _PEM.sub(REDACTED, value)
    value = _AUTH_HEADER.sub(lambda m: m[1] + REDACTED, value)
    value = _URL_AUTH.sub(lambda m: m[1] + REDACTED + "@", value)
    value = _ASSIGNMENT.sub(lambda m: m[1] + REDACTED, value)
    return _BEARER.sub("Bearer " + REDACTED, value)


def redact_data(value: Any, *, max_depth: int = 32) -> Any:
    """Return a redacted copy; reject unknown objects and excessive nesting."""
    def walk(item: Any, depth: int) -> Any:
        if depth > max_depth:
            raise ValueError("redaction nesting limit exceeded")
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("log mapping keys must be strings")
                result[key] = REDACTED if _SECRET_KEY.search(key) else walk(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, str):
            return redact_text(item)
        if item is None or type(item) in (int, float, bool):
            return item
        raise TypeError("unsupported diagnostic value type")
    return walk(value, 0)
