"""Fail-closed redaction for installer diagnostics (Python 3.11+).

This is defense-in-depth, NOT a substitute for avoiding plaintext secrets in
configuration files, process arguments, environment variables or shell history.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEY = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|"
    r"credential|masterauth|requirepass|authorization)",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>\b(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"masterauth|requirepass|authorization)\b\s*[:=]\s*)"
    r"(?P<value>\\"[^\\"\r\n]*\\"|'[^'\r\n]*'|[^\s,;#]+)"
)
_JDBC = re.compile(r"(?i)(jdbc:[^\s]*?)(?P<credentials>password=[^&\s;]+)")
_URL_AUTH = re.compile(r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s/@:]+:)[^\s/@]+@", re.I)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

REDACTED = "[REDACTED]"


def redact_text(value: str) -> str:
    """Mask known credential patterns before writing logs or reports."""
    if not isinstance(value, str):
        raise TypeError("redact_text expects str")
    value = re.sub(r"(?im)(\\bAuthorization\\s*:\\s*)(?:Bearer\\s+)?[^\\r\\n]+",\n                   lambda m: m[1] + REDACTED, value)\n    value = _PEM.sub(REDACTED, value)
    value = _URL_AUTH.sub(lambda m: m["prefix"] + REDACTED + "@", value)
    value = _JDBC.sub(lambda m: m[1] + "password=" + REDACTED, value)
    value = _ASSIGNMENT.sub(lambda m: m["key"] + REDACTED, value)
    return _BEARER.sub("Bearer " + REDACTED, value)


def redact_data(value: Any, *, max_depth: int = 32) -> Any:
    """Return a redacted copy of JSON-like values; reject unknown object types.

    A depth cap prevents cyclic/untrusted nested structures from hanging logging.
    """
    def walk(item: Any, depth: int) -> Any:
        if depth > max_depth:
            raise ValueError("redaction nesting limit exceeded")
        if isinstance(item, Mapping):
            output: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("log mapping keys must be strings")
                output[key] = REDACTED if _SECRET_KEY.search(key) else walk(child, depth + 1)
            return output
        if isinstance(item, (list, tuple)):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, str):
            return redact_text(item)
        if item is None or type(item) in (int, float, bool):
            return item
        raise TypeError("unsupported diagnostic value type")
    return walk(value, 0)
