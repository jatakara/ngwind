"""Conservative log redaction for diagnostic output."""
from __future__ import annotations
import re

_PATTERNS = (
    (re.compile(r'(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|requirepass|masterauth)\b(\s*[:=]\s*|\s+)(["\']?)([^\s,"\';]+)'), r'\1\2[REDACTED]'),
    (re.compile(r'(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)([a-z][a-z0-9+.-]*://[^\s/@:]+:)[^\s/@]+(@)'), r'\1[REDACTED]\2'),
    (re.compile(r'-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z ]* )?PRIVATE KEY-----', re.S), '[PRIVATE KEY REDACTED]'),
)

def redact(value: object) -> str:
    result = str(value)
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result
