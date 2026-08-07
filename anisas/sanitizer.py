"""PII and sensitive-data sanitization utilities for ANISAS reports.

Default behavior redacts emails, IPv4/IPv6 addresses, and likely secrets in fields named like "token", "api_key", "secret", "password".
Return value preserves the original model type (reconstructed from sanitized dict) so existing report generators can continue to use attribute access.
"""
from __future__ import annotations

import re
from typing import Any

# Patterns
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Simplified IPv6 pattern (not exhaustive)
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

SUSPICIOUS_FIELD_KEYWORDS = ["token", "api_key", "apikey", "secret", "password", "passwd", "key"]
REDACTED = "[REDACTED]"


def _redact_string(s: str) -> str:
    if not s:
        return s
    s = EMAIL_RE.sub(REDACTED, s)
    s = IPV4_RE.sub(REDACTED, s)
    s = IPV6_RE.sub(REDACTED, s)
    return s


def _is_suspicious_key(k: str) -> bool:
    k = k.lower()
    return any(keyword in k for keyword in SUSPICIOUS_FIELD_KEYWORDS)


def sanitize_obj(obj: Any) -> Any:
    """Recursively sanitize an object (dict/list/primitives)."""
    if obj is None:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _is_suspicious_key(k):
                out[k] = REDACTED
            else:
                out[k] = sanitize_obj(v)
        return out
    if isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    # numbers, bools
    return obj


def sanitize_model(model) -> "Any":
    """Return a sanitized instance of the model with PII redacted.

    Attempts to preserve the original model class by reconstructing from
    the sanitized dict. If reconstruction fails, returns the sanitized dict.
    """
    try:
        # Pydantic v2 - model_dump
        data = model.model_dump()
    except Exception:
        # Fallback: try __dict__
        data = getattr(model, "__dict__", {})
    sanitized = sanitize_obj(data)
    # Reconstruct model if possible
    try:
        cls = model.__class__
        # Pydantic v2: model_validate accepts dict
        if hasattr(cls, "model_validate"):
            return cls.model_validate(sanitized)
        else:
            return cls(**sanitized)
    except Exception:
        return sanitized
