"""Shared utilities for safe logging and text sanitization."""

from __future__ import annotations

import os
import re
from pathlib import Path

# Patterns that may contain sensitive data
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_RE = re.compile(r"\+?\d[\d\s\-().]{6,}\d")
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def redact(text: str) -> str:
    """Redact emails and phone numbers from a string for safe logging."""
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _PHONE_RE.sub("[REDACTED_PHONE]", text)
    return text


def sanitize_text(text: str, max_length: int = 5000) -> str:
    """Strip control characters, collapse whitespace, and truncate."""
    if not text:
        return ""
    # Remove control chars except newline/tab
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Collapse runs of whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return text


def safe_path(base_dir: str, requested: str) -> str:
    """Canonicalize a file path and ensure it stays within base_dir.

    Returns the resolved absolute path.
    Raises ValueError if the path escapes base_dir or contains suspicious components.
    """
    base = Path(base_dir).resolve()
    target = Path(requested)

    # Reject absolute paths — they should be relative to base_dir
    if target.is_absolute():
        # Allow if they're already inside base
        resolved = target.resolve()
    else:
        resolved = (base / target).resolve()

    # Ensure resolved path is inside base directory
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError(
            f"Output path escapes base directory: {requested} -> {resolved} "
            f"is outside {base}"
        )

    # Reject suspicious path components
    parts = resolved.parts
    for part in parts:
        if part in ("..", "~"):
            raise ValueError(f"Suspicious path component: {part}")

    return str(resolved)


def safe_filename(ip_str: str) -> str:
    """Create a safe filename from an IP address, stripping separators."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", ip_str)
