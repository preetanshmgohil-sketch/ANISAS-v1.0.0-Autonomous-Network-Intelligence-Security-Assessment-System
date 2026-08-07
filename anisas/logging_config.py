"""Central logging configuration with redaction filter and structured output.

Call configure_logging(level=logging.INFO) early in CLI entrypoints to enable JSON-like
structured logs and automatic PII redaction for string messages.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from .sanitizer import _redact_string


class RedactFilter(logging.Filter):
    """Filter that redacts PII-like patterns from log messages (strings)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_string(record.getMessage())
                # prevent formatting with args again
                record.args = None
        except Exception:
            # Never fail logging
            pass
        return True


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    # remove existing handlers to avoid duplicate logs
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    # Add redact filter
    root.addFilter(RedactFilter())
