"""Structured logging with redaction helpers."""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from app.detectors.patterns import PII_PATTERNS, SECRET_PATTERNS

REDACTION_TOKEN = "[REDACTED]"

MESSAGE_FIELDS = {"content", "prompt", "messages", "input", "inputs", "query"}
HEADER_FIELDS = {"authorization", "api-key", "x-api-key"}


class JsonFormatter(logging.Formatter):
    """Simple JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
        }
        payload.update(getattr(record, "extra_fields", {}))
        return json.dumps(payload, default=str)


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in list(SECRET_PATTERNS) + list(PII_PATTERNS):
            value = pattern.sub(REDACTION_TOKEN, value)
        return value
    return value


def redact_payload(data: Any) -> Any:
    """Return a redacted copy of request/response payloads for safe logging."""

    if data is None:
        return None

    if isinstance(data, Mapping):
        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            lowered = key.lower()
            if lowered in HEADER_FIELDS:
                sanitized[key] = REDACTION_TOKEN
                continue
            if lowered in MESSAGE_FIELDS:
                sanitized[key] = REDACTION_TOKEN
                continue
            sanitized[key] = redact_payload(value)
        return sanitized

    if isinstance(data, list):
        return [redact_payload(item) for item in data]

    return _mask_value(data)


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("llm_security_proxy")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    return logger


LOGGER = setup_logging()

__all__ = ["LOGGER", "setup_logging", "redact_payload", "REDACTION_TOKEN"]
