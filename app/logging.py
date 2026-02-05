"""Structured logging with redaction helpers."""
from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Iterable, Mapping

REDACTION_TOKEN = "[REDACTED]"

# Patterns used both for detection and masking in logs
SECRET_PATTERNS: Iterable[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9-_\.]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"),
]

PII_PATTERNS: Iterable[re.Pattern[str]] = [
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
    re.compile(r"\+?\d{1,2}[\s-]?(?:\(\d{3}\)|\d{3})[\s-]?\d{3}[\s-]?\d{4}"),
]

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
        sanitized: Dict[str, Any] = {}
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
