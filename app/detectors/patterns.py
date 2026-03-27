"""Central registry of detection patterns shared between detectors and log redaction."""
from __future__ import annotations

import re

# Expanded secret patterns - used by SecretDetector fallback and log redaction
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),                                    # OpenAI
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"),                             # Anthropic
    re.compile(r"AKIA[0-9A-Z]{16}"),                                        # AWS access key
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-_\.]{20,}"),                     # Bearer token
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"),   # JWT
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                                     # GitHub personal
    re.compile(r"ghs_[A-Za-z0-9]{36}"),                                     # GitHub server
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),                             # GitHub PAT
    re.compile(r"sk_live_[A-Za-z0-9]{24,}"),                                # Stripe live key
    re.compile(r"rk_live_[A-Za-z0-9]{24,}"),                                # Stripe restricted
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),                          # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),  # PEM private key
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                  # GCP API key
    re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S{8,}"),             # Inline passwords
]

# PII patterns - used by PiiDetector fallback and log redaction
PII_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),        # Email
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                                   # SSN (strict)
    re.compile(                                                              # Phone number
        r"\+?\d{1,2}[\s-]?(?:\(\d{3}\)|\d{3})[\s-]?\d{3}[\s-]?\d{4}"
    ),
]

__all__ = ["SECRET_PATTERNS", "PII_PATTERNS"]
