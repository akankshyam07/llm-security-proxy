"""Secret token detector using detect-secrets plugins with regex fallback."""
from __future__ import annotations

from collections.abc import Generator
from typing import Any

from app.detectors.base import Detector, register_detector
from app.detectors.patterns import SECRET_PATTERNS
from app.models.events import DetectorFinding

try:
    from detect_secrets.plugins.aws import AWSKeyDetector
    from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
    from detect_secrets.plugins.basic_auth import BasicAuthDetector
    from detect_secrets.plugins.github_token import GitHubTokenDetector
    from detect_secrets.plugins.jwt import JwtTokenDetector
    from detect_secrets.plugins.openai import OpenAIDetector
    from detect_secrets.plugins.private_key import PrivateKeyDetector
    from detect_secrets.plugins.slack import SlackDetector
    from detect_secrets.plugins.stripe import StripeDetector

    _DS_PLUGINS = [
        AWSKeyDetector(),
        AzureStorageKeyDetector(),
        BasicAuthDetector(),
        GitHubTokenDetector(),
        JwtTokenDetector(),
        OpenAIDetector(),
        PrivateKeyDetector(),
        SlackDetector(),
        StripeDetector(),
    ]
    _detect_secrets_available = True
except ImportError:
    _DS_PLUGINS = []
    _detect_secrets_available = False


def _extract_strings(value: Any) -> list[str]:
    """Recursively collect all string values from a nested payload."""
    results: list[str] = []
    if isinstance(value, str):
        results.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            results.extend(_extract_strings(v))
    elif isinstance(value, list):
        for item in value:
            results.extend(_extract_strings(item))
    return results


def _scan_with_ds(texts: list[str]) -> Generator[str, None, None]:
    """Yield secret type strings for every finding across all texts and plugins.

    In detect-secrets >= 1.5, analyze_string() yields the raw secret value (str).
    The secret type comes from the plugin's own secret_type class attribute.
    """
    for text in texts:
        for line in (text.splitlines() or [text]):
            for plugin in _DS_PLUGINS:
                for _ in plugin.analyze_string(line):
                    yield plugin.secret_type


@register_detector("secrets")
class SecretDetector(Detector):
    name = "secrets"
    reason_code = "SECRET_DETECTED"

    def check(self, payload: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        texts = _extract_strings(payload)

        if _detect_secrets_available:
            seen: set[str] = set()
            for secret_type in _scan_with_ds(texts):
                if secret_type not in seen:
                    seen.add(secret_type)
                    findings.append(
                        DetectorFinding(
                            reason_code=self.reason_code,
                            message=f"Potential secret detected ({secret_type})",
                            detector=self.name,
                            metadata={"secret_type": secret_type},
                        )
                    )
        else:
            # Fallback: scan all strings against expanded regex patterns
            for text in texts:
                for pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(text):
                        findings.append(
                            DetectorFinding(
                                reason_code=self.reason_code,
                                message="Potential secret detected in payload",
                                detector=self.name,
                                metadata={"matched": match.group()[:8] + "…"},
                            )
                        )

        return findings
