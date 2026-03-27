"""PII detector using Microsoft Presidio with regex fallback."""
from __future__ import annotations

from typing import Any

from app.detectors.base import Detector, register_detector
from app.detectors.patterns import PII_PATTERNS
from app.models.events import DetectorFinding

try:
    from presidio_analyzer import AnalyzerEngine

    _analyzer = AnalyzerEngine()
    _presidio_available = True
except Exception:  # covers ImportError and missing spacy model
    _analyzer = None
    _presidio_available = False


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


@register_detector("pii")
class PiiDetector(Detector):
    name = "pii"
    reason_code = "PII_DETECTED"

    def check(self, payload: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        texts = _extract_strings(payload)

        # Presidio for high-confidence entity recognition (names, addresses, etc.)
        if _presidio_available and _analyzer is not None:
            full_text = " ".join(texts)
            if full_text.strip():
                results = _analyzer.analyze(text=full_text, language="en")
                for result in results:
                    findings.append(
                        DetectorFinding(
                            reason_code=self.reason_code,
                            message=f"PII detected: {result.entity_type}",
                            detector=self.name,
                            metadata={"entity_type": result.entity_type, "score": result.score},
                        )
                    )

        # Always also run regex patterns — Presidio with small spacy models misses
        # structured formats like SSNs. Regex is more reliable for these.
        for text in texts:
            for pattern in PII_PATTERNS:
                for _match in pattern.finditer(text):
                    findings.append(
                        DetectorFinding(
                            reason_code=self.reason_code,
                            message="PII pattern detected in payload",
                            detector=self.name,
                        )
                    )

        return findings
