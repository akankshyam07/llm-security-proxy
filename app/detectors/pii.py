"""PII detector for common personal information patterns."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from app.detectors.base import Detector, register_detector
from app.models.events import DetectorFinding

PII_REGEXES = [
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
    re.compile(r"\+?\d{1,2}[\s-]?(?:\(\d{3}\)|\d{3})[\s-]?\d{3}[\s-]?\d{4}"),
]


@register_detector("pii")
class PiiDetector(Detector):
    name = "pii"
    reason_code = "PII_DETECTED"

    def check(self, payload: Dict[str, Any]) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)
            elif isinstance(value, str):
                for pattern in PII_REGEXES:
                    if pattern.search(value):
                        findings.append(
                            DetectorFinding(
                                reason_code=self.reason_code,
                                message="PII pattern detected in payload",
                                detector=self.name,
                            )
                        )
                        return

        walk(payload)
        return findings
