"""Secret token detector."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from app.detectors.base import Detector, register_detector
from app.models.events import DetectorFinding

SECRET_REGEXES = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9-_\.]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"),
]


@register_detector("secrets")
class SecretDetector(Detector):
    name = "secrets"
    reason_code = "SECRET_DETECTED"

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
                for pattern in SECRET_REGEXES:
                    if pattern.search(value):
                        findings.append(
                            DetectorFinding(
                                reason_code=self.reason_code,
                                message="Potential secret detected in payload",
                                detector=self.name,
                            )
                        )
                        return

        walk(payload)
        return findings
