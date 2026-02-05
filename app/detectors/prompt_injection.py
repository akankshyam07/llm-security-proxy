"""Naive prompt-injection detector using heuristics."""
from __future__ import annotations

from typing import Any, Dict, List

from app.detectors.base import Detector, register_detector
from app.models.events import DetectorFinding

TRIGGER_PHRASES = [
    "ignore previous instructions",
    "disregard prior",
    "system prompt",
    "developer message",
    "reveal hidden instructions",
    "bypass safety",
]


@register_detector("prompt_injection")
class PromptInjectionDetector(Detector):
    name = "prompt_injection"
    reason_code = "PROMPT_INJECTION_SUSPECTED"

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
                lowered = value.lower()
                if any(trigger in lowered for trigger in TRIGGER_PHRASES):
                    findings.append(
                        DetectorFinding(
                            reason_code=self.reason_code,
                            message="Prompt injection heuristic matched",
                            detector=self.name,
                        )
                    )

        walk(payload)
        return findings
