"""Prompt injection detector using an ML classifier with heuristic fallback."""
from __future__ import annotations

from typing import Any

from app.detectors.base import Detector, register_detector
from app.models.events import DetectorFinding

try:
    from transformers import pipeline as hf_pipeline

    _transformers_available = True
except ImportError:
    _transformers_available = False

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_DEFAULT_THRESHOLD = 0.85
_INJECTION_LABEL = "INJECTION"

# Expanded heuristic list used when ML is disabled or unavailable.
# Covers common jailbreak/injection patterns but is still bypassable — use ML in production.
TRIGGER_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard prior",
    "disregard all previous",
    "forget previous instructions",
    "forget all prior",
    "system prompt",
    "developer message",
    "reveal hidden instructions",
    "bypass safety",
    "bypass your",
    "override instructions",
    "override your",
    "new persona",
    "act as if",
    "pretend you are",
    "pretend to be",
    "you are now",
    "from now on you",
    "jailbreak",
    "dan mode",
    "do anything now",
    "ignore constraints",
    "without restrictions",
    "no restrictions",
    "ignore ethics",
    "ignore your training",
    "ignore your guidelines",
    "you have no restrictions",
    "your new instructions",
    "your true self",
    "escape from",
    "unlock your",
]


def _extract_text(payload: Any) -> str:
    """Concatenate all string values from the payload for classification."""
    parts: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return " ".join(parts)


@register_detector("prompt_injection")
class PromptInjectionDetector(Detector):
    name = "prompt_injection"
    reason_code = "PROMPT_INJECTION_SUSPECTED"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        cfg = config or {}
        use_ml: bool = cfg.get("use_ml", True)
        model_name: str = cfg.get("model", _DEFAULT_MODEL)
        self._threshold: float = float(cfg.get("threshold", _DEFAULT_THRESHOLD))
        self._classifier = None

        if use_ml and _transformers_available:
            self._classifier = hf_pipeline(
                "text-classification",
                model=model_name,
                truncation=True,
                max_length=512,
            )

    def check(self, payload: dict[str, Any]) -> list[DetectorFinding]:
        if self._classifier is not None:
            return self._ml_check(payload)
        return self._heuristic_check(payload)

    def _ml_check(self, payload: dict[str, Any]) -> list[DetectorFinding]:
        text = _extract_text(payload)
        if not text.strip():
            return []
        result = self._classifier(text[:512])[0]
        if result["label"] == _INJECTION_LABEL and result["score"] >= self._threshold:
            return [
                DetectorFinding(
                    reason_code=self.reason_code,
                    message="ML classifier detected prompt injection",
                    detector=self.name,
                    metadata={"score": result["score"], "label": result["label"]},
                )
            ]
        return []

    def _heuristic_check(self, payload: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for v in value.values():
                    walk(v)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str):
                lowered = value.lower()
                matched = [p for p in TRIGGER_PHRASES if p in lowered]
                if matched:
                    findings.append(
                        DetectorFinding(
                            reason_code=self.reason_code,
                            message=f"Prompt injection heuristic matched: {matched[0]!r}",
                            detector=self.name,
                            metadata={"matched_phrases": matched},
                        )
                    )

        walk(payload)
        return findings
