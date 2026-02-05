"""Simple policy engine that wires detectors based on YAML config."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from app.config import get_settings
from app.detectors.base import REGISTRY, Detector
from app.models.events import DetectorFinding, PolicyDecision


class PolicyEngine:
    def __init__(self, policy_path: Path | str | None = None) -> None:
        self.settings = get_settings()
        self.policy_path = Path(policy_path or self.settings.policy_path)
        self.config = self._load_policy()
        self.request_detectors = self._build_detectors(self.config.get("detectors", {}).get("request", []))
        self.response_detectors = self._build_detectors(
            self.config.get("detectors", {}).get("response", [])
        )

    def _load_policy(self) -> Dict[str, Any]:
        with self.policy_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def _build_detectors(self, detector_configs: Iterable[Dict[str, Any]]) -> List[Detector]:
        detectors: List[Detector] = []
        for entry in detector_configs:
            key = entry.get("type")
            config = entry.get("config", {})
            # apply tool allowlist override from settings if provided
            if key == "tool_allowlist" and self.settings.allowed_tools is not None:
                config = {**config, "allowlist": self.settings.allowed_tools}
            detector = REGISTRY.create(key, config=config)
            detectors.append(detector)
        return detectors

    def evaluate_request(self, payload: Dict[str, Any], request_id: str) -> PolicyDecision:
        findings: List[DetectorFinding] = []
        start = time.perf_counter()
        for detector in self.request_detectors:
            findings.extend(detector.check(payload))
        latency_ms = (time.perf_counter() - start) * 1000
        allowed = len(findings) == 0
        return PolicyDecision(
            allowed=allowed,
            request_id=request_id,
            reasons=findings,
            upstream_url=str(self.settings.upstream_base_url),
            latency_ms=latency_ms,
        )

    def evaluate_response(self, payload: Dict[str, Any], request_id: str) -> PolicyDecision:
        if not self.settings.enable_output_detection:
            return PolicyDecision(
                allowed=True,
                request_id=request_id,
                reasons=[],
                upstream_url=str(self.settings.upstream_base_url),
            )

        findings: List[DetectorFinding] = []
        start = time.perf_counter()
        for detector in self.response_detectors:
            findings.extend(detector.check(payload))
        latency_ms = (time.perf_counter() - start) * 1000
        allowed = len(findings) == 0
        return PolicyDecision(
            allowed=allowed,
            request_id=request_id,
            reasons=findings,
            upstream_url=str(self.settings.upstream_base_url),
            latency_ms=latency_ms,
        )


__all__ = ["PolicyEngine"]
