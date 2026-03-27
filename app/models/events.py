"""Shared data models for logging and detector findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectorFinding:
    reason_code: str
    message: str
    detector: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    allowed: bool
    request_id: str
    reasons: list[DetectorFinding] = field(default_factory=list)
    upstream_url: str | None = None
    latency_ms: float | None = None

    @property
    def reason_codes(self) -> list[str]:
        return [finding.reason_code for finding in self.reasons]


__all__ = ["DetectorFinding", "PolicyDecision"]
