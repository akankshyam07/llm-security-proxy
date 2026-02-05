"""Shared data models for logging and detector findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectorFinding:
    reason_code: str
    message: str
    detector: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    allowed: bool
    request_id: str
    reasons: List[DetectorFinding] = field(default_factory=list)
    upstream_url: Optional[str] = None
    latency_ms: Optional[float] = None

    @property
    def reason_codes(self) -> List[str]:
        return [finding.reason_code for finding in self.reasons]


__all__ = ["DetectorFinding", "PolicyDecision"]
