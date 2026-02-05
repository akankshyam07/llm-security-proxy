"""Detector that blocks non-allowlisted tool/function calls."""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.detectors.base import Detector, register_detector
from app.models.events import DetectorFinding


@register_detector("tool_allowlist")
class ToolAllowlistDetector(Detector):
    name = "tool_allowlist"
    reason_code = "TOOL_CALL_BLOCKED"

    def check(self, payload: Dict[str, Any]) -> List[DetectorFinding]:
        allowlist: Sequence[str] = self.config.get("allowlist", [])
        if not allowlist:
            return []

        # OpenAI-style tool_calls live under messages[].tool_calls[].function.name
        requested_tools: List[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                if "function" in value and isinstance(value.get("function"), dict):
                    name = value["function"].get("name")
                    if isinstance(name, str):
                        requested_tools.append(name)
                if "tool_calls" in value and isinstance(value.get("tool_calls"), list):
                    for call in value["tool_calls"]:
                        walk(call)
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(payload)

        blocked = [tool for tool in requested_tools if tool not in allowlist]
        if not blocked:
            return []

        return [
            DetectorFinding(
                reason_code=self.reason_code,
                message=f"Tool calls blocked: {', '.join(blocked)}",
                detector=self.name,
                metadata={"blocked_tools": blocked, "allowlist": list(allowlist)},
            )
        ]
