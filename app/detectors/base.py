"""Detector base classes and registry."""
from __future__ import annotations

import abc
from typing import Any, Dict, List

from app.models.events import DetectorFinding


class Detector(abc.ABC):
    name: str
    reason_code: str

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abc.abstractmethod
    def check(self, payload: Dict[str, Any]) -> List[DetectorFinding]:
        """Inspect the payload and return any findings."""


class DetectorRegistry:
    def __init__(self) -> None:
        self._registry: Dict[str, type[Detector]] = {}

    def register(self, key: str, detector_cls: type[Detector]) -> None:
        self._registry[key] = detector_cls

    def create(self, key: str, config: Dict[str, Any] | None = None) -> Detector:
        if key not in self._registry:
            raise KeyError(f"Unknown detector: {key}")
        return self._registry[key](config=config)

    def available(self) -> List[str]:
        return sorted(self._registry.keys())


REGISTRY = DetectorRegistry()


def register_detector(name: str):
    def decorator(cls: type[Detector]) -> type[Detector]:
        REGISTRY.register(name, cls)
        return cls

    return decorator


__all__ = ["Detector", "REGISTRY", "register_detector", "DetectorRegistry"]
