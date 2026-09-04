from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


REGISTRY_PATH = Path(__file__).with_name("capabilities.json")


@dataclass(frozen=True)
class CapabilityRequest:
    capability: str
    permission: str = "READ"
    context: Optional[Dict[str, Any]] = None


class CapabilityRegistry:
    """Small capability-first router for OGENIC CORE HARNESS.

    This intentionally separates *what needs to be done* from *which concrete
    tool/agent performs it*. Concrete bindings can be supplied at runtime.
    """

    def __init__(self, registry_path: Path = REGISTRY_PATH) -> None:
        self.registry_path = registry_path
        self.data = json.loads(registry_path.read_text(encoding="utf-8"))
        self._capabilities = self._flatten(self.data.get("planes", {}))
        self._aliases = self.data.get("aliases", {})

    @staticmethod
    def _flatten(planes: Dict[str, Iterable[str]]) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for plane, capabilities in planes.items():
            for capability in capabilities:
                result[capability] = plane
        return result

    def resolve_alias(self, command: str) -> str:
        return self._aliases.get(command, command)

    def has(self, capability: str) -> bool:
        return self.resolve_alias(capability) in self._capabilities

    def plane_for(self, capability: str) -> Optional[str]:
        return self._capabilities.get(self.resolve_alias(capability))

    def discover(self, text: str = "") -> List[Dict[str, str]]:
        needle = text.strip().lower()
        rows = []
        for capability, plane in sorted(self._capabilities.items()):
            if not needle or needle in capability.lower() or needle in plane.lower():
                rows.append({"capability": capability, "plane": plane})
        return rows

    def validate_permission(self, permission: str) -> None:
        allowed = self.data.get("permission_classes", [])
        if permission not in allowed:
            raise ValueError(f"Unsupported permission class: {permission}")

    def route(self, request: CapabilityRequest, bindings: Dict[str, str]) -> Dict[str, Any]:
        capability = self.resolve_alias(request.capability)
        self.validate_permission(request.permission)

        if capability not in self._capabilities:
            return {
                "status": "CAPABILITY_REQUIRED",
                "capability": capability,
                "permission": request.permission,
                "continue_independent_work": True,
            }

        binding = bindings.get(capability)
        if not binding:
            return {
                "status": "UNBOUND_CAPABILITY",
                "capability": capability,
                "plane": self._capabilities[capability],
                "permission": request.permission,
                "continue_independent_work": True,
            }

        return {
            "status": "READY",
            "capability": capability,
            "plane": self._capabilities[capability],
            "permission": request.permission,
            "tool_binding": binding,
            "context": request.context or {},
        }


if __name__ == "__main__":
    registry = CapabilityRegistry()
    for row in registry.discover():
        print(f"{row['plane']:16} {row['capability']}")
