from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

HOOK_STATUSES = frozenset({"HOOK_VERIFIED", "HOOK_UNVERIFIED", "INSTRUCTION_FALLBACK", "DISABLED", "BROKEN"})
SKILL_DISCOVERY_STATUSES = frozenset({"DISCOVERED", "UNVERIFIED", "NOT_FOUND", "UNSUPPORTED"})
SKILL_ACTIVATION_MODES = frozenset({"AUTO_ALLOWED", "CONSENT_REQUIRED", "MANUAL_ONLY", "UNAVAILABLE"})
CAPTURE_PRIMARY_PATHS = frozenset({"HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"})


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class HookStatus:
    host_id: str
    host_instance_id: str
    hook_status: str
    skill_discovery_status: str
    skill_activation_mode: str
    capture_primary_path: str
    reason_codes: tuple[str, ...] = ()
    static_checks: Mapping[str, Any] = field(default_factory=dict)
    received_events: tuple[str, ...] = ()
    last_receipt_at: str | None = None
    fallback_command: str | None = None
    checked_at: str = field(default_factory=_timestamp)
    team: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.host_id or not self.host_instance_id:
            raise ValueError("HOOK_STATUS_ID_INVALID")
        if self.hook_status not in HOOK_STATUSES:
            raise ValueError("HOOK_STATUS_INVALID")
        if self.skill_discovery_status not in SKILL_DISCOVERY_STATUSES:
            raise ValueError("SKILL_DISCOVERY_STATUS_INVALID")
        if self.skill_activation_mode not in SKILL_ACTIVATION_MODES:
            raise ValueError("SKILL_ACTIVATION_MODE_INVALID")
        if self.capture_primary_path not in CAPTURE_PRIMARY_PATHS:
            raise ValueError("CAPTURE_PRIMARY_PATH_INVALID")
        if any(not isinstance(item, str) or not item for item in self.reason_codes):
            raise ValueError("HOOK_REASON_INVALID")
        if any(not isinstance(item, str) or not item for item in self.received_events):
            raise ValueError("HOOK_RECEIVED_EVENT_INVALID")

    @property
    def status(self) -> str:
        return self.hook_status

    @property
    def skill_status(self) -> str:
        return self.skill_discovery_status

    @property
    def activation_mode(self) -> str:
        return self.skill_activation_mode

    @property
    def capture_primary(self) -> str:
        return self.capture_primary_path

    @property
    def verified(self) -> bool:
        return self.hook_status == "HOOK_VERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "host_instance_id": self.host_instance_id,
            "hook_status": self.hook_status,
            "skill_discovery_status": self.skill_discovery_status,
            "skill_activation_mode": self.skill_activation_mode,
            "capture_primary_path": self.capture_primary_path,
            "reason_codes": list(self.reason_codes),
            "static_checks": dict(self.static_checks),
            "received_events": list(self.received_events),
            "last_receipt_at": self.last_receipt_at,
            "fallback_command": self.fallback_command,
            "checked_at": self.checked_at,
            "team": dict(self.team),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "HookStatus":
        if not isinstance(value, Mapping):
            raise ValueError("HOOK_STATUS_OBJECT_REQUIRED")
        return cls(
            host_id=str(value.get("host_id", "")),
            host_instance_id=str(value.get("host_instance_id", "")),
            hook_status=str(value.get("hook_status", value.get("status", ""))),
            skill_discovery_status=str(value.get("skill_discovery_status", "UNVERIFIED")),
            skill_activation_mode=str(value.get("skill_activation_mode", "UNAVAILABLE")),
            capture_primary_path=str(value.get("capture_primary_path", "NATIVE_SOURCE")),
            reason_codes=tuple(str(item) for item in value.get("reason_codes", ()) if isinstance(item, str)),
            static_checks=dict(value.get("static_checks", {})) if isinstance(value.get("static_checks", {}), Mapping) else {},
            received_events=tuple(str(item) for item in value.get("received_events", ()) if isinstance(item, str)),
            last_receipt_at=value.get("last_receipt_at") if isinstance(value.get("last_receipt_at"), str) else None,
            fallback_command=value.get("fallback_command") if isinstance(value.get("fallback_command"), str) else None,
            checked_at=str(value.get("checked_at", _timestamp())),
            team=dict(value.get("team", {})) if isinstance(value.get("team", {}), Mapping) else {},
        )


__all__ = [
    "CAPTURE_PRIMARY_PATHS",
    "HOOK_STATUSES",
    "SKILL_ACTIVATION_MODES",
    "SKILL_DISCOVERY_STATUSES",
    "HookStatus",
]
