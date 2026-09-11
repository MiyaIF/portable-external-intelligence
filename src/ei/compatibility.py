from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .config import Settings


SkillDiscoveryStatus = Literal["DISCOVERED", "UNVERIFIED", "NOT_FOUND", "UNSUPPORTED"]
SkillActivationMode = Literal["AUTO_ALLOWED", "CONSENT_REQUIRED", "MANUAL_ONLY", "UNAVAILABLE"]
CapturePrimaryPath = Literal["HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"]
HookFeatureState = Literal["ENABLED", "DISABLED", "UNKNOWN", "NOT_APPLICABLE"]


@dataclass(frozen=True)
class CompatibilityResult:
    host_id: str
    executable_path: Path | None
    installed: bool
    detected_version: str | None
    hook_feature_state: HookFeatureState
    hook_schema_supported: bool
    skill_discovery_status: SkillDiscoveryStatus
    skill_activation_mode: SkillActivationMode
    capture_primary_path: CapturePrimaryPath
    reason_codes: tuple[str, ...]
    # A host ID can be configured more than once on a machine.  Keep the
    # instance identity alongside compatibility evidence so consumers do not
    # accidentally treat one installation as another.
    host_instance_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "host_instance_id": self.host_instance_id or self.host_id,
            "executable_path": str(self.executable_path) if self.executable_path else None,
            "installed": self.installed,
            "detected_version": self.detected_version,
            "hook_feature_state": self.hook_feature_state,
            "hook_schema_supported": self.hook_schema_supported,
            "skill_discovery_status": self.skill_discovery_status,
            "skill_activation_mode": self.skill_activation_mode,
            "capture_primary_path": self.capture_primary_path,
            "reason_codes": list(self.reason_codes),
        }


def _version_parts(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"\s*v?(\d+(?:\.\d+)*)(?:[-+].*)?\s*", value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _version_at_least(version: str, minimum: str) -> bool | None:
    actual = _version_parts(version)
    required = _version_parts(minimum)
    if actual is None or required is None:
        return None
    width = max(len(actual), len(required))
    return (actual + (0,) * (width - len(actual))) >= (required + (0,) * (width - len(required)))


def _find_executable(names: tuple[str, ...]) -> Path | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found).expanduser().resolve()
    return None


def _skill_discovery_status(roots: tuple[Path, ...]) -> SkillDiscoveryStatus:
    if not roots:
        return "UNSUPPORTED"
    if any((root / "external-intelligence" / "SKILL.md").is_file() or (root / "SKILL.md").is_file() for root in roots):
        return "DISCOVERED"
    if any(root.exists() for root in roots):
        return "UNVERIFIED"
    return "NOT_FOUND"


def check_compatibility(
    host_id: str,
    executable: Path | None,
    version: str | None,
    settings: Settings,
    *,
    host_instance_id: str | None = None,
) -> CompatibilityResult:
    instance_id = str(host_instance_id or host_id)
    host = settings.hosts.get(host_id)
    if host is None:
        return CompatibilityResult(
            host_id=host_id,
            executable_path=None,
            installed=False,
            detected_version=version,
            hook_feature_state="UNKNOWN",
            hook_schema_supported=False,
            skill_discovery_status="UNSUPPORTED",
            skill_activation_mode="UNAVAILABLE",
            capture_primary_path="NATIVE_SOURCE",
            reason_codes=("HOST_UNSUPPORTED",),
            host_instance_id=instance_id,
        )

    executable_path = Path(executable).expanduser().resolve() if executable is not None else _find_executable(tuple(host.executable_names))
    installed = bool(executable_path and executable_path.is_file())
    if host.hook_feature_key is None:
        feature_state: HookFeatureState = "NOT_APPLICABLE"
    elif version is None:
        feature_state = "UNKNOWN"
    elif host.minimum_supported_version is None:
        feature_state = "ENABLED"
    else:
        supported = _version_at_least(version, host.minimum_supported_version)
        feature_state = "UNKNOWN" if supported is None else ("ENABLED" if supported else "DISABLED")

    skill_status = _skill_discovery_status(tuple(host.skill_roots))
    reasons: list[str] = []
    if not installed:
        reasons.append("HOST_EXECUTABLE_NOT_FOUND")
    if feature_state == "UNKNOWN":
        reasons.extend(("HOST_VERSION_UNKNOWN", "HOOK_UNVERIFIED"))
    elif feature_state == "DISABLED":
        reasons.append("HOOK_FEATURE_DISABLED")
    elif feature_state == "ENABLED":
        reasons.append("HOOK_FEATURE_ENABLED")
    if skill_status == "NOT_FOUND":
        reasons.append("SKILL_NOT_FOUND")
    elif skill_status == "UNVERIFIED":
        reasons.append("SKILL_UNVERIFIED")
    elif skill_status == "UNSUPPORTED":
        reasons.append("SKILL_UNSUPPORTED")
    return CompatibilityResult(
        host_id=host.host_id,
        executable_path=executable_path,
        installed=installed,
        detected_version=version,
        hook_feature_state=feature_state,
        hook_schema_supported=feature_state in ("ENABLED", "NOT_APPLICABLE"),
        skill_discovery_status=skill_status,
        skill_activation_mode=host.skill_activation_mode,
        capture_primary_path=host.capture_primary_path,
        reason_codes=tuple(reasons),
        host_instance_id=instance_id,
    )
