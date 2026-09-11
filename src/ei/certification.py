from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canary import read_hook_status, skill_discovery_canary
from .compatibility import check_compatibility
from .config import PUBLIC_CLI_HOST_IDS
from .hooks.registry import canonical_host_id, get_adapter

# Public certification is intentionally limited to CLI agents.  Legacy
# Codex-App receipts may still be classified as private development evidence,
# but can never satisfy this required release matrix.
REQUIRED_HOST_IDS = PUBLIC_CLI_HOST_IDS
REQUIRED_OS_PROFILES = (
    "windows-10",
    "windows-11",
    "macos-current",
    "ubuntu-24.04",
    "debian-12",
)
REQUIRED_EVENT_NAMES = (
    "session.start",
    "prompt.before",
    "turn.stop",
    "session.end",
)
RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "mode",
        "host_id",
        "host_instance_id",
        "host_version",
        "os_family",
        "os_version",
        "python_version",
        "artifact_sha256",
        "event_sha256",
        "activation_state",
        "certified_at",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_MODES = frozenset({"fixture", "real"})
_ALLOWED_STATUSES = frozenset({"PASSED", "FAILED", "MISSING", "BLOCKED"})
_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
_ABSOLUTE_PATH_RE = re.compile(r"(?:^[A-Za-z]:[\\/]|^/|^\\\\)")
CERTIFICATION_RECEIPT_CLASSES = frozenset({"fixture", "private_development", "real_host"})
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("CERTIFICATION_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("CERTIFICATION_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("CERTIFICATION_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any] | bytes) -> str:
    raw = _canonical_json(value) if isinstance(value, Mapping) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _runtime_root(settings: Any) -> Path:
    paths = getattr(settings, "paths", settings)
    value = getattr(paths, "runtime_root", None)
    if value is None:
        value = getattr(paths, "runtime_dir", None)
    if value is None:
        raise ValueError("CERTIFICATION_RUNTIME_ROOT_REQUIRED")
    return Path(value).expanduser().resolve()


def _host_activation(host_id: str, settings: Any) -> str:
    hosts = getattr(settings, "hosts", {})
    if isinstance(hosts, Mapping):
        spec = hosts.get(host_id)
        if spec is not None:
            value = getattr(spec, "skill_activation_mode", None)
            if isinstance(value, str) and value:
                return value
    return "CONSENT_REQUIRED" if host_id == "gemini-cli" else "AUTO_ALLOWED"


def _environment_value(
    settings: Any,
    name: str,
    default: str,
    override: str | None,
) -> str:
    if override is not None:
        return str(override)
    value = getattr(settings, name, None)
    if isinstance(value, str) and value:
        return value
    return default


def _os_profile(os_family: str, os_version: str) -> str | None:
    family = os_family.casefold()
    version = os_version.casefold()
    if family in {"windows", "microsoft windows"}:
        if "11" in version:
            return "windows-11"
        if "10" in version:
            return "windows-10"
    if family in {"darwin", "macos", "mac os", "mac"}:
        return "macos-current"
    if family in {"linux", "ubuntu", "debian"}:
        if "ubuntu" in version and ("24.04" in version or "24" in version):
            return "ubuntu-24.04"
        if "debian" in version and ("12" in version or "bookworm" in version):
            return "debian-12"
    return None


def _artifact_basis(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in sorted(RECEIPT_KEYS - {"artifact_sha256"})}


def _receipt_id(host_id: str, instance_id: str, mode: str, certified_at: str) -> str:
    material = f"{host_id}|{instance_id}|{mode}|{certified_at}".encode("utf-8")
    return "cert_" + hashlib.sha256(material).hexdigest()[:32]


def validate_receipt_artifact(receipt: Mapping[str, Any]) -> bool:
    if not isinstance(receipt, Mapping):
        raise ValueError("CERTIFICATION_RECEIPT_OBJECT_REQUIRED")
    if set(receipt) != RECEIPT_KEYS:
        raise ValueError("CERTIFICATION_RECEIPT_SCHEMA_INVALID")
    if receipt.get("mode") not in _ALLOWED_MODES:
        raise ValueError("CERTIFICATION_MODE_INVALID")
    try:
        host_id = canonical_host_id(str(receipt["host_id"]))
        get_adapter(host_id)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("CERTIFICATION_HOST_INVALID") from exc
    for name in (
        "receipt_id",
        "host_instance_id",
        "host_version",
        "os_family",
        "os_version",
        "python_version",
        "activation_state",
        "certified_at",
    ):
        value = receipt.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("CERTIFICATION_RECEIPT_FIELD_INVALID")
        if "\x00" in value:
            raise ValueError("CERTIFICATION_RECEIPT_FIELD_INVALID")
    if not _SHA256_RE.fullmatch(str(receipt["artifact_sha256"])):
        raise ValueError("CERTIFICATION_ARTIFACT_HASH_INVALID")
    if not _SHA256_RE.fullmatch(str(receipt["event_sha256"])):
        raise ValueError("CERTIFICATION_EVENT_HASH_INVALID")
    certified_at = _parse_time(receipt["certified_at"])
    if certified_at > _now() + timedelta(minutes=5):
        raise ValueError("CERTIFICATION_TIME_IN_FUTURE")
    expected = _digest(_artifact_basis(receipt))
    if receipt["artifact_sha256"] != expected:
        raise ValueError("CERTIFICATION_ARTIFACT_HASH_MISMATCH")
    raw = json.dumps(dict(receipt), ensure_ascii=False)
    forbidden = ("prompt", "response", "tool_output", "authorization", "bearer ")
    if any(value in raw.casefold() for value in forbidden):
        raise ValueError("CERTIFICATION_RAW_CONTENT_FORBIDDEN")
    if any(
        isinstance(value, str) and _ABSOLUTE_PATH_RE.search(value)
        for value in receipt.values()
    ):
        raise ValueError("CERTIFICATION_ABSOLUTE_PATH_FORBIDDEN")
    return True


def classify_certification_receipt(
    receipt: Mapping[str, Any],
    *,
    public_subject_commit_sha: str | None = None,
) -> str:
    """Return an explicit evidence class; an unbound real receipt is private development evidence."""
    validate_receipt_artifact(receipt)
    if receipt["mode"] == "fixture":
        return "fixture"
    if public_subject_commit_sha is None:
        return "private_development"
    if not isinstance(public_subject_commit_sha, str) or not _COMMIT_SHA_RE.fullmatch(public_subject_commit_sha):
        raise ValueError("CERTIFICATION_PUBLIC_SUBJECT_INVALID")
    if receipt.get("activation_state") == "real-missing":
        return "private_development"
    return "real_host"


def _missing_receipt(
    host_id: str,
    instance_id: str,
    mode: str,
    settings: Any,
    *,
    reason: str,
    now: datetime,
    os_family: str | None = None,
    os_version: str | None = None,
    host_version: str | None = None,
    os_profile: str | None = None,
) -> "CertificationResult":
    family = _environment_value(settings, "certification_os_family", platform.system(), os_family)
    version_default = platform.release()
    version = _environment_value(settings, "certification_os_version", version_default, os_version)
    if os_profile:
        version = os_profile
    certified_at = _iso(now)
    receipt = {
        "receipt_id": _receipt_id(host_id, instance_id, mode, certified_at),
        "mode": mode,
        "host_id": host_id,
        "host_instance_id": instance_id,
        "host_version": host_version or ("fixture" if mode == "fixture" else "unknown"),
        "os_family": family,
        "os_version": version,
        "python_version": platform.python_version(),
        "event_sha256": _digest({"required_events": list(REQUIRED_EVENT_NAMES), "observed_events": []}),
        "activation_state": "fixture-only" if mode == "fixture" else "real-missing",
        "certified_at": certified_at,
    }
    receipt["artifact_sha256"] = _digest(_artifact_basis(receipt))
    result = CertificationResult(
        host_id=host_id,
        host_instance_id=instance_id,
        mode=mode,
        status="PASSED" if mode == "fixture" else "MISSING",
        reason_codes=() if mode == "fixture" else (reason,),
        receipt=receipt,
        real_evidence=False,
        os_profile=os_profile or _os_profile(family, version) or "",
    )
    return result


def _official_host_version(host_id: str, settings: Any) -> str:
    hosts = getattr(settings, "hosts", {})
    spec = hosts.get(host_id) if isinstance(hosts, Mapping) else None
    names = tuple(getattr(spec, "executable_names", ())) if spec is not None else ()
    for name in names:
        executable = shutil.which(str(name))
        if not executable:
            continue
        try:
            completed = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(r"\bv?\d+(?:\.\d+){1,3}\b", output)
        if match:
            return match.group(0)
    return "unknown"


def _read_real_events(
    host_id: str,
    instance_id: str,
    settings: Any,
    now: datetime,
) -> tuple[dict[str, str], str, bool]:
    path = _runtime_root(settings) / "canary-receipts.jsonl"
    if not path.is_file():
        return {}, "unknown", False
    ttl_value = getattr(settings, "canary_receipt_ttl_seconds", _DEFAULT_TTL_SECONDS)
    try:
        ttl = max(1, int(ttl_value))
    except (TypeError, ValueError):
        ttl = _DEFAULT_TTL_SECONDS
    observed: dict[str, str] = {}
    host_version = "unknown"
    found_real = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}, "unknown", False
    for line in lines:
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeError):
            continue
        if not isinstance(value, Mapping):
            continue
        if value.get("record_type") not in {None, "hook_canary"}:
            continue
        if canonical_host_id(str(value.get("host_id", ""))) != host_id:
            continue
        if str(value.get("host_instance_id", "")) != instance_id:
            continue
        if value.get("mode") != "real" or value.get("outcome", "PASSED") != "PASSED":
            continue
        try:
            completed = _parse_time(value.get("completed_at"))
        except ValueError:
            continue
        if now - completed > timedelta(seconds=ttl):
            continue
        events = value.get("event_receipt_hashes", {})
        if not isinstance(events, Mapping):
            continue
        found_real = True
        candidate_version = value.get("host_version")
        if isinstance(candidate_version, str) and candidate_version and candidate_version != "unknown":
            host_version = candidate_version
        for event_name, event_hash in events.items():
            if (
                isinstance(event_name, str)
                and event_name in REQUIRED_EVENT_NAMES
                and isinstance(event_hash, str)
                and _SHA256_RE.fullmatch(event_hash)
            ):
                observed[event_name] = event_hash
    return observed, host_version, found_real


@dataclass(frozen=True)
class CertificationResult:
    host_id: str
    host_instance_id: str
    mode: str
    status: str
    reason_codes: tuple[str, ...]
    receipt: Mapping[str, Any]
    real_evidence: bool
    os_profile: str = ""

    def __post_init__(self) -> None:
        host = canonical_host_id(self.host_id)
        if host not in REQUIRED_HOST_IDS:
            raise ValueError("CERTIFICATION_HOST_INVALID")
        if self.mode not in _ALLOWED_MODES or self.status not in _ALLOWED_STATUSES:
            raise ValueError("CERTIFICATION_RESULT_INVALID")
        if not str(self.host_instance_id).strip():
            raise ValueError("CERTIFICATION_INSTANCE_INVALID")
        validate_receipt_artifact(self.receipt)
        if self.receipt["host_id"] != host or self.receipt["host_instance_id"] != str(self.host_instance_id):
            raise ValueError("CERTIFICATION_IDENTITY_MISMATCH")
        if self.receipt["mode"] != self.mode:
            raise ValueError("CERTIFICATION_MODE_MISMATCH")
        if self.real_evidence and not (self.mode == "real" and self.status == "PASSED"):
            raise ValueError("CERTIFICATION_REAL_FLAG_INVALID")
        object.__setattr__(self, "host_id", host)
        object.__setattr__(self, "host_instance_id", str(self.host_instance_id))
        object.__setattr__(self, "reason_codes", tuple(dict.fromkeys(str(item) for item in self.reason_codes)))
        object.__setattr__(self, "receipt", dict(self.receipt))

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "host_instance_id": self.host_instance_id,
            "mode": self.mode,
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "receipt": dict(self.receipt),
            "real_evidence": self.real_evidence,
        }


@dataclass(frozen=True)
class CertificationSetStatus:
    software_complete: bool
    production_enabled: bool
    missing_hosts: tuple[str, ...]
    missing_os_profiles: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "software_complete": self.software_complete,
            "production_enabled": self.production_enabled,
            "missing_hosts": list(self.missing_hosts),
            "missing_os_profiles": list(self.missing_os_profiles),
            "reason_codes": list(self.reason_codes),
        }


def certify_host(
    host_id: str,
    host_instance_id: str,
    mode: str,
    settings: Any,
    *,
    now: datetime | None = None,
    os_family: str | None = None,
    os_version: str | None = None,
    os_profile: str | None = None,
) -> CertificationResult:
    try:
        host = canonical_host_id(host_id)
        get_adapter(host)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("CERTIFICATION_HOST_INVALID") from exc
    instance = str(host_instance_id).strip()
    if not instance:
        raise ValueError("CERTIFICATION_INSTANCE_INVALID")
    if mode not in _ALLOWED_MODES:
        raise ValueError("CERTIFICATION_MODE_INVALID")
    timestamp = now.astimezone(timezone.utc) if now is not None else _now()
    if mode == "fixture":
        return _missing_receipt(
            host,
            instance,
            mode,
            settings,
            reason="",
            now=timestamp,
            os_family=os_family,
            os_version=os_version,
            os_profile=os_profile,
            host_version="fixture",
        )
    observed, host_version, found_real = _read_real_events(host, instance, settings, timestamp)
    if host_version in {"", "unknown"}:
        host_version = _official_host_version(host, settings)
    reasons: list[str] = []
    try:
        hook_status = read_hook_status(host, instance, settings)
        hook_verified = getattr(hook_status, "hook_status", "") == "HOOK_VERIFIED"
    except (OSError, ValueError, TypeError):
        hook_verified = False
    try:
        skill_status = skill_discovery_canary(host, instance, settings)
    except (OSError, ValueError, TypeError):
        skill_status = "NOT_FOUND"
    if not found_real or not hook_verified or not set(REQUIRED_EVENT_NAMES).issubset(observed):
        reasons.append("HOST_CERTIFICATION_MISSING")
    if skill_status != "DISCOVERED":
        reasons.append("SKILL_DISCOVERY_MISSING")
    if host_version in {"", "unknown"}:
        reasons.append("HOST_VERSION_MISSING")
    hosts = getattr(settings, "hosts", {})
    if not isinstance(hosts, Mapping) or host not in hosts:
        reasons.append("HOST_EXECUTABLE_NOT_FOUND")
    else:
        compatibility = check_compatibility(host, None, host_version, settings)
        if not compatibility.installed:
            reasons.append("HOST_EXECUTABLE_NOT_FOUND")
    if reasons:
        result = _missing_receipt(
            host,
            instance,
            mode,
            settings,
            reason="HOST_CERTIFICATION_MISSING",
            now=timestamp,
            os_family=os_family,
            os_version=os_version,
            os_profile=os_profile,
            host_version=host_version,
        )
        return CertificationResult(
            host_id=result.host_id,
            host_instance_id=result.host_instance_id,
            mode=result.mode,
            status="MISSING",
            reason_codes=tuple(dict.fromkeys(reasons)),
            receipt=result.receipt,
            real_evidence=False,
            os_profile=result.os_profile,
        )
    family = _environment_value(settings, "certification_os_family", platform.system(), os_family)
    version = _environment_value(settings, "certification_os_version", platform.release(), os_version)
    if os_profile:
        version = os_profile
    certified_at = _iso(timestamp)
    event_hash = _digest({"required_events": list(REQUIRED_EVENT_NAMES), "observed_events": dict(sorted(observed.items()))})
    receipt = {
        "receipt_id": _receipt_id(host, instance, mode, certified_at),
        "mode": "real",
        "host_id": host,
        "host_instance_id": instance,
        "host_version": host_version,
        "os_family": family,
        "os_version": version,
        "python_version": platform.python_version(),
        "event_sha256": event_hash,
        "activation_state": _host_activation(host, settings),
        "certified_at": certified_at,
    }
    receipt["artifact_sha256"] = _digest(_artifact_basis(receipt))
    return CertificationResult(
        host_id=host,
        host_instance_id=instance,
        mode="real",
        status="PASSED",
        reason_codes=(),
        receipt=receipt,
        real_evidence=True,
        os_profile=os_profile or _os_profile(family, version) or "",
    )


def evaluate_certification_set(
    results: Iterable[CertificationResult],
    *,
    required_host_ids: Sequence[str] = REQUIRED_HOST_IDS,
    required_os_profiles: Sequence[str] = REQUIRED_OS_PROFILES,
) -> CertificationSetStatus:
    normalized_hosts = tuple(canonical_host_id(item) for item in required_host_ids)
    normalized_os = tuple(str(item) for item in required_os_profiles)
    valid = [item for item in results if isinstance(item, CertificationResult) and item.status == "PASSED" and item.real_evidence]
    host_ids = {item.host_id for item in valid}
    missing_hosts = tuple(host for host in normalized_hosts if host not in host_ids)
    observed_os = {
        item.os_profile or _os_profile(str(item.receipt["os_family"]), str(item.receipt["os_version"]))
        for item in valid
    }
    observed_os.discard(None)
    missing_os = tuple(profile for profile in normalized_os if profile not in observed_os)
    reasons: list[str] = []
    if missing_hosts:
        reasons.append("HOST_CERTIFICATION_MISSING")
    if missing_os:
        reasons.append("OS_CERTIFICATION_MISSING")
    if any(item.mode == "fixture" for item in results):
        reasons.append("REAL_CERTIFICATION_REQUIRED")
    if not valid:
        reasons.append("REAL_CERTIFICATION_REQUIRED")
    complete = not missing_hosts and not missing_os
    return CertificationSetStatus(
        software_complete=complete,
        production_enabled=False,
        missing_hosts=missing_hosts,
        missing_os_profiles=missing_os,
        reason_codes=tuple(dict.fromkeys(reasons)),
    )


def write_certification_artifact(path: Path | str, result: CertificationResult | Mapping[str, Any]) -> Path:
    receipt = result.receipt if isinstance(result, CertificationResult) else result
    validate_receipt_artifact(receipt)
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(dict(receipt), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def read_certification_artifact(path: Path | str) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("CERTIFICATION_ARTIFACT_READ_FAILED") from exc
    validate_receipt_artifact(value)
    return dict(value)


__all__ = [
    "CertificationResult",
    "CertificationSetStatus",
    "CERTIFICATION_RECEIPT_CLASSES",
    "RECEIPT_KEYS",
    "REQUIRED_EVENT_NAMES",
    "REQUIRED_HOST_IDS",
    "REQUIRED_OS_PROFILES",
    "certify_host",
    "classify_certification_receipt",
    "evaluate_certification_set",
    "read_certification_artifact",
    "validate_receipt_artifact",
    "write_certification_artifact",
]
