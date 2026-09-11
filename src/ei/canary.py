from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from .config import HostSpec, Settings
from .hooks.base import NormalizedHookEvent, extract_hook_command_fields, validate_hook_command, validate_hook_command_fields
from .hooks.registry import canonical_host_id, supported_events

HookStatusValue = Literal["HOOK_VERIFIED", "HOOK_UNVERIFIED", "INSTRUCTION_FALLBACK", "DISABLED", "BROKEN"]
SkillDiscoveryStatus = Literal["DISCOVERED", "UNVERIFIED", "NOT_FOUND", "UNSUPPORTED"]
SkillActivationMode = Literal["AUTO_ALLOWED", "CONSENT_REQUIRED", "MANUAL_ONLY", "UNAVAILABLE"]
CapturePrimaryPath = Literal["HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"]
CertificationMode = Literal["fixture", "real"]
CertificationOutcome = Literal["PASSED", "FAILED", "MISSING", "BLOCKED"]

HOOK_REQUIRED_EVENTS = ("session.start", "prompt.before", "turn.stop")
_TEMPLATE_NAMES = {"codex-cli": "codex", "codex-app": "codex", "claude-code": "claude", "gemini-cli": "gemini", "qwen-code": "qwen"}
_HASH_RE = __import__("re").compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_SKILL_STATUSES = frozenset({"DISCOVERED", "UNVERIFIED", "NOT_FOUND", "UNSUPPORTED"})
_ALLOWED_ACTIVATION_MODES = frozenset({"AUTO_ALLOWED", "CONSENT_REQUIRED", "MANUAL_ONLY", "UNAVAILABLE"})
_ALLOWED_HOOK_STATUSES = frozenset({"HOOK_VERIFIED", "HOOK_UNVERIFIED", "INSTRUCTION_FALLBACK", "DISABLED", "BROKEN"})
_ALLOWED_OUTCOMES = frozenset({"PASSED", "FAILED", "MISSING", "BLOCKED"})
_DEFAULT_RECEIPT_TTL_SECONDS = 7 * 24 * 60 * 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | str | None) -> datetime:
    if value is None:
        return _now()
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("CANARY_TIME_INVALID") from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("CANARY_TIMEZONE_REQUIRED")
    return value.astimezone(timezone.utc)


def _iso(value: datetime | str | None) -> str:
    return _aware(value).isoformat().replace("+00:00", "Z")


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hash_json(value: Mapping[str, Any]) -> str:
    return _hash_bytes(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        if os.name != "nt":
            raise


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _runtime_path(settings: Settings, name: str) -> Path:
    root = Path(settings.paths.runtime_dir).expanduser().resolve()
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if root == repo or root.is_relative_to(repo):
        raise ValueError("CANARY_RUNTIME_REPOSITORY_PATH_FORBIDDEN")
    return root / name


def _template_path(settings: Settings, host_id: str) -> Path:
    name = _TEMPLATE_NAMES.get(host_id)
    if not name:
        raise ValueError("HOST_UNSUPPORTED")
    return Path(settings.paths.engine_root).resolve() / "hooks" / name / "hooks.template.json"


def _host_spec(host_id: str, settings: Settings) -> HostSpec:
    canonical = canonical_host_id(host_id)
    hosts = getattr(settings, "hosts", {})
    if isinstance(hosts, Mapping) and canonical in hosts:
        return hosts[canonical]
    from .hooks.registry import _fallback_spec
    fallback = _fallback_spec(canonical)
    if canonical.startswith("codex"):
        return replace(fallback, hook_config_path=Path(settings.paths.hooks_path), global_context_path=Path(settings.paths.agents_path), skill_roots=(Path(settings.paths.codex_home) / "skills",))
    return fallback


def _hash_tree(settings: Settings) -> str:
    root = Path(settings.paths.engine_root).resolve() / "skills" / "external-intelligence"
    if not root.is_dir():
        return ""
    files: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            files.append((path.relative_to(root).as_posix(), _hash_bytes(path.read_bytes())))
    return _hash_json({"files": files}) if files else ""


def _template_hash(settings: Settings, host_id: str) -> str:
    try:
        return _hash_bytes(_template_path(settings, host_id).read_bytes())
    except OSError:
        return ""


def _schema_hash(settings: Settings) -> str:
    try:
        return _hash_bytes((Path(settings.paths.engine_root).resolve() / "schemas" / "hook-event.schema.json").read_bytes())
    except OSError:
        return ""


def _receipt_id(host_id: str, instance_id: str, completed: str, events: Mapping[str, str]) -> str:
    material = {"host_id": host_id, "host_instance_id": instance_id, "completed_at": completed, "event_receipt_hashes": dict(sorted(events.items()))}
    return "canary_" + hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class CertificationReceipt:
    host_id: str
    host_instance_id: str
    mode: CertificationMode = "real"
    host_version: str = "unknown"
    os_name: str = field(default_factory=platform.system)
    os_version: str = field(default_factory=platform.release)
    architecture: str = field(default_factory=platform.machine)
    python_version: str = field(default_factory=platform.python_version)
    event_receipt_hashes: Mapping[str, str] = field(default_factory=dict)
    skill_discovery_status: SkillDiscoveryStatus = "UNVERIFIED"
    skill_activation_mode: SkillActivationMode = "UNAVAILABLE"
    hook_status: HookStatusValue = "HOOK_UNVERIFIED"
    hook_template_hash: str = ""
    source_skill_hash: str = ""
    started_at: datetime | str = field(default_factory=_now)
    completed_at: datetime | str = field(default_factory=_now)
    outcome: CertificationOutcome = "PASSED"
    artifact_hash: str = ""
    receipt_id: str = ""

    def __post_init__(self) -> None:
        host = canonical_host_id(self.host_id)
        if not host or not str(self.host_instance_id):
            raise ValueError("CANARY_ID_INVALID")
        if self.mode not in {"fixture", "real"}:
            raise ValueError("CANARY_MODE_INVALID")
        if self.skill_discovery_status not in _ALLOWED_SKILL_STATUSES:
            raise ValueError("SKILL_DISCOVERY_STATUS_INVALID")
        if self.skill_activation_mode not in _ALLOWED_ACTIVATION_MODES:
            raise ValueError("SKILL_ACTIVATION_MODE_INVALID")
        if self.hook_status not in _ALLOWED_HOOK_STATUSES:
            raise ValueError("HOOK_STATUS_INVALID")
        if self.outcome not in _ALLOWED_OUTCOMES:
            raise ValueError("CANARY_OUTCOME_INVALID")
        hashes = dict(self.event_receipt_hashes)
        if any(not isinstance(key, str) or not key or not isinstance(value, str) or not _HASH_RE.fullmatch(value) for key, value in hashes.items()):
            raise ValueError("CANARY_EVENT_HASH_INVALID")
        started, completed = _aware(self.started_at), _aware(self.completed_at)
        if completed < started:
            raise ValueError("CANARY_TIME_ORDER_INVALID")
        object.__setattr__(self, "host_id", host)
        object.__setattr__(self, "host_instance_id", str(self.host_instance_id))
        object.__setattr__(self, "event_receipt_hashes", dict(sorted(hashes.items())))
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)

    def to_dict(self) -> dict[str, Any]:
        completed = _iso(self.completed_at)
        events = dict(sorted(self.event_receipt_hashes.items()))
        receipt_id = self.receipt_id or _receipt_id(self.host_id, self.host_instance_id, completed, events)
        basis = {
            "receipt_id": receipt_id, "mode": self.mode, "host_id": self.host_id, "host_instance_id": self.host_instance_id,
            "host_version": str(self.host_version), "os_name": str(self.os_name), "os_version": str(self.os_version),
            "architecture": str(self.architecture), "python_version": str(self.python_version), "event_receipt_hashes": events,
            "skill_discovery_status": self.skill_discovery_status, "skill_activation_mode": self.skill_activation_mode,
            "hook_status": self.hook_status, "hook_template_hash": self.hook_template_hash, "source_skill_hash": self.source_skill_hash,
            "started_at": _iso(self.started_at), "completed_at": completed, "outcome": self.outcome,
        }
        return {**basis, "artifact_hash": self.artifact_hash or _hash_json(basis)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CertificationReceipt":
        if not isinstance(value, Mapping) or "host_id" not in value or "host_instance_id" not in value:
            raise ValueError("CANARY_RECEIPT_FIELDS_MISSING")
        try:
            return cls(
                host_id=str(value["host_id"]), host_instance_id=str(value["host_instance_id"]), mode=str(value.get("mode", "real")),
                host_version=str(value.get("host_version", "unknown")), os_name=str(value.get("os_name", platform.system())),
                os_version=str(value.get("os_version", platform.release())), architecture=str(value.get("architecture", platform.machine())),
                python_version=str(value.get("python_version", platform.python_version())), event_receipt_hashes=dict(value.get("event_receipt_hashes", {})),
                skill_discovery_status=str(value.get("skill_discovery_status", "UNVERIFIED")), skill_activation_mode=str(value.get("skill_activation_mode", "UNAVAILABLE")),
                hook_status=str(value.get("hook_status", "HOOK_UNVERIFIED")), hook_template_hash=str(value.get("hook_template_hash", "")),
                source_skill_hash=str(value.get("source_skill_hash", "")), started_at=value.get("started_at", _now()),
                completed_at=value.get("completed_at", _now()), outcome=str(value.get("outcome", "PASSED")),
                artifact_hash=str(value.get("artifact_hash", "")), receipt_id=str(value.get("receipt_id", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc).endswith(("_INVALID", "_REQUIRED")):
                raise
            raise ValueError("CANARY_RECEIPT_INVALID") from exc

    @classmethod
    def from_event(cls, event: NormalizedHookEvent, settings: Settings, mode: CertificationMode | None = None) -> "CertificationReceipt":
        event_hash = _hash_json(event.to_dict())
        spec = _host_spec(event.host_id, settings)
        selected = mode or str(os.environ.get("EI_CANARY_MODE", "real"))
        if selected not in {"fixture", "real"}:
            selected = "real"
        return cls(
            host_id=event.host_id, host_instance_id=event.host_instance_id, mode=selected,
            host_version=str(os.environ.get("EI_HOST_VERSION", "unknown")), event_receipt_hashes={event.normalized_event_name: event_hash},
            skill_activation_mode=spec.skill_activation_mode if spec.skill_activation_mode in _ALLOWED_ACTIVATION_MODES else "UNAVAILABLE",
            hook_template_hash=_template_hash(settings, event.host_id), source_skill_hash="",
            started_at=event.received_at, completed_at=event.received_at,
        )


@dataclass(frozen=True)
class StaticCanaryResult:
    host_id: str
    host_instance_id: str
    valid: bool
    feature_state: str
    template_hash: str
    schema_hash: str
    command_hash: str
    checks: Mapping[str, bool]
    reason_codes: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return "STATIC_VALID" if self.valid else "STATIC_INVALID"

    def to_dict(self) -> dict[str, Any]:
        return {"host_id": self.host_id, "host_instance_id": self.host_instance_id, "status": self.status, "valid": self.valid, "feature_state": self.feature_state, "template_hash": self.template_hash, "schema_hash": self.schema_hash, "command_hash": self.command_hash, "checks": dict(self.checks), "reason_codes": list(self.reason_codes)}


def _feature_state(spec: HostSpec, settings: Settings) -> str:
    if spec.hook_feature_key is None:
        return "NOT_APPLICABLE"
    path = Path(settings.paths.config_path)
    if not path.exists():
        return "UNKNOWN"
    try:
        lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").splitlines()
    except (OSError, UnicodeError):
        return "UNKNOWN"
    section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip() == "features"
        elif section and "=" in stripped and not stripped.startswith("#"):
            key, value = (part.strip() for part in stripped.split("=", 1))
            if key == "hooks":
                if value.casefold() in {"true", "1"}:
                    return "ENABLED"
                if value.casefold() in {"false", "0"}:
                    return "DISABLED"
    return "UNKNOWN"


def _commands(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for key, child in value.items():
            if str(key).casefold() in {"command", "commandwindows", "commandunix", "commandposix"}:
                result.extend([child] if isinstance(child, str) else [" ".join(map(str, child))] if isinstance(child, list) else [])
            else:
                result.extend(_commands(child))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for child in value:
            result.extend(_commands(child))
        return result
    return []


def _command_ok(command: str, host_id: str) -> bool:
    for platform_name in ("posix", "windows"):
        try:
            validate_hook_command(command, platform=platform_name, expected_host_id=host_id, allow_template=True)
            return True
        except (TypeError, ValueError):
            continue
    return False


def _managed_ids(value: Mapping[str, Any]) -> set[str]:
    hooks = value.get("hooks")
    found: set[str] = set()
    if isinstance(hooks, Mapping):
        for entries in hooks.values():
            if isinstance(entries, list):
                found.update(str(entry["id"]) for entry in entries if isinstance(entry, Mapping) and isinstance(entry.get("id"), str))
    return found


def _template_checks(host_id: str, value: Mapping[str, Any]) -> tuple[dict[str, bool], set[str], list[str]]:
    hooks = value.get("hooks")
    checks = {"schema_version": type(value.get("schema_version")) is int and value.get("schema_version") == 1, "managed_id": isinstance(value.get("managed_id"), str) and bool(value.get("managed_id")), "hooks_object": isinstance(hooks, Mapping), "event_set": False, "command_argv": False, "unique_managed_entries": False, "canary_contract": False}
    reasons: list[str] = []
    ids: list[str] = []
    commands: list[str] = []
    canary = value.get("canary")
    if isinstance(canary, Mapping):
        required_events = canary.get("required_normalized_events")
        validity_window = canary.get("validity_window_seconds")
        checks["canary_contract"] = (isinstance(required_events, list) and all(isinstance(item, str) for item in required_events) and set(required_events) == set(HOOK_REQUIRED_EVENTS) and type(validity_window) is int and validity_window > 0)

    observed: set[str] = set()
    command_valid = True
    command_layout: tuple[str, ...] | None = None
    command_argv: tuple[str, ...] | None = None
    saw_template = False
    saw_command = False
    if isinstance(hooks, Mapping):
        for name, entries in hooks.items():
            observed.add(str(name))
            if not isinstance(entries, list):
                reasons.append("HOOK_EVENT_NOT_LIST")
                command_valid = False
                continue
            for entry in entries:
                if not isinstance(entry, Mapping):
                    command_valid = False
                    continue
                if isinstance(entry.get("id"), str):
                    ids.append(entry["id"])
                handlers = entry.get("hooks")
                if not isinstance(handlers, list):
                    command_valid = False
                    continue
                for handler in handlers:
                    if not isinstance(handler, Mapping) or handler.get("type") != "command":
                        command_valid = False
                        continue
                    try:
                        fields = extract_hook_command_fields(handler)
                        candidate = validate_hook_command_fields(fields, expected_host_id=host_id, allow_templates=True)
                    except (TypeError, ValueError):
                        command_valid = False
                        continue
                    commands.extend(value for value in fields.values() if isinstance(value, str))
                    current_layout = tuple(sorted(fields))
                    if command_layout is None:
                        command_layout = current_layout
                    elif command_layout != current_layout:
                        command_valid = False
                    if candidate is None:
                        saw_template = True
                    else:
                        saw_command = True
                        if command_argv is None:
                            command_argv = candidate
                        elif command_argv != candidate:
                            command_valid = False
        checks["event_set"] = observed == set(supported_events(host_id))
        checks["command_argv"] = bool(commands) and command_valid and not (saw_template and saw_command)
        checks["unique_managed_entries"] = len(ids) == len(set(ids)) == len(set(supported_events(host_id)))
    if not checks["schema_version"]:
        reasons.append("HOOK_TEMPLATE_SCHEMA_INVALID")
    if not checks["managed_id"]:
        reasons.append("HOOK_MANAGED_ID_MISSING")
    if not checks["hooks_object"]:
        reasons.append("HOOK_TEMPLATE_HOOKS_INVALID")
    if not checks["event_set"]:
        reasons.append("HOOK_EVENT_SET_INVALID")
    if not checks["command_argv"]:
        reasons.append("HOOK_COMMAND_INVALID")
    if not checks["unique_managed_entries"]:
        reasons.append("HOOK_ENTRY_IDS_INVALID")
    if not checks["canary_contract"]:
        reasons.append("HOOK_CANARY_CONTRACT_INVALID")
    return checks, _managed_ids(value), reasons


def _installed_checks(spec: HostSpec, ids: set[str], host_id: str) -> tuple[dict[str, bool], list[str]]:
    path = Path(spec.hook_config_path)
    checks = {"config_present": path.exists(), "config_json": False, "managed_entries": False, "command_argv": False}
    if not path.exists():
        return checks, ["HOOK_CONFIG_MISSING"]
    value = _read_json(path)
    if value is None:
        return checks, ["HOOK_CONFIG_INVALID"]
    checks["config_json"] = True
    installed_ids = _managed_ids(value)
    expected_ids = {identifier + "-codex-app" for identifier in ids} if host_id == "codex-app" else set(ids)
    checks["managed_entries"] = bool(ids) and expected_ids.issubset(installed_ids)
    command_valid = True
    command_seen = False
    command_layout: tuple[str, ...] | None = None
    command_argv: tuple[str, ...] | None = None
    hooks = value.get("hooks")
    if isinstance(hooks, Mapping):
        for entries in hooks.values():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                identifier = entry.get("id")
                if not isinstance(identifier, str) or not (identifier in ids if host_id != "codex-app" else identifier.endswith("-codex-app") and identifier[:-10] in ids):
                    continue
                handlers = entry.get("hooks")
                if not isinstance(handlers, list):
                    command_valid = False
                    continue
                for handler in handlers:
                    if not isinstance(handler, Mapping) or handler.get("type") != "command":
                        command_valid = False
                        continue
                    try:
                        fields = extract_hook_command_fields(handler)
                        candidate = validate_hook_command_fields(fields, expected_host_id=host_id)
                    except (TypeError, ValueError):
                        command_valid = False
                        continue
                    current_layout = tuple(sorted(fields))
                    if command_layout is None:
                        command_layout = current_layout
                    elif command_layout != current_layout:
                        command_valid = False
                    if command_argv is None:
                        command_argv = candidate
                    elif command_argv != candidate:
                        command_valid = False
                    command_seen = True
    checks["command_argv"] = command_seen and command_valid
    reasons: list[str] = []
    if not checks["managed_entries"]:
        reasons.append("HOOK_MANAGED_ENTRIES_MISSING")
    if not checks["command_argv"]:
        reasons.append("HOOK_COMMAND_INVALID")
    return checks, reasons


def static_canary(host_id: str, host_instance_id: str, settings: Settings) -> StaticCanaryResult:
    canonical = canonical_host_id(host_id)
    if not canonical or not str(host_instance_id):
        return StaticCanaryResult(str(host_id), str(host_instance_id), False, "UNKNOWN", "", "", "", {}, ("HOST_ID_INVALID",))
    try:
        spec = _host_spec(canonical, settings)
        template = _read_json(_template_path(settings, canonical))
        if template is None:
            return StaticCanaryResult(canonical, str(host_instance_id), False, _feature_state(spec, settings), "", "", "", {}, ("HOOK_TEMPLATE_MISSING_OR_INVALID",))
        template_checks, ids, reasons = _template_checks(canonical, template)
        installed_checks, installed_reasons = _installed_checks(spec, ids, canonical)
        reasons.extend(installed_reasons)
        checks = {**template_checks, **installed_checks}
        feature = _feature_state(spec, settings)
        checks["feature_state_known_or_not_applicable"] = feature in {"ENABLED", "NOT_APPLICABLE"}
        checks["feature_not_disabled"] = feature != "DISABLED"
        if feature == "UNKNOWN" and spec.hook_feature_key is not None:
            reasons.append("HOOK_FEATURE_UNKNOWN")
        schema_hash = _schema_hash(settings)
        checks["schema_file"] = bool(schema_hash)
        checks["host_executable_contract"] = bool(spec.executable_names)
        commands = sorted(_commands(template))
        command_hash = _hash_bytes("\n".join(commands).encode("utf-8")) if commands else ""
        valid = all(template_checks.values()) and all(installed_checks.values()) and feature != "DISABLED" and bool(schema_hash)
        return StaticCanaryResult(canonical, str(host_instance_id), valid, feature, _template_hash(settings, canonical), schema_hash, command_hash, checks, tuple(dict.fromkeys(reasons)))
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return StaticCanaryResult(canonical, str(host_instance_id), False, "UNKNOWN", "", "", "", {}, (type(exc).__name__,))


def _read_receipts(settings: Settings) -> tuple[CertificationReceipt, ...]:
    path = _runtime_path(settings, "canary-receipts.jsonl")
    if not path.exists():
        return ()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ()
    result: list[CertificationReceipt] = []
    for line in lines:
        try:
            value = json.loads(line)
            if isinstance(value, Mapping) and value.get("record_type") in {None, "hook_canary"}:
                result.append(CertificationReceipt.from_mapping(value))
        except (json.JSONDecodeError, TypeError, ValueError, UnicodeError):
            continue
    return tuple(result)


def record_canary(receipt: CertificationReceipt, settings: Settings) -> None:
    if not isinstance(receipt, CertificationReceipt):
        raise TypeError("CANARY_RECEIPT_REQUIRED")
    data = receipt.to_dict()
    data["record_type"] = "hook_canary"
    data["recorded_at"] = _iso(None)
    identity = (data["receipt_id"], data["artifact_hash"])
    if any((row.to_dict().get("receipt_id"), row.to_dict().get("artifact_hash")) == identity for row in _read_receipts(settings)):
        return
    _append_jsonl(_runtime_path(settings, "canary-receipts.jsonl"), data)


def record_skill_discovery(host_id: str, host_instance_id: str, status: SkillDiscoveryStatus, settings: Settings, *, source_skill_hash: str = "", observed_at: datetime | str | None = None) -> None:
    canonical = canonical_host_id(host_id)
    if not canonical or not str(host_instance_id) or status not in _ALLOWED_SKILL_STATUSES:
        raise ValueError("SKILL_DISCOVERY_RECEIPT_INVALID")
    _append_jsonl(_runtime_path(settings, "skill-discovery-receipts.jsonl"), {"record_type": "skill_discovery", "host_id": canonical, "host_instance_id": str(host_instance_id), "status": status, "source_skill_hash": str(source_skill_hash), "observed_at": _iso(observed_at)})


def _latest_skill_status(host_id: str, instance_id: str, settings: Settings) -> str | None:
    path = _runtime_path(settings, "skill-discovery-receipts.jsonl")
    if not path.exists():
        return None
    latest: str | None = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    for line in lines:
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeError):
            continue
        if isinstance(value, Mapping) and value.get("record_type") == "skill_discovery" and value.get("host_id") == host_id and value.get("host_instance_id") == instance_id and value.get("status") in _ALLOWED_SKILL_STATUSES:
            latest = str(value["status"])
    return latest


def skill_discovery_canary(host_id: str, host_instance_id: str, settings: Settings) -> SkillDiscoveryStatus:
    canonical = canonical_host_id(host_id)
    try:
        spec = _host_spec(canonical, settings)
    except (KeyError, ValueError):
        return "UNSUPPORTED"
    roots = tuple(Path(root).expanduser().resolve() for root in spec.skill_roots)
    if not roots:
        return "UNSUPPORTED"
    found = any((root / "external-intelligence" / "SKILL.md").is_file() or (root / "SKILL.md").is_file() for root in roots)
    observed = _latest_skill_status(canonical, str(host_instance_id), settings)
    if observed == "DISCOVERED" and found:
        return "DISCOVERED"
    if observed == "NOT_FOUND":
        return "NOT_FOUND"
    return "UNVERIFIED" if found else "NOT_FOUND"


def _previous_status(settings: Settings, host_id: str, instance_id: str) -> str | None:
    document = _read_json(_runtime_path(settings, "hook-status.json")) or {}
    value = document.get(f"{host_id}:{instance_id}")
    return str(value.get("hook_status")) if isinstance(value, Mapping) else None


def _write_status_snapshot(settings: Settings, status: Mapping[str, Any]) -> None:
    path = _runtime_path(settings, "hook-status.json")
    document = _read_json(path) or {}
    updated = dict(document)
    updated[f"{status.get('host_id')}:{status.get('host_instance_id')}"] = dict(status)
    _atomic_json(path, updated)


def read_hook_status(host_id: str, host_instance_id: str, settings: Settings):
    from .hook_status import HookStatus
    canonical = canonical_host_id(host_id)
    static = static_canary(canonical, str(host_instance_id), settings)
    skill = skill_discovery_canary(canonical, str(host_instance_id), settings)
    try:
        spec = _host_spec(canonical, settings)
    except (KeyError, ValueError):
        return HookStatus(canonical, str(host_instance_id), "DISABLED", skill, "UNAVAILABLE", "NATIVE_SOURCE", ("HOST_UNSUPPORTED",), static.to_dict(), (), None)
    previous = _previous_status(settings, canonical, str(host_instance_id))
    ttl_value = getattr(settings, "canary_receipt_ttl_seconds", _DEFAULT_RECEIPT_TTL_SECONDS)
    try:
        ttl = max(1, int(ttl_value))
    except (TypeError, ValueError):
        ttl = _DEFAULT_RECEIPT_TTL_SECONDS
    now = _now()
    current: set[str] = set()
    last_received: datetime | None = None
    expired = False
    for receipt in _read_receipts(settings):
        if receipt.host_id != canonical or receipt.host_instance_id != str(host_instance_id):
            continue
        completed = _aware(receipt.completed_at)
        if now - completed > timedelta(seconds=ttl):
            expired = True
        elif receipt.mode == "real" and receipt.outcome == "PASSED":
            current.update(name for name in receipt.event_receipt_hashes if name in HOOK_REQUIRED_EVENTS)
            last_received = max(last_received or completed, completed)
    reasons = list(static.reason_codes)
    if static.feature_state == "DISABLED":
        status: HookStatusValue = "BROKEN" if previous == "HOOK_VERIFIED" else "DISABLED"
        reasons.append("HOOK_FEATURE_DISABLED")
    elif not static.valid:
        status = "BROKEN" if previous == "HOOK_VERIFIED" else "HOOK_UNVERIFIED"
    elif set(HOOK_REQUIRED_EVENTS).issubset(current):
        status = "HOOK_VERIFIED"
    elif previous == "HOOK_VERIFIED" and expired:
        status = "BROKEN"
        reasons.append("CANARY_RECEIPT_EXPIRED")
    else:
        status = "HOOK_UNVERIFIED"
        reasons.append("REAL_CANARY_INCOMPLETE")
    if canonical.startswith("codex") and static.feature_state == "UNKNOWN":
        status = "BROKEN" if previous == "HOOK_VERIFIED" else "HOOK_UNVERIFIED"
        reasons.append("HOOK_FEATURE_UNKNOWN")
    fallback = False
    try:
        from .install_agents import BEGIN_MARKER, END_MARKER
        path = Path(spec.global_context_path)
        fallback = path.exists() and BEGIN_MARKER in path.read_text(encoding="utf-8") and END_MARKER in path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        fallback = False
    if status in {"DISABLED", "BROKEN"} and fallback:
        status = "INSTRUCTION_FALLBACK"
        reasons.append("INSTRUCTION_FALLBACK_ACTIVE")
    result = HookStatus(canonical, str(host_instance_id), status, skill, spec.skill_activation_mode, spec.capture_primary_path, tuple(dict.fromkeys(reasons)), static.to_dict(), tuple(sorted(current)), _iso(last_received) if last_received else None)
    _write_status_snapshot(settings, result.to_dict())
    return result


def build_canary_receipt_from_event(event: NormalizedHookEvent, settings: Settings, mode: CertificationMode | None = None) -> CertificationReceipt:
    return CertificationReceipt.from_event(event, settings, mode)


def certify_host(host_id: str, host_instance_id: str, mode: CertificationMode, settings: Settings) -> dict[str, Any]:
    canonical = canonical_host_id(host_id)
    status = read_hook_status(canonical, host_instance_id, settings)
    result_status = status.hook_status if mode == "real" else "HOOK_UNVERIFIED"
    outcome: CertificationOutcome = "PASSED" if mode == "fixture" or result_status == "HOOK_VERIFIED" else "MISSING"
    receipt = CertificationReceipt(host_id=canonical, host_instance_id=host_instance_id, mode=mode, event_receipt_hashes={name: "sha256:" + "0" * 64 for name in status.received_events}, skill_discovery_status=status.skill_discovery_status, skill_activation_mode=status.skill_activation_mode, hook_status=result_status, hook_template_hash=str(status.static_checks.get("template_hash", "")), outcome=outcome)
    return {"status": outcome, "receipt": receipt, "reason_codes": status.reason_codes}


__all__ = ["CertificationReceipt", "CertificationMode", "CapturePrimaryPath", "HOOK_REQUIRED_EVENTS", "HookStatusValue", "SkillActivationMode", "SkillDiscoveryStatus", "StaticCanaryResult", "build_canary_receipt_from_event", "certify_host", "record_canary", "record_skill_discovery", "read_hook_status", "skill_discovery_canary", "static_canary"]
