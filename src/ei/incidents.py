from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .operation_health import HealthIssue, STORAGE_CODES, validate_pending_count
from .notifications.base import DeliveryResult
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory


_STATE_VERSION = 1
_STATE_MAX_BYTES = 8 * 1024 * 1024
_LOCK_TIMEOUT_SECONDS = 5.0
_INCIDENT_ID = re.compile(r"^inc_[0-9a-f]{32}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_KNOWN_REASONS = STORAGE_CODES | frozenset(
    {
        "ACCUMULATION_STALLED",
        "AUTH_FAILED",
        "AUTH_PENDING",
        "CAPACITY_RISK",
        "CLOSEOUT_RECOVERY_LOSS",
        "DEADLINE_EXCEEDED",
        "EXPIRY_CLEANUP_FAILED",
        "EXPIRY_RISK",
        "MALFORMED_RESPONSE",
        "NO_PROVIDER_AVAILABLE",
        "OPERATION_FAILED",
        "ORGANIZER_PROVIDER_NOT_CONFIGURED",
        "ORGANIZER_SELECTION_REQUIRED",
        "PENDING_EXPIRED",
        "PERMISSION_DENIED",
        "PROVIDER_DISABLED",
        "PROVIDER_PERMISSION_DENIED",
        "PROVIDER_PROTOCOL_ERROR",
        "PROVIDER_RATE_LIMITED",
        "PROVIDER_TIMEOUT",
        "PROVIDER_UNAVAILABLE",
        "QUOTA_EXHAUSTED",
        "RATE_LIMITED",
        "SCHEDULER_STOPPED",
        "SCHEMA_VIOLATION",
        "SOURCE_UNAVAILABLE",
    }
)
_PROVIDER_REASONS = frozenset(
    {
        "AUTH_FAILED",
        "AUTH_PENDING",
        "DEADLINE_EXCEEDED",
        "MALFORMED_RESPONSE",
        "NO_PROVIDER_AVAILABLE",
        "OPERATION_FAILED",
        "ORGANIZER_PROVIDER_NOT_CONFIGURED",
        "ORGANIZER_SELECTION_REQUIRED",
        "PERMISSION_DENIED",
        "PROVIDER_DISABLED",
        "PROVIDER_PERMISSION_DENIED",
        "PROVIDER_PROTOCOL_ERROR",
        "PROVIDER_RATE_LIMITED",
        "PROVIDER_TIMEOUT",
        "PROVIDER_UNAVAILABLE",
        "QUOTA_EXHAUSTED",
        "RATE_LIMITED",
        "SCHEMA_VIOLATION",
    }
)
_INCIDENT_FIELDS = frozenset(
    {
        "schema_version",
        "incident_id",
        "reason_family",
        "reason_code",
        "component_id",
        "severity",
        "pending_count",
        "detected_at",
        "last_observed_at",
        "status",
        "resolved_at",
        "notification_generation",
        "delivery",
    }
)
_OPTIONAL_INCIDENT_FIELDS = frozenset({"occurrence_generation", "pending_count_status"})
_DELIVERY_FIELDS = frozenset(
    {"last_attempt_at", "last_success_at", "last_result", "success_generation", "successful_sessions"}
)
_OPTIONAL_DELIVERY_FIELDS = frozenset({"lease", "last_status", "last_reason_code", "delivery_id", "display_status"})
_LEASE_FIELDS = frozenset({"token", "notification_generation", "occurrence_generation", "session_hash"})


@dataclass(frozen=True)
class NotificationLease:
    incident_id: str
    channel: str
    token: str
    notification_generation: int
    occurrence_generation: int
    session_hash: str | None
    reason_code: str
    pending_count: int | None
    recovered: bool
    pending_count_status: str = "COMPLETE"

    def persisted(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in _LEASE_FIELDS}


class IncidentStateError(RuntimeError):
    """Raised when operation incident state cannot be safely updated."""


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("INCIDENT_TIMEZONE_REQUIRED")
    return value


def _timestamp(value: datetime) -> str:
    return _aware(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, *, optional: bool = False) -> datetime | None:
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT") from exc
    try:
        return _aware(parsed)
    except ValueError as exc:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT") from exc


def _reason_code(value: str) -> str:
    return value if value in _KNOWN_REASONS else "OPERATION_FAILED"


def reason_family(reason_code: str) -> str:
    """Return the stable family used with component_id to derive incident IDs."""

    reason = _reason_code(reason_code)
    if reason in STORAGE_CODES:
        return "STORAGE_FAILURE"
    return "PROVIDER_FAILURE" if reason in _PROVIDER_REASONS else reason


def incident_id(reason_code: str, component_id: str) -> str:
    """Deterministically identify a reason family for one sanitized component."""

    family = reason_family(reason_code)
    if not isinstance(component_id, str) or not _SAFE_ID.fullmatch(component_id):
        raise ValueError("INCIDENT_COMPONENT_ID_INVALID")
    digest = hashlib.sha256(f"{family}\0{component_id}".encode("utf-8")).hexdigest()[:32]
    return f"inc_{digest}"


def closeout_recovery_loss_issue(record_id: str) -> HealthIssue:
    """Build the stable, body-free issue for one expired closeout record."""

    if not isinstance(record_id, str) or not re.fullmatch(r"co_[0-9a-f]{64}", record_id):
        raise ValueError("CLOSEOUT_RECORD_ID_INVALID")
    return HealthIssue("CLOSEOUT_RECOVERY_LOSS", "closeout-loss-" + record_id[3:], "critical", None, "UNKNOWN")


def _empty_delivery() -> dict[str, dict[str, Any]]:
    return {
        channel: {
            "last_attempt_at": None,
            "last_success_at": None,
            "last_result": None,
            "success_generation": 0,
            "successful_sessions": [],
        }
        for channel in ("os", "cli")
    }


def _state_root(settings: Any) -> Path:
    try:
        runtime = safe_ensure_directory(Path(settings.paths.runtime_dir))
        assert_safe_target(runtime, runtime, allow_root=True, allow_missing=False, expected_type="dir")
        return safe_ensure_directory(runtime / "state", mode=0o700)
    except (AttributeError, OSError, SafeFilesystemError, TypeError, ValueError) as exc:
        raise IncidentStateError("INCIDENT_STATE_ROOT_FAILED") from exc


def _state_path(root: Path) -> Path:
    return assert_safe_target(root, root / "operation-incidents.json", allow_missing=True)


def _lock_path(root: Path) -> Path:
    return assert_safe_target(root, root / ".operation-incidents.lock", allow_missing=True)


def _try_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _check_budget(budget) -> None:
    if budget is not None:
        budget.check()


def _acquire(root: Path, *, timeout_seconds: float = _LOCK_TIMEOUT_SECONDS, budget=None) -> int:
    _check_budget(budget)
    if budget is not None:
        timeout_seconds = min(timeout_seconds, budget.remaining_ms() / 1000)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (float, int)) or not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise ValueError("INCIDENT_LOCK_TIMEOUT_INVALID")
    path = _lock_path(root)
    try:
        descriptor = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        raise IncidentStateError("INCIDENT_LOCK_FAILED") from exc
    started = time.monotonic()
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        while True:
            _check_budget(budget)
            try:
                _try_lock(descriptor)
                return descriptor
            except OSError as exc:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise IncidentStateError("INCIDENT_LOCK_TIMEOUT") from exc
                time.sleep(min(0.01, remaining))
    except BaseException:
        os.close(descriptor)
        raise


def _release(descriptor: int) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        return
    finally:
        os.close(descriptor)


def _validate_delivery(value: Any, generation: int, *, budget=None) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {"os", "cli"}:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    result: dict[str, dict[str, Any]] = {}
    for channel in ("os", "cli"):
        item = value[channel]
        if not isinstance(item, Mapping) or not _DELIVERY_FIELDS.issubset(item) or set(item) - _DELIVERY_FIELDS - _OPTIONAL_DELIVERY_FIELDS:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        _parse_timestamp(item["last_attempt_at"], optional=True)
        if item["last_result"] == "UNKNOWN" and item["last_attempt_at"] is None:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        _parse_timestamp(item["last_success_at"], optional=True)
        if item["last_result"] not in {None, "SUCCESS", "FAILED", "UNKNOWN"}:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        success_generation = item["success_generation"]
        if type(success_generation) is not int or success_generation < 0 or success_generation > generation:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        sessions = item["successful_sessions"]
        if not isinstance(sessions, list):
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        unique_sessions = {}
        for session in sessions:
            _check_budget(budget)
            if not isinstance(session, str) or not _SAFE_ID.fullmatch(session):
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            unique_sessions[session] = None
        result[channel] = {
            "last_attempt_at": item["last_attempt_at"],
            "last_success_at": item["last_success_at"],
            "last_result": item["last_result"],
            "success_generation": success_generation,
            "successful_sessions": list(unique_sessions),
        }
        if item.get("display_status") not in {None, "UNVERIFIED"}:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        if item.get("last_status") is not None:
            try:
                DeliveryResult(item["last_status"], item.get("last_reason_code"), item.get("delivery_id"))
            except (ValueError, TypeError) as exc:
                raise IncidentStateError("INCIDENT_STATE_CORRUPT") from exc
        elif item.get("last_reason_code") is not None or item.get("delivery_id") is not None:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        lease = item.get("lease")
        if lease is not None:
            if not isinstance(lease, Mapping) or not _LEASE_FIELDS.issubset(lease) or set(lease) - _LEASE_FIELDS - {"previous_delivery"}:
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            if "previous_delivery" in lease:
                previous = lease["previous_delivery"]
                if not isinstance(previous, Mapping) or "lease" in previous:
                    raise IncidentStateError("INCIDENT_STATE_CORRUPT")
                snapshots = _empty_delivery()
                snapshots[channel] = previous
                _validate_delivery(snapshots, generation, budget=budget)
            if not isinstance(lease["token"], str) or not re.fullmatch(r"[0-9a-f]{32}", lease["token"]):
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            for field in ("notification_generation", "occurrence_generation"):
                if type(lease[field]) is not int or not 1 <= lease[field] <= generation:
                    raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            if lease["occurrence_generation"] > lease["notification_generation"]:
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            session = lease["session_hash"]
            if (channel == "os" and session is not None) or (channel == "cli" and (not isinstance(session, str) or not _SAFE_ID.fullmatch(session))):
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
            if item["last_result"] != "UNKNOWN" or item["last_attempt_at"] is None:
                raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        result[channel].update({key: item[key] for key in _OPTIONAL_DELIVERY_FIELDS if key in item})
    return result


def _validate_incident(value: Any, *, budget=None) -> dict[str, Any]:
    _check_budget(budget)
    if (
        not isinstance(value, Mapping)
        or not _INCIDENT_FIELDS.issubset(value)
        or set(value) - _INCIDENT_FIELDS - _OPTIONAL_INCIDENT_FIELDS
    ):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if value["schema_version"] != 1 or not isinstance(value["incident_id"], str) or not _INCIDENT_ID.fullmatch(
        value["incident_id"]
    ):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    for field in ("reason_family", "reason_code"):
        if not isinstance(value[field], str) or not _CODE.fullmatch(value[field]):
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if value["reason_code"] not in _KNOWN_REASONS or value["reason_family"] != reason_family(value["reason_code"]):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    component = value["component_id"]
    if not isinstance(component, str) or not _SAFE_ID.fullmatch(component):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if value["incident_id"] != incident_id(value["reason_code"], component):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if value["severity"] not in _SEVERITY_RANK:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if "pending_count_status" in value:
        try:
            validate_pending_count(value["pending_count"], value["pending_count_status"])
        except (TypeError, ValueError) as exc:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT") from exc
    elif type(value["pending_count"]) is not int or value["pending_count"] < 0:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    _parse_timestamp(value["detected_at"])
    _parse_timestamp(value["last_observed_at"])
    status = value["status"]
    if status not in {"OPEN", "RESOLVED", "HISTORICAL"}:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    resolved_at = _parse_timestamp(value["resolved_at"], optional=True)
    if (status == "RESOLVED") != (resolved_at is not None):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    generation = value["notification_generation"]
    if type(generation) is not int or generation < 1:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    occurrence_generation = value.get("occurrence_generation")
    if occurrence_generation is None:
        if status == "RESOLVED":
            occurrence_generation = max(1, generation - 1)
        elif status == "HISTORICAL":
            occurrence_generation = 1
        else:
            occurrence_generation = generation
    if (
        type(occurrence_generation) is not int
        or occurrence_generation < 1
        or occurrence_generation > generation
    ):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    result = dict(value)
    if "pending_count_status" not in result:
        result.update(pending_count=None, pending_count_status="UNKNOWN")
    result["occurrence_generation"] = occurrence_generation
    result["delivery"] = _validate_delivery(value["delivery"], generation, budget=budget)
    return result


def _read(root: Path, *, budget=None) -> dict[str, dict[str, Any]]:
    _check_budget(budget)
    path = _state_path(root)
    if not path.exists():
        return {}
    try:
        safe_path = assert_safe_target(root, path, allow_missing=False, expected_type="file")
        with safe_path.open("rb") as stream:
            raw = stream.read(_STATE_MAX_BYTES + 1)
        if len(raw) > _STATE_MAX_BYTES:
            raise IncidentStateError("INCIDENT_STATE_TOO_LARGE")
        document = json.loads(raw.decode("utf-8", errors="strict"))
    except IncidentStateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, SafeFilesystemError) as exc:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT") from exc
    if not isinstance(document, Mapping) or set(document) != {"schema_version", "incidents"}:
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    if document["schema_version"] != _STATE_VERSION or not isinstance(document["incidents"], list):
        raise IncidentStateError("INCIDENT_STATE_CORRUPT")
    result: dict[str, dict[str, Any]] = {}
    for raw in document["incidents"]:
        _check_budget(budget)
        item = _validate_incident(raw, budget=budget)
        identifier = item["incident_id"]
        if identifier in result:
            raise IncidentStateError("INCIDENT_STATE_CORRUPT")
        result[identifier] = item
    return result


def _write(root: Path, incidents: Mapping[str, Mapping[str, Any]], *, budget=None) -> None:
    _check_budget(budget)
    rows = []
    for key in sorted(incidents):
        _check_budget(budget)
        rows.append(incidents[key])
    document = {
        "schema_version": _STATE_VERSION,
        "incidents": rows,
    }
    try:
        encoded = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IncidentStateError("INCIDENT_STATE_INVALID") from exc
    if len(encoded) > _STATE_MAX_BYTES:
        raise IncidentStateError("INCIDENT_STATE_TOO_LARGE")
    try:
        _check_budget(budget)
        safe_atomic_write(root, _state_path(root), encoded, mode=0o600)
    except SafeFilesystemError as exc:
        raise IncidentStateError("INCIDENT_STATE_WRITE_FAILED") from exc


def _new_incident(issue: HealthIssue, reason: str, *, now: datetime) -> dict[str, Any]:
    component = issue.component_id
    historical = reason == "PENDING_EXPIRED"
    timestamp = _timestamp(now)
    return {
        "schema_version": 1,
        "incident_id": incident_id(reason, component),
        "reason_family": reason_family(reason),
        "reason_code": reason,
        "component_id": component,
        "severity": issue.severity,
        "pending_count": issue.pending_count,
        "pending_count_status": issue.pending_count_status,
        "detected_at": timestamp,
        "last_observed_at": timestamp,
        "status": "HISTORICAL" if historical else "OPEN",
        "resolved_at": None,
        "notification_generation": 1,
        "occurrence_generation": 1,
        "delivery": _empty_delivery(),
    }


def _merge_observation(existing: dict[str, Any], issue: HealthIssue, reason: str, *, now: datetime) -> None:
    old_rank = _SEVERITY_RANK[existing["severity"]]
    new_rank = _SEVERITY_RANK[issue.severity]
    reopened = existing["status"] == "RESOLVED"
    if reopened or new_rank > old_rank:
        existing["notification_generation"] += 1
    if reopened:
        existing["status"] = "OPEN"
        existing["resolved_at"] = None
        existing["occurrence_generation"] = existing["notification_generation"]
        existing["severity"] = issue.severity
        existing["reason_code"] = reason
        existing["reason_family"] = reason_family(reason)
        existing["delivery"]["cli"]["successful_sessions"] = []
    elif new_rank > old_rank or (new_rank == old_rank and existing["reason_code"] == "OPERATION_FAILED"):
        existing["severity"] = issue.severity
        existing["reason_code"] = reason
        existing["reason_family"] = reason_family(reason)
    existing["pending_count"] = issue.pending_count
    existing["pending_count_status"] = issue.pending_count_status
    existing["last_observed_at"] = _timestamp(now)


def update_incidents(
    settings: Any,
    issues: tuple[HealthIssue, ...],
    *,
    now: datetime,
    verified_resolutions: tuple[str, ...] = (),
    budget=None,
) -> tuple[dict, ...]:
    _check_budget(budget)
    moment = _aware(now)
    if not isinstance(issues, tuple) or any(not isinstance(item, HealthIssue) for item in issues):
        raise TypeError("HEALTH_ISSUES_REQUIRED")
    if not isinstance(verified_resolutions, tuple) or any(not isinstance(item, str) for item in verified_resolutions):
        raise TypeError("VERIFIED_RESOLUTIONS_REQUIRED")
    root = _state_root(settings)
    descriptor = _acquire(root, budget=budget)
    try:
        incidents = _read(root, budget=budget)
        seen: set[str] = set()
        ordered = sorted(issues, key=lambda item: (_SEVERITY_RANK[item.severity], item.reason_code, item.component_id))
        for issue in ordered:
            _check_budget(budget)
            reason = _reason_code(issue.reason_code)
            identifier = incident_id(reason, issue.component_id)
            seen.add(identifier)
            if identifier in incidents:
                _merge_observation(incidents[identifier], issue, reason, now=moment)
            else:
                incidents[identifier] = _new_incident(issue, reason, now=moment)
        verified = {item for item in verified_resolutions if _INCIDENT_ID.fullmatch(item)}
        for identifier in verified - seen:
            _check_budget(budget)
            existing = incidents.get(identifier)
            if existing is None or existing["status"] != "OPEN":
                continue
            existing["status"] = "RESOLVED"
            existing["resolved_at"] = _timestamp(moment)
            existing["notification_generation"] += 1
        for value in incidents.values():
            _check_budget(budget)
            _validate_incident(value, budget=budget)
        _write(root, incidents, budget=budget)
        copied = []
        for key in sorted(incidents):
            _check_budget(budget)
            copied.append(json.loads(json.dumps(incidents[key])))
        return tuple(copied)
    finally:
        _release(descriptor)


def notification_due(
    incident: dict,
    *,
    channel: str,
    session_hash: str | None,
    now: datetime,
    budget=None,
) -> bool:
    moment = _aware(now)
    value = _validate_incident(incident, budget=budget)
    if channel not in {"os", "cli"}:
        raise ValueError("INCIDENT_CHANNEL_INVALID")
    if channel == "cli":
        if session_hash is None:
            return False
        if not isinstance(session_hash, str) or not _SAFE_ID.fullmatch(session_hash):
            raise ValueError("INCIDENT_SESSION_HASH_INVALID")
    state = value["delivery"][channel]
    if channel == "cli" and session_hash in state["successful_sessions"]:
        return False
    attempt_at = _parse_timestamp(state["last_attempt_at"], optional=True)
    if state["last_result"] in {"FAILED", "UNKNOWN"} and attempt_at is not None and moment < attempt_at + timedelta(hours=1):
        return False
    generation = value["notification_generation"]
    success_generation = state["success_generation"]
    success_at = _parse_timestamp(state["last_success_at"], optional=True)
    if value["status"] == "RESOLVED":
        return (
            success_at is not None
            and success_generation >= value["occurrence_generation"]
            and success_generation < generation
        )
    if value["severity"] == "info":
        return False
    if success_generation < generation:
        return True
    if value["status"] == "HISTORICAL":
        return False
    if channel == "cli":
        return True
    return success_at is None or moment >= success_at + timedelta(hours=24)


def inspect_incidents(settings: Any, *, budget=None) -> dict:
    """Atomic-file read without creating directories, locks or state.

    A concurrent replacement yields either validated version. No read lock is
    needed because writers replace the complete document atomically.
    """
    try:
        _check_budget(budget)
        root = Path(settings.paths.runtime_dir) / "state"
        if not root.exists() or not (root / "operation-incidents.json").exists():
            return {"status": "UNKNOWN", "incidents": (), "reason_code": "INCIDENT_STATE_MISSING"}
        values = _read(root, budget=budget)
        return {"status": "KNOWN", "incidents": tuple(values.values()), "reason_code": "OK"}
    except (OSError, ValueError, TypeError, RuntimeError):
        return {"status": "UNKNOWN", "incidents": (), "reason_code": "INCIDENT_STATE_UNAVAILABLE"}


def read_incidents(settings: Any, *, lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS, budget=None) -> tuple[dict, ...]:
    """Return validated durable snapshots without rewriting incident history."""
    _check_budget(budget)
    root = _state_root(settings)
    descriptor = _acquire(root, timeout_seconds=lock_timeout_seconds, budget=budget)
    try:
        incidents = _read(root, budget=budget)
        return tuple(incidents[key] for key in sorted(incidents))
    finally:
        _release(descriptor)


def claim_notification(settings: Any, identifier: str, *, channel: str, session_hash: str | None,
                       now: datetime, lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS, budget=None) -> NotificationLease | None:
    """Atomically persist an attempt/UNKNOWN before any external send.

    An uncompleted lease is retryable at one hour, including after a crash.
    At most one claimant wins within that window. Snapshot fields are derived
    from this locked incident, not from a caller's potentially stale snapshot.
    """
    moment = _aware(now)
    if not isinstance(identifier, str) or not _INCIDENT_ID.fullmatch(identifier):
        raise ValueError("INCIDENT_ID_INVALID")
    if channel not in {"os", "cli"}:
        raise ValueError("INCIDENT_CHANNEL_INVALID")
    if channel == "os" and session_hash is not None:
        raise ValueError("INCIDENT_SESSION_HASH_INVALID")
    _check_budget(budget)
    root = _state_root(settings)
    descriptor = _acquire(root, timeout_seconds=lock_timeout_seconds, budget=budget)
    try:
        incidents = _read(root, budget=budget)
        value = incidents.get(identifier)
        if value is None or not notification_due(value, channel=channel, session_hash=session_hash, now=moment, budget=budget):
            return None
        lease = NotificationLease(identifier, channel, uuid.uuid4().hex, value["notification_generation"],
                                  value["occurrence_generation"], session_hash, value["reason_code"],
                                  value["pending_count"], value["status"] == "RESOLVED", value["pending_count_status"])
        persisted_lease = lease.persisted()
        persisted_lease["previous_delivery"] = {
            key: field for key, field in value["delivery"][channel].items() if key != "lease"
        }
        value["delivery"][channel].update({"last_attempt_at": _timestamp(moment), "last_result": "UNKNOWN",
                                           "lease": persisted_lease, "last_status": None,
                                           "last_reason_code": None, "delivery_id": None,
                                           "display_status": "UNVERIFIED"})
        _validate_incident(value, budget=budget)
        _write(root, incidents, budget=budget)
        return lease
    finally:
        _release(descriptor)


def _matching_lease(value: dict, lease: NotificationLease) -> bool:
    persisted = value["delivery"][lease.channel].get("lease")
    return (
        isinstance(persisted, Mapping)
        and {key: persisted[key] for key in _LEASE_FIELDS} == lease.persisted()
        and value["notification_generation"] == lease.notification_generation
        and value["occurrence_generation"] == lease.occurrence_generation
    )


def abort_notification(settings: Any, lease: NotificationLease, *,
                       lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS, budget=None) -> bool:
    """Release only a positively unstarted send; never call after invoking OS.

    Restore the previous attempt/result without resurrecting an old lease. A
    crash has no such proof and remains UNKNOWN. Correlation changes reject
    rollback, as do legacy leases without a rollback snapshot.
    """
    if not isinstance(lease, NotificationLease) or lease.channel not in {"os", "cli"}:
        raise TypeError("INCIDENT_DELIVERY_CONTRACT_REQUIRED")
    _check_budget(budget)
    root = _state_root(settings)
    descriptor = _acquire(root, timeout_seconds=lock_timeout_seconds, budget=budget)
    try:
        incidents = _read(root, budget=budget)
        value = incidents.get(lease.incident_id)
        if value is None or not _matching_lease(value, lease):
            return False
        previous = value["delivery"][lease.channel]["lease"].get("previous_delivery")
        if previous is None:
            return False
        value["delivery"][lease.channel] = dict(previous)
        _validate_incident(value, budget=budget)
        _write(root, incidents, budget=budget)
        return True
    finally:
        _release(descriptor)


def settle_notification(settings: Any, lease: NotificationLease, result: DeliveryResult, *,
                        now: datetime, lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS, budget=None) -> bool:
    """Settle only the exact incident/token/generation/occurrence claimed.

    False means superseded/stale: never promote an old send into evidence for a
    current recurrence. Its attempt remains UNKNOWN until the retry window.
    """
    moment = _aware(now)
    if not isinstance(lease, NotificationLease) or not isinstance(result, DeliveryResult):
        raise TypeError("INCIDENT_DELIVERY_CONTRACT_REQUIRED")
    if lease.channel not in {"os", "cli"}:
        raise ValueError("INCIDENT_CHANNEL_INVALID")
    _check_budget(budget)
    root = _state_root(settings)
    descriptor = _acquire(root, timeout_seconds=lock_timeout_seconds, budget=budget)
    try:
        incidents = _read(root, budget=budget)
        value = incidents.get(lease.incident_id)
        if value is None:
            return False
        state = value["delivery"][lease.channel]
        if not _matching_lease(value, lease):
            return False
        attempted = _parse_timestamp(state["last_attempt_at"])
        if moment < attempted:
            raise ValueError("INCIDENT_SETTLEMENT_TIME_INVALID")
        state.update({"lease": None, "last_result": "SUCCESS" if result.status == "SENT" else "FAILED",
                      "last_status": result.status, "last_reason_code": result.reason_code,
                      "delivery_id": result.delivery_id, "display_status": "UNVERIFIED"})
        if result.status == "SENT":
            state["last_success_at"] = _timestamp(moment)
            state["success_generation"] = lease.notification_generation
            if lease.channel == "cli" and lease.session_hash not in state["successful_sessions"]:
                state["successful_sessions"].append(lease.session_hash)
        _validate_incident(value, budget=budget)
        _write(root, incidents, budget=budget)
        return True
    finally:
        _release(descriptor)


__all__ = [
    "IncidentStateError",
    "NotificationLease",
    "abort_notification",
    "claim_notification",
    "incident_id",
    "inspect_incidents",
    "notification_due",
    "reason_family",
    "read_incidents",
    "settle_notification",
    "update_incidents",
]
