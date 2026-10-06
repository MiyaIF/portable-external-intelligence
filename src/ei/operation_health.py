from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta


_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_COMPONENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$")
_SEVERITIES = frozenset({"info", "warning", "error", "critical"})
_KNOWN_PROVIDER_CODES = frozenset(
    {
        "AUTH_FAILED",
        "AUTH_PENDING",
        "DEADLINE_EXCEEDED",
        "MALFORMED_RESPONSE",
        "NO_PROVIDER_AVAILABLE",
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
_IMMEDIATE_PROVIDER_CODES = frozenset({"AUTH_FAILED", "PERMISSION_DENIED", "PROVIDER_PERMISSION_DENIED"})
STORAGE_CODES = frozenset({
    "RUNTIME_ACCOUNTING_UNKNOWN", "RUNTIME_CAPACITY_UNKNOWN", "RUNTIME_CATALOG_MISSING",
    "RUNTIME_CATALOG_UNAVAILABLE", "RUNTIME_DELETE_UNCONFIRMED", "RUNTIME_DUPLICATE_MISMATCH",
    "RUNTIME_DUPLICATE_UNRESOLVED", "RUNTIME_ENTRY_CHANGED", "RUNTIME_ENTRY_TOO_LARGE",
    "RUNTIME_ENTRY_UNVERIFIED", "RUNTIME_INVENTORY_UNSAFE", "RUNTIME_MEMBERSHIP_UNKNOWN",
    "RUNTIME_PATH_INVALID", "RUNTIME_PREPARED_MISMATCH", "RUNTIME_PREPARED_UNRESOLVED",
    "RUNTIME_ROOT_INVENTORY_UNKNOWN", "RUNTIME_SHARD_INVENTORY_UNKNOWN",
    "RUNTIME_UPDATE_METADATA_UNKNOWN", "RUNTIME_WRITE_UNCONFIRMED", "STORAGE_UNAVAILABLE",
    "SPOOL_CAPACITY_UNKNOWN", "SPOOL_CAPACITY_UNVERIFIED", "SPOOL_KEY_UNAVAILABLE",
    "SPOOL_FULL", "SPOOL_TEMP_CLEANUP_UNCONFIRMED", "PENDING_STORAGE_UNAVAILABLE",
    "JOURNAL_BOUNDED_LIMIT", "JOURNAL_CORRUPT", "PROJECTION_STORAGE_LIMIT",
    "PROJECTION_GENERATION_UNOWNED", "PROJECTION_GENERATION_CONFLICT",
    "PROJECTION_ATTRIBUTES_CONFLICT", "PROJECTION_GENERATION_INVALID",
    "INDEX_GENERATION_EXPIRED", "INDEX_GENERATION_INVALID", "INDEX_FILE_HASH_MISMATCH",
    "CLOSEOUT_ASSOCIATION_PENDING", "CLOSEOUT_METADATA_UNKNOWN",
})


def validate_pending_count(count: int | None, status: str) -> None:
    if status not in {"COMPLETE", "PARTIAL", "UNKNOWN"} or (
        (count is not None) if status == "UNKNOWN" else (type(count) is not int or count < 0)
    ):
        raise ValueError("HEALTH_PENDING_COUNT_INVALID")


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("HEALTH_TIMEZONE_REQUIRED")
    return value


def _component(value: str, fallback: str) -> str:
    selected = value or fallback
    if not isinstance(selected, str) or not _COMPONENT_ID.fullmatch(selected):
        raise ValueError("HEALTH_COMPONENT_ID_INVALID")
    return selected


@dataclass(frozen=True)
class HealthInput:
    pending_count: int | None = 0
    pending_bytes: int | None = 0
    max_items: int = 1000
    max_bytes: int = 67108864
    oldest_pending_at: datetime | None = None
    earliest_expiry: datetime | None = None
    last_progress_at: datetime | None = None
    last_attempt_at: datetime | None = None
    provider_code: str | None = None
    provider_needs_action: bool = False
    provider_id: str = ""
    host_id: str = ""
    scheduler_requested: bool = True
    missed_eligible_runs: int | None = None
    source_missing_count: int = 0
    source_missing_ids: tuple[str, ...] = ()
    expired_capture_ids: tuple[str, ...] = ()
    cleanup_failed_capture_ids: tuple[str, ...] = ()
    pending_count_status: str = "COMPLETE"
    reserved_count: int | None = None
    reserved_bytes: int | None = None
    storage_code: str | None = None
    storage_component_id: str = "pending-store"
    closeout_pending_count: int | None = 0
    closeout_pending_bytes: int | None = 0
    closeout_max_items: int = 64
    closeout_max_bytes: int = 1048576
    closeout_earliest_expiry: datetime | None = None
    closeout_pending_status: str = "COMPLETE"
    closeout_unknown_count: int = 0

    def __post_init__(self) -> None:
        validate_pending_count(self.pending_count, self.pending_count_status)
        for name in ("max_items", "max_bytes", "source_missing_count"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"HEALTH_INPUT_INVALID:{name}")
        for name in ("closeout_max_items", "closeout_max_bytes", "closeout_unknown_count"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"HEALTH_INPUT_INVALID:{name}")
        for name in ("pending_bytes", "reserved_count", "reserved_bytes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"HEALTH_INPUT_INVALID:{name}")
        if self.pending_count_status == "UNKNOWN" and self.pending_bytes is not None:
            raise ValueError("HEALTH_INPUT_INVALID:pending_bytes")
        validate_pending_count(self.closeout_pending_count, self.closeout_pending_status)
        if self.closeout_pending_status == "UNKNOWN" and self.closeout_pending_bytes is not None:
            raise ValueError("HEALTH_INPUT_INVALID:closeout_pending_bytes")
        if self.closeout_pending_bytes is not None and (type(self.closeout_pending_bytes) is not int or self.closeout_pending_bytes < 0):
            raise ValueError("HEALTH_INPUT_INVALID:closeout_pending_bytes")
        if self.storage_code is not None and self.storage_code not in STORAGE_CODES:
            raise ValueError("HEALTH_STORAGE_CODE_INVALID")
        _component(self.storage_component_id, "pending-store")
        if self.missed_eligible_runs is not None and (
            type(self.missed_eligible_runs) is not int or self.missed_eligible_runs < 0
        ):
            raise ValueError("HEALTH_INPUT_INVALID:missed_eligible_runs")
        if type(self.provider_needs_action) is not bool or type(self.scheduler_requested) is not bool:
            raise ValueError("HEALTH_INPUT_INVALID:flag")
        for name in ("oldest_pending_at", "earliest_expiry", "last_progress_at", "last_attempt_at", "closeout_earliest_expiry"):
            value = getattr(self, name)
            if value is not None:
                _aware(value)
        for name in ("source_missing_ids", "expired_capture_ids", "cleanup_failed_capture_ids"):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                raise ValueError(f"HEALTH_INPUT_INVALID:{name}")
            for item in value:
                _component(item, "component")
        if self.provider_id:
            _component(self.provider_id, "provider")
        if self.host_id:
            _component(self.host_id, "host")


@dataclass(frozen=True)
class HealthIssue:
    reason_code: str
    component_id: str
    severity: str
    pending_count: int | None
    pending_count_status: str = "COMPLETE"

    def __post_init__(self) -> None:
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(self.reason_code):
            raise ValueError("HEALTH_REASON_CODE_INVALID")
        _component(self.component_id, "component")
        if self.severity not in _SEVERITIES:
            raise ValueError("HEALTH_SEVERITY_INVALID")
        validate_pending_count(self.pending_count, self.pending_count_status)


def stalled(snapshot: HealthInput, now: datetime) -> bool:
    moment = _aware(now)
    if not snapshot.pending_count:
        return False
    baseline = snapshot.last_progress_at or snapshot.oldest_pending_at
    return baseline is not None and (moment - baseline).total_seconds() >= 86400


def _at_capacity_risk(value: int | None, maximum: int) -> bool:
    if value is None or value == 0:
        return False
    if maximum == 0:
        return True
    return value * 5 >= maximum * 4


def evaluate_health(snapshot: HealthInput, *, now: datetime) -> tuple[HealthIssue, ...]:
    moment = _aware(now)
    if not isinstance(snapshot, HealthInput):
        raise TypeError("HEALTH_INPUT_REQUIRED")
    issues: list[HealthIssue] = []
    def issue(reason, component, severity):
        return HealthIssue(reason, component, severity, snapshot.pending_count, snapshot.pending_count_status)

    if stalled(snapshot, moment):
        issues.append(issue("ACCUMULATION_STALLED", "pending-store", "error"))
    if _at_capacity_risk(snapshot.pending_count, snapshot.max_items) or _at_capacity_risk(
        snapshot.pending_bytes, snapshot.max_bytes
    ) or _at_capacity_risk(snapshot.reserved_count, snapshot.max_items) or _at_capacity_risk(snapshot.reserved_bytes, snapshot.max_bytes):
        issues.append(issue("CAPACITY_RISK", "pending-store", "warning"))
    if (
        snapshot.pending_count is not None and snapshot.pending_count > 0
        and snapshot.earliest_expiry is not None
        and snapshot.earliest_expiry - moment <= timedelta(hours=24)
    ):
        issues.append(issue("EXPIRY_RISK", "pending-store", "warning"))
    if snapshot.scheduler_requested and snapshot.missed_eligible_runs is not None and snapshot.missed_eligible_runs >= 2:
        issues.append(
            issue(
                "SCHEDULER_STOPPED",
                _component(snapshot.host_id, "scheduler"),
                "error",
            )
        )

    if snapshot.provider_code is not None:
        reason = snapshot.provider_code if snapshot.provider_code in _KNOWN_PROVIDER_CODES else "OPERATION_FAILED"
        severity = "error" if snapshot.provider_needs_action or reason in _IMMEDIATE_PROVIDER_CODES else "info"
        issues.append(
            issue(reason, _component(snapshot.provider_id, "provider"), severity)
        )
    if snapshot.storage_code is not None:
        issues.append(issue(snapshot.storage_code, snapshot.storage_component_id, "error"))

    closeout_count = snapshot.closeout_pending_count
    closeout_status = snapshot.closeout_pending_status
    if closeout_status != "UNKNOWN" and closeout_count is not None and closeout_count > 0:
        issues.append(HealthIssue(
            "CLOSEOUT_ASSOCIATION_PENDING", "closeout-store", "warning",
            None, "UNKNOWN",
        ))
    if (
        _at_capacity_risk(closeout_count, snapshot.closeout_max_items)
        or _at_capacity_risk(snapshot.closeout_pending_bytes, snapshot.closeout_max_bytes)
    ):
        issues.append(HealthIssue(
            "CAPACITY_RISK", "closeout-store", "warning", None, "UNKNOWN",
        ))
    if (
        closeout_status != "UNKNOWN" and closeout_count is not None and closeout_count > 0
        and snapshot.closeout_earliest_expiry is not None
        and snapshot.closeout_earliest_expiry - moment <= timedelta(hours=24)
    ):
        issues.append(HealthIssue(
            "EXPIRY_RISK", "closeout-store", "warning", None, "UNKNOWN",
        ))
    if closeout_status == "UNKNOWN" or snapshot.closeout_unknown_count > 0:
        issues.append(HealthIssue(
            "CLOSEOUT_METADATA_UNKNOWN", "closeout-store", "error",
            None, "UNKNOWN",
        ))

    source_ids = tuple(sorted(set(snapshot.source_missing_ids)))
    for source_id in source_ids:
        issues.append(issue("SOURCE_UNAVAILABLE", source_id, "critical"))
    unidentified = max(0, snapshot.source_missing_count - len(source_ids))
    if unidentified:
        issues.append(
            issue(
                "SOURCE_UNAVAILABLE",
                _component(snapshot.host_id, "source-index"),
                "critical",
            )
        )

    for capture_id in sorted(set(snapshot.expired_capture_ids)):
        issues.append(issue("PENDING_EXPIRED", capture_id, "critical"))
    for capture_id in sorted(set(snapshot.cleanup_failed_capture_ids)):
        issues.append(issue("EXPIRY_CLEANUP_FAILED", capture_id, "error"))
    return tuple(issues)


__all__ = ["HealthInput", "HealthIssue", "evaluate_health", "stalled"]
