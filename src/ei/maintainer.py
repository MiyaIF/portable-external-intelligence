from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .changeset import apply_changeset, validate_changeset
from .curator import curate_candidate
from .gate import GateDecision, apply_gate_decision, decide_inheritance
from .ids import machine_id, stable_hash
from .index import build_index, read_index_items
from .inference.base import InferenceBudget, ProviderResult
from .inference.router import ProviderRouter, ProviderSelectionError
from .ingest import ingest_sources
from .journal import append_event, iter_events
from .models import Event, KnowledgeIndex, PromotionPolicy
from .persistable_fields import is_privacy_or_safety_violation
from .project import project_events
from .queue import QueueError, QueueItem, QueueState, claim_queue_item, list_queue_items, recover_emergency_spool, transition_queue_item
from .reconciliation import ReconciliationResult, reconcile_lifecycle
from .recovery import RecoveryResult, reconcile_orphans
from .spool import SpoolError, delete_spool, gc_expired_spool, read_spool, spool_health
from .sync import SyncResult, sync_once


_ALLOWED_SYNC_POLICIES = frozenset({"disabled", "manual", "auto"})
_RETRYABLE_PROVIDER_CODES = frozenset({
    "NO_PROVIDER_AVAILABLE", "PROVIDER_DISABLED", "QUOTA_EXHAUSTED",
    "RATE_LIMITED", "PROVIDER_RATE_LIMITED", "PROVIDER_TIMEOUT",
    "PROVIDER_UNAVAILABLE", "AUTH_PENDING", "AUTH_FAILED", "DEADLINE_EXCEEDED",
    "ORGANIZER_SELECTION_REQUIRED", "ORGANIZER_PROVIDER_NOT_CONFIGURED",
    "INFERENCE_PROVIDER_CONFIG_READ_FAILED", "INFERENCE_PROVIDER_CONFIG_INVALID",
    "ORGANIZER_PROVIDER_CONFIG_INVALID",
})
_MALFORMED_CODES = frozenset({
    "MALFORMED_RESPONSE", "SCHEMA_VIOLATION", "GATE_OUTPUT_OBJECT_REQUIRED",
    "GATE_DECISION_INVALID", "GATE_YES_FIELDS_INVALID", "GATE_EVIDENCE_REFS_INVALID",
    "GATE_APPLICABILITY_INVALID", "GATE_HOST_LIST_INVALID", "PROVIDER_PROTOCOL_ERROR",
})


class MaintenanceError(RuntimeError):
    """Raised when a maintenance contract cannot safely complete."""


class TeamServices(Protocol):
    """Small seam for the optional team maintenance side effects.

    The protocol deliberately keeps the personal maintenance pipeline
    independent from shared-folder I/O.  Production uses the adapter below;
    tests can provide a spy without importing or constructing team services
    when the team store is disabled.
    """

    def drain_outbox(
        self,
        settings: Any,
        *,
        max_items: int,
        now: datetime | None,
    ) -> Mapping[str, Any]:
        ...

    def refresh_projection(
        self,
        shared_root: Path,
        runtime_root: Path,
        store_id: str,
    ) -> Any:
        ...


class _DefaultTeamServices:
    def drain_outbox(
        self,
        settings: Any,
        *,
        max_items: int,
        now: datetime | None,
    ) -> Mapping[str, Any]:
        from .team_outbox import drain_team_outbox

        return drain_team_outbox(settings, max_items=max_items, now=now)

    def refresh_projection(
        self,
        shared_root: Path,
        runtime_root: Path,
        store_id: str,
    ) -> Any:
        from .team_projection import refresh_team_projection

        return refresh_team_projection(shared_root, runtime_root, store_id)


@dataclass(frozen=True)
class QueueDrainResult:
    status: str
    attempted: int
    processed: int
    completed: int
    discarded: int
    deferred: int
    failed: int
    remaining: int
    recovered_emergency: int
    completed_queue_ids: tuple[str, ...] = ()
    deferred_queue_ids: tuple[str, ...] = ()
    failed_queue_ids: tuple[str, ...] = ()
    errors: tuple[Mapping[str, Any], ...] = ()
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status, "attempted": self.attempted, "processed": self.processed,
            "completed": self.completed, "discarded": self.discarded, "deferred": self.deferred,
            "failed": self.failed, "remaining": self.remaining,
            "recovered_emergency": self.recovered_emergency,
            "completed_queue_ids": list(self.completed_queue_ids),
            "deferred_queue_ids": list(self.deferred_queue_ids),
            "failed_queue_ids": list(self.failed_queue_ids),
            "errors": [dict(item) for item in self.errors],
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class MaintenanceResult:
    status: str
    started_at: str
    finished_at: str
    elapsed_ms: int
    ingest_sources: int
    ingest_created_events: int
    ingest_skipped_records: int
    ingest_parse_skipped: int
    ingest_rejected_records: int
    ingest_results: tuple[Mapping[str, Any], ...]
    recovered_emergency: int
    expired_spool: int
    queue: Mapping[str, Any]
    capture: Mapping[str, Any]
    recovery: Mapping[str, Any]
    lifecycle: Mapping[str, Any]
    projection: Mapping[str, Any]
    metrics: Mapping[str, Any]
    sync: Mapping[str, Any]
    errors: tuple[Mapping[str, Any], ...] = ()
    blocked_reason: str | None = None
    personal: Mapping[str, Any] = field(default_factory=dict)
    team: Mapping[str, Any] = field(default_factory=dict)

    @property
    def drain(self) -> Mapping[str, Any]:
        return self.queue

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status, "started_at": self.started_at, "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms, "ingest_sources": self.ingest_sources,
            "ingest_created_events": self.ingest_created_events,
            "ingest_skipped_records": self.ingest_skipped_records,
            "ingest_parse_skipped": self.ingest_parse_skipped,
            "ingest_rejected_records": self.ingest_rejected_records,
            "ingest_results": [dict(item) for item in self.ingest_results],
            "recovered_emergency": self.recovered_emergency, "expired_spool": self.expired_spool,
            "queue": dict(self.queue), "capture": dict(self.capture), "recovery": dict(self.recovery),
            "lifecycle": dict(self.lifecycle), "projection": dict(self.projection),
            "metrics": dict(self.metrics), "sync": dict(self.sync),
            "personal": dict(self.personal or self.projection),
            "team": dict(self.team or {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}),
            "knowledge_stores": {
                "personal": dict(self.personal or self.projection),
                "team": dict(self.team or {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}),
            },
            "errors": [dict(item) for item in self.errors], "blocked_reason": self.blocked_reason,
        }


class _RouterAdapter:
    locality = "router"

    def __init__(self, router: ProviderRouter) -> None:
        self.router = router
        self.provider_id = "provider-router"

    def available(self) -> bool:
        # Selection and provider availability are distinct states.  Calling
        # ``generate`` on the selected provider lets it return a bounded
        # disabled/quota/auth/timeout result without trying another provider.
        return self.router.organizer.status in {"READY", "SELECTION_REQUIRED"}

    def generate(self, schema_name: str, input_json: Mapping[str, Any], budget: InferenceBudget | Mapping[str, Any] | None) -> ProviderResult:
        return self.router.generate("inheritance-gate", schema_name, input_json, InferenceBudget.from_value(budget))


class _UnavailableAdapter:
    locality = "unavailable"
    provider_id = "provider-router"

    def __init__(self, reason_code: str = "NO_PROVIDER_AVAILABLE") -> None:
        self.reason_code = reason_code

    def available(self) -> bool:
        return False


def _utc(value: datetime | None = None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("MAINTENANCE_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _safe_code(value: object, fallback: str = "MAINTENANCE_FAILED") -> str:
    text = str(value or "")
    if text and len(text) <= 96 and all(char.isalnum() or char in "_.:-" for char in text):
        return text
    return fallback


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_INVALID")
    return value


def _remaining_ms(started: float, limit_ms: int) -> int:
    return max(0, limit_ms - int((time.monotonic() - started) * 1000))


def _events(settings: Any) -> list[Event]:
    root = Path(settings.paths.event_dir)
    return list(iter_events(root)) if root.exists() else []


def _event_by_id(settings: Any, event_id: str) -> Event | None:
    return next((event for event in _events(settings) if event.event_id == event_id), None) if event_id else None


def _candidate_for(item: QueueItem, settings: Any, now: datetime | None = None) -> dict[str, Any]:
    if item.payload_ref is not None:
        try:
            raw = read_spool(item.payload_ref, settings, now=now)
        except SpoolError as exc:
            raise MaintenanceError(_safe_code(str(exc), "SPOOL_READ_FAILED")) from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise MaintenanceError("QUEUE_PAYLOAD_INVALID") from exc
        if not isinstance(value, Mapping):
            raise MaintenanceError("QUEUE_PAYLOAD_INVALID")
        candidate = {str(key): child for key, child in value.items() if isinstance(key, str)}
    else:
        event = _event_by_id(settings, item.event_id)
        candidate = dict(event.payload) if event is not None else {}
    candidate.setdefault("source_kind", "queue")
    candidate.setdefault("source_ref", item.source_ref or "queue")
    candidate.setdefault("classification", item.privacy_classification)
    candidate.setdefault("source_hash", item.source_hash)
    # The queue receipt is the trusted source boundary; payload/provider fields
    # cannot replace its host identity.
    if not item.source_host_id or not item.source_host_family:
        raise MaintenanceError("QUEUE_SOURCE_HOST_PAIR_REQUIRED")
    candidate["source_host_id"] = item.source_host_id
    candidate["source_host_family"] = item.source_host_family
    candidate.setdefault("applicability_scope", "host")
    candidate.setdefault("applicable_host_ids", [item.source_host_id])
    candidate.setdefault("applicable_host_families", [])
    candidate.setdefault("evidence_refs", [item.source_hash] if item.source_hash.startswith("sha256:") else [])
    candidate.setdefault("domain", "general")
    candidate.setdefault("outcome_status", "unknown")
    candidate.setdefault("benefit", "")
    return candidate


def _provider_for(settings: Any, provider: Any | None) -> Any:
    if provider is not None:
        return provider
    try:
        return _RouterAdapter(ProviderRouter(settings=settings))
    except (OSError, TypeError, ValueError) as exc:
        reason = _safe_code(str(exc), "ORGANIZER_PROVIDER_CONFIG_INVALID")
        if reason not in {"INFERENCE_PROVIDER_CONFIG_READ_FAILED", "INFERENCE_PROVIDER_CONFIG_INVALID"}:
            reason = "ORGANIZER_PROVIDER_CONFIG_INVALID"
        return _UnavailableAdapter(reason)


def _deferred(candidate: Mapping[str, Any], reason: str, now: datetime, provider_id: str = "provider-router") -> GateDecision:
    source_host_id = candidate.get("source_host_id", "")
    source_host_family = candidate.get("source_host_family", "")
    scope = candidate.get("applicability_scope", "host")
    host_ids = candidate.get("applicable_host_ids", [source_host_id])
    host_families = candidate.get("applicable_host_families", [])
    if not isinstance(source_host_id, str) or not isinstance(source_host_family, str):
        source_host_id, source_host_family = "", ""
    if not isinstance(scope, str):
        scope = "universal"
    if not isinstance(host_ids, (list, tuple)) or any(not isinstance(item, str) for item in host_ids):
        host_ids = []
    if not isinstance(host_families, (list, tuple)) or any(not isinstance(item, str) for item in host_families):
        host_families = []
    return GateDecision(
        "DEFERRED", _safe_code(reason, "PROVIDER_UNAVAILABLE"),
        str(candidate.get("title", candidate.get("candidate_title", "")))[:160], "", (), "",
        str(candidate.get("classification", "private-reusable")), 0.0, provider_id,
        processing_state=_safe_code(reason, "PROVIDER_UNAVAILABLE"), retry_after_seconds=300,
        next_eligible_at=now + timedelta(seconds=300),
        source_host_id=source_host_id,
        source_host_family=source_host_family,
        applicability_scope=scope,
        applicable_host_ids=tuple(host_ids),
        applicable_host_families=tuple(host_families),
    )


def _settings_retry_policy(settings: Any, *, max_attempts: int | None = None, retry_delay_seconds: int | None = None) -> tuple[int, int]:
    attempts = max_attempts if max_attempts is not None else getattr(settings, "curation_max_attempts", 3)
    delay = retry_delay_seconds if retry_delay_seconds is not None else getattr(settings, "curation_retry_delay_seconds", 300)
    if type(attempts) is not int or attempts < 1 or type(delay) is not int or delay < 0:
        raise ValueError("CURATION_RETRY_POLICY_INVALID")
    return attempts, delay


def _failure_target(reason_code: str, attempts: int, max_attempts: int) -> QueueState:
    if is_privacy_or_safety_violation(reason_code):
        return QueueState.QUARANTINED
    if reason_code in _MALFORMED_CODES or reason_code.startswith(("SCHEMA_", "GATE_", "OUTPUT_", "PROVIDER_PROTOCOL")):
        return QueueState.FAILED_NEEDS_ATTENTION if attempts >= max_attempts else QueueState.FAILED_RETRYABLE
    return QueueState.FAILED_NEEDS_ATTENTION if attempts >= max_attempts else QueueState.FAILED_RETRYABLE


def process_failure(
    item: QueueItem,
    reason_code: str,
    *,
    max_attempts: int | None = None,
    retry_delay_seconds: int | None = None,
    now: datetime | None = None,
    settings: Any | None = None,
) -> QueueItem:
    """Classify one processing failure without discarding its candidate.

    With settings supplied the durable queue file is transitioned atomically;
    without settings the helper remains useful as a pure state transition for
    tests and recovery planning.
    """

    if not isinstance(item, QueueItem):
        raise ValueError("QUEUE_ITEM_INVALID")
    if settings is not None:
        max_attempts, retry_delay_seconds = _settings_retry_policy(
            settings, max_attempts=max_attempts, retry_delay_seconds=retry_delay_seconds
        )
    else:
        max_attempts = 3 if max_attempts is None else max_attempts
        retry_delay_seconds = 300 if retry_delay_seconds is None else retry_delay_seconds
    if type(max_attempts) is not int or max_attempts < 1 or type(retry_delay_seconds) is not int or retry_delay_seconds < 0:
        raise ValueError("CURATION_RETRY_POLICY_INVALID")
    reason = _safe_code(reason_code, "PROCESSING_FAILED")
    target = _failure_target(reason, item.attempts, max_attempts)
    moment = _utc(now)
    next_at = moment + timedelta(seconds=retry_delay_seconds) if target == QueueState.FAILED_RETRYABLE else None
    if settings is not None:
        return transition_queue_item(item, target, settings, now=moment, reason_code=reason, next_eligible_at=next_at)
    return replace(
        item,
        state=target,
        next_eligible_at=_iso(next_at) if next_at else None,
        lease_owner=None,
        lease_expires_at=None,
        last_error_code=reason,
    )


def _apply_processing_decision(decision: GateDecision, item: QueueItem, settings: Any, now: datetime) -> tuple[str, QueueItem]:
    reason = _safe_code(decision.reason_code, "PROCESSING_FAILED")
    if decision.decision == "NO":
        applied = apply_gate_decision(decision, item, settings)
        return "discarded", applied.queue_item
    if decision.decision == "DEFERRED":
        updated = transition_queue_item(
            item,
            QueueState.DEFERRED,
            settings,
            now=now,
            reason_code=reason,
            next_eligible_at=decision.next_eligible_at or now + timedelta(seconds=300),
        )
        return "deferred", updated
    if decision.decision == "FAILED":
        if reason in _RETRYABLE_PROVIDER_CODES:
            updated = transition_queue_item(
                item,
                QueueState.DEFERRED,
                settings,
                now=now,
                reason_code=reason,
                next_eligible_at=decision.next_eligible_at or now + timedelta(seconds=300),
            )
            return "deferred", updated
        return "failed", process_failure(item, reason, now=now, settings=settings)
    applied = apply_gate_decision(decision, item, settings)
    return "curating", applied.queue_item


def _index_or_none(settings: Any) -> KnowledgeIndex | None:
    root = Path(settings.paths.knowledge_dir)
    path = root / "index.json"
    return build_index(root, path) if path.is_file() else None


def _process_claimed(item: QueueItem, settings: Any, provider: Any, now: datetime) -> tuple[str, QueueItem]:
    candidate = _candidate_for(item, settings, now=now)
    try:
        organizer = getattr(settings, "organizer", None)
        if getattr(organizer, "status", None) == "SELECTION_REQUIRED":
            # Setup has not selected an organizer yet.  Keep the candidate in
            # the queue without entering the gate or invoking an injected
            # test/provider adapter.
            decision = _deferred(candidate, "ORGANIZER_SELECTION_REQUIRED", now)
        else:
            availability = getattr(provider, "available", None)
            unavailable = (not availability()) if callable(availability) else (availability is False)
            if availability is not None and unavailable:
                decision = _deferred(
                    candidate,
                    _safe_code(getattr(provider, "reason_code", None), "NO_PROVIDER_AVAILABLE"),
                    now,
                )
            else:
                budget = InferenceBudget(
                    candidate_id=item.queue_id,
                    purpose="inheritance-gate",
                    deadline_ms=max(1, int(getattr(settings, "prompt_budget_ms", 1000))),
                )
                decision = decide_inheritance(candidate, provider, budget)
    except ProviderSelectionError as exc:
        decision = _deferred(candidate, exc.reason_code, now)
    outcome, current = _apply_processing_decision(decision, item, settings, now)
    if outcome in {"discarded", "deferred"}:
        return outcome, current
    if decision.decision == "FAILED":
        return outcome, current

    index = _index_or_none(settings)
    provider_id = decision.provider_id or getattr(provider, "provider_id", "provider-router") or "provider-router"
    changeset = curate_candidate(
        {
            **candidate, "decision": "YES", "title": decision.candidate_title,
            "claim": decision.candidate_claim, "candidate_title": decision.candidate_title,
            "candidate_claim": decision.candidate_claim, "benefit": decision.benefit,
            "classification": decision.classification, "evidence_refs": list(decision.evidence_refs),
            "source_host_id": decision.source_host_id or candidate.get("source_host_id", ""),
            "source_host_family": decision.source_host_family or candidate.get("source_host_family", ""),
            "applicability_scope": decision.applicability_scope,
            "applicable_host_ids": list(decision.applicable_host_ids),
            "applicable_host_families": list(decision.applicable_host_families),
        },
        index, {"provider_id": provider_id}, None,
    )
    validation = validate_changeset(changeset, settings)
    if not validation.valid:
        reason = _safe_code(validation.reason_codes[0] if validation.reason_codes else "CHANGESET_INVALID")
        return "failed", process_failure(current, reason, now=now, settings=settings)
    applied = apply_changeset(changeset, settings)
    if not applied.applied:
        reason = _safe_code(applied.reason_code, "CHANGESET_INVALID")
        return "failed", process_failure(current, reason, now=now, settings=settings)
    if current.payload_ref is not None:
        delete_spool(current.payload_ref, settings, reason_code="QUEUE_DONE")
    return "completed", transition_queue_item(current, QueueState.DONE, settings, reason_code="CURATION_APPLIED")
def drain_queue(
    settings: Any,
    *,
    provider: Any | None = None,
    max_items: int = 100,
    time_budget_ms: int = 5000,
    now: datetime | None = None,
    worker_id: str | None = None,
) -> QueueDrainResult:
    max_items = _bounded_int(max_items, "MAX_ITEMS", 1, 10000)
    time_budget_ms = _bounded_int(time_budget_ms, "TIME_BUDGET_MS", 1, 600000)
    moment = _utc(now)
    started = time.monotonic()
    worker = worker_id or f"maintainer-{os.getpid()}"
    errors: list[Mapping[str, Any]] = []
    try:
        recovered = len(recover_emergency_spool(settings, now=moment))
    except (OSError, QueueError, ValueError) as exc:
        recovered = 0
        errors.append({"stage": "emergency_recovery", "error_code": _safe_code(str(exc))})
    organizer = getattr(settings, "organizer", None)
    if getattr(organizer, "status", None) == "SELECTION_REQUIRED":
        # Selection state must be handled before reading provider config.  An
        # injected adapter remains useful for the test seam, but is never
        # reached by _process_claimed while selection is required.
        selected_provider = provider or _UnavailableAdapter("ORGANIZER_SELECTION_REQUIRED")
    else:
        selected_provider = _provider_for(settings, provider)
    attempted = processed = completed = discarded = deferred = failed = 0
    completed_ids: list[str] = []
    deferred_ids: list[str] = []
    failed_ids: list[str] = []
    while attempted < max_items and _remaining_ms(started, time_budget_ms) > 0:
        try:
            item = claim_queue_item(
                worker, settings, now=moment,
                lease_seconds=max(1, min(300, time_budget_ms // 1000 or 1)),
            )
        except (OSError, QueueError, ValueError) as exc:
            errors.append({"stage": "claim", "error_code": _safe_code(str(exc))})
            break
        if item is None:
            break
        attempted += 1
        try:
            outcome, updated = _process_claimed(item, settings, selected_provider, moment)
            processed += 1
            if outcome in {"completed", "discarded"}:
                completed += outcome == "completed"
                discarded += outcome == "discarded"
                completed_ids.append(updated.queue_id)
            elif outcome == "deferred":
                deferred += 1
                deferred_ids.append(updated.queue_id)
            else:
                failed += 1
                failed_ids.append(updated.queue_id)
        except (OSError, QueueError, MaintenanceError, ValueError, TypeError) as exc:
            failed += 1
            failed_ids.append(item.queue_id)
            reason = _safe_code(str(exc))
            errors.append({"stage": "item", "queue_id_hash": _hash(item.queue_id), "error_code": reason})
            try:
                if reason in _RETRYABLE_PROVIDER_CODES:
                    transition_queue_item(
                        item,
                        QueueState.DEFERRED,
                        settings,
                        now=moment,
                        reason_code=reason,
                        next_eligible_at=moment + timedelta(seconds=300),
                    )
                elif is_privacy_or_safety_violation(reason):
                    transition_queue_item(item, QueueState.QUARANTINED, settings, now=moment, reason_code=reason)
                else:
                    process_failure(item, reason, now=moment, settings=settings)
            except (OSError, QueueError, ValueError) as transition_error:
                errors.append({
                    "stage": "transition", "queue_id_hash": _hash(item.queue_id),
                    "error_code": _safe_code(str(transition_error)),
                })
    try:
        remaining = len(list_queue_items(settings, include_terminal=False))
    except (OSError, QueueError, ValueError):
        remaining = -1
        errors.append({"stage": "health", "error_code": "QUEUE_HEALTH_UNAVAILABLE"})
    elapsed = int((time.monotonic() - started) * 1000)
    status = "partial" if errors or remaining < 0 or _remaining_ms(started, time_budget_ms) == 0 else "success"
    return QueueDrainResult(
        status, attempted, processed, completed, discarded, deferred, failed, remaining,
        recovered, tuple(completed_ids), tuple(deferred_ids), tuple(failed_ids),
        tuple(errors), elapsed,
    )


def _source_files(values: Sequence[Path] | None, settings: Any) -> tuple[Path, ...]:
    if values is None:
        default = Path(settings.paths.codex_home) / "memories"
        values = (default,) if default.exists() else ()
    result: list[Path] = []
    for raw in values:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            raise ValueError("SOURCE_NOT_FOUND")
        if path.is_file():
            result.append(path)
        elif path.is_dir():
            result.extend(sorted(path.rglob("*.md")))
            result.extend(sorted(path.rglob("*.jsonl")))
        else:
            raise ValueError("SOURCE_NOT_REGULAR")
    return tuple(dict.fromkeys(result))


def _adapter(path: Path) -> Any:
    if path.suffix.casefold() == ".md":
        from .adapters.codex_memory import CodexMemoryAdapter
        return CodexMemoryAdapter([path])
    if path.suffix.casefold() == ".jsonl":
        from .adapters.rollout_summary import RolloutSummaryAdapter
        return RolloutSummaryAdapter([path])
    raise ValueError("UNSUPPORTED_SOURCE_FORMAT")


def _ingest(settings: Any, source_paths: Sequence[Path] | None, errors: list[Mapping[str, Any]]) -> tuple[int, int, int, int, int, tuple[Mapping[str, Any], ...]]:
    paths = _source_files(source_paths, settings)
    results: list[Mapping[str, Any]] = []
    created = skipped = parse_skipped = rejected = 0
    for path in paths:
        try:
            result = ingest_sources(settings, [_adapter(path)])
            created += result.created_events
            skipped += result.skipped_records
            parse_skipped += result.parse_skipped
            rejected += result.rejected_records
            row = {
                "source_kind": path.suffix.casefold().lstrip("."),
                "source_hash": _file_hash(path),
                "status": "partial" if result.parse_skipped or result.rejected_records else "success",
                "created_events": result.created_events,
                "skipped_records": result.skipped_records,
                "parse_skipped": result.parse_skipped,
                "rejected_records": result.rejected_records,
                "health": dict(result.health),
            }
            results.append(row)
            if result.parse_skipped or result.rejected_records:
                errors.append({"stage": "ingest", "source_hash": row["source_hash"], "error_code": "SOURCE_PARTIAL"})
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            try:
                source_hash = _file_hash(path)
            except OSError:
                source_hash = ""
            results.append({
                "source_kind": path.suffix.casefold().lstrip("."),
                "source_hash": source_hash,
                "status": "failed",
                "error_code": _safe_code(str(exc)),
            })
            errors.append({"stage": "ingest", "source_hash": source_hash, "error_code": _safe_code(str(exc))})
    return len(paths), created, skipped, parse_skipped, rejected, tuple(results)


def _append_audit(
    settings: Any,
    action: str,
    target: str,
    reason: str,
    old_version: int = 0,
    new_version: int = 0,
    changeset_hash: str = "",
) -> None:
    policy_version = "promotion-v1"
    try:
        value = json.loads(Path(settings.promotion_policy_path).read_text(encoding="utf-8"))
        if isinstance(value, Mapping) and isinstance(value.get("policy_version"), str):
            policy_version = value["policy_version"]
    except (OSError, UnicodeError, json.JSONDecodeError):
        policy_version = "promotion-v1"
    payload = {
        "audit_action": _safe_code(action, "MAINTENANCE"),
        "target_id_hash": _hash(target),
        "reason_code": _safe_code(reason),
        "source_hashes": [_hash(target)],
        "old_version": old_version,
        "new_version": new_version,
        "policy_version": policy_version,
        "changeset_hash": changeset_hash or _hash(action + target + reason),
    }
    event_id = "evt_maintenance_" + stable_hash(payload)[:32]
    if _event_by_id(settings, event_id) is not None:
        return
    event = Event.create(
        "maintenance.audit",
        _iso(),
        "maintainer",
        machine_id(),
        payload,
        event_id=event_id,
    )
    append_event(event, settings.paths.event_dir)


def _quality_audits(settings: Any, reconciliation: ReconciliationResult, projection: KnowledgeIndex | None, policy: PromotionPolicy) -> None:
    if reconciliation.duplicate_observations:
        _append_audit(settings, "DUPLICATE_OBSERVATION", "duplicate", "DUPLICATE_OBSERVATION")
    if projection is None:
        return
    try:
        item_ids = list(projection.active_pattern_ids) + list(projection.archive_pattern_ids)
        items = read_index_items(projection, item_ids)
    except (OSError, ValueError, KeyError, TypeError):
        return
    for item in items:
        pattern_id = str(item.get("pattern_id", item.get("item_id", "")))
        if str(item.get("status", "")) == "active" and len(str(item.get("rule", ""))) > policy.always_on_hard_cap_chars:
            _append_audit(settings, "ALWAYS_ON_DEMOTED", pattern_id, "ALWAYS_ON_HARD_CAP")
    if projection.always_on_chars > policy.always_on_hard_cap_chars:
        _append_audit(settings, "ALWAYS_ON_DEMOTED", "always-on", "ALWAYS_ON_HARD_CAP")


def _knowledge_summary(index: KnowledgeIndex | None) -> dict[str, Any]:
    if index is None:
        return {"status": "NOT_READY", "active_patterns": 0, "candidates": 0, "observations": 0, "always_on_chars": 0}
    candidate_count = 0
    try:
        document = json.loads(Path(index.index_path).read_text(encoding="utf-8"))
        if isinstance(document, Mapping):
            candidate_count = len(document.get("candidate_pattern_ids", ()))
    except (OSError, UnicodeError, json.JSONDecodeError):
        candidate_count = 0
    return {
        "status": "READY",
        "active_patterns": len(index.active_pattern_ids),
        "candidates": candidate_count,
        "observations": index.observation_count,
        "always_on_chars": index.always_on_chars,
        "generation_hash": index.generation_hash,
    }


def _team_store_value(settings: Any, name: str, default: Any = None) -> Any:
    stores = getattr(settings, "knowledge_stores", None)
    if isinstance(stores, Mapping):
        team = stores.get("team")
    else:
        team = getattr(stores, "team", None) if stores is not None else None
    if isinstance(team, Mapping):
        return team.get(name, default)
    return getattr(team, name, default) if team is not None else default


def _team_store_enabled(settings: Any) -> bool:
    team = _team_store_value(settings, "enabled", None)
    # Settings uses a nullable descriptor for the feature gate.  A mapping
    # supplied by a test or a future loader may carry an explicit flag.
    stores = getattr(settings, "knowledge_stores", None)
    descriptor = stores.get("team") if isinstance(stores, Mapping) else getattr(stores, "team", None) if stores is not None else None
    return team is not False and descriptor is not None


def _team_root(settings: Any) -> Path | None:
    value = _team_store_value(settings, "root")
    if isinstance(value, (str, os.PathLike)) and str(value):
        return Path(value).expanduser()
    return None


def _team_store_id_hint(settings: Any, root: Path | None) -> str:
    value = _team_store_value(settings, "store_id")
    if isinstance(value, str) and value:
        return value
    manifest_path = Path(getattr(settings.paths, "install_manifest_path", ""))
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        document = {}
    stores = document.get("knowledge_stores", {}) if isinstance(document, Mapping) else {}
    team = stores.get("team") if isinstance(stores, Mapping) else None
    if isinstance(team, Mapping) and isinstance(team.get("store_id"), str):
        return str(team["store_id"])
    if root is not None:
        try:
            team_manifest = json.loads((root / "team-manifest.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            team_manifest = {}
        if isinstance(team_manifest, Mapping) and isinstance(team_manifest.get("store_id"), str):
            return str(team_manifest["store_id"])
    return ""


def _team_descriptor(settings: Any) -> tuple[Path | None, str, str | None]:
    """Return ``(root, store_id, issue)`` without exposing raw paths."""

    if not _team_store_enabled(settings):
        return None, "", "TEAM_DISABLED"
    root = _team_root(settings)
    if root is None:
        return None, "", "TEAM_ROOT_REQUIRED"
    store_id = _team_store_id_hint(settings, root)
    try:
        from .team_store import inspect_team_store

        descriptor = inspect_team_store(root, expected_store_id=store_id or None)
        store_id = descriptor.store_id
    except (OSError, TypeError, ValueError) as exc:
        code = _safe_code(str(exc), "TEAM_ROOT_UNAVAILABLE")
        if not root.is_dir() or code in {"TEAM_ROOT_INVALID", "TEAM_ROOT_UNAVAILABLE"}:
            return root, store_id, "TEAM_ROOT_UNAVAILABLE"
        return root, store_id, code
    return root, store_id, None


def _team_identity_issue_codes(root: Path) -> set[str]:
    """Detect ambiguous member slugs without returning member/writer values."""

    codes: set[str] = set()
    members = root / "members"
    try:
        if not members.is_dir():
            return codes
        for member in members.iterdir():
            if member.is_symlink() or not member.is_dir():
                continue
            writers = member / "writers"
            if not writers.is_dir() or writers.is_symlink():
                continue
            writer_ids = {
                child.name
                for child in writers.iterdir()
                if child.is_dir() and not child.is_symlink()
            }
            if len(writer_ids) > 1:
                codes.add("TEAM_MEMBER_ID_REUSED")
    except OSError:
        codes.add("TEAM_KNOWLEDGE_UNAVAILABLE")
    return codes


def _safe_issue_codes(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: set[str] = set()
    for item in value:
        raw = item.get("code", item.get("reason_code")) if isinstance(item, Mapping) else item
        code = _safe_code(raw, "TEAM_SCAN_ISSUE")
        result.add(code)
    return sorted(result)


def _team_projection_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        status = str(value.get("status", "UNAVAILABLE"))
        issues = _safe_issue_codes(value.get("issues", value.get("reason_codes", ())))
        accepted = value.get("accepted_event_count", 0)
        index = value.get("index")
    else:
        status = str(getattr(value, "status", "UNAVAILABLE"))
        issues = _safe_issue_codes(getattr(value, "issues", ()))
        accepted = getattr(value, "accepted_event_count", 0)
        index = getattr(value, "index", None)
    try:
        accepted_count = max(0, int(accepted or 0))
    except (TypeError, ValueError):
        accepted_count = 0
    active = candidates = observations = always_on = 0
    generation_hash = ""
    if index is not None:
        try:
            active = len(index.active_pattern_ids)
            candidates = len(getattr(index, "candidate_pattern_ids", ()))
            observations = int(index.observation_count)
            always_on = int(index.always_on_chars)
            generation_hash = str(index.generation_hash)
        except (AttributeError, TypeError, ValueError):
            index = None
    if status not in {"UPDATED", "UNCHANGED", "UNAVAILABLE", "DEFERRED", "READY"}:
        status = "UNAVAILABLE"
    return {
        "status": status,
        "accepted_event_count": accepted_count,
        "active_patterns": active,
        "candidate_patterns": candidates,
        "observations": observations,
        "always_on_chars": always_on,
        "generation_hash": generation_hash,
        "issue_codes": issues,
    }


def _team_outbox_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "FAILED", "reason_code": "TEAM_OUTBOX_RESULT_INVALID"}
    allowed = ("status", "attempted", "delivered", "deferred", "failed", "remaining")
    result: dict[str, Any] = {
        key: value.get(key, 0 if key != "status" else "EMPTY")
        for key in allowed
    }
    result["status"] = str(result["status"])
    for key in allowed[1:]:
        try:
            result[key] = max(0, int(result[key] or 0))
        except (TypeError, ValueError):
            result[key] = 0
    errors = value.get("errors", ())
    if not isinstance(errors, (list, tuple)):
        errors = ()
    result["errors"] = [
        {
            "receipt_id_hash": str(item.get("receipt_id_hash", "")),
            "reason_code": _safe_code(item.get("reason_code"), "TEAM_OUTBOX_FAILED"),
        }
        for item in errors
        if isinstance(item, Mapping)
    ][:100]
    if value.get("reason_code"):
        result["reason_code"] = _safe_code(value.get("reason_code"), "TEAM_OUTBOX_FAILED")
    return result


def _team_base_status(
    settings: Any,
    *,
    include_scan: bool = True,
) -> dict[str, Any]:
    if not _team_store_enabled(settings):
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    root, store_id, issue = _team_descriptor(settings)
    result: dict[str, Any] = {
        "status": "DEFERRED",
        "reason_code": "DEFERRED_TEAM_STORE",
        "store_id_hash": _hash(store_id) if store_id else "",
        "transport_managed": False,
        "access_control_verified": False,
        "active_patterns": 0,
        "candidate_patterns": 0,
        "observations": 0,
        "accepted_event_count": 0,
        "issue_codes": [],
    }
    if issue == "TEAM_DISABLED":
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    if issue is not None:
        result["issue_codes"] = [issue if issue != "TEAM_ROOT_UNAVAILABLE" else "TEAM_KNOWLEDGE_UNAVAILABLE"]
        if issue not in {"TEAM_ROOT_UNAVAILABLE", "TEAM_ROOT_REQUIRED"}:
            result["status"] = "BLOCKED"
            result["reason_code"] = issue
        return result
    if root is None or not store_id:
        result["issue_codes"] = ["TEAM_KNOWLEDGE_UNAVAILABLE"]
        return result
    if include_scan:
        try:
            from .team_store import scan_team_events

            scan = scan_team_events(root)
            result["accepted_event_count"] = len(scan.events)
            result["issue_codes"] = sorted(set(_safe_issue_codes(scan.issues)) | _team_identity_issue_codes(root))
        except (OSError, TypeError, ValueError, RuntimeError):
            result["issue_codes"] = ["TEAM_KNOWLEDGE_UNAVAILABLE"]
            return result
    try:
        from .team_projection import team_cache_paths

        paths = team_cache_paths(settings.paths.runtime_root, store_id)
        if paths.index_path.is_file():
            index = build_index(paths.knowledge_dir, paths.index_path)
            result.update({
                "active_patterns": len(index.active_pattern_ids),
                "candidate_patterns": len(getattr(index, "candidate_pattern_ids", ())),
                "observations": index.observation_count,
                "always_on_chars": index.always_on_chars,
                "generation_hash": index.generation_hash,
            })
        result["status"] = "READY"
        result.pop("reason_code", None)
    except (OSError, TypeError, ValueError):
        result["status"] = "DEFERRED"
        result["reason_code"] = "DEFERRED_TEAM_STORE"
    return result


def team_status_snapshot(settings: Any) -> dict[str, Any]:
    """Return a sanitized, read-only team store health view."""

    return _team_base_status(settings)


def _maintain_team(
    settings: Any,
    *,
    max_queue_items: int,
    now: datetime,
    started_clock: float,
    time_budget_ms: int,
    team_services: TeamServices | None,
) -> dict[str, Any]:
    if not _team_store_enabled(settings):
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    if _remaining_ms(started_clock, time_budget_ms) <= 0:
        return {"status": "DEFERRED", "reason_code": "DEFERRED_TEAM_STORE"}
    services: TeamServices = team_services or _DefaultTeamServices()
    try:
        outbox_value = services.drain_outbox(settings, max_items=max_queue_items, now=now)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        outbox_value = {"status": "FAILED", "reason_code": _safe_code(str(exc), "TEAM_OUTBOX_FAILED")}
    outbox = _team_outbox_summary(outbox_value)
    root, store_id, issue = _team_descriptor(settings)
    projection_value: Any = None
    if issue is None and root is not None and store_id and _remaining_ms(started_clock, time_budget_ms) > 0:
        try:
            projection_value = services.refresh_projection(root, settings.paths.runtime_root, store_id)
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            projection_value = {"status": "UNAVAILABLE", "reason_codes": [_safe_code(str(exc), "TEAM_KNOWLEDGE_UNAVAILABLE")]}
    projection = _team_projection_summary(projection_value) if projection_value is not None else {
        "status": "UNAVAILABLE",
        "accepted_event_count": 0,
        "active_patterns": 0,
        "candidate_patterns": 0,
        "observations": 0,
        "always_on_chars": 0,
        "generation_hash": "",
        "issue_codes": [],
    }
    base = _team_base_status(settings, include_scan=False)
    issue_codes = set(base.get("issue_codes", ())) | set(projection.get("issue_codes", ()))
    if issue is None and root is not None:
        issue_codes.update(_team_identity_issue_codes(root))
    if issue is not None:
        issue_codes.add(issue if issue != "TEAM_ROOT_UNAVAILABLE" else "TEAM_KNOWLEDGE_UNAVAILABLE")
    if outbox.get("status") == "FAILED" or int(outbox.get("failed", 0) or 0) > 0:
        issue_codes.add(str(outbox.get("reason_code") or "TEAM_OUTBOX_FAILED"))
    unavailable = (
        issue is not None
        or projection.get("status") == "UNAVAILABLE"
        or outbox.get("status") == "DEFERRED"
    )
    blocked = (
        any(code in {"TEAM_STORE_ID_MISMATCH", "TEAM_ROOT_CONTRACT_INVALID", "TEAM_STORE_MANIFEST_INVALID"} for code in issue_codes)
        or outbox.get("status") == "FAILED"
        or int(outbox.get("failed", 0) or 0) > 0
    )
    status = "BLOCKED" if blocked else "DEFERRED" if unavailable else "READY"
    structural_reason = next(
        (code for code in sorted(issue_codes) if code in {"TEAM_STORE_ID_MISMATCH", "TEAM_ROOT_CONTRACT_INVALID", "TEAM_STORE_MANIFEST_INVALID"}),
        None,
    )
    result = {
        "status": status,
        "reason_code": "DEFERRED_TEAM_STORE" if status == "DEFERRED" else "TEAM_OUTBOX_FAILED" if status == "BLOCKED" and outbox.get("status") == "FAILED" else structural_reason if status == "BLOCKED" else None,
        "store_id_hash": base.get("store_id_hash", ""),
        "outbox": outbox,
        "projection": projection,
        "active_patterns": projection.get("active_patterns", 0),
        "candidate_patterns": projection.get("candidate_patterns", 0),
        "accepted_event_count": projection.get("accepted_event_count", 0),
        "issue_codes": sorted(code for code in issue_codes if code),
        "transport_managed": False,
        "access_control_verified": False,
    }
    if result["reason_code"] is None:
        result.pop("reason_code")
    return result


def _capture_summary(events: Sequence[Event]) -> dict[str, Any]:
    direct = sum(1 for event in events if event.event_type == "observation.recorded" and event.payload.get("capture_path") == "agent_direct")
    native = sum(1 for event in events if event.event_type == "observation.recorded" and event.payload.get("capture_path") != "agent_direct")
    return {
        "direct_count": direct,
        "native_count": native,
        "primary": "agent_direct" if direct else "native_or_fallback" if native else "unknown",
        "coverage_unknown": not bool(direct or native),
    }
def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _metric_summary(settings: Any) -> dict[str, Any]:
    try:
        from .metrics import collect_local_metrics
        return collect_local_metrics(settings.paths.codex_home, settings.paths.metrics_dir).to_dict()
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "unknown", "source_status": "unknown", "error_code": _safe_code(str(exc))}


def run_maintenance(
    settings: Any,
    *,
    source_paths: Sequence[Path] | None = None,
    provider: Any | None = None,
    max_queue_items: int = 100,
    time_budget_ms: int = 30000,
    sync_policy: str = "disabled",
    now: datetime | None = None,
    orphan_host_id: str | None = None,
    adapters: Iterable[Any] | None = None,
    team_services: TeamServices | None = None,
) -> MaintenanceResult:
    if sync_policy not in _ALLOWED_SYNC_POLICIES:
        raise ValueError("SYNC_POLICY_INVALID")
    max_queue_items = _bounded_int(max_queue_items, "MAX_QUEUE_ITEMS", 1, 10000)
    time_budget_ms = _bounded_int(time_budget_ms, "TIME_BUDGET_MS", 1, 600000)
    started_clock = time.monotonic()
    moment = _utc(now)
    started_at = _iso(moment)
    errors: list[Mapping[str, Any]] = []
    source_count = created = skipped = parse_skipped = rejected = 0
    ingest_results_list: list[Mapping[str, Any]] = []

    if adapters is not None:
        adapter_values = tuple(adapters)
        for adapter in adapter_values:
            try:
                result = ingest_sources(settings, [adapter])
                source_count += 1
                created += result.created_events
                skipped += result.skipped_records
                parse_skipped += result.parse_skipped
                rejected += result.rejected_records
                row = {
                    "status": "partial" if result.parse_skipped or result.rejected_records else "success",
                    "created_events": result.created_events,
                    "skipped_records": result.skipped_records,
                    "parse_skipped": result.parse_skipped,
                    "rejected_records": result.rejected_records,
                    "health": dict(result.health),
                }
                ingest_results_list.append(row)
                if result.parse_skipped or result.rejected_records:
                    errors.append({"stage": "ingest", "error_code": "SOURCE_PARTIAL"})
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                source_count += 1
                reason = _safe_code(str(exc))
                ingest_results_list.append({"status": "failed", "error_code": reason})
                errors.append({"stage": "ingest", "error_code": reason})
    else:
        try:
            source_count, created, skipped, parse_skipped, rejected, rows = _ingest(settings, source_paths, errors)
            ingest_results_list.extend(rows)
        except (OSError, ValueError, TypeError) as exc:
            errors.append({"stage": "source_discovery", "error_code": _safe_code(str(exc))})

    expired = 0
    try:
        expired = gc_expired_spool(settings, now=moment)
    except (OSError, SpoolError, ValueError) as exc:
        errors.append({"stage": "spool_gc", "error_code": _safe_code(str(exc))})

    recovery_result = RecoveryResult(0, 0, 0, False)
    if orphan_host_id:
        try:
            recovery_result = reconcile_orphans(orphan_host_id, None, settings)
        except (OSError, ValueError, TypeError) as exc:
            errors.append({"stage": "orphan_recovery", "error_code": _safe_code(str(exc))})

    remaining_budget = max(1, _remaining_ms(started_clock, time_budget_ms))
    try:
        queue_result = drain_queue(
            settings, provider=provider, max_items=max_queue_items,
            time_budget_ms=remaining_budget, now=moment,
        )
        errors.extend(queue_result.errors)
    except (OSError, QueueError, ValueError, TypeError, RuntimeError) as exc:
        reason = _safe_code(str(exc), "QUEUE_DRAIN_FAILED")
        errors.append({"stage": "queue_drain", "error_code": reason})
        queue_result = QueueDrainResult(
            "partial", 0, 0, 0, 0, 0, 1, -1, 0,
            errors=({"stage": "queue_drain", "error_code": reason},),
        )

    lifecycle_result = ReconciliationResult(0, 0, 0, 0, 0, 0, 0, 0)
    projection: KnowledgeIndex | None = None
    events: list[Event] = []
    try:
        events = _events(settings)
        lifecycle_result = reconcile_lifecycle(events, settings.paths.event_dir, now_utc=moment)
        events = _events(settings)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        errors.append({"stage": "lifecycle", "error_code": _safe_code(str(exc))})
    try:
        events = _events(settings)
        projection = project_events(events, settings.paths.knowledge_dir)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        errors.append({"stage": "projection", "error_code": _safe_code(str(exc))})

    try:
        raw_policy = json.loads(Path(settings.promotion_policy_path).read_text(encoding="utf-8"))
        policy = PromotionPolicy(**{
            field_name: raw_policy[field_name]
            for field_name in PromotionPolicy.__dataclass_fields__
            if isinstance(raw_policy, Mapping) and field_name in raw_policy
        })
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        policy = PromotionPolicy.defaults()
    if projection is not None:
        try:
            _quality_audits(settings, lifecycle_result, projection, policy)
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            errors.append({"stage": "quality_audit", "error_code": _safe_code(str(exc))})

    # Team work is deliberately after all personal work.  A shared-folder
    # outage or a slow projection must never turn a successful personal
    # maintenance run into a failed run, and the deadline gate prevents any
    # team I/O once the personal budget is exhausted.
    team_result = _maintain_team(
        settings,
        max_queue_items=max_queue_items,
        now=moment,
        started_clock=started_clock,
        time_budget_ms=time_budget_ms,
        team_services=team_services,
    )
    personal_summary = _knowledge_summary(projection)
    from .reconciliation import candidate_diagnostics

    try:
        personal_summary["candidate_diagnostics"] = list(candidate_diagnostics(events))
    except (ValueError, TypeError, RuntimeError) as exc:
        errors.append({"stage": "candidate_diagnostics", "error_code": _safe_code(str(exc), "CANDIDATE_DIAGNOSTICS_UNAVAILABLE")})
    if projection is not None:
        from .projection_state import projection_freshness_report

        try:
            freshness = projection_freshness_report(projection.index_path, _events(settings))
            personal_summary.update(freshness)
            if freshness["freshness"] != "CURRENT":
                errors.append({"stage": "projection", "error_code": freshness["reason_code"]})
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            personal_summary["freshness"] = "UNKNOWN"
            errors.append({"stage": "projection", "error_code": _safe_code(str(exc), "PROJECTION_CHECK_FAILED")})

    sync_result: Mapping[str, Any] = {
        "requested": sync_policy == "auto", "policy": sync_policy, "status": "not_requested",
    }
    if sync_policy == "auto":
        if errors:
            sync_result = {
                "requested": True, "policy": sync_policy, "status": "blocked",
                "reason_code": "PRE_SYNC_CHECKS_FAILED",
            }
        else:
            try:
                value: SyncResult = sync_once(settings)
                sync_result = {
                    "requested": True, "policy": sync_policy,
                    "status": "success" if value.ok else "blocked",
                    **value.to_dict(),
                }
                if not value.ok:
                    errors.append({"stage": "sync", "error_code": _safe_code(value.reason_code)})
            except (OSError, ValueError, RuntimeError) as exc:
                reason = _safe_code(str(exc))
                sync_result = {
                    "requested": True, "policy": sync_policy,
                    "status": "blocked", "reason_code": reason,
                }
                errors.append({"stage": "sync", "error_code": reason})

    try:
        capture = _capture_summary(events)
    except (OSError, ValueError, TypeError):
        capture = {"direct_count": 0, "native_count": 0, "primary": "unknown", "coverage_unknown": True}
    metrics = _metric_summary(settings)
    recovery_summary = recovery_result.to_dict()
    queue_mapping = queue_result.to_dict()
    try:
        spool_mapping = spool_health(settings).to_dict()
    except (OSError, SpoolError, ValueError, RuntimeError) as exc:
        spool_mapping = {"status": "unavailable", "error_code": _safe_code(str(exc), "SPOOL_HEALTH_UNAVAILABLE")}
        errors.append({"stage": "spool_health", "error_code": spool_mapping["error_code"]})
    lifecycle_mapping = {
        "created_events": lifecycle_result.created_events,
        "candidate_events": lifecycle_result.candidate_events,
        "promotion_events": lifecycle_result.promotion_events,
        "revision_events": lifecycle_result.revision_events,
        "deprecation_events": lifecycle_result.deprecation_events,
        "tombstone_events": lifecycle_result.tombstone_events,
        "duplicate_observations": lifecycle_result.duplicate_observations,
        "cluster_count": lifecycle_result.cluster_count,
    }
    health = {
        "status": "partial" if errors or team_result.get("status") == "BLOCKED" else "success",
        "queue": queue_mapping,
        "spool": spool_mapping,
        "capture": capture,
        "recovery": recovery_summary,
        "projection": personal_summary,
        "knowledge_stores": {
            "personal": personal_summary,
            "team": dict(team_result),
        },
        "sync": dict(sync_result),
        "errors": [dict(item) for item in errors],
        "recorded_at": _iso(),
    }
    try:
        _write_json(Path(settings.paths.runtime_dir) / "health.json", health)
    except (OSError, ValueError, TypeError) as exc:
        errors.append({"stage": "health", "error_code": _safe_code(str(exc))})
    finished_at = _iso()
    elapsed = int((time.monotonic() - started_clock) * 1000)
    status = "partial" if errors or queue_result.status == "partial" or team_result.get("status") == "BLOCKED" else "success"
    blocked = _safe_code(errors[0].get("error_code")) if errors else _safe_code(team_result.get("reason_code")) if team_result.get("status") == "BLOCKED" else None
    return MaintenanceResult(
        status, started_at, finished_at, elapsed, source_count, created, skipped,
        parse_skipped, rejected, tuple(ingest_results_list), queue_result.recovered_emergency,
        expired, queue_mapping, capture, recovery_summary, lifecycle_mapping,
        personal_summary, metrics, dict(sync_result), tuple(errors), blocked,
        personal_summary, team_result,
    )


maintain = run_maintenance


__all__ = [
    "MaintenanceError", "MaintenanceResult", "QueueDrainResult", "TeamServices",
    "drain_queue", "maintain", "process_failure", "run_maintenance", "team_status_snapshot",
]
