from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
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
from .inference.budget import BudgetLedger, BudgetLockError, BudgetPolicy
from .inference.router import ProviderRouter, ProviderSelectionError
from .ingest import ingest_sources
from .journal import append_event, iter_events
from .models import Event, KnowledgeIndex, PromotionPolicy
from .persistable_fields import is_privacy_or_safety_violation
from .project import project_events
from .queue import QueueError, QueueItem, QueueState, attach_validated_result, claim_queue_item, list_queue_items, read_queue_item, recover_emergency_spool, transition_queue_item
from .organizer_recovery import OrganizerRecovery, load_validated_result, save_validated_result, next_retry
from .reconciliation import ReconciliationResult, reconcile_lifecycle
from .recovery import RecoveryResult, reconcile_orphans
from .spool import SpoolError, gc_expired_spool, read_spool, spool_health
from .sync import SyncResult, sync_once
from .operation_runtime import OperationBudget, _read_json
from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory


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
        budget=None,
    ) -> Mapping[str, Any]:
        ...

    def refresh_projection(
        self,
        shared_root: Path,
        runtime_root: Path,
        store_id: str,
        *, budget=None,
    ) -> Any:
        ...


class _DefaultTeamServices:
    def drain_outbox(
        self,
        settings: Any,
        *,
        max_items: int,
        now: datetime | None,
        budget=None,
    ) -> Mapping[str, Any]:
        from .team_outbox import drain_team_outbox

        return drain_team_outbox(settings, max_items=max_items, now=now, budget=budget)

    def refresh_projection(
        self,
        shared_root: Path,
        runtime_root: Path,
        store_id: str,
        *, budget=None,
    ) -> Any:
        from .team_projection import refresh_team_projection

        return refresh_team_projection(shared_root, runtime_root, store_id, budget=budget)


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
    provider_state: Mapping[str, Any] = field(default_factory=dict)
    provider_verified_success: bool = False

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
    operation: Mapping[str, Any] = field(default_factory=dict)

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
            "operation": dict(self.operation),
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
        self.admission_refused = False
        self.provider_id = "provider-router"
        if router.organizer.provider_id:
            self.provider_id = router.organizer.provider_id

    def available(self) -> bool:
        # Selection and provider availability are distinct states.  Calling
        # ``generate`` on the selected provider lets it return a bounded
        # disabled/quota/auth/timeout result without trying another provider.
        return self.router.organizer.status in {"READY", "SELECTION_REQUIRED"}

    def generate(self, schema_name: str, input_json: Mapping[str, Any], budget: InferenceBudget | Mapping[str, Any] | None) -> ProviderResult:
        self.admission_refused = False
        result = self.router.generate("inheritance-gate", schema_name, input_json, InferenceBudget.from_value(budget))
        self.admission_refused = result.admission_refused
        return result


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


def _events(settings: Any, *, budget=None) -> list[Event]:
    root = Path(settings.paths.event_dir)
    if budget is not None:
        budget.check()
    return list(iter_events(root, budget=budget)) if root.exists() else []


def _event_by_id(settings: Any, event_id: str, *, budget=None) -> Event | None:
    return next((event for event in _events(settings, budget=budget) if event.event_id == event_id), None) if event_id else None


def _candidate_for(item: QueueItem, settings: Any, now: datetime | None = None, *, budget=None) -> dict[str, Any]:
    if item.payload_ref is not None:
        if item.payload_ref.purpose == "pending" and not item.capture_id:
            raise MaintenanceError("QUEUE_CAPTURE_BINDING_REQUIRED")
        try:
            raw = read_spool(item.payload_ref, settings, now=now,
                expected_capture_id=item.capture_id if item.payload_ref.purpose == "pending" else None, budget=budget)
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
        event = _event_by_id(settings, item.event_id, budget=budget)
        if event is None or event.event_type != "observation.recorded":
            raise MaintenanceError("METADATA_ONLY_CAPTURE")
        candidate = dict(event.payload)
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


def _budget_ledger(settings, budget=None):
    if budget is None:
        return BudgetLedger(settings)
    budget.check()
    policy_path = Path(settings.budget_policy_path)
    policy = BudgetPolicy.from_mapping(_read_json(policy_path, max_bytes=65536, budget=budget)) if policy_path.exists() else BudgetPolicy()
    return BudgetLedger(settings, policy=policy, operation_budget=budget)


def _provider_for(settings: Any, provider: Any | None, *, budget=None) -> Any:
    if provider is not None:
        return provider
    config = None
    if budget is not None:
        try:
            config = _read_json(Path(settings.paths.engine_root) / "config/inference-providers.json", max_bytes=262144, budget=budget)
        except TimeoutError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            return _UnavailableAdapter("INFERENCE_PROVIDER_CONFIG_READ_FAILED")
        except ValueError as exc:
            reason = "INFERENCE_PROVIDER_CONFIG_INVALID" if str(exc) == "OPERATION_CACHE_INVALID" else "INFERENCE_PROVIDER_CONFIG_READ_FAILED"
            return _UnavailableAdapter(reason)
        if config is None:
            return _UnavailableAdapter("INFERENCE_PROVIDER_CONFIG_READ_FAILED")
    try:
        return _RouterAdapter(ProviderRouter(settings=settings, provider_config=config, budget_ledger=_budget_ledger(settings, budget)))
    except TimeoutError:
        raise
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
    budget=None,
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
        return transition_queue_item(item, target, settings, now=moment, reason_code=reason, next_eligible_at=next_at, budget=budget)
    return replace(
        item,
        state=target,
        next_eligible_at=_iso(next_at) if next_at else None,
        lease_owner=None,
        lease_expires_at=None,
        last_error_code=reason,
    )


def _apply_processing_decision(decision: GateDecision, item: QueueItem, settings: Any, now: datetime, *, budget=None) -> tuple[str, QueueItem]:
    reason = _safe_code(decision.reason_code, "PROCESSING_FAILED")
    if decision.decision == "NO":
        applied = apply_gate_decision(decision, item, settings, budget=budget)
        return "discarded", applied.queue_item
    if decision.decision == "DEFERRED":
        updated = transition_queue_item(
            item,
            QueueState.DEFERRED,
            settings,
            now=now,
            reason_code=reason,
            next_eligible_at=decision.next_eligible_at or now + timedelta(seconds=300),
            budget=budget,
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
                budget=budget,
            )
            return "deferred", updated
        return "failed", process_failure(item, reason, now=now, settings=settings, budget=budget)
    applied = apply_gate_decision(decision, item, settings, budget=budget)
    return "curating", applied.queue_item


def _index_or_none(settings: Any, *, budget=None) -> KnowledgeIndex | None:
    root = Path(settings.paths.knowledge_dir)
    path = root / "index.json"
    return build_index(root, path, budget=budget) if path.is_file() else None


def _process_claimed(item: QueueItem, settings: Any, provider: Any, now: datetime, *, maintenance_remaining_ms: int = 120000, run_id: str = "", budget=None, evidence=None) -> tuple[str, QueueItem]:
    started = time.monotonic()
    if budget is not None:
        budget.check()
    candidate = _candidate_for(item, settings, now=now, budget=budget)
    provider_id = getattr(provider, "provider_id", "provider-router")
    cached = load_validated_result(item, candidate, provider_id, settings, now, budget=budget)
    if cached is not None:
        decision, changeset = cached
        if decision.decision == "NO":
            return _apply_processing_decision(decision, item, settings, now, budget=budget)
        return _finish_changeset(changeset, item, settings, now, budget=budget)
    policy = _budget_ledger(settings, budget).policy
    deadline = min(policy.deadline_ms, maintenance_remaining_ms, budget.remaining_ms() if budget is not None else maintenance_remaining_ms)
    if deadline <= 0:
        return _apply_processing_decision(_deferred(candidate, "DEADLINE_EXCEEDED", now), item, settings, now, budget=budget)
    try:
        organizer = getattr(settings, "organizer", None)
        if getattr(organizer, "status", None) == "SELECTION_REQUIRED":
            # Setup has not selected an organizer yet.  Keep the candidate in
            # the queue without entering the gate or invoking an injected
            # test/provider adapter.
            decision = _deferred(candidate, "ORGANIZER_SELECTION_REQUIRED", now)
        else:
            # Evidence belongs to this gate operation only, including a gate
            # that exits without generate. Do not reuse the caller's adapter.
            gate_provider = _RouterAdapter(provider.router) if isinstance(provider, _RouterAdapter) else provider
            def infer() -> GateDecision:
                remaining = min(policy.deadline_ms, _remaining_ms(started, maintenance_remaining_ms), budget.remaining_ms() if budget is not None else maintenance_remaining_ms)
                if remaining <= 0:
                    return _deferred(candidate, "DEADLINE_EXCEEDED", now)
                availability = getattr(provider, "available", None)
                unavailable = (not availability()) if callable(availability) else (availability is False)
                if availability is not None and unavailable:
                    return _deferred(candidate, _safe_code(getattr(provider, "reason_code", None), "NO_PROVIDER_AVAILABLE"), now)
                inference_budget = InferenceBudget(
                    candidate_id=item.queue_id,
                    purpose="inheritance-gate",
                    deadline_ms=remaining,
                    max_input_tokens=min(policy.per_candidate_input_tokens, policy.per_run_input_tokens),
                    max_output_tokens=min(policy.per_candidate_output_tokens, policy.per_run_output_tokens),
                    max_cost=min(policy.per_candidate_cost, policy.per_run_cost),
                    run_id=run_id,
                    attempt_id=uuid.uuid4().hex,
                )
                result = decide_inheritance(candidate, gate_provider, inference_budget)
                if evidence is not None and result.semantic:
                    evidence["provider_verified_success"] = True
                return result
            retry_provider = provider
            recovery_fingerprint = ""
            if isinstance(provider, _RouterAdapter):
                retry_provider = provider.router.selected()
                recovery_fingerprint = "sha256:" + stable_hash({
                    "organizer": provider.router.organizer.to_dict(), "config": provider.router.config,
                })
            recovery = OrganizerRecovery(Path(settings.paths.runtime_dir) / ("organizer-" + stable_hash(provider_id) + ".json"), provider_id,
                malformed_limit=getattr(settings, "curation_max_attempts", 3),
                config_fingerprint=recovery_fingerprint, operation_budget=budget)
            decision = recovery.run(infer, now, admission_refused=lambda:
                isinstance(gate_provider, _RouterAdapter) and gate_provider.admission_refused,
                retry_provider=retry_provider)
    except ProviderSelectionError as exc:
        decision = _deferred(candidate, exc.reason_code, now)
    if decision.decision in {"FAILED", "DEFERRED"}:
        # Provider exhaustion does not terminate the candidate's TTL window.
        decision = replace(decision, decision="DEFERRED", next_eligible_at=decision.next_eligible_at or next_retry(now, max(1, item.attempts)))
        return _apply_processing_decision(decision, item, settings, now, budget=budget)
    if decision.decision == "NO":
        ref = save_validated_result(item, candidate, provider_id, decision, None, settings, now, budget=budget)
        current = attach_validated_result(item, ref, settings, budget=budget)
        return _apply_processing_decision(decision, current, settings, now, budget=budget)

    index = _index_or_none(settings, budget=budget)
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
        index, {"provider_id": provider_id}, None, operation_budget=budget,
    )
    validation = validate_changeset(changeset, settings, budget=budget)
    if not validation.valid:
        reason = _safe_code(validation.reason_codes[0] if validation.reason_codes else "CHANGESET_INVALID")
        return "failed", process_failure(item, reason, now=now, settings=settings, budget=budget)
    ref = save_validated_result(item, candidate, provider_id, decision, changeset, settings, now, budget=budget)
    current = attach_validated_result(item, ref, settings, budget=budget)
    _, current = _apply_processing_decision(decision, current, settings, now, budget=budget)
    return _finish_changeset(changeset, current, settings, now, budget=budget)


def _finish_changeset(changeset: Any, current: QueueItem, settings: Any, now: datetime, *, budget=None) -> tuple[str, QueueItem]:
    existing = _events(settings, budget=budget)
    marker = next((event for event in existing if event.event_type == "curation.changeset.applied" and event.payload.get("changeset_id") == changeset.changeset_id), None)
    if marker is not None and marker.payload.get("changeset_hash") != changeset.fingerprint:
        raise MaintenanceError("VALIDATED_RESULT_JOURNAL_MISMATCH")
    applied = apply_changeset(changeset, settings, budget=budget)
    if not applied.applied:
        reason = _safe_code(applied.reason_code, "CHANGESET_INVALID")
        if reason in {"OSError", "PermissionError", "FileNotFoundError", "TimeoutError"}:
            return "deferred", transition_queue_item(current, QueueState.DEFERRED, settings, now=now,
                reason_code=reason, next_eligible_at=next_retry(now, max(1, current.attempts)), budget=budget)
        return "failed", process_failure(current, reason, now=now, settings=settings, budget=budget)
    project_events(_events(settings, budget=budget), settings.paths.knowledge_dir, budget=budget)
    current = transition_queue_item(current, QueueState.DONE, settings, now=now, reason_code="CURATION_APPLIED", budget=budget)
    return "completed", current
def drain_queue(
    settings: Any,
    *,
    provider: Any | None = None,
    max_items: int = 100,
    time_budget_ms: int = 5000,
    now: datetime | None = None,
    worker_id: str | None = None,
    run_id: str | None = None,
    budget=None,
) -> QueueDrainResult:
    max_items = _bounded_int(max_items, "MAX_ITEMS", 1, 10000)
    time_budget_ms = _bounded_int(time_budget_ms, "TIME_BUDGET_MS", 1, 600000)
    moment = _utc(now)
    started = time.monotonic()
    budget = budget if budget is not None else OperationBudget(time_budget_ms)
    if budget.remaining_ms() <= 0:
        return QueueDrainResult("partial", 0, 0, 0, 0, 0, 0, -1, 0,
            errors=({"stage": "queue_drain", "error_code": "OPERATION_BUDGET_EXHAUSTED"},))
    worker = worker_id or f"maintainer-{os.getpid()}"
    maintenance_run = run_id or uuid.uuid4().hex
    errors: list[Mapping[str, Any]] = []
    try:
        recovered = len(recover_emergency_spool(settings, now=moment, budget=budget))
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
        selected_provider = _provider_for(settings, provider, budget=budget)
    provider_id = getattr(selected_provider, "provider_id", "provider-router")
    recovery = OrganizerRecovery(Path(settings.paths.runtime_dir) / ("organizer-" + stable_hash(provider_id) + ".json"), provider_id,
        malformed_limit=getattr(settings, "curation_max_attempts", 3), operation_budget=budget)
    if isinstance(selected_provider, _RouterAdapter):
        try:
            actual = selected_provider.router.selected()
            # Hash trusted parsed configuration; never persist its values.
            fingerprint = "sha256:" + stable_hash({"organizer": selected_provider.router.organizer.to_dict(), "config": selected_provider.router.config})
            recovery.recover(actual, config_fingerprint=fingerprint)
        except ProviderSelectionError as exc:
            errors.append({"stage": "organizer_selection", "error_code": _safe_code(str(exc), "ORGANIZER_SELECTION_UNAVAILABLE")})
    evidence = {}
    attempted = processed = completed = discarded = deferred = failed = 0
    completed_ids: list[str] = []
    deferred_ids: list[str] = []
    failed_ids: list[str] = []
    while attempted < max_items and budget.remaining_ms() > 0:
        try:
            item = claim_queue_item(
                worker, settings, now=moment,
                lease_seconds=max(1, min(300, time_budget_ms // 1000 or 1)),
                budget=budget,
            )
        except (OSError, QueueError, ValueError) as exc:
            errors.append({"stage": "claim", "error_code": _safe_code(str(exc))})
            break
        if item is None:
            break
        attempted += 1
        try:
            outcome, updated = _process_claimed(item, settings, selected_provider, moment,
                maintenance_remaining_ms=budget.remaining_ms(), run_id=maintenance_run, budget=budget, evidence=evidence)
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
        except (OSError, SpoolError, BudgetLockError, QueueError, MaintenanceError, ValueError, TypeError) as exc:
            failed += 1
            failed_ids.append(item.queue_id)
            reason = _safe_code(str(exc))
            errors.append({"stage": "item", "queue_id_hash": _hash(item.queue_id), "error_code": reason})
            try:
                persisted = read_queue_item(item.queue_id, settings, budget=budget)
                if persisted.state in {QueueState.DONE, QueueState.NO_DISCARDED}:
                    # The terminal decision is already durable; a cleanup
                    # failure must not turn completed work back into retryable
                    # inference or block unrelated candidates.
                    continue
                if reason in _RETRYABLE_PROVIDER_CODES or reason in {"METADATA_ONLY_CAPTURE", "JOURNAL_BOUNDED_LIMIT", "PROJECTION_STORAGE_LIMIT", "PROJECTION_GENERATION_UNOWNED", "PROJECTION_GENERATION_CONFLICT"} or isinstance(exc, (OSError, SpoolError, BudgetLockError)):
                    transition_queue_item(
                        item,
                        QueueState.DEFERRED,
                        settings,
                        now=moment,
                        reason_code=reason,
                        next_eligible_at=next_retry(moment, max(1, item.attempts)),
                        budget=budget,
                    )
                elif is_privacy_or_safety_violation(reason):
                    transition_queue_item(item, QueueState.QUARANTINED, settings, now=moment, reason_code=reason, budget=budget)
                else:
                    process_failure(item, reason, now=moment, settings=settings, budget=budget)
            except (OSError, QueueError, ValueError) as transition_error:
                errors.append({
                    "stage": "transition", "queue_id_hash": _hash(item.queue_id),
                    "error_code": _safe_code(str(transition_error)),
                })
    try:
        from .queue import _catalog, _read_item, _TERMINAL, _root
        catalog = _catalog(_root(settings), budget=budget)
        count, _ = catalog.capacity("queue", budget=budget)
        page = catalog.page("maintenance-health", limit=64, budget=budget, advance=False)
        rows = [_read_item(path, budget=budget) for path in page.paths]
        remaining = sum(item.state not in _TERMINAL for item in rows) if page.complete and len(rows) == count else -1
    except (OSError, QueueError, ValueError):
        remaining = -1
        errors.append({"stage": "health", "error_code": "QUEUE_HEALTH_UNAVAILABLE"})
    elapsed = int((time.monotonic() - started) * 1000)
    status = "partial" if errors or remaining < 0 or budget.remaining_ms() == 0 else "success"
    provider_state = {}
    if budget.remaining_ms() > 0:
        try:
            provider_state = recovery.snapshot()
        except (OSError, ValueError, RuntimeError):
            errors.append({"stage": "organizer_state", "error_code": "ORGANIZER_STATE_UNAVAILABLE"})
    return QueueDrainResult(
        status, attempted, processed, completed, discarded, deferred, failed, remaining,
        recovered, tuple(completed_ids), tuple(deferred_ids), tuple(failed_ids),
        tuple(errors), elapsed, provider_state, evidence.get("provider_verified_success", False),
    )


def _adapter(path: Path) -> Any:
    if path.suffix.casefold() == ".md":
        from .adapters.codex_memory import CodexMemoryAdapter
        return CodexMemoryAdapter([path])
    if path.suffix.casefold() == ".jsonl":
        from .adapters.rollout_summary import RolloutSummaryAdapter
        return RolloutSummaryAdapter([path])
    raise ValueError("UNSUPPORTED_SOURCE_FORMAT")


def _ingest(settings: Any, source_paths: Sequence[Path] | None, errors: list[Mapping[str, Any]], *, now, budget, adapters=None) -> tuple[int, int, int, int, int, tuple[Mapping[str, Any], ...]]:
    from .capture_recovery import RecoverySource, recover_page
    from .operation_runtime import capture_namespace
    from .adapters.codex_memory import CodexMemoryAdapter
    from .adapters.rollout_summary import RolloutSummaryAdapter
    from .adapters.claude import ClaudeAdapter
    from .adapters.gemini import GeminiAdapter
    from .adapters.qwen import QwenAdapter
    verified_types = {CodexMemoryAdapter, RolloutSummaryAdapter, ClaudeAdapter, GeminiAdapter, QwenAdapter}
    def selections():
        if adapters is not None:
            for adapter in adapters:
                budget.check()
                if type(adapter) not in verified_types:
                    yield None, adapter
                else:
                    for path in adapter.sources:
                        budget.check()
                        yield Path(path), adapter
            return
        values = source_paths
        if values is None:
            default = Path(settings.paths.codex_home) / "memories"
            budget.check()
            values = (default,) if default.exists() else ()
        for raw in values:
            budget.check()
            path = Path(raw).expanduser().absolute()
            if path.suffix.casefold() in {".md", ".jsonl"} or path.is_file():
                yield path, _adapter(path)
            else:
                for adapter_type in (CodexMemoryAdapter, RolloutSummaryAdapter):
                    yield path, adapter_type([])
    results: list[Mapping[str, Any]] = []
    created = skipped = parse_skipped = rejected = 0
    for path, adapter in selections():
        budget.check()
        source_id = _hash("maintenance-" + stable_hash([getattr(adapter, "host_id", "unknown"), str(path)]))
        try:
            if path is None:
                raise ValueError("SOURCE_ENUMERATION_UNVERIFIED")
            assert_safe_target(path.parent, path, allow_missing=True)
            if not path.exists():
                results.append({"source_id_hash": source_id, "status": "failed", "source_available": False, "reason_code": "SOURCE_ENTRY_MISSING"})
                errors.append({"stage": "ingest", "source_id_hash": source_id, "error_code": "SOURCE_ENTRY_MISSING"})
                continue
            namespace = capture_namespace(settings, adapter.host_id, budget=budget)
            source = RecoverySource("maintenance-" + stable_hash([adapter.host_id, str(path)]), adapter.host_id,
                *(namespace or (None, None)), path, adapter, enumeration_verified=True)
            result = recover_page(settings, source, now=now, max_records=64,
                max_ms=budget.remaining_ms(), budget=budget)
            created += result.created_events
            rejected += result.rejected
            parse_skipped += int(getattr(adapter, "parse_skipped", 0))
            row = {
                "source_kind": adapter.capture_path,
                "source_id_hash": _hash(source.source_id),
                "status": "success" if result.reason_code == "SOURCE_CORRELATION_UNKNOWN" and not result.rejected and not getattr(adapter, "parse_skipped", 0) else "partial",
                "created_events": result.created_events,
                "scanned": result.scanned, "secured": result.secured,
                "parse_skipped": int(getattr(adapter, "parse_skipped", 0)),
                "rejected_records": result.rejected, "coverage": result.coverage,
                "reason_code": result.reason_code,
                "source_available": True if result.reason_code == "SOURCE_CORRELATION_UNKNOWN" else None,
            }
            results.append(row)
            if row["status"] == "partial":
                errors.append({"stage": "ingest", "source_id_hash": row["source_id_hash"], "error_code": result.reason_code if result.reason_code != "SOURCE_CORRELATION_UNKNOWN" else "SOURCE_PARTIAL"})
        except TimeoutError:
            raise
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            results.append({"source_id_hash": source_id, "status": "failed", "error_code": _safe_code(str(exc), "SOURCE_READ_UNAVAILABLE")})
            errors.append({"stage": "ingest", "source_id_hash": source_id, "error_code": _safe_code(str(exc), "SOURCE_READ_UNAVAILABLE")})
    return len(results), created, skipped, parse_skipped, rejected, tuple(results)


def _append_audit(
    settings: Any,
    action: str,
    target: str,
    reason: str,
    old_version: int = 0,
    new_version: int = 0,
    changeset_hash: str = "",
    *, budget=None,
) -> None:
    if budget is not None:
        budget.check()
    policy_version = "promotion-v1"
    try:
        value = _read_json(Path(settings.promotion_policy_path), max_bytes=65536, budget=budget)
        if isinstance(value, Mapping) and isinstance(value.get("policy_version"), str):
            policy_version = value["policy_version"]
    except TimeoutError:
        raise
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
    if _event_by_id(settings, event_id, budget=budget) is not None:
        return
    event = Event.create(
        "maintenance.audit",
        _iso(),
        "maintainer",
        machine_id(),
        payload,
        event_id=event_id,
    )
    append_event(event, settings.paths.event_dir, budget=budget)


def _quality_audits(settings: Any, reconciliation: ReconciliationResult, projection: KnowledgeIndex | None, policy: PromotionPolicy, *, budget=None) -> None:
    if budget is not None:
        budget.check()
    if reconciliation.duplicate_observations:
        _append_audit(settings, "DUPLICATE_OBSERVATION", "duplicate", "DUPLICATE_OBSERVATION", budget=budget)
    if projection is None:
        return
    try:
        item_ids = list(projection.active_pattern_ids) + list(projection.archive_pattern_ids)
        items = read_index_items(projection, item_ids, budget=budget)
    except TimeoutError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        return
    for item in items:
        if budget is not None:
            budget.check()
        pattern_id = str(item.get("pattern_id", item.get("item_id", "")))
        if str(item.get("status", "")) == "active" and len(str(item.get("rule", ""))) > policy.always_on_hard_cap_chars:
            _append_audit(settings, "ALWAYS_ON_DEMOTED", pattern_id, "ALWAYS_ON_HARD_CAP", budget=budget)
    if projection.always_on_chars > policy.always_on_hard_cap_chars:
        _append_audit(settings, "ALWAYS_ON_DEMOTED", "always-on", "ALWAYS_ON_HARD_CAP", budget=budget)


def _knowledge_summary(index: KnowledgeIndex | None) -> dict[str, Any]:
    if index is None:
        return {"status": "NOT_READY", "active_patterns": 0, "candidates": 0, "observations": 0, "always_on_chars": 0}
    return {
        "status": "READY",
        "active_patterns": len(index.active_pattern_ids),
        "candidates": len(index.candidate_pattern_ids),
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


def _team_store_id_hint(settings: Any, root: Path | None, *, budget=None) -> str:
    if budget is not None:
        budget.check()
    value = _team_store_value(settings, "store_id")
    if isinstance(value, str) and value:
        return value
    manifest_path = Path(getattr(settings.paths, "install_manifest_path", ""))
    try:
        document = _read_json(manifest_path, budget=budget) or {}
    except TimeoutError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        document = {}
    stores = document.get("knowledge_stores", {}) if isinstance(document, Mapping) else {}
    team = stores.get("team") if isinstance(stores, Mapping) else None
    if isinstance(team, Mapping) and isinstance(team.get("store_id"), str):
        return str(team["store_id"])
    if root is not None:
        try:
            team_manifest = _read_json(root / "team-manifest.json", budget=budget) or {}
        except TimeoutError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            team_manifest = {}
        if isinstance(team_manifest, Mapping) and isinstance(team_manifest.get("store_id"), str):
            return str(team_manifest["store_id"])
    return ""


def _team_descriptor(settings: Any, *, budget=None) -> tuple[Path | None, str, str | None]:
    """Return ``(root, store_id, issue)`` without exposing raw paths."""

    if not _team_store_enabled(settings):
        return None, "", "TEAM_DISABLED"
    root = _team_root(settings)
    if root is None:
        return None, "", "TEAM_ROOT_REQUIRED"
    store_id = _team_store_id_hint(settings, root, budget=budget)
    try:
        from .team_store import inspect_team_store

        descriptor = inspect_team_store(root, expected_store_id=store_id or None, budget=budget)
        store_id = descriptor.store_id
    except TimeoutError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        code = _safe_code(str(exc), "TEAM_ROOT_UNAVAILABLE")
        if not root.is_dir() or code in {"TEAM_ROOT_INVALID", "TEAM_ROOT_UNAVAILABLE"}:
            return root, store_id, "TEAM_ROOT_UNAVAILABLE"
        return root, store_id, code
    return root, store_id, None


def _team_identity_issue_codes(root: Path, *, budget=None) -> set[str]:
    """Detect ambiguous member slugs without returning member/writer values."""

    codes: set[str] = set()
    members = root / "members"
    try:
        if budget is not None:
            budget.check()
        assert_safe_target(root, members, allow_missing=True, expected_type="dir")
        if not members.is_dir():
            return codes
        for member in members.iterdir():
            if budget is not None:
                budget.check()
            if member.is_symlink() or not member.is_dir():
                continue
            writers = member / "writers"
            if not writers.is_dir() or writers.is_symlink():
                continue
            writer_ids = set()
            for child in writers.iterdir():
                if budget is not None:
                    budget.check()
                if child.is_dir() and not child.is_symlink():
                    writer_ids.add(child.name)
            if len(writer_ids) > 1:
                codes.add("TEAM_MEMBER_ID_REUSED")
    except TimeoutError:
        raise
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
    budget=None,
) -> dict[str, Any]:
    if not _team_store_enabled(settings):
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    root, store_id, issue = _team_descriptor(settings, budget=budget)
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

            scan = scan_team_events(root, budget=budget)
            result["accepted_event_count"] = len(scan.events)
            result["issue_codes"] = sorted(set(_safe_issue_codes(scan.issues)) | _team_identity_issue_codes(root, budget=budget))
        except TimeoutError:
            raise
        except (OSError, TypeError, ValueError, RuntimeError):
            result["issue_codes"] = ["TEAM_KNOWLEDGE_UNAVAILABLE"]
            return result
    try:
        from .team_projection import team_cache_paths

        paths = team_cache_paths(settings.paths.runtime_root, store_id)
        if paths.index_path.is_file():
            index = build_index(paths.knowledge_dir, paths.index_path, budget=budget)
            result.update({
                "active_patterns": len(index.active_pattern_ids),
                "candidate_patterns": len(getattr(index, "candidate_pattern_ids", ())),
                "observations": index.observation_count,
                "always_on_chars": index.always_on_chars,
                "generation_hash": index.generation_hash,
            })
        result["status"] = "READY"
        result.pop("reason_code", None)
    except TimeoutError:
        raise
    except (OSError, TypeError, ValueError):
        result["status"] = "DEFERRED"
        result["reason_code"] = "DEFERRED_TEAM_STORE"
    return result


def team_status_snapshot(settings: Any, *, budget=None) -> dict[str, Any]:
    """Return a sanitized, read-only team store health view."""

    return _team_base_status(settings, budget=budget)


def _maintain_team(
    settings: Any,
    *,
    max_queue_items: int,
    now: datetime,
    started_clock: float,
    time_budget_ms: int,
    team_services: TeamServices | None,
    budget=None,
) -> dict[str, Any]:
    if not _team_store_enabled(settings):
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    if _remaining_ms(started_clock, time_budget_ms) <= 0:
        return {"status": "DEFERRED", "reason_code": "DEFERRED_TEAM_STORE"}
    if budget is not None:
        budget.check()
    services: TeamServices = team_services or _DefaultTeamServices()
    try:
        outbox_value = services.drain_outbox(settings, max_items=max_queue_items, now=now, budget=budget)
    except TimeoutError:
        raise
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        outbox_value = {"status": "FAILED", "reason_code": _safe_code(str(exc), "TEAM_OUTBOX_FAILED")}
    outbox = _team_outbox_summary(outbox_value)
    root, store_id, issue = _team_descriptor(settings, budget=budget)
    projection_value: Any = None
    if issue is None and root is not None and store_id and _remaining_ms(started_clock, time_budget_ms) > 0:
        try:
            projection_value = services.refresh_projection(root, settings.paths.runtime_root, store_id, budget=budget)
        except TimeoutError:
            raise
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
    base = _team_base_status(settings, include_scan=False, budget=budget)
    issue_codes = set(base.get("issue_codes", ())) | set(projection.get("issue_codes", ()))
    if issue is None and root is not None:
        issue_codes.update(_team_identity_issue_codes(root, budget=budget))
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


def _capture_summary(events: Sequence[Event], *, budget=None) -> dict[str, Any]:
    direct = native = 0
    for event in events:
        if budget is not None:
            budget.check()
        if event.event_type == "observation.recorded":
            if event.payload.get("capture_path") == "agent_direct":
                direct += 1
            else:
                native += 1
    return {
        "direct_count": direct,
        "native_count": native,
        "primary": "agent_direct" if direct else "native_or_fallback" if native else "unknown",
        "coverage_unknown": not bool(direct or native),
    }
def _write_json(path: Path, value: Mapping[str, Any], *, budget=None) -> None:
    if budget is not None:
        budget.check()
    raw = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(raw) > 262144:
        raise ValueError("MAINTENANCE_HEALTH_LIMIT")
    safe_ensure_directory(path.parent)
    if budget is not None:
        budget.check()
    safe_atomic_write(path.parent, path, raw)


def _metric_summary(settings: Any, *, budget=None) -> dict[str, Any]:
    try:
        from .metrics import collect_local_metrics
        return collect_local_metrics(settings.paths.codex_home, settings.paths.metrics_dir, budget=budget).to_dict()
    except TimeoutError:
        raise
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
    budget=None,
) -> MaintenanceResult:
    if sync_policy not in _ALLOWED_SYNC_POLICIES:
        raise ValueError("SYNC_POLICY_INVALID")
    max_queue_items = _bounded_int(max_queue_items, "MAX_QUEUE_ITEMS", 1, 10000)
    time_budget_ms = _bounded_int(time_budget_ms, "TIME_BUDGET_MS", 0, 600000)
    started_clock = time.monotonic()
    budget = budget if budget is not None else OperationBudget(time_budget_ms, deadline=started_clock + time_budget_ms / 1000)
    maintenance_run = uuid.uuid4().hex
    moment = _utc(now)
    started_at = _iso(moment)
    errors: list[Mapping[str, Any]] = []
    def phase(stage, operation, default):
        try:
            budget.check()
            return operation()
        except TimeoutError:
            if not any(row.get("error_code") == "OPERATION_BUDGET_EXHAUSTED" for row in errors):
                errors.append({"stage": stage, "error_code": "OPERATION_BUDGET_EXHAUSTED"})
        except Exception as exc:
            errors.append({"stage": stage, "error_code": _safe_code(str(exc), stage.upper() + "_FAILED")})
        return default

    from .pending_capture import reconcile_pending
    from .operation_runtime import last_maintenance_activity
    previous_activity = phase("snapshot", lambda: last_maintenance_activity(settings, now=moment, budget=budget), {})
    pending = phase("pending", lambda: reconcile_pending(settings, now=moment, budget=budget, max_records=64), {})
    source_count = created = skipped = parse_skipped = rejected = 0
    ingest_results_list: list[Mapping[str, Any]] = []
    source_count, created, skipped, parse_skipped, rejected, rows = phase("source_recovery",
        lambda: _ingest(settings, source_paths, errors, now=moment, budget=budget, adapters=adapters), (0, 0, 0, 0, 0, ()))
    ingest_results_list.extend(rows)

    from .closeout_association import recover_closeout_associations
    from .incidents import closeout_recovery_loss_issue
    closeout_recovery = phase("closeout_recovery", lambda: recover_closeout_associations(
        settings, now=moment, budget=budget, max_records=64),
        {"processed": 0, "results": [], "reason_code": "CLOSEOUT_RECOVERY_UNKNOWN"})
    recovery_rows = closeout_recovery.get("results") if isinstance(closeout_recovery, Mapping) else None
    terminal_closeout_losses = ()
    if (
        isinstance(closeout_recovery, Mapping)
        and closeout_recovery.get("reason_code") == "CLOSEOUT_RECOVERY_COMPLETE"
        and isinstance(recovery_rows, list)
        and type(closeout_recovery.get("processed")) is int
        and closeout_recovery["processed"] == len(recovery_rows)
    ):
        loss_issues = {}
        for row in recovery_rows:
            if (
                isinstance(row, Mapping)
                and row.get("association") == "PENDING"
                and row.get("reason_code") == "CLOSEOUT_CACHE_EXPIRED"
            ):
                record_id = row.get("record_id")
                if isinstance(record_id, str) and re.fullmatch(r"co_[0-9a-f]{64}", record_id):
                    issue = closeout_recovery_loss_issue(record_id)
                    loss_issues[issue.component_id] = issue
        terminal_closeout_losses = tuple(loss_issues.values())
    terminal_closeout_ids = {issue.component_id.removeprefix("closeout-loss-") for issue in terminal_closeout_losses}
    if (
        not isinstance(closeout_recovery, Mapping)
        or closeout_recovery.get("reason_code") != "CLOSEOUT_RECOVERY_COMPLETE"
        or not isinstance(recovery_rows, list)
        or type(closeout_recovery.get("processed")) is not int
        or closeout_recovery["processed"] != len(recovery_rows)
        or any(
            not isinstance(row, Mapping)
            or (
                row.get("association") != "COMMITTED"
                and not (
                    row.get("association") == "PENDING"
                    and row.get("reason_code") == "CLOSEOUT_CACHE_EXPIRED"
                    and isinstance(row.get("record_id"), str)
                    and row["record_id"].startswith("co_")
                    and row["record_id"][3:] in terminal_closeout_ids
                )
            )
            for row in recovery_rows
        )
    ):
        errors.append({"stage": "closeout_recovery", "error_code": "CLOSEOUT_METADATA_UNKNOWN"})
    elif terminal_closeout_losses:
        errors.append({"stage": "closeout_recovery", "error_code": "CLOSEOUT_RECOVERY_LOSS"})

    expired = phase("spool_gc", lambda: gc_expired_spool(settings, now=moment, budget=budget), 0)

    recovery_result = RecoveryResult(0, 0, 0, False)
    if orphan_host_id:
        recovery_result = phase("orphan_recovery", lambda: reconcile_orphans(orphan_host_id, None, settings, budget=budget), recovery_result)

    queue_result = phase("queue_drain", lambda: drain_queue(settings, provider=provider,
        max_items=max_queue_items, time_budget_ms=budget.remaining_ms(), now=moment,
        run_id=maintenance_run, budget=budget), QueueDrainResult("partial", 0, 0, 0, 0, 0, 0, -1, 0))
    errors.extend(queue_result.errors)

    lifecycle_result = ReconciliationResult(0, 0, 0, 0, 0, 0, 0, 0)
    projection: KnowledgeIndex | None = None
    events: list[Event] = []
    events = phase("journal", lambda: _events(settings, budget=budget), None)
    if events is not None:
        lifecycle_result = phase("lifecycle", lambda: reconcile_lifecycle(events, settings.paths.event_dir, now_utc=moment, budget=budget), lifecycle_result)
        events = phase("journal", lambda: _events(settings, budget=budget), None)
    if events is not None:
        projection = phase("projection", lambda: project_events(events, settings.paths.knowledge_dir, budget=budget), None)
    from .changeset import _policy
    policy = phase("policy", lambda: _policy(settings, budget=budget), PromotionPolicy.defaults())
    if projection is not None:
        phase("quality_audit", lambda: _quality_audits(settings, lifecycle_result, projection, policy, budget=budget), None)

    # Team work is deliberately after all personal work.  A shared-folder
    # outage or a slow projection must never turn a successful personal
    # maintenance run into a failed run, and the deadline gate prevents any
    # team I/O once the personal budget is exhausted.
    team_result = phase("team", lambda: _maintain_team(
        settings,
        max_queue_items=max_queue_items,
        now=moment,
        started_clock=started_clock,
        time_budget_ms=time_budget_ms,
        team_services=team_services,
        budget=budget,
    ), {"status": "DEFERRED", "reason_code": "DEFERRED_TEAM_STORE"} if _team_store_enabled(settings) else {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
    personal_summary = _knowledge_summary(projection)
    from .reconciliation import candidate_diagnostics

    if events is not None:
        personal_summary["candidate_diagnostics"] = phase("candidate_diagnostics", lambda: list(candidate_diagnostics(events, budget=budget)), [])
    if projection is not None:
        def check_freshness():
            from .index import _load_index_document
            from .projection_state import projection_source_state, projection_freshness
            document, _ = _load_index_document(projection.index_path, budget=budget)
            current_events = _events(settings, budget=budget)
            def checked():
                for event in current_events:
                    budget.check()
                    yield event
            current = projection_source_state(checked())
            budget.check()
            freshness = projection_freshness(document.get("source_state"), current)
            return {"freshness": freshness, "reason_code": {"CURRENT": None, "STALE": "PROJECTION_STALE", "UNKNOWN": "PROJECTION_FRESHNESS_UNKNOWN"}[freshness],
                "source_event_count": current["event_count"]}
        freshness = phase("projection", check_freshness, None)
        if freshness is not None:
            personal_summary.update(freshness)
            if freshness["freshness"] != "CURRENT":
                errors.append({"stage": "projection", "error_code": freshness["reason_code"]})
        else:
            personal_summary["freshness"] = "UNKNOWN"

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
                budget.check()
                value: SyncResult = sync_once(settings, budget=budget)
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

    capture = phase("capture_summary", lambda: _capture_summary(events, budget=budget),
        {"direct_count": None, "native_count": None, "primary": "unknown", "coverage_unknown": True}) if events is not None else {"direct_count": None, "native_count": None, "primary": "unknown", "coverage_unknown": True}
    metrics = phase("metrics", lambda: _metric_summary(settings, budget=budget), {"status": "unknown", "source_status": "unknown", "error_code": "OPERATION_BUDGET_EXHAUSTED"})
    recovery_summary = recovery_result.to_dict()
    queue_mapping = queue_result.to_dict()
    from .operation_runtime import collect_operation_snapshot, write_operation_snapshot, service_operation, settings_binding
    from .task_scheduler import inspect_scheduler_opportunities
    from .operation_health import STORAGE_CODES, evaluate_health
    from .incidents import incident_id
    scheduler = phase("scheduler", lambda: inspect_scheduler_opportunities(settings, now=moment, budget=budget),
        {"requested": False, "missed_eligible_runs": None, "next_run_at": None, "reason_code": "SCHEDULER_BUDGET_EXHAUSTED"})
    progress = bool(created or queue_result.completed or queue_result.discarded or lifecycle_result.created_events)
    last_progress = moment if progress else previous_activity.get("last_progress_at")
    observed = phase("operation_health", lambda: collect_operation_snapshot(settings, now=moment, budget=budget,
        pending=pending, provider_state=queue_result.provider_state, scheduler=scheduler,
        last_progress_at=last_progress, last_attempt_at=moment,
        closeout_recovery=closeout_recovery), None)
    operation = {"schema_version": 1, "binding": settings_binding(settings), "run_id": maintenance_run,
        "last_attempt_at": moment.isoformat(), "last_progress_at": last_progress.isoformat() if last_progress else None,
        "scheduler": scheduler, "issues": [], "notifications_sent": 0, "reason_code": "OPERATION_BUDGET_EXHAUSTED"}
    spool_mapping = {"status": "UNKNOWN", "pending_count": None, "pending_bytes": None}
    if observed is not None:
        snapshot, binding = observed
        missing_sources = tuple(sorted({row["source_id_hash"] for row in ingest_results_list if row.get("source_available") is False}))
        snapshot = replace(snapshot, source_missing_ids=missing_sources, source_missing_count=len(missing_sources))
        fault = next((row["error_code"] for row in errors
                      if row.get("error_code") in STORAGE_CODES
                      and row.get("stage") != "closeout_recovery"), None)
        if fault is not None and snapshot.storage_code is None:
            snapshot = replace(snapshot, storage_code=fault, storage_component_id="knowledge-projection")
        written = phase("operation_cache", lambda: write_operation_snapshot(settings, snapshot, now=moment, budget=budget, custody_binding=binding), None)
        spool_mapping = {"status": snapshot.pending_count_status, "pending_count": snapshot.pending_count,
            "pending_bytes": snapshot.pending_bytes, "reserved_count": snapshot.reserved_count, "reserved_bytes": snapshot.reserved_bytes}
        resolutions = [incident_id("EXPIRY_CLEANUP_FAILED", value) for value in pending.get("cleanup_confirmed_capture_ids", ())]
        resolutions.extend(incident_id("SOURCE_UNAVAILABLE", row["source_id_hash"]) for row in ingest_results_list if row.get("source_available") is True)
        if queue_result.provider_verified_success:
            resolutions.append(incident_id("AUTH_FAILED", queue_result.provider_state.get("provider_id", "provider")))
        issues = evaluate_health(snapshot, now=moment)
        closeout_reasons = {(issue.reason_code, issue.component_id) for issue in issues
                            if issue.component_id == "closeout-store"}
        if snapshot.closeout_pending_status == "COMPLETE":
            if ("CLOSEOUT_ASSOCIATION_PENDING", "closeout-store") not in closeout_reasons:
                resolutions.append(incident_id("CLOSEOUT_ASSOCIATION_PENDING", "closeout-store"))
            if ("CLOSEOUT_METADATA_UNKNOWN", "closeout-store") not in closeout_reasons:
                resolutions.append(incident_id("CLOSEOUT_METADATA_UNKNOWN", "closeout-store"))
            for reason in ("CAPACITY_RISK", "EXPIRY_RISK"):
                if (reason, "closeout-store") not in closeout_reasons:
                    resolutions.append(incident_id(reason, "closeout-store"))
        if snapshot.pending_count_status == "COMPLETE":
            current_reasons = {issue.reason_code for issue in issues}
            for reason in ("CAPACITY_RISK", "EXPIRY_RISK", "ACCUMULATION_STALLED"):
                if reason not in current_reasons:
                    resolutions.append(incident_id(reason, "pending-store"))
            if snapshot.storage_code is None:
                resolutions.append(incident_id("STORAGE_UNAVAILABLE", "pending-store"))
        if projection is not None and personal_summary.get("freshness") == "CURRENT" and fault is None:
            resolutions.append(incident_id("STORAGE_UNAVAILABLE", "knowledge-projection"))
        if written is not None:
            operation.update(phase("operation_service", lambda: service_operation(settings, now=moment,
                channel="maintenance", budget=budget, verified_resolutions=tuple(resolutions), scheduler=scheduler,
                additional_issues=terminal_closeout_losses), operation))
    elif budget.remaining_ms() > 0:
        # Existing incident delivery is still possible when collection failed.
        operation.update(phase("operation_service", lambda: service_operation(settings, now=moment,
            channel="maintenance", budget=budget, additional_issues=terminal_closeout_losses), operation))
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
        "operation": operation,
        "errors": [dict(item) for item in errors],
        "recorded_at": _iso(),
    }
    phase("health", lambda: _write_json(Path(settings.paths.runtime_dir) / "health.json", health, budget=budget), None)
    finished_at = _iso()
    elapsed = int((time.monotonic() - started_clock) * 1000)
    status = "partial" if errors or queue_result.status == "partial" or team_result.get("status") == "BLOCKED" else "success"
    blocked = _safe_code(errors[0].get("error_code")) if errors else _safe_code(team_result.get("reason_code")) if team_result.get("status") == "BLOCKED" else None
    return MaintenanceResult(
        status, started_at, finished_at, elapsed, source_count, created, skipped,
        parse_skipped, rejected, tuple(ingest_results_list), queue_result.recovered_emergency,
        expired, queue_mapping, capture, recovery_summary, lifecycle_mapping,
        personal_summary, metrics, dict(sync_result), tuple(errors), blocked,
        personal_summary, team_result, operation,
    )


maintain = run_maintenance


__all__ = [
    "MaintenanceError", "MaintenanceResult", "QueueDrainResult", "TeamServices",
    "drain_queue", "maintain", "process_failure", "run_maintenance", "team_status_snapshot",
]
