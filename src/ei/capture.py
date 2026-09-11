from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from .dedup import content_fingerprint, normalize_claim
from .ids import fingerprint, machine_id, stable_hash
from .journal import append_event, iter_events
from .models import (
    CaptureContext,
    CaptureResult,
    Event,
    ObservationInput,
    validate_host_applicability_mapping,
)
from .privacy import inspect_observation


CAPTURE_PARSER_VERSION = "agent-direct-v1"
_OUTCOMES = {"success", "failed", "partial", "unknown"}
_BENEFITS = {"avoided_failure", "reduced_rework", "faster_completion", "quality_improvement", "discovered_structure", ""}
_CLASSIFICATIONS = {"public", "private-reusable", "external-reference", "client-confidential"}
_FULL_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEGACY_CONSUMPTION_EVENT = "capture.fallback_legacy_consumed"


def _persisted_hash(value: str) -> str:
    return value if _FULL_HASH.fullmatch(value) else fingerprint(value)


def _claim_hash(value: str) -> str:
    return "sha256:" + content_fingerprint(value)


def _capture_key(observation: ObservationInput, context: CaptureContext) -> str:
    return stable_hash("\0".join((
        context.session_id,
        context.turn_id,
        normalize_claim(observation.claim),
        observation.source_host_id or context.source_host_id,
        observation.source_host_family or context.source_host_family,
        CAPTURE_PARSER_VERSION,
    )))


def _capture_events(settings) -> list[Event]:
    if not settings.paths.event_dir.exists():
        return []
    return [event for event in iter_events(settings.paths.event_dir) if event.payload.get("capture_path") == "agent_direct"]


def _invalid_capture(observation: ObservationInput, context: CaptureContext, reason: str) -> CaptureResult:
    del observation, context
    return CaptureResult(False, None, reason)


def _record_deferred(settings, reason_code: str, error_type: str) -> None:
    path = settings.paths.runtime_dir / "capture-deferred.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"occurred_at": datetime.now(timezone.utc).isoformat(), "reason_code": reason_code, "error_type": error_type, "capture_path": "agent_direct"}, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(line)


def record_agent_observation(observation: ObservationInput, context: CaptureContext, settings) -> CaptureResult:
    if not context.session_id or not context.turn_id or context.capture_index not in {1, 2, 3}:
        return _invalid_capture(observation, context, "CAPTURE_INPUT_INVALID")
    if len(observation.title) > 160 or not 20 <= len(observation.claim) <= 1200:
        return _invalid_capture(observation, context, "CAPTURE_TEXT_LIMIT")
    if not observation.cwd and not observation.domain:
        return _invalid_capture(observation, context, "CAPTURE_SCOPE_REQUIRED")
    if observation.outcome_status not in _OUTCOMES or observation.benefit not in _BENEFITS or observation.classification not in _CLASSIFICATIONS:
        return _invalid_capture(observation, context, "CAPTURE_ENUM_INVALID")
    observation_pair = (observation.source_host_id, observation.source_host_family)
    context_pair = (context.source_host_id, context.source_host_family)
    if bool(observation_pair[0]) != bool(observation_pair[1]) or bool(context_pair[0]) != bool(context_pair[1]):
        return _invalid_capture(observation, context, "CAPTURE_HOST_APPLICABILITY_INVALID")
    if all(context_pair) and all(observation_pair) and observation_pair != context_pair:
        return _invalid_capture(observation, context, "CAPTURE_HOST_APPLICABILITY_INVALID")
    source_host_id = observation.source_host_id or context.source_host_id
    source_host_family = observation.source_host_family or context.source_host_family
    if not source_host_id or not source_host_family:
        return _invalid_capture(observation, context, "CAPTURE_HOST_PAIR_REQUIRED")
    applicability = {
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
        "applicability_scope": observation.applicability_scope,
        "applicable_host_ids": list(observation.applicable_host_ids),
        "applicable_host_families": list(observation.applicable_host_families),
    }
    try:
        host_scope = validate_host_applicability_mapping(applicability, require_source_pair=True)
    except ValueError as exc:
        code = str(exc)
        if code == "HOST_SOURCE_PAIR_REQUIRED":
            return _invalid_capture(observation, context, "CAPTURE_HOST_PAIR_REQUIRED")
        return _invalid_capture(observation, context, "CAPTURE_HOST_APPLICABILITY_INVALID")
    decision = inspect_observation(observation)
    if not decision.allow_private_sync:
        return _invalid_capture(observation, context, "PRIVACY_REJECTED")
    key = _capture_key(observation, context)
    existing = _capture_events(settings)
    existing_event = next((event for event in existing if event.payload.get("capture_idempotency_key") == key), None)
    if existing_event is not None:
        return CaptureResult(False, existing_event.event_id, "IDEMPOTENT_REPLAY")
    session_hash = fingerprint(context.session_id)
    if sum(1 for event in existing if event.payload.get("session_id_hash") == session_hash) >= settings.capture_max_per_session:
        return _invalid_capture(observation, context, "SESSION_CAPTURE_LIMIT")
    event = Event.create("observation.recorded", datetime.now(timezone.utc).isoformat(), "agent_direct", machine_id(), {"observation_id": "obs_" + key[:24], "title": observation.title, "claim": observation.claim, "source_kind": "agent_direct", "source_ref_hash": fingerprint(observation.source_ref), "source_hash": "", "cwd_fingerprint": fingerprint(observation.cwd) if observation.cwd else "", "domain": observation.domain, "outcome_status": observation.outcome_status, "benefit": observation.benefit, "classification": decision.classification.value, "applicability": list(observation.applicability), "capture_path": "agent_direct", "capture_idempotency_key": key, "session_id_hash": session_hash, "turn_id_hash": fingerprint(context.turn_id), "capture_index": context.capture_index, "source_host_id": source_host_id, "source_host_family": source_host_family, "applicability_scope": host_scope.scope, "applicable_host_ids": list(host_scope.host_ids), "applicable_host_families": list(host_scope.host_families)})
    try:
        append_event(event, settings.paths.event_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        try:
            _record_deferred(settings, "CAPTURE_DEFERRED", type(exc).__name__)
        except OSError as deferred_error:
            del deferred_error
        return CaptureResult(False, None, "CAPTURE_DEFERRED")
    return CaptureResult(True, event.event_id, "CREATED")


def select_capture_path(host_spec: object, available_paths: Mapping[str, bool] | Sequence[str]) -> str:
    """Select the first host-declared capture path; unknown coverage is explicit."""
    order = getattr(host_spec, "capture_order", ())
    if not isinstance(order, Sequence) or isinstance(order, (str, bytes, bytearray)):
        return "capture_coverage_unknown"
    if isinstance(available_paths, Mapping):
        available = {str(key) for key, value in available_paths.items() if value is True}
    else:
        available = {str(value) for value in available_paths if isinstance(value, str)}
    for path in order:
        if isinstance(path, str) and path in available:
            return path
    return "capture_coverage_unknown"


def _record_value(record: object, field: str, default: str = "") -> str:
    if isinstance(record, Event):
        return str(record.payload.get(field, default) or default)
    return str(getattr(record, field, default) or default)


def _record_text(record: object, field: str) -> str:
    if isinstance(record, Event):
        value = record.payload.get(field, "")
    else:
        value = getattr(record, field, "")
    return value if isinstance(value, str) else ""


def _legacy_consumption_key(legacy_event: Event, claim_fp: str, source_host_id: str, source_host_family: str) -> tuple[str, str, str, str]:
    return (fingerprint(legacy_event.event_id), claim_fp, source_host_id, source_host_family)


def _append_legacy_consumption_marker(settings, legacy_event: Event, claim_fp: str, source_host_id: str, source_host_family: str) -> None:
    marker_key = _legacy_consumption_key(legacy_event, claim_fp, source_host_id, source_host_family)
    payload = {
        "legacy_source_event_id_hash": marker_key[0],
        "observation_fingerprint": claim_fp,
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
        "applicability_scope": "host",
        "applicable_host_ids": [source_host_id],
        "applicable_host_families": [],
        "capture_path": "fallback",
        "audit_action": "legacy_fallback_consumed",
    }
    marker_id = "evt_" + stable_hash("\0".join(marker_key))[:32]
    append_event(
        Event.create(
            _LEGACY_CONSUMPTION_EVENT,
            legacy_event.occurred_at,
            "capture_reconciler",
            machine_id(),
            payload,
            event_id=marker_id,
        ),
        settings.paths.event_dir,
    )


@dataclass(frozen=True)
class FallbackResult:
    direct_count: int
    native_count: int
    recovered: int
    coverage_rate: float | None
    coverage_unknown: bool
    rejected: int = 0


def reconcile_fallback(settings, direct_events: Iterable[Event], native_records: Iterable[object]) -> FallbackResult:
    direct = list(direct_events)
    native = list(native_records)
    direct_keys = {
        (
            _claim_hash(str(event.payload.get("claim", ""))),
            _record_text(event, "source_host_id"),
            _record_text(event, "source_host_family"),
        )
        for event in direct
        if event.payload.get("claim") and _record_text(event, "source_host_id") and _record_text(event, "source_host_family")
    }
    recovered_keys: set[tuple[str, str, str]] = set()
    legacy_sources: dict[str, Event] = {}
    legacy_consumed_keys: set[tuple[str, str, str, str]] = set()
    if settings.paths.event_dir.exists():
        for event in iter_events(settings.paths.event_dir):
            if event.event_type == _LEGACY_CONSUMPTION_EVENT:
                claim_fp = _record_text(event, "observation_fingerprint")
                source_event_hash = _record_text(event, "legacy_source_event_id_hash")
                source_host_id = _record_text(event, "source_host_id")
                source_host_family = _record_text(event, "source_host_family")
                try:
                    validate_host_applicability_mapping(
                        {
                            "source_host_id": source_host_id,
                            "source_host_family": source_host_family,
                            "applicability_scope": event.payload.get("applicability_scope"),
                            "applicable_host_ids": event.payload.get("applicable_host_ids"),
                            "applicable_host_families": event.payload.get("applicable_host_families"),
                        },
                        require_source_pair=True,
                    )
                except (TypeError, ValueError):
                    continue
                if _FULL_HASH.fullmatch(claim_fp) and _FULL_HASH.fullmatch(source_event_hash):
                    legacy_consumed_keys.add((source_event_hash, claim_fp, source_host_id, source_host_family))
                continue
            if event.event_type != "capture.fallback_recovered" or not event.payload.get("observation_fingerprint"):
                continue
            claim_fp = str(event.payload["observation_fingerprint"])
            source_host_id = _record_text(event, "source_host_id")
            source_host_family = _record_text(event, "source_host_family")
            if source_host_id and source_host_family:
                recovered_keys.add((claim_fp, source_host_id, source_host_family))
            elif not source_host_id and not source_host_family:
                # Keep the first source event deterministic without rewriting it.
                legacy_sources.setdefault(claim_fp, event)
    recovered = 0
    rejected = 0
    legacy_claims_consumed: set[str] = set()
    for record in native:
        source_host_id = _record_text(record, "source_host_id")
        source_host_family = _record_text(record, "source_host_family")
        try:
            validate_host_applicability_mapping(
                {
                    "source_host_id": source_host_id,
                    "source_host_family": source_host_family,
                    "applicability_scope": "host",
                    "applicable_host_ids": [source_host_id] if source_host_id else [],
                    "applicable_host_families": [],
                },
                require_source_pair=True,
            )
        except ValueError:
            rejected += 1
            continue
        claim = _record_value(record, "claim")
        claim_fp = _claim_hash(claim)
        key = (claim_fp, source_host_id, source_host_family)
        if not claim or key in direct_keys or key in recovered_keys:
            continue
        legacy_event = legacy_sources.get(claim_fp)
        if legacy_event is not None:
            legacy_key = _legacy_consumption_key(legacy_event, claim_fp, source_host_id, source_host_family)
            if legacy_key in legacy_consumed_keys:
                continue
            if claim_fp not in legacy_claims_consumed and not any(key[0] == legacy_key[0] and key[1] == claim_fp for key in legacy_consumed_keys):
                _append_legacy_consumption_marker(settings, legacy_event, claim_fp, source_host_id, source_host_family)
                legacy_consumed_keys.add(legacy_key)
                legacy_claims_consumed.add(claim_fp)
                continue
        try:
            scope = validate_host_applicability_mapping(
                {
                    "source_host_id": source_host_id,
                    "source_host_family": source_host_family,
                    "applicability_scope": "host",
                    "applicable_host_ids": [source_host_id],
                    "applicable_host_families": [],
                },
                require_source_pair=True,
            )
        except ValueError:
            rejected += 1
            continue
        event = Event.create("capture.fallback_recovered", _record_value(record, "observed_at", datetime.now(timezone.utc).isoformat()), "capture_reconciler", machine_id(), {"observation_fingerprint": claim_fp, "source_kind": _record_value(record, "source_kind", "native_memory"), "source_hash": _persisted_hash(_record_value(record, "source_hash")), "source_ref_hash": fingerprint(_record_value(record, "source_ref")), "classification": _record_value(record, "classification", "private-reusable"), "capture_path": "fallback", "source_host_id": source_host_id, "source_host_family": source_host_family, "applicability_scope": scope.scope, "applicable_host_ids": list(scope.host_ids), "applicable_host_families": list(scope.host_families)})
        append_event(event, settings.paths.event_dir)
        recovered_keys.add(key)
        recovered += 1
    coverage_unknown = (not direct and not native) or bool(rejected)
    coverage_rate = None if coverage_unknown or not native else (len(native) - recovered) / len(native)
    coverage = {"direct_count": len(direct), "native_count": len(native), "fallback_recovered": recovered, "rejected": rejected, "capture_coverage": coverage_rate, "capture_coverage_unknown": coverage_unknown}
    path = settings.paths.runtime_dir / "capture-coverage.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(coverage, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return FallbackResult(len(direct), len(native), recovered, coverage_rate, coverage_unknown, rejected)

__all__ = ["CaptureContext", "CaptureResult", "FallbackResult", "record_agent_observation", "reconcile_fallback", "select_capture_path"]
