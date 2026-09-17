from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .cluster import assign_cluster
from .dedup import content_fingerprint, detect_polarity, normalize_claim
from .ids import machine_id, stable_hash
from .journal import append_event
from .lifecycle import evaluate_lifecycle, promotion_eligibility
from .models import (
    ClusterState,
    Event,
    ObservationState,
    PromotionPolicy,
    host_applicability_fields,
    validate_host_applicability_mapping,
)


@dataclass(frozen=True)
class ReconciliationResult:
    created_events: int
    candidate_events: int
    promotion_events: int
    revision_events: int
    deprecation_events: int
    tombstone_events: int
    duplicate_observations: int
    cluster_count: int


@dataclass
class _ClusterRecord:
    state: ClusterState
    observations: list[ObservationState]
    canonical_rule: str
    revision: int


def _observation_state(event: Event) -> ObservationState:
    payload = event.payload

    def text(name: str, default: str = "") -> str:
        value = payload.get(name, default)
        return value if isinstance(value, str) else default

    source_kind = text("source_kind", "native_memory")
    source_hash = text("source_hash")
    source_ref_hash = text("source_ref_hash")
    provenance = text("provenance_key") or f"{source_kind}:{source_hash or source_ref_hash or event.event_id}"
    raw_applicability = payload.get("applicability", ())
    applicability = (
        tuple(item for item in raw_applicability if isinstance(item, str) and item)
        if isinstance(raw_applicability, (tuple, list))
        else ()
    )
    host_fields = host_applicability_fields(payload, allow_legacy=True, require_source_pair=True)
    return ObservationState(
        observation_id=text("observation_id", "obs_" + event.event_id),
        title=text("title"),
        claim=text("claim"),
        domain=text("domain", "general"),
        cwd_fingerprint=text("cwd_fingerprint"),
        provenance_key=provenance,
        outcome_status=text("outcome_status", "unknown"),
        benefit=text("benefit"),
        classification=text("classification", "private-reusable"),
        source_hash=source_hash,
        applicability=applicability,
        scope=host_fields["applicability_scope"],
        source_host_id=host_fields["source_host_id"],
        source_host_family=host_fields["source_host_family"],
        applicability_scope=host_fields["applicability_scope"],
        applicable_host_ids=tuple(host_fields["applicable_host_ids"]),
        applicable_host_families=tuple(host_fields["applicable_host_families"]),
    )


def _state_host_fields(state: ClusterState) -> dict[str, object]:
    if not state.source_host_id or not state.source_host_family:
        # Do not manufacture a real host while projecting pre-feature legacy data.
        return {}
    validate_host_applicability_mapping(
        {
            "source_host_id": state.source_host_id,
            "source_host_family": state.source_host_family,
            "applicability_scope": state.applicability_scope,
            "applicable_host_ids": list(state.applicable_host_ids),
            "applicable_host_families": list(state.applicable_host_families),
        },
        require_source_pair=True,
    )
    return {
        "source_host_id": state.source_host_id,
        "source_host_family": state.source_host_family,
        "applicability_scope": state.applicability_scope,
        "applicable_host_ids": list(state.applicable_host_ids),
        "applicable_host_families": list(state.applicable_host_families),
    }
def _scope(observation: ObservationState) -> str:
    return observation.cwd_fingerprint or "domain:" + observation.domain


def _host_applicability_key(observation: ObservationState) -> tuple[object, ...]:
    """Return the persisted host contract used to keep clusters distinct.

    A legacy observation has no trusted source pair and is kept in its own
    compatibility partition.  Explicit records from different hosts (or with
    different applicability scopes) must not collapse into one pattern whose
    single source identity would erase the distinction.
    """
    if not observation.source_host_id or not observation.source_host_family:
        return ("legacy",)
    return (
        "explicit",
        observation.source_host_id,
        observation.source_host_family,
        observation.applicability_scope,
        observation.applicable_host_ids,
        observation.applicable_host_families,
    )


def _cluster_id(observation: ObservationState) -> str:
    base = "cluster_" + content_fingerprint(observation.claim)[:20]
    if _host_applicability_key(observation) == ("legacy",):
        return base
    return base + "_" + stable_hash(_host_applicability_key(observation))[:12]


def _canonical_rule(observations: Iterable[ObservationState]) -> str:
    choices = sorted((observation.claim for observation in observations if observation.claim), key=lambda value: (-len(normalize_claim(value)), normalize_claim(value)))
    return choices[0] if choices else ""


def _event_map(events: Iterable[Event]) -> dict[str, Event]:
    return {event.event_id: event for event in events}


def _event_for_pattern(
    event_type: str,
    record: _ClusterRecord,
    occurred_at: str,
    payload: dict[str, object],
    policy: PromotionPolicy,
    reason: str,
    *,
    new_version: int | None = None,
) -> Event:
    evidence_refs = tuple(sorted(record.state.evidence_refs or record.state.provenances))
    complete: dict[str, object] = {
        "cluster_id": record.state.cluster_id,
        "reason": reason,
        "reason_code": reason,
        "evidence_refs": list(evidence_refs),
        "policy_version": policy.policy_version,
        "old_version": record.revision,
        "new_version": record.revision if new_version is None else new_version,
        **payload,
    }
    complete.update(_state_host_fields(record.state))
    complete["idempotency_key"] = "sha256:" + stable_hash(
        {"event_type": event_type, "cluster_id": record.state.cluster_id, "occurred_at": occurred_at, "payload": complete}
    )
    event_id = "evt_reconcile_" + stable_hash(
        {"event_type": event_type, "cluster_id": record.state.cluster_id, "payload": complete}
    )[:28]
    return Event.create(event_type, occurred_at, "reconcile", machine_id(), complete, event_id=event_id)
def _new_record(cluster_id: str, observations: list[ObservationState], last_used_at: str | None) -> _ClusterRecord:
    first = observations[0]
    state = ClusterState(
        cluster_id=cluster_id,
        pattern_id=None,
        status="raw",
        rule=_canonical_rule(observations),
        provenances=frozenset(observation.provenance_key for observation in observations),
        scopes=frozenset(_scope(observation) for observation in observations),
        benefit_count=sum(1 for observation in observations if observation.benefit),
        contradiction_provenances=frozenset(),
        classification=first.classification,
        last_used_at=last_used_at,
        applicability=(first.domain,) if first.domain else (),
        precondition=first.domain or None,
        failure_mode=first.outcome_status or None,
        evidence_refs=tuple(sorted(observation.provenance_key for observation in observations if observation.provenance_key)),
        source_host_id=first.source_host_id,
        source_host_family=first.source_host_family,
        applicability_scope=first.applicability_scope,
        applicable_host_ids=first.applicable_host_ids,
        applicable_host_families=first.applicable_host_families,
    )
    return _ClusterRecord(state, observations, state.rule, 0)


def _cluster_observations(events: list[Event]) -> tuple[dict[str, _ClusterRecord], int]:
    observations: list[ObservationState] = []
    observation_clusters: dict[str, str] = {}
    records: dict[str, _ClusterRecord] = {}
    duplicate_count = 0
    observation_times: dict[str, str] = {}
    for event in events:
        if event.event_type != "observation.recorded" or not event.payload.get("claim"):
            continue
        observation = _observation_state(event)
        decision = assign_cluster(
            observation,
            [candidate for candidate in observations if _host_applicability_key(candidate) == _host_applicability_key(observation)],
        )
        if decision.kind == "new" or decision.target_observation_id is None:
            cluster_id = _cluster_id(observation)
        else:
            cluster_id = observation_clusters[decision.target_observation_id]
            if decision.kind == "duplicate":
                duplicate_count += 1
        observation_clusters[observation.observation_id] = cluster_id
        observations.append(observation)
        observation_times[cluster_id] = max(observation_times.get(cluster_id, ""), event.occurred_at)
        if cluster_id not in records:
            records[cluster_id] = _new_record(cluster_id, [observation], event.occurred_at)
        else:
            record = records[cluster_id]
            record.observations.append(observation)
            record.state = replace(
                record.state,
                rule=_canonical_rule(record.observations),
                provenances=frozenset(item.provenance_key for item in record.observations),
                scopes=frozenset(_scope(item) for item in record.observations),
                benefit_count=sum(1 for item in record.observations if item.benefit),
                last_used_at=observation_times[cluster_id],
                applicability=tuple(sorted({item.domain for item in record.observations if item.domain})),
                precondition=next((item.domain for item in record.observations if item.domain), None),
                failure_mode=next((item.outcome_status for item in record.observations if item.outcome_status), None),
                evidence_refs=tuple(sorted(item.provenance_key for item in record.observations if item.provenance_key)),
            )
            if not record.state.source_host_id and observation.source_host_id and observation.source_host_family:
                record.state = replace(
                    record.state,
                    source_host_id=observation.source_host_id,
                    source_host_family=observation.source_host_family,
                    applicability_scope=observation.applicability_scope,
                    applicable_host_ids=observation.applicable_host_ids,
                    applicable_host_families=observation.applicable_host_families,
                )
            record.canonical_rule = record.state.rule
        contradictory = set(records[cluster_id].state.contradiction_provenances)
        for prior in observations[:-1]:
            if observation_clusters.get(prior.observation_id) != cluster_id:
                continue
            if prior.provenance_key != observation.provenance_key and detect_polarity(prior.claim) != detect_polarity(observation.claim):
                contradictory.add(observation.provenance_key)
        if decision.kind == "contradiction" and decision.independent_provenance:
            contradictory.add(observation.provenance_key)
        records[cluster_id].state = replace(records[cluster_id].state, contradiction_provenances=frozenset(contradictory))
    return records, duplicate_count


def _apply_pattern_events(records: dict[str, _ClusterRecord], events: Iterable[Event]) -> None:
    exposure_counts: dict[str, int] = {}
    exposure_times: dict[str, str] = {}
    for event in events:
        payload = event.payload
        cluster_id = str(payload.get("cluster_id", ""))
        record = records.get(cluster_id)
        if record is None:
            continue
        event_type = event.event_type
        if event_type == "pattern.exposed" or event_type == "pattern.used":
            pattern_id = str(payload.get("pattern_id", ""))
            exposure_counts[pattern_id] = exposure_counts.get(pattern_id, 0) + 1
            exposure_times[cluster_id] = max(exposure_times.get(cluster_id, ""), event.occurred_at)
            continue
        if event_type == "pattern.candidate_created":
            updates = {"status": "candidate", "pattern_id": str(payload.get("pattern_id", record.state.pattern_id or "")), "rule": str(payload.get("rule", record.state.rule)), "classification": str(payload.get("classification", record.state.classification))}
            if any(field in payload for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
                updates.update(host_applicability_fields(payload, allow_legacy=False, require_source_pair=True))
                updates.update({
                    "source_host_id": updates.pop("source_host_id"),
                    "source_host_family": updates.pop("source_host_family"),
                    "applicability_scope": updates.pop("applicability_scope"),
                    "applicable_host_ids": tuple(updates.pop("applicable_host_ids")),
                    "applicable_host_families": tuple(updates.pop("applicable_host_families")),
                })
            record.state = replace(record.state, **updates)
        elif event_type == "pattern.promoted":
            updates = {"status": "active", "pattern_id": str(payload.get("pattern_id", record.state.pattern_id or "")), "rule": str(payload.get("rule", record.state.rule)), "classification": str(payload.get("classification", record.state.classification))}
            if any(field in payload for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
                fields = host_applicability_fields(payload, allow_legacy=False, require_source_pair=True)
                updates.update({"source_host_id": fields["source_host_id"], "source_host_family": fields["source_host_family"], "applicability_scope": fields["applicability_scope"], "applicable_host_ids": tuple(fields["applicable_host_ids"]), "applicable_host_families": tuple(fields["applicable_host_families"])})
            record.state = replace(record.state, **updates)
        elif event_type == "pattern.revised":
            record.revision = max(record.revision, int(payload.get("revision", 0)))
            updates = {"rule": str(payload.get("rule", record.state.rule)), "classification": str(payload.get("classification", record.state.classification))}
            if any(field in payload for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
                fields = host_applicability_fields(payload, allow_legacy=False, require_source_pair=True)
                updates.update({"source_host_id": fields["source_host_id"], "source_host_family": fields["source_host_family"], "applicability_scope": fields["applicability_scope"], "applicable_host_ids": tuple(fields["applicable_host_ids"]), "applicable_host_families": tuple(fields["applicable_host_families"])})
            record.state = replace(record.state, **updates)
        elif event_type == "pattern.deprecated":
            record.state = replace(record.state, status="deprecated", deprecated_at=event.occurred_at)
        elif event_type == "pattern.superseded":
            record.state = replace(record.state, status="superseded", superseded_by=str(payload.get("replacement_pattern_id", payload.get("superseded_by", ""))), replacement_active=bool(payload.get("replacement_active", False)))
        elif event_type == "pattern.tombstoned":
            record.state = replace(record.state, status="tombstoned")
        record.canonical_rule = _canonical_rule(record.observations)
    for record in records.values():
        if record.state.pattern_id:
            count = exposure_counts.get(record.state.pattern_id, 0)
            last_used = max(record.state.last_used_at or "", exposure_times.get(record.state.cluster_id, "")) or None
            record.state = replace(record.state, exposure_count=count, last_used_at=last_used)


def candidate_diagnostics(events: Iterable[Event], policy: PromotionPolicy | None = None) -> tuple[dict[str, Any], ...]:
    """Explain existing candidates using the lifecycle's evidence, without writes."""
    current = sorted(list(events), key=lambda event: (event.occurred_at, event.event_id))
    candidates: dict[str, str] = {}
    for event in current:
        pattern_id = event.payload.get("pattern_id")
        if not isinstance(pattern_id, str) or not pattern_id:
            continue
        if event.event_type == "pattern.candidate_created":
            candidates[pattern_id] = str(event.payload.get("cluster_id", ""))
        elif event.event_type in {"pattern.promoted", "pattern.revised", "pattern.deprecated", "pattern.superseded", "pattern.tombstoned"}:
            candidates.pop(pattern_id, None)
    if not candidates:
        return ()
    records, _ = _cluster_observations(current)
    _apply_pattern_events(records, current)
    selected_policy = policy or PromotionPolicy.defaults()
    rows: list[dict[str, Any]] = []
    for pattern_id, cluster_id in sorted(candidates.items()):
        record = records.get(cluster_id)
        state = record.state if record is not None else None
        eligibility = promotion_eligibility(state, selected_policy) if state is not None else None
        rows.append({
            "pattern_id": pattern_id,
            "eligible": eligibility.valid if eligibility else False,
            "reason_codes": list(eligibility.reason_codes) if eligibility else ["CANDIDATE_EVIDENCE_UNAVAILABLE"],
            "provenance_count": len(state.provenances) if state else 0,
            "scope_count": len(state.scopes) if state else 0,
            "benefit_count": state.benefit_count if state else 0,
            "contradiction_count": len(state.contradiction_provenances) if state else 0,
            "policy_version": selected_policy.policy_version,
        })
    return tuple(rows)


def reconcile_lifecycle(events: Iterable[Event], event_dir, now_utc: datetime | str | None = None, policy: PromotionPolicy | None = None) -> ReconciliationResult:
    current_events = sorted(list(events), key=lambda event: (event.occurred_at, event.event_id))
    original_event_ids = set(_event_map(current_events))
    event_ids = set(original_event_ids)
    records, duplicate_count = _cluster_observations(current_events)
    selected_policy = policy or PromotionPolicy.defaults()
    _apply_pattern_events(records, current_events)
    now = now_utc or datetime.now(timezone.utc)
    now_text = now.isoformat() if isinstance(now, datetime) else str(now)
    if current_events:
        latest_text = max(event.occurred_at for event in current_events)
        if now_text <= latest_text:
            try:
                latest = datetime.fromisoformat(latest_text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("RECONCILIATION_TIMESTAMP_INVALID") from exc
            now_text = (latest + timedelta(microseconds=1)).isoformat()
    generated: list[Event] = []
    candidate_events = 0
    revision_events = 0
    for record in records.values():
        state = record.state
        if state.status in {"raw", "candidate"} and len(state.provenances) >= selected_policy.independent_provenance_count and not state.pattern_id:
            pattern_id = "pat_" + stable_hash(state.cluster_id)[:20]
            observed_at = max((event.occurred_at for event in current_events if event.event_type == "observation.recorded" and str(event.payload.get("observation_id", "")) in {item.observation_id for item in record.observations}), default=now_text)
            generated.append(_event_for_pattern("pattern.candidate_created", record, observed_at, {"pattern_id": pattern_id, "rule": record.canonical_rule, "provenances": sorted(state.provenances), "scopes": sorted(state.scopes), "applicability": list(state.applicability), "benefit_count": state.benefit_count, "classification": state.classification}, selected_policy, "REPEATED_OBSERVATION", new_version=0))
            candidate_events += 1
        elif state.status == "active" and record.canonical_rule and record.canonical_rule != state.rule:
            revision = record.revision + 1
            generated.append(_event_for_pattern("pattern.revised", record, now_text, {"pattern_id": state.pattern_id, "revision": revision, "rule": record.canonical_rule, "provenances": sorted(state.provenances), "scopes": sorted(state.scopes), "applicability": list(state.applicability), "benefit_count": state.benefit_count, "classification": state.classification}, selected_policy, "NEW_REUSABLE_EVIDENCE", new_version=revision))
            revision_events += 1
    for event in generated:
        if event.event_id not in event_ids:
            append_event(event, event_dir)
            event_ids.add(event.event_id)
    updated_events = current_events + [event for event in generated if event.event_id not in original_event_ids]
    updated_records, _ = _cluster_observations(sorted(updated_events, key=lambda event: (event.occurred_at, event.event_id)))
    _apply_pattern_events(updated_records, sorted(updated_events, key=lambda event: (event.occurred_at, event.event_id)))
    lifecycle_events: list[Event] = []
    for record in updated_records.values():
        lifecycle_events.extend(evaluate_lifecycle(record.state, selected_policy, now_utc=now_text))
    promotion_events = sum(1 for event in lifecycle_events if event.event_type == "pattern.promoted")
    deprecation_events = sum(1 for event in lifecycle_events if event.event_type == "pattern.deprecated")
    tombstone_events = sum(1 for event in lifecycle_events if event.event_type == "pattern.tombstoned")
    for event in lifecycle_events:
        if event.event_id not in event_ids:
            append_event(event, event_dir)
            event_ids.add(event.event_id)
    unique_created = len(event_ids.difference(original_event_ids))
    return ReconciliationResult(unique_created, candidate_events, promotion_events, revision_events, deprecation_events, tombstone_events, duplicate_count, len(updated_records))
