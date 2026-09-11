from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from .ids import stable_hash
from .models import (
    ClusterState,
    Event,
    PatternState,
    PromotionPolicy,
    ValidationResult,
)


_PROMOTABLE_CLASSIFICATIONS = {"public", "private-reusable"}
_BENEFIT_VALUES = {
    "avoided_failure",
    "reduced_rework",
    "reduced_search",
    "improved_correctness",
}


def _timestamp(value: datetime | str | None, fallback: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    return str(value)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _state_value(state: object, name: str, default: Any = None) -> Any:
    if isinstance(state, Mapping):
        return state.get(name, default)
    return getattr(state, name, default)


def _evidence_refs(state: ClusterState) -> tuple[str, ...]:
    values = _state_value(state, "evidence_refs", ()) or _state_value(state, "provenances", ())
    if not isinstance(values, (tuple, list, set, frozenset)):
        return ()
    return tuple(sorted(str(value) for value in values if value))


def _policy_version(policy: PromotionPolicy) -> str:
    value = getattr(policy, "policy_version", "promotion-v1")
    return value if isinstance(value, str) and value else "promotion-v1"


def _event(
    event_type: str,
    state: ClusterState,
    timestamp: str,
    policy: PromotionPolicy,
    reason: str,
    payload: dict[str, Any] | None = None,
    *,
    old_version: int | str | None = None,
    new_version: int | str | None = None,
) -> Event:
    body: dict[str, Any] = {
        "cluster_id": state.cluster_id,
        "reason": reason,
        "reason_code": reason,
        "evidence_refs": list(_evidence_refs(state)),
        "policy_version": _policy_version(policy),
        "old_version": old_version if old_version is not None else _state_value(state, "revision", 0),
        "new_version": new_version if new_version is not None else _state_value(state, "revision", 0),
    }
    if payload:
        body.update(payload)
    source_host_id = _state_value(state, "source_host_id", "")
    source_host_family = _state_value(state, "source_host_family", "")
    if isinstance(source_host_id, str) and isinstance(source_host_family, str) and source_host_id and source_host_family:
        body.update(
            {
                "source_host_id": source_host_id,
                "source_host_family": source_host_family,
                "applicability_scope": _state_value(state, "applicability_scope", "universal"),
                "applicable_host_ids": list(_state_value(state, "applicable_host_ids", ()) or ()),
                "applicable_host_families": list(_state_value(state, "applicable_host_families", ()) or ()),
            }
        )
    idempotency = "sha256:" + stable_hash(
        {
            "event_type": event_type,
            "cluster_id": state.cluster_id,
            "occurred_at": timestamp,
            "payload": body,
        }
    )
    body["idempotency_key"] = idempotency
    event_id = "evt_lifecycle_" + stable_hash(
        {"event_type": event_type, "cluster_id": state.cluster_id, "payload": body}
    )[:24]
    return Event.create(
        event_type=event_type,
        occurred_at=timestamp,
        actor="lifecycle",
        machine_id="lifecycle",
        payload=body,
        event_id=event_id,
    )


def promotion_eligibility(cluster: ClusterState, policy: PromotionPolicy) -> ValidationResult:
    reasons: list[str] = []
    if cluster.status not in {"raw", "candidate"}:
        reasons.append("STATUS_NOT_PROMOTABLE")
    if len(cluster.provenances) < policy.independent_provenance_count:
        reasons.append("INSUFFICIENT_INDEPENDENT_PROVENANCE")
    if len(cluster.scopes) < policy.distinct_scope_count:
        reasons.append("INSUFFICIENT_DISTINCT_SCOPE")
    if cluster.benefit_count < policy.benefit_evidence_count:
        reasons.append("INSUFFICIENT_BENEFIT_EVIDENCE")
    if len(cluster.contradiction_provenances) > policy.max_unresolved_contradictions:
        reasons.append("UNRESOLVED_CONTRADICTION")
    if cluster.classification not in _PROMOTABLE_CLASSIFICATIONS:
        reasons.append("CLASSIFICATION_NOT_PROMOTABLE")
    if not isinstance(cluster.rule, str) or not policy.min_rule_chars <= len(cluster.rule) <= policy.max_rule_chars:
        reasons.append("RULE_LENGTH_INVALID")
    precondition = _state_value(cluster, "precondition", None)
    if precondition == "":
        reasons.append("PRECONDITION_MISSING")
    elif precondition is None and not cluster.scopes:
        reasons.append("PRECONDITION_MISSING")
    failure_mode = _state_value(cluster, "failure_mode", None)
    if failure_mode == "":
        reasons.append("FAILURE_MODE_MISSING")
    elif failure_mode is None and cluster.benefit_count < 1:
        reasons.append("FAILURE_MODE_MISSING")
    applicability = _state_value(cluster, "applicability", ())
    if not isinstance(applicability, (tuple, list, set, frozenset)) or not any(str(item).strip() for item in applicability):
        reasons.append("APPLICABILITY_MISSING")
    return ValidationResult(valid=not reasons, reason_codes=tuple(dict.fromkeys(reasons)))


def _promotion_ready(state: ClusterState, policy: PromotionPolicy) -> bool:
    return promotion_eligibility(state, policy).valid


def _inactive_long_enough(state: ClusterState, now: datetime, days: int) -> bool:
    reference = _parse_timestamp(state.last_used_at) or _parse_timestamp(state.deprecated_at)
    if reference is None:
        return False
    return now - reference.astimezone(timezone.utc) >= timedelta(days=days)


def _pattern_from(value: PatternState | Mapping[str, Any]) -> PatternState:
    if isinstance(value, PatternState):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("PATTERN_STATE_REQUIRED")
    return PatternState(
        pattern_id=str(value.get("pattern_id", "")),
        rule=str(value.get("rule", "")),
        precondition=str(value.get("precondition", "")),
        scope=str(value.get("scope", "")),
        evidence_ids=tuple(str(item) for item in value.get("evidence_ids", value.get("provenances", ())) if item),
        benefit_refs=tuple(str(item) for item in value.get("benefit_refs", ())),
        exceptions=tuple(str(item) for item in value.get("exceptions", ())),
        version_constraint=value.get("version_constraint") if isinstance(value.get("version_constraint"), str) else None,
        status=str(value.get("status", "active")),
        classification=str(value.get("classification", "private-reusable")),
        utility=float(value.get("utility", 0.0)),
        cluster_id=str(value.get("cluster_id", "")),
        applicability=tuple(str(item) for item in value.get("applicability", value.get("scopes", ())) if item),
        updated_at=value.get("updated_at"),
        contradiction_count=int(value.get("contradiction_count", 0)),
        pinned=bool(value.get("pinned", False)),
        legal_hold=bool(value.get("legal_hold", False)),
        source_host_id=value.get("source_host_id", "") if isinstance(value.get("source_host_id", ""), str) else "",
        source_host_family=value.get("source_host_family", "") if isinstance(value.get("source_host_family", ""), str) else "",
        applicability_scope=value.get("applicability_scope", "universal") if value.get("applicability_scope", "universal") in {"universal", "family", "host"} else "universal",
        applicable_host_ids=tuple(item for item in value.get("applicable_host_ids", ()) if isinstance(item, str)),
        applicable_host_families=tuple(item for item in value.get("applicable_host_families", ()) if isinstance(item, str)),
    )


def _freshness(pattern: PatternState, usage: Mapping[str, int | float]) -> float:
    explicit = usage.get("freshness")
    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool):
        return max(0.0, min(1.0, float(explicit)))
    updated = _parse_timestamp(pattern.updated_at if isinstance(pattern.updated_at, str) else None)
    now = _parse_timestamp(str(usage.get("now_utc", ""))) if usage.get("now_utc") else None
    if updated is None or now is None:
        return 0.5 if updated is not None else 0.0
    age = max(0.0, (now - updated).total_seconds() / 86400.0)
    return 1.0 / (1.0 + age / 365.0)


def utility_score(pattern: PatternState | Mapping[str, Any], usage: Mapping[str, int | float]) -> float:
    item = _pattern_from(pattern)
    retrieval_frequency = float(usage.get("retrieval_frequency", usage.get(item.pattern_id, 0)) or 0)
    frequency = max(0.0, min(1.0, retrieval_frequency / 10.0))
    benefit_strength = float(usage.get("benefit_strength", min(1.0, len(item.benefit_refs) / 2.0)) or 0)
    scope_breadth = float(usage.get("scope_breadth", min(1.0, len(item.applicability) / 2.0)) or 0)
    evidence_strength = float(usage.get("evidence_strength", min(1.0, len(item.evidence_ids) / 2.0)) or 0)
    contradiction_penalty = float(
        usage.get("contradiction_penalty", min(1.0, item.contradiction_count / 3.0)) or 0
    )
    context_penalty = float(
        usage.get("context_cost_penalty", min(0.25, len(item.rule) / 12000.0 * 0.25)) or 0
    )
    score = (
        frequency * 0.25
        + max(0.0, min(1.0, benefit_strength)) * 0.25
        + max(0.0, min(1.0, scope_breadth)) * 0.15
        + max(0.0, min(1.0, evidence_strength)) * 0.20
        + _freshness(item, usage) * 0.15
        - max(0.0, contradiction_penalty)
        - max(0.0, context_penalty)
    )
    return round(max(-1.0, min(1.0, score)), 6)


def select_always_on(
    patterns: Iterable[PatternState | Mapping[str, Any]],
    usage: Mapping[str, int | float] | None = None,
    target_chars: int = 9000,
    hard_cap_chars: int = 12000,
) -> tuple[PatternState, ...]:
    if target_chars <= 0 or hard_cap_chars <= 0 or target_chars > hard_cap_chars:
        raise ValueError("ALWAYS_ON_BUDGET_INVALID")
    usage = usage or {}
    candidates = [
        _pattern_from(pattern)
        for pattern in patterns
        if _pattern_from(pattern).status == "active"
        and _pattern_from(pattern).classification in _PROMOTABLE_CLASSIFICATIONS
        and _pattern_from(pattern).contradiction_count == 0
    ]
    ranked = sorted(
        candidates,
        key=lambda item: (-utility_score(item, usage), -int(item.pinned), item.pattern_id),
    )
    selected: list[PatternState] = []
    total = 0
    for item in ranked:
        cost = len(item.rule)
        if cost > hard_cap_chars or total + cost > hard_cap_chars:
            continue
        if total + cost <= target_chars or item.pinned or item.legal_hold:
            selected.append(
                PatternState(
                    **{
                        **item.__dict__,
                        "utility": utility_score(item, usage),
                    }
                )
            )
            total += cost
    return tuple(selected)


def choose_always_on(
    patterns: Iterable[PatternState | Mapping[str, Any]],
    usage: Mapping[str, int | float] | None = None,
    target_chars: int = 9000,
    hard_cap_chars: int = 12000,
) -> tuple[PatternState, ...]:
    return select_always_on(patterns, usage, target_chars, hard_cap_chars)


def apply_lifecycle_transition(
    cluster: ClusterState,
    event: Event,
    policy: PromotionPolicy,
) -> tuple[Event, ...]:
    if event.event_type == "pattern.promoted" and not promotion_eligibility(cluster, policy).valid:
        return ()
    if event.event_type == "pattern.revised" and event.payload.get("meaning_reversing"):
        replacement_id = str(event.payload.get("replacement_pattern_id") or "pat_" + stable_hash(event.event_id)[:20])
        replacement_payload = {
            "pattern_id": replacement_id,
            "rule": event.payload.get("rule", cluster.rule),
            "classification": cluster.classification,
            "relation": "replacement_for",
            "replaces_pattern_id": cluster.pattern_id,
        }
        replacement = _event(
            "pattern.revised",
            cluster,
            event.occurred_at,
            policy,
            "MEANING_REVERSING_REPLACEMENT",
            replacement_payload,
            old_version=cluster.revision,
            new_version=cluster.revision + 1,
        )
        superseded = _event(
            "pattern.superseded",
            cluster,
            event.occurred_at,
            policy,
            "MEANING_REVERSING_REPLACEMENT",
            {
                "pattern_id": cluster.pattern_id,
                "replacement_pattern_id": replacement_id,
                "replacement_active": False,
            },
            old_version=cluster.revision,
            new_version=cluster.revision,
        )
        return replacement, superseded
    return (event,)


def evaluate_lifecycle(
    state: ClusterState,
    policy: PromotionPolicy,
    now_utc: datetime | str | None = None,
) -> list[Event]:
    """Evaluate lifecycle transitions without reading wall-clock state internally."""
    timestamp = _timestamp(now_utc, state.last_used_at or state.deprecated_at or "1970-01-01T00:00:00+00:00")
    now = _parse_timestamp(timestamp) or datetime(1970, 1, 1, tzinfo=timezone.utc)

    if state.status == "active" and len(state.contradiction_provenances) >= policy.contradiction_count_for_deprecation:
        return [
            _event(
                "pattern.deprecated",
                state,
                timestamp,
                policy,
                "THREE_INDEPENDENT_CONTRADICTIONS",
                {"pattern_id": state.pattern_id},
            )
        ]

    if (
        state.status == "active"
        and state.benefit_count == 0
        and _inactive_long_enough(state, now, policy.unused_days_for_deprecation)
    ):
        return [
            _event(
                "pattern.deprecated",
                state,
                timestamp,
                policy,
                "STALE_NO_BENEFIT",
                {"pattern_id": state.pattern_id},
            )
        ]

    if _promotion_ready(state, policy):
        pattern_id = state.pattern_id or "pat_" + stable_hash(state.cluster_id)[:20]
        return [
            _event(
                "pattern.promoted",
                state,
                timestamp,
                policy,
                "PROMOTION_ELIGIBLE",
                {
                    "pattern_id": pattern_id,
                    "rule": state.rule,
                    "provenances": sorted(state.provenances),
                    "scopes": sorted(state.scopes),
                    "benefit_count": state.benefit_count,
                    "classification": state.classification,
                    "applicability": list(state.applicability),
                },
            )
        ]

    if state.pattern_id and not state.pinned and not state.legal_hold and not state.contradiction_provenances:
        if (
            state.status == "superseded"
            and state.replacement_active
            and state.superseded_by
            and state.exposure_count == 0
            and _inactive_long_enough(state, now, policy.superseded_unused_days_for_tombstone)
        ):
            return [
                _event(
                    "pattern.tombstoned",
                    state,
                    timestamp,
                    policy,
                    "SUPERSEDED_INACTIVE",
                    {"pattern_id": state.pattern_id, "replacement": state.superseded_by},
                )
            ]
        if (
            state.status == "deprecated"
            and state.exposure_count == 0
            and _inactive_long_enough(state, now, policy.deprecated_unused_days_for_tombstone)
        ):
            return [
                _event(
                    "pattern.tombstoned",
                    state,
                    timestamp,
                    policy,
                    "DEPRECATED_INACTIVE",
                    {"pattern_id": state.pattern_id},
                )
            ]
    return []


__all__ = [
    "apply_lifecycle_transition",
    "choose_always_on",
    "evaluate_lifecycle",
    "promotion_eligibility",
    "select_always_on",
    "utility_score",
]
