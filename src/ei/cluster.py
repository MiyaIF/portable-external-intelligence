from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .dedup import (
    alias_match,
    claim_fingerprint,
    classify_polarity,
    extract_outcome,
    extract_version,
    is_independent,
    similarity,
    tokenize_similarity,
)
from .models import ClusterState, ObservationState


@dataclass(frozen=True)
class ClusterDecision:
    kind: str
    target_observation_id: str | None
    similarity: float
    independent_provenance: bool
    contradiction_reason: str | None = None
    matched_alias: bool = False

    @property
    def evidence_action(self) -> str:
        return "ATTACH_EVIDENCE" if self.kind == "duplicate" else self.kind.upper()


def _field(value: object, name: str, default: object = "") -> object:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _claim(value: object) -> str:
    claim = _field(value, "claim", _field(value, "canonical_claim", ""))
    return claim if isinstance(claim, str) else ""


def _observation_id(value: object) -> str:
    identifier = _field(value, "observation_id", _field(value, "cluster_id", ""))
    return identifier if isinstance(identifier, str) else str(identifier)


def _domain(value: object) -> str:
    domain = _field(value, "domain", "")
    return domain.strip().casefold() if isinstance(domain, str) else ""


def _version(value: object) -> str | None:
    explicit = _field(value, "version_constraint", None)
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().casefold()
    claim = _claim(value)
    return extract_version(claim)


def _outcome(value: object) -> str | None:
    explicit = _field(value, "outcome_status", None)
    result = extract_outcome(explicit)
    return result or extract_outcome(_claim(value))


def _contradiction_reason(left: object, right: object) -> str | None:
    left_polarity = classify_polarity(_claim(left))
    right_polarity = classify_polarity(_claim(right))
    if {left_polarity, right_polarity} == {"SUPPORTS", "CONTRADICTS"}:
        return "POLARITY_OPPOSITION"
    left_version = _version(left)
    right_version = _version(right)
    if left_version and right_version and left_version != right_version:
        return "INCOMPATIBLE_VERSION"
    left_outcome = _outcome(left)
    right_outcome = _outcome(right)
    if left_outcome and right_outcome and left_outcome != right_outcome:
        return "OPPOSITE_OUTCOME"
    return None


def _threshold(left: object, right: object) -> float:
    return 0.72 if _domain(left) and _domain(left) == _domain(right) else 0.82


def _candidate_observation(value: object) -> object:
    if isinstance(value, ClusterState):
        return {
            "observation_id": value.cluster_id,
            "claim": value.canonical_claim or value.rule,
            "domain": value.provenance_scopes[0] if value.provenance_scopes else "",
            "provenance_key": next(iter(value.provenances), ""),
            "cwd_fingerprint": "",
            "classification": value.classification,
            "source_host_id": value.source_host_id,
            "source_host_family": value.source_host_family,
            "applicability_scope": value.applicability_scope,
            "applicable_host_ids": list(value.applicable_host_ids),
            "applicable_host_families": list(value.applicable_host_families),
        }
    return value


def assign_cluster(observation: ObservationState, existing: Iterable[ObservationState | ClusterState]) -> ClusterDecision:
    """Find the deterministic target cluster while preserving contradictions."""
    incoming_claim = _claim(observation)
    if not incoming_claim:
        return ClusterDecision("new", None, 0.0, True)
    incoming_fingerprint = claim_fingerprint(incoming_claim)
    best: tuple[float, int, int, str, object] | None = None
    for raw_candidate in existing:
        candidate = _candidate_observation(raw_candidate)
        candidate_claim = _claim(candidate)
        if not candidate_claim:
            continue
        candidate_fingerprint = claim_fingerprint(candidate_claim)
        exact = incoming_fingerprint == candidate_fingerprint
        matched_alias = alias_match(incoming_claim, candidate_claim)
        score = 1.0 if exact else similarity(incoming_claim, candidate_claim)
        qualifies = exact or matched_alias or score >= _threshold(observation, candidate)
        if not qualifies:
            continue
        key = (
            score,
            1 if exact else 0,
            1 if matched_alias else 0,
            _observation_id(candidate),
            candidate,
        )
        if best is None or key[:4] > best[:4]:
            best = key
    if best is None:
        return ClusterDecision("new", None, 0.0, True)
    score, exact_rank, alias_rank, _, candidate = best
    del exact_rank, alias_rank
    independent = is_independent(observation, candidate)
    target_id = _observation_id(candidate)
    if claim_fingerprint(_claim(candidate)) == incoming_fingerprint:
        return ClusterDecision("duplicate", target_id, score, independent, matched_alias=alias_match(incoming_claim, _claim(candidate)))
    contradiction_reason = _contradiction_reason(observation, candidate)
    if contradiction_reason is not None:
        return ClusterDecision(
            "contradiction",
            target_id,
            score,
            independent,
            contradiction_reason=contradiction_reason,
            matched_alias=alias_match(incoming_claim, _claim(candidate)),
        )
    return ClusterDecision(
        "join",
        target_id,
        score,
        independent,
        matched_alias=alias_match(incoming_claim, _claim(candidate)),
    )


def cluster_polarity(claims: Iterable[str]) -> str:
    labels = {classify_polarity(claim) for claim in claims if isinstance(claim, str) and claim}
    if not labels:
        return "MIXED"
    if len(labels) == 1:
        return next(iter(labels))
    return "MIXED"


def _alias_overlap(left: ObservationState, right: ObservationState) -> bool:
    return alias_match(left.claim, right.claim)


def _threshold_for_domains(left_domain: str, right_domain: str) -> float:
    return 0.72 if left_domain and left_domain == right_domain else 0.82


__all__ = [
    "ClusterDecision",
    "assign_cluster",
    "cluster_polarity",
]
