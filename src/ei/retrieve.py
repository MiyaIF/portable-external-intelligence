from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, is_dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .dedup import claim_fingerprint as normalize_claim_fingerprint
from .dedup import tokenize_similarity
from .models import (
    HOST_APPLICABILITY_FIELDS,
    KnowledgeIndex,
    PatternState,
    RetrievalHit,
    validate_host_applicability_mapping,
)


@dataclass(frozen=True)
class RetrievalQuery:
    """Privacy-safe query descriptor; never persist the prompt field."""

    prompt: str = ""
    cwd_fingerprint: str = ""
    domain: str = ""
    now_utc: str | None = None
    scope_tags: tuple[str, ...] = ()
    host_id: str = ""
    host_family: str = ""
    version: str = ""
    query_text: str = ""
    cwd_hash: str = ""
    now: datetime | str | None = None
    max_chars: int = 5000

    @property
    def text(self) -> str:
        return self.prompt or self.query_text

    @property
    def effective_cwd(self) -> str:
        return self.cwd_fingerprint or self.cwd_hash

    @property
    def effective_now(self) -> str | None:
        if self.now_utc:
            return self.now_utc
        if isinstance(self.now, datetime):
            return self.now.isoformat()
        return self.now


@dataclass(frozen=True)
class RetrievalPolicy:
    lexical_relevance: float = 0.35
    scope_match: float = 0.20
    evidence_strength: float = 0.15
    freshness: float = 0.10
    observed_benefit: float = 0.10
    min_score: float = 0.35
    max_results: int = 5
    max_chars: int = 5000
    host_applicability: float = 0.05
    prior_success: float = 0.05
    policy_version: str = "retrieval-v1"
    freshness_half_life_days: int = 365
    allow_cross_host: bool = False
    include_tombstones: bool = False

    def __post_init__(self) -> None:
        weights = (
            self.lexical_relevance,
            self.scope_match,
            self.evidence_strength,
            self.freshness,
            self.observed_benefit,
            self.host_applicability,
            self.prior_success,
        )
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 for value in weights):
            raise ValueError("RETRIEVAL_WEIGHT_INVALID")
        if self.max_results < 1 or self.max_chars < 1 or self.freshness_half_life_days < 1:
            raise ValueError("RETRIEVAL_LIMIT_INVALID")
        if not isinstance(self.policy_version, str) or not self.policy_version:
            raise ValueError("RETRIEVAL_POLICY_VERSION_INVALID")

    @classmethod
    def defaults(cls) -> "RetrievalPolicy":
        return cls()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RetrievalPolicy":
        aliases = {
            "maximum_results": "max_results",
            "maximum_context_chars": "max_chars",
            "minimum_score": "min_score",
        }
        values: dict[str, Any] = {}
        for field_name in cls.__dataclass_fields__:
            if field_name in data:
                values[field_name] = data[field_name]
        for source, target in aliases.items():
            if source in data and target not in values:
                values[target] = data[source]
        return cls(**values)

    @property
    def maximum_results(self) -> int:
        return self.max_results

    @property
    def maximum_context_chars(self) -> int:
        return self.max_chars

    @property
    def minimum_score(self) -> float:
        return self.min_score


@dataclass(frozen=True)
class ExposureRecord:
    exposure_id: str
    experiment_id: str = ""
    session_id_hash: str = ""
    arm: str = "treatment"
    selected_ids: tuple[str, ...] = ()
    query_fingerprint: str = ""
    injection_chars: int = 0
    retrieval_latency_ms: int = 0
    host_id: str = ""
    recorded_at: str | datetime = ""
    candidate_ids: tuple[str, ...] = ()
    candidate_scopes: tuple[str, ...] = ()
    selected_scopes: tuple[str, ...] = ()
    empty_result: bool = False
    team_unavailable: bool = False
    scope: str = ""

    @property
    def selected_pattern_ids(self) -> tuple[str, ...]:
        return self.selected_ids


def _pattern_mapping(pattern: PatternState | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(pattern, Mapping):
        return pattern
    if isinstance(pattern, PatternState):
        return {
            "pattern_id": pattern.pattern_id,
            "cluster_id": pattern.cluster_id or pattern.pattern_id,
            "rule": pattern.rule,
            "precondition": pattern.precondition,
            "scope": pattern.scope,
            "evidence_ids": pattern.evidence_ids,
            "benefit_refs": pattern.benefit_refs,
            "version_constraint": pattern.version_constraint,
            "status": pattern.status,
            "classification": pattern.classification,
            "utility": pattern.utility,
            "applicability": pattern.applicability,
            "updated_at": pattern.updated_at,
            "contradiction_count": pattern.contradiction_count,
            "pinned": pattern.pinned,
            "legal_hold": pattern.legal_hold,
            "source_host_id": pattern.source_host_id,
            "source_host_family": pattern.source_host_family,
            "applicability_scope": pattern.applicability_scope,
            "applicable_host_ids": pattern.applicable_host_ids,
            "applicable_host_families": pattern.applicable_host_families,
        }
    raise TypeError("PATTERN_REQUIRED")


def _as_tokens(value: object) -> frozenset[str]:
    if value is None:
        return frozenset()
    return tokenize_similarity(str(value))


def _values(pattern: Mapping[str, Any], *names: str) -> tuple[str, ...]:
    result: list[str] = []
    for name in names:
        value = pattern.get(name, ())
        if isinstance(value, str):
            value = (value,)
        if isinstance(value, (tuple, list, set, frozenset)):
            result.extend(str(item) for item in value if str(item).strip())
    return tuple(dict.fromkeys(result))


def _parse_date(value: object) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def _scope_score(query: RetrievalQuery, pattern: Mapping[str, Any]) -> float:
    cwd_values = set(_values(pattern, "cwd_fingerprints", "cwd_hashes", "scopes"))
    applicability = set(_values(pattern, "applicability", "scope_tags", "domains"))
    query_scope = set(query.scope_tags)
    score = 0.0
    if query.effective_cwd and query.effective_cwd in cwd_values:
        score = 1.0
    if query.domain and query.domain in applicability:
        score = max(score, 0.90)
    if query_scope and applicability.intersection(query_scope):
        score = max(score, 0.80)
    if not cwd_values and not applicability:
        score = 0.50
    return score


def _scope_allowed(query: RetrievalQuery, pattern: Mapping[str, Any]) -> bool:
    cwd_values = set(_values(pattern, "cwd_fingerprints", "cwd_hashes"))
    applicability = set(_values(pattern, "applicability", "scope_tags", "domains"))
    if query.effective_cwd and cwd_values and query.effective_cwd not in cwd_values:
        return False
    if query.domain and applicability and query.domain not in applicability and "general" not in applicability:
        return False
    if query.scope_tags and applicability and not applicability.intersection(query.scope_tags) and "general" not in applicability:
        return False
    return True


def _host_values(pattern: Mapping[str, Any]) -> set[str]:
    return set(_values(pattern, "host_ids", "hosts", "host_applicability"))


_LEGACY_HOST_SELECTOR_FIELDS = ("host_ids", "hosts", "host_applicability")


def _new_host_scope_present(pattern: Mapping[str, Any]) -> bool:
    return any(field in pattern for field in HOST_APPLICABILITY_FIELDS)


def _legacy_host_selector_nonempty(pattern: Mapping[str, Any]) -> bool:
    for field in _LEGACY_HOST_SELECTOR_FIELDS:
        if field not in pattern:
            continue
        value = pattern.get(field)
        if value is None:
            continue
        if isinstance(value, str):
            if value.strip():
                return True
            continue
        if isinstance(value, (tuple, list, set, frozenset)):
            if value:
                return True
            continue
        return True
    return False


def _legacy_default_host_scope(pattern: Mapping[str, Any]) -> bool:
    return (
        pattern.get("source_host_id") == ""
        and pattern.get("source_host_family") == ""
        and pattern.get("applicability_scope") == "universal"
        and isinstance(pattern.get("applicable_host_ids"), (tuple, list))
        and not pattern.get("applicable_host_ids")
        and isinstance(pattern.get("applicable_host_families"), (tuple, list))
        and not pattern.get("applicable_host_families")
    )


def _validated_host_scope(pattern: Mapping[str, Any]):
    if not all(field in pattern for field in HOST_APPLICABILITY_FIELDS):
        return None
    if _legacy_host_selector_nonempty(pattern):
        return None
    try:
        return validate_host_applicability_mapping(pattern, require_source_pair=True)
    except (TypeError, ValueError):
        if not _legacy_default_host_scope(pattern):
            return None
        try:
            # Pre-feature PatternState/index compatibility has no trusted
            # source identity; preserve its universal read behavior without
            # inventing one.
            return validate_host_applicability_mapping(pattern, require_source_pair=False)
        except (TypeError, ValueError):
            return None


def host_scope_allowed(
    query: RetrievalQuery,
    pattern: PatternState | Mapping[str, Any],
) -> bool:
    """Return whether a pattern's explicit host applicability permits recall."""

    mapped = _pattern_mapping(pattern)
    if _new_host_scope_present(mapped):
        scope = _validated_host_scope(mapped)
        if scope is None:
            return False
        if scope.scope == "universal":
            return True
        if scope.scope == "family":
            return bool(query.host_family) and query.host_family in scope.host_families
        return bool(query.host_id) and query.host_id in scope.host_ids

    # Legacy records only have host_ids/hosts/host_applicability.  A record
    # without those fields has always been universal.
    hosts = _host_values(mapped)
    return not hosts or (bool(query.host_id) and query.host_id in hosts)


def _host_allowed(query: RetrievalQuery, pattern: Mapping[str, Any], policy: RetrievalPolicy) -> bool:
    if _new_host_scope_present(pattern):
        # The explicit applicability contract is authoritative; the legacy
        # cross-host escape hatch must not widen it.
        return host_scope_allowed(query, pattern)
    if host_scope_allowed(query, pattern):
        return True
    # Preserve the old host_ids contract, including the policy's optional
    # cross-host allowance.  Hostless legacy patterns remain universal.
    return bool(_host_values(pattern)) and policy.allow_cross_host


def _host_score(query: RetrievalQuery, pattern: Mapping[str, Any]) -> float:
    hosts = _host_values(pattern)
    if not hosts:
        return 1.0
    return 1.0 if query.host_id and query.host_id in hosts else 0.0


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.search(r"\d+(?:\.\d+)*", value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _version_allowed(query: RetrievalQuery, pattern: Mapping[str, Any]) -> bool:
    constraint = pattern.get("version_constraint") or pattern.get("version")
    if not constraint:
        return True
    if not query.version:
        return False
    actual = _version_tuple(query.version)
    if actual is None:
        return False
    for raw_part in str(constraint).split(","):
        part = raw_part.strip()
        if not part:
            continue
        operator = "=="
        for candidate in (">=", "<=", "!=", ">", "<", "="):
            if part.startswith(candidate):
                operator = candidate
                part = part[len(candidate):].strip()
                break
        if part.endswith(".*") or part.casefold().endswith(".x"):
            prefix = part[:-2]
            expected = _version_tuple(prefix)
            if expected is None or actual[: len(expected)] != expected:
                return False
            continue
        expected = _version_tuple(part)
        if expected is None:
            return False
        left = actual[: max(len(actual), len(expected))]
        right = expected + (0,) * max(0, len(actual) - len(expected))
        if operator in {"=", "=="} and left != right:
            return False
        if operator == "!=" and left == right:
            return False
        if operator == ">=" and left < right:
            return False
        if operator == "<=" and left > right:
            return False
        if operator == ">" and left <= right:
            return False
        if operator == "<" and left >= right:
            return False
    return True


def _freshness_score(query: RetrievalQuery, pattern: Mapping[str, Any], latest: datetime, half_life_days: int) -> float:
    updated = _parse_date(pattern.get("updated_at"))
    if updated is None:
        return 0.0
    reference = _parse_date(query.effective_now) or latest
    age_days = max(0.0, (reference - updated.astimezone(timezone.utc)).total_seconds() / 86400.0)
    return 0.5 ** (age_days / max(1, half_life_days))


def _bm25(query_tokens: frozenset[str], document_tokens: frozenset[str], average_length: float) -> float:
    if not query_tokens or not document_tokens:
        return 0.0
    overlap = len(query_tokens & document_tokens)
    if not overlap:
        return 0.0
    length_ratio = len(document_tokens) / max(average_length, 1.0)
    return overlap * (2.2 / (1.0 + 1.2 * (0.25 + 0.75 * length_ratio)))


def _numeric(pattern: Mapping[str, Any], *names: str, default: float = 0.0) -> float:
    for name in names:
        value = pattern.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return default


def _claim_fingerprint(pattern: Mapping[str, Any]) -> str:
    claim = pattern.get("claim") or pattern.get("rule") or pattern.get("title") or ""
    return "sha256:" + normalize_claim_fingerprint(str(claim))


def _eligible(query: RetrievalQuery, pattern: Mapping[str, Any], policy: RetrievalPolicy) -> bool:
    pattern_id = pattern.get("pattern_id")
    if not isinstance(pattern_id, str) or not pattern_id:
        return False
    status = str(pattern.get("status", "active")).casefold()
    # Tombstones are historical records and never enter operational recall.
    if status in {"deprecated", "tombstoned", "superseded", "inactive", "archived"}:
        return False
    classification = str(pattern.get("classification", "private-reusable"))
    if classification not in {"public", "private-reusable"}:
        return False
    contradiction_count = _numeric(pattern, "contradiction_count", default=0)
    if contradiction_count > 0:
        return False
    return _scope_allowed(query, pattern) and _host_allowed(query, pattern, policy) and _version_allowed(query, pattern)


def _rank_patterns(
    query: RetrievalQuery,
    patterns: Iterable[PatternState | Mapping[str, Any]] | KnowledgeIndex,
    policy: RetrievalPolicy | None = None,
    *,
    result_limit: int | None,
    knowledge_scope: str = "personal",
) -> list[RetrievalHit]:
    policy = policy or RetrievalPolicy.defaults()
    if isinstance(patterns, KnowledgeIndex):
        return search_index(patterns, query, policy)
    eligible: list[Mapping[str, Any]] = []
    for raw_pattern in patterns:
        pattern = _pattern_mapping(raw_pattern)
        if _eligible(query, pattern, policy):
            eligible.append(pattern)
    if not eligible:
        return []
    tokenized = []
    for pattern in eligible:
        text = " ".join(str(pattern.get(name, "")) for name in ("rule", "title", "claim", "domain"))
        tokenized.append((pattern, _as_tokens(text)))
    average_length = sum(len(tokens) for _, tokens in tokenized) / max(1, len(tokenized))
    query_tokens = _as_tokens(query.text)
    dates = [parsed for pattern in eligible if (parsed := _parse_date(pattern.get("updated_at"))) is not None]
    latest = max(dates, default=datetime(1970, 1, 1, tzinfo=timezone.utc))
    scored: list[tuple[float, Mapping[str, Any]]] = []
    for pattern, document_tokens in tokenized:
        lexical_raw = _bm25(query_tokens, document_tokens, average_length)
        lexical = lexical_raw / (lexical_raw + 1.0) if lexical_raw else 0.0
        scope = _scope_score(query, pattern)
        evidence_count = int(max(0, _numeric(pattern, "evidence_count", default=len(_values(pattern, "provenances", "evidence_ids")))))
        evidence = min(1.0, evidence_count / 2.0)
        freshness = _freshness_score(query, pattern, latest, policy.freshness_half_life_days)
        benefit_count = _numeric(pattern, "benefit_count", default=0)
        benefit = 1.0 if benefit_count > 0 or pattern.get("observed_benefit") or _values(pattern, "benefit_refs") else 0.0
        host = _host_score(query, pattern)
        prior = max(0.0, min(1.0, _numeric(pattern, "prior_success", "success_rate", "outcome_success_rate", default=0.0)))
        contradiction_penalty = min(1.0, _numeric(pattern, "contradiction_count", default=0) / 3.0)
        stale_penalty = 0.10 if freshness == 0.0 else 0.0
        score = (
            policy.lexical_relevance * lexical
            + policy.scope_match * scope
            + policy.evidence_strength * evidence
            + policy.freshness * freshness
            + policy.observed_benefit * benefit
            + policy.host_applicability * host
            + policy.prior_success * prior
            - contradiction_penalty
            - stale_penalty
        )
        if score >= policy.min_score:
            scored.append((score, pattern))

    best_by_cluster: dict[str, tuple[float, Mapping[str, Any]]] = {}
    for score, pattern in scored:
        cluster_id = str(pattern.get("cluster_id") or pattern.get("pattern_id"))
        current = best_by_cluster.get(cluster_id)
        pattern_id = str(pattern.get("pattern_id"))
        if current is None or score > current[0] or (math.isclose(score, current[0], abs_tol=1e-12) and pattern_id < str(current[1].get("pattern_id"))):
            best_by_cluster[cluster_id] = (score, pattern)

    ranked = sorted(
        best_by_cluster.values(),
        key=lambda item: (-round(item[0], 12), str(item[1].get("pattern_id", "")), str(item[1].get("cluster_id", ""))),
    )
    if result_limit is not None:
        ranked = ranked[:result_limit]
    result: list[RetrievalHit] = []
    for score, pattern in ranked:
        applicability = _values(pattern, "applicability", "scope_tags", "domains")
        evidence_count = int(max(0, _numeric(pattern, "evidence_count", default=len(_values(pattern, "provenances", "evidence_ids")))))
        result.append(
            RetrievalHit(
                pattern_id=str(pattern.get("pattern_id", "")),
                cluster_id=str(pattern.get("cluster_id") or pattern.get("pattern_id", "")),
                score=round(score, 6),
                rule=str(pattern.get("rule", "")),
                applicability=applicability,
                evidence_count=evidence_count,
                updated_at=str(pattern.get("updated_at", "")),
                knowledge_scope=knowledge_scope if knowledge_scope in {"personal", "team"} else "personal",
                claim_fingerprint=str(pattern.get("claim_fingerprint") or _claim_fingerprint(pattern)),
                supersedes=_values(pattern, "supersedes", "superseded_by"),
                precondition=str(pattern.get("precondition", "") or ""),
                failure_mode=str(pattern.get("failure_mode", "") or ""),
            )
        )
    return result


def rank_patterns(
    query: RetrievalQuery,
    patterns: Iterable[PatternState | Mapping[str, Any]] | KnowledgeIndex,
    policy: RetrievalPolicy | None = None,
) -> list[RetrievalHit]:
    """Rank patterns using the policy's result limit (legacy API)."""

    policy = policy or RetrievalPolicy.defaults()
    return _rank_patterns(query, patterns, policy, result_limit=policy.max_results)


def search_index(index: KnowledgeIndex, query: RetrievalQuery, policy: RetrievalPolicy | None = None) -> list[RetrievalHit]:
    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    from .index import read_index_items

    patterns = read_index_items(index, list(index.active_pattern_ids) or None)
    selected_policy = policy or RetrievalPolicy.defaults()
    return _rank_patterns(query, patterns, selected_policy, result_limit=selected_policy.max_results)


def search_index_candidates(
    index: KnowledgeIndex,
    query: RetrievalQuery,
    policy: RetrievalPolicy | None = None,
    *,
    knowledge_scope: str = "personal",
) -> list[RetrievalHit]:
    """Return all eligible ranked candidates before the final merged limit."""

    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    selected_policy = policy or RetrievalPolicy.defaults()
    from .index import read_index_items

    patterns = read_index_items(index, list(index.active_pattern_ids) or None)
    return _rank_patterns(
        query,
        patterns,
        selected_policy,
        result_limit=None,
        knowledge_scope=knowledge_scope,
    )


def _hit_key(hit: RetrievalHit) -> tuple[str, str]:
    """Return the stable identity used for exact pattern-id deduplication."""

    return ("pattern", str(hit.pattern_id))


def _normalised_rule_fingerprint(hit: RetrievalHit) -> str:
    """Normalize the claim/rule material before comparing personal and team hits."""

    text = str(hit.rule or "")
    if text:
        return "sha256:" + normalize_claim_fingerprint(text)
    supplied = str(hit.claim_fingerprint or "").strip().casefold()
    if supplied.startswith("sha256:"):
        supplied = supplied.removeprefix("sha256:")
    return "sha256:" + (supplied or normalize_claim_fingerprint(""))


def _hit_fingerprints(hit: RetrievalHit) -> frozenset[str]:
    """Return normalized comparison keys for rule and producer-supplied claim."""

    fingerprints = {_normalised_rule_fingerprint(hit)}
    supplied = str(hit.claim_fingerprint or "").strip().casefold()
    if supplied:
        if supplied.startswith("sha256:"):
            supplied = supplied.removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", supplied):
            supplied = normalize_claim_fingerprint(supplied)
        fingerprints.add("sha256:" + supplied)
    return frozenset(fingerprints)


def _supersedes_relation(left: RetrievalHit, right: RetrievalHit) -> bool:
    left_targets = set(left.supersedes)
    right_targets = set(right.supersedes)
    return str(left.pattern_id) in right_targets or str(right.pattern_id) in left_targets


def merge_retrieval_hits(
    personal_hits: Iterable[RetrievalHit],
    team_hits: Iterable[RetrievalHit],
    policy: RetrievalPolicy | None = None,
) -> list[RetrievalHit]:
    """Merge scopes under one result budget with a deterministic personal tie-break."""

    selected_policy = policy or RetrievalPolicy.defaults()
    candidates: list[RetrievalHit] = []
    for expected_scope, source in (("personal", personal_hits), ("team", team_hits)):
        for hit in source:
            if not isinstance(hit, RetrievalHit):
                raise TypeError("RETRIEVAL_HIT_REQUIRED")
            # The rule is the only claim text carried by a retrieval hit.  Always
            # derive the comparison fingerprint from its normalized form when it
            # is available; a producer-supplied fingerprint is retained only for
            # hits that do not carry rule text.
            supplied = str(hit.claim_fingerprint or "").strip().casefold()
            if supplied:
                if supplied.startswith("sha256:"):
                    supplied = supplied.removeprefix("sha256:")
                if not re.fullmatch(r"[0-9a-f]{64}", supplied):
                    supplied = normalize_claim_fingerprint(supplied)
                fingerprint = "sha256:" + supplied
            else:
                fingerprint = _normalised_rule_fingerprint(hit)
            candidates.append(replace(hit, knowledge_scope=expected_scope, claim_fingerprint=fingerprint))
    ordered = sorted(
        candidates,
        key=lambda hit: (
            -round(float(hit.score), 12),
            0 if hit.knowledge_scope == "personal" else 1,
            str(hit.pattern_id),
            str(hit.cluster_id),
        ),
    )
    groups: list[list[RetrievalHit]] = []
    for hit in ordered:
        matches = [
            group
            for group in groups
            if any(
                _hit_key(hit) == _hit_key(member)
                or bool(_hit_fingerprints(hit) & _hit_fingerprints(member))
                or _supersedes_relation(hit, member)
                for member in group
            )
        ]
        if not matches:
            groups.append([hit])
            continue
        target = matches[0]
        target.append(hit)
        for other in matches[1:]:
            target.extend(other)
            groups.remove(other)
    winners: list[RetrievalHit] = []
    for group in groups:
        winners.append(
            min(
                group,
                key=lambda hit: (
                    -round(float(hit.score), 12),
                    0 if hit.knowledge_scope == "personal" else 1,
                    str(hit.pattern_id),
                    str(hit.cluster_id),
                ),
            )
        )
    merged = sorted(
        winners,
        key=lambda hit: (
            -round(float(hit.score), 12),
            0 if hit.knowledge_scope == "personal" else 1,
            str(hit.pattern_id),
            str(hit.cluster_id),
        ),
    )
    return merged[: selected_policy.max_results]


def _exposure_dict(exposure: ExposureRecord | Mapping[str, Any]) -> dict[str, Any]:
    forbidden = {"prompt", "query", "query_text", "raw_query", "raw_prompt", "context", "additional_context", "response"}
    if isinstance(exposure, Mapping):
        if forbidden.intersection(exposure):
            raise ValueError("EXPOSURE_RAW_TEXT_FORBIDDEN")
        source = dict(exposure)
    elif is_dataclass(exposure):
        source = {field: getattr(exposure, field) for field in exposure.__dataclass_fields__}
    else:
        raise TypeError("EXPOSURE_RECORD_REQUIRED")
    required = {"exposure_id", "query_fingerprint"}
    if not all(isinstance(source.get(key), str) and source[key] for key in required):
        raise ValueError("EXPOSURE_FIELDS_INVALID")
    selected = source.get("selected_ids", source.get("selected_pattern_ids", ()))
    if isinstance(selected, str) or not isinstance(selected, (tuple, list, set, frozenset)):
        raise ValueError("EXPOSURE_SELECTED_IDS_INVALID")
    raw_candidates = source.get("candidate_ids") or selected
    if isinstance(raw_candidates, str) or not isinstance(raw_candidates, (tuple, list, set, frozenset)):
        raise ValueError("EXPOSURE_CANDIDATE_IDS_INVALID")
    candidate_ids = sorted({str(item) for item in raw_candidates if str(item)})
    selected_ids = sorted({str(item) for item in selected if str(item)})

    def _scopes(raw: object, count: int, field_name: str) -> list[str]:
        if raw in (None, (), [], ""):
            return ["personal"] * count
        if isinstance(raw, str) or not isinstance(raw, (tuple, list, set, frozenset)):
            raise ValueError(f"EXPOSURE_{field_name.upper()}_INVALID")
        values = [str(item) for item in raw]
        if len(values) != count or any(item not in {"personal", "team"} for item in values):
            raise ValueError(f"EXPOSURE_{field_name.upper()}_INVALID")
        return values

    candidate_scopes = _scopes(source.get("candidate_scopes"), len(candidate_ids), "candidate_scopes")
    explicit_selected_scopes = source.get("selected_scopes")
    if explicit_selected_scopes not in (None, (), [], ""):
        selected_scopes = _scopes(explicit_selected_scopes, len(selected_ids), "selected_scopes")
    else:
        scope_by_id = dict(zip(candidate_ids, candidate_scopes))
        selected_scopes = [scope_by_id.get(item, "personal") for item in selected_ids]
    scope_values = set(candidate_scopes)
    scope = str(source.get("scope") or (next(iter(scope_values)) if len(scope_values) == 1 else "mixed" if scope_values else "personal"))
    if scope not in {"personal", "team", "mixed"}:
        raise ValueError("EXPOSURE_SCOPE_INVALID")
    allowed = {
        "exposure_id",
        "experiment_id",
        "session_id_hash",
        "arm",
        "candidate_ids",
        "selected_ids",
        "query_fingerprint",
        "injection_chars",
        "retrieval_latency_ms",
        "host_id",
        "recorded_at",
        "candidate_scopes",
        "selected_scopes",
        "empty_result",
        "team_unavailable",
        "scope",
    }
    result = {key: source.get(key, "") for key in allowed}
    result["candidate_ids"] = candidate_ids
    result["selected_ids"] = selected_ids
    result["candidate_scopes"] = candidate_scopes
    result["selected_scopes"] = selected_scopes
    result["empty_result"] = bool(source.get("empty_result", not candidate_ids))
    result["team_unavailable"] = bool(source.get("team_unavailable", False))
    result["scope"] = scope
    for key in ("injection_chars", "retrieval_latency_ms"):
        try:
            value = int(result[key] or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("EXPOSURE_METRIC_INVALID") from exc
        if value < 0:
            raise ValueError("EXPOSURE_METRIC_INVALID")
        result[key] = value
    if not result["recorded_at"]:
        result["recorded_at"] = datetime.now(timezone.utc).isoformat()
    elif isinstance(result["recorded_at"], datetime):
        if result["recorded_at"].tzinfo is None:
            raise ValueError("EXPOSURE_TIMESTAMP_INVALID")
        result["recorded_at"] = result["recorded_at"].isoformat()
    elif not isinstance(result["recorded_at"], str):
        raise ValueError("EXPOSURE_TIMESTAMP_INVALID")
    return {key: result[key] for key in sorted(result)}


def record_retrieval_exposure(exposure: ExposureRecord | Mapping[str, Any], path: Path) -> None:
    payload = _exposure_dict(exposure)

    line = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(str(target), flags, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "ExposureRecord",
    "RetrievalPolicy",
    "RetrievalQuery",
    "host_scope_allowed",
    "rank_patterns",
    "search_index_candidates",
    "merge_retrieval_hits",
    "record_retrieval_exposure",
    "search_index",
]
