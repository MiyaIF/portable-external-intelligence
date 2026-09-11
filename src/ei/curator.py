from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .changeset import ChangeOperation, ChangeSet
from .dedup import alias_match, classify_polarity, normalize_claim, similarity
from .gate import GateDecision
from .index import read_index_items
from .models import HostApplicability, KnowledgeIndex, PromotionPolicy, validate_host_applicability_mapping, validate_host_label
from .privacy import inspect_text
from .ids import stable_hash


_WRITABLE = frozenset({"public", "private-reusable"})
_SAFE_REASON = re.compile(r"^[A-Z0-9_.:-]{1,80}$")
_SAFE_HOST_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_HOST_SCOPES = frozenset({"universal", "family", "host"})
_MAX_HOST_TARGETS = 16


def _host_label(value: Any) -> str | None:
    try:
        return validate_host_label(value)
    except ValueError:
        return None


def _host_labels(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, (list, tuple)):
        return None
    result: list[str] = []
    for item in value:
        label = _host_label(item)
        if label is None:
            return None
        if label in result:
            return None
        result.append(label)
    if len(result) > _MAX_HOST_TARGETS:
        return None
    return tuple(sorted(result))


def normalize_host_applicability(
    data: Mapping[str, Any],
    *,
    source_host_id: str,
    source_host_family: str,
) -> HostApplicability:
    """Normalize provider/applicant scope and fail closed to the source host."""

    source_id = _host_label(source_host_id) or ""
    source_family = _host_label(source_host_family) or ""
    # A source-host fallback is safe only when the trusted source pair is
    # complete.  Legacy callers may have no pair at all; keep that projection
    # universal rather than emitting an invalid host scope with no target.
    fallback = (
        HostApplicability("host", (source_id,), ())
        if source_id and source_family
        else HostApplicability("universal", (), ())
    )
    if not isinstance(data, Mapping):
        return fallback
    scope = data.get("applicability_scope")
    if not isinstance(scope, str) or scope not in _HOST_SCOPES:
        return fallback
    if scope == "universal" and ("applicable_host_ids" not in data or "applicable_host_families" not in data):
        return fallback
    ids = _host_labels(data.get("applicable_host_ids", ()))
    families = _host_labels(data.get("applicable_host_families", ()))
    if ids is None or families is None:
        return fallback
    if scope == "universal":
        if ids or families:
            return fallback
        return HostApplicability("universal", (), ())
    if scope == "family":
        if not families or ids or not source_family or source_family not in families:
            return fallback
        return HostApplicability("family", (), families)
    if not ids or families or not source_id or source_id not in ids:
        return fallback
    return HostApplicability("host", ids, ())


def _value(source: Any, name: str, default: Any = "") -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _text(source: Any, *names: str) -> str:
    for name in names:
        value = _value(source, name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _list(source: Any, *names: str) -> list[str]:
    for name in names:
        value = _value(source, name)
        if isinstance(value, str):
            if value.strip():
                return [value.strip()]
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return sorted({str(item).strip() for item in value if isinstance(item, str) and item.strip()})
    return []


def _hash(value: str) -> str:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return value
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _provider_id(provider: Any) -> str:
    value = _value(provider, "provider_id", "")
    if isinstance(value, str) and value:
        return value
    if isinstance(provider, Mapping):
        value = provider.get("id", "")
        if isinstance(value, str) and value:
            return value
    return "deterministic-curator"


def _patterns(index: Any) -> list[dict[str, Any]]:
    if isinstance(index, KnowledgeIndex):
        return [dict(item) for item in read_index_items(index, list(index.active_pattern_ids) or None)]
    if isinstance(index, Mapping):
        value = index.get("patterns", index.get("items", ()))
        if isinstance(value, Mapping):
            return [{**dict(item), "pattern_id": str(item_id)} for item_id, item in value.items() if isinstance(item, Mapping)]
        index = value
    if isinstance(index, Sequence) and not isinstance(index, (str, bytes, bytearray)):
        return [dict(item) for item in index if isinstance(item, Mapping)]
    if isinstance(index, Iterable) and not isinstance(index, (str, bytes, bytearray)):
        return [dict(item) for item in index if isinstance(item, Mapping)]
    return []


def _candidate_data(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, GateDecision):
        return {
            "title": candidate.candidate_title,
            "claim": candidate.candidate_claim,
            "benefit": candidate.benefit,
            "classification": candidate.classification,
            "evidence_refs": list(candidate.evidence_refs),
            "source_host_id": candidate.source_host_id,
            "source_host_family": candidate.source_host_family,
            "applicability_scope": candidate.applicability_scope,
            "applicable_host_ids": list(candidate.applicable_host_ids),
            "applicable_host_families": list(candidate.applicable_host_families),
        }
    if isinstance(candidate, Mapping):
        return {str(key): value for key, value in candidate.items() if isinstance(key, str)}
    return {
        name: getattr(candidate, name)
        for name in (
            "title", "claim", "rule", "precondition", "failure_mode", "benefit",
            "classification", "evidence_refs", "provenances", "scopes",
            "applicability", "domain", "source_ref", "source_kind",
            "outcome_status", "version_constraint", "exception", "exceptions",
            "source_host_id", "source_host_family", "applicability_scope",
            "applicable_host_ids", "applicable_host_families",
        )
        if hasattr(candidate, name)
    }


def _policy(budget: Any) -> PromotionPolicy:
    if isinstance(budget, Mapping) and isinstance(budget.get("promotion_policy"), Mapping):
        raw = budget["promotion_policy"]
        try:
            return PromotionPolicy(**{key: raw[key] for key in PromotionPolicy.__dataclass_fields__ if key in raw})
        except (TypeError, ValueError):
            return PromotionPolicy.defaults()
    return PromotionPolicy.defaults()


def _no_change(data: Mapping[str, Any], provider_id: str, reason: str, source_hashes: Sequence[str]) -> ChangeSet:
    safe = reason if _SAFE_REASON.fullmatch(reason) else "NO_CHANGE"
    candidate_id = "cand_" + stable_hash({"claim": _text(data, "claim"), "reason": safe})[:20]
    source_host_id = _host_label(data.get("source_host_id")) or ""
    source_host_family = _host_label(data.get("source_host_family")) or ""
    host_scope = normalize_host_applicability(
        data,
        source_host_id=source_host_id,
        source_host_family=source_host_family,
    )
    payload = {
        "actor": "external-intelligence",
        "provider_id": provider_id,
        "classification": "private-reusable",
        "source_hashes": list(source_hashes),
        "reason_code": safe,
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
        "applicability_scope": host_scope.scope,
        "applicable_host_ids": list(host_scope.host_ids),
        "applicable_host_families": list(host_scope.host_families),
    }
    operation = ChangeOperation("NO_CHANGE", None, payload)
    changeset_id = "cs_" + stable_hash({"candidate_id": candidate_id, "operation": operation.to_dict()})[:24]
    return ChangeSet(
        changeset_id,
        candidate_id,
        (operation,),
        tuple(source_hashes),
        "promotion-v1",
        datetime.now(timezone.utc).isoformat(),
        provider_id,
        source_host_id,
        source_host_family,
        host_scope.scope,
        host_scope.host_ids,
        host_scope.host_families,
    )


def _base(data: Mapping[str, Any], provider_id: str, hashes: Sequence[str]) -> dict[str, Any]:
    classification = str(data.get("classification", "private-reusable") or "private-reusable")
    title = _text(data, "title", "candidate_title")[:160]
    claim = _text(data, "claim", "candidate_claim")
    rule = _text(data, "rule", "claim", "candidate_claim")[:1200]
    domain = _text(data, "domain") or "general"
    scopes = _list(data, "scopes", "scope") or [domain]
    applicability = _list(data, "applicability", "scope_tags") or [domain]
    evidence_refs = [_hash(item) for item in _list(data, "evidence_refs", "evidence_ids")]
    provenances = [_hash(item) for item in (_list(data, "provenances", "provenance_refs") or evidence_refs)]
    if not hashes:
        hashes = tuple(dict.fromkeys(evidence_refs or provenances or [_hash(claim)]))
    source_host_id = _host_label(data.get("source_host_id")) or ""
    source_host_family = _host_label(data.get("source_host_family")) or ""
    host_scope = normalize_host_applicability(
        data,
        source_host_id=source_host_id,
        source_host_family=source_host_family,
    )
    return {
        "actor": "external-intelligence",
        "provider_id": provider_id,
        "classification": classification,
        "source_hashes": list(hashes),
        "title": title,
        "claim": claim,
        "rule": rule,
        "precondition": _text(data, "precondition") or "The same problem structure is observed again",
        "failure_mode": _text(data, "failure_mode", "outcome_status") or "Repeated investigation or rework is required",
        "exception": _text(data, "exception") or (_list(data, "exceptions")[0] if _list(data, "exceptions") else ""),
        "version_constraint": _text(data, "version_constraint") or None,
        "domain": domain,
        "scopes": scopes,
        "applicability": applicability,
        "evidence_refs": evidence_refs or list(hashes),
        "provenances": provenances or list(hashes),
        "benefit": _text(data, "benefit"),
        "benefit_count": 1 if _text(data, "benefit") else 0,
        "source_kind": _text(data, "source_kind") or classification,
        "source_ref": _text(data, "source_ref") or "curator",
        "outcome_status": _text(data, "outcome_status") or "observed",
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
        "applicability_scope": host_scope.scope,
        "applicable_host_ids": list(host_scope.host_ids),
        "applicable_host_families": list(host_scope.host_families),
    }


def _privacy(data: Mapping[str, Any]) -> bool:
    classification = str(data.get("classification", "private-reusable"))
    if classification not in _WRITABLE:
        return False
    material = "\n".join(str(data.get(name, "")) for name in ("title", "claim", "rule", "benefit", "precondition", "failure_mode"))
    decision = inspect_text(material, classification, str(data.get("source_ref", "curator")))
    return decision.reason_code in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}


def _pattern_primary(pattern: Mapping[str, Any]) -> str:
    for name in ("claim", "rule", "title"):
        value = pattern.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _pattern_text(pattern: Mapping[str, Any]) -> str:
    return " ".join(str(pattern.get(name, "")) for name in ("rule", "claim", "title", "domain"))


def _pattern_applicability(pattern: Mapping[str, Any]) -> HostApplicability | None:
    if not any(field in pattern for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
        return HostApplicability("universal", (), ())
    try:
        return validate_host_applicability_mapping(
            {
                "source_host_id": pattern.get("source_host_id", ""),
                "source_host_family": pattern.get("source_host_family", ""),
                "applicability_scope": pattern.get("applicability_scope", "universal"),
                "applicable_host_ids": pattern.get("applicable_host_ids", ()),
                "applicable_host_families": pattern.get("applicable_host_families", ()),
            },
            allow_legacy=False,
            require_source_pair=False,
        )
    except (TypeError, ValueError):
        return None


def _applicability_compatible(target: HostApplicability | None, candidate: HostApplicability | None) -> bool:
    if target is None or candidate is None:
        return False
    if target.scope == "universal" or candidate.scope == "universal":
        return True
    if target.scope != candidate.scope:
        return False
    if target.scope == "family":
        return bool(set(target.host_families) & set(candidate.host_families))
    return bool(set(target.host_ids) & set(candidate.host_ids))


def _status(pattern: Mapping[str, Any]) -> str:
    return str(pattern.get("status", "active")).casefold()


def _match(patterns: Sequence[Mapping[str, Any]], claim: str, candidate_scope: HostApplicability | None = None) -> tuple[str, Mapping[str, Any], float] | None:
    eligible = [
        item for item in patterns
        if _status(item) in {"active", "candidate"}
        and item.get("pattern_id")
        and _applicability_compatible(_pattern_applicability(item), candidate_scope)
    ]
    exact = sorted(
        (item for item in eligible if normalize_claim(claim) == normalize_claim(_pattern_primary(item))),
        key=lambda item: (str(item.get("pattern_id")), str(item.get("cluster_id", ""))),
    )
    if exact:
        return "exact", exact[0], 1.0
    scored: list[tuple[float, Mapping[str, Any]]] = []
    for item in eligible:
        target = _pattern_text(item)
        score = similarity(claim, target)
        if alias_match(claim, target):
            score = max(score, 0.65)
        if score >= 0.45:
            scored.append((score, item))
    if not scored:
        return None
    score, target = sorted(
        scored,
        key=lambda pair: (-round(pair[0], 12), str(pair[1].get("pattern_id")), str(pair[1].get("cluster_id", ""))),
    )[0]
    return "similar", target, score


def _changeset(candidate_id: str, operations: Sequence[ChangeOperation], hashes: Sequence[str], provider_id: str) -> ChangeSet:
    unique_hashes = tuple(dict.fromkeys(str(item) for item in hashes if re.fullmatch(r"sha256:[0-9a-f]{64}", str(item))))
    if not unique_hashes:
        unique_hashes = ("sha256:" + "0" * 64,)
    body = {"candidate_id": candidate_id, "operations": [item.to_dict() for item in operations], "source_hashes": list(unique_hashes)}
    first_payload = operations[0].payload if operations else {}
    return ChangeSet(
        "cs_" + stable_hash(body)[:24],
        candidate_id,
        tuple(operations),
        unique_hashes,
        "promotion-v1",
        datetime.now(timezone.utc).isoformat(),
        provider_id,
        str(first_payload.get("source_host_id", "") or ""),
        str(first_payload.get("source_host_family", "") or ""),
        str(first_payload.get("applicability_scope", "universal") or "universal"),
        tuple(str(item) for item in first_payload.get("applicable_host_ids", ()) if isinstance(item, str)),
        tuple(str(item) for item in first_payload.get("applicable_host_families", ()) if isinstance(item, str)),
    )


def curate_candidate(candidate: Any, index: Any, provider: Any, budget: Any = None) -> ChangeSet:
    if isinstance(candidate, GateDecision):
        if candidate.decision != "YES":
            raise ValueError("CURATOR_REQUIRES_GATE_YES")
    elif isinstance(candidate, Mapping) and candidate.get("decision") is not None and candidate.get("decision") != "YES":
        raise ValueError("CURATOR_REQUIRES_GATE_YES")
    data = _candidate_data(candidate)
    provider_id = _provider_id(provider)
    claim = _text(data, "claim", "candidate_claim")
    title = _text(data, "title", "candidate_title")
    raw_hashes = _list(data, "evidence_refs", "source_hashes", "source_hash")
    hashes = tuple(dict.fromkeys(_hash(item) for item in raw_hashes if item))
    if not claim or len(claim) < 20 or not hashes or not _privacy(data):
        reason = "NO_EVIDENCE" if not claim or not hashes else "PRIVACY_REJECTED"
        return _no_change(data, provider_id, reason, hashes or (_hash(claim or title),))
    normalized = _base(data, provider_id, hashes)
    candidate_id = "cand_" + stable_hash({"claim": normalize_claim(claim), "hashes": list(hashes)})[:20]
    match = _match(_patterns(index), claim, _pattern_applicability(normalized))
    if match and match[0] == "exact":
        target = match[1]
        payload = {
            "actor": "external-intelligence", "provider_id": provider_id,
            "classification": str(target.get("classification", normalized["classification"])),
            "source_hash": hashes[0], "source_hashes": list(hashes),
            "evidence_refs": list(dict.fromkeys(hashes)),
            "provenances": list(dict.fromkeys(hashes)),
            "match_kind": "exact",
            "source_host_id": normalized["source_host_id"],
            "source_host_family": normalized["source_host_family"],
            "applicability_scope": normalized["applicability_scope"],
            "applicable_host_ids": normalized["applicable_host_ids"],
            "applicable_host_families": normalized["applicable_host_families"],
        }
        return _changeset(candidate_id, (ChangeOperation("ATTACH_EVIDENCE", str(target["pattern_id"]), payload),), hashes, provider_id)
    if match:
        target = match[1]
        target_id = str(target["pattern_id"])
        contradictory = classify_polarity(claim) != classify_polarity(_pattern_text(target))
        if contradictory:
            prior = int(target.get("contradiction_count", 0) or 0)
            if prior + 1 >= 3 and _status(target) == "active":
                operation = ChangeOperation("DEPRECATE_PATTERN", target_id, {
                    "actor": "external-intelligence", "provider_id": provider_id,
                    "classification": str(target.get("classification", normalized["classification"])),
                    "source_hash": hashes[0], "source_hashes": list(hashes),
                    "evidence_refs": list(hashes), "reason_code": "CONTRADICTION_REVIEW",
                    "source_host_id": normalized["source_host_id"],
                    "source_host_family": normalized["source_host_family"],
                    "applicability_scope": normalized["applicability_scope"],
                    "applicable_host_ids": normalized["applicable_host_ids"],
                    "applicable_host_families": normalized["applicable_host_families"],
                })
            else:
                operation = ChangeOperation("REVISE_PATTERN", target_id, {
                    **normalized, "source_hash": hashes[0], "proposal_only": True,
                    "reason_code": "CONTRADICTION_REVIEW", "contradiction_count": prior + 1,
                })
            return _changeset(candidate_id, (operation,), hashes, provider_id)
        payload = {
            "actor": "external-intelligence", "provider_id": provider_id,
            "classification": str(target.get("classification", normalized["classification"])),
            "source_hash": hashes[0], "source_hashes": list(hashes),
            "evidence_refs": list(dict.fromkeys(hashes)),
            "provenances": list(dict.fromkeys(hashes)),
            "match_kind": "similar",
            "source_host_id": normalized["source_host_id"],
            "source_host_family": normalized["source_host_family"],
            "applicability_scope": normalized["applicability_scope"],
            "applicable_host_ids": normalized["applicable_host_ids"],
            "applicable_host_families": normalized["applicable_host_families"],
        }
        return _changeset(candidate_id, (ChangeOperation("ATTACH_EVIDENCE", target_id, payload),), hashes, provider_id)

    observation_id = "obs_" + stable_hash({"candidate_id": candidate_id, "source": hashes[0]})[:20]
    pattern_id = "pat_" + stable_hash(normalize_claim(normalized["rule"]))[:20]
    operations: list[ChangeOperation] = [ChangeOperation("CREATE_OBSERVATION", observation_id, normalized)]
    policy = _policy(budget)
    if len(set(normalized["provenances"])) >= policy.independent_provenance_count and len(normalized["rule"]) <= policy.max_rule_chars:
        operations.append(ChangeOperation("CREATE_CANDIDATE", pattern_id, normalized))
    return _changeset(candidate_id, operations, hashes, provider_id)


__all__ = ["curate_candidate", "normalize_host_applicability"]
