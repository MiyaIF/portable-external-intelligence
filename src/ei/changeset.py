from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

from .ids import machine_id, stable_hash
from .journal import append_event, iter_events, validate_schema
from .models import Event, PromotionPolicy, ValidationResult, validate_host_applicability_mapping, validate_host_label
from .persistable_fields import inspect_changeset_payload, inspect_persistable
from .privacy import inspect_text
from .redaction import domain_hash


OPERATIONS = frozenset({
    "CREATE_OBSERVATION", "ATTACH_EVIDENCE", "CREATE_CANDIDATE",
    "PROMOTE_PATTERN", "REVISE_PATTERN", "DEPRECATE_PATTERN",
    "TOMBSTONE_PATTERN", "REDACT_REFERENCE", "NO_CHANGE",
})
_WRITABLE = frozenset({"public", "private-reusable"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset({
    "body", "candidate_text", "raw", "raw_input", "raw_response",
    "response", "transcript", "tool_output", "prompt", "query",
    "context", "secret", "token", "password",
})
_PATH_KEYS = frozenset({"path", "file", "file_path", "target_path", "relative_path", "repository_path"})


@dataclass(frozen=True)
class ChangeOperation:
    operation: str
    target_id: str | None
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        if self.operation not in OPERATIONS:
            raise ValueError("CHANGE_OPERATION_FORBIDDEN")
        if self.target_id is not None and not isinstance(self.target_id, str):
            raise ValueError("CHANGE_TARGET_INVALID")
        if not isinstance(self.payload, dict):
            raise ValueError("CHANGE_PAYLOAD_INVALID")

    def to_dict(self) -> dict[str, Any]:
        return {"operation": self.operation, "target_id": self.target_id, "payload": dict(self.payload)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ChangeOperation":
        if not isinstance(value, Mapping) or set(value) != {"operation", "target_id", "payload"}:
            raise ValueError("CHANGE_OPERATION_SCHEMA_INVALID")
        if not isinstance(value["payload"], Mapping):
            raise ValueError("CHANGE_PAYLOAD_INVALID")
        if not isinstance(value["operation"], str) or (value["target_id"] is not None and not isinstance(value["target_id"], str)):
            raise ValueError("CHANGE_OPERATION_SCHEMA_INVALID")
        return cls(value["operation"], value["target_id"], dict(value["payload"]))


@dataclass(frozen=True)
class ChangeSet:
    changeset_id: str
    candidate_id: str
    operations: tuple[ChangeOperation, ...]
    source_hashes: tuple[str, ...]
    policy_version: str
    generated_at: str
    provider_id: str
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.changeset_id or ""):
            raise ValueError("CHANGESET_ID_INVALID")
        if not _SAFE_ID.fullmatch(self.candidate_id or ""):
            raise ValueError("CANDIDATE_ID_INVALID")
        if not self.operations:
            raise ValueError("CHANGESET_EMPTY")
        if not self.source_hashes or any(not _HASH.fullmatch(item) for item in self.source_hashes):
            raise ValueError("SOURCE_HASH_INVALID")
        if not isinstance(self.policy_version, str) or not self.policy_version:
            raise ValueError("POLICY_VERSION_INVALID")
        _timestamp(self.generated_at)
        if not _SAFE_LABEL.fullmatch(self.provider_id or ""):
            raise ValueError("PROVIDER_ID_INVALID")
        for field_name in ("source_host_id", "source_host_family"):
            value = getattr(self, field_name)
            try:
                validate_host_label(value, field=field_name, allow_empty=True)
            except ValueError:
                raise ValueError("SOURCE_HOST_LABEL_INVALID")
        try:
            validate_host_applicability_mapping(
                {
                    "source_host_id": self.source_host_id,
                    "source_host_family": self.source_host_family,
                    "applicability_scope": self.applicability_scope,
                    "applicable_host_ids": list(self.applicable_host_ids),
                    "applicable_host_families": list(self.applicable_host_families),
                },
                require_source_pair=bool(
                    self.source_host_id
                    or self.source_host_family
                    or self.applicability_scope != "universal"
                    or self.applicable_host_ids
                    or self.applicable_host_families
                ),
            )
        except ValueError as exc:
            raise ValueError("APPLICABILITY_INVALID") from exc

    def to_dict(self) -> dict[str, Any]:
        value = {
            "changeset_id": self.changeset_id,
            "candidate_id": self.candidate_id,
            "operations": [item.to_dict() for item in self.operations],
            "source_hashes": list(self.source_hashes),
            "policy_version": self.policy_version,
            "generated_at": self.generated_at,
            "provider_id": self.provider_id,
        }
        # A legacy ChangeSet has no host metadata at all.  Keep that
        # read-only shape instead of serializing five empty fields, which
        # would turn a legacy value into malformed new persistence data.
        if self.source_host_id and self.source_host_family:
            value.update(
                {
                    "source_host_id": self.source_host_id,
                    "source_host_family": self.source_host_family,
                    "applicability_scope": self.applicability_scope,
                    "applicable_host_ids": list(self.applicable_host_ids),
                    "applicable_host_families": list(self.applicable_host_families),
                }
            )
        return value

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ChangeSet":
        validate_schema("change-set", value)
        return cls(
            value["changeset_id"],
            value["candidate_id"],
            tuple(ChangeOperation.from_mapping(item) for item in value["operations"]),
            tuple(value["source_hashes"]),
            value["policy_version"],
            value["generated_at"],
            value["provider_id"],
            value.get("source_host_id", ""),
            value.get("source_host_family", ""),
            value.get("applicability_scope", "universal"),
            tuple(value.get("applicable_host_ids", ())),
            tuple(value.get("applicable_host_families", ())),
        )

    @property
    def fingerprint(self) -> str:
        raw = json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    reason_code: str
    event_ids: tuple[str, ...]
    changeset_id: str
    already_applied: bool = False
    validation: ValidationResult = ValidationResult(False, ())

    @property
    def ok(self) -> bool:
        return self.applied


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("TIMESTAMP_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _coerce(value: ChangeSet | Mapping[str, Any]) -> ChangeSet:
    return value if isinstance(value, ChangeSet) else ChangeSet.from_mapping(value)


def _policy(settings: Any) -> PromotionPolicy:
    raw_path = getattr(settings, "promotion_policy_path", None)
    path = Path(raw_path) if raw_path else Path()
    if not path.is_file():
        return PromotionPolicy.defaults()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("POLICY_READ_FAILED") from exc
    if not isinstance(document, Mapping):
        raise ValueError("POLICY_SCHEMA_INVALID")
    candidate = document.get("candidate", {})
    promotion = document.get("promotion", {})
    deprecation = document.get("deprecation", {})
    always_on = document.get("always_on", {})
    if not all(isinstance(item, Mapping) for item in (candidate, promotion, deprecation, always_on)):
        raise ValueError("POLICY_SCHEMA_INVALID")
    values = {
        "policy_version": document.get("policy_version", "promotion-v1"),
        "independent_provenance_count": promotion.get("independent_provenance_count", candidate.get("independent_provenance_count", 2)),
        "distinct_scope_count": promotion.get("distinct_scope_count", 2),
        "benefit_evidence_count": promotion.get("benefit_evidence_count", 1),
        "max_unresolved_contradictions": promotion.get("max_unresolved_contradictions", 0),
        "min_rule_chars": promotion.get("min_rule_chars", 80),
        "max_rule_chars": promotion.get("max_rule_chars", 1200),
        "contradiction_count_for_deprecation": deprecation.get("independent_contradiction_count", 3),
        "unused_days_for_deprecation": deprecation.get("unused_days", 180),
        "always_on_target_chars": always_on.get("target_chars", 9000),
        "always_on_hard_cap_chars": always_on.get("hard_cap_chars", 12000),
        "candidate_retention_days": candidate.get("candidate_retention_days", 180),
    }
    try:
        return PromotionPolicy(**values)
    except (TypeError, ValueError) as exc:
        raise ValueError("POLICY_SCHEMA_INVALID") from exc


def _forbidden(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).casefold() in _FORBIDDEN_KEYS or _forbidden(nested) for key, nested in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_forbidden(item) for item in value)
    return False


def _safe_target(value: str | None) -> bool:
    return value is None or bool(_SAFE_ID.fullmatch(value)) and "/" not in value and "\\" not in value and ".." not in value


def _bad_path(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.replace("\\", "/")
    return (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized) is not None
        or normalized.startswith("~/")
        or normalized in {".", ".."}
        or ".." in normalized.split("/")
    )


def _hashes(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, str):
        if _HASH.fullmatch(value):
            result.add(value)
    elif isinstance(value, Mapping):
        for nested in value.values():
            result.update(_hashes(nested))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            result.update(_hashes(nested))
    return result


def _payload_text(payload: Mapping[str, Any]) -> str:
    values: list[str] = []
    for field in ("title", "claim", "rule", "precondition", "failure_mode", "benefit", "exception", "scope", "version_constraint"):
        value = payload.get(field)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            values.extend(str(item) for item in value if isinstance(item, str))
    return "\n".join(values)


def _persisted_identifier(value: Any, domain: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("PERSISTED_IDENTIFIER_INVALID")
    if not value and allow_empty:
        return ""
    if _HASH.fullmatch(value):
        return value
    return domain_hash(value, domain)


def _events(settings: Any) -> list[Event]:
    root = Path(settings.paths.event_dir)
    if not root.exists():
        return []
    try:
        return list(iter_events(root))
    except Exception as exc:
        raise ValueError("JOURNAL_CORRUPT") from exc


def _states(events: Iterable[Event]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for event in sorted(events, key=lambda item: (item.occurred_at, item.event_id)):
        if not event.event_type.startswith("pattern."):
            continue
        payload = event.payload
        pattern_id = payload.get("pattern_id")
        if not isinstance(pattern_id, str) or not pattern_id:
            continue
        state = result.setdefault(pattern_id, {
            "pattern_id": pattern_id,
            "cluster_id": str(payload.get("cluster_id", pattern_id)),
            "status": "candidate",
            "rule": str(payload.get("rule", "")),
            "classification": str(payload.get("classification", "private-reusable")),
            "provenances": list(payload.get("provenances", payload.get("evidence_refs", ()))),
            "scopes": list(payload.get("scopes", ())),
            "applicability": list(payload.get("applicability", ())),
            "benefit_count": int(payload.get("benefit_count", 0) or 0),
            "contradiction_count": int(payload.get("contradiction_count", 0) or 0),
            "precondition": str(payload.get("precondition", "")),
            "failure_mode": str(payload.get("failure_mode", "")),
            "version_constraint": payload.get("version_constraint"),
            "revision": int(payload.get("revision", 0) or 0),
            "source_host_id": str(payload.get("source_host_id", "") or ""),
            "source_host_family": str(payload.get("source_host_family", "") or ""),
            "applicability_scope": str(payload.get("applicability_scope", "universal") or "universal"),
            "applicable_host_ids": list(payload.get("applicable_host_ids", ())),
            "applicable_host_families": list(payload.get("applicable_host_families", ())),
        })
        for field in ("cluster_id", "rule", "classification", "precondition", "failure_mode", "version_constraint", "source_host_id", "source_host_family", "applicability_scope"):
            if field in payload and payload[field] is not None:
                state[field] = payload[field]
        for field in ("provenances", "scopes", "applicability", "applicable_host_ids", "applicable_host_families"):
            value = payload.get(field)
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                state[field] = list(dict.fromkeys(str(item) for item in value if str(item)))
        for field in ("benefit_count", "contradiction_count", "revision"):
            if field in payload:
                try:
                    state[field] = int(payload[field])
                except (TypeError, ValueError):
                    state[field] = 0
        state["status"] = {
            "pattern.candidate_created": "candidate",
            "pattern.promoted": "active",
            "pattern.revised": "active",
            "pattern.deprecated": "deprecated",
            "pattern.superseded": "superseded",
            "pattern.tombstoned": "tombstoned",
        }.get(event.event_type, state["status"])
    for state in list(result.values()):
        cluster_id = str(state.get("cluster_id", ""))
        if cluster_id and cluster_id not in result:
            result[cluster_id] = state
    return result


def _configured_sources(settings: Any) -> set[str] | None:
    value = getattr(settings, "source_hashes", None)
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.values()
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, Sequence):
        return None
    return {str(item) for item in value if isinstance(item, str)}


def _unique(reasons: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(item) for item in reasons if item))


def validate_changeset(changeset: ChangeSet | Mapping[str, Any], settings: Any) -> ValidationResult:
    try:
        value = _coerce(changeset)
    except Exception:
        return ValidationResult(False, ("CHANGESET_SCHEMA_INVALID",))
    try:
        policy = _policy(settings)
        existing_events = _events(settings)
    except ValueError as exc:
        return ValidationResult(False, (str(exc),))
    reasons: list[str] = []
    if value.policy_version != policy.policy_version:
        reasons.append("STALE_POLICY")
    if not _SAFE_LABEL.fullmatch(value.provider_id):
        reasons.append("PROVIDER_ID_INVALID")
    if _forbidden(value.to_dict()):
        reasons.append("RAW_CONTENT_FORBIDDEN")
    document_inspection = inspect_persistable(value.to_dict())
    reasons.extend(document_inspection.reason_codes)
    configured = _configured_sources(settings)
    if configured is not None and not set(value.source_hashes).issubset(configured):
        reasons.append("STALE_SOURCE_HASH")
    if len(json.dumps(value.to_dict(), ensure_ascii=False).encode("utf-8")) > 512 * 1024:
        reasons.append("CHANGESET_TOO_LARGE")
    projected = {key: dict(state) for key, state in _states(existing_events).items()}

    for operation in value.operations:
        op = operation.operation
        payload = operation.payload
        payload_inspection = inspect_changeset_payload(
            payload,
            classification=str(payload.get("classification", "private-reusable")),
        )
        reasons.extend(payload_inspection.reason_codes)
        if not _safe_target(operation.target_id):
            reasons.append("PATH_TRAVERSAL")
        if _forbidden(payload):
            reasons.append("RAW_CONTENT_FORBIDDEN")
        for key, nested in payload.items():
            if str(key).casefold() in _PATH_KEYS and _bad_path(nested):
                reasons.append("PATH_TRAVERSAL")
        actor = payload.get("actor")
        if not isinstance(actor, str) or not _SAFE_LABEL.fullmatch(actor):
            reasons.append("ACTOR_INVALID")
        provider = payload.get("provider_id", value.provider_id)
        if not isinstance(provider, str) or provider != value.provider_id or not _SAFE_LABEL.fullmatch(provider):
            reasons.append("PROVIDER_MISMATCH")
        classification = payload.get("classification", "private-reusable")
        if classification not in _WRITABLE:
            reasons.append("CLASSIFICATION_NOT_SYNCABLE")
        else:
            privacy = inspect_text(_payload_text(payload), str(classification), "change-set")
            if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
                reasons.append("PRIVACY_REJECTED")
        operation_hashes = _hashes(payload)
        if not operation_hashes.intersection(value.source_hashes):
            reasons.append("SOURCE_HASH_MISMATCH")
        if op != "NO_CHANGE" and not operation_hashes:
            reasons.append("SOURCE_HASH_MISSING")

        if op == "CREATE_OBSERVATION":
            title = payload.get("title")
            claim = payload.get("claim")
            if not isinstance(title, str) or not title or len(title) > 160:
                reasons.append("OBSERVATION_TITLE_INVALID")
            if not isinstance(claim, str) or not 20 <= len(claim) <= 1200:
                reasons.append("OBSERVATION_CLAIM_INVALID")
        rule = payload.get("rule")
        if isinstance(rule, str):
            if len(rule) > policy.always_on_hard_cap_chars:
                reasons.append("RULE_HARD_CAP_EXCEEDED")
            elif len(rule) > policy.max_rule_chars:
                reasons.append("RULE_LENGTH_INVALID")
        elif op in {"CREATE_CANDIDATE", "PROMOTE_PATTERN", "REVISE_PATTERN"}:
            reasons.append("RULE_MISSING")

        target = operation.target_id
        state = projected.get(target) if target else None
        if op == "ATTACH_EVIDENCE":
            if state is None or state.get("status") not in {"active", "candidate"}:
                reasons.append("TARGET_STATE_INVALID")
        elif op == "CREATE_CANDIDATE":
            provenances = payload.get("provenances", payload.get("evidence_refs", ()))
            count = len(provenances) if isinstance(provenances, Sequence) and not isinstance(provenances, (str, bytes, bytearray)) else 0
            if not target or target in projected:
                reasons.append("TARGET_ALREADY_EXISTS")
            elif count < policy.independent_provenance_count:
                reasons.append("CANDIDATE_POLICY_INELIGIBLE")
            else:
                projected[target] = {
                    "pattern_id": target, "cluster_id": str(payload.get("cluster_id", target)),
                    "status": "candidate", "rule": str(payload.get("rule", "")),
                    "classification": str(classification), "provenances": list(provenances),
                    "scopes": list(payload.get("scopes", ())), "applicability": list(payload.get("applicability", ())),
                    "benefit_count": int(payload.get("benefit_count", 0) or 0),
                    "contradiction_count": int(payload.get("contradiction_count", 0) or 0),
                    "revision": 0,
                    "source_host_id": str(payload.get("source_host_id", "") or ""),
                    "source_host_family": str(payload.get("source_host_family", "") or ""),
                    "applicability_scope": str(payload.get("applicability_scope", "universal") or "universal"),
                    "applicable_host_ids": list(payload.get("applicable_host_ids", ())),
                    "applicable_host_families": list(payload.get("applicable_host_families", ())),
                }
        elif op == "PROMOTE_PATTERN":
            if state is None or state.get("status") != "candidate":
                reasons.append("INVALID_LIFECYCLE_TRANSITION")
            contradiction = int(payload.get("contradiction_count", state.get("contradiction_count", 0) if state else 0) or 0)
            if contradiction > policy.max_unresolved_contradictions:
                reasons.append("UNRESOLVED_CONTRADICTION")
            if not isinstance(payload.get("precondition"), str) or not payload.get("precondition"):
                reasons.append("PRECONDITION_MISSING")
            if not isinstance(payload.get("failure_mode"), str) or not payload.get("failure_mode"):
                reasons.append("FAILURE_MODE_MISSING")
            applicability = payload.get("applicability", ())
            if not isinstance(applicability, Sequence) or isinstance(applicability, (str, bytes, bytearray)) or not any(str(item).strip() for item in applicability):
                reasons.append("APPLICABILITY_MISSING")
            if state is not None:
                state["status"] = "active"
        elif op == "REVISE_PATTERN":
            if state is None or state.get("status") not in {"active", "candidate"}:
                reasons.append("INVALID_LIFECYCLE_TRANSITION")
            if payload.get("proposal_only") and not getattr(settings, "allow_proposal_apply", False):
                reasons.append("REVIEW_REQUIRED")
            if state is not None:
                state["status"] = "active"
                state["rule"] = payload.get("rule", state.get("rule", ""))
        elif op == "DEPRECATE_PATTERN":
            if state is None or state.get("status") != "active":
                reasons.append("INVALID_LIFECYCLE_TRANSITION")
            if state is not None:
                state["status"] = "deprecated"
        elif op == "TOMBSTONE_PATTERN":
            if state is None or state.get("status") not in {"deprecated", "superseded"}:
                reasons.append("INVALID_LIFECYCLE_TRANSITION")
            if state is not None:
                state["status"] = "tombstoned"
        elif op == "REDACT_REFERENCE":
            if not getattr(settings, "allow_redaction", False) or not (payload.get("approval_identity_hash") or payload.get("approved_by")):
                reasons.append("REDACTION_REQUIRES_APPROVAL")
        elif op == "NO_CHANGE":
            reason = payload.get("reason_code")
            if reason is not None and not _SAFE_LABEL.fullmatch(str(reason)):
                reasons.append("REASON_CODE_INVALID")
    return ValidationResult(not reasons, _unique(reasons))


def _marker(events: Iterable[Event], changeset_id: str) -> Event | None:
    return next(
        (event for event in events if event.event_type == "curation.changeset.applied" and event.payload.get("changeset_id") == changeset_id),
        None,
    )


def _items(payload: Mapping[str, Any], field: str) -> list[str]:
    value = payload.get(field, ())
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return sorted({str(item) for item in value if str(item)})
    return []


def _merged(payload: Mapping[str, Any], state: Mapping[str, Any] | None, target: str) -> dict[str, Any]:
    current = dict(state or {})
    provenance = _items(payload, "provenances") or _items(payload, "evidence_refs") or _items(current, "provenances")
    result = {
        "pattern_id": target or str(payload.get("pattern_id", "")),
        "cluster_id": str(payload.get("cluster_id") or current.get("cluster_id") or target),
        "rule": str(payload.get("rule") or current.get("rule") or ""),
        "provenances": sorted(set(provenance)),
        "scopes": sorted(set(_items(payload, "scopes") or _items(current, "scopes"))),
        "applicability": sorted(set(_items(payload, "applicability") or _items(current, "applicability"))),
        "benefit_count": int(payload.get("benefit_count", current.get("benefit_count", 0)) or 0),
        "classification": str(payload.get("classification") or current.get("classification") or "private-reusable"),
        "precondition": str(payload.get("precondition") or current.get("precondition") or ""),
        "failure_mode": str(payload.get("failure_mode") or current.get("failure_mode") or ""),
        "version_constraint": payload.get("version_constraint", current.get("version_constraint")),
        "contradiction_count": int(payload.get("contradiction_count", current.get("contradiction_count", 0)) or 0),
    }
    # A matched target owns its existing applicability metadata.  Candidate
    # metadata is used only when creating a new target or when the legacy
    # target has no host fields at all.
    source_host_id = current.get("source_host_id") or payload.get("source_host_id") or ""
    source_host_family = current.get("source_host_family") or payload.get("source_host_family") or ""
    if source_host_id and source_host_family:
        result.update(
            {
                "source_host_id": source_host_id,
                "source_host_family": source_host_family,
                "applicability_scope": current.get("applicability_scope") or payload.get("applicability_scope") or "universal",
                "applicable_host_ids": sorted(set(_items(current, "applicable_host_ids") if "applicable_host_ids" in current else _items(payload, "applicable_host_ids"))),
                "applicable_host_families": sorted(set(_items(current, "applicable_host_families") if "applicable_host_families" in current else _items(payload, "applicable_host_families"))),
            }
        )
    return result


def _event_payload(changeset: ChangeSet, operation: ChangeOperation, state: Mapping[str, Any] | None) -> tuple[str, dict[str, Any]]:
    source = operation.payload
    existing = state or {}
    source_host_id = str(existing.get("source_host_id") or source.get("source_host_id") or changeset.source_host_id or "")
    source_host_family = str(existing.get("source_host_family") or source.get("source_host_family") or changeset.source_host_family or "")
    applicability_scope = str(existing.get("applicability_scope") or source.get("applicability_scope") or changeset.applicability_scope or "universal")
    applicable_host_ids = _items(existing, "applicable_host_ids") if "applicable_host_ids" in existing else (_items(source, "applicable_host_ids") if "applicable_host_ids" in source else list(changeset.applicable_host_ids))
    applicable_host_families = _items(existing, "applicable_host_families") if "applicable_host_families" in existing else (_items(source, "applicable_host_families") if "applicable_host_families" in source else list(changeset.applicable_host_families))
    common = {
        "changeset_id": changeset.changeset_id, "candidate_id": changeset.candidate_id,
        "change_operation": operation.operation, "policy_version": changeset.policy_version,
        "provider_id": changeset.provider_id, "actor": str(source["actor"]),
        "source_hashes": list(changeset.source_hashes),
        "classification": str(source.get("classification", "private-reusable")),
    }
    if source_host_id and source_host_family:
        common.update(
            {
                "source_host_id": source_host_id,
                "source_host_family": source_host_family,
                "applicability_scope": applicability_scope,
                "applicable_host_ids": applicable_host_ids,
                "applicable_host_families": applicable_host_families,
            }
        )
    target = operation.target_id
    if operation.operation == "CREATE_OBSERVATION":
        source_hash = str(source.get("source_hash") or changeset.source_hashes[0])
        observation_id = target or "obs_" + hashlib.sha256((str(source.get("claim", "")) + source_hash).encode()).hexdigest()[:20]
        return "observation.recorded", {
            **common, "observation_id": observation_id, "title": str(source.get("title", "observation")),
            "claim": str(source.get("claim", "")), "source_kind": str(source.get("source_kind", "private-reusable")),
            "source_ref_hash": _persisted_identifier(str(source.get("source_ref", "curation")), "source-ref"),
            "source_hash": source_hash, "provenance_key": _persisted_identifier(str(source.get("provenance_key") or source_hash), "provenance"),
            "cwd_fingerprint": _persisted_identifier(str(source.get("cwd_fingerprint", "")), "cwd", allow_empty=True),
            "domain": str(source.get("domain", "general")), "outcome_status": str(source.get("outcome_status", "unknown")),
            "benefit": str(source.get("benefit", "")), "applicability": _items(source, "applicability"),
            "record_fingerprint": "sha256:" + hashlib.sha256((observation_id + source_hash).encode()).hexdigest(),
        }
    if operation.operation == "ATTACH_EVIDENCE":
        body = _merged(source, state, target or "")
        body.update(common)
        body["pattern_id"] = target
        body["evidence_refs"] = sorted(set(body["provenances"]) | set(_items(source, "evidence_refs")))
        body["evidence_count"] = len(body["evidence_refs"])
        event_type = "pattern.revised" if state and state.get("status") == "active" else "pattern.candidate_created"
        body["revision"] = int(state.get("revision", 0) if state else 0) + int(event_type == "pattern.revised")
        return event_type, body
    if operation.operation == "CREATE_CANDIDATE":
        body = _merged(source, None, target or str(source.get("pattern_id", "")))
        body.update(common)
        body["reason"] = str(source.get("reason_code", "CURATOR_NEW_OBSERVATION"))
        body["reason_code"] = body["reason"]
        body["evidence_refs"] = list(body["provenances"])
        body["evidence_count"] = len(body["evidence_refs"])
        return "pattern.candidate_created", body
    if operation.operation in {"PROMOTE_PATTERN", "REVISE_PATTERN"}:
        body = _merged(source, state, target or "")
        body.update(common)
        body["pattern_id"] = target
        body["evidence_refs"] = list(body["provenances"])
        body["evidence_count"] = len(body["evidence_refs"])
        body["revision"] = int(source.get("revision", (state or {}).get("revision", 0)) or 0)
        reason = str(source.get("reason_code", "CURATOR_UPDATE"))
        body["reason"] = reason
        body["reason_code"] = reason
        return ("pattern.promoted" if operation.operation == "PROMOTE_PATTERN" else "pattern.revised"), body
    if operation.operation in {"DEPRECATE_PATTERN", "TOMBSTONE_PATTERN"}:
        reason = str(source.get("reason_code", "CONTRADICTION_REVIEW" if operation.operation == "DEPRECATE_PATTERN" else "RETENTION_EXPIRED"))
        body = {
            **common, "pattern_id": target, "cluster_id": str((state or {}).get("cluster_id", target)),
            "reason": reason, "reason_code": reason,
            "evidence_refs": _items(source, "evidence_refs") or _items(state or {}, "provenances"),
        }
        event_type = "pattern.deprecated" if operation.operation == "DEPRECATE_PATTERN" else "pattern.tombstoned"
        return event_type, body
    if operation.operation == "REDACT_REFERENCE":
        return "reference.redacted", {
            **common, "reference_id": target,
            "reference_hash": _persisted_identifier(str(source.get("reference_hash") or changeset.source_hashes[0]), "reference"),
            "approval_identity_hash": _persisted_identifier(str(source.get("approval_identity_hash") or source.get("approved_by", "")), "approval-identity"),
        }
    return "curation.no_change", {**common, "reason_code": str(source.get("reason_code", "NO_CHANGE"))}


def _first_privacy_pointer(changeset: ChangeSet) -> str:
    for index, operation in enumerate(changeset.operations):
        inspection = inspect_changeset_payload(
            operation.payload,
            classification=str(operation.payload.get("classification", "private-reusable")),
        )
        if inspection.issues:
            issue = inspection.issues[0]
            suffix = "" if issue.pointer in {"", "/"} else issue.pointer
            return f"/operations/{index}/payload{suffix}"
    return "/"


def _failure(settings: Any, changeset: ChangeSet, reason: str, *, field_path: str | None = None) -> None:
    root = Path(settings.paths.runtime_dir).resolve()
    repo = Path(settings.paths.engine_root).resolve()
    if root == repo or root.is_relative_to(repo):
        return
    root.mkdir(parents=True, exist_ok=True)
    safe = reason if _SAFE_LABEL.fullmatch(reason) else "APPLY_FAILED"
    policy_version = changeset.policy_version if _SAFE_LABEL.fullmatch(changeset.policy_version) else "unknown"
    row = {
        "reason_code": safe,
        "source_hashes": list(changeset.source_hashes),
        "field_path": field_path or _first_privacy_pointer(changeset),
        "policy_version": policy_version,
    }
    path = root / "changeset-failures.jsonl"
    data = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(str(path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_changeset(changeset: ChangeSet | Mapping[str, Any], settings: Any) -> ApplyResult:
    try:
        value = _coerce(changeset)
    except Exception:
        return ApplyResult(False, "CHANGESET_SCHEMA_INVALID", (), "unknown")
    try:
        existing = _events(settings)
    except ValueError as exc:
        reason = str(exc)
        validation = ValidationResult(False, (reason,))
        _failure(settings, value, reason, field_path=_first_privacy_pointer(value))
        return ApplyResult(False, reason, (), value.changeset_id, validation=validation)
    if _marker(existing, value.changeset_id) is not None:
        return ApplyResult(True, "ALREADY_APPLIED", (), value.changeset_id, True, ValidationResult(True, ("ALREADY_APPLIED",)))
    validation = validate_changeset(value, settings)
    if not validation.valid:
        reason = validation.reason_codes[0] if validation.reason_codes else "CHANGESET_INVALID"
        _failure(settings, value, reason, field_path=_first_privacy_pointer(value))
        return ApplyResult(False, reason, (), value.changeset_id, validation=validation)

    state_map = _states(existing)
    built: list[tuple[Event, str]] = []
    for index, operation in enumerate(value.operations):
        state = state_map.get(operation.target_id) if operation.target_id else None
        event_type, payload = _event_payload(value, operation, state)
        event_id = "evt_changeset_" + stable_hash({"changeset_id": value.changeset_id, "index": index, "operation": operation.to_dict()})[:32]
        built.append((Event.create(event_type, value.generated_at, "external-intelligence", machine_id(), payload, event_id=event_id), event_id))
        if operation.operation == "CREATE_CANDIDATE" and operation.target_id:
            state_map[operation.target_id] = {
                "pattern_id": operation.target_id, "cluster_id": str(payload.get("cluster_id", operation.target_id)),
                "status": "candidate", "rule": str(payload.get("rule", "")),
                "classification": str(payload.get("classification", "private-reusable")),
                "provenances": list(payload.get("provenances", ())), "revision": 0,
            }
        elif operation.target_id and operation.target_id in state_map:
            state_map[operation.target_id]["status"] = {
                "PROMOTE_PATTERN": "active", "REVISE_PATTERN": "active",
                "DEPRECATE_PATTERN": "deprecated", "TOMBSTONE_PATTERN": "tombstoned",
            }.get(operation.operation, state_map[operation.target_id].get("status", "candidate"))

    marker_payload = {
        "changeset_id": value.changeset_id, "candidate_id": value.candidate_id,
        "changeset_hash": value.fingerprint, "operation_count": len(value.operations),
        "event_ids": [event_id for _, event_id in built], "policy_version": value.policy_version,
        "provider_id": value.provider_id, "actor": "external-intelligence",
        "source_hashes": list(value.source_hashes),
    }
    marker_id = "evt_changeset_" + stable_hash({"changeset_id": value.changeset_id, "marker": marker_payload})[:32]
    built.append((Event.create("curation.changeset.applied", value.generated_at, "external-intelligence", machine_id(), marker_payload, event_id=marker_id), marker_id))

    event_ids: list[str] = []
    try:
        for event, event_id in built:
            append_event(event, settings.paths.event_dir)
            event_ids.append(event_id)
    except Exception as exc:
        reason = type(exc).__name__ if _SAFE_LABEL.fullmatch(type(exc).__name__) else "APPLY_FAILED"
        _failure(settings, value, reason)
        return ApplyResult(False, reason, (), value.changeset_id, validation=ValidationResult(False, (reason,)))
    return ApplyResult(True, "APPLIED", tuple(event_ids), value.changeset_id, validation=validation)


__all__ = ["ApplyResult", "ChangeOperation", "ChangeSet", "OPERATIONS", "apply_changeset", "validate_changeset"]
