from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from .ids import canonical_json, new_event_id, stable_hash


HOST_APPLICABILITY_FIELDS = (
    "source_host_id",
    "source_host_family",
    "applicability_scope",
    "applicable_host_ids",
    "applicable_host_families",
)
HOST_SCOPE_VALUES = frozenset({"universal", "family", "host"})
MAX_HOST_APPLICABILITY_ITEMS = 16
_SAFE_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")


def validate_host_label(value: Any, *, field: str = "host", allow_empty: bool = False) -> str:
    """Validate a non-secret public host label without coercion or path syntax."""
    if not isinstance(value, str):
        raise ValueError(f"HOST_LABEL_INVALID:{field}")
    if value == "" and allow_empty:
        return value
    if not value or len(value) > 160 or not _SAFE_HOST_LABEL_RE.fullmatch(value):
        raise ValueError(f"HOST_LABEL_INVALID:{field}")
    # A drive-qualified or path-like value must never become a persisted host id.
    if "/" in value or "\\" in value or (len(value) >= 2 and value[1] == ":" and value[0].isalpha()):
        raise ValueError(f"HOST_LABEL_INVALID:{field}")
    return value


def validate_host_list(value: Any, *, field: str) -> tuple[str, ...]:
    """Validate a strict host/family list; numeric and other coercions are rejected."""
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"HOST_LIST_INVALID:{field}")
    if len(value) > MAX_HOST_APPLICABILITY_ITEMS:
        raise ValueError(f"HOST_LIST_INVALID:{field}")
    labels = tuple(validate_host_label(item, field=field) for item in value)
    if len(set(labels)) != len(labels):
        raise ValueError(f"HOST_LIST_INVALID:{field}")
    return labels


def validate_host_applicability_mapping(
    value: Mapping[str, Any],
    *,
    allow_legacy: bool = False,
    require_source_pair: bool = True,
) -> HostApplicability:
    """Validate the five-field applicability contract at a persistence boundary.

    A mapping with none of the five keys is accepted only when ``allow_legacy`` is
    true; this is the read-time compatibility projection for pre-feature records.
    Partial mappings, unknown scopes, non-string list items, and contradictory
    scope/list combinations are always rejected.
    """
    if not isinstance(value, Mapping):
        raise ValueError("HOST_APPLICABILITY_INVALID")
    present = tuple(field in value for field in HOST_APPLICABILITY_FIELDS)
    if not any(present):
        if allow_legacy:
            return HostApplicability("universal", (), ())
        raise ValueError("HOST_APPLICABILITY_REQUIRED")
    if not all(present):
        raise ValueError("HOST_APPLICABILITY_FIELDS_INCOMPLETE")

    source_id = validate_host_label(value["source_host_id"], field="source_host_id", allow_empty=not require_source_pair)
    source_family = validate_host_label(value["source_host_family"], field="source_host_family", allow_empty=not require_source_pair)
    if bool(source_id) != bool(source_family):
        raise ValueError("HOST_SOURCE_PAIR_INVALID")
    if require_source_pair and (not source_id or not source_family):
        raise ValueError("HOST_SOURCE_PAIR_REQUIRED")
    scope = value["applicability_scope"]
    if not isinstance(scope, str) or scope not in HOST_SCOPE_VALUES:
        raise ValueError("HOST_APPLICABILITY_SCOPE_INVALID")
    host_ids = validate_host_list(value["applicable_host_ids"], field="applicable_host_ids")
    host_families = validate_host_list(value["applicable_host_families"], field="applicable_host_families")
    if scope == "universal":
        if host_ids or host_families:
            raise ValueError("HOST_APPLICABILITY_SCOPE_CONTRADICTORY")
    elif scope == "family":
        if not host_families or host_ids or (source_family and source_family not in host_families):
            raise ValueError("HOST_APPLICABILITY_SCOPE_CONTRADICTORY")
    elif not host_ids or host_families or (source_id and source_id not in host_ids):
        raise ValueError("HOST_APPLICABILITY_SCOPE_CONTRADICTORY")
    return HostApplicability(scope, host_ids, host_families)


def host_applicability_fields(value: Mapping[str, Any], *, allow_legacy: bool = False, require_source_pair: bool = True) -> dict[str, Any]:
    """Return a canonical five-field dictionary after strict validation."""
    scope = validate_host_applicability_mapping(
        value,
        allow_legacy=allow_legacy,
        require_source_pair=require_source_pair,
    )
    if not any(field in value for field in HOST_APPLICABILITY_FIELDS):
        return {
            "source_host_id": "",
            "source_host_family": "",
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        }
    return {
        "source_host_id": value["source_host_id"],
        "source_host_family": value["source_host_family"],
        "applicability_scope": scope.scope,
        "applicable_host_ids": list(scope.host_ids),
        "applicable_host_families": list(scope.host_families),
    }



def _utc_isoformat(moment: datetime) -> str:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("EVENT_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")



def _canonical_payload_hash(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(dict(payload))).hexdigest()



def _default_idempotency_key(
    event_type: str,
    occurred_at: str,
    actor: str,
    machine_id: str,
    payload: Mapping[str, Any],
) -> str:
    material = {
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": actor,
        "machine_id": machine_id,
        "payload": dict(payload),
    }
    return "sha256:" + stable_hash(material)


@dataclass(frozen=True)
class HostApplicability:
    """A normalized, host-safe boundary for a reusable knowledge item."""

    scope: Literal["universal", "family", "host"]
    host_ids: tuple[str, ...] = ()
    host_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    occurred_at: str
    actor: str
    machine_id: str
    payload: dict[str, Any]
    schema_version: int = 1
    integrity_sha256: str = ""
    idempotency_key: str = ""
    provenance: tuple[str, ...] = ()
    integrity: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        event_type: str,
        occurred_at: str,
        actor: str,
        machine_id: str,
        payload: Mapping[str, Any],
        event_id: str | None = None,
    ) -> "Event":
        event_id = event_id or new_event_id(datetime.now(timezone.utc), machine_id)
        return cls(
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            actor=actor,
            machine_id=machine_id,
            payload=dict(payload),
        )

    @classmethod
    def create_v2(
        cls,
        event_type: str,
        actor: str,
        machine_id: str,
        payload: Mapping[str, Any],
        occurred_at: datetime | None = None,
        idempotency_key: str | None = None,
    ) -> "Event":
        moment = occurred_at or datetime.now(timezone.utc)
        occurred_at_text = _utc_isoformat(moment)
        payload_dict = dict(payload)
        return cls(
            event_id=new_event_id(moment, machine_id),
            event_type=event_type,
            occurred_at=occurred_at_text,
            actor=actor,
            machine_id=machine_id,
            payload=payload_dict,
            schema_version=2,
            idempotency_key=idempotency_key or _default_idempotency_key(event_type, occurred_at_text, actor, machine_id, payload_dict),
            provenance=(),
            integrity={
                "algorithm": "sha256",
                "canonical_payload_hash": _canonical_payload_hash(payload_dict),
            },
        )

    def canonical_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "machine_id": self.machine_id,
            "payload": self.payload,
        }
        if self.schema_version >= 2:
            result["idempotency_key"] = self.idempotency_key
            result["provenance"] = list(self.provenance)
            result["integrity"] = self.integrity
        return result

    def to_dict(self) -> dict[str, Any]:
        result = self.canonical_dict()
        result["integrity_sha256"] = self.integrity_sha256
        return result

    def idempotency_basis(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "machine_id": self.machine_id,
            "payload": self.payload,
            "idempotency_key": self.idempotency_key,
            "provenance": list(self.provenance),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        if not isinstance(data, Mapping):
            raise ValueError("EVENT_OBJECT_REQUIRED")
        required = {
            "event_id",
            "event_type",
            "occurred_at",
            "actor",
            "machine_id",
            "payload",
            "integrity_sha256",
        }
        missing = required.difference(data)
        if missing:
            raise ValueError(f"EVENT_FIELDS_MISSING:{','.join(sorted(missing))}")
        schema_version = data.get("schema_version", 1)
        if type(schema_version) is not int:
            raise ValueError("EVENT_SCHEMA_VERSION_INVALID")
        text_fields = ("event_id", "event_type", "occurred_at", "actor", "machine_id", "integrity_sha256")
        for field_name in text_fields:
            if not isinstance(data[field_name], str):
                raise ValueError(f"EVENT_{field_name.upper()}_INVALID")
        if not isinstance(data["payload"], dict):
            raise ValueError("EVENT_PAYLOAD_NOT_OBJECT")
        provenance_value = data.get("provenance", ())
        if not isinstance(provenance_value, (list, tuple)) or not all(isinstance(value, str) for value in provenance_value):
            raise ValueError("EVENT_PROVENANCE_INVALID")
        integrity_value = data.get("integrity", {})
        if not isinstance(integrity_value, dict):
            raise ValueError("EVENT_INTEGRITY_OBJECT_REQUIRED")
        idempotency_key = data.get("idempotency_key", "")
        if not isinstance(idempotency_key, str):
            raise ValueError("EVENT_IDEMPOTENCY_KEY_INVALID")
        return cls(
            schema_version=schema_version,
            event_id=data["event_id"],
            event_type=data["event_type"],
            occurred_at=data["occurred_at"],
            actor=data["actor"],
            machine_id=data["machine_id"],
            payload=dict(data["payload"]),
            integrity_sha256=data["integrity_sha256"],
            idempotency_key=idempotency_key,
            provenance=tuple(provenance_value),
            integrity=dict(integrity_value),
        )


@dataclass(frozen=True)
class ObservationInput:
    title: str
    claim: str
    source_kind: str
    source_ref: str
    cwd: str
    domain: str
    outcome_status: str
    benefit: str
    classification: str
    applicability: tuple[str, ...] = ()
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProvenanceRef:
    source_hash: str
    session_id_hash: str | None = None
    rollout_id_hash: str | None = None
    copied_from_hash: str | None = None
    copy_of_hash: str | None = None
    copy_source_hash: str | None = None
    copy_origin_hash: str | None = None
    cwd_hash: str = ""
    domain: str = ""
    source_family: str = ""
    observed_at: datetime | str | None = None


@dataclass(frozen=True)
class ObservationState:
    observation_id: str
    title: str
    claim: str
    domain: str
    cwd_fingerprint: str
    provenance_key: str
    outcome_status: str
    benefit: str
    classification: str
    source_hash: str = ""
    applicability: tuple[str, ...] = ()
    scope: str = ""
    provenance: tuple[ProvenanceRef, ...] = ()
    benefit_refs: tuple[str, ...] = ()
    version_constraint: str | None = None
    status: str = "OBSERVED"
    session_id_hash: str | None = None
    rollout_id_hash: str | None = None
    copied_from_hash: str | None = None
    source_family: str = ""
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClusterState:
    cluster_id: str
    pattern_id: str | None
    status: str
    rule: str
    provenances: frozenset[str]
    scopes: frozenset[str]
    benefit_count: int
    contradiction_provenances: frozenset[str]
    classification: str
    last_used_at: str | None
    deprecated_at: str | None = None
    superseded_by: str | None = None
    replacement_active: bool = False
    pinned: bool = False
    legal_hold: bool = False
    exposure_count: int = 0
    member_ids: tuple[str, ...] = ()
    canonical_claim: str = ""
    polarity: str = "MIXED"
    contradiction_ids: tuple[str, ...] = ()
    provenance_scopes: tuple[str, ...] = ()
    last_observed_at: datetime | str | None = None
    precondition: str | None = None
    failure_mode: str | None = None
    version_constraint: str | None = None
    evidence_refs: tuple[str, ...] = ()
    applicability: tuple[str, ...] = ()
    revision: int = 0
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetrievalHit:
    pattern_id: str
    cluster_id: str
    score: float
    rule: str
    applicability: tuple[str, ...]
    evidence_count: int
    updated_at: str
    knowledge_scope: str = "personal"
    claim_fingerprint: str = ""
    supersedes: tuple[str, ...] = ()
    precondition: str = ""
    failure_mode: str = ""


@dataclass(frozen=True)
class CaptureContext:
    session_id: str
    turn_id: str
    capture_index: int
    source_host_id: str = ""
    source_host_family: str = ""


@dataclass(frozen=True)
class CaptureResult:
    created: bool
    event_id: str | None
    reason_code: str


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    reason_codes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.valid

    @property
    def reasons(self) -> tuple[str, ...]:
        return self.reason_codes


@dataclass(frozen=True)
class PatternState:
    pattern_id: str
    rule: str
    precondition: str = ""
    scope: str = ""
    evidence_ids: tuple[str, ...] = ()
    benefit_refs: tuple[str, ...] = ()
    exceptions: tuple[str, ...] = ()
    version_constraint: str | None = None
    status: str = "active"
    classification: str = "private-reusable"
    utility: float = 0.0
    cluster_id: str = ""
    applicability: tuple[str, ...] = ()
    updated_at: datetime | str | None = None
    contradiction_count: int = 0
    pinned: bool = False
    legal_hold: bool = False
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class KnowledgeIndex:
    index_path: Path
    generation_hash: str
    item_count: int
    schema_version: str = "2"
    manifest_path: Path | None = None
    manifest_sha256: str = ""
    active_pattern_ids: tuple[str, ...] = ()
    archive_pattern_ids: tuple[str, ...] = ()
    observation_count: int = 0
    always_on_chars: int = 0
    # Candidate IDs were omitted from the original handle. Keep the field at
    # the end with a default so existing positional construction remains valid.
    candidate_pattern_ids: tuple[str, ...] = ()

    @property
    def knowledge_index(self) -> "KnowledgeIndex":
        return self


@dataclass(frozen=True)
class PromotionPolicy:
    independent_provenance_count: int = 2
    distinct_scope_count: int = 2
    benefit_evidence_count: int = 1
    max_unresolved_contradictions: int = 0
    min_rule_chars: int = 80
    max_rule_chars: int = 1200
    contradiction_count_for_deprecation: int = 3
    unused_days_for_deprecation: int = 180
    superseded_unused_days_for_tombstone: int = 90
    deprecated_unused_days_for_tombstone: int = 365
    policy_version: str = "promotion-v1"
    always_on_target_chars: int = 9000
    always_on_hard_cap_chars: int = 12000
    candidate_retention_days: int = 180
    tombstone_retention_days: int = 365

    @classmethod
    def defaults(cls) -> "PromotionPolicy":
        return cls()
