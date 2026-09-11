"""Closed-schema and privacy checks for values that may cross the journal boundary."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .privacy import inspect_persisted_text
from .models import validate_host_applicability_mapping, validate_host_label


_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_SAFE_REASON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,79}$")
_HOST_SCOPES = frozenset({"universal", "family", "host"})
_PATH_FIELD_NAMES = frozenset({
    "path", "file", "file_path", "target_path", "relative_path", "repository_path",
    "source_path", "cwd_path", "local_path", "client_path", "user_home", "source_ref",
    "cwd", "working_directory", "workspace", "workspace_path",
})
_HASHED_FIELD_NAMES = frozenset({
    "source_hash", "source_ref_hash", "source_hashes", "evidence_refs", "reference_hash",
    "record_fingerprint", "cwd_fingerprint", "user_id_hash", "machine_id_hash", "host_id_hash",
    "session_id_hash", "turn_id_hash",
})
_FORBIDDEN_KEYS = frozenset({
    "body", "candidate_text", "raw", "raw_input", "raw_response", "response", "transcript",
    "tool_output", "prompt", "query", "context", "secret", "token", "password",
})
_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]")
_UNIX_PERSONAL_PATH = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home|private/var|tmp)(?:/|$)", re.IGNORECASE)
_PERSONAL_FIELD_NAMES = frozenset({
    "author", "email", "username", "user", "user_id", "client", "client_id", "client_name",
    "customer", "customer_id", "customer_name", "owner", "identity", "approval_identity",
    "approved_by",
})

# These reason codes mark a value that must not be retried into the durable
# knowledge/change-set boundary.  Keep the classification here, next to the
# validator that emits the codes, so queue maintenance cannot drift from the
# privacy/schema safety contract.
PERSISTABLE_PRIVACY_SAFETY_CODES = frozenset({
    "SECRET_PATTERN_MATCH",
    "ABSOLUTE_PATH_FORBIDDEN",
    "UNICODE_CONTROL_FORBIDDEN",
    "IDENTIFIER_HASH_REQUIRED",
    "PERSONAL_OR_CLIENT_IDENTIFIER_FORBIDDEN",
    "MACHINE_LOCAL_SOURCE",
    "MACHINE_LOCAL_PATH",
    "PAYLOAD_TOO_LARGE",
    "CHANGESET_TOO_LARGE",
    "RAW_CONTENT_FORBIDDEN",
    "PRIVACY_REJECTED",
    "CLIENT_CONFIDENTIAL_REMOTE_FORBIDDEN",
    "PATH_TRAVERSAL",
    "CLASSIFICATION_NOT_SYNCABLE",
    "HOST_APPLICABILITY_INVALID",
    "PERSISTED_PAYLOAD_TOO_LARGE",
    "JSON_VALUE_INVALID",
    "QUEUE_PAYLOAD_INVALID",
    "QUEUE_SOURCE_HOST_PAIR_REQUIRED",
    "SPOOL_READ_FAILED",
    "SPOOL_NOT_FOUND",
    "SPOOL_DECRYPT_FAILED",
})
PERSISTABLE_PRIVACY_SAFETY_PREFIXES = (
    "PRIVACY_",
    "RAW_",
    "SECRET_",
    "ABSOLUTE_PATH_",
    "UNICODE_CONTROL_",
    "IDENTIFIER_",
    "PERSONAL_OR_CLIENT_",
    "MACHINE_LOCAL_",
    "PAYLOAD_TOO_LARGE",
    "CLIENT_CONFIDENTIAL_",
    "PATH_TRAVERSAL",
    "HOST_APPLICABILITY_",
    "HOST_LIST_",
    "QUEUE_SOURCE_HOST_",
    "SPOOL_",
)


def is_privacy_or_safety_violation(reason_code: object) -> bool:
    """Return whether a validator reason requires local quarantine."""

    if not isinstance(reason_code, str):
        return False
    code = reason_code.strip().upper()
    return bool(
        code
        and (
            code in PERSISTABLE_PRIVACY_SAFETY_CODES
            or code.startswith(PERSISTABLE_PRIVACY_SAFETY_PREFIXES)
        )
    )

# This is intentionally closed. Adding a field requires a schema and test update.
CHANGESET_PAYLOAD_FIELDS: dict[str, tuple[str, int | None]] = {
    "actor": ("string", 160),
    "provider_id": ("string", 160),
    "classification": ("classification", 32),
    "source_hash": ("hash", 71),
    "source_ref_hash": ("hash", 71),
    "source_hashes": ("hash_list", None),
    "evidence_refs": ("hash_list", None),
    "provenances": ("string_list", 240),
    "record_fingerprint": ("hash", 71),
    "session_id_hash": ("optional_hash", 71),
    "turn_id_hash": ("optional_hash", 71),
    "provenance_key": ("string", 240),
    "title": ("string", 160),
    "claim": ("string", 1200),
    "rule": ("string", 12000),
    "precondition": ("string", 500),
    "failure_mode": ("string", 500),
    "exception": ("string", 500),
    "version_constraint": ("nullable_string", 160),
    "domain": ("string", 160),
    "scopes": ("string_list", 240),
    "applicability": ("string_list", 240),
    "benefit": ("string", 240),
    "benefit_count": ("nonnegative_integer", None),
    "source_kind": ("string", 80),
    "source_ref": ("string", 240),
    "outcome_status": ("string", 80),
    "reason_code": ("reason", 80),
    "pattern_id": ("identifier", 160),
    "cluster_id": ("identifier", 160),
    "proposal_only": ("boolean", None),
    "contradiction_count": ("nonnegative_integer", None),
    "revision": ("nonnegative_integer", None),
    "approved_by": ("approval_identity", 71),
    "approval_identity_hash": ("hash", 71),
    "cwd_fingerprint": ("optional_hash", 71),
    "user_id_hash": ("optional_hash", 71),
    "machine_id_hash": ("optional_hash", 71),
    "host_id_hash": ("optional_hash", 71),
    "reference_hash": ("hash", 71),
    "match_kind": ("match_kind", 16),
    "source_host_id": ("optional_safe_label", 160),
    "source_host_family": ("optional_safe_label", 160),
    "applicability_scope": ("applicability_scope", 16),
    "applicable_host_ids": ("host_label_list", None),
    "applicable_host_families": ("host_label_list", None),
}

# The append-only journal is a privacy boundary, not a generic JSON store.
# This registry is deliberately a closed union of fields emitted by supported
# engine event families.  Event-specific semantic validation remains in the
# producer/domain layer, while this gate prevents an otherwise valid caller
# from adding raw notes, transcripts, paths, or unhashed session identifiers.
EVENT_PAYLOAD_FIELDS: dict[str, tuple[str, int | None]] = {
    "actor": ("string", 160),
    "provider_id": ("string", 160),
    "classification": ("string", 32),
    "knowledge_scope": ("safe_label", 32),
    "origin_event_hash": ("optional_hash", 71),
    "source_hash": ("optional_hash", 71),
    "source_ref_hash": ("optional_hash", 71),
    "source_hashes": ("hash_list", 71),
    "record_fingerprint": ("optional_hash", 71),
    "cwd_fingerprint": ("optional_hash", 71),
    "session_id_hash": ("optional_hash", 71),
    "turn_id_hash": ("optional_hash", 71),
    "user_id_hash": ("optional_hash", 71),
    "machine_id_hash": ("optional_hash", 71),
    "host_id_hash": ("optional_hash", 71),
    "reference_hash": ("optional_hash", 71),
    "approval_identity_hash": ("optional_hash", 71),
    "observation_fingerprint": ("optional_hash", 71),
    "legacy_source_event_id_hash": ("optional_hash", 71),
    "target_id_hash": ("optional_hash", 71),
    "idempotency_key": ("optional_hash", 71),
    "evidence_refs": ("string_list", 240),
    "provenances": ("string_list", 240),
    "event_ids": ("string_list", 160),
    "provenance_key": ("string", 240),
    "title": ("string", 160),
    "claim": ("string", 1200),
    "rule": ("string", 12000),
    "precondition": ("string", 500),
    "failure_mode": ("string", 500),
    "exception": ("string", 500),
    "version_constraint": ("nullable_string", 160),
    "domain": ("string", 160),
    "scopes": ("string_list", 240),
    "scope": ("string_list", 240),
    "preconditions": ("string_list", 500),
    "failure_modes": ("string_list", 500),
    "applicability": ("string_list", 240),
    "benefit": ("string", 240),
    "source_kind": ("string", 80),
    "outcome_status": ("string", 80),
    "reason": ("string", 160),
    "reason_code": ("reason", 80),
    "pattern_id": ("string", 160),
    "cluster_id": ("string", 160),
    "candidate_id": ("string", 160),
    "candidate_id_hash": ("optional_hash", 71),
    "changeset_id": ("string", 160),
    "observation_id": ("string", 160),
    "reference_id": ("string", 160),
    "change_operation": ("string", 80),
    "changeset_hash": ("string", 160),
    "policy_version": ("string", 160),
    "status": ("string", 80),
    "decision": ("string", 16),
    "parser_status": ("string", 80),
    "capture_path": ("string", 80),
    "capture_idempotency_key": ("string", 160),
    "host_id": ("string", 160),
    "audit_action": ("string", 160),
    "last_used_at": ("nullable_string", 80),
    "benefit_count": ("nonnegative_integer", None),
    "evidence_count": ("nonnegative_integer", None),
    "revision": ("nonnegative_integer", None),
    "contradiction_count": ("nonnegative_integer", None),
    "operation_count": ("nonnegative_integer", None),
    "capture_index": ("nonnegative_integer", None),
    "exposure_count": ("nonnegative_integer", None),
    "old_version": ("string_or_integer", 160),
    "new_version": ("string_or_integer", 160),
    "migration": ("boolean", None),
    "status_is_not_evidence": ("boolean", None),
    "source_host_id": ("optional_safe_label", 160),
    "source_host_family": ("optional_safe_label", 160),
    "applicability_scope": ("applicability_scope", 16),
    "applicable_host_ids": ("host_label_list", None),
    "applicable_host_families": ("host_label_list", None),
}


@dataclass(frozen=True)
class PersistableIssue:
    pointer: str
    reason_code: str

    def to_dict(self) -> dict[str, str]:
        return {"pointer": self.pointer, "reason_code": self.reason_code}


@dataclass(frozen=True)
class PersistableInspection:
    valid: bool
    inspected_paths: tuple[str, ...] = ()
    normalized_values: tuple[tuple[str, str], ...] = ()
    issues: tuple[PersistableIssue, ...] = ()

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.reason_code for item in self.issues))

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "inspected_paths": list(self.inspected_paths),
            "normalized_values": dict(self.normalized_values) if self.valid else {},
            "issues": [item.to_dict() for item in self.issues],
        }


def _pointer(parent: str, part: str | int) -> str:
    escaped = str(part).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}" if parent else f"/{escaped}"


def _field_name(pointer: str) -> str:
    return pointer.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~").casefold()


def _is_path_like(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return (
        normalized.startswith("/")
        or bool(re.match(r"^[A-Za-z]:/", normalized))
        or normalized.startswith("~/")
        or normalized in {".", ".."}
        or ".." in normalized.split("/")
    )


def _issue(issues: list[PersistableIssue], pointer: str, reason: str) -> None:
    issues.append(PersistableIssue(pointer or "/", reason))


def _validate_string(
    value: str,
    pointer: str,
    field_name: str,
    limit: int | None,
    classification: str,
    issues: list[PersistableIssue],
    normalized_values: dict[str, str],
    *,
    require_hash: bool = False,
) -> None:
    normalized = unicodedata.normalize("NFKC", value)
    if limit is not None and len(normalized) > limit:
        _issue(issues, pointer, "FIELD_LENGTH_EXCEEDED")
        return
    if any(unicodedata.category(char) in {"Cc", "Cf"} and char not in "\t\n\r" for char in normalized):
        _issue(issues, pointer, "UNICODE_CONTROL_FORBIDDEN")
        return
    if field_name in _PATH_FIELD_NAMES and _is_path_like(normalized):
        _issue(issues, pointer, "ABSOLUTE_PATH_FORBIDDEN")
        return
    if _WINDOWS_ABSOLUTE_PATH.search(normalized) or _UNIX_PERSONAL_PATH.search(normalized):
        _issue(issues, pointer, "ABSOLUTE_PATH_FORBIDDEN")
        return
    if require_hash and normalized and not _HASH.fullmatch(normalized):
        _issue(issues, pointer, "IDENTIFIER_HASH_REQUIRED")
        return
    decision = inspect_persisted_text(normalized, classification, pointer)
    if not decision.allow_private_sync and decision.reason_code != "CLASSIFIED":
        _issue(issues, pointer, decision.reason_code)
        return
    if ("email" in field_name or field_name in _PERSONAL_FIELD_NAMES) and not _HASH.fullmatch(normalized):
        _issue(issues, pointer, "PERSONAL_OR_CLIENT_IDENTIFIER_FORBIDDEN")
        return
    normalized_values[pointer] = normalized


def _walk(
    value: Any,
    pointer: str,
    classification: str,
    issues: list[PersistableIssue],
    inspected: list[str],
    normalized_values: dict[str, str],
    *,
    closed_fields: Mapping[str, tuple[str, int | None]] | None = None,
    field_name: str = "",
    expected: tuple[str, int | None] | None = None,
) -> None:
    if isinstance(value, str):
        inspected.append(pointer or "/")
        kind, limit = expected or ("string", None)
        if kind == "hash":
            _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values, require_hash=True)
        elif kind == "optional_hash":
            _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values, require_hash=True)
        elif kind == "identifier":
            if not _SAFE_LABEL.fullmatch(value):
                _issue(issues, pointer, "IDENTIFIER_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "reason":
            if not _SAFE_REASON.fullmatch(value):
                _issue(issues, pointer, "REASON_CODE_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "classification":
            if value not in {"public", "private-reusable"}:
                _issue(issues, pointer, "CLASSIFICATION_NOT_SYNCABLE")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "approval_identity":
            if not _HASH.fullmatch(value):
                _issue(issues, pointer, "IDENTIFIER_HASH_REQUIRED")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "match_kind":
            if value not in {"exact", "similar"}:
                _issue(issues, pointer, "MATCH_KIND_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "optional_safe_label":
            try:
                validate_host_label(value, field=field_name, allow_empty=True)
            except ValueError:
                _issue(issues, pointer, "IDENTIFIER_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "safe_label":
            try:
                validate_host_label(value, field=field_name)
            except ValueError:
                _issue(issues, pointer, "IDENTIFIER_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        elif kind == "applicability_scope":
            if value not in _HOST_SCOPES:
                _issue(issues, pointer, "APPLICABILITY_SCOPE_INVALID")
            else:
                _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        else:
            _validate_string(value, pointer, field_name, limit, classification, issues, normalized_values)
        return
    if value is None:
        if expected is not None and expected[0] != "nullable_string":
            _issue(issues, pointer, "NULL_NOT_ALLOWED")
        return
    if isinstance(value, bool):
        if expected is not None and expected[0] != "boolean":
            _issue(issues, pointer, "TYPE_INVALID")
        return
    if isinstance(value, int):
        if expected is not None and (expected[0] not in {"nonnegative_integer", "string_or_integer"} or value < 0):
            _issue(issues, pointer, "TYPE_INVALID")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _issue(issues, pointer, "JSON_VALUE_INVALID")
        elif expected is not None:
            _issue(issues, pointer, "TYPE_INVALID")
        return
    if isinstance(value, Mapping):
        if expected is not None:
            _issue(issues, pointer, "NESTED_OBJECT_FORBIDDEN")
            return
        for key, nested in value.items():
            if not isinstance(key, str):
                _issue(issues, pointer, "FIELD_NAME_INVALID")
                continue
            child = _pointer(pointer, key)
            if key.casefold() in _FORBIDDEN_KEYS:
                _issue(issues, child, "RAW_CONTENT_FORBIDDEN")
            child_expected = None
            if closed_fields is not None:
                child_expected = closed_fields.get(key)
                if child_expected is None:
                    _issue(issues, child, "UNKNOWN_FIELD")
                    continue
            _walk(
                nested,
                child,
                classification,
                issues,
                inspected,
                normalized_values,
                closed_fields=None,
                field_name=key.casefold(),
                expected=child_expected,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if expected is not None and expected[0] not in {"hash_list", "string_list", "host_label_list"}:
            _issue(issues, pointer, "TYPE_INVALID")
            return
        if expected is not None and expected[0] == "host_label_list":
            if len(value) > 16:
                _issue(issues, pointer, "HOST_LIST_TOO_LARGE")
            labels = [item for item in value if isinstance(item, str)]
            if len(labels) != len(value) or len(set(labels)) != len(labels):
                _issue(issues, pointer, "HOST_LIST_INVALID")
        if expected is not None and not value:
            return
        child_expected = (
            ("hash", expected[1])
            if expected is not None and expected[0] == "hash_list"
            else ("safe_label", 160)
            if expected is not None and expected[0] == "host_label_list"
            else ("string", expected[1])
            if expected is not None
            else None
        )
        for index, nested in enumerate(value):
            _walk(
                nested,
                _pointer(pointer, index),
                classification,
                issues,
                inspected,
                normalized_values,
                field_name=field_name,
                expected=child_expected,
            )
        return
    _issue(issues, pointer, "TYPE_INVALID")


def inspect_persistable(
    value: Any,
    *,
    classification: str = "private-reusable",
    closed_fields: Mapping[str, tuple[str, int | None]] | None = None,
    max_bytes: int = 512 * 1024,
) -> PersistableInspection:
    issues: list[PersistableIssue] = []
    inspected: list[str] = []
    normalized_values: dict[str, str] = {}
    try:
        encoded_size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        _issue(issues, "/", "JSON_VALUE_INVALID")
        encoded_size = 0
    if encoded_size > max_bytes:
        _issue(issues, "/", "PERSISTED_PAYLOAD_TOO_LARGE")
    _walk(value, "", classification, issues, inspected, normalized_values, closed_fields=closed_fields)
    if isinstance(value, Mapping) and any(
        field in value
        for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")
    ):
        try:
            # A payload crossing this boundary is new data, not the legacy
            # read-only projection.  Host-scoped data therefore needs the
            # trusted source pair; curator normalization is the only layer
            # allowed to repair a malformed provider scope.
            validate_host_applicability_mapping(value, allow_legacy=False, require_source_pair=True)
        except ValueError:
            _issue(issues, "/applicability_scope", "HOST_APPLICABILITY_INVALID")
    unique_issues = tuple(dict.fromkeys(issues))
    return PersistableInspection(
        not unique_issues,
        tuple(dict.fromkeys(inspected)),
        tuple(sorted(normalized_values.items())) if not unique_issues else (),
        unique_issues,
    )


def inspect_changeset_payload(payload: Mapping[str, Any], *, classification: str = "private-reusable") -> PersistableInspection:
    if not isinstance(payload, Mapping):
        return PersistableInspection(False, issues=(PersistableIssue("/payload", "PAYLOAD_OBJECT_REQUIRED"),))
    return inspect_persistable(payload, classification=classification, closed_fields=CHANGESET_PAYLOAD_FIELDS)


def inspect_event_payload(payload: Mapping[str, Any], *, classification: str = "private-reusable") -> PersistableInspection:
    """Apply the closed journal field registry before append or read."""
    return inspect_persistable(
        payload,
        classification=classification,
        closed_fields=EVENT_PAYLOAD_FIELDS,
        max_bytes=1024 * 1024,
    )


__all__ = [
    "CHANGESET_PAYLOAD_FIELDS",
    "EVENT_PAYLOAD_FIELDS",
    "PERSISTABLE_PRIVACY_SAFETY_CODES",
    "PERSISTABLE_PRIVACY_SAFETY_PREFIXES",
    "PersistableInspection",
    "PersistableIssue",
    "inspect_changeset_payload",
    "inspect_event_payload",
    "inspect_persistable",
    "is_privacy_or_safety_violation",
]
