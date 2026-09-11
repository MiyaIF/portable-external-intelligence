from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .ids import canonical_json
from .models import Event, validate_host_applicability_mapping, validate_host_label
from .persistable_fields import inspect_changeset_payload, inspect_event_payload

MAX_EVENT_PAYLOAD_BYTES = 1024 * 1024
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_HOST_SCOPE_VALUES = frozenset({"universal", "family", "host"})
_EVENT_ID_RE = re.compile(r"^evt_[0-9TZ]+_[0-9a-f]{12}$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_FIXED_CHANGESET_OPERATIONS = {
    "CREATE_OBSERVATION",
    "ATTACH_EVIDENCE",
    "CREATE_CANDIDATE",
    "PROMOTE_PATTERN",
    "REVISE_PATTERN",
    "DEPRECATE_PATTERN",
    "TOMBSTONE_PATTERN",
    "REDACT_REFERENCE",
    "NO_CHANGE",
}
_FORBIDDEN_TRANSIENT_KEYS = {"transient_input", "raw_response", "body", "candidate_text"}



class JournalIntegrityError(ValueError):
    """Raised when an append-only event is invalid or tampered with."""



def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()



def _sha256_prefixed(raw: bytes) -> str:
    return "sha256:" + _sha256_hex(raw)



def _canonical_bytes(data: dict) -> bytes:
    return canonical_json(data)



def event_integrity(event: Event) -> str:
    return _sha256_hex(_canonical_bytes(event.canonical_dict()))



def _canonical_payload_hash(event: Event) -> str:
    return _sha256_prefixed(canonical_json(event.payload))



def _materialize(event: Event) -> Event:
    materialized = event
    if materialized.schema_version >= 2:
        materialized = replace(
            materialized,
            integrity={
                "algorithm": "sha256",
                "canonical_payload_hash": _canonical_payload_hash(materialized),
            },
        )
    return replace(materialized, integrity_sha256=event_integrity(materialized))



def _raise_schema_invalid(reason: str) -> None:
    raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{reason}")



def _validate_schema(event: Event) -> None:
    if type(event.schema_version) is not int or event.schema_version not in (1, 2):
        _raise_schema_invalid("schema_version")
    if not event.event_id:
        _raise_schema_invalid("event_id")
    if event.schema_version >= 2 and not _EVENT_ID_RE.fullmatch(event.event_id):
        _raise_schema_invalid("event_id")
    if not event.event_type:
        _raise_schema_invalid("event_type")
    if not event.actor:
        _raise_schema_invalid("actor")
    if not event.machine_id:
        _raise_schema_invalid("machine_id")
    if event.schema_version >= 2:
        _require_datetime("event", "occurred_at", event.occurred_at)
    if not isinstance(event.payload, dict):
        _raise_schema_invalid("payload")
    try:
        payload_bytes = canonical_json(event.payload)
    except (TypeError, ValueError) as exc:
        raise JournalIntegrityError("EVENT_SCHEMA_INVALID:payload") from exc
    if len(payload_bytes) > MAX_EVENT_PAYLOAD_BYTES:
        raise JournalIntegrityError("EVENT_PAYLOAD_TOO_LARGE:payload")
    if event.schema_version >= 2:
        if not _HASH_RE.fullmatch(event.idempotency_key):
            _raise_schema_invalid("idempotency_key")
        if not isinstance(event.provenance, tuple):
            _raise_schema_invalid("provenance")
        if not isinstance(event.integrity, dict):
            _raise_schema_invalid("integrity")
        if set(event.integrity) - {"algorithm", "canonical_payload_hash"}:
            _raise_schema_invalid("integrity")
        if event.integrity.get("algorithm") != "sha256":
            _raise_schema_invalid("integrity.algorithm")
        if event.integrity.get("canonical_payload_hash") != _sha256_prefixed(payload_bytes):
            raise JournalIntegrityError("EVENT_INTEGRITY_INVALID:canonical_payload_hash")



def _validate_incoming_v2_event(event: Event) -> None:
    _validate_schema(event)
    _validate_persisted_event_payload(event)
    if event.integrity_sha256 and event.integrity_sha256 != event_integrity(event):
        raise JournalIntegrityError(f"EVENT_INTEGRITY_INVALID:{event.event_id}")



def _validate_stored_integrity(event: Event) -> None:
    if event.integrity_sha256 != event_integrity(event):
        raise JournalIntegrityError(f"EVENT_INTEGRITY_INVALID:{event.event_id}")
    if event.schema_version >= 2 and event.integrity.get("canonical_payload_hash") != _canonical_payload_hash(event):
        raise JournalIntegrityError(f"EVENT_INTEGRITY_INVALID:{event.event_id}")



def _schema_error(name: str, reason: str) -> None:
    raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{name}.{reason}")


def _require_mapping(name: str, value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _schema_error(name, "type")
    return value


def _require_string(name: str, field: str, value: Any, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value) < minimum:
        _schema_error(name, field)
    return value


def _require_optional_string(name: str, field: str, value: Any) -> str | None:
    if value is None:
        return None
    return _require_string(name, field, value)


def _require_hash(name: str, field: str, value: Any) -> str:
    text = _require_string(name, field, value)
    if not _HASH_RE.fullmatch(text):
        _schema_error(name, field)
    return text


def _require_safe_label(name: str, field: str, value: Any, *, allow_empty: bool = False) -> str:
    try:
        validate_host_label(value, field=field, allow_empty=allow_empty)
    except ValueError:
        _schema_error(name, field)
    return value


def _require_host_applicability(name: str, value: Mapping[str, Any], *, allow_legacy: bool = True, require_source_pair: bool = False) -> None:
    try:
        validate_host_applicability_mapping(
            value,
            allow_legacy=allow_legacy,
            require_source_pair=require_source_pair,
        )
    except ValueError as exc:
        reason = str(exc).split(":", 1)[0].lower()
        _schema_error(name, reason)


def _require_host_list(name: str, field: str, value: Any) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)) or len(value) > 16:
        _schema_error(name, field)
    labels = list(value)
    if len(set(labels)) != len(labels):
        _schema_error(name, field)
    for item in labels:
        _require_safe_label(name, field, item)


def _require_datetime(name: str, field: str, value: Any) -> str:
    text = _require_string(name, field, value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{name}.{field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _schema_error(name, field)
    return text



def _reject_extra(name: str, value: Mapping[str, Any], allowed: set[str]) -> None:
    extra = set(value) - allowed
    if extra:
        _schema_error(name, sorted(extra)[0])



def _reject_forbidden_content(name: str, value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in _FORBIDDEN_TRANSIENT_KEYS:
                _schema_error(name, key)
            _reject_forbidden_content(name, nested)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            _reject_forbidden_content(name, nested)


def _validate_spool_ref(name: str, value: Any) -> None:
    data = _require_mapping(name, value)
    _require_string(name, "spool_id", data.get("spool_id"))
    _require_hash(name, "content_hash", data.get("content_hash"))
    _require_string(name, "classification", data.get("classification"))
    _require_datetime(name, "created_at", data.get("created_at"))
    _require_datetime(name, "expires_at", data.get("expires_at"))
    key_id = data.get("key_id")
    if key_id is not None:
        _require_string(name, "key_id", key_id)
    if not isinstance(data.get("encrypted"), bool):
        _schema_error(name, "encrypted")
    allowed = {"spool_id", "content_hash", "classification", "created_at", "expires_at", "key_id", "encrypted"}
    extra = set(data) - allowed
    if extra:
        _schema_error(name, sorted(extra)[0])


def _validate_hook_event(value: Mapping[str, Any]) -> None:
    name = "hook-event"
    _reject_extra(name, value, {"event_id", "idempotency_key", "host_id", "host_instance_id", "host_event_name", "normalized_event_name", "session_id_hash", "turn_id_hash", "cwd_hash", "source_ref", "source_hash", "payload_hash", "received_at", "privacy_classification", "source_host_id", "source_host_family"})
    for field in ("event_id", "idempotency_key", "host_id", "host_instance_id", "host_event_name", "normalized_event_name", "session_id_hash", "turn_id_hash", "cwd_hash", "source_hash", "payload_hash", "received_at", "privacy_classification"):
        if field not in value:
            _schema_error(name, field)
    event_id = _require_string(name, "event_id", value["event_id"])
    if not _EVENT_ID_RE.fullmatch(event_id):
        _schema_error(name, "event_id")
    for field in ("idempotency_key", "session_id_hash", "turn_id_hash", "cwd_hash", "source_hash", "payload_hash"):
        _require_hash(name, field, value[field])
    _require_optional_string(name, "source_ref", value.get("source_ref"))
    _require_datetime(name, "received_at", value["received_at"])
    if "source_host_id" in value:
        _require_safe_label(name, "source_host_id", value["source_host_id"])
    if "source_host_family" in value:
        _require_safe_label(name, "source_host_family", value["source_host_family"], allow_empty=True)
    _reject_forbidden_content(name, value)


def _validate_queue_item(value: Mapping[str, Any]) -> None:
    name = "queue-item"
    _reject_extra(name, value, {"queue_id", "event_id", "idempotency_key", "stage", "state", "attempts", "created_at", "next_eligible_at", "source_ref", "source_hash", "host_id", "session_id_hash", "turn_id_hash", "payload_ref", "provider_preference", "privacy_classification", "lease_owner", "lease_expires_at", "last_error_code", "source_host_id", "source_host_family"})
    required = ("queue_id", "event_id", "idempotency_key", "stage", "state", "attempts", "created_at", "source_hash", "host_id", "session_id_hash", "turn_id_hash", "payload_ref", "provider_preference", "privacy_classification")
    for field in required:
        if field not in value:
            _schema_error(name, field)
    if "body" in value:
        _schema_error(name, "body")
    _require_string(name, "queue_id", value["queue_id"])
    event_id = _require_string(name, "event_id", value["event_id"])
    if not _EVENT_ID_RE.fullmatch(event_id):
        _schema_error(name, "event_id")
    _require_hash(name, "idempotency_key", value["idempotency_key"])
    _require_string(name, "stage", value["stage"])
    _require_string(name, "state", value["state"])
    if type(value["attempts"]) is not int or value["attempts"] < 0:
        _schema_error(name, "attempts")
    _require_datetime(name, "created_at", value["created_at"])
    if value.get("next_eligible_at") is not None:
        _require_datetime(name, "next_eligible_at", value["next_eligible_at"])
    _require_optional_string(name, "source_ref", value.get("source_ref"))
    _require_hash(name, "source_hash", value["source_hash"])
    _require_string(name, "host_id", value["host_id"])
    _require_hash(name, "session_id_hash", value["session_id_hash"])
    _require_hash(name, "turn_id_hash", value["turn_id_hash"])
    if value["payload_ref"] is not None:
        _validate_spool_ref("queue-item.payload_ref", value["payload_ref"])
    preferences = value["provider_preference"]
    if not isinstance(preferences, Sequence) or isinstance(preferences, (str, bytes, bytearray)):
        _schema_error(name, "provider_preference")
    for provider in preferences:
        _require_string(name, "provider_preference", provider)
    _require_string(name, "privacy_classification", value["privacy_classification"])
    _require_optional_string(name, "lease_owner", value.get("lease_owner"))
    if value.get("lease_expires_at") is not None:
        _require_datetime(name, "lease_expires_at", value["lease_expires_at"])
    _require_optional_string(name, "last_error_code", value.get("last_error_code"))
    if "source_host_id" in value:
        _require_safe_label(name, "source_host_id", value["source_host_id"])
    if "source_host_family" in value:
        _require_safe_label(name, "source_host_family", value["source_host_family"], allow_empty=True)
    _reject_forbidden_content(name, value)


def _validate_spool_envelope(value: Mapping[str, Any]) -> None:
    name = "spool-envelope"
    _reject_extra(name, value, {"spool_id", "algorithm", "nonce", "ciphertext", "aad_sha256", "content_sha256", "classification", "created_at", "expires_at", "key_id"})
    for field in ("spool_id", "algorithm", "nonce", "ciphertext", "aad_sha256", "content_sha256", "classification", "created_at", "expires_at", "key_id"):
        if field not in value:
            _schema_error(name, field)
    _require_string(name, "spool_id", value["spool_id"])
    if value["algorithm"] != "AES-256-GCM":
        _schema_error(name, "algorithm")
    nonce = _require_string(name, "nonce", value["nonce"])
    if len(nonce) != 16:
        _schema_error(name, "nonce")
    try:
        decoded_nonce = base64.b64decode(nonce, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{name}.nonce") from exc
    if len(decoded_nonce) != 12:
        _schema_error(name, "nonce")
    ciphertext = _require_string(name, "ciphertext", value["ciphertext"])
    try:
        base64.b64decode(ciphertext, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{name}.ciphertext") from exc
    _require_hash(name, "aad_sha256", value["aad_sha256"])
    _require_hash(name, "content_sha256", value["content_sha256"])
    _require_string(name, "classification", value["classification"])
    _require_datetime(name, "created_at", value["created_at"])
    _require_datetime(name, "expires_at", value["expires_at"])
    _require_string(name, "key_id", value["key_id"])
    _reject_forbidden_content(name, value)


def _validate_gate_decision(value: Mapping[str, Any]) -> None:
    name = "gate-decision"
    _reject_extra(name, value, {"decision", "reason_code", "candidate_title", "candidate_claim", "evidence_refs", "benefit", "classification", "confidence", "applicability_scope", "applicable_host_ids", "applicable_host_families", "source_host_id", "source_host_family", "processing_state", "retry_after_seconds", "next_eligible_at"})
    if value.get("decision") not in {"YES", "NO"}:
        _schema_error(name, "decision")
    _require_string(name, "reason_code", value.get("reason_code"))
    _require_string(name, "candidate_title", value.get("candidate_title"))
    _require_string(name, "candidate_claim", value.get("candidate_claim"), minimum=20)
    evidence_refs = value.get("evidence_refs")
    if not isinstance(evidence_refs, Sequence) or isinstance(evidence_refs, (str, bytes, bytearray)):
        _schema_error(name, "evidence_refs")
    for evidence_ref in evidence_refs:
        _require_hash(name, "evidence_refs", evidence_ref)
    _require_string(name, "benefit", value.get("benefit"))
    _require_string(name, "classification", value.get("classification"))
    confidence = value.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
        _schema_error(name, "confidence")
    if value.get("decision") == "YES":
        for field in ("applicability_scope", "applicable_host_ids", "applicable_host_families"):
            if field not in value:
                _schema_error(name, field)
        scope = value["applicability_scope"]
        if scope not in _HOST_SCOPE_VALUES:
            _schema_error(name, "applicability_scope")
        _require_host_list(name, "applicable_host_ids", value["applicable_host_ids"])
        _require_host_list(name, "applicable_host_families", value["applicable_host_families"])
        if scope == "universal" and (value["applicable_host_ids"] or value["applicable_host_families"]):
            _schema_error(name, "applicability_scope")
        if scope == "family" and (not value["applicable_host_families"] or value["applicable_host_ids"]):
            _schema_error(name, "applicability_scope")
        if scope == "host" and (not value["applicable_host_ids"] or value["applicable_host_families"]):
            _schema_error(name, "applicability_scope")
    for field in ("source_host_id", "source_host_family"):
        if field in value:
            _require_safe_label(name, field, value[field], allow_empty=True)
    if value.get("decision") == "YES" and any(field in value for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
        gate_scope = {
            "source_host_id": value.get("source_host_id", ""),
            "source_host_family": value.get("source_host_family", ""),
            "applicability_scope": value["applicability_scope"],
            "applicable_host_ids": value["applicable_host_ids"],
            "applicable_host_families": value["applicable_host_families"],
        }
        _require_host_applicability(name, gate_scope, allow_legacy=False, require_source_pair=False)


def _validate_change_set(value: Mapping[str, Any]) -> None:
    name = "change-set"
    _reject_extra(name, value, {"changeset_id", "candidate_id", "operations", "source_hashes", "policy_version", "generated_at", "provider_id", "source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families"})
    for field in ("changeset_id", "candidate_id", "operations", "source_hashes", "policy_version", "generated_at", "provider_id"):
        if field not in value:
            _schema_error(name, field)
    _require_string(name, "changeset_id", value["changeset_id"])
    _require_string(name, "candidate_id", value["candidate_id"])
    operations = value["operations"]
    if not isinstance(operations, Sequence) or isinstance(operations, (str, bytes, bytearray)) or not operations:
        _schema_error(name, "operations")
    for operation in operations:
        data = _require_mapping(f"{name}.operations", operation)
        _reject_extra(f"{name}.operations", data, {"operation", "target_id", "payload"})
        if "operation" not in data or "target_id" not in data or "payload" not in data:
            _schema_error(f"{name}.operations", "required")
        if data.get("operation") not in _FIXED_CHANGESET_OPERATIONS:
            _schema_error(name, "operation")
        if data.get("target_id") is not None:
            _require_string(name, "target_id", data.get("target_id"))
        payload = _require_mapping(name, data.get("payload"))
        inspection = inspect_changeset_payload(
            payload,
            classification=str(payload.get("classification", "private-reusable")),
        )
        if not inspection.valid:
            issue = inspection.issues[0]
            _schema_error(name, f"{issue.pointer}:{issue.reason_code}")
    hashes = value["source_hashes"]
    if not isinstance(hashes, Sequence) or isinstance(hashes, (str, bytes, bytearray)) or not hashes:
        _schema_error(name, "source_hashes")
    for source_hash in hashes:
        _require_hash(name, "source_hashes", source_hash)
    _require_string(name, "policy_version", value["policy_version"])
    _require_datetime(name, "generated_at", value["generated_at"])
    _require_string(name, "provider_id", value["provider_id"])
    for field in ("source_host_id", "source_host_family"):
        if field in value:
            _require_safe_label(name, field, value[field], allow_empty=True)
    if "applicability_scope" in value and value["applicability_scope"] not in _HOST_SCOPE_VALUES:
        _schema_error(name, "applicability_scope")
    for field in ("applicable_host_ids", "applicable_host_families"):
        if field in value:
            _require_host_list(name, field, value[field])
    if any(field in value for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
        _require_host_applicability(
            name,
            value,
            allow_legacy=False,
            require_source_pair=True,
        )


def _validate_host_certification_receipt(value: Mapping[str, Any]) -> None:
    name = "host-certification-receipt"
    _reject_extra(name, value, {"receipt_id", "mode", "host_id", "host_instance_id", "host_version", "os_family", "os_version", "python_version", "artifact_sha256", "event_sha256", "activation_state", "certified_at"})
    for field in ("receipt_id", "mode", "host_id", "host_instance_id", "host_version", "os_family", "os_version", "python_version", "artifact_sha256", "event_sha256", "activation_state", "certified_at"):
        if field not in value:
            _schema_error(name, field)
    if value["mode"] not in {"real", "fixture"}:
        _schema_error(name, "mode")
    for field in ("receipt_id", "host_id", "host_instance_id", "host_version", "os_family", "os_version", "python_version", "activation_state"):
        _require_string(name, field, value[field])
    _require_hash(name, "artifact_sha256", value["artifact_sha256"])
    _require_hash(name, "event_sha256", value["event_sha256"])
    _require_datetime(name, "certified_at", value["certified_at"])


def _validate_release_evidence(value: Mapping[str, Any]) -> None:
    name = "release-evidence"
    if value.get("evidence_type") == "public_release_evidence":
        from .release import validate_public_evidence_index

        try:
            validate_public_evidence_index(value)
        except (TypeError, ValueError) as exc:
            _schema_error(name, str(exc))
        return
    _reject_extra(name, value, {"evidence_type", "subject_commit_sha", "evidence_commit_sha", "manifest_sha256", "workflow_sha256", "certification_sha256", "attested_at"})
    evidence_type = value.get("evidence_type")
    if evidence_type not in {"subject_manifest", "post_push_attestation"}:
        _schema_error(name, "evidence_type")
    subject = _require_string(name, "subject_commit_sha", value.get("subject_commit_sha"))
    if not _COMMIT_SHA_RE.fullmatch(subject):
        _schema_error(name, "subject_commit_sha")
    for field in ("manifest_sha256", "workflow_sha256"):
        _require_hash(name, field, value.get(field))
    cert_hashes = value.get("certification_sha256")
    if not isinstance(cert_hashes, Sequence) or isinstance(cert_hashes, (str, bytes, bytearray)) or not cert_hashes:
        _schema_error(name, "certification_sha256")
    for cert_hash in cert_hashes:
        _require_hash(name, "certification_sha256", cert_hash)
    evidence_commit = value.get("evidence_commit_sha")
    if evidence_type == "subject_manifest":
        if "evidence_commit_sha" in value:
            _schema_error(name, "evidence_commit_sha")
        return
    commit_text = _require_string(name, "evidence_commit_sha", evidence_commit)
    if not _COMMIT_SHA_RE.fullmatch(commit_text):
        _schema_error(name, "evidence_commit_sha")
    _require_datetime(name, "attested_at", value.get("attested_at"))


def _validate_event_mapping(value: Mapping[str, Any]) -> None:
    schema_version = value.get("schema_version", 1)
    if type(schema_version) is not int or schema_version not in (1, 2):
        _schema_error("event", "schema_version")
    common_required = ("event_id", "event_type", "occurred_at", "actor", "machine_id", "payload", "integrity_sha256")
    for field in common_required:
        if field not in value:
            _schema_error("event", field)
    allowed = set(common_required) | {"schema_version"}
    if schema_version == 2:
        allowed |= {"idempotency_key", "provenance", "integrity"}
        for field in ("idempotency_key", "provenance", "integrity"):
            if field not in value:
                _schema_error("event", field)
    _reject_extra("event", value, allowed)
    _require_string("event", "event_id", value["event_id"])
    _require_string("event", "event_type", value["event_type"])
    if schema_version == 2:
        _require_datetime("event", "occurred_at", value["occurred_at"])
    _require_string("event", "actor", value["actor"])
    _require_string("event", "machine_id", value["machine_id"])
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        _schema_error("event", "payload")
    integrity_sha256 = value["integrity_sha256"]
    if not isinstance(integrity_sha256, str):
        _schema_error("event", "integrity_sha256")
    if integrity_sha256 and not re.fullmatch(r"[0-9a-f]{64}", integrity_sha256):
        _schema_error("event", "integrity_sha256")
    if schema_version == 2:
        _require_hash("event", "idempotency_key", value["idempotency_key"])
        provenance = value["provenance"]
        if not isinstance(provenance, Sequence) or isinstance(provenance, (str, bytes, bytearray)):
            _schema_error("event", "provenance")
        for item in provenance:
            _require_string("event", "provenance", item)
        integrity = _require_mapping("event", value["integrity"])
        _reject_extra("event.integrity", integrity, {"algorithm", "canonical_payload_hash"})
        if integrity.get("algorithm") != "sha256":
            _schema_error("event", "integrity.algorithm")
        _require_hash("event", "canonical_payload_hash", integrity.get("canonical_payload_hash"))
    if schema_version == 2:
        _reject_forbidden_content("event", payload)
    event = Event.from_dict(value)
    _validate_schema(event)
    _validate_persisted_event_payload(event)


def _validate_persisted_event_payload(event: Event) -> None:
    """Independent privacy gate for direct journal callers."""
    inspection = inspect_event_payload(
        event.payload,
        classification=str(event.payload.get("classification", "private-reusable")),
    )
    if not inspection.valid:
        issue = inspection.issues[0]
        raise JournalIntegrityError(f"EVENT_PRIVACY_INVALID:{issue.pointer}:{issue.reason_code}")
    provenance_inspection = inspect_event_payload(
        list(event.provenance),
        classification=str(event.payload.get("classification", "private-reusable")),
    )
    if not provenance_inspection.valid:
        issue = provenance_inspection.issues[0]
        pointer = issue.pointer if issue.pointer.startswith("/") else f"/{issue.pointer}"
        raise JournalIntegrityError(f"EVENT_PRIVACY_INVALID:/provenance{pointer}:{issue.reason_code}")


def _validate_observation(value: Mapping[str, Any]) -> None:
    name = "observation"
    _reject_extra(name, value, {"observation_id", "title", "claim", "domain", "cwd_fingerprint", "provenance_key", "outcome_status", "benefit", "classification", "source_hash", "applicability", "source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families"})
    for field in ("observation_id", "title", "claim", "domain", "cwd_fingerprint", "provenance_key", "outcome_status", "benefit", "classification"):
        if field not in value:
            _schema_error(name, field)
    _require_string(name, "observation_id", value["observation_id"])
    title = _require_string(name, "title", value["title"])
    claim = _require_string(name, "claim", value["claim"], minimum=20)
    if len(title) > 160:
        _schema_error(name, "title")
    if len(claim) > 1200:
        _schema_error(name, "claim")
    _require_string(name, "domain", value["domain"])
    _require_string(name, "cwd_fingerprint", value["cwd_fingerprint"])
    _require_string(name, "provenance_key", value["provenance_key"])
    _require_string(name, "outcome_status", value["outcome_status"])
    _require_string(name, "benefit", value["benefit"])
    _require_string(name, "classification", value["classification"])
    source_hash = value.get("source_hash", "")
    if not isinstance(source_hash, str):
        _schema_error(name, "source_hash")
    if source_hash:
        _require_hash(name, "source_hash", source_hash)
    applicability = value.get("applicability", [])
    if not isinstance(applicability, Sequence) or isinstance(applicability, (str, bytes, bytearray)):
        _schema_error(name, "applicability")
    for item in applicability:
        _require_string(name, "applicability", item)
    if "source_host_id" in value:
        _require_safe_label(name, "source_host_id", value["source_host_id"], allow_empty=True)
    if "source_host_family" in value:
        _require_safe_label(name, "source_host_family", value["source_host_family"], allow_empty=True)
    if "applicability_scope" in value:
        if value["applicability_scope"] not in _HOST_SCOPE_VALUES:
            _schema_error(name, "applicability_scope")
    for field in ("applicable_host_ids", "applicable_host_families"):
        if field in value:
            _require_host_list(name, field, value[field])
    if any(field in value for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
        _require_host_applicability(name, value, allow_legacy=False, require_source_pair=True)
    _reject_forbidden_content(name, value)


def _validate_pattern(value: Mapping[str, Any]) -> None:
    name = "pattern"
    required = ("pattern_id", "status", "rule", "classification")
    _reject_extra(
        name,
        value,
        {
            *required,
            "cluster_id", "provenances", "scopes", "applicability", "benefit_count", "evidence_count",
            "precondition", "failure_mode", "version_constraint", "source_host_id", "source_host_family",
            "applicability_scope", "applicable_host_ids", "applicable_host_families",
        },
    )
    for field in required:
        if field not in value:
            _schema_error(name, field)
    _require_safe_label(name, "pattern_id", value["pattern_id"])
    if value["status"] not in {"candidate", "active", "deprecated", "superseded", "tombstoned"}:
        _schema_error(name, "status")
    _require_string(name, "rule", value["rule"])
    if len(value["rule"]) > 1200:
        _schema_error(name, "rule")
    if value["classification"] not in {"public", "private-reusable", "external-reference"}:
        _schema_error(name, "classification")
    for field in ("source_host_id", "source_host_family"):
        if field in value:
            _require_safe_label(name, field, value[field], allow_empty=True)
    if "applicability_scope" in value and value["applicability_scope"] not in _HOST_SCOPE_VALUES:
        _schema_error(name, "applicability_scope")
    for field in ("applicable_host_ids", "applicable_host_families"):
        if field in value:
            _require_host_list(name, field, value[field])
    if any(field in value for field in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")):
        _require_host_applicability(name, value, allow_legacy=False, require_source_pair=True)


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    schema_name = Path(name).name.removesuffix(".schema.json")
    data = _require_mapping(schema_name, value)
    validators = {
        "hook-event": _validate_hook_event,
        "queue-item": _validate_queue_item,
        "spool-item": lambda item: _validate_spool_ref("spool-item", item),
        "spool-envelope": _validate_spool_envelope,
        "gate-decision": _validate_gate_decision,
        "change-set": _validate_change_set,
        "host-certification-receipt": _validate_host_certification_receipt,
        "release-evidence": _validate_release_evidence,
        "event": _validate_event_mapping,
        "observation": _validate_observation,
        "pattern": _validate_pattern,
    }
    validator = validators.get(schema_name)
    if validator is None:
        _schema_error(schema_name, "unknown_schema")
    validator(data)


def _existing_duplicate(event: Event, event_root: Path) -> Path | None:
    if event.schema_version < 2 or not event.idempotency_key or not event_root.exists():
        return None
    for path in sorted(Path(event_root).rglob("*.json")):
        existing = read_event(path)
        if existing.schema_version < 2:
            continue
        if existing.idempotency_key != event.idempotency_key:
            continue
        if existing.idempotency_basis() == event.idempotency_basis():
            return path
        raise JournalIntegrityError(f"EVENT_ID_COLLISION:{event.idempotency_key}")
    return None



def _event_partition(event: Event) -> tuple[str, str]:
    occurred_at = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00"))
    return occurred_at.strftime("%Y"), occurred_at.strftime("%m")



def append_event(event: Event, event_root: Path) -> Path:
    if event.schema_version >= 2:
        _validate_incoming_v2_event(event)
        event = _materialize(event)
    else:
        event = _materialize(event)
        _validate_schema(event)
        _validate_persisted_event_payload(event)

    duplicate = _existing_duplicate(event, Path(event_root))
    if duplicate is not None:
        return duplicate

    year, month = _event_partition(event)
    target_dir = Path(event_root) / year / month
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{event.event_id}.json"
    if target.exists():
        existing = read_event(target)
        if existing.canonical_dict() != event.canonical_dict():
            raise JournalIntegrityError(f"EVENT_ID_COLLISION:{event.event_id}")
        return target

    temporary = target.with_name(target.name + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target



def read_event(path: Path) -> Event:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            _schema_error("event", "type")
        validate_schema("event", raw)
        event = Event.from_dict(raw)
    except JournalIntegrityError:
        raise
    except Exception as exc:
        raise JournalIntegrityError(f"EVENT_SCHEMA_INVALID:{path}") from exc
    _validate_stored_integrity(event)
    return event



def iter_events(event_root: Path, *, include_uncommitted: bool = False) -> Iterable[Event]:
    paths = sorted(Path(event_root).rglob("*.json"))
    events = [read_event(path) for path in paths]
    ordered = sorted(events, key=lambda event: (event.occurred_at, event.event_id))
    if include_uncommitted:
        return iter(ordered)
    committed_changesets = {
        str(event.payload.get("changeset_id"))
        for event in ordered
        if event.event_type == "curation.changeset.applied" and event.payload.get("changeset_id")
    }
    visible = [
        event
        for event in ordered
        if event.event_type == "curation.changeset.applied"
        or not event.payload.get("changeset_id")
        or str(event.payload.get("changeset_id")) in committed_changesets
    ]
    return iter(visible)
