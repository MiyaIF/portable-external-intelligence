"""One-shot, receipt-bound closeout application and bounded crash recovery."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .capture_contract import CaptureIdentity, CaptureReceipt, CloseoutProofRef, capture_key, pending_policy
from .capture_ledger import _record_receipt_locked, _root as _capture_root, read_receipt, _acquire, _release
from .changeset import AppliedMarkerRef, ChangeSet, apply_changeset, read_application_proof
from .closeout_context import (
    CloseoutContext,
    CloseoutContextError,
    CloseoutScope,
    ContextValidation,
    _read_binding,
    _receipt_is_usable,
    _revalidate_context_under_lock,
    _revalidate_persisted_context_under_lock,
    _semantic_binding_digest,
    _validate_binding_identity,
    _validate_context_shape,
    _write_binding_closeout_proof,
)
from .closeout_store import CloseoutStore, CloseoutStoreError
from .config import HostSpec
from .ids import fingerprint
from .journal import JournalIntegrityError, JournalLimitError, read_event
from .operation_runtime import OperationBudget, capture_namespace
from .safe_fs import SafeFilesystemError, assert_safe_target
from .spool import SpoolError, SpoolRef, _policy as _spool_policy, _read_envelope, _root as _spool_root, _safe_path as _spool_path, delete_spool, read_spool, write_spool


_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_RECEIPT_CANDIDATE_RE = re.compile(r"(?:sha256:[0-9a-f]{64}|queue_[0-9a-f]{32}|evt_[0-9TZ]+_[0-9a-f]{12}|cand_[0-9a-f]{20})")
_RECORD_RE = re.compile(r"co_[0-9a-f]{64}")
_MAX_CLOSEOUT_AGE_SECONDS = 30 * 24 * 60 * 60


@dataclass(frozen=True)
class PreparedCloseout:
    candidate_id: str
    content_hash: str
    decision: str
    changeset: ChangeSet | None
    team_prepared: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class AssociationResult:
    knowledge: str
    association: str
    reason_code: str
    acknowledged: bool
    event_ids: tuple[str, ...] = ()
    changeset_hash: str | None = None
    team_result: Mapping[str, Any] | None = None


@contextmanager
def _capture_lock(settings: Any, budget: OperationBudget):
    root = _capture_root(settings)
    descriptor = _acquire(root, budget=budget)
    try:
        yield root
    finally:
        _release(root, descriptor)


def _now_utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        return None
    return value.astimezone(timezone.utc)


def _record_id(context: CloseoutContext) -> str:
    identity = context.identity
    value = fingerprint(
        {
            "domain": "ei-closeout-record-identity-v1",
            "host_hash": fingerprint(identity.host_id),
            "instance_hash": identity.instance_hash,
            "store_hash": identity.store_id,
            "session_hash": identity.session_hash,
            "record_hash": identity.record_hash,
        }
    )
    return "co_" + value.removeprefix("sha256:")


def _target_set_hash(target_ids: tuple[str, ...]) -> str:
    return fingerprint({"domain": "ei-closeout-target-set-v1", "target_ids": list(sorted(target_ids))})


def _record_identity_valid(record: Mapping[str, Any]) -> bool:
    try:
        identity = CaptureIdentity(
            # This required field is only a stable label for hash validation; it is not native host authority.
            host_id="record-identity-check",
            instance_hash=record["instance_hash"],
            store_id=record["store_hash"],
            session_hash=record["session_hash"],
            turn_hash=None,
            record_hash=record["record_hash"],
        )
        expected = fingerprint(
            {
                "domain": "ei-closeout-record-identity-v1",
                "host_hash": record["host_hash"],
                "instance_hash": identity.instance_hash,
                "store_hash": identity.store_id,
                "session_hash": identity.session_hash,
                "record_hash": identity.record_hash,
            }
        )
        return (
            record.get("record_id") == "co_" + expected.removeprefix("sha256:")
            and record.get("target_set_hash") == _target_set_hash(tuple(record["target_ids"]))
        )
    except (KeyError, TypeError, ValueError):
        return False


def _new_intent(settings: Any, validation: ContextValidation, content_hash: str, now: datetime, budget: OperationBudget) -> dict[str, Any]:
    context = validation.context
    assert context is not None
    try:
        policy_file = Path(settings.capture_policy_path)
        retention = pending_policy(dict(_spool_policy(settings)) if policy_file.exists() else {})
    except (OSError, ValueError, TypeError, SpoolError):
        raise CloseoutStoreError("CLOSEOUT_POLICY_UNKNOWN")
    moment = now.astimezone(timezone.utc)
    created_at = moment.isoformat().replace("+00:00", "Z")
    expires_at = (moment + timedelta(seconds=retention.ttl_seconds)).isoformat().replace("+00:00", "Z")
    record_id = _record_id(context)
    spool_hex = hashlib.sha256(f"ei-closeout-spool-v1\0{record_id}\0{created_at}".encode("utf-8")).hexdigest()[:32]
    target_ids = tuple(sorted(context.target_ids))
    namespace = capture_namespace(settings, context.identity.host_id, budget=budget)
    if namespace is None or namespace != (context.identity.instance_hash, context.identity.store_id):
        raise CloseoutStoreError("CLOSEOUT_NAMESPACE_MISMATCH")
    return {
        "schema_version": 1,
        "record_id": record_id,
        "status": "PREPARING",
        "host_hash": fingerprint(context.identity.host_id),
        "instance_hash": context.identity.instance_hash,
        "store_hash": context.identity.store_id,
        "session_hash": context.identity.session_hash,
        "record_hash": context.identity.record_hash,
        "cwd_hash": context.scope.cwd_hash,
        "domain_hash": context.scope.domain_hash,
        "target_ids": list(target_ids),
        "target_set_hash": _target_set_hash(target_ids),
        "binding_digest": validation.target_binding_digest,
        "content_hash": content_hash,
        "created_at": created_at,
        "expires_at": expires_at,
        "spool_id": "spool_" + spool_hex,
        "spool_ref": None,
        "decision": None,
        "candidate_hash": None,
        "changeset_id_hash": None,
        "changeset_hash": None,
        "application_ref": None,
        "witness": [],
        "team_result": None,
        "reason_code": "CLOSEOUT_RESERVED",
        "result_digest": None,
    }


def _result(knowledge: str, association: str, reason: str, *, acknowledged: bool = False, event_ids: tuple[str, ...] = (), changeset_hash: str | None = None, team_result: Mapping[str, Any] | None = None) -> AssociationResult:
    return AssociationResult(knowledge, association, reason, acknowledged, event_ids, changeset_hash, team_result)


def _target_conflict(record: Mapping[str, Any], validation: ContextValidation, content_hash: str) -> bool:
    context = validation.context
    if context is None:
        return True
    return (
        record.get("content_hash") != content_hash
        or record.get("target_set_hash") != _target_set_hash(tuple(context.target_ids))
        or record.get("binding_digest") != validation.target_binding_digest
    )


def _request_conflict_reason(
    record: Mapping[str, Any], validation: ContextValidation, content_hash: str
) -> str | None:
    """Distinguish a semantic payload replay conflict from a target mismatch."""
    context = validation.context
    if context is None:
        return "CLOSEOUT_TARGET_CONFLICT"
    if record.get("content_hash") != content_hash:
        return "CLOSEOUT_CONTENT_CONFLICT"
    if (
        record.get("target_set_hash") != _target_set_hash(tuple(context.target_ids))
        or record.get("binding_digest") != validation.target_binding_digest
    ):
        return "CLOSEOUT_TARGET_CONFLICT"
    return None


def _prepared_payload(prepared: PreparedCloseout) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "decision": prepared.decision,
        "candidate_id": prepared.candidate_id,
        "content_hash": prepared.content_hash,
    }
    if prepared.decision == "YES" and prepared.changeset is not None:
        value["changeset"] = prepared.changeset.to_dict()
    if prepared.team_prepared is not None:
        value["team_prepared"] = dict(prepared.team_prepared)
    return value


def _validate_prepared(value: Any, content_hash: str) -> tuple[PreparedCloseout | None, str | None]:
    if not isinstance(value, PreparedCloseout):
        return None, "CLOSEOUT_PREPARE_INVALID"
    if (
        not isinstance(value.candidate_id, str)
        or (
            _SAFE_ID_RE.fullmatch(value.candidate_id) is None
            if value.decision == "NO"
            else _RECEIPT_CANDIDATE_RE.fullmatch(value.candidate_id) is None
        )
        or not isinstance(value.content_hash, str)
        or _HASH_RE.fullmatch(value.content_hash) is None
        or value.content_hash != content_hash
    ):
        return None, "CLOSEOUT_PREPARE_INVALID"
    if value.decision == "NO":
        if value.changeset is not None:
            return None, "CLOSEOUT_PREPARE_INVALID"
        if value.team_prepared is not None:
            from .team_routing import validate_prepared_team_routing
            if not validate_prepared_team_routing(value.team_prepared):
                return None, "CLOSEOUT_PREPARE_INVALID"
        return value, None
    if value.decision != "YES" or not isinstance(value.changeset, ChangeSet):
        return None, "CLOSEOUT_PREPARE_INVALID"
    try:
        changeset = ChangeSet.from_mapping(value.changeset.to_dict())
    except (TypeError, ValueError):
        return None, "CLOSEOUT_PREPARE_INVALID"
    if changeset.candidate_id != value.candidate_id:
        return None, "CLOSEOUT_PREPARE_INVALID"
    if value.team_prepared is not None:
        from .team_routing import validate_prepared_team_routing
        if not validate_prepared_team_routing(value.team_prepared):
            return None, "CLOSEOUT_PREPARE_INVALID"
    return value, None


def _prepared_classification(prepared: PreparedCloseout) -> str:
    if prepared.decision != "YES" or prepared.changeset is None:
        return "private-reusable"
    classifications = {
        str(operation.payload.get("classification", "private-reusable"))
        for operation in prepared.changeset.operations
    }
    if "client-confidential" in classifications:
        return "client-confidential"
    if classifications == {"public"}:
        return "public"
    return "private-reusable"


def _result_digest(record: Mapping[str, Any], *, decision: str, changeset_id_hash: str | None, changeset_hash: str | None, witness: list[dict[str, str]]) -> str:
    return fingerprint(
        {
            "domain": "ei-closeout-result-v1",
            "record_id": record["record_id"],
            "decision": decision,
            "content_hash": record["content_hash"],
            "target_set_hash": record["target_set_hash"],
            "binding_digest": record["binding_digest"],
            "changeset_id_hash": changeset_id_hash,
            "changeset_hash": changeset_hash,
            "witness": witness,
        }
    )


def _deserialize_application_ref(value: Mapping[str, Any]) -> AppliedMarkerRef | None:
    ref = value.get("application_ref")
    if not isinstance(ref, Mapping):
        return None
    try:
        return AppliedMarkerRef(str(ref["marker_id"]), str(ref["occurred_at"]), str(ref["changeset_hash"]))
    except (KeyError, TypeError, ValueError):
        return None


def _prepared_from_payload(raw: bytes, record: Mapping[str, Any]) -> PreparedCloseout:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, Mapping) or value.get("schema_version") != 1:
            raise ValueError
        candidate_id = value.get("candidate_id")
        decision = value.get("decision")
        content_hash = value.get("content_hash")
        if not isinstance(candidate_id, str) or fingerprint(candidate_id) != record["candidate_hash"]:
            raise ValueError
        if content_hash != record["content_hash"] or decision != record["decision"]:
            raise ValueError
        if decision == "NO":
            if set(value) - {"schema_version", "decision", "candidate_id", "content_hash", "team_prepared"}:
                raise ValueError
            team_prepared = value.get("team_prepared")
            if team_prepared is not None:
                from .team_routing import validate_prepared_team_routing
                if not validate_prepared_team_routing(team_prepared):
                    raise ValueError
            return PreparedCloseout(candidate_id, content_hash, decision, None, team_prepared)
        if decision != "YES" or set(value) - {"schema_version", "decision", "candidate_id", "content_hash", "changeset", "team_prepared"} or "changeset" not in value:
            raise ValueError
        changeset = ChangeSet.from_mapping(value["changeset"])
        if changeset.candidate_id != candidate_id:
            raise ValueError
        team_prepared = value.get("team_prepared")
        if team_prepared is not None:
            from .team_routing import validate_prepared_team_routing
            if not validate_prepared_team_routing(team_prepared):
                raise ValueError
        return PreparedCloseout(candidate_id, content_hash, decision, changeset, team_prepared)
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise SpoolError("CLOSEOUT_CACHE_INVALID") from exc


def _read_prepared(settings: Any, record: Mapping[str, Any], now: datetime, budget: OperationBudget) -> PreparedCloseout:
    reference = record.get("spool_ref")
    if not isinstance(reference, Mapping):
        raise SpoolError("CLOSEOUT_CACHE_MISSING")
    ref = SpoolRef.from_dict(reference)
    context = _context_from_record(settings, record)
    if context is None:
        raise SpoolError("CLOSEOUT_CONTEXT_UNVERIFIED")
    closeout_capture_id = capture_key(context.identity)
    raw = read_spool(ref, settings, now=now, expected_capture_id=closeout_capture_id, budget=budget)
    prepared = _prepared_from_payload(raw, record)
    validated, reason = _validate_prepared(prepared, record["content_hash"])
    if validated is None or reason is not None:
        raise SpoolError("CLOSEOUT_CACHE_INVALID")
    return validated


def _recover_planned_spool(settings: Any, record: Mapping[str, Any], now: datetime, budget: OperationBudget) -> tuple[SpoolRef, PreparedCloseout] | None:
    context = _context_from_record(settings, record)
    if context is None:
        return None
    try:
        root = _spool_root(settings)
        path = _spool_path(root, record["spool_id"], budget)
        if not path.exists():
            return None
        envelope = _read_envelope(path, budget=budget)
        capture_id = capture_key(context.identity)
        if (
            envelope.get("spool_id") != record["spool_id"]
            or envelope.get("purpose") != "validated-result"
            or envelope.get("capture_id") != capture_id
            or envelope.get("created_at") != record["created_at"]
            or envelope.get("expires_at") != record["expires_at"]
        ):
            raise SpoolError("CLOSEOUT_CACHE_INVALID")
        ref = SpoolRef(
            str(envelope["spool_id"]), str(envelope["content_sha256"]), str(envelope["classification"]),
            str(envelope["created_at"]), str(envelope["expires_at"]), envelope.get("key_id"),
            purpose="validated-result",
        )
        raw = read_spool(ref, settings, now=now, expected_capture_id=capture_id, budget=budget)
        try:
            payload = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SpoolError("CLOSEOUT_CACHE_INVALID") from exc
        if not isinstance(payload, Mapping):
            raise SpoolError("CLOSEOUT_CACHE_INVALID")
        prepared = _prepared_from_payload(
            raw,
            {
                **record,
                "decision": payload.get("decision"),
                "candidate_hash": fingerprint(payload.get("candidate_id"))
                if isinstance(payload.get("candidate_id"), str)
                else None,
            },
        )
        validated, reason = _validate_prepared(prepared, record["content_hash"])
        if validated is None or reason is not None:
            raise SpoolError("CLOSEOUT_CACHE_INVALID")
        return ref, validated
    except TimeoutError:
        raise
    except SpoolError:
        raise
    except (OSError, SafeFilesystemError, KeyError, TypeError, ValueError, JournalIntegrityError) as exc:
        raise SpoolError("CLOSEOUT_CACHE_INVALID") from exc


def _context_from_record(settings: Any, record: Mapping[str, Any]) -> CloseoutContext | None:
    try:
        hosts = getattr(settings, "hosts", None)
        if not isinstance(hosts, Mapping):
            return None
        host_ids = [host_id for host_id in hosts if fingerprint(host_id) == record["host_hash"]]
        if len(host_ids) != 1:
            return None
        context = CloseoutContext(
            identity=CaptureIdentity(
                host_ids[0], record["instance_hash"], record["store_hash"],
                record["session_hash"], None, record["record_hash"],
            ),
            target_ids=tuple(record["target_ids"]),
            scope=CloseoutScope(record["cwd_hash"], record["domain_hash"]),
        )
        if _validate_context_shape(context) is not None or not _record_identity_valid(record):
            return None
        return context
    except (KeyError, TypeError, ValueError):
        return None


def _persist_prepared(settings: Any, record: dict[str, Any], prepared: PreparedCloseout, now: datetime, budget: OperationBudget) -> dict[str, Any]:
    context = _context_from_record(settings, record)
    if context is None:
        raise CloseoutStoreError("CLOSEOUT_CONTEXT_UNVERIFIED")
    try:
        policy_file = Path(settings.capture_policy_path)
        current = pending_policy(dict(_spool_policy(settings)) if policy_file.exists() else {})
        created_at = datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        ttl = int((expires_at - created_at).total_seconds())
    except (OSError, ValueError, TypeError, SpoolError) as exc:
        raise CloseoutStoreError("CLOSEOUT_POLICY_UNKNOWN") from exc
    # Keep the original admission expiry even if policy changes while preparing.
    retention = pending_policy({"ttl_seconds": ttl, "max_items": current.max_items, "max_bytes": current.max_bytes})
    ref = write_spool(
        _prepared_payload(prepared),
        _prepared_classification(prepared),
        settings,
        now=created_at,
        spool_id=record["spool_id"],
        purpose="validated-result",
        retention=retention,
        capture_id=capture_key(context.identity),
        budget=budget,
    )
    if ref.expires_at != record["expires_at"]:
        raise CloseoutStoreError("CLOSEOUT_EXPIRY_CONFLICT")
    updated = dict(record)
    updated.update(
        {
            "status": "PREPARED",
            "spool_ref": ref.to_dict(),
            "decision": prepared.decision,
            "candidate_hash": fingerprint(prepared.candidate_id),
            "reason_code": "CLOSEOUT_PREPARED" if prepared.decision == "YES" else "CLOSEOUT_NO_EVALUATED",
        }
    )
    if prepared.decision == "NO":
        updated["result_digest"] = _result_digest(
            updated, decision="NO", changeset_id_hash=None, changeset_hash=None, witness=[]
        )
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current_record = store.read_record(record["record_id"])
        if current_record is None or _target_conflict(current_record, ContextValidation(context, record["binding_digest"], "OK"), record["content_hash"]):
            raise CloseoutStoreError("CLOSEOUT_TARGET_CONFLICT")
        if current_record["status"] == "PREPARING":
            store.write_record(updated)
        elif current_record["status"] == "PREPARED" and (
            current_record.get("spool_ref") == updated["spool_ref"]
            and current_record.get("decision") == updated["decision"]
            and current_record.get("candidate_hash") == updated["candidate_hash"]
        ):
            updated = current_record
        else:
            raise CloseoutStoreError("CLOSEOUT_STATE_CONFLICT")
    return updated


def _load_prepared(settings: Any, record: dict[str, Any], now: datetime, budget: OperationBudget) -> tuple[dict[str, Any], PreparedCloseout | None]:
    status = record.get("status")
    if status == "PREPARING":
        try:
            planned = _recover_planned_spool(settings, record, now, budget)
        except SpoolError:
            return record, None
        if planned is None:
            return record, None
        ref, prepared = planned
        record = dict(record)
        record.update(
            {
                "status": "PREPARED",
                "spool_ref": ref.to_dict(),
                "decision": prepared.decision,
                "candidate_hash": fingerprint(prepared.candidate_id),
                "reason_code": "CLOSEOUT_PREPARED" if prepared.decision == "YES" else "CLOSEOUT_NO_EVALUATED",
            }
        )
        if prepared.decision == "NO":
            record["result_digest"] = _result_digest(record, decision="NO", changeset_id_hash=None, changeset_hash=None, witness=[])
        with _capture_lock(settings, budget):
            store = CloseoutStore(settings, budget=budget)
            current = store.read_record(record["record_id"])
            if current is None:
                raise CloseoutStoreError("CLOSEOUT_RECORD_UNKNOWN")
            if current["status"] == "PREPARING":
                store.write_record(record)
            elif current["status"] == "PREPARED" and current.get("spool_ref") == ref.to_dict():
                record = current
            else:
                raise CloseoutStoreError("CLOSEOUT_STATE_CONFLICT")
        return record, prepared
    if status == "PREPARED":
        try:
            return record, _read_prepared(settings, record, now, budget)
        except TimeoutError:
            raise
        except SpoolError:
            return record, None
    return record, None


def _host_spec(settings: Any, host_id: str) -> HostSpec | None:
    hosts = getattr(settings, "hosts", None)
    value = hosts.get(host_id) if isinstance(hosts, Mapping) else None
    return value if isinstance(value, HostSpec) and value.host_id == host_id else None


def _validate_changeset_context(settings: Any, context: CloseoutContext, changeset: ChangeSet) -> str | None:
    spec = _host_spec(settings, context.identity.host_id)
    if spec is None or not isinstance(spec.host_family, str) or not spec.host_family:
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    for operation in changeset.operations:
        payload = operation.payload
        source_host = payload.get("source_host_id") or changeset.source_host_id
        source_family = payload.get("source_host_family") or changeset.source_host_family
        scope = payload.get("applicability_scope") or changeset.applicability_scope
        host_ids = payload.get("applicable_host_ids", changeset.applicable_host_ids)
        families = payload.get("applicable_host_families", changeset.applicable_host_families)
        if source_host != context.identity.host_id or source_family != spec.host_family:
            return "CLOSEOUT_HOST_MISMATCH"
        if not isinstance(host_ids, (list, tuple)) or not isinstance(families, (list, tuple)):
            return "CLOSEOUT_HOST_MISMATCH"
        if scope == "host" and context.identity.host_id not in host_ids:
            return "CLOSEOUT_HOST_MISMATCH"
        if scope == "family" and spec.host_family not in families:
            return "CLOSEOUT_HOST_MISMATCH"
        if scope not in {"universal", "family", "host"}:
            return "CLOSEOUT_HOST_MISMATCH"
        domain = payload.get("domain")
        cwd_hash = payload.get("cwd_fingerprint")
        if (
            not isinstance(domain, str)
            or not domain
            or not isinstance(cwd_hash, str)
            or _HASH_RE.fullmatch(cwd_hash) is None
            or cwd_hash != context.scope.cwd_hash
            or fingerprint(domain) != context.scope.domain_hash
        ):
            return "CLOSEOUT_SCOPE_UNKNOWN"
    return None


def _event_path(settings: Any, event_id: str, occurred_at: str, budget: OperationBudget) -> Path:
    try:
        partition = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        root = Path(settings.paths.event_dir)
        path = root / partition.strftime("%Y") / partition.strftime("%m") / f"{event_id}.json"
        budget.check()
        return assert_safe_target(root, path, allow_missing=False, expected_type="file")
    except (ValueError, OSError, SafeFilesystemError) as exc:
        raise JournalIntegrityError("CLOSEOUT_EVENT_MISSING") from exc


def _verify_yes(settings: Any, record: Mapping[str, Any], context: CloseoutContext, prepared: PreparedCloseout, ref: AppliedMarkerRef, budget: OperationBudget) -> tuple[list[dict[str, str]], tuple[str, ...], str | None]:
    changeset = prepared.changeset
    if changeset is None:
        return [], (), "CLOSEOUT_PREPARE_INVALID"
    reason = _validate_changeset_context(settings, context, changeset)
    if reason is not None:
        return [], (), reason
    proof = read_application_proof(changeset, settings, application_ref=ref, budget=budget)
    if not proof.applied or proof.reason_code != "APPLICATION_PROOF_VERIFIED" or not proof.event_ids:
        return [], (), proof.reason_code or "APPLICATION_PROOF_INVALID"
    if len(proof.event_ids) != len(changeset.operations) + 1 or proof.event_ids[-1] != ref.marker_id:
        return [], (), "APPLICATION_PROOF_INVALID"
    events = [read_event(_event_path(settings, event_id, ref.occurred_at, budget), budget=budget) for event_id in proof.event_ids]
    marker = events[-1]
    payload = marker.payload
    if (
        marker.event_type != "curation.changeset.applied"
        or not isinstance(payload, Mapping)
        or payload.get("changeset_id") != changeset.changeset_id
        or payload.get("candidate_id") != prepared.candidate_id
        or payload.get("changeset_hash") != ref.changeset_hash
        or fingerprint(prepared.candidate_id) != record.get("candidate_hash")
        or fingerprint(changeset.changeset_id) != record.get("changeset_id_hash")
        or ref.changeset_hash != record.get("changeset_hash")
        or payload.get("event_ids") != list(proof.event_ids[:-1])
    ):
        return [], (), "APPLICATION_PROOF_INVALID"
    spec = _host_spec(settings, context.identity.host_id)
    if spec is None:
        return [], (), "CLOSEOUT_CONTEXT_UNVERIFIED"
    for operation, event in zip(changeset.operations, events[:-1]):
        event_payload = event.payload
        if (
            not isinstance(event_payload, Mapping)
            or event_payload.get("source_host_id") != context.identity.host_id
            or event_payload.get("source_host_family") != spec.host_family
            or event_payload.get("changeset_id") != changeset.changeset_id
            or event_payload.get("candidate_id") != prepared.candidate_id
        ):
            return [], (), "CLOSEOUT_HOST_MISMATCH"
        if operation.operation == "CREATE_OBSERVATION" and (
            event_payload.get("cwd_fingerprint") != context.scope.cwd_hash
            or not isinstance(event_payload.get("domain"), str)
            or fingerprint(event_payload["domain"]) != context.scope.domain_hash
        ):
            return [], (), "CLOSEOUT_SCOPE_UNKNOWN"
    witness = [
        {
            "event_id": event.event_id,
            "occurred_at": event.occurred_at,
            "integrity_digest": event.integrity_sha256,
        }
        for event in events
    ]
    if any(not isinstance(item["integrity_digest"], str) or re.fullmatch(r"[0-9a-f]{64}", item["integrity_digest"]) is None for item in witness):
        return [], (), "APPLICATION_PROOF_INVALID"
    return witness, tuple(proof.event_ids), None


def _record_matches_intent(current: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(
        current.get(field) == expected.get(field)
        for field in (
            "record_id", "host_hash", "instance_hash", "store_hash", "session_hash", "record_hash",
            "cwd_hash", "domain_hash", "target_ids", "target_set_hash", "binding_digest", "content_hash",
        )
    )


def _persist_application_ref(settings: Any, record: Mapping[str, Any], ref: AppliedMarkerRef, changeset: ChangeSet, budget: OperationBudget) -> dict[str, Any]:
    if not isinstance(ref, AppliedMarkerRef):
        raise CloseoutStoreError("CLOSEOUT_APPLICATION_REF_INVALID")
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(str(record.get("record_id", "")))
        if current is None or not _record_matches_intent(current, record):
            raise CloseoutStoreError("CLOSEOUT_RECORD_CONFLICT")
        value = {"marker_id": ref.marker_id, "occurred_at": ref.occurred_at, "changeset_hash": ref.changeset_hash}
        if current.get("application_ref") is not None:
            if current.get("application_ref") != value:
                raise CloseoutStoreError("CLOSEOUT_APPLICATION_REF_CONFLICT")
            return current
        if current.get("status") != "PREPARED" or current.get("decision") != "YES":
            raise CloseoutStoreError("CLOSEOUT_STATE_CONFLICT")
        updated = dict(current)
        updated.update(
            {
                "application_ref": value,
                "changeset_id_hash": fingerprint(changeset.changeset_id),
                "changeset_hash": ref.changeset_hash,
            }
        )
        return store.write_record(updated)


def _persist_verified_witness(settings: Any, record: Mapping[str, Any], witness: list[dict[str, str]], budget: OperationBudget) -> dict[str, Any]:
    updated = dict(record)
    updated.update(
        {
            "status": "APPLIED",
            "witness": witness,
            "result_digest": _result_digest(
                updated,
                decision="YES",
                changeset_id_hash=updated.get("changeset_id_hash"),
                changeset_hash=updated.get("changeset_hash"),
                witness=witness,
            ),
            "reason_code": "APPLICATION_PROOF_VERIFIED",
        }
    )
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(str(record.get("record_id", "")))
        if current is None or not _record_matches_intent(current, record):
            raise CloseoutStoreError("CLOSEOUT_RECORD_CONFLICT")
        if current.get("status") == "APPLIED":
            if current.get("witness") != witness or current.get("result_digest") != updated["result_digest"]:
                raise CloseoutStoreError("CLOSEOUT_PROOF_CONFLICT")
            return current
        if current.get("status") != "PREPARED" or current.get("application_ref") != record.get("application_ref"):
            raise CloseoutStoreError("CLOSEOUT_STATE_CONFLICT")
        return store.write_record(updated)


def _closeout_proof(record: Mapping[str, Any]) -> CloseoutProofRef:
    return CloseoutProofRef(
        record_id=str(record["record_id"]),
        target_set_hash=str(record["target_set_hash"]),
        content_hash=str(record["content_hash"]),
        binding_digest=str(record["binding_digest"]),
        result_digest=str(record["result_digest"]),
    )


def _proof_value(proof: CloseoutProofRef) -> dict[str, str]:
    return {
        "record_id": proof.record_id,
        "target_set_hash": proof.target_set_hash,
        "content_hash": proof.content_hash,
        "binding_digest": proof.binding_digest,
        "result_digest": proof.result_digest,
    }


def _preflight_closeout_targets(
    settings: Any,
    record: Mapping[str, Any],
    context: CloseoutContext,
    *,
    validation: ContextValidation | None,
    now: datetime,
    budget: OperationBudget,
    allow_missing_proofs: bool,
    candidate_id: str | None,
) -> tuple[list[tuple[str, CaptureReceipt, dict[str, Any]]], str | None]:
    root = _capture_root(settings)
    reason = (
        _revalidate_context_under_lock(settings, validation, budget=budget)
        if validation is not None
        else _revalidate_persisted_context_under_lock(settings, context, str(record["binding_digest"]), budget=budget)
    )
    if reason is not None:
        return [], reason
    proof = _closeout_proof(record)
    proof_value = _proof_value(proof)
    receipts: list[tuple[str, CaptureReceipt, dict[str, Any]]] = []
    bindings: list[Mapping[str, Any]] = []
    try:
        for target_id in context.target_ids:
            budget.check()
            binding = _read_binding(root, target_id, budget=budget)
            if binding is None:
                return [], "CLOSEOUT_TARGET_UNKNOWN"
            identity = _validate_binding_identity(binding, target_id)
            if (
                identity.host_id != context.identity.host_id
                or identity.instance_hash != context.identity.instance_hash
                or identity.store_id != context.identity.store_id
                or identity.session_hash != context.identity.session_hash
                or binding.get("scope_hash") != context.scope.fingerprint
            ):
                return [], "CLOSEOUT_SCOPE_MISMATCH"
            receipt = read_receipt(settings, target_id, budget=budget)
            if not _receipt_is_usable(receipt, target_id):
                return [], "CLOSEOUT_TARGET_UNKNOWN"
            assert receipt is not None
            if candidate_id is not None:
                existing_hash = dict(receipt.candidate_hashes).get(candidate_id)
                if existing_hash is not None and existing_hash != record.get("content_hash"):
                    return [], "CLOSEOUT_CONTENT_CONFLICT"
            matching_receipts = [item for item in receipt.closeout_proofs if item.record_id == proof.record_id]
            if matching_receipts and any(item != proof for item in matching_receipts):
                return [], "CLOSEOUT_PROOF_CONFLICT"
            receipt_missing = not matching_receipts
            if receipt_missing and len(receipt.closeout_proofs) >= 8:
                return [], "CLOSEOUT_PROOF_CAPACITY"
            target_proofs = binding.get("closeout_proofs", [])
            if not isinstance(target_proofs, list):
                return [], "CLOSEOUT_TARGET_CONFLICT"
            matching_bindings = [item for item in target_proofs if isinstance(item, Mapping) and item.get("record_id") == proof.record_id]
            if matching_bindings and any(dict(item) != proof_value for item in matching_bindings):
                return [], "CLOSEOUT_PROOF_CONFLICT"
            binding_missing = not matching_bindings
            if binding_missing and len(target_proofs) >= 8:
                return [], "CLOSEOUT_PROOF_CAPACITY"
            if binding_missing:
                preview = dict(binding)
                preview_proofs = [dict(item) for item in target_proofs]
                preview_proofs.append(proof_value)
                preview["closeout_proofs"] = sorted(preview_proofs, key=lambda item: item["record_id"])
                preview["updated_at"] = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if len((json.dumps(preview, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")) > 16 * 1024:
                    return [], "CLOSEOUT_PROOF_CAPACITY"
            if not allow_missing_proofs and (receipt_missing or binding_missing):
                return [], "CLOSEOUT_PROOF_UNKNOWN"
            receipts.append((target_id, receipt, binding))
            bindings.append(binding)
        if _semantic_binding_digest(list(bindings)) != record.get("binding_digest"):
            return [], "CLOSEOUT_TARGET_CONFLICT"
        return receipts, None
    except TimeoutError:
        raise
    except CloseoutContextError as exc:
        return [], exc.reason_code
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, JournalIntegrityError):
        return [], "CLOSEOUT_TARGET_CONFLICT"


def _commit_receipts_locked(
    settings: Any,
    record: Mapping[str, Any],
    context: CloseoutContext,
    *,
    validation: ContextValidation | None,
    now: datetime,
    budget: OperationBudget,
    allow_missing_proofs: bool,
    candidate_id: str | None = None,
) -> str | None:
    if allow_missing_proofs and record.get("decision") == "YES" and (
        not isinstance(candidate_id, str)
        or _RECEIPT_CANDIDATE_RE.fullmatch(candidate_id) is None
        or fingerprint(candidate_id) != record.get("candidate_hash")
    ):
        return "CLOSEOUT_CANDIDATE_UNVERIFIED"
    if record.get("decision") == "YES":
        expected = _result_digest(
            record,
            decision="YES",
            changeset_id_hash=record.get("changeset_id_hash"),
            changeset_hash=record.get("changeset_hash"),
            witness=list(record.get("witness", [])),
        )
    elif record.get("decision") == "NO":
        expected = _result_digest(record, decision="NO", changeset_id_hash=None, changeset_hash=None, witness=[])
    else:
        return "CLOSEOUT_RESULT_UNKNOWN"
    if record.get("result_digest") != expected:
        return "CLOSEOUT_PROOF_CONFLICT"
    receipts, reason = _preflight_closeout_targets(
        settings,
        record,
        context,
        validation=validation,
        now=now,
        budget=budget,
        allow_missing_proofs=allow_missing_proofs,
        candidate_id=candidate_id,
    )
    if reason is not None:
        return reason
    if allow_missing_proofs:
        root = _capture_root(settings)
        state = "SECURED" if record["decision"] == "YES" else "EVALUATED_NONE"
        reason_code = "CLOSEOUT_APPLIED" if record["decision"] == "YES" else "CLOSEOUT_EVALUATED_NONE"
        proof = _closeout_proof(record)
        proof_value = _proof_value(proof)
        try:
            for target_id, _, _ in receipts:
                budget.check()
                receipt = CaptureReceipt(
                    capture_id=target_id,
                    state=state,
                    candidate_ids=(candidate_id,) if record["decision"] == "YES" and candidate_id is not None else (),
                    covered_target_ids=(target_id,),
                    reason_code=reason_code,
                    updated_at=now,
                    candidate_hashes=((candidate_id, record["content_hash"]),) if record["decision"] == "YES" and candidate_id is not None else (),
                    closeout_proofs=(proof,),
                )
                _record_receipt_locked(root, receipt, budget=budget)
                _write_binding_closeout_proof(settings, target_id, proof_value, now=now, budget=budget)
        except TimeoutError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, CloseoutContextError, JournalIntegrityError) as exc:
            reason = getattr(exc, "reason_code", None) or getattr(exc, "code", None)
            if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason):
                return reason
            if isinstance(exc, JournalIntegrityError) and re.fullmatch(r"[A-Z0-9_.:-]{1,96}", str(exc), flags=re.IGNORECASE):
                return re.sub(r"[^A-Z0-9]+", "_", str(exc).upper())[:96]
            return type(exc).__name__.upper() if _SAFE_ID_RE.fullmatch(type(exc).__name__) else "CLOSEOUT_RECEIPT_PENDING"
    # Read every receipt and binding again before COMMITTED can be persisted.
    proof = _closeout_proof(record)
    root = _capture_root(settings)
    for target_id, _, _ in receipts:
        budget.check()
        receipt = read_receipt(settings, target_id, budget=budget)
        binding = _read_binding(root, target_id, budget=budget)
        if (
            not _receipt_is_usable(receipt, target_id)
            or receipt is None
            or proof not in receipt.closeout_proofs
            or target_id not in receipt.covered_target_ids
            or (
                record.get("decision") == "YES"
                and (
                    receipt.state != "SECURED"
                    or candidate_id not in receipt.candidate_ids
                    or dict(receipt.candidate_hashes).get(candidate_id) != record.get("content_hash")
                )
            )
            or (
                record.get("decision") == "NO"
                and receipt.state not in {"EVALUATED_NONE", "SECURED"}
            )
            or binding is None
            or _proof_value(proof) not in binding.get("closeout_proofs", [])
        ):
            return "CLOSEOUT_RECEIPT_READBACK_FAILED"
    return None


def _commit_receipts(
    settings: Any,
    record: Mapping[str, Any],
    context: CloseoutContext,
    *,
    validation: ContextValidation | None,
    now: datetime,
    budget: OperationBudget,
    allow_missing_proofs: bool,
    candidate_id: str | None = None,
) -> str | None:
    with _capture_lock(settings, budget):
        return _commit_receipts_locked(
            settings,
            record,
            context,
            validation=validation,
            now=now,
            budget=budget,
            allow_missing_proofs=allow_missing_proofs,
            candidate_id=candidate_id,
        )


def _verify_saved_yes(settings: Any, record: Mapping[str, Any], context: CloseoutContext, budget: OperationBudget) -> tuple[tuple[str, ...], str | None, str | None]:
    reference = _deserialize_application_ref(record)
    witness = record.get("witness")
    if reference is None or not isinstance(witness, list) or len(witness) < 2:
        return (), None, "APPLICATION_PROOF_INVALID"
    if record.get("changeset_hash") != reference.changeset_hash:
        return (), None, "APPLICATION_PROOF_INVALID"
    spec = _host_spec(settings, context.identity.host_id)
    if spec is None:
        return (), None, "CLOSEOUT_CONTEXT_UNVERIFIED"
    events = []
    try:
        for item in witness:
            if not isinstance(item, Mapping) or item.get("occurred_at") != reference.occurred_at:
                return (), None, "APPLICATION_PROOF_INVALID"
            event = read_event(_event_path(settings, str(item["event_id"]), reference.occurred_at, budget), budget=budget)
            if event.event_id != item["event_id"] or event.integrity_sha256 != item["integrity_digest"]:
                return (), None, "APPLICATION_PROOF_INVALID"
            events.append(event)
    except TimeoutError:
        raise
    except (KeyError, TypeError, ValueError, JournalIntegrityError, SafeFilesystemError, OSError):
        return (), None, "APPLICATION_PROOF_INVALID"
    marker = events[-1]
    payload = marker.payload
    operation_events = events[:-1]
    event_ids = [event.event_id for event in operation_events]
    if (
        marker.event_type != "curation.changeset.applied"
        or marker.occurred_at != reference.occurred_at
        or not isinstance(payload, Mapping)
        or payload.get("changeset_hash") != reference.changeset_hash
        or payload.get("event_ids") != event_ids
        or payload.get("operation_count") != len(operation_events)
        or not isinstance(payload.get("changeset_id"), str)
        or fingerprint(payload["changeset_id"]) != record.get("changeset_id_hash")
        or not isinstance(payload.get("candidate_id"), str)
        or fingerprint(payload["candidate_id"]) != record.get("candidate_hash")
    ):
        return (), None, "APPLICATION_PROOF_INVALID"
    for event in operation_events:
        event_payload = event.payload
        if (
            not isinstance(event_payload, Mapping)
            or event_payload.get("changeset_id") != payload.get("changeset_id")
            or event_payload.get("candidate_id") != payload.get("candidate_id")
            or event_payload.get("source_host_id") != context.identity.host_id
            or event_payload.get("source_host_family") != spec.host_family
        ):
            return (), None, "CLOSEOUT_HOST_MISMATCH"
        scope = event_payload.get("applicability_scope")
        host_ids = event_payload.get("applicable_host_ids")
        families = event_payload.get("applicable_host_families")
        if (
            scope not in {"universal", "family", "host"}
            or not isinstance(host_ids, (list, tuple))
            or not isinstance(families, (list, tuple))
            or (scope == "host" and context.identity.host_id not in host_ids)
            or (scope == "family" and spec.host_family not in families)
        ):
            return (), None, "CLOSEOUT_HOST_MISMATCH"
        if event.event_type == "observation.recorded" and (
            event_payload.get("cwd_fingerprint") != context.scope.cwd_hash
            or not isinstance(event_payload.get("domain"), str)
            or fingerprint(event_payload["domain"]) != context.scope.domain_hash
        ):
            return (), None, "CLOSEOUT_SCOPE_UNKNOWN"
        if "domain" in event_payload and (
            not isinstance(event_payload["domain"], str)
            or fingerprint(event_payload["domain"]) != context.scope.domain_hash
        ):
            return (), None, "CLOSEOUT_SCOPE_UNKNOWN"
        if "cwd_fingerprint" in event_payload and event_payload["cwd_fingerprint"] != context.scope.cwd_hash:
            return (), None, "CLOSEOUT_SCOPE_UNKNOWN"
    result_digest = _result_digest(
        record,
        decision="YES",
        changeset_id_hash=record.get("changeset_id_hash"),
        changeset_hash=record.get("changeset_hash"),
        witness=witness,
    )
    if record.get("result_digest") != result_digest:
        return (), None, "CLOSEOUT_PROOF_CONFLICT"
    return tuple(event.event_id for event in events), str(payload["candidate_id"]), None


def _team_summary(prepared: Mapping[str, Any] | None, decision: Any | None, *, personal_event_hash: str | None) -> dict[str, Any]:
    from .redaction import domain_hash

    team_store_id = prepared.get("team_store_id") if isinstance(prepared, Mapping) else None
    team_root_hash = prepared.get("team_root_hash") if isinstance(prepared, Mapping) else None
    status = getattr(decision, "status", None)
    if status == "ELIGIBLE":
        compact_status = "DELIVERED"
    elif status == "NOT_ELIGIBLE":
        compact_status = "NOT_ELIGIBLE"
    elif status == "DEFERRED":
        compact_status = "DEFERRED"
    elif decision is None:
        compact_status = "UNKNOWN"
    else:
        compact_status = "PENDING"
    reason = getattr(decision, "reason_code", None)
    if not isinstance(reason, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason) is None:
        reason = "TEAM_HANDOFF_UNKNOWN"
    receipt_id = getattr(decision, "receipt_id", None)
    delivery_hash = getattr(decision, "delivery_event_hash", None)
    if isinstance(delivery_hash, str) and re.fullmatch(r"[0-9a-f]{64}", delivery_hash):
        delivery_hash = "sha256:" + delivery_hash
    elif not isinstance(delivery_hash, str) or _HASH_RE.fullmatch(delivery_hash) is None:
        delivery_hash = None
    return {
        "status": compact_status,
        "reason_code": reason,
        "personal_event_hash": personal_event_hash if isinstance(personal_event_hash, str) and _HASH_RE.fullmatch(personal_event_hash) else None,
        "team_store_hash": domain_hash(team_store_id, "team-store-id") if isinstance(team_store_id, str) and team_store_id else None,
        "team_root_hash": team_root_hash if isinstance(team_root_hash, str) and _HASH_RE.fullmatch(team_root_hash) else None,
        "delivery_event_id": getattr(decision, "delivery_event_id", None),
        "delivery_event_hash": delivery_hash,
        "receipt_id_hash": domain_hash(receipt_id, "team-outbox-receipt-id") if isinstance(receipt_id, str) and receipt_id else None,
        "receipt_status": getattr(decision, "receipt_status", None),
    }


_TEAM_SUMMARY_FIELDS = frozenset({
    "status", "reason_code", "personal_event_hash", "team_store_hash", "team_root_hash",
    "delivery_event_id", "delivery_event_hash", "receipt_id_hash", "receipt_status",
})


def _team_summary_integrity_hash(record: Mapping[str, Any], summary: Mapping[str, Any]) -> str:
    from .redaction import domain_hash

    identity = {
        "record_id": record.get("record_id"),
        "content_hash": record.get("content_hash"),
        "target_set_hash": record.get("target_set_hash"),
        "binding_digest": record.get("binding_digest"),
        "decision": record.get("decision"),
        "changeset_hash": record.get("changeset_hash"),
    }
    body = {key: summary.get(key) for key in sorted(_TEAM_SUMMARY_FIELDS)}
    encoded = json.dumps(
        {"domain": "ei-closeout-team-result-v1", "identity": identity, "team_result": body},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return domain_hash(encoded, "closeout-team-result")


def _bind_team_summary(record: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[str, Any]:
    bound = {key: summary.get(key) for key in _TEAM_SUMMARY_FIELDS}
    bound["integrity_hash"] = _team_summary_integrity_hash(record, bound)
    return bound


def _team_summary_valid(record: Mapping[str, Any], summary: Any) -> bool:
    if not isinstance(summary, Mapping) or set(summary) != _TEAM_SUMMARY_FIELDS | {"integrity_hash"}:
        return False
    integrity_hash = summary.get("integrity_hash")
    if (
        not isinstance(integrity_hash, str)
        or _HASH_RE.fullmatch(integrity_hash) is None
        or integrity_hash != _team_summary_integrity_hash(record, summary)
    ):
        return False
    decision = record.get("decision")
    personal_hash = record.get("changeset_hash") if decision == "YES" else None
    if summary.get("personal_event_hash") != personal_hash:
        return False
    status = summary.get("status")
    if status == "DELIVERED":
        if (
            decision != "YES"
            or not isinstance(summary.get("team_store_hash"), str)
            or _HASH_RE.fullmatch(summary["team_store_hash"]) is None
            or not isinstance(summary.get("team_root_hash"), str)
            or _HASH_RE.fullmatch(summary["team_root_hash"]) is None
            or not isinstance(summary.get("delivery_event_id"), str)
            or _RECEIPT_CANDIDATE_RE.fullmatch(summary["delivery_event_id"]) is None
            or not isinstance(summary.get("delivery_event_hash"), str)
            or _HASH_RE.fullmatch(summary["delivery_event_hash"]) is None
        ):
            return False
        receipt_id_hash = summary.get("receipt_id_hash")
        receipt_status = summary.get("receipt_status")
        return (receipt_id_hash is None and receipt_status is None) or (
            isinstance(receipt_id_hash, str)
            and _HASH_RE.fullmatch(receipt_id_hash) is not None
            and receipt_status == "DELIVERED"
        )
    if status == "NOT_ELIGIBLE":
        if any(summary.get(field) is not None for field in ("delivery_event_id", "delivery_event_hash", "receipt_id_hash", "receipt_status")):
            return False
        store_hash, root_hash = summary.get("team_store_hash"), summary.get("team_root_hash")
        if (store_hash is None) != (root_hash is None):
            return False
        return store_hash is None or (
            isinstance(store_hash, str) and _HASH_RE.fullmatch(store_hash) is not None
            and isinstance(root_hash, str) and _HASH_RE.fullmatch(root_hash) is not None
        )
    return False


def _persist_team_summary(settings: Any, record: Mapping[str, Any], summary: Mapping[str, Any], budget: OperationBudget) -> dict[str, Any]:
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(str(record["record_id"]))
        if current is None or current.get("status") != "COMMITTED" or not _record_matches_intent(current, record):
            raise CloseoutStoreError("CLOSEOUT_RECORD_CONFLICT")
        updated = dict(current)
        bound = _bind_team_summary(current, summary)
        updated["team_result"] = bound
        store.write_record(updated)
        return bound


def _finalize_team_handoff(
    settings: Any,
    record: Mapping[str, Any],
    context: CloseoutContext,
    *,
    now: datetime,
    budget: OperationBudget,
    event_ids: tuple[str, ...],
) -> tuple[dict[str, Any] | None, str | None]:
    """Finish the frozen team decision before the validated-result spool is removed."""

    existing = record.get("team_result")
    if isinstance(existing, Mapping) and existing.get("status") in {"DELIVERED", "NOT_ELIGIBLE"}:
        if _team_summary_valid(record, existing):
            return dict(existing), None
        return dict(existing), "TEAM_RESULT_UNKNOWN"
    prepared: PreparedCloseout | None = None
    try:
        prepared = _read_prepared(settings, record, now, budget)
    except TimeoutError:
        raise
    except (SpoolError, OSError, ValueError, TypeError, SafeFilesystemError, JournalIntegrityError):
        summary = _team_summary(None, None, personal_event_hash=record.get("changeset_hash"))
        summary["reason_code"] = "TEAM_PREPARED_RESULT_UNKNOWN"
        try:
            summary = _persist_team_summary(settings, record, summary, budget)
        except TimeoutError:
            raise
        except (CloseoutStoreError, OSError, ValueError, TypeError, SafeFilesystemError):
            return None, "TEAM_RESULT_PERSIST_PENDING"
        return summary, "TEAM_PREPARED_RESULT_UNKNOWN"

    team_prepared = prepared.team_prepared
    if not isinstance(team_prepared, Mapping):
        summary = _team_summary(None, None, personal_event_hash=record.get("changeset_hash"))
        summary["reason_code"] = "TEAM_PREPARED_RESULT_UNKNOWN"
        try:
            summary = _persist_team_summary(settings, record, summary, budget)
        except TimeoutError:
            raise
        except (CloseoutStoreError, OSError, ValueError, TypeError, SafeFilesystemError):
            return None, "TEAM_RESULT_PERSIST_PENDING"
        return summary, "TEAM_PREPARED_RESULT_UNKNOWN"

    if record.get("decision") == "NO":
        from .team_routing import TeamRoutingDecision
        no_apply = TeamRoutingDecision(
            "NOT_ELIGIBLE", str(team_prepared.get("reason_code", "PERSONAL_APPLY_NOT_SUCCESS")),
            "", str(team_prepared.get("team_store_id", "")), None,
        )
        summary = _team_summary(team_prepared, no_apply, personal_event_hash=None)
    else:
        changeset_hash = record.get("changeset_hash")
        if not isinstance(changeset_hash, str) or _HASH_RE.fullmatch(changeset_hash) is None or not event_ids:
            summary = _team_summary(team_prepared, None, personal_event_hash=changeset_hash)
            summary["reason_code"] = "TEAM_PERSONAL_PROOF_UNKNOWN"
            try:
                summary = _persist_team_summary(settings, record, summary, budget)
            except TimeoutError:
                raise
            except (CloseoutStoreError, OSError, ValueError, TypeError, SafeFilesystemError):
                return None, "TEAM_RESULT_PERSIST_PENDING"
            return summary, "TEAM_PERSONAL_PROOF_UNKNOWN"
        try:
            from .team_routing import deliver_prepared_team_routing
            decision = deliver_prepared_team_routing(
                team_prepared,
                settings,
                personal_event_hash=changeset_hash,
                event_ids=event_ids,
                operation_budget=budget,
            )
            summary = _team_summary(team_prepared, decision, personal_event_hash=changeset_hash)
        except TimeoutError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError, SpoolError, JournalIntegrityError, SafeFilesystemError):
            summary = _team_summary(None, None, personal_event_hash=changeset_hash)
            summary["reason_code"] = "TEAM_HANDOFF_UNKNOWN"

    try:
        summary = _persist_team_summary(settings, record, summary, budget)
    except TimeoutError:
        raise
    except (CloseoutStoreError, OSError, ValueError, TypeError, SafeFilesystemError):
        return None, "TEAM_RESULT_PERSIST_PENDING"
    if summary["status"] not in {"DELIVERED", "NOT_ELIGIBLE"}:
        return summary, str(summary["reason_code"])
    return summary, None


def _cleanup_committed(settings: Any, record: Mapping[str, Any], context: CloseoutContext, *, validation: ContextValidation | None, now: datetime, budget: OperationBudget) -> AssociationResult:
    event_ids: tuple[str, ...] = ()
    candidate_id: str | None = None
    if record.get("decision") == "YES":
        event_ids, candidate_id, reason = _verify_saved_yes(settings, record, context, budget)
        if reason is not None:
            return _result("UNKNOWN", "PENDING", reason)
    reason = _commit_receipts(
        settings,
        record,
        context,
        validation=validation,
        now=now,
        budget=budget,
        allow_missing_proofs=False,
        candidate_id=candidate_id,
    )
    if reason is not None:
        return _result("APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE", "PENDING", reason)
    team_result = record.get("team_result")
    if not _team_summary_valid(record, team_result):
        expiry = _record_expiry(record)
        if expiry is not None and expiry <= now:
            return _expire_lost_closeout(settings, record, now=now, budget=budget)
    team_result, team_reason = _finalize_team_handoff(
        settings, record, context, now=now, budget=budget, event_ids=event_ids,
    )
    if team_reason is not None or team_result is None:
        return _result(
            "APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE",
            "PENDING",
            team_reason or "TEAM_HANDOFF_PENDING",
            event_ids=event_ids,
            changeset_hash=record.get("changeset_hash"),
            team_result=team_result,
        )
    if not _team_summary_valid(record, team_result):
        return _result(
            "APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE",
            "PENDING",
            "TEAM_RESULT_UNKNOWN",
            event_ids=event_ids,
            changeset_hash=record.get("changeset_hash"),
            team_result=team_result,
        )
    spool_ref_value = record.get("spool_ref")
    if isinstance(spool_ref_value, Mapping):
        try:
            spool_ref = SpoolRef.from_dict(spool_ref_value)
            delete_spool(spool_ref, settings, budget=budget)
        except TimeoutError:
            raise
        except (SpoolError, OSError, TypeError, ValueError, SafeFilesystemError):
            return _result("APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE", "PENDING", "CLOSEOUT_CLEANUP_PENDING", event_ids=event_ids, changeset_hash=record.get("changeset_hash"))
    updated = dict(record)
    updated["spool_ref"] = None
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(str(record["record_id"]))
        if current is None or current.get("status") != "COMMITTED" or not _record_matches_intent(current, record):
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
        current["spool_ref"] = None
        current["reason_code"] = "CLOSEOUT_COMMITTED"
        store.finish(current)
    return _result(
        "APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE",
        "COMMITTED",
            "CLOSEOUT_COMMITTED",
        acknowledged=True,
        event_ids=event_ids,
        changeset_hash=record.get("changeset_hash"),
        team_result=team_result,
    )


def _cleanup_lost_closeout(settings: Any, record: Mapping[str, Any], *, now: datetime, budget: OperationBudget) -> AssociationResult:
    record_id = str(record.get("record_id", ""))
    spool_ref_value = record.get("spool_ref")
    if isinstance(spool_ref_value, Mapping):
        try:
            delete_spool(SpoolRef.from_dict(spool_ref_value), settings, budget=budget)
        except TimeoutError:
            raise
        except (SpoolError, OSError, TypeError, ValueError, SafeFilesystemError):
            with _capture_lock(settings, budget):
                store = CloseoutStore(settings, budget=budget)
                current = store.read_record(record_id)
                if (
                    current is None
                    or current.get("status") != "LOST"
                    or current.get("spool_ref") != spool_ref_value
                    or not _record_matches_intent(current, record)
                ):
                    return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
                current["reason_code"] = "CLOSEOUT_CLEANUP_PENDING"
                store.write_record(current)
            return _result(_lost_personal_knowledge(current), "PENDING", "CLOSEOUT_CLEANUP_PENDING", changeset_hash=current.get("changeset_hash"))
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(record_id)
        if (
            current is None
            or current.get("status") != "LOST"
            or current.get("spool_ref") != spool_ref_value
            or not _record_matches_intent(current, record)
        ):
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
        current["spool_ref"] = None
        current["reason_code"] = "CLOSEOUT_CACHE_EXPIRED"
        current = store.write_record(current)

    # Persist the bounded, sanitized handoff before dropping the last active
    # recovery locator. Use the same operation time and budget, outside the
    # closeout lock to preserve lock ordering.
    from .incidents import closeout_recovery_loss_issue, update_incidents

    update_incidents(
        settings,
        (closeout_recovery_loss_issue(record_id),),
        now=now,
        budget=budget,
    )

    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(record_id)
        if (
            current is None
            or current.get("status") != "LOST"
            or current.get("spool_ref") is not None
            or not _record_matches_intent(current, record)
        ):
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
        store.finish(current)
    return _result(_lost_personal_knowledge(current), "PENDING", "CLOSEOUT_CACHE_EXPIRED", changeset_hash=current.get("changeset_hash"))


def _record_expiry(record: Mapping[str, Any]) -> datetime | None:
    try:
        expiry = datetime.fromisoformat(str(record.get("expires_at", "")).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return expiry if expiry.tzinfo is not None and expiry.utcoffset() is not None else None


def _lost_personal_knowledge(record: Mapping[str, Any]) -> str:
    summary = record.get("team_result")
    if not isinstance(summary, Mapping) or summary.get("reason_code") != "TEAM_HANDOFF_EXPIRED":
        return "NOT_APPLIED"
    decision = record.get("decision")
    if decision == "YES":
        reference = _deserialize_application_ref(record)
        witness = record.get("witness")
        if (
            reference is None
            or not isinstance(witness, list)
            or len(witness) < 2
            or record.get("changeset_hash") != reference.changeset_hash
        ):
            return "UNKNOWN"
        expected = _result_digest(
            record,
            decision="YES",
            changeset_id_hash=record.get("changeset_id_hash"),
            changeset_hash=record.get("changeset_hash"),
            witness=witness,
        )
        return "APPLIED" if record.get("result_digest") == expected else "UNKNOWN"
    if decision == "NO":
        expected = _result_digest(record, decision="NO", changeset_id_hash=None, changeset_hash=None, witness=[])
        return "EVALUATED_NONE" if record.get("result_digest") == expected else "UNKNOWN"
    return "NOT_APPLIED"


def _expire_lost_closeout(settings: Any, record: Mapping[str, Any], *, budget: OperationBudget, now: datetime) -> AssociationResult:
    record_id = str(record.get("record_id", ""))
    with _capture_lock(settings, budget):
        store = CloseoutStore(settings, budget=budget)
        current = store.read_record(record_id)
        if current is None or not _record_matches_intent(current, record):
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
        if current.get("status") != "LOST":
            expiry = _record_expiry(current)
            if expiry is None or expiry > now:
                return _result("UNKNOWN", "PENDING", "CLOSEOUT_STATE_CONFLICT")
            status = current.get("status")
            if (
                status == "COMMITTED"
                and not _team_summary_valid(current, current.get("team_result"))
            ):
                existing_summary = current.get("team_result")
                summary = dict(existing_summary) if isinstance(existing_summary, Mapping) else _team_summary(
                    None,
                    None,
                    personal_event_hash=current.get("changeset_hash") if current.get("decision") == "YES" else None,
                )
                summary.update({"status": "UNKNOWN", "reason_code": "TEAM_HANDOFF_EXPIRED"})
                personal_hash = current.get("changeset_hash") if current.get("decision") == "YES" else None
                summary["personal_event_hash"] = personal_hash if isinstance(personal_hash, str) and _HASH_RE.fullmatch(personal_hash) else None
                current["team_result"] = _bind_team_summary(current, summary)
            elif status not in {"PREPARING", "PREPARED"}:
                return _result("UNKNOWN", "PENDING", "CLOSEOUT_STATE_CONFLICT")
            current["status"] = "LOST"
            current["reason_code"] = "CLOSEOUT_CACHE_EXPIRED"
            current = store.write_record(current)
    return _cleanup_lost_closeout(settings, current, now=now, budget=budget)


def _commit_closeout(settings: Any, record: Mapping[str, Any], context: CloseoutContext, *, validation: ContextValidation | None, now: datetime, budget: OperationBudget) -> AssociationResult:
    event_ids: tuple[str, ...] = ()
    candidate_id: str | None = None
    if record.get("decision") == "YES":
        event_ids, candidate_id, verification_reason = _verify_saved_yes(settings, record, context, budget)
        if verification_reason is not None:
            return _result("UNKNOWN", "PENDING", verification_reason)
    if record.get("status") != "COMMITTED":
        reason = _commit_receipts(
            settings, record, context, validation=validation, now=now, budget=budget, allow_missing_proofs=True, candidate_id=candidate_id
        )
        if reason is not None:
            return _result(
                "APPLIED" if record.get("decision") == "YES" else "EVALUATED_NONE",
                "PENDING",
                reason,
                event_ids=event_ids,
                changeset_hash=record.get("changeset_hash"),
            )
        committed = dict(record)
        committed.update({"status": "COMMITTED", "reason_code": "CLOSEOUT_COMMITTED"})
        with _capture_lock(settings, budget):
            store = CloseoutStore(settings, budget=budget)
            current = store.read_record(str(record["record_id"]))
            if current is None or not _record_matches_intent(current, record):
                return _result("UNKNOWN", "PENDING", "CLOSEOUT_RECORD_CONFLICT")
            if current.get("status") != "COMMITTED":
                if current.get("status") not in {"PREPARED", "APPLIED"}:
                    return _result("UNKNOWN", "PENDING", "CLOSEOUT_STATE_CONFLICT")
                committed = dict(current)
                committed.update({"status": "COMMITTED", "reason_code": "CLOSEOUT_COMMITTED"})
                store.write_record(committed)
            else:
                committed = current
        record = committed
    return _cleanup_committed(settings, record, context, validation=validation, now=now, budget=budget)


def _apply_prepared(settings: Any, record: Mapping[str, Any], context: CloseoutContext, prepared: PreparedCloseout, *, validation: ContextValidation | None, now: datetime, budget: OperationBudget) -> AssociationResult:
    with _capture_lock(settings, budget):
        if validation is None:
            context_reason = _revalidate_persisted_context_under_lock(
                settings,
                context,
                str(record.get("binding_digest", "")),
                budget=budget,
            )
        else:
            context_reason = _revalidate_context_under_lock(settings, validation, budget=budget)
    if context_reason is not None:
        return _result("UNKNOWN", "PENDING", context_reason)
    if prepared.decision == "NO":
        if record.get("status") != "COMMITTED":
            with _capture_lock(settings, budget):
                store = CloseoutStore(settings, budget=budget)
                current = store.read_record(str(record["record_id"]))
                if current is None or current.get("decision") != "NO" or current.get("result_digest") != record.get("result_digest"):
                    return _result("UNKNOWN", "PENDING", "CLOSEOUT_PROOF_CONFLICT")
                record = current
        return _commit_closeout(settings, record, context, validation=validation, now=now, budget=budget)
    changeset = prepared.changeset
    if changeset is None:
        return _result("UNKNOWN", "PENDING", "CLOSEOUT_PREPARE_INVALID")
    reason = _validate_changeset_context(settings, context, changeset)
    if reason is not None:
        return _result("UNKNOWN", "PENDING", reason)
    ref = _deserialize_application_ref(record)
    if ref is None:
        try:
            applied = apply_changeset(changeset, settings, budget=budget)
        except TimeoutError:
            raise
        except (JournalLimitError, JournalIntegrityError, OSError, ValueError, TypeError, SafeFilesystemError):
            return _result("NOT_APPLIED", "PENDING", "CLOSEOUT_APPLY_UNKNOWN")
        if not applied.applied or applied.application_ref is None:
            return _result("NOT_APPLIED", "PENDING", applied.reason_code if _SAFE_ID_RE.fullmatch(applied.reason_code or "") else "CLOSEOUT_APPLY_REJECTED")
        try:
            record = _persist_application_ref(settings, record, applied.application_ref, changeset, budget)
        except TimeoutError:
            raise
        except (CloseoutStoreError, OSError, ValueError, SafeFilesystemError):
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_APPLICATION_REF_PENDING")
        ref = applied.application_ref
    witness, event_ids, reason = _verify_yes(settings, record, context, prepared, ref, budget)
    if reason is not None:
        return _result("UNKNOWN", "PENDING", reason)
    try:
        record = _persist_verified_witness(settings, record, witness, budget)
    except TimeoutError:
        raise
    except (CloseoutStoreError, OSError, ValueError, SafeFilesystemError):
        return _result("UNKNOWN", "PENDING", "CLOSEOUT_WITNESS_PENDING")
    return _commit_closeout(settings, record, context, validation=validation, now=now, budget=budget)


def apply_associated_closeout(
    settings: Any,
    validation: ContextValidation,
    *,
    content_hash: str,
    prepare: Callable[[], PreparedCloseout],
    now: datetime,
    budget: OperationBudget,
) -> AssociationResult:
    """Reserve, apply, and receipt-commit one adapter-validated closeout."""
    moment = _now_utc(now)
    if moment is None or not isinstance(content_hash, str) or _HASH_RE.fullmatch(content_hash) is None or not callable(prepare):
        return _result("UNKNOWN", "REJECTED", "CLOSEOUT_REQUEST_INVALID")
    try:
        budget.check()
        with _capture_lock(settings, budget):
            reason = _revalidate_context_under_lock(settings, validation, budget=budget)
            if reason is not None:
                return _result("UNKNOWN", "REJECTED", reason)
            context = validation.context
            assert context is not None
            intent = _new_intent(settings, validation, content_hash, moment, budget)
            store = CloseoutStore(settings, budget=budget)
            record = store.read_record(intent["record_id"])
            if record is None:
                record = store.reserve(intent)
                new_request = True
            else:
                new_request = False
                conflict_reason = _request_conflict_reason(record, validation, content_hash)
                if conflict_reason is not None:
                    return _result("UNKNOWN", "REJECTED", conflict_reason)
        if new_request:
            try:
                prepared, reason = _validate_prepared(prepare(), content_hash)
            except TimeoutError:
                raise
            except Exception:
                return _result("UNKNOWN", "PENDING", "CLOSEOUT_PREPARE_PENDING")
            if prepared is None:
                return _result("UNKNOWN", "PENDING", reason or "CLOSEOUT_PREPARE_INVALID")
            try:
                record = _persist_prepared(settings, record, prepared, moment, budget)
            except TimeoutError:
                raise
            except (CloseoutStoreError, SpoolError, OSError, ValueError, TypeError, SafeFilesystemError):
                return _result("UNKNOWN", "PENDING", "CLOSEOUT_CACHE_PENDING")
        if record.get("status") == "COMMITTED":
            return _cleanup_committed(settings, record, context, validation=validation, now=moment, budget=budget)
        if record.get("status") == "LOST":
            return _cleanup_lost_closeout(settings, record, now=moment, budget=budget)
        if record.get("status") == "APPLIED":
            return _commit_closeout(settings, record, context, validation=validation, now=moment, budget=budget)
        record, prepared = _load_prepared(settings, record, moment, budget)
        if prepared is None:
            expiry = datetime.fromisoformat(str(record["expires_at"]).replace("Z", "+00:00"))
            if expiry <= moment and record.get("status") in {"PREPARING", "PREPARED"}:
                return _expire_lost_closeout(settings, record, budget=budget, now=moment)
            return _result("UNKNOWN", "PENDING", "CLOSEOUT_CACHE_PENDING")
        return _apply_prepared(settings, record, context, prepared, validation=validation, now=moment, budget=budget)
    except TimeoutError:
        raise
    except CloseoutStoreError as exc:
        return _result("UNKNOWN", "PENDING", exc.reason_code)
    except JournalIntegrityError as exc:
        reason = re.sub(r"[^A-Z0-9]+", "_", str(exc).upper())[:96]
        return _result("UNKNOWN", "PENDING", reason if re.fullmatch(r"[A-Z0-9_]{1,96}", reason) else "CLOSEOUT_STORAGE_UNKNOWN")
    except (CloseoutContextError, JournalLimitError, SpoolError, SafeFilesystemError, OSError, RuntimeError, ValueError, TypeError):
        return _result("UNKNOWN", "PENDING", "CLOSEOUT_STORAGE_UNKNOWN")


def recover_closeout_associations(settings: Any, *, now: datetime, budget: OperationBudget, max_records: int = 64) -> dict[str, Any]:
    """Resume only body-free indexed closeout intents; never prepare or curate."""
    moment = _now_utc(now)
    if moment is None:
        return {"processed": 0, "results": [], "reason_code": "CLOSEOUT_REQUEST_INVALID"}
    try:
        with _capture_lock(settings, budget):
            records = CloseoutStore(settings, budget=budget).active_records(max_records=max_records)
    except TimeoutError:
        raise
    except CloseoutStoreError as exc:
        return {"processed": 0, "results": [], "reason_code": exc.reason_code}
    results: list[dict[str, str]] = []
    for item in records:
        budget.check()
        record_id = str(item.get("record_id", ""))
        try:
            context = _context_from_record(settings, item)
            if context is None:
                item_result = {"record_id": record_id, "association": "UNKNOWN", "reason_code": "CLOSEOUT_CONTEXT_UNVERIFIED"}
            else:
                with _capture_lock(settings, budget):
                    reason = _revalidate_persisted_context_under_lock(settings, context, str(item["binding_digest"]), budget=budget)
                if reason is not None:
                    item_result = {"record_id": record_id, "association": "UNKNOWN", "reason_code": reason}
                elif item.get("status") == "LOST":
                    result = _cleanup_lost_closeout(settings, item, now=moment, budget=budget)
                    item_result = {"record_id": record_id, "association": result.association, "reason_code": result.reason_code}
                elif item.get("status") == "COMMITTED":
                    result = _cleanup_committed(settings, item, context, validation=None, now=moment, budget=budget)
                    item_result = {"record_id": record_id, "association": result.association, "reason_code": result.reason_code}
                elif item.get("status") == "APPLIED":
                    result = _commit_closeout(settings, item, context, validation=None, now=moment, budget=budget)
                    item_result = {"record_id": record_id, "association": result.association, "reason_code": result.reason_code}
                elif item.get("status") in {"PREPARING", "PREPARED"}:
                    item, prepared = _load_prepared(settings, dict(item), moment, budget)
                    if prepared is None:
                        expiry = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
                        if expiry <= moment:
                            result = _expire_lost_closeout(settings, item, budget=budget, now=moment)
                            item_result = {"record_id": record_id, "association": result.association, "reason_code": result.reason_code}
                        else:
                            item_result = {"record_id": record_id, "association": "PENDING", "reason_code": "CLOSEOUT_CACHE_PENDING"}
                    else:
                        result = _apply_prepared(settings, item, context, prepared, validation=None, now=moment, budget=budget)
                        item_result = {"record_id": record_id, "association": result.association, "reason_code": result.reason_code}
                else:
                    item_result = {"record_id": record_id, "association": "PENDING", "reason_code": "CLOSEOUT_STATE_UNKNOWN"}
        except TimeoutError:
            raise
        except (CloseoutStoreError, CloseoutContextError, SpoolError, JournalIntegrityError, JournalLimitError, SafeFilesystemError, OSError, RuntimeError, ValueError, TypeError):
            item_result = {"record_id": record_id, "association": "UNKNOWN", "reason_code": "CLOSEOUT_RECOVERY_UNKNOWN"}
        results.append(item_result)
        try:
            with _capture_lock(settings, budget):
                CloseoutStore(settings, budget=budget).advance_cursor(record_id)
        except TimeoutError:
            raise
        except (CloseoutStoreError, SafeFilesystemError, OSError, RuntimeError, ValueError, TypeError):
            results[-1] = {"record_id": record_id, "association": "UNKNOWN", "reason_code": "CLOSEOUT_CURSOR_UNKNOWN"}
    return {"processed": len(results), "results": results, "reason_code": "CLOSEOUT_RECOVERY_COMPLETE"}
