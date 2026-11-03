"""Durable intake of explicitly supplied structured candidates (never transcripts)."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from . import capture_ledger as ledger
from .capture_contract import CaptureIdentity, CaptureReceipt, capture_key, pending_policy
from .config import Settings
from .journal import validate_schema
from .key_provider import KeyProvider
from .models import Event, ObservationInput
from .privacy import inspect_observation
from .queue import QueueError, QueueState, _new_queue_id, enqueue_receipt, read_queue_item, transition_queue_item
from .safe_fs import assert_safe_target, safe_ensure_directory, safe_unlink
from .spool import SpoolRef, _authenticated_pending_ref, delete_spool, read_spool, write_spool, _pid_state
from .runtime_catalog import RuntimeCatalog, CatalogUnknown, lookup, read_entry
from .operation_runtime import OperationBudget


class AgentAdmissionError(ValueError):
    """A Skill-only admission limit or incomplete history, never custody."""


def pending_id(capture_id: str, content_hash: str) -> str:
    return "pending_" + hashlib.sha256((capture_id + "\n" + content_hash).encode("ascii")).hexdigest()


def _hash(value: str | bytes) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _iso(now: datetime) -> str:
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("CAPTURE_TIME_INVALID")
    return now.isoformat().replace("+00:00", "Z")


def _validate(observation: ObservationInput) -> bytes:
    if not isinstance(observation, ObservationInput) or not inspect_observation(observation).allow_private_sync:
        raise ValueError("PENDING_PRIVACY_REJECTED")
    if observation.outcome_status not in {"success", "failed", "partial", "unknown"}:
        raise ValueError("PENDING_SCHEMA_REJECTED")
    value = asdict(observation)
    schema_value = {k: v for k, v in value.items() if k not in {"source_kind", "source_ref", "cwd"}}
    schema_value.update(observation_id="pending", cwd_fingerprint=_hash(observation.cwd), provenance_key=_hash(observation.source_ref))
    # The existing observation validator is the semantic boundary (not merely
    # JSON Schema). It validates host applicability and forbidden content too.
    validate_schema("observation", schema_value)
    if observation.classification not in {"public", "private-reusable"}:
        raise ValueError("PENDING_PRIVACY_REJECTED")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _policy(settings: Settings):
    path = Path(settings.capture_policy_path)
    return pending_policy(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {})


def _intent_root(root: Path) -> Path:
    target = safe_ensure_directory(root / "intents", mode=0o700)
    return assert_safe_target(root, target, allow_missing=False, expected_type="dir")


def _intent_path(root: Path, spool_id: str, budget=None) -> Path:
    if not spool_id.startswith("pending_") or len(spool_id) != 72 or any(c not in "0123456789abcdef" for c in spool_id[8:]):
        raise ValueError("PENDING_INTENT_INVALID")
    return lookup(root, spool_id, budget=budget)


def _save(root: Path, path: Path, value: dict, budget=None) -> None:
    catalog = _catalog(root, budget)
    page = catalog.migrate_page(budget=budget, inspect_metadata=lambda path: ("intent", _intent_tag(_load(root, path, budget=budget))),
                                inspect_update=lambda path: _update_metadata(root, path, budget))
    if not page.complete:
        reservation = catalog.reservation(path.stem, budget=budget)
        if reservation is None or reservation["phase"] != "writing":
            raise CatalogUnknown("PENDING_INVENTORY_PARTIAL")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    catalog.write(path.stem, data, purpose="intent", tag=_intent_tag(value), budget=budget,
        created_at=value["spool_ref"]["created_at"], expires_at=value["spool_ref"]["expires_at"],
        writer=lambda target: ledger._write_path(root, target, data, budget=budget))


def _catalog(root, budget):
    def cleanup(path):
        if budget is not None:
            budget.check()
        match = re.fullmatch(r"\.pending_[0-9a-f]{64}\.json\.([1-9][0-9]{0,9})\.[0-9a-f]{32}\.tmp", path.name)
        if match is None:
            return False
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if _pid_state(int(match[1])) is not False:
            raise CatalogUnknown("PENDING_TEMP_CLEANUP_UNCONFIRMED")
        if budget is not None:
            budget.check()
        return safe_unlink(root, path, allow_missing=True)
    return RuntimeCatalog(root, prefix="pending_", clean_temporary=cleanup)


def _load(root: Path, path: Path, budget=None) -> dict:
    if budget is not None:
        budget.check()
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    value = json.loads(read_entry(root, path, budget=budget))
    allowed = {"capture_id", "content_hash", "spool_ref", "phase", "queue_id", "session_hash", "turn_hash", "reason_code", "cleanup_code"}
    if not isinstance(value, dict) or set(value) not in (allowed, allowed | {"admission"}) or value["phase"] not in {"PREPARED", "COMMITTED", "EXPIRED"}:
        raise ValueError("PENDING_INTENT_INVALID")
    ledger._path(root, value["capture_id"])
    ref = SpoolRef.from_dict(value["spool_ref"])
    validate_schema("spool-item", value["spool_ref"])
    if ref.purpose != "pending" or value["content_hash"] != ref.content_hash or path != _intent_path(root, pending_id(value["capture_id"], value["content_hash"]), budget=budget):
        raise ValueError("PENDING_INTENT_INVALID")
    if ref.spool_id != path.stem:
        raise ValueError("PENDING_INTENT_INVALID")
    if value["reason_code"] not in {"PENDING_PREPARED", "PENDING_SECURED", "PENDING_EXPIRED"} or value["cleanup_code"] not in {None, "EXPIRY_CLEANUP_FAILED", "EXPIRY_CLEANUP_CONFIRMED"}:
        raise ValueError("PENDING_INTENT_INVALID")
    for name in ("session_hash", "turn_hash"):
        if value[name] is not None:
            ledger._path(root, value[name])
    _intent_tag(value)
    return value


def _intent_tag(value):
    admission = value.get("admission")
    if admission is None:
        # Unpublished experimental records are not auto-upgraded or classified.
        return ""
    if not isinstance(admission, dict) or set(admission) != {"origin", "session_hash", "agent_key"}:
        raise ValueError("PENDING_ADMISSION_INVALID")
    origin, session, key = (admission[name] for name in ("origin", "session_hash", "agent_key"))
    if origin not in {"AGENT_SKILL", "NATIVE_SOURCE", "UNKNOWN"} or session != value["session_hash"]:
        raise ValueError("PENDING_ADMISSION_INVALID")
    if session is not None and (not isinstance(session, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", session)):
        raise ValueError("PENDING_ADMISSION_INVALID")
    if origin == "AGENT_SKILL":
        if session is None or not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("PENDING_ADMISSION_INVALID")
    elif key is not None:
        raise ValueError("PENDING_ADMISSION_INVALID")
    return origin + ":" + (session or "unknown")


def _agent_session_intents(settings, root, session_hash, *, budget):
    """Caller owns the capture lock. Reservations are not custody evidence."""
    budget.check()
    intent_root = assert_safe_target(root, root / "intents", allow_missing=True, expected_type="dir")
    if not intent_root.exists():
        return {}
    catalog = _catalog(intent_root, budget)
    page = catalog.migrate_page(budget=budget,
        inspect_metadata=lambda path: ("intent", _intent_tag(_load(intent_root, path, budget=budget))),
        inspect_update=lambda path: _update_metadata(intent_root, path, budget))
    if not page.complete:
        raise CatalogUnknown("SESSION_CAPTURE_HISTORY_UNKNOWN")
    unknown_tag = "UNKNOWN:" + session_hash
    if catalog.tagged_paths(unknown_tag, limit=1, budget=budget):
        raise CatalogUnknown("SESSION_CAPTURE_HISTORY_UNKNOWN")
    tag = "AGENT_SKILL:" + session_hash
    paths = catalog.tagged_paths(tag, limit=max(1, settings.capture_max_per_session) + 1, budget=budget)
    found = {}
    for path in paths:
        budget.check()
        value = _load(intent_root, path, budget=budget)
        if _intent_tag(value) != tag:
            raise CatalogUnknown("SESSION_CAPTURE_HISTORY_UNKNOWN")
        found[value["admission"]["agent_key"]] = value
    budget.check()
    return found


def _update_metadata(root, path, budget):
    value = _load(root, path, budget=budget)
    return dict(purpose="intent", tag=_intent_tag(value), retry_tag="", created_at=value["spool_ref"]["created_at"], expires_at=value["spool_ref"]["expires_at"])


def _receipt(capture_id: str, now: datetime, state="WAITING", code="PENDING_WAITING", item=None) -> CaptureReceipt:
    return CaptureReceipt(capture_id, state, (item.queue_id,) if item else (), (capture_id,), code, now,
        ((item.queue_id, item.source_hash),) if item else ())


def _recover_terminal(settings, root, intent_root, path, intent, item, old, now, budget=None):
    if not _intent_tag(intent):
        raise CatalogUnknown("SESSION_CAPTURE_HISTORY_UNKNOWN")
    """Capture lock is held; matched terminal metadata replaces consumed body evidence."""
    ref = SpoolRef.from_dict(intent["spool_ref"])
    digest = ref.spool_id[8:]
    stamp = datetime.fromisoformat(ref.created_at.replace("Z", "+00:00")).strftime("%Y%m%dT%H%M%SZ")
    event_id = "evt_" + stamp + "_" + digest[:12]
    key = "sha256:" + digest
    if (item.state not in {QueueState.DONE, QueueState.NO_DISCARDED}
            or item.capture_id != intent["capture_id"] or item.source_hash != ref.content_hash
            or item.event_id != event_id or item.idempotency_key != key
            or item.queue_id != intent["queue_id"]
            or item.queue_id != _new_queue_id(event_id, key, item.source_host_id)
            or item.host_id != item.source_host_id or item.created_at != ref.created_at
            or item.privacy_classification != ref.classification
            or item.session_id_hash != (intent["session_hash"] or _hash(""))
            or item.turn_id_hash != (intent["turn_hash"] or _hash(""))
            or (item.payload_ref is not None and item.payload_ref != ref)):
        raise ValueError("PENDING_QUEUE_MISMATCH")
    if item.state in {QueueState.NO_DISCARDED, QueueState.DONE} and (item.payload_ref or item.validated_result_ref):
        transition_queue_item(item, item.state, settings, now=now, reason_code=item.last_error_code,
            next_eligible_at=now + timedelta(seconds=300), budget=budget)
    if old is not None and (old.state == "UNKNOWN" or old.reason_code == "PENDING_EXPIRED"):
        return old
    # Consumer completion is durable even when its payload has been deleted.
    # Never synthesize it, and never classify a completed candidate as TTL loss.
    result = ledger._record_receipt_locked(root, _receipt(intent["capture_id"], now, "SECURED", "PENDING_SECURED", item), budget=budget)
    intent.update(phase="COMMITTED", reason_code="PENDING_SECURED")
    _save(intent_root, path, intent, budget=budget)
    return result


def _complete(settings, root, intent_root, path, intent, now, key_provider=None, budget=None):
    if not _intent_tag(intent):
        raise CatalogUnknown("SESSION_CAPTURE_HISTORY_UNKNOWN")
    original = dict(intent)
    ref = SpoolRef.from_dict(intent["spool_ref"])
    # Always authenticate the body before ACK, even if a receipt/queue exists.
    raw = read_spool(ref, settings, now=now, key_provider=key_provider, budget=budget)
    payload = json.loads(raw.decode("utf-8"))
    observation = ObservationInput(**payload)
    if _validate(observation) != raw:
        raise ValueError("PENDING_CONTENT_INVALID")
    # A crash can leave the planned ref (without its key ID) in the intent.
    # Recover original metadata through a read-only authenticated operation.
    ref = _authenticated_pending_ref(ref, settings, intent["capture_id"], now=now, key_provider=key_provider, budget=budget)
    intent["spool_ref"] = ref.to_dict()
    digest = ref.spool_id[8:]
    stamp = datetime.fromisoformat(ref.created_at.replace("Z", "+00:00")).strftime("%Y%m%dT%H%M%SZ")
    event = Event("evt_" + stamp + "_" + digest[:12], "pending.candidate", ref.created_at,
        observation.source_host_id, "pending", {
            "source_hash": ref.content_hash, "classification": ref.classification,
            "session_id_hash": intent["session_hash"] or _hash(""),
            "turn_id_hash": intent["turn_hash"] or _hash(""),
            "source_host_id": observation.source_host_id, "source_host_family": observation.source_host_family,
        }, idempotency_key="sha256:" + digest)
    intent["queue_id"] = _new_queue_id(event.event_id, event.idempotency_key, observation.source_host_id)
    if intent != original:
        _save(intent_root, path, intent, budget=budget)
    original = dict(intent)
    stored = _read_optional_queue(intent["queue_id"], settings, budget=budget)
    if stored is None:
        item = enqueue_receipt(event, ref, settings, now=datetime.fromisoformat(ref.created_at.replace("Z", "+00:00")), capture_id=intent["capture_id"], budget=budget)
        # Emergency metadata alone is not a durable queue acknowledgement.
        stored = read_queue_item(item.queue_id, settings, budget=budget)
    if stored.capture_id != intent["capture_id"] or stored.payload_ref != ref or stored.idempotency_key != event.idempotency_key or stored.source_hash != ref.content_hash:
        raise ValueError("PENDING_QUEUE_MISMATCH")
    result = ledger._record_receipt_locked(root, _receipt(intent["capture_id"], now, "SECURED", "PENDING_SECURED", stored), budget=budget)
    intent.update(phase="COMMITTED", reason_code="PENDING_SECURED", queue_id=stored.queue_id)
    if intent != original:
        _save(intent_root, path, intent, budget=budget)
    return result


def _expire(settings, root, intent_root, path, intent, now, budget=None):
    capture_id = intent["capture_id"]
    # Loss evidence must survive failure at every following cleanup boundary.
    result = ledger._record_receipt_locked(root, _receipt(capture_id, now, "UNAVAILABLE", "PENDING_EXPIRED"), budget=budget)
    intent.update(phase="EXPIRED", reason_code="PENDING_EXPIRED")
    _save(intent_root, path, intent, budget=budget)
    try:
        if intent["queue_id"]:
            item = _read_optional_queue(intent["queue_id"], settings, budget=budget)
            if item is not None:
                if item.capture_id != capture_id or (item.payload_ref is not None and item.payload_ref.spool_id != intent["spool_ref"]["spool_id"]):
                    raise ValueError("PENDING_QUEUE_MISMATCH")
                if item.state not in {QueueState.DONE, QueueState.NO_DISCARDED}:
                    item = transition_queue_item(item, QueueState.FAILED_NEEDS_ATTENTION, settings, now=now, reason_code="PENDING_EXPIRED", budget=budget)
                if item.validated_result_ref is not None:
                    delete_spool(item.validated_result_ref, settings, reason_code="PENDING_EXPIRED", budget=budget)
        delete_spool(SpoolRef.from_dict(intent["spool_ref"]), settings, reason_code="PENDING_EXPIRED", budget=budget)
    except (OSError, ValueError, TypeError, RuntimeError):
        intent["cleanup_code"] = "EXPIRY_CLEANUP_FAILED"
    else:
        intent["cleanup_code"] = "EXPIRY_CLEANUP_CONFIRMED"
    _save(intent_root, path, intent, budget=budget)
    return result


def _read_optional_queue(queue_id, settings, budget=None):
    try:
        return read_queue_item(queue_id, settings, budget=budget)
    except QueueError as exc:
        if str(exc) == "QUEUE_ITEM_NOT_FOUND":
            return None
        raise


def accept_candidate(settings: Settings, identity: CaptureIdentity, observation: ObservationInput, *, now: datetime, key_provider: KeyProvider | None = None, budget=None, origin="UNKNOWN") -> CaptureReceipt:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    _iso(now)
    capture_id = capture_key(identity)
    if capture_id is None:
        return ledger.register_target(settings, identity, now=now, budget=budget)
    try:
        if origin not in {"NATIVE_SOURCE", "UNKNOWN"}:
            raise ValueError("PENDING_ADMISSION_INVALID")
        _validate(observation)
        if observation.source_host_id != identity.host_id:
            raise ValueError("PENDING_HOST_MISMATCH")
    except (ValueError, TypeError, RuntimeError):
        return _receipt(capture_id, now, "UNAVAILABLE", "PENDING_INPUT_REJECTED")
    descriptor = None
    try:
        root = ledger._root(settings)
        descriptor = ledger._acquire(root, budget=budget)
        return _accept_candidate_locked(settings, identity, observation, root=root, now=now, key_provider=key_provider,
            budget=budget, admission=dict(origin=origin, session_hash=identity.session_hash, agent_key=None))
    except (OSError, ValueError, TypeError, RuntimeError):
        return _receipt(capture_id, now, code="PENDING_STORAGE_UNAVAILABLE")
    finally:
        if descriptor is not None:
            ledger._release(root, descriptor)


def _accept_candidate_locked(settings, identity, observation, *, root, now, admission, key_provider=None, budget, check_admission=None):
    """Caller owns the capture lock and, for Skill, has checked admission."""
    budget.check()
    capture_id = capture_key(identity)
    if capture_id is None:
        raise ValueError("PENDING_ADMISSION_INVALID")
    content = _validate(observation)
    if observation.source_host_id != identity.host_id:
        raise ValueError("PENDING_HOST_MISMATCH")
    _intent_tag(dict(admission=admission, session_hash=identity.session_hash))
    try:
        old = ledger.read_receipt(settings, capture_id, budget=budget)
        if old is not None and (old.reason_code == "PENDING_EXPIRED" or old.state == "UNKNOWN"):
            return old
        intent_root = _intent_root(root)
        content_hash = _hash(content)
        spool_id = pending_id(capture_id, content_hash)
        path = _intent_path(intent_root, spool_id, budget=budget)
        if path.exists():
            intent = _load(intent_root, path, budget=budget)
            if not _intent_tag(intent):
                return _receipt(capture_id, now, code="SESSION_CAPTURE_HISTORY_UNKNOWN")
            if intent["queue_id"]:
                item = _read_optional_queue(intent["queue_id"], settings, budget=budget)
                if item is not None and item.state in {QueueState.DONE, QueueState.NO_DISCARDED}:
                    return _recover_terminal(settings, root, intent_root, path, intent, item, old, now, budget=budget)
        else:
            if check_admission is not None:
                previous = check_admission()
                if previous is not None:
                    # The Skill key, unlike capture identity/content, ignores
                    # title/source-ref changes. Recover only the original
                    # authenticated candidate; never relabel its AAD/coverage.
                    prior_path = _intent_path(intent_root, previous["spool_ref"]["spool_id"], budget=budget)
                    prior = _load(intent_root, prior_path, budget=budget)
                    if prior != previous:
                        raise ValueError("PENDING_ADMISSION_CHANGED")
                    prior_receipt = ledger.read_receipt(settings, prior["capture_id"], budget=budget)
                    if prior_receipt is not None and prior_receipt.reason_code == "PENDING_EXPIRED":
                        return prior_receipt
                    item = _read_optional_queue(prior["queue_id"], settings, budget=budget) if prior["queue_id"] else None
                    if item is not None and item.state in {QueueState.DONE, QueueState.NO_DISCARDED}:
                        return _recover_terminal(settings, root, intent_root, prior_path, prior, item, prior_receipt, now, budget=budget)
                    if datetime.fromisoformat(prior["spool_ref"]["expires_at"].replace("Z", "+00:00")) <= now:
                        return _expire(settings, root, intent_root, prior_path, prior, now, budget=budget)
                    return _complete(settings, root, intent_root, prior_path, prior, now, key_provider, budget=budget)
            policy = _policy(settings)
            reserved = _catalog(intent_root, budget).reservation(spool_id, budget=budget)
            created = reserved["created_at"] if reserved and reserved["phase"] == "writing" else _iso(now)
            expires = reserved["expires_at"] if reserved and reserved["phase"] == "writing" else _iso(now + timedelta(seconds=policy.ttl_seconds))
            planned = SpoolRef(spool_id, content_hash, observation.classification, created, expires, None, purpose="pending")
            intent = dict(capture_id=capture_id, content_hash=content_hash, spool_ref=planned.to_dict(),
                phase="PREPARED", queue_id=None, session_hash=identity.session_hash, turn_hash=identity.turn_hash,
                reason_code="PENDING_PREPARED", cleanup_code=None, admission=admission)
            _save(intent_root, path, intent, budget=budget)
        ref = SpoolRef.from_dict(intent["spool_ref"])
        expiry = datetime.fromisoformat(ref.expires_at.replace("Z", "+00:00"))
        if expiry <= now:
            return _expire(settings, root, intent_root, path, intent, now, budget=budget)
        actual = write_spool(content, observation.classification, settings,
            now=datetime.fromisoformat(ref.created_at.replace("Z", "+00:00")),
            ttl_seconds=int((expiry - datetime.fromisoformat(ref.created_at.replace("Z", "+00:00"))).total_seconds()),
            spool_id=spool_id, key_provider=key_provider, purpose="pending", capture_id=capture_id, retention=_policy(settings), budget=budget)
        if intent["spool_ref"] != actual.to_dict():
            intent["spool_ref"] = actual.to_dict()
            _save(intent_root, path, intent, budget=budget)
        return _complete(settings, root, intent_root, path, intent, now, key_provider, budget=budget)
    except AgentAdmissionError as exc:
        return _receipt(capture_id, now, "UNAVAILABLE", str(exc))
    except TimeoutError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError):
        return _receipt(capture_id, now, code="PENDING_STORAGE_UNAVAILABLE")


def reconcile_pending(settings: Settings, *, now: datetime, budget=None, max_records=64) -> dict:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    _iso(now)
    counts = dict(secured=0, waiting=0, expired=0, cleanup_failed=0, complete=False,
        inventory_complete=False, page_complete=False, aggregate_complete=False, processed=[],
        reason_code="PENDING_INVENTORY_PARTIAL", expired_capture_ids=[], cleanup_failed_capture_ids=[], cleanup_confirmed_capture_ids=[])
    root = ledger._root(settings)
    descriptor = ledger._acquire(root, budget=budget)
    try:
        intent_root = _intent_root(root)
        catalog = _catalog(intent_root, budget)
        inventory = catalog.migrate_page(limit=max_records, budget=budget,
            inspect_metadata=lambda path: ("intent", _intent_tag(_load(intent_root, path, budget=budget))),
            inspect_update=lambda path: _update_metadata(intent_root, path, budget))
        page = catalog.page("pending", limit=max_records, budget=budget, advance=False)
        counts["inventory_complete"] = inventory.complete and page.complete
        for path in page.paths:
            if budget is not None:
                budget.check()
            fact = dict(pending_id=path.stem, capture_id=None, candidate_id=None, created_at=None, expires_at=None,
                retained_verified=False, receipt_state="UNKNOWN", reason_code="PENDING_STORAGE_UNAVAILABLE", cleanup_code=None)
            try:
                intent = _load(intent_root, path, budget=budget)
                ref = SpoolRef.from_dict(intent["spool_ref"])
                fact.update(capture_id=intent["capture_id"], candidate_id=intent["queue_id"], created_at=ref.created_at, expires_at=ref.expires_at, cleanup_code=intent["cleanup_code"])
                old = ledger.read_receipt(settings, intent["capture_id"], budget=budget)
                if old is not None and old.state == "UNKNOWN":
                    counts["waiting"] += 1
                    fact.update(receipt_state=old.state, reason_code=old.reason_code)
                    counts["processed"].append(fact)
                    catalog.advance("pending", path.stem, budget=budget)
                    continue
                if intent["queue_id"]:
                    item = _read_optional_queue(intent["queue_id"], settings, budget=budget)
                    if item is not None and item.state in {QueueState.DONE, QueueState.NO_DISCARDED}:
                        result = _recover_terminal(settings, root, intent_root, path, intent, item, old, now, budget=budget)
                        counts["secured"] += result.state == "SECURED"
                        fact.update(receipt_state=result.state, reason_code=result.reason_code)
                        counts["processed"].append(fact)
                        catalog.advance("pending", path.stem, budget=budget)
                        continue
                if datetime.fromisoformat(ref.expires_at.replace("Z", "+00:00")) <= now or (old and old.reason_code == "PENDING_EXPIRED"):
                    result = _expire(settings, root, intent_root, path, intent, now, budget=budget)
                    fact.update(receipt_state=result.state, reason_code=result.reason_code, cleanup_code=intent["cleanup_code"])
                    counts["expired"] += 1
                    counts["expired_capture_ids"].append(intent["capture_id"])
                    counts["cleanup_failed"] += intent["cleanup_code"] == "EXPIRY_CLEANUP_FAILED"
                    if intent["cleanup_code"] == "EXPIRY_CLEANUP_FAILED":
                        counts["cleanup_failed_capture_ids"].append(intent["capture_id"])
                    elif intent["cleanup_code"] == "EXPIRY_CLEANUP_CONFIRMED":
                        counts["cleanup_confirmed_capture_ids"].append(intent["capture_id"])
                else:
                    result = _complete(settings, root, intent_root, path, intent, now, budget=budget)
                    fact.update(candidate_id=intent["queue_id"], receipt_state=result.state, reason_code=result.reason_code,
                        retained_verified=result.state == "SECURED")
                    counts["secured"] += 1
            except TimeoutError:
                raise
            except (OSError, ValueError, TypeError, RuntimeError):
                counts["waiting"] += 1
            counts["processed"].append(fact)
            catalog.advance("pending", path.stem, budget=budget)
        # These are this page's outcomes, never an all-history custody count.
        counts["page_complete"] = True
        counts["reason_code"] = "PENDING_PAGE_COMPLETE" if counts["inventory_complete"] else page.reason_code
        return counts
    except TimeoutError:
        counts["reason_code"] = "PENDING_TIME_LIMIT"
        return counts
    except CatalogUnknown as exc:
        counts["reason_code"] = str(exc)
        return counts
    finally:
        ledger._release(root, descriptor)


__all__ = ["accept_candidate", "reconcile_pending", "pending_id"]
