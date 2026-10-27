"""Encrypted, bounded deferred delivery for sanitized team events.

Only receipt metadata is written in ``runtime_root/team-outbox``.  The event
body and writer/member identifiers remain inside the encrypted spool envelope.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .journal import event_integrity
from .models import Event
from .persistable_fields import inspect_persistable
from .operation_runtime import _read_json
from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory
from .redaction import domain_hash
from .spool import SpoolError, delete_spool, read_spool, write_spool
from .team_store import append_team_event, inspect_team_store, scan_team_events


def _check(budget):
    if budget is not None:
        budget.check()


OUTBOX_SCHEMA_VERSION = 1
OUTBOX_DIR_NAME = "team-outbox"
_RECEIPT_KEYS = frozenset({
    "schema_version", "receipt_id", "status", "store_id_hash", "member_id_hash", "writer_id_hash",
    "personal_event_hash", "idempotency_key", "spool_ref", "created_at", "attempts",
    "last_error_code", "delivered_at", "final_event_hash", "team_root_hash",
})


@dataclass(frozen=True)
class TeamOutboxListing:
    count: int
    records: tuple[Mapping[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"count": self.count, "records": [dict(item) for item in self.records]}


def _runtime(settings: object) -> Path:
    return Path(settings.paths.runtime_root)


def _root(settings: object) -> Path:
    return _runtime(settings) / OUTBOX_DIR_NAME


def _now(value: datetime | None = None) -> str:
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("OUTBOX_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: object, domain: str = "team-outbox") -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return domain_hash(text, domain)


def _safe_receipt_id(value: str) -> str:
    if not value.startswith("teamoutbox_") or len(value) != len("teamoutbox_") + 32 or any(char not in "0123456789abcdef" for char in value[len("teamoutbox_"):]):
        raise ValueError("TEAM_OUTBOX_RECEIPT_INVALID")
    return value


def _receipt_path(settings: object, receipt_id: str) -> Path:
    _safe_receipt_id(receipt_id)
    return _root(settings) / f"{receipt_id}.json"


def _atomic_json(path: Path, value: Mapping[str, object], *, budget=None) -> None:
    _check(budget)
    raw = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(raw) > 262144:
        raise ValueError("TEAM_OUTBOX_RECEIPT_TOO_LARGE")
    safe_ensure_directory(path.parent)
    _check(budget)
    safe_atomic_write(path.parent, path, raw)


def _read_receipt(path: Path, *, budget=None) -> dict[str, object] | None:
    try:
        value = _read_json(path, budget=budget)
    except TimeoutError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping) or value.get("schema_version") != OUTBOX_SCHEMA_VERSION:
        return None
    if not isinstance(value.get("receipt_id"), str):
        return None
    try:
        _safe_receipt_id(str(value["receipt_id"]))
    except ValueError:
        return None
    if "team_root_hash" in value and (
        not isinstance(value["team_root_hash"], str)
        or len(value["team_root_hash"]) != 71
        or not value["team_root_hash"].startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value["team_root_hash"][7:])
    ):
        return None
    return dict(value)


def _records(settings: object, *, budget=None) -> list[dict[str, object]]:
    _check(budget)
    root = _root(settings)
    assert_safe_target(root.parent, root, allow_missing=True)
    if not root.is_dir():
        return []
    result: list[dict[str, object]] = []
    with os.scandir(root) as entries:
        for entry in entries:
            _check(budget)
            path = Path(entry.path)
            if not path.name.startswith("teamoutbox_") or path.suffix != ".json":
                continue
            assert_safe_target(root, path, allow_missing=False, expected_type="file")
            value = _read_receipt(path, budget=budget)
            if value is not None:
                result.append(value)
    _check(budget)
    return sorted(result, key=lambda item: str(item["receipt_id"]))


def list_team_outbox(settings: object, *, budget=None) -> TeamOutboxListing:
    records = _records(settings, budget=budget)
    pending = tuple(item for item in records if item.get("status") in {"PENDING", "DEFERRED"})
    return TeamOutboxListing(len(pending), pending)


def read_team_outbox_receipt(settings: object, receipt_id: str, *, budget=None) -> Mapping[str, object] | None:
    """Read one bounded body-free receipt without scanning the outbox."""

    _check(budget)
    path = _receipt_path(settings, receipt_id)
    root = _root(settings)
    if not root.is_dir():
        return None
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    return _read_receipt(path, budget=budget)


def _idempotency_key(payload: Mapping[str, object], personal_event_hash: str, store_id: str) -> str:
    value = payload.get("idempotency_key")
    if isinstance(value, str) and value.startswith("sha256:"):
        return value
    return _hash(personal_event_hash + store_id, "team-event-idempotency")


def enqueue_team_event(
    settings: object,
    payload: Mapping[str, object],
    *,
    personal_event_hash: str,
    store_id: str,
    member_id: str,
    writer_id: str,
    now: datetime | None = None,
    key_provider: object | None = None,
    budget=None,
) -> dict[str, object]:
    """Encrypt a complete sanitized event and create/reuse one body-free receipt."""

    _check(budget)
    if not isinstance(payload, Mapping):
        raise ValueError("TEAM_OUTBOX_PAYLOAD_INVALID")
    for value, code in ((personal_event_hash, "TEAM_OUTBOX_PERSONAL_HASH_INVALID"), (store_id, "TEAM_OUTBOX_STORE_ID_INVALID")):
        if not isinstance(value, str) or not value.startswith("sha256:") and code.endswith("HASH_INVALID"):
            raise ValueError(code)
    classification = str((payload.get("event") or payload).get("payload", {}).get("classification", "private-reusable")) if isinstance(payload.get("event") or payload, Mapping) else "private-reusable"
    if classification not in {"public", "private-reusable"}:
        raise ValueError("TEAM_OUTBOX_CLASSIFICATION_REJECTED")
    inspection = inspect_persistable(payload, classification=classification)
    if not inspection.valid:
        raise ValueError(inspection.reason_codes[0] if inspection.reason_codes else "TEAM_OUTBOX_PAYLOAD_INVALID")
    idempotency = _idempotency_key(payload, personal_event_hash, store_id)
    receipt_id = "teamoutbox_" + hashlib.sha256((store_id + personal_event_hash + idempotency).encode("utf-8")).hexdigest()[:32]
    root = _root(settings)
    _check(budget)
    safe_ensure_directory(root)
    existing = next((item for item in _records(settings, budget=budget) if item.get("receipt_id") == receipt_id), None)
    if existing is not None:
        return {"receipt_id": receipt_id, "receipt_path": str(_receipt_path(settings, receipt_id)), **existing}
    # The encrypted spool is the only location containing raw event body or
    # path-layout identifiers.  The receipt contains hashes and operational
    # state only.
    spool_ref = write_spool(payload, classification, settings, now=now, spool_id=receipt_id.replace("teamoutbox_", "spool_team_"), key_provider=key_provider, budget=budget)
    receipt: dict[str, object] = {
        "schema_version": OUTBOX_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "status": "PENDING",
        "store_id_hash": _hash(store_id, "team-store-id"),
        "member_id_hash": _hash(member_id, "team-member-id"),
        "writer_id_hash": _hash(writer_id, "team-writer-id"),
        "personal_event_hash": personal_event_hash,
        "idempotency_key": idempotency,
        "spool_ref": spool_ref.to_dict(),
        "created_at": _now(now),
        "attempts": 0,
        "last_error_code": None,
        "delivered_at": None,
        "final_event_hash": None,
    }
    team_root_hash = payload.get("team_root_hash")
    if (
        isinstance(team_root_hash, str)
        and len(team_root_hash) == 71
        and team_root_hash.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in team_root_hash[7:])
    ):
        receipt["team_root_hash"] = team_root_hash
    _atomic_json(_receipt_path(settings, receipt_id), receipt, budget=budget)
    return {"receipt_id": receipt_id, "receipt_path": str(_receipt_path(settings, receipt_id)), **receipt}


def _team_root(settings: object) -> Path | None:
    stores = getattr(settings, "knowledge_stores", None)
    team = getattr(stores, "team", None) if stores is not None else None
    if team is None:
        return None
    value = team.get("root") if isinstance(team, Mapping) else getattr(team, "root", None)
    return Path(value) if isinstance(value, (str, os.PathLike)) else None


def _binding_error(record: Mapping[str, object], root: Path, current_root_hash: str, *, budget=None) -> str | None:
    """Return a fixed error when the receipt no longer names this store."""
    _check(budget)
    saved_root_hash = record.get("team_root_hash")
    if saved_root_hash is not None and saved_root_hash != current_root_hash:
        return "TEAM_TARGET_BINDING_CHANGED"
    try:
        descriptor = inspect_team_store(root, budget=budget)
    except TimeoutError:
        raise
    except (OSError, ValueError, TypeError):
        return "TEAM_TARGET_BINDING_CHANGED"
    saved_store_hash = record.get("store_id_hash")
    if not isinstance(saved_store_hash, str) or saved_store_hash != _hash(descriptor.store_id, "team-store-id"):
        return "TEAM_TARGET_BINDING_CHANGED"
    return None


def _spooled_identity_matches(record: Mapping[str, object], settings: object, key_provider: object | None, *, now=None, budget=None) -> bool:
    """Check encrypted body identities against their hash-only receipt bindings."""
    reference = record.get("spool_ref")
    if reference is None:
        return True
    raw = read_spool(reference if isinstance(reference, Mapping) else str(record.get("receipt_id")), settings, now=now, key_provider=key_provider, budget=budget)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, Mapping):
        return False
    member_id, writer_id = value.get("member_id"), value.get("writer_id")
    return (
        isinstance(member_id, str)
        and isinstance(writer_id, str)
        and record.get("member_id_hash") == _hash(member_id, "team-member-id")
        and record.get("writer_id_hash") == _hash(writer_id, "team-writer-id")
    )


def _already_recorded(root: Path, idempotency_key: str, *, budget=None) -> Event | None:
    _check(budget)
    scan = scan_team_events(root, budget=budget)
    found = None
    for event in scan.events:
        _check(budget)
        if event.payload.get("idempotency_key") == idempotency_key:
            if found is not None and event_integrity(found) != event_integrity(event):
                raise OSError("TEAM_IDEMPOTENCY_CONFLICT")
            found = event
    if found is None and scan.issues:
        raise OSError("TEAM_SCAN_INCOMPLETE")
    return found


def _update_receipt(settings: object, record: Mapping[str, object], *, budget=None, **updates: object) -> dict[str, object]:
    value = {**dict(record), **updates}
    _atomic_json(_receipt_path(settings, str(value["receipt_id"])), value, budget=budget)
    return value


def _release_delivered(settings, record, root, key_provider, budget):
    """A durable receipt and actual matching event precede ciphertext release."""
    _check(budget)
    reference = record.get("spool_ref")
    if reference is None:
        return
    current_root_hash = domain_hash(str(root.expanduser().resolve(strict=False)), "team-root")
    if _binding_error(record, root, current_root_hash, budget=budget) is not None:
        raise ValueError("TEAM_TARGET_BINDING_CHANGED")
    spool_present = True
    try:
        if not _spooled_identity_matches(record, settings, key_provider, budget=budget):
            raise ValueError("TEAM_TARGET_BINDING_CHANGED")
    except SpoolError as exc:
        if str(exc) != "SPOOL_NOT_FOUND":
            raise
        # A previous delete may have succeeded before its receipt update timed
        # out. The durable event proof below authorizes reconciling that state.
        spool_present = False
    existing = _already_recorded(root, str(record.get("idempotency_key")), budget=budget)
    if existing is None or event_integrity(existing) != record.get("final_event_hash"):
        raise OSError("TEAM_DELIVERY_PROOF_UNAVAILABLE")
    spool_id = reference.get("spool_id") if isinstance(reference, Mapping) else reference
    if not isinstance(spool_id, str):
        raise ValueError("TEAM_OUTBOX_RECEIPT_INVALID")
    if spool_present:
        delete_spool(spool_id, settings, reason_code="TEAM_OUTBOX_DELIVERED", budget=budget, key_provider=key_provider)
    _update_receipt(settings, record, spool_ref=None, budget=budget)


def _try_release_delivered(settings, record, root, key_provider, budget):
    try:
        _release_delivered(settings, record, root, key_provider, budget)
        return True
    except TimeoutError:
        raise
    except (OSError, SpoolError, ValueError, TypeError):
        # Delivery is already durable. A cleanup fault must not downgrade that
        # proof or expose a filesystem exception containing private paths.
        return False


def drain_team_outbox(
    settings: object,
    *,
    max_items: int = 100,
    now: datetime | None = None,
    key_provider: object | None = None,
    budget=None,
) -> dict[str, object]:
    """Deliver pending receipts once, retaining deferred work for retry."""

    _check(budget)
    if type(max_items) is not int or not 1 <= max_items <= 10000:
        raise ValueError("TEAM_OUTBOX_MAX_ITEMS_INVALID")
    root = _team_root(settings)
    if root is None:
        return {"status": "DISABLED", "attempted": 0, "delivered": 0, "deferred": 0, "failed": 0, "remaining": 0}
    current_root_hash = domain_hash(str(root.expanduser().resolve(strict=False)), "team-root")
    attempted = delivered = deferred = failed = 0
    errors: list[dict[str, object]] = []
    for record in _records(settings, budget=budget):
        _check(budget)
        if record.get("status") == "DELIVERED" and record.get("spool_ref") is not None:
            if _binding_error(record, root, current_root_hash, budget=budget) is not None:
                errors.append({"receipt_id_hash": _hash(str(record["receipt_id"])), "reason_code": "TEAM_TARGET_BINDING_CHANGED"})
                continue
            try:
                if not _spooled_identity_matches(record, settings, key_provider, now=now, budget=budget):
                    errors.append({"receipt_id_hash": _hash(str(record["receipt_id"])), "reason_code": "TEAM_TARGET_BINDING_CHANGED"})
                    continue
            except TimeoutError:
                raise
            except SpoolError as exc:
                if str(exc) != "SPOOL_NOT_FOUND":
                    errors.append({"receipt_id_hash": _hash(str(record["receipt_id"])), "reason_code": "TEAM_TARGET_BINDING_CHANGED"})
                    continue
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                errors.append({"receipt_id_hash": _hash(str(record["receipt_id"])), "reason_code": "TEAM_TARGET_BINDING_CHANGED"})
                continue
            if not _try_release_delivered(settings, record, root, key_provider, budget):
                errors.append({"receipt_id_hash": _hash(str(record["receipt_id"])), "reason_code": "TEAM_DELIVERY_CLEANUP_PENDING"})
            continue
        if attempted >= max_items or record.get("status") not in {"PENDING", "DEFERRED"}:
            continue
        attempted += 1
        receipt_id = str(record.get("receipt_id"))
        spool_ref = record.get("spool_ref")
        try:
            saved_root_hash = record.get("team_root_hash")
            binding_error = _binding_error(record, root, current_root_hash, budget=budget)
            if binding_error is not None:
                deferred += 1
                _update_receipt(settings, record, status="DEFERRED", attempts=int(record.get("attempts", 0)) + 1, last_error_code=binding_error, budget=budget)
                continue
            if not root.is_dir():
                raise OSError("TEAM_ROOT_UNAVAILABLE")
            raw = read_spool(spool_ref if isinstance(spool_ref, Mapping) else receipt_id, settings, now=now, key_provider=key_provider, budget=budget)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, Mapping) or not isinstance(value.get("event"), Mapping):
                raise ValueError("TEAM_EVENT_NOT_READY")
            if saved_root_hash is not None and value.get("team_root_hash") != saved_root_hash:
                raise ValueError("TEAM_EVENT_BINDING_INVALID")
            event = Event.from_dict(value["event"])
            if event_integrity(event) != event.integrity_sha256:
                raise ValueError("TEAM_EVENT_INTEGRITY_INVALID")
            member_id = value.get("member_id")
            writer_id = value.get("writer_id")
            if not isinstance(member_id, str) or not isinstance(writer_id, str):
                raise ValueError("TEAM_EVENT_IDENTITY_INVALID")
            if (
                record.get("member_id_hash") != _hash(member_id, "team-member-id")
                or record.get("writer_id_hash") != _hash(writer_id, "team-writer-id")
            ):
                raise ValueError("TEAM_TARGET_BINDING_CHANGED")
            existing = _already_recorded(root, str(record.get("idempotency_key")), budget=budget)
            final_event = existing or event
            if existing is None:
                append_team_event(root, member_id, writer_id, event, budget=budget)
                final_event = event
            completed = _update_receipt(settings, record, status="DELIVERED", attempts=int(record.get("attempts", 0)) + 1, delivered_at=_now(now), final_event_hash=event_integrity(final_event), last_error_code=None, budget=budget)
            if not _try_release_delivered(settings, completed, root, key_provider, budget):
                errors.append({"receipt_id_hash": _hash(receipt_id), "reason_code": "TEAM_DELIVERY_CLEANUP_PENDING"})
            delivered += 1
        except TimeoutError:
            # Neither an incomplete absence scan nor an interrupted publication
            # authorizes a failure receipt or removal of the encrypted retry.
            raise
        except (OSError, SpoolError, ValueError, TypeError, json.JSONDecodeError) as exc:
            code = str(exc)
            reason = code if code in {"TEAM_ROOT_UNAVAILABLE", "SPOOL_NOT_FOUND", "TEAM_SCAN_INCOMPLETE", "TEAM_IDEMPOTENCY_CONFLICT", "TEAM_DELIVERY_PROOF_UNAVAILABLE", "TEAM_EVENT_NOT_READY", "TEAM_EVENT_INTEGRITY_INVALID", "TEAM_EVENT_IDENTITY_INVALID", "TEAM_EVENT_BINDING_INVALID", "TEAM_TARGET_BINDING_CHANGED"} else "TEAM_OUTBOX_DELIVERY_FAILED"
            if reason in {"TEAM_ROOT_UNAVAILABLE", "SPOOL_NOT_FOUND", "TEAM_SCAN_INCOMPLETE", "TEAM_IDEMPOTENCY_CONFLICT", "TEAM_DELIVERY_PROOF_UNAVAILABLE", "TEAM_EVENT_BINDING_INVALID", "TEAM_TARGET_BINDING_CHANGED"}:
                deferred += 1
                _update_receipt(settings, record, status="DEFERRED", attempts=int(record.get("attempts", 0)) + 1, last_error_code=reason, budget=budget)
            else:
                failed += 1
                errors.append({"receipt_id_hash": _hash(receipt_id), "reason_code": reason})
                _update_receipt(settings, record, status="FAILED", attempts=int(record.get("attempts", 0)) + 1, last_error_code=reason, budget=budget)
    remaining = list_team_outbox(settings, budget=budget).count
    status = "DEFERRED" if deferred and not failed else "FAILED" if failed else "DELIVERED" if delivered else "EMPTY"
    return {"status": status, "attempted": attempted, "delivered": delivered, "deferred": deferred, "failed": failed, "remaining": remaining, "errors": errors}


__all__ = ["TeamOutboxListing", "drain_team_outbox", "enqueue_team_event", "list_team_outbox", "read_team_outbox_receipt"]
