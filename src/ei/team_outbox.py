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
from .redaction import domain_hash
from .spool import SpoolError, delete_spool, read_spool, write_spool
from .team_store import append_team_event, scan_team_events


OUTBOX_SCHEMA_VERSION = 1
OUTBOX_DIR_NAME = "team-outbox"
_RECEIPT_KEYS = frozenset({
    "schema_version", "receipt_id", "status", "store_id_hash", "member_id_hash", "writer_id_hash",
    "personal_event_hash", "idempotency_key", "spool_ref", "created_at", "attempts",
    "last_error_code", "delivered_at", "final_event_hash",
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


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_receipt(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
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
    return dict(value)


def _records(settings: object) -> list[dict[str, object]]:
    root = _root(settings)
    if not root.is_dir():
        return []
    result: list[dict[str, object]] = []
    for path in sorted(root.glob("teamoutbox_*.json")):
        if path.name.endswith(".tmp"):
            continue
        value = _read_receipt(path)
        if value is not None:
            result.append(value)
    return result


def list_team_outbox(settings: object) -> TeamOutboxListing:
    records = _records(settings)
    pending = tuple(item for item in records if item.get("status") in {"PENDING", "DEFERRED"})
    return TeamOutboxListing(len(pending), pending)


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
) -> dict[str, object]:
    """Encrypt a complete sanitized event and create/reuse one body-free receipt."""

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
    root.mkdir(parents=True, exist_ok=True)
    existing = next((item for item in _records(settings) if item.get("receipt_id") == receipt_id), None)
    if existing is not None:
        return {"receipt_id": receipt_id, "receipt_path": str(_receipt_path(settings, receipt_id)), **existing}
    # The encrypted spool is the only location containing raw event body or
    # path-layout identifiers.  The receipt contains hashes and operational
    # state only.
    spool_ref = write_spool(payload, classification, settings, now=now, spool_id=receipt_id.replace("teamoutbox_", "spool_team_"), key_provider=key_provider)
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
    _atomic_json(_receipt_path(settings, receipt_id), receipt)
    return {"receipt_id": receipt_id, "receipt_path": str(_receipt_path(settings, receipt_id)), **receipt}


def _team_root(settings: object) -> Path | None:
    stores = getattr(settings, "knowledge_stores", None)
    team = getattr(stores, "team", None) if stores is not None else None
    if team is None:
        return None
    value = team.get("root") if isinstance(team, Mapping) else getattr(team, "root", None)
    return Path(value) if isinstance(value, (str, os.PathLike)) else None


def _already_recorded(root: Path, idempotency_key: str) -> Event | None:
    try:
        scan = scan_team_events(root)
    except Exception:
        return None
    for event in scan.events:
        if event.payload.get("idempotency_key") == idempotency_key:
            return event
    return None


def _update_receipt(settings: object, record: Mapping[str, object], **updates: object) -> dict[str, object]:
    value = {**dict(record), **updates}
    _atomic_json(_receipt_path(settings, str(value["receipt_id"])), value)
    return value


def drain_team_outbox(
    settings: object,
    *,
    max_items: int = 100,
    now: datetime | None = None,
    key_provider: object | None = None,
) -> dict[str, object]:
    """Deliver pending receipts once, retaining deferred work for retry."""

    if type(max_items) is not int or not 1 <= max_items <= 10000:
        raise ValueError("TEAM_OUTBOX_MAX_ITEMS_INVALID")
    root = _team_root(settings)
    if root is None:
        return {"status": "DISABLED", "attempted": 0, "delivered": 0, "deferred": 0, "failed": 0, "remaining": 0}
    attempted = delivered = deferred = failed = 0
    errors: list[dict[str, object]] = []
    for record in _records(settings):
        if attempted >= max_items or record.get("status") not in {"PENDING", "DEFERRED"}:
            continue
        attempted += 1
        receipt_id = str(record.get("receipt_id"))
        spool_ref = record.get("spool_ref")
        try:
            if not root.is_dir():
                raise OSError("TEAM_ROOT_UNAVAILABLE")
            raw = read_spool(spool_ref if isinstance(spool_ref, Mapping) else receipt_id, settings, now=now, key_provider=key_provider)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, Mapping) or not isinstance(value.get("event"), Mapping):
                raise ValueError("TEAM_EVENT_NOT_READY")
            event = Event.from_dict(value["event"])
            if event_integrity(event) != event.integrity_sha256:
                raise ValueError("TEAM_EVENT_INTEGRITY_INVALID")
            member_id = value.get("member_id")
            writer_id = value.get("writer_id")
            if not isinstance(member_id, str) or not isinstance(writer_id, str):
                raise ValueError("TEAM_EVENT_IDENTITY_INVALID")
            existing = _already_recorded(root, str(record.get("idempotency_key")))
            final_event = existing or event
            if existing is None:
                append_team_event(root, member_id, writer_id, event)
                final_event = event
            delete_spool(spool_ref if isinstance(spool_ref, Mapping) else receipt_id, settings, reason_code="TEAM_OUTBOX_DELIVERED")
            _update_receipt(settings, record, status="DELIVERED", attempts=int(record.get("attempts", 0)) + 1, delivered_at=_now(now), final_event_hash=event_integrity(final_event), last_error_code=None)
            delivered += 1
        except (OSError, SpoolError, ValueError, TypeError, json.JSONDecodeError) as exc:
            reason = str(exc) or type(exc).__name__
            if reason in {"TEAM_ROOT_UNAVAILABLE", "SPOOL_NOT_FOUND"}:
                deferred += 1
                _update_receipt(settings, record, status="DEFERRED", attempts=int(record.get("attempts", 0)) + 1, last_error_code=reason)
            else:
                failed += 1
                errors.append({"receipt_id_hash": _hash(receipt_id), "reason_code": reason})
                _update_receipt(settings, record, status="FAILED", attempts=int(record.get("attempts", 0)) + 1, last_error_code=reason)
    remaining = list_team_outbox(settings).count
    status = "DEFERRED" if deferred and not failed else "FAILED" if failed else "DELIVERED" if delivered else "EMPTY"
    return {"status": status, "attempted": attempted, "delivered": delivered, "deferred": deferred, "failed": failed, "remaining": remaining, "errors": errors}


__all__ = ["TeamOutboxListing", "drain_team_outbox", "enqueue_team_event", "list_team_outbox"]
