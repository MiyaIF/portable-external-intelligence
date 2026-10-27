from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .journal import validate_schema
from .spool import SpoolError, SpoolRef, delete_spool, _cleanup_temporary
from .models import Event
from .safe_fs import safe_unlink
from .hooks.base import NormalizedHookEvent
from .runtime_catalog import RuntimeCatalog, CatalogUnknown, lookup, inventory_paths, read_entry
from .operation_runtime import OperationBudget


class QueueError(RuntimeError):
    """Raised when a durable queue operation cannot safely complete."""


class QueueState(StrEnum):
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    DEFERRED = "DEFERRED"
    # Read/transition compatibility for queue files written before Task 5.
    # The alias deliberately serializes as the new non-destructive state.
    DEFERRED_QUOTA = "DEFERRED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_NEEDS_ATTENTION = "FAILED_NEEDS_ATTENTION"
    YES_CURATING = "YES_CURATING"
    NO_DISCARDED = "NO_DISCARDED"
    DONE = "DONE"
    # Legacy FAILED is accepted while reading old queue files and is mapped to
    # manual-attention state. New writes use one of the two explicit states.
    FAILED = "FAILED"
    QUARANTINED = "QUARANTINED"


_TERMINAL = frozenset({
    QueueState.NO_DISCARDED,
    QueueState.DONE,
    QueueState.FAILED_NEEDS_ATTENTION,
    QueueState.FAILED,
    QueueState.QUARANTINED,
})
_ALLOWED_TRANSITIONS = {
    QueueState.READY: frozenset({QueueState.IN_PROGRESS, QueueState.DEFERRED, QueueState.YES_CURATING, QueueState.NO_DISCARDED, QueueState.FAILED_RETRYABLE, QueueState.FAILED_NEEDS_ATTENTION, QueueState.QUARANTINED}),
    QueueState.DEFERRED: frozenset({QueueState.IN_PROGRESS, QueueState.YES_CURATING, QueueState.NO_DISCARDED, QueueState.FAILED_RETRYABLE, QueueState.FAILED_NEEDS_ATTENTION, QueueState.QUARANTINED}),
    QueueState.IN_PROGRESS: frozenset({QueueState.READY, QueueState.DEFERRED, QueueState.YES_CURATING, QueueState.NO_DISCARDED, QueueState.DONE, QueueState.FAILED_RETRYABLE, QueueState.FAILED_NEEDS_ATTENTION, QueueState.QUARANTINED}),
    QueueState.FAILED_RETRYABLE: frozenset({QueueState.READY, QueueState.IN_PROGRESS, QueueState.DEFERRED, QueueState.FAILED_NEEDS_ATTENTION, QueueState.QUARANTINED}),
    QueueState.FAILED_NEEDS_ATTENTION: frozenset({QueueState.READY, QueueState.QUARANTINED}),
    QueueState.YES_CURATING: frozenset({QueueState.READY, QueueState.DEFERRED, QueueState.DONE, QueueState.FAILED_RETRYABLE, QueueState.FAILED_NEEDS_ATTENTION, QueueState.QUARANTINED}),
    QueueState.NO_DISCARDED: frozenset(),
    QueueState.DONE: frozenset(),
    QueueState.FAILED: frozenset({QueueState.READY, QueueState.QUARANTINED}),
    QueueState.QUARANTINED: frozenset(),
}


@dataclass(frozen=True)
class QueueItem:
    queue_id: str
    event_id: str
    idempotency_key: str
    stage: str
    state: QueueState
    attempts: int
    created_at: str
    next_eligible_at: str | None
    source_ref: str | None
    source_hash: str
    host_id: str
    session_id_hash: str
    turn_id_hash: str
    payload_ref: SpoolRef | None
    provider_preference: tuple[str, ...]
    privacy_classification: str
    lease_owner: str | None = None
    lease_expires_at: str | None = None
    last_error_code: str | None = None
    source_host_id: str = ""
    source_host_family: str = ""
    capture_id: str | None = None
    validated_result_ref: SpoolRef | None = None

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "queue_id": self.queue_id,
            "event_id": self.event_id,
            "idempotency_key": self.idempotency_key,
            "stage": self.stage,
            "state": self.state.value,
            "attempts": self.attempts,
            "created_at": self.created_at,
            "next_eligible_at": self.next_eligible_at,
            "source_ref": self.source_ref,
            "source_hash": self.source_hash,
            "host_id": self.host_id,
            "session_id_hash": self.session_id_hash,
            "turn_id_hash": self.turn_id_hash,
            "payload_ref": self.payload_ref.to_dict() if self.payload_ref else None,
            "provider_preference": list(self.provider_preference),
            "privacy_classification": self.privacy_classification,
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at,
            "last_error_code": self.last_error_code,
            "source_host_id": self.source_host_id,
            "source_host_family": self.source_host_family,
            "capture_id": self.capture_id,
            "validated_result_ref": self.validated_result_ref.to_dict() if self.validated_result_ref else None,
        }
        # Pre-host-scope queues have no trusted source pair. Preserve absence
        # instead of manufacturing an invalid empty label or a current host.
        if self.source_host_id == "" and self.source_host_family == "":
            serialized.pop("source_host_id")
            serialized.pop("source_host_family")
        return serialized

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QueueItem":
        if not isinstance(value, Mapping):
            raise QueueError("QUEUE_ITEM_INVALID")
        try:
            validate_schema("queue-item", value)
            if "source_host_id" in value or "source_host_family" in value:
                if not value.get("source_host_id") or not value.get("source_host_family"):
                    raise QueueError("QUEUE_ITEM_INVALID")
            result = cls(
                queue_id=str(value["queue_id"]),
                event_id=str(value["event_id"]),
                idempotency_key=str(value["idempotency_key"]),
                stage=str(value["stage"]),
                state=(
                    QueueState.DEFERRED
                    if str(value["state"]) == "DEFERRED_QUOTA"
                    else QueueState.FAILED_NEEDS_ATTENTION
                    if str(value["state"]) == "FAILED"
                    else QueueState(str(value["state"]))
                ),
                attempts=int(value["attempts"]),
                created_at=str(value["created_at"]),
                next_eligible_at=value.get("next_eligible_at"),
                source_ref=value.get("source_ref"),
                source_hash=str(value["source_hash"]),
                host_id=str(value["host_id"]),
                session_id_hash=str(value["session_id_hash"]),
                turn_id_hash=str(value["turn_id_hash"]),
                payload_ref=SpoolRef.from_dict(value["payload_ref"]) if value.get("payload_ref") is not None else None,
                provider_preference=tuple(str(item) for item in value["provider_preference"]),
                privacy_classification=str(value["privacy_classification"]),
                lease_owner=value.get("lease_owner"),
                lease_expires_at=value.get("lease_expires_at"),
                last_error_code=value.get("last_error_code"),
                source_host_id=value.get("source_host_id", ""),
                source_host_family=value.get("source_host_family", ""),
                capture_id=value.get("capture_id"),
                validated_result_ref=SpoolRef.from_dict(value["validated_result_ref"]) if value.get("validated_result_ref") is not None else None,
            )
            if result.attempts < 0:
                raise QueueError("QUEUE_ITEM_INVALID")
            serialized = result.to_dict()
            # Legacy queue files may contain a provider priority list.  Keep
            # it in memory for read compatibility, while validating the
            # canonical single-provider wire shape.
            if len(result.provider_preference) > 1:
                serialized["provider_preference"] = [result.provider_preference[0]]
            validate_schema("queue-item", serialized)
            return result
        except (KeyError, TypeError, ValueError, QueueError) as exc:
            if isinstance(exc, QueueError) and str(exc) == "QUEUE_ITEM_INVALID":
                raise
            raise QueueError("QUEUE_ITEM_INVALID") from exc


@dataclass(frozen=True)
class QueueHealth:
    ready: int
    in_progress: int
    deferred: int
    retryable: int
    needs_attention: int
    terminal: int
    corrupt: int
    emergency_items: int
    emergency_bytes: int
    organizer_status: str = "SELECTION_REQUIRED"
    organizer_provider_id: str | None = None
    organizer_host_id: str | None = None
    organizer_reason_code: str | None = "ORGANIZER_SELECTION_REQUIRED"

    def to_dict(self) -> dict[str, Any]:
        organizer = {
            "status": self.organizer_status,
            "provider_id": self.organizer_provider_id,
            "host_id": self.organizer_host_id,
            "reason_code": self.organizer_reason_code,
        }
        return {
            "ready": self.ready,
            "in_progress": self.in_progress,
            "deferred": self.deferred,
            "retryable": self.retryable,
            "needs_attention": self.needs_attention,
            # Keep the old field visible for status consumers during the
            # read-compatibility window; it is never used for new writes.
            "deferred_quota": self.deferred,
            "terminal": self.terminal,
            "corrupt": self.corrupt,
            "emergency_items": self.emergency_items,
            "emergency_bytes": self.emergency_bytes,
            "organizer": organizer,
            "organizer_status": self.organizer_status,
        }

    @property
    def deferred_quota(self) -> int:
        return self.deferred


def _aware(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise QueueError("QUEUE_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return _aware(moment).isoformat().replace("+00:00", "Z")


def _root(settings: Any) -> Path:
    path = Path(settings.paths.queue_dir).expanduser().resolve()
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if path == repo or path.is_relative_to(repo):
        raise QueueError("QUEUE_REPOSITORY_PATH_FORBIDDEN")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        if os.name != "nt":
            raise QueueError("QUEUE_PERMISSION_CHECK_FAILED") from exc
    return path


def _emergency_root(settings: Any) -> Path:
    path = Path(settings.paths.emergency_spool_dir).expanduser().resolve()
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if path == repo or path.is_relative_to(repo):
        raise QueueError("EMERGENCY_SPOOL_REPOSITORY_PATH_FORBIDDEN")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        if os.name != "nt":
            raise QueueError("EMERGENCY_SPOOL_PERMISSION_FAILED") from exc
    return path


def _safe_queue_path(root: Path, queue_id: str, budget=None) -> Path:
    if not isinstance(queue_id, str) or not queue_id.startswith("queue_") or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-." for char in queue_id):
        raise QueueError("QUEUE_ID_INVALID")
    try:
        return lookup(root, queue_id, budget=budget)
    except ValueError as exc:
        raise QueueError("QUEUE_PATH_TRAVERSAL") from exc


def _tag(key, host):
    return hashlib.sha256(json.dumps([key, host]).encode("utf-8")).hexdigest()


def _update_metadata(root, path, budget):
    item = _read_item(path, budget=budget)
    if path.stem != item.queue_id or item.queue_id != _new_queue_id(item.event_id, item.idempotency_key, item.source_host_id):
        raise QueueError("QUEUE_IDEMPOTENCY_COLLISION")
    return dict(purpose="queue", tag=_tag(item.idempotency_key, item.source_host_id), retry_tag="",
                created_at=item.created_at, expires_at=item.payload_ref.expires_at if item.payload_ref else "")


def _catalog(root, budget=None, *, replay_id=None):
    catalog = RuntimeCatalog(root, prefix="queue_", clean_temporary=lambda path: _cleanup_temporary(root, path, budget))
    def inspect(path):
        item = _read_item(path, budget=budget)
        return "queue", _tag(item.idempotency_key, item.source_host_id)
    page = catalog.migrate_page(budget=budget, inspect_metadata=inspect,
                                inspect_update=lambda path: _update_metadata(root, path, budget))
    if not page.complete:
        reservation = catalog.reservation(replay_id, budget=budget) if replay_id else None
        if reservation is None or reservation["phase"] != "writing":
            raise QueueError("QUEUE_INVENTORY_PARTIAL")
    return catalog


def _store(root, item, budget=None):
    value = item.to_dict()
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    catalog = _catalog(root, budget, replay_id=item.queue_id)
    reservation = catalog.reservation(item.queue_id, budget=budget)
    expiry = item.payload_ref.expires_at if item.payload_ref else reservation["expires_at"] if reservation else ""
    return catalog.write(item.queue_id, encoded, purpose="queue", tag=_tag(item.idempotency_key, item.source_host_id),
        created_at=item.created_at, expires_at=expiry,
        budget=budget, writer=lambda path: _atomic_json(path, value, budget=budget))


def _atomic_json(path: Path, value: Mapping[str, Any], budget=None) -> None:
    if budget is not None:
        budget.check()
    temporary = path.with_name(path.name + f".{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    try:
        try:
            encoded = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            remaining = memoryview(encoded)
            while remaining:
                if budget is not None:
                    budget.check()
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise QueueError("QUEUE_WRITE_FAILED")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if budget is not None:
            budget.check()
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if os.name != "nt":
                raise QueueError("QUEUE_PERMISSION_CHECK_FAILED") from exc
    finally:
        if temporary.exists() or temporary.is_symlink():
            safe_unlink(path.parent, temporary, allow_missing=True)


def _lock_path(root: Path) -> Path:
    return root / ".queue.lock"


def _acquire(root: Path, budget=None) -> int:
    lock = _lock_path(root)
    started = time.monotonic()
    while True:
        if budget is not None:
            budget.check()
        try:
            return os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except PermissionError as exc:
            raise QueueError("QUEUE_LOCK_PERMISSION_DENIED") from exc
        except FileExistsError:
            if time.monotonic() - started >= 5:
                raise QueueError("QUEUE_LOCK_TIMEOUT")
            time.sleep(min(0.01, budget.remaining_ms() / 1000) if budget is not None else 0.01)
            try:
                if time.time() - lock.stat().st_mtime > 120:
                    lock.unlink()
            except PermissionError as exc:
                raise QueueError("QUEUE_LOCK_PERMISSION_DENIED") from exc
            except OSError:
                continue


def _release(root: Path, descriptor: int) -> None:
    os.close(descriptor)
    try:
        _lock_path(root).unlink()
    except FileNotFoundError:
        return


def _read_item(path: Path, budget=None) -> QueueItem:
    if budget is not None:
        budget.check()
    try:
        root = path.parents[2] if path.parent.parent.name == "managed" else path.parent
        value = json.loads(read_entry(root, path, budget=budget))
        return QueueItem.from_dict(value)
    except TimeoutError:
        raise
    except (OSError, UnicodeError, ValueError, QueueError) as exc:
        raise QueueError("QUEUE_ITEM_CORRUPT") from exc


def _event_fields(event: NormalizedHookEvent | Event) -> dict[str, Any]:
    if isinstance(event, NormalizedHookEvent):
        value = event.to_dict()
        source_host_id = event.source_host_id
        source_host_family = event.source_host_family
        if not isinstance(source_host_id, str) or not isinstance(source_host_family, str) or not source_host_id or not source_host_family:
            raise QueueError("QUEUE_SOURCE_HOST_PAIR_REQUIRED")
        return {
            "event_id": event.event_id,
            "idempotency_key": event.idempotency_key,
            "source_ref": event.source_ref,
            "source_hash": event.source_hash,
            "host_id": event.host_id,
            "session_id_hash": event.session_id_hash,
            "turn_id_hash": event.turn_id_hash,
            "privacy_classification": event.privacy_classification,
            "source_host_id": source_host_id,
            "source_host_family": source_host_family,
        }
    if isinstance(event, Event):
        key = event.idempotency_key or "sha256:" + hashlib.sha256(event.event_id.encode("utf-8")).hexdigest()
        source_hash = event.payload.get("source_hash") or "sha256:" + hashlib.sha256(event.event_id.encode("utf-8")).hexdigest()
        source_host_id = event.payload.get("source_host_id", "")
        source_host_family = event.payload.get("source_host_family", "")
        if not isinstance(source_host_id, str) or not isinstance(source_host_family, str) or not source_host_id or not source_host_family:
            raise QueueError("QUEUE_SOURCE_HOST_PAIR_REQUIRED")
        return {
            "event_id": event.event_id,
            "idempotency_key": key,
            "source_ref": event.payload.get("source_ref"),
            "source_hash": source_hash,
            "host_id": str(event.actor),
            "session_id_hash": event.payload.get("session_id_hash") or "sha256:" + hashlib.sha256(event.event_id.encode("utf-8")).hexdigest(),
            "turn_id_hash": event.payload.get("turn_id_hash") or "sha256:" + hashlib.sha256(event.event_id.encode("utf-8")).hexdigest(),
            "privacy_classification": event.payload.get("classification", "private-reusable"),
            "source_host_id": source_host_id,
            "source_host_family": source_host_family,
        }
    raise QueueError("QUEUE_EVENT_INVALID")


def _existing_by_idempotency(root: Path, key: str) -> QueueItem | None:
    for path in sorted(root.glob("queue_*.json")):
        try:
            item = _read_item(path)
        except QueueError:
            continue
        if item.idempotency_key == key:
            return item
    return None


def _existing_by_source_idempotency(root: Path, key: str, source_host_id: str, budget=None, replay_id=None) -> QueueItem | None:
    path = _catalog(root, budget, replay_id=replay_id).find_tag(_tag(key, source_host_id), budget=budget)
    if path is None or (path.stem == replay_id and not path.exists()):
        return None
    return _read_item(path, budget=budget)


def _new_queue_id(event_id: str, idempotency_key: str, source_host_id: str = "") -> str:
    return "queue_" + hashlib.sha256(f"{event_id}|{idempotency_key}|{source_host_id}".encode("utf-8")).hexdigest()[:32]


def _provider_preference(settings: Any, explicit: Sequence[str] | None) -> tuple[str, ...]:
    organizer = getattr(settings, "organizer", None)
    if organizer is not None:
        if getattr(organizer, "status", None) == "READY" and isinstance(getattr(organizer, "provider_id", None), str):
            return (organizer.provider_id,)
        # A queue receipt may be created while setup is awaiting explicit
        # organizer selection.  Keep the candidate durable; the maintainer
        # resolves the current manifest when it retries.
        return ()
    values = explicit if explicit is not None else getattr(settings, "provider_order", ())
    result = tuple(str(item) for item in values if isinstance(item, str) and item)
    return result[:1]


def _emergency_limits(settings: Any) -> tuple[int, int, int]:
    policy_path = Path(getattr(settings, "capture_policy_path", ""))
    defaults = (1000, 64 * 1024 * 1024, 86400)
    if not policy_path.exists():
        return defaults
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        emergency = policy.get("emergency_spool", {}) if isinstance(policy, Mapping) else {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QueueError("CAPTURE_POLICY_INVALID") from exc
    if not isinstance(emergency, Mapping):
        raise QueueError("CAPTURE_POLICY_INVALID")
    values = (emergency.get("max_items", defaults[0]), emergency.get("max_bytes", defaults[1]), emergency.get("ttl_seconds", defaults[2]))
    if any(type(item) is not int or item <= 0 for item in values):
        raise QueueError("CAPTURE_POLICY_INVALID")
    return values


def _read_emergency(root, path, budget):
    value = json.loads(read_entry(root, path, budget=budget))
    if (not isinstance(value, dict) or value.get("schema_version") != 1
            or value.get("emergency_id") != path.stem
            or _parse_optional_time(value.get("created_at")) is None
            or _parse_optional_time(value.get("expires_at")) is None):
        raise QueueError("EMERGENCY_ENVELOPE_INVALID")
    QueueItem.from_dict(value["queue_item"])
    return value


def _emergency_catalog(root, budget, replay_id=None):
    catalog = RuntimeCatalog(root, prefix="emergency_", clean_temporary=lambda path: _cleanup_temporary(root, path, budget))
    def inspect(path):
        _read_emergency(root, path, budget)
        return "queue"  # same body-free queue metadata, separate root/accounting
    page = catalog.migrate_page(budget=budget, inspect_metadata=inspect)
    if not page.complete:
        reservation = catalog.reservation(replay_id, budget=budget) if replay_id else None
        if not reservation or reservation["phase"] != "writing":
            raise QueueError("EMERGENCY_INVENTORY_UNKNOWN")
    return catalog


def write_emergency_envelope(item: QueueItem, settings: Any, *, reason_code: str, now: datetime | None = None, budget=None) -> Path:
    budget = budget if budget is not None else OperationBudget(5000)
    budget.check()
    root = _emergency_root(settings)
    max_items, max_bytes, ttl = _emergency_limits(settings)
    emergency_id = "emergency_" + hashlib.sha256(f"{item.queue_id}|{item.idempotency_key}".encode("utf-8")).hexdigest()[:32]
    descriptor = _acquire(root, budget=budget)
    try:
        catalog = _emergency_catalog(root, budget, replay_id=emergency_id)
        reservation = catalog.reservation(emergency_id, budget=budget)
        path = lookup(root, emergency_id, budget=budget)
        if path.exists():
            existing = _read_emergency(root, path, budget)
            if existing["queue_item"] != item.to_dict():
                raise QueueError("QUEUE_IDEMPOTENCY_COLLISION")
            return path
        created = _parse_optional_time(reservation["created_at"]) if reservation else _aware(now)
        expires = _parse_optional_time(reservation["expires_at"]) if reservation else created + timedelta(seconds=ttl)
        envelope = {"schema_version": 1, "emergency_id": emergency_id, "queue_item": item.to_dict(),
                    "reason_code": reason_code, "created_at": _iso(created), "expires_at": _iso(expires)}
        encoded = (json.dumps(envelope, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if not reservation:
            count, current_bytes = catalog.capacity("queue", budget=budget)
            if count >= max_items or current_bytes + len(encoded) > max_bytes:
                _atomic_json(root / "health.json", {"status": "EMERGENCY_SPOOL_FULL", "items": count, "bytes": current_bytes}, budget=budget)
                raise QueueError("EMERGENCY_SPOOL_FULL")
        return catalog.write(emergency_id, encoded, purpose="queue", created_at=_iso(created), expires_at=_iso(expires),
                             budget=budget, writer=lambda target: _atomic_json(target, envelope, budget=budget))
    finally:
        _release(root, descriptor)


def enqueue_receipt(
    event: NormalizedHookEvent | Event,
    payload_ref: SpoolRef | None,
    settings: Any,
    *,
    provider_preference: Sequence[str] | None = None,
    stage: str = "inheritance-gate",
    now: datetime | None = None,
    capture_id: str | None = None,
    budget=None,
) -> QueueItem:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    if payload_ref is not None and not isinstance(payload_ref, SpoolRef):
        raise QueueError("QUEUE_PAYLOAD_REF_INVALID")
    fields = _event_fields(event)
    created = _aware(now)
    root = _root(settings)
    item = QueueItem(
        queue_id=_new_queue_id(
            fields["event_id"], fields["idempotency_key"], fields["source_host_id"]
        ),
        event_id=fields["event_id"],
        idempotency_key=fields["idempotency_key"],
        stage=stage,
        state=QueueState.READY,
        attempts=0,
        created_at=_iso(created),
        next_eligible_at=None,
        source_ref=fields["source_ref"] if isinstance(fields["source_ref"], str) else None,
        source_hash=str(fields["source_hash"]),
        host_id=str(fields["host_id"]),
        session_id_hash=str(fields["session_id_hash"]),
        turn_id_hash=str(fields["turn_id_hash"]),
        payload_ref=payload_ref,
        provider_preference=_provider_preference(settings, provider_preference),
        privacy_classification=str(fields["privacy_classification"]),
        source_host_id=str(fields["source_host_id"]),
        source_host_family=str(fields["source_host_family"]),
        capture_id=capture_id,
    )
    try:
        validate_schema("queue-item", item.to_dict())
    except Exception as exc:
        raise QueueError("QUEUE_ITEM_INVALID") from exc
    descriptor = _acquire(root, budget=budget)
    try:
        existing = _existing_by_source_idempotency(root, item.idempotency_key, item.source_host_id, budget=budget, replay_id=item.queue_id)
        if existing is not None:
            same_payload = (existing.payload_ref.to_dict() if existing.payload_ref else None) == (item.payload_ref.to_dict() if item.payload_ref else None)
            same_identity = existing.event_id == item.event_id and existing.source_hash == item.source_hash and existing.host_id == item.host_id and existing.capture_id == item.capture_id and same_payload
            if same_identity:
                return existing
            raise QueueError("QUEUE_IDEMPOTENCY_COLLISION")
        path = _safe_queue_path(root, item.queue_id, budget=budget)
        reservation = RuntimeCatalog(root, prefix="queue_").reservation(item.queue_id, budget=budget)
        if reservation and reservation["phase"] == "writing" and not path.exists():
            if not reservation["created_at"]:
                raise QueueError("QUEUE_RETRY_TIME_UNKNOWN")
            item = replace(item, created_at=reservation["created_at"])
        try:
            _store(root, item, budget=budget)
        except TimeoutError:
            raise
        except (OSError, QueueError) as exc:
            try:
                emergency_path = write_emergency_envelope(item, settings, reason_code="QUEUE_WRITE_FAILED", now=created, budget=budget)
            except QueueError as emergency_error:
                raise QueueError(str(emergency_error)) from exc
            return replace(item, state=QueueState.QUARANTINED, last_error_code=f"EMERGENCY:{emergency_path.name}")
        return item
    finally:
        _release(root, descriptor)


def list_queue_items(settings: Any, *, include_terminal: bool = True) -> tuple[QueueItem, ...]:
    root = _root(settings)
    result: list[QueueItem] = []
    for path in inventory_paths(root, prefix="queue_"):
        try:
            item = _read_item(path)
        except QueueError:
            continue
        if include_terminal or item.state not in _TERMINAL:
            result.append(item)
    return tuple(result)


def read_queue_item(queue_id: str, settings: Any, *, budget=None) -> QueueItem:
    if budget is not None:
        budget.check()
    path = _safe_queue_path(_root(settings), queue_id, budget=budget)
    if not path.exists():
        raise QueueError("QUEUE_ITEM_NOT_FOUND")
    return _read_item(path, budget=budget)


def _parse_optional_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise QueueError("QUEUE_TIME_INVALID") from exc
    if parsed.tzinfo is None:
        raise QueueError("QUEUE_TIME_INVALID")
    return parsed.astimezone(timezone.utc)


def claim_queue_item(worker_id: str, settings: Any, now: datetime | None = None, *, lease_seconds: int = 300, budget=None, max_records=64) -> QueueItem | None:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    if not isinstance(worker_id, str) or not worker_id or len(worker_id) > 120:
        raise QueueError("QUEUE_WORKER_INVALID")
    if type(lease_seconds) is not int or lease_seconds <= 0:
        raise QueueError("QUEUE_LEASE_INVALID")
    moment = _aware(now)
    root = _root(settings)
    paths = None
    cleanup_attempted = False
    while True:
        cleanup = None
        descriptor = _acquire(root, budget=budget)
        try:
            if paths is None:
                catalog = _catalog(root, budget)
                paths = iter(catalog.page("claim", limit=max_records, budget=budget, advance=False).paths)
            for path in paths:
                if budget is not None:
                    budget.check()
                try:
                    item = _read_item(path, budget=budget)
                except QueueError:
                    catalog.advance("claim", path.stem, budget=budget)
                    continue
                if not cleanup_attempted and item.state in {QueueState.NO_DISCARDED, QueueState.DONE} and (item.payload_ref or item.validated_result_ref):
                    eligible = _parse_optional_time(item.next_eligible_at)
                    if eligible is None or eligible <= moment:
                        cleanup = item
                        break
                if item.state in _TERMINAL:
                    catalog.advance("claim", path.stem, budget=budget)
                    continue
                if item.payload_ref is not None and item.payload_ref.purpose == "pending" and _parse_optional_time(item.payload_ref.expires_at) <= moment:
                    catalog.advance("claim", path.stem, budget=budget)
                    continue  # reconciliation records loss before deleting the body
                lease_expiry = _parse_optional_time(item.lease_expires_at)
                if item.state in {QueueState.IN_PROGRESS, QueueState.YES_CURATING}:
                    if lease_expiry is None or lease_expiry > moment:
                        catalog.advance("claim", path.stem, budget=budget)
                        continue
                    item = replace(item, state=QueueState.READY, lease_owner=None, lease_expires_at=None, last_error_code="STALE_LEASE_RECLAIMED")
                if item.state not in {QueueState.READY, QueueState.DEFERRED, QueueState.FAILED_RETRYABLE}:
                    catalog.advance("claim", path.stem, budget=budget)
                    continue
                eligible = _parse_optional_time(item.next_eligible_at)
                if eligible is not None and eligible > moment:
                    catalog.advance("claim", path.stem, budget=budget)
                    continue
                # A claim is the single durable attempt increment. Normalize
                # old provider preferences before exposing an AI work lease.
                claimed = replace(
                    item,
                    state=QueueState.IN_PROGRESS,
                    attempts=item.attempts + 1,
                    provider_preference=_provider_preference(settings, item.provider_preference),
                    lease_owner=worker_id,
                    lease_expires_at=_iso(moment + timedelta(seconds=lease_seconds)),
                    last_error_code=None,
                )
                _store(root, claimed, budget=budget)
                catalog.advance("claim", path.stem, budget=budget)
                return claimed
            if cleanup is None:
                return None
        finally:
            _release(root, descriptor)
        # Reuse this scan's iterator after at most one cleanup, outside the
        # queue lock and before leasing any AI work. A durable cooldown avoids
        # a failing first NO item monopolizing later calls' cleanup attempts.
        cleanup_attempted = True
        try:
            transition_queue_item(
                cleanup, cleanup.state, settings, now=moment,
                reason_code=cleanup.last_error_code,
                next_eligible_at=moment + timedelta(seconds=300),
                budget=budget,
            )
            descriptor = _acquire(root, budget=budget)
            try:
                catalog.advance("claim", cleanup.queue_id, budget=budget)
            finally:
                _release(root, descriptor)
        except TimeoutError:
            raise
        except (OSError, QueueError, SpoolError, ValueError):
            # The durable NO + refs remains the retry evidence; never give it
            # to the organizer or prevent unrelated READY work from claiming.
            continue


def transition_queue_item(
    item: QueueItem,
    state: QueueState | str,
    settings: Any,
    now: datetime | None = None,
    reason_code: str | None = None,
    *,
    next_eligible_at: datetime | None = None,
    budget=None,
) -> QueueItem:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    if not isinstance(item, QueueItem):
        raise QueueError("QUEUE_ITEM_INVALID")
    raw_target = str(state)
    if raw_target == "DEFERRED_QUOTA":
        target = QueueState.DEFERRED
    elif raw_target == "FAILED":
        target = QueueState.FAILED_RETRYABLE
    else:
        target = QueueState(str(state))
    moment = _aware(now)
    def expiry_of_quarantined(current: QueueItem) -> bool:
        return (
            current.state == QueueState.QUARANTINED and target == QueueState.FAILED_NEEDS_ATTENTION
            and reason_code == "PENDING_EXPIRED" and current.capture_id is not None
            and current.payload_ref is not None and current.payload_ref.purpose == "pending"
            and _parse_optional_time(current.payload_ref.expires_at) <= moment
        )
    if target != item.state and target not in _ALLOWED_TRANSITIONS[item.state] and not expiry_of_quarantined(item):
        raise QueueError("QUEUE_TRANSITION_INVALID")
    root = _root(settings)
    path = _safe_queue_path(root, item.queue_id, budget=budget)
    descriptor = _acquire(root, budget=budget)
    try:
        current = _read_item(path, budget=budget)
        if current.idempotency_key != item.idempotency_key:
            raise QueueError("QUEUE_IDEMPOTENCY_COLLISION")
        if target != current.state and target not in _ALLOWED_TRANSITIONS[current.state] and not expiry_of_quarantined(current):
            raise QueueError("QUEUE_TRANSITION_INVALID")
        terminal_with_refs = target in {QueueState.NO_DISCARDED, QueueState.DONE} and (current.payload_ref is not None or current.validated_result_ref is not None)
        cleanup_due = None
        if terminal_with_refs:
            cleanup_deadline = next_eligible_at or _parse_optional_time(current.next_eligible_at)
            cleanup_due = _iso(cleanup_deadline or moment + timedelta(seconds=300))
        updated = replace(
            current,
            state=target,
            provider_preference=_provider_preference(settings, current.provider_preference),
            next_eligible_at=cleanup_due if target in {QueueState.NO_DISCARDED, QueueState.DONE} else _iso(next_eligible_at) if next_eligible_at else current.next_eligible_at if target in {QueueState.DEFERRED, QueueState.FAILED_RETRYABLE, QueueState.READY} else None,
            lease_owner=current.lease_owner if target in {QueueState.IN_PROGRESS, QueueState.YES_CURATING} else None,
            lease_expires_at=current.lease_expires_at if target in {QueueState.IN_PROGRESS, QueueState.YES_CURATING} else None,
            last_error_code=reason_code if reason_code is not None else current.last_error_code if target == current.state and target in {QueueState.NO_DISCARDED, QueueState.DONE} else None,
        )
        _store(root, updated, budget=budget)
    finally:
        _release(root, descriptor)
    if target in {QueueState.NO_DISCARDED, QueueState.DONE}:
        cleanup_reason = "QUEUE_DONE" if target == QueueState.DONE else "NO_DISCARDED"
        for field in ("payload_ref", "validated_result_ref"):
            ref = getattr(updated, field)
            if ref is None:
                continue
            # Terminal state and immutable ownership are durable before the
            # body delete. A retry may safely repeat a delete whose result was
            # not checkpointed before interruption.
            delete_spool(ref, settings, reason_code=cleanup_reason, budget=budget)
            descriptor = _acquire(root, budget=budget)
            try:
                current = _read_item(path, budget=budget)
                if current.idempotency_key != updated.idempotency_key or current.state != target:
                    raise QueueError("QUEUE_TERMINAL_CLEANUP_BINDING_INVALID")
                saved_ref = getattr(current, field)
                if saved_ref == ref:
                    remaining = current.payload_ref if field != "payload_ref" else current.validated_result_ref
                    updated = replace(
                        current,
                        **{field: None},
                        next_eligible_at=_iso(moment + timedelta(seconds=300)) if remaining is not None else None,
                    )
                    _store(root, updated, budget=budget)
                elif saved_ref is None:
                    updated = current
                else:
                    raise QueueError("QUEUE_TERMINAL_CLEANUP_BINDING_INVALID")
            finally:
                _release(root, descriptor)
    return updated


def attach_validated_result(item: QueueItem, ref: SpoolRef, settings: Any, *, budget=None) -> QueueItem:
    budget = budget if budget is not None else OperationBudget(5000)
    budget.check()
    if ref.purpose != "validated-result":
        raise QueueError("QUEUE_RESULT_PURPOSE_INVALID")
    if item.payload_ref and _parse_optional_time(ref.expires_at) > _parse_optional_time(item.payload_ref.expires_at):
        raise QueueError("QUEUE_RESULT_EXPIRY_INVALID")
    root = _root(settings)
    descriptor = _acquire(root, budget=budget)
    try:
        current = _read_item(_safe_queue_path(root, item.queue_id, budget=budget), budget=budget)
        if current != item or current.state != QueueState.IN_PROGRESS:
            raise QueueError("QUEUE_RESULT_CLAIM_CHANGED")
        updated = replace(current, validated_result_ref=ref)
        _store(root, updated, budget=budget)
        return updated
    finally:
        _release(root, descriptor)


def recover_emergency_spool(settings: Any, *, now: datetime | None = None, budget=None, max_records=64) -> tuple[QueueItem, ...]:
    budget = budget if budget is not None else OperationBudget(5000)
    budget.check()
    moment = _aware(now)
    emergency = _emergency_root(settings)
    root = _root(settings)
    recovered: list[QueueItem] = []
    # Match enqueue's queue -> emergency lock order. No opposite-order path.
    descriptor = _acquire(root, budget=budget)
    try:
        emergency_lock = _acquire(emergency, budget=budget)
        try:
            catalog = _emergency_catalog(emergency, budget)
            paths = catalog.page("recovery", limit=max_records, budget=budget, advance=False).paths
            for path in paths:
                budget.check()
                envelope = _read_emergency(emergency, path, budget)
                item = QueueItem.from_dict(envelope["queue_item"])
                if _parse_optional_time(envelope["expires_at"]) > moment:
                    existing = _existing_by_source_idempotency(root, item.idempotency_key, item.source_host_id, budget=budget, replay_id=item.queue_id)
                    if existing is not None:
                        if (existing.event_id, existing.source_hash, existing.capture_id, existing.payload_ref) != (item.event_id, item.source_hash, item.capture_id, item.payload_ref):
                            raise QueueError("QUEUE_IDEMPOTENCY_COLLISION")
                    else:
                        existing = replace(item, provider_preference=_provider_preference(settings, item.provider_preference))
                        _store(root, existing, budget=budget)
                    # Queue durable outcome precedes verified deletion and cursor.
                    catalog.delete(path.stem, budget=budget)
                    recovered.append(existing)
                else:
                    catalog.delete(path.stem, budget=budget)
                catalog.advance("recovery", path.stem, budget=budget)
        except TimeoutError:
            raise
        except (OSError, ValueError, KeyError, QueueError):
            # Keep original bytes and any reservation charge for safe repair.
            _atomic_json(emergency / "health.json", {"status": "EMERGENCY_INVENTORY_UNKNOWN"}, budget=budget)
        finally:
            _release(emergency, emergency_lock)
        return tuple(recovered)
    finally:
        _release(root, descriptor)


def queue_health(settings: Any) -> QueueHealth:
    root = _root(settings)
    counts = {state: 0 for state in QueueState}
    corrupt = 0
    for path in inventory_paths(root, prefix="queue_"):
        try:
            item = _read_item(path)
            counts[item.state] += 1
        except QueueError:
            corrupt += 1
    emergency = _emergency_root(settings)
    emergency_files = tuple(inventory_paths(emergency, prefix="emergency_"))
    configured = getattr(settings, "organizer", None)
    if hasattr(configured, "to_dict"):
        organizer = configured.to_dict()
    elif isinstance(configured, Mapping):
        organizer = dict(configured)
    else:
        organizer = {
            "status": "SELECTION_REQUIRED",
            "provider_id": None,
            "host_id": None,
            "reason_code": "ORGANIZER_SELECTION_REQUIRED",
        }
    return QueueHealth(
        ready=counts[QueueState.READY],
        in_progress=counts[QueueState.IN_PROGRESS],
        deferred=counts[QueueState.DEFERRED],
        retryable=counts[QueueState.FAILED_RETRYABLE],
        needs_attention=counts[QueueState.FAILED_NEEDS_ATTENTION],
        terminal=sum(counts[state] for state in _TERMINAL),
        corrupt=corrupt,
        emergency_items=len(emergency_files),
        emergency_bytes=sum(path.stat().st_size for path in emergency_files),
        organizer_status=str(organizer.get("status", "SELECTION_REQUIRED")),
        organizer_provider_id=organizer.get("provider_id") if isinstance(organizer.get("provider_id"), str) else None,
        organizer_host_id=organizer.get("host_id") if isinstance(organizer.get("host_id"), str) else None,
        organizer_reason_code=organizer.get("reason_code") if isinstance(organizer.get("reason_code"), str) else None,
    )


__all__ = [
    "QueueError",
    "QueueHealth",
    "QueueItem",
    "QueueState",
    "claim_queue_item",
    "enqueue_receipt",
    "list_queue_items",
    "queue_health",
    "read_queue_item",
    "recover_emergency_spool",
    "transition_queue_item",
    "write_emergency_envelope",
]
