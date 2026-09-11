from __future__ import annotations

import hashlib
import json
import platform
import socket
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Mapping


_EVENT_COUNTERS: dict[tuple[str, str], int] = defaultdict(int)
_EVENT_COUNTER_LOCK = Lock()


def machine_id() -> str:
    source = f"{socket.gethostname()}|{platform.node()}".encode("utf-8", "replace")
    return hashlib.sha256(source).hexdigest()[:12]


def canonical_json(value: Mapping[str, Any] | Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hashable_bytes(value: object) -> bytes:
    if isinstance(value, (dict, list, tuple, int, float, bool)) or value is None:
        return canonical_json(value)
    return str(value).encode("utf-8", "replace")


def fingerprint(value: object) -> str:
    """Return a collision-resistant persisted identifier digest.

    Earlier builds truncated this value to twelve hex characters.  Persisted
    audit records now use the complete SHA-256 digest; legacy experiment
    fixtures remain readable through their versioned validators.
    """

    return "sha256:" + _hash_bytes(_hashable_bytes(value))


def stable_hash(value: object) -> str:
    return _hash_bytes(_hashable_bytes(value))


def _normalize_time(now: datetime | None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("EVENT_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc)


def new_event_id(now: datetime | None = None, machine_id: str | None = None) -> str:
    moment = _normalize_time(now)
    machine = machine_id or globals()["machine_id"]()
    timestamp = moment.strftime("%Y%m%dT%H%M%S%fZ")
    key = (timestamp, machine)
    with _EVENT_COUNTER_LOCK:
        sequence = _EVENT_COUNTERS[key]
        _EVENT_COUNTERS[key] += 1
    machine_prefix = hashlib.sha256(machine.encode("utf-8", "replace")).hexdigest()[:8]
    return f"evt_{timestamp}_{machine_prefix}{sequence:04x}"
