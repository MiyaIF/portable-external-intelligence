from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Literal


CaptureState = Literal["WAITING", "SECURED", "EVALUATED_NONE", "UNAVAILABLE", "UNKNOWN"]

_HOST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}")
_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class CaptureIdentity:
    host_id: str
    instance_hash: str
    store_id: str
    session_hash: str | None
    turn_hash: str | None
    record_hash: str | None


@dataclass(frozen=True)
class CloseoutProofRef:
    record_id: str
    target_set_hash: str
    content_hash: str
    binding_digest: str
    result_digest: str


@dataclass(frozen=True)
class CaptureReceipt:
    capture_id: str
    state: CaptureState
    candidate_ids: tuple[str, ...]
    covered_target_ids: tuple[str, ...]
    reason_code: str
    updated_at: datetime
    candidate_hashes: tuple[tuple[str, str], ...] = ()
    closeout_proofs: tuple[CloseoutProofRef, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.updated_at, datetime) or self.updated_at.tzinfo is None or self.updated_at.utcoffset() != timedelta(0):
            raise ValueError("CAPTURE_TIME_INVALID")


@dataclass(frozen=True)
class PendingPolicy:
    ttl_seconds: int = 2_592_000
    max_items: int = 1_000
    max_bytes: int = 67_108_864


def capture_key(identity: CaptureIdentity) -> str | None:
    fields = asdict(identity)
    if not isinstance(identity.host_id, str) or not _HOST_ID_RE.fullmatch(identity.host_id):
        raise ValueError("CAPTURE_HOST_INVALID")
    for name, value in fields.items():
        if name == "host_id":
            continue
        if value is None and name in {"session_hash", "turn_hash", "record_hash"}:
            continue
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise ValueError("CAPTURE_ID_INVALID")
    if identity.record_hash is None:
        return None
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pending_policy(mapping: dict) -> PendingPolicy:
    if not isinstance(mapping, dict):
        raise ValueError("PENDING_POLICY_INVALID")
    defaults = PendingPolicy()
    selected = mapping.get("pending", {})
    if not isinstance(selected, dict):
        raise ValueError("PENDING_POLICY_INVALID")
    result: dict[str, int] = {}
    for name in ("ttl_seconds", "max_items", "max_bytes"):
        value = selected.get(name, mapping.get(name, getattr(defaults, name)))
        if type(value) is not int or value <= 0:
            raise ValueError("PENDING_POLICY_INVALID")
        result[name] = value
    return PendingPolicy(**result)


__all__ = [
    "CaptureIdentity",
    "CaptureReceipt",
    "CaptureState",
    "CloseoutProofRef",
    "PendingPolicy",
    "capture_key",
    "pending_policy",
]
