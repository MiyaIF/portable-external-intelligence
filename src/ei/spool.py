from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .crypto import CryptoError, decrypt_payload, encrypt_payload
from .key_provider import KeyProvider, KeyProviderError, default_key_provider
from .privacy import inspect_text


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ALLOWED_CLASSIFICATIONS = frozenset({"public", "private-reusable", "client-confidential"})
_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_SPOOL_ITEMS = 10_000
_MAX_SPOOL_BYTES = 512 * 1024 * 1024
_CAPACITY_FILE = ".spool-capacity.json"
_LOCK_FILE = ".spool.lock"
_LOCK_TIMEOUT_SECONDS = 5


class SpoolError(RuntimeError):
    """Raised when encrypted temporary storage cannot safely complete."""


@dataclass(frozen=True)
class SpoolRef:
    spool_id: str
    content_hash: str
    classification: str
    created_at: str
    expires_at: str
    key_id: str | None
    encrypted: bool = True

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.spool_id):
            raise ValueError("SPOOL_ID_INVALID")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.content_hash):
            raise ValueError("SPOOL_HASH_INVALID")
        if self.classification not in _ALLOWED_CLASSIFICATIONS:
            raise ValueError("SPOOL_CLASSIFICATION_INVALID")
        for name in ("created_at", "expires_at"):
            value = getattr(self, name)
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (AttributeError, ValueError) as exc:
                raise ValueError(f"SPOOL_TIME_INVALID:{name}") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError(f"SPOOL_TIME_INVALID:{name}")
        if not isinstance(self.encrypted, bool) or not self.encrypted:
            raise ValueError("SPOOL_MUST_BE_ENCRYPTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "spool_id": self.spool_id,
            "content_hash": self.content_hash,
            "classification": self.classification,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SpoolRef":
        if not isinstance(value, Mapping):
            raise ValueError("SPOOL_REF_OBJECT_REQUIRED")
        return cls(
            spool_id=str(value.get("spool_id", "")),
            content_hash=str(value.get("content_hash", "")),
            classification=str(value.get("classification", "")),
            created_at=str(value.get("created_at", "")),
            expires_at=str(value.get("expires_at", "")),
            key_id=value.get("key_id") if value.get("key_id") is None else str(value.get("key_id")),
            encrypted=value.get("encrypted") is True,
        )


@dataclass(frozen=True)
class SpoolHealth:
    items: int
    bytes: int
    expired: int
    quarantined: int
    emergency_items: int = 0
    emergency_bytes: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "items": self.items,
            "bytes": self.bytes,
            "expired": self.expired,
            "quarantined": self.quarantined,
            "emergency_items": self.emergency_items,
            "emergency_bytes": self.emergency_bytes,
        }


def _now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise SpoolError("SPOOL_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc)


def _root(settings: Any) -> Path:
    path = Path(settings.paths.spool_dir).expanduser().resolve()
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if path == repo or path.is_relative_to(repo):
        raise SpoolError("SPOOL_REPOSITORY_PATH_FORBIDDEN")
    return path


def _emergency_root(settings: Any) -> Path:
    path = Path(settings.paths.emergency_spool_dir).expanduser().resolve()
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if path == repo or path.is_relative_to(repo):
        raise SpoolError("EMERGENCY_SPOOL_REPOSITORY_PATH_FORBIDDEN")
    return path


def _safe_path(root: Path, spool_id: str) -> Path:
    if not isinstance(spool_id, str) or not _SAFE_ID.fullmatch(spool_id):
        raise SpoolError("SPOOL_ID_INVALID")
    path = (root / f"{spool_id}.json").resolve()
    if not path.is_relative_to(root):
        raise SpoolError("SPOOL_PATH_TRAVERSAL")
    return path


def _permissions(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError as exc:
        if os.name != "nt":
            raise SpoolError("SPOOL_PERMISSION_CHECK_FAILED") from exc


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        encoded = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if os.name != "nt":
                raise SpoolError("SPOOL_PERMISSION_CHECK_FAILED") from exc
    finally:
        if temporary.exists():
            temporary.unlink()



def _spool_files(root: Path) -> list[Path]:
    return [path for path in root.glob("*.json") if path.is_file() and path.name != _CAPACITY_FILE]


def _lock_path(root: Path) -> Path:
    return root / _LOCK_FILE


def _acquire(root: Path) -> int:
    lock = _lock_path(root)
    started = time.monotonic()
    while True:
        try:
            return os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except (FileExistsError, PermissionError):
            if not lock.exists():
                continue
            try:
                if time.time() - lock.stat().st_mtime > 120:
                    lock.unlink()
                    continue
            except OSError:
                continue
            if time.monotonic() - started >= _LOCK_TIMEOUT_SECONDS:
                raise SpoolError("SPOOL_LOCK_TIMEOUT")
            time.sleep(0.01)


def _release(root: Path, descriptor: int) -> None:
    os.close(descriptor)
    try:
        _lock_path(root).unlink()
    except FileNotFoundError:
        return


def _capacity_path(root: Path) -> Path:
    return root / _CAPACITY_FILE


def _capacity_size(value: Mapping[str, Any]) -> tuple[int, int] | None:
    if value.get("schema_version") != 1 or type(value.get("items")) is not int or type(value.get("bytes")) is not int:
        return None
    if value["items"] < 0 or value["bytes"] < 0:
        return None
    pending = value.get("pending")
    if pending is not None and not isinstance(pending, Mapping):
        return None
    return value["items"], value["bytes"]


def _scan_capacity(root: Path) -> tuple[int, int]:
    files = _spool_files(root)
    return len(files), sum(path.stat().st_size for path in files)


def _write_capacity(root: Path, items: int, size: int, pending: Mapping[str, Any] | None = None) -> None:
    _atomic_json(
        _capacity_path(root),
        {"schema_version": 1, "items": items, "bytes": size, "pending": dict(pending) if pending is not None else None},
    )


def _capacity_state(root: Path) -> tuple[int, int]:
    path = _capacity_path(root)
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        value = None
    if isinstance(value, Mapping) and _capacity_size(value) is not None and value.get("pending") is None:
        return value["items"], value["bytes"]
    items, size = _scan_capacity(root)
    _write_capacity(root, items, size)
    return items, size


def _invalidate_capacity(root: Path) -> None:
    try:
        _capacity_path(root).unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def _json_size(value: Mapping[str, Any]) -> int:
    return len((json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
def _audit(settings: Any, action: str, spool_id: str, reason_code: str) -> None:
    path = Path(settings.paths.runtime_dir) / "spool-audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "action": action,
        "spool_id_hash": "sha256:" + hashlib.sha256(spool_id.encode("utf-8")).hexdigest(),
        "reason_code": reason_code,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def _quarantine(settings: Any, spool_id: str, reason_code: str, source: Path | None = None) -> Path:
    root = _root(settings) / "quarantine"
    _permissions(root)
    path = _safe_path(root, spool_id)
    if source is not None and source.exists():
        try:
            os.replace(source, path)
        except OSError:
            _atomic_json(path, {"spool_id_hash": "sha256:" + hashlib.sha256(spool_id.encode("utf-8")).hexdigest(), "reason_code": reason_code})
    else:
        _atomic_json(path, {"spool_id_hash": "sha256:" + hashlib.sha256(spool_id.encode("utf-8")).hexdigest(), "reason_code": reason_code})
    _invalidate_capacity(_root(settings))
    _audit(settings, "quarantine", spool_id, reason_code)
    return path


def _policy(settings: Any) -> Mapping[str, Any]:
    path = Path(getattr(settings, "capture_policy_path", ""))
    if not path.exists():
        return {"ttl_seconds": _DEFAULT_TTL_SECONDS, "max_items": _MAX_SPOOL_ITEMS, "max_bytes": _MAX_SPOOL_BYTES}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SpoolError("CAPTURE_POLICY_INVALID") from exc
    if not isinstance(value, Mapping):
        raise SpoolError("CAPTURE_POLICY_INVALID")
    return value


def _limits(settings: Any) -> tuple[int, int, int]:
    policy = _policy(settings)
    ttl = policy.get("ttl_seconds", _DEFAULT_TTL_SECONDS)
    max_items = policy.get("max_items", _MAX_SPOOL_ITEMS)
    max_bytes = policy.get("max_bytes", _MAX_SPOOL_BYTES)
    if any(type(item) is not int or item <= 0 for item in (ttl, max_items, max_bytes)):
        raise SpoolError("CAPTURE_POLICY_INVALID")
    return ttl, max_items, max_bytes


def _payload_bytes(payload: bytes | bytearray | str | Mapping[str, Any]) -> bytes:
    if isinstance(payload, bytes):
        result = payload
    elif isinstance(payload, bytearray):
        result = bytes(payload)
    elif isinstance(payload, str):
        result = payload.encode("utf-8")
    elif isinstance(payload, Mapping):
        result = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        raise SpoolError("SPOOL_CONTENT_TYPE_INVALID")
    if not result or len(result) > _MAX_PAYLOAD_BYTES:
        raise SpoolError("SPOOL_CONTENT_SIZE_INVALID")
    return result


def _provider(settings: Any, key_provider: KeyProvider | None) -> KeyProvider:
    return key_provider or default_key_provider(Path(settings.paths.runtime_root))


def write_spool(
    payload: bytes | bytearray | str | Mapping[str, Any],
    classification: str,
    settings: Any,
    *,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
    spool_id: str | None = None,
    key_provider: KeyProvider | None = None,
) -> SpoolRef:
    content = _payload_bytes(payload)
    if classification not in _ALLOWED_CLASSIFICATIONS:
        raise SpoolError("SPOOL_CLASSIFICATION_REJECTED")
    source_kind = classification
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpoolError("SPOOL_UTF8_REQUIRED") from exc
    decision = inspect_text(text, source_kind, "spool-payload")
    if decision.reason_code not in {"CLASSIFIED", "CLIENT_CONFIDENTIAL_LOCAL_ONLY"}:
        raise SpoolError("SPOOL_PRIVACY_REJECTED")
    moment = _now(now)
    configured_ttl, max_items, max_bytes = _limits(settings)
    ttl = configured_ttl if ttl_seconds is None else ttl_seconds
    if type(ttl) is not int or ttl <= 0:
        raise SpoolError("SPOOL_TTL_INVALID")
    root = _root(settings)
    _permissions(root)
    selected_id = spool_id or "spool_" + secrets.token_hex(16)
    if not _SAFE_ID.fullmatch(selected_id):
        raise SpoolError("SPOOL_ID_INVALID")
    path = _safe_path(root, selected_id)
    descriptor = _acquire(root)
    try:
        if path.exists():
            try:
                existing = _read_envelope(path)
            except SpoolError as exc:
                _quarantine(settings, selected_id, "SPOOL_EXISTING_INVALID", path)
                raise SpoolError("SPOOL_EXISTING_INVALID") from exc
            if existing.get("content_sha256") == "sha256:" + hashlib.sha256(content).hexdigest() and existing.get("classification") == classification:
                return SpoolRef(selected_id, str(existing["content_sha256"]), classification, str(existing["created_at"]), str(existing["expires_at"]), existing.get("key_id"))
            raise SpoolError("SPOOL_ID_COLLISION")
        expires = moment + timedelta(seconds=ttl)
        try:
            envelope = encrypt_payload(content, selected_id, classification, expires, _provider(settings, key_provider), created_at=moment)
        except (KeyProviderError, CryptoError, OSError) as exc:
            _quarantine(settings, selected_id, "SPOOL_KEY_UNAVAILABLE")
            raise SpoolError("SPOOL_KEY_UNAVAILABLE") from exc
        envelope_size = _json_size(envelope)
        current_items, current_bytes = _capacity_state(root)
        if current_items >= max_items or current_bytes + envelope_size > max_bytes:
            raise SpoolError("SPOOL_FULL")
        _write_capacity(root, current_items, current_bytes, {"operation": "add", "spool_id": selected_id, "bytes": envelope_size})
        _atomic_json(path, envelope)
        _write_capacity(root, current_items + 1, current_bytes + envelope_size)
        _audit(settings, "write", selected_id, "SPOOL_WRITTEN")
        return SpoolRef(selected_id, envelope["content_sha256"], classification, envelope["created_at"], envelope["expires_at"], envelope["key_id"])
    finally:
        _release(root, descriptor)

def _read_envelope(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SpoolError("SPOOL_ENVELOPE_INVALID") from exc
    if not isinstance(value, Mapping):
        raise SpoolError("SPOOL_ENVELOPE_INVALID")
    return value


def read_spool(
    ref: SpoolRef | Mapping[str, Any] | str,
    settings: Any,
    *,
    now: datetime | None = None,
    key_provider: KeyProvider | None = None,
) -> bytes:
    if isinstance(ref, str):
        spool_id = ref
        reference = None
    elif isinstance(ref, SpoolRef):
        spool_id = ref.spool_id
        reference = ref
    else:
        reference = SpoolRef.from_dict(ref)
        spool_id = reference.spool_id
    root = _root(settings)
    path = _safe_path(root, spool_id)
    if not path.exists():
        raise SpoolError("SPOOL_NOT_FOUND")
    try:
        envelope = _read_envelope(path)
        if reference is not None:
            for field in ("content_sha256", "classification", "expires_at"):
                expected = reference.content_hash if field == "content_sha256" else getattr(reference, field.replace("content_sha256", "content_hash"), None)
                if field == "content_sha256":
                    expected = reference.content_hash
                elif field == "classification":
                    expected = reference.classification
                elif field == "expires_at":
                    expected = reference.expires_at
                if envelope.get(field) != expected:
                    raise SpoolError("SPOOL_REF_MISMATCH")
        payload = decrypt_payload(envelope, _provider(settings, key_provider), now=_now(now), expected_classification=reference.classification if reference else None)
        return payload
    except CryptoError as exc:
        reason = str(exc)
        if reason == "SPOOL_EXPIRED":
            delete_spool(spool_id, settings, reason_code=reason)
        else:
            _quarantine(settings, spool_id, reason, path)
        raise SpoolError(reason) from exc
    except (SpoolError, KeyProviderError, OSError) as exc:
        if isinstance(exc, SpoolError) and str(exc) == "SPOOL_NOT_FOUND":
            raise
        _quarantine(settings, spool_id, str(exc) or "SPOOL_READ_FAILED", path)
        raise SpoolError(str(exc) or "SPOOL_READ_FAILED") from exc


def delete_spool(spool: SpoolRef | str, settings: Any, *, reason_code: str = "SPOOL_DELETED") -> bool:
    spool_id = spool.spool_id if isinstance(spool, SpoolRef) else str(spool)
    root = _root(settings)
    _permissions(root)
    path = _safe_path(root, spool_id)
    descriptor = _acquire(root)
    try:
        if not path.exists():
            _audit(settings, "delete", spool_id, "SPOOL_ALREADY_DELETED")
            return False
        size = path.stat().st_size
        current_items, current_bytes = _capacity_state(root)
        _write_capacity(root, current_items, current_bytes, {"operation": "remove", "spool_id": spool_id, "bytes": size})
        try:
            path.unlink()
        except FileNotFoundError:
            _invalidate_capacity(root)
            _audit(settings, "delete", spool_id, "SPOOL_ALREADY_DELETED")
            return False
        _write_capacity(root, max(0, current_items - 1), max(0, current_bytes - size))
        _audit(settings, "delete", spool_id, reason_code)
        return True
    except OSError as exc:
        raise SpoolError("SPOOL_DELETE_FAILED") from exc
    finally:
        _release(root, descriptor)

def gc_expired_spool(settings: Any, *, now: datetime | None = None) -> int:
    moment = _now(now)
    root = _root(settings)
    if not root.exists():
        return 0
    removed = 0
    invalid: list[Path] = []
    descriptor = _acquire(root)
    try:
        current_items, current_bytes = _capacity_state(root)
        for path in sorted(_spool_files(root)):
            try:
                envelope = _read_envelope(path)
                expiry = datetime.fromisoformat(str(envelope["expires_at"]).replace("Z", "+00:00"))
                if expiry <= moment:
                    size = path.stat().st_size
                    _write_capacity(root, current_items, current_bytes, {"operation": "remove", "spool_id": path.stem, "bytes": size})
                    path.unlink()
                    current_items = max(0, current_items - 1)
                    current_bytes = max(0, current_bytes - size)
                    removed += 1
                    _audit(settings, "delete", path.stem, "SPOOL_EXPIRED")
            except (SpoolError, OSError, KeyError, ValueError, TypeError):
                invalid.append(path)
        _write_capacity(root, current_items, current_bytes)
    finally:
        _release(root, descriptor)
    for path in invalid:
        if path.exists():
            _quarantine(settings, path.stem, "SPOOL_GC_INVALID", path)
    return removed

def spool_health(settings: Any) -> SpoolHealth:
    root = _root(settings)
    quarantine = root / "quarantine"
    items = _spool_files(root)
    emergency = _emergency_root(settings)
    emergency_items = [item for item in emergency.glob("emergency_*.json") if item.is_file()] if emergency.exists() else []
    return SpoolHealth(
        items=len(items),
        bytes=sum(item.stat().st_size for item in items),
        expired=0,
        quarantined=len([item for item in quarantine.glob("*.json") if item.is_file()]) if quarantine.exists() else 0,
        emergency_items=len(emergency_items),
        emergency_bytes=sum(item.stat().st_size for item in emergency_items),
    )


__all__ = [
    "SpoolError",
    "SpoolHealth",
    "SpoolRef",
    "delete_spool",
    "gc_expired_spool",
    "read_spool",
    "spool_health",
    "write_spool",
]
