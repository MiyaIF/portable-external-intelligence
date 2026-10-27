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
from .capture_contract import PendingPolicy, pending_policy
from .journal import validate_schema
from .safe_fs import assert_safe_target, safe_unlink
from .runtime_catalog import RuntimeCatalog, CatalogUnknown, lookup, inventory_paths, read_entry
from .operation_runtime import OperationBudget


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ALLOWED_CLASSIFICATIONS = frozenset({"public", "private-reusable", "client-confidential"})
_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_SPOOL_ITEMS = 10_000
_MAX_SPOOL_BYTES = 512 * 1024 * 1024
_LOCK_FILE = ".spool.lock"
_LOCK_TIMEOUT_SECONDS = 5
_MANAGED_TEMP = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|\.spool-capacity)\.json\.(?P<pid>[1-9][0-9]{0,9})\.[0-9a-f]{8}\.tmp$")


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
    purpose: str = "legacy"

    def __post_init__(self) -> None:
        if self.purpose not in {"legacy", "pending", "validated-result"}:
            raise ValueError("SPOOL_PURPOSE_INVALID")
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
            "purpose": self.purpose,
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
            purpose=value.get("purpose", "legacy"),
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


def _safe_path(root: Path, spool_id: str, budget=None) -> Path:
    if not isinstance(spool_id, str) or not _SAFE_ID.fullmatch(spool_id):
        raise SpoolError("SPOOL_ID_INVALID")
    try:
        return lookup(root, spool_id, budget=budget)
    except ValueError as exc:
        raise SpoolError("SPOOL_PATH_TRAVERSAL") from exc


def _permissions(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError as exc:
        if os.name != "nt":
            raise SpoolError("SPOOL_PERMISSION_CHECK_FAILED") from exc


def _atomic_json(path: Path, value: Mapping[str, Any], budget=None) -> None:
    if budget is not None:
        budget.check()
    path.parent.mkdir(parents=True, exist_ok=True)
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
                    raise SpoolError("SPOOL_WRITE_FAILED")
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
                raise SpoolError("SPOOL_PERMISSION_CHECK_FAILED") from exc
    finally:
        if temporary.exists() or temporary.is_symlink():
            safe_unlink(path.parent, temporary, allow_missing=True)


def _pid_state(pid: int) -> bool | None:
    """True=live, False=confirmed gone, None=unknown; never signal on Windows."""
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        return None
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return None
        return True
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
        if not handle:
            return False if ctypes.get_last_error() == 87 else None
        try:
            status = kernel.WaitForSingleObject(handle, 0)
        finally:
            closed = kernel.CloseHandle(handle)
        if not closed:
            return None
        return False if status == 0 else True if status == 0x102 else None
    except (OSError, AttributeError, ValueError):
        return None


def _cleanup_temporary(root: Path, path: Path, budget=None) -> bool:
    """One entry visited by bounded migration/shard validation under its lock."""
    if budget is not None:
        budget.check()
    match = _MANAGED_TEMP.fullmatch(path.name)
    if match is None:
        return False
    try:
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if _pid_state(int(match["pid"])) is not False:
            raise SpoolError("SPOOL_TEMP_CLEANUP_UNCONFIRMED")
        if budget is not None:
            budget.check()
        return safe_unlink(root, path, allow_missing=True)
    except TimeoutError:
        raise
    except (OSError, ValueError) as exc:
        raise SpoolError("SPOOL_TEMP_CLEANUP_UNCONFIRMED") from exc



def _spool_files(root: Path, budget=None) -> list[Path]:
    return list(inventory_paths(root, budget=budget))


def _lock_path(root: Path) -> Path:
    return root / _LOCK_FILE


def _acquire(root: Path, budget=None) -> int:
    lock = _lock_path(root)
    started = time.monotonic()
    while True:
        if budget is not None:
            budget.check()
        try:
            return os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except PermissionError as exc:
            raise SpoolError("SPOOL_LOCK_PERMISSION_DENIED") from exc
        except FileExistsError:
            if time.monotonic() - started >= _LOCK_TIMEOUT_SECONDS:
                raise SpoolError("SPOOL_LOCK_TIMEOUT")
            time.sleep(min(0.01, budget.remaining_ms() / 1000) if budget is not None else 0.01)
            try:
                if time.time() - lock.stat().st_mtime > 120:
                    lock.unlink()
            except PermissionError as exc:
                raise SpoolError("SPOOL_LOCK_PERMISSION_DENIED") from exc
            except OSError:
                continue


def _release(root: Path, descriptor: int) -> None:
    os.close(descriptor)
    try:
        _lock_path(root).unlink()
    except FileNotFoundError:
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


def _quarantine(settings: Any, spool_id: str, reason_code: str, source: Path | None = None, budget=None, *, locked=False) -> Path:
    """Record a sanitized diagnostic; unsafe payloads and their charge stay put."""
    if budget is not None:
        budget.check()
    payload_root = _root(settings)
    descriptor = None if locked else _acquire(payload_root, budget=budget)
    try:
        if source is not None:
            try:
                RuntimeCatalog(payload_root).mark_unknown(budget=budget)
            except CatalogUnknown:
                # Missing/corrupt accounting already denies admission. Keep
                # the payload and a diagnostic without trying to rebuild it.
                reason_code = "SPOOL_CATALOG_UNAVAILABLE"
        root = payload_root / "quarantine"
        _permissions(root)
        path = _safe_path(root, spool_id, budget)
        _atomic_json(path, {"spool_id_hash": "sha256:" + hashlib.sha256(spool_id.encode("utf-8")).hexdigest(), "reason_code": reason_code}, budget=budget)
        _audit(settings, "quarantine", spool_id, reason_code)
        return path
    finally:
        if descriptor is not None:
            _release(payload_root, descriptor)


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


def _catalog(root, budget):
    return RuntimeCatalog(root, clean_temporary=lambda path: _cleanup_temporary(root, path, budget))


def _inventory(catalog, settings, key_provider, budget):
    def authenticate(path):
        try:
            value = _read_envelope(path, budget=budget)
            decrypt_payload(value, _provider(settings, key_provider), now=datetime.min.replace(tzinfo=timezone.utc))
            if value["spool_id"] != path.stem:
                raise SpoolError("SPOOL_ID_COLLISION")
        except TimeoutError:
            raise
        except (SpoolError, CryptoError, KeyProviderError, OSError) as exc:
            raise CatalogUnknown("RUNTIME_ENTRY_UNVERIFIED") from exc
        return value.get("purpose", "legacy")
    return catalog.migrate_page(budget=budget, inspect_metadata=authenticate)


def _retry_tag(entry_id, content_hash, classification, purpose, capture_id, created_at, expires_at):
    fields = ["ei.spool.reservation.v1", entry_id, content_hash, classification, purpose, capture_id, created_at, expires_at]
    return "sha256:" + hashlib.sha256(json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def write_spool(
    payload: bytes | bytearray | str | Mapping[str, Any],
    classification: str,
    settings: Any,
    *,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
    spool_id: str | None = None,
    key_provider: KeyProvider | None = None,
    purpose: str = "legacy",
    retention: PendingPolicy | None = None,
    capture_id: str | None = None,
    budget=None,
) -> SpoolRef:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
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
    if purpose not in {"legacy", "pending", "validated-result"}:
        raise SpoolError("SPOOL_PURPOSE_INVALID")
    if purpose != "legacy":
        selected_policy = retention or pending_policy(dict(_policy(settings)) if Path(settings.capture_policy_path).exists() else {})
        configured_ttl, max_items, max_bytes = selected_policy.ttl_seconds, selected_policy.max_items, selected_policy.max_bytes
        if any(type(item) is not int or item <= 0 for item in (configured_ttl, max_items, max_bytes)):
            raise SpoolError("PENDING_POLICY_INVALID")
    ttl = configured_ttl if ttl_seconds is None else ttl_seconds
    if type(ttl) is not int or ttl <= 0:
        raise SpoolError("SPOOL_TTL_INVALID")
    root = _root(settings)
    _permissions(root)
    selected_id = spool_id or "spool_" + secrets.token_hex(16)
    if not _SAFE_ID.fullmatch(selected_id):
        raise SpoolError("SPOOL_ID_INVALID")
    descriptor = _acquire(root, budget=budget)
    try:
        path = _safe_path(root, selected_id, budget)
        catalog = _catalog(root, budget)
        reservation = catalog.reservation(selected_id, budget=budget)
        content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        if path.exists():
            try:
                existing = _read_envelope(path, budget=budget, expected_digest=reservation["digest"] if reservation else None)
            except SpoolError as exc:
                if purpose == "legacy":
                    _quarantine(settings, selected_id, "SPOOL_EXISTING_INVALID", path, budget, locked=True)
                raise SpoolError("SPOOL_EXISTING_INVALID") from exc
            created = datetime.fromisoformat(existing["created_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(existing["expires_at"].replace("Z", "+00:00"))
            if existing.get("content_sha256") == content_hash and existing.get("classification") == classification and existing.get("purpose", "legacy") == purpose and existing.get("capture_id") == capture_id and expires - created == timedelta(seconds=ttl):
                try:
                    decrypt_payload(existing, _provider(settings, key_provider), now=moment)
                except (CryptoError, KeyProviderError) as exc:
                    raise SpoolError("SPOOL_EXISTING_INVALID") from exc
                if not _inventory(catalog, settings, key_provider, budget).complete:
                    raise SpoolError("SPOOL_CAPACITY_UNKNOWN")
                budget.check()
                return SpoolRef(selected_id, str(existing["content_sha256"]), classification, str(existing["created_at"]), str(existing["expires_at"]), existing.get("key_id"), purpose=purpose)
            raise SpoolError("SPOOL_ID_COLLISION")
        created, expires = moment, moment + timedelta(seconds=ttl)
        if reservation is not None:
            if reservation["phase"] != "writing" or not reservation["retry_tag"]:
                raise SpoolError("SPOOL_ID_COLLISION")
            created = datetime.fromisoformat(reservation["created_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(reservation["expires_at"].replace("Z", "+00:00"))
            if expires - created != timedelta(seconds=ttl):
                raise SpoolError("SPOOL_ID_COLLISION")
        created_at = created.isoformat().replace("+00:00", "Z")
        expires_at = expires.isoformat().replace("+00:00", "Z")
        tag = _retry_tag(selected_id, content_hash, classification, purpose, capture_id, created_at, expires_at)
        if reservation is not None and (reservation["retry_tag"] != tag or reservation["purpose"] != purpose):
            raise SpoolError("SPOOL_ID_COLLISION")
        if expires <= moment:
            raise SpoolError("SPOOL_EXPIRED")
        inventory = _inventory(catalog, settings, key_provider, budget)
        if not inventory.complete and reservation is None:
            raise SpoolError("SPOOL_CAPACITY_UNKNOWN")
        catalog.validate_page(budget=budget)
        try:
            envelope = encrypt_payload(content, selected_id, classification, expires, _provider(settings, key_provider), created_at=created,
                aad_version=2 if purpose != "legacy" else None, purpose=purpose, capture_id=capture_id)
        except (KeyProviderError, CryptoError, OSError) as exc:
            _quarantine(settings, selected_id, "SPOOL_KEY_UNAVAILABLE", budget=budget, locked=True)
            raise SpoolError("SPOOL_KEY_UNAVAILABLE") from exc
        envelope_size = _json_size(envelope)
        if reservation is None:
            capacity_items, capacity_bytes = _purpose_capacity(root, purpose, _provider(settings, key_provider), budget=budget)
            increment = 0 if purpose == "validated-result" else 1
            if capacity_items + increment > max_items or capacity_bytes + envelope_size > max_bytes:
                raise SpoolError("SPOOL_FULL")
        catalog.write(selected_id, (json.dumps(envelope, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"), purpose=purpose,
            budget=budget, writer=lambda target: _atomic_json(target, envelope, budget=budget),
            retry_tag=tag, created_at=created_at, expires_at=expires_at)
        if budget is not None:
            budget.check()
        _audit(settings, "write", selected_id, "SPOOL_WRITTEN")
        return SpoolRef(selected_id, envelope["content_sha256"], classification, envelope["created_at"], envelope["expires_at"], envelope["key_id"], purpose=purpose)
    except CatalogUnknown as exc:
        raise SpoolError("SPOOL_CAPACITY_UNVERIFIED" if str(exc) == "RUNTIME_ENTRY_CHANGED" else str(exc)) from exc
    finally:
        _release(root, descriptor)

def _read_envelope(path: Path, budget=None, *, expected_digest=None) -> Mapping[str, Any]:
    if budget is not None:
        budget.check()
    try:
        data = read_entry(path.parent, path, budget=budget)
        if expected_digest is not None and hashlib.sha256(data).hexdigest() != expected_digest:
            raise SpoolError("SPOOL_EXISTING_INVALID")
        value = json.loads(data)
    except TimeoutError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SpoolError("SPOOL_ENVELOPE_INVALID") from exc
    if not isinstance(value, Mapping):
        raise SpoolError("SPOOL_ENVELOPE_INVALID")
    try:
        validate_schema("spool-envelope", value)
    except ValueError as exc:
        raise SpoolError("SPOOL_ENVELOPE_INVALID") from exc
    return value


def _purpose_capacity(root: Path, purpose: str, provider: KeyProvider, budget=None) -> tuple[int, int]:
    catalog = RuntimeCatalog(root)
    if purpose == "legacy":
        return catalog.capacity("legacy", budget=budget)
    items, size = catalog.capacity("pending", budget=budget)
    _, result_size = catalog.capacity("validated-result", budget=budget)
    return items, size + result_size


def _authenticated_pending_ref(ref: SpoolRef, settings: Any, capture_id: str, *, now: datetime, key_provider: KeyProvider | None = None, budget=None) -> SpoolRef:
    """Recover committed envelope metadata without ever creating ciphertext."""
    envelope = _read_envelope(_safe_path(_root(settings), ref.spool_id, budget), budget=budget)
    decrypt_payload(envelope, _provider(settings, key_provider), now=now)
    if envelope.get("capture_id") != capture_id or envelope.get("purpose") != "pending":
        raise SpoolError("SPOOL_REF_MISMATCH")
    actual = SpoolRef(str(envelope["spool_id"]), str(envelope["content_sha256"]), str(envelope["classification"]),
        str(envelope["created_at"]), str(envelope["expires_at"]), str(envelope["key_id"]), purpose="pending")
    if any(getattr(actual, name) != getattr(ref, name) for name in ("spool_id", "content_hash", "classification", "created_at", "expires_at", "purpose")):
        raise SpoolError("SPOOL_REF_MISMATCH")
    return actual


def read_spool(
    ref: SpoolRef | Mapping[str, Any] | str,
    settings: Any,
    *,
    now: datetime | None = None,
    key_provider: KeyProvider | None = None,
    expected_capture_id: str | None = None,
    budget=None,
) -> bytes:
    if budget is not None:
        budget.check()
    if expected_capture_id is not None and (not isinstance(expected_capture_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_capture_id)):
        raise SpoolError("SPOOL_CAPTURE_ID_INVALID")
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
    path = _safe_path(root, spool_id, budget)
    if not path.exists():
        raise SpoolError("SPOOL_NOT_FOUND")
    try:
        envelope = _read_envelope(path, budget=budget)
        # Authenticate the stored envelope independently of caller references.
        # A wrong reference is not corruption; a damaged envelope is.
        payload = decrypt_payload(envelope, _provider(settings, key_provider), now=_now(now))
        if expected_capture_id is not None and envelope.get("capture_id") != expected_capture_id:
            raise SpoolError("SPOOL_CAPTURE_MISMATCH")
        if reference is not None:
            if envelope.get("purpose", "legacy") != reference.purpose:
                raise SpoolError("SPOOL_REF_MISMATCH")
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
        return payload
    except TimeoutError:
        raise
    except CryptoError as exc:
        reason = str(exc)
        if reason == "SPOOL_EXPIRED":
            if envelope.get("purpose", "legacy") == "legacy" and expected_capture_id is None and (reference is None or reference.purpose == "legacy"):
                delete_spool(spool_id, settings, reason_code=reason, budget=budget)
        elif not isinstance(exc.__cause__, KeyProviderError) and reason != "CRYPTO_DEPENDENCY_UNAVAILABLE":
            _quarantine(settings, spool_id, reason, path, budget)
        raise SpoolError(reason) from exc
    except (SpoolError, KeyProviderError, OSError) as exc:
        if isinstance(exc, SpoolError) and str(exc) == "SPOOL_ENVELOPE_INVALID" and not isinstance(exc.__cause__, OSError):
            _quarantine(settings, spool_id, "SPOOL_ENVELOPE_INVALID", path, budget)
        if expected_capture_id is not None or (reference is not None and reference.purpose != "legacy"):
            raise SpoolError("SPOOL_READ_FAILED") from exc
        raise SpoolError(str(exc) or "SPOOL_READ_FAILED") from exc


def delete_spool(spool: SpoolRef | str, settings: Any, *, reason_code: str = "SPOOL_DELETED", budget=None, key_provider=None) -> bool:
    budget = budget if budget is not None else OperationBudget(5000)
    if budget is not None:
        budget.check()
    spool_id = spool.spool_id if isinstance(spool, SpoolRef) else str(spool)
    root = _root(settings)
    _permissions(root)
    descriptor = _acquire(root, budget=budget)
    try:
        catalog = _catalog(root, budget)
        path = _safe_path(root, spool_id, budget)
        if (root / (spool_id + ".json")).exists() or (catalog.reservation(spool_id, budget=budget) is None and path.exists()):
            _inventory(catalog, settings, key_provider, budget)
        removed = catalog.delete(spool_id, budget=budget)
        _audit(settings, "delete", spool_id, reason_code if removed else "SPOOL_ALREADY_DELETED")
        return removed
    except TimeoutError:
        raise
    except CatalogUnknown as exc:
        raise SpoolError(str(exc)) from exc
    except OSError as exc:
        raise SpoolError("SPOOL_DELETE_FAILED") from exc
    finally:
        _release(root, descriptor)

def gc_expired_spool(settings: Any, *, now: datetime | None = None, budget=None, max_records=64, key_provider=None) -> int:
    budget = budget if budget is not None else OperationBudget(5000)
    moment = _now(now)
    root = _root(settings)
    if not root.exists():
        return 0
    removed = 0
    descriptor = _acquire(root, budget=budget)
    try:
        catalog = _catalog(root, budget)
        _inventory(catalog, settings, key_provider, budget)
        page = catalog.page("spool-gc", limit=max_records, budget=budget, advance=False)
        for path in page.paths:
            budget.check()
            try:
                if catalog.reservation(path.stem, budget=budget)["purpose"] != "legacy" or path.stem.startswith("pending_"):
                    catalog.advance("spool-gc", path.stem, budget=budget)
                    continue  # pending expiry must first be recorded in its capture receipt
                envelope = _read_envelope(path, budget=budget)
                expiry = datetime.fromisoformat(str(envelope["expires_at"]).replace("Z", "+00:00"))
                if expiry <= moment:
                    catalog.delete(path.stem, budget=budget)
                    removed += 1
                    _audit(settings, "delete", path.stem, "SPOOL_EXPIRED")
            except TimeoutError:
                raise
            except (SpoolError, OSError, KeyError, ValueError, TypeError):
                _quarantine(settings, path.stem, "SPOOL_GC_INVALID", path, budget, locked=True)
            catalog.advance("spool-gc", path.stem, budget=budget)
    except CatalogUnknown as exc:
        raise SpoolError(str(exc)) from exc
    finally:
        _release(root, descriptor)
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
