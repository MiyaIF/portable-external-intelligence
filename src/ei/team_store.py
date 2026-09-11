"""Append-only shared team event store and machine-local writer identity."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .ids import canonical_json
from .journal import event_integrity, read_event
from .models import Event
from .persistable_fields import inspect_event_payload
from .safe_fs import (
    SafeFilesystemError,
    assert_no_reparse_components,
    assert_safe_target,
    canonical_path,
    safe_atomic_write,
    safe_ensure_directory,
    safe_unlink,
)


TEAM_STORE_SCHEMA_VERSION = 1
TEAM_EVENT_SCHEMA_VERSION = 2
TEAM_STORE_KIND = "portable-external-intelligence-team-store"
TEAM_STORE_LAYOUT = "member-writer-events-v1"
TEAM_MANIFEST_NAME = "team-manifest.json"
TEAM_EVENT_TYPE = "team.knowledge.recorded"
MAX_TEAM_EVENT_BYTES = 1024 * 1024

_MEMBER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_WRITER_ID_RE = re.compile(r"^writer_[0-9a-f]{16,64}$")
_STORE_ID_RE = re.compile(r"^team_[0-9a-f]{16,64}$")
_EVENT_ID_RE = re.compile(r"^evt_[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MANIFEST_KEYS = frozenset({"schema_version", "kind", "store_id", "layout", "event_schema_version", "created_at"})
_IDENTITY_KEYS = frozenset({"schema_version", "store_id", "writer_id", "created_at"})
_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "actor",
        "machine_id",
        "payload",
        "integrity_sha256",
        "idempotency_key",
        "provenance",
        "integrity",
    }
)
_TEAM_PAYLOAD_KEYS = frozenset(
    {
        "knowledge_scope",
        "origin_event_hash",
        "idempotency_key",
        "title",
        "claim",
        "scope",
        "preconditions",
        "failure_modes",
        "benefit",
        "classification",
    }
)


@dataclass(frozen=True)
class TeamStoreDescriptor:
    root: Path
    store_id: str
    layout: str
    event_schema_version: int
    created_at: str


@dataclass(frozen=True)
class TeamEventScan:
    events: tuple[Event, ...]
    issues: tuple[Mapping[str, object], ...]


def _raise(code: str) -> None:
    raise ValueError(code)


def _safe_root(value: Path | str, *, require_exists: bool) -> tuple[Path, Path]:
    if isinstance(value, bool) or not isinstance(value, (Path, str)) or not str(value):
        _raise("TEAM_ROOT_INVALID")
    try:
        raw = assert_no_reparse_components(value)
        resolved = canonical_path(raw, require_exists=require_exists)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("TEAM_ROOT_INVALID") from exc
    if require_exists and (not resolved.exists() or not resolved.is_dir()):
        _raise("TEAM_ROOT_INVALID")
    return raw, resolved


def _format_time(value: datetime | str | None) -> str:
    if value is None:
        moment = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("TEAM_MANIFEST_INVALID") from exc
    else:
        _raise("TEAM_MANIFEST_INVALID")
    if moment.tzinfo is None or moment.utcoffset() is None:
        _raise("TEAM_MANIFEST_INVALID")
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_store_id(value: object) -> str:
    if not isinstance(value, str) or not _STORE_ID_RE.fullmatch(value):
        _raise("TEAM_STORE_ID_INVALID")
    return value


def _validate_member_id(value: object) -> str:
    if not isinstance(value, str) or not _MEMBER_ID_RE.fullmatch(value):
        _raise("TEAM_MEMBER_ID_INVALID")
    return value


def _validate_writer_id(value: object) -> str:
    if not isinstance(value, str) or not _WRITER_ID_RE.fullmatch(value):
        _raise("TEAM_WRITER_ID_INVALID")
    return value


def _manifest_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _validate_manifest(value: Mapping[str, Any]) -> TeamStoreDescriptor:
    if set(value) != _MANIFEST_KEYS:
        _raise("TEAM_STORE_MANIFEST_INVALID")
    if type(value.get("schema_version")) is not int or value.get("schema_version") != TEAM_STORE_SCHEMA_VERSION:
        _raise("TEAM_STORE_MANIFEST_INVALID")
    if value.get("kind") != TEAM_STORE_KIND or value.get("layout") != TEAM_STORE_LAYOUT:
        _raise("TEAM_STORE_MANIFEST_INVALID")
    store_id = _validate_store_id(value.get("store_id"))
    if type(value.get("event_schema_version")) is not int or value.get("event_schema_version") != TEAM_EVENT_SCHEMA_VERSION:
        _raise("TEAM_STORE_MANIFEST_INVALID")
    created_at = _format_time(value.get("created_at"))
    if created_at != value.get("created_at"):
        # Stored timestamps are normalized UTC strings, keeping the manifest
        # byte-stable across repeated setup calls.
        _raise("TEAM_STORE_MANIFEST_INVALID")
    return TeamStoreDescriptor(Path(), store_id, TEAM_STORE_LAYOUT, TEAM_EVENT_SCHEMA_VERSION, created_at)


def inspect_team_store(root: Path | str, *, expected_store_id: str | None = None) -> TeamStoreDescriptor:
    """Read and validate a shared team root without modifying it."""

    raw_root, canonical_root = _safe_root(root, require_exists=True)
    try:
        assert_safe_target(raw_root, raw_root, allow_root=True, allow_missing=False, expected_type="dir")
        manifest_path = assert_safe_target(raw_root, raw_root / TEAM_MANIFEST_NAME, allow_missing=False, expected_type="file")
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (SafeFilesystemError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("TEAM_STORE_MANIFEST_INVALID") from exc
    if not isinstance(raw_manifest, Mapping):
        _raise("TEAM_STORE_MANIFEST_INVALID")
    descriptor = _validate_manifest(raw_manifest)
    if expected_store_id is not None and descriptor.store_id != _validate_store_id(expected_store_id):
        _raise("TEAM_STORE_ID_MISMATCH")
    try:
        entries = {entry.name: entry for entry in raw_root.iterdir()}
    except OSError as exc:
        raise ValueError("TEAM_ROOT_UNAVAILABLE") from exc
    if set(entries) - {TEAM_MANIFEST_NAME, "members"} or "members" not in entries:
        _raise("TEAM_ROOT_CONTRACT_INVALID")
    members = entries["members"]
    if members.is_symlink() or not members.is_dir():
        _raise("TEAM_ROOT_CONTRACT_INVALID")
    return replace(descriptor, root=canonical_root)


def initialize_team_store(
    root: Path | str,
    *,
    now: datetime | str | None = None,
    random_id: Callable[[], str] | None = None,
    expected_store_id: str | None = None,
) -> TeamStoreDescriptor:
    """Create an empty team store, or return an existing valid one."""

    raw_root, canonical_root = _safe_root(root, require_exists=False)
    if raw_root.exists() or raw_root.is_symlink():
        if raw_root.is_symlink() or not raw_root.is_dir():
            _raise("TEAM_ROOT_CONTRACT_INVALID")
        try:
            entries = {entry.name for entry in raw_root.iterdir()}
        except OSError as exc:
            raise ValueError("TEAM_ROOT_UNAVAILABLE") from exc
        if entries:
            if entries - {TEAM_MANIFEST_NAME, "members"}:
                _raise("TEAM_ROOT_CONTRACT_INVALID")
            # Existing stores are never retargeted or rewritten.  A caller may
            # still require a specific identity during re-attachment.
            return inspect_team_store(raw_root, expected_store_id=expected_store_id)

    safe_ensure_directory(raw_root, mode=0o700)
    safe_ensure_directory(raw_root / "members", mode=0o700)
    if expected_store_id is not None:
        _validate_store_id(expected_store_id)
    generator = random_id or (lambda: uuid.uuid4().hex)
    suffix = generator()
    if not isinstance(suffix, str) or not re.fullmatch(r"[0-9a-f]{16,64}", suffix):
        _raise("TEAM_STORE_ID_INVALID")
    store_id = f"team_{suffix}"
    if expected_store_id is not None and store_id != expected_store_id:
        # This branch can only occur for a newly-created root when a caller
        # supplied an identity constraint; do not create a mismatched store.
        _raise("TEAM_STORE_ID_MISMATCH")
    created_at = _format_time(now)
    manifest = {
        "schema_version": TEAM_STORE_SCHEMA_VERSION,
        "kind": TEAM_STORE_KIND,
        "store_id": store_id,
        "layout": TEAM_STORE_LAYOUT,
        "event_schema_version": TEAM_EVENT_SCHEMA_VERSION,
        "created_at": created_at,
    }
    manifest_path = raw_root / TEAM_MANIFEST_NAME
    try:
        safe_atomic_write(raw_root, manifest_path, _manifest_bytes(manifest), mode=0o600)
    except SafeFilesystemError as exc:
        raise ValueError("TEAM_STORE_MANIFEST_WRITE_FAILED") from exc
    return TeamStoreDescriptor(canonical_root, store_id, TEAM_STORE_LAYOUT, TEAM_EVENT_SCHEMA_VERSION, created_at)


def writer_identity_path(runtime_root: Path | str, store_id: str) -> Path:
    _validate_store_id(store_id)
    return Path(runtime_root) / "team-identities" / f"{store_id}.json"


def _read_writer_identity(path: Path, expected_store_id: str) -> str:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TEAM_WRITER_IDENTITY_INVALID") from exc
    if not isinstance(raw, Mapping) or set(raw) != _IDENTITY_KEYS:
        _raise("TEAM_WRITER_IDENTITY_INVALID")
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        _raise("TEAM_WRITER_IDENTITY_INVALID")
    if raw.get("store_id") != expected_store_id:
        _raise("TEAM_STORE_ID_MISMATCH")
    writer = _validate_writer_id(raw.get("writer_id"))
    _format_time(raw.get("created_at"))
    return writer


def load_or_create_writer_identity(
    runtime_root: Path | str,
    store_id: str,
    *,
    random_id: Callable[[], str] | None = None,
    now: datetime | str | None = None,
) -> str:
    """Load a stable machine-local writer ID, creating it once if absent."""

    store_id = _validate_store_id(store_id)
    raw_runtime, _ = _safe_root(runtime_root, require_exists=False)
    safe_ensure_directory(raw_runtime, mode=0o700)
    identity = writer_identity_path(raw_runtime, store_id)
    parent = identity.parent
    safe_ensure_directory(parent, mode=0o700)
    assert_safe_target(raw_runtime, identity, allow_missing=True)
    if identity.exists() or identity.is_symlink():
        if identity.is_symlink():
            _raise("TEAM_WRITER_IDENTITY_INVALID")
        return _read_writer_identity(identity, store_id)

    generator = random_id or (lambda: uuid.uuid4().hex)
    suffix = generator()
    if not isinstance(suffix, str) or suffix.startswith("writer_"):
        suffix = suffix.removeprefix("writer_") if isinstance(suffix, str) else ""
    if not re.fullmatch(r"[0-9a-f]{16,64}", suffix):
        _raise("TEAM_WRITER_ID_INVALID")
    writer = f"writer_{suffix}"
    identity_value = {
        "schema_version": 1,
        "store_id": store_id,
        "writer_id": writer,
        "created_at": _format_time(now),
    }
    payload = _manifest_bytes(identity_value)
    # An exclusive create avoids replacing another process's identity.  The
    # fallback reads the winner when two processes initialize concurrently.
    try:
        with identity.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return _read_writer_identity(identity, store_id)
    except OSError as exc:
        raise ValueError("TEAM_WRITER_IDENTITY_WRITE_FAILED") from exc
    return writer


def _event_partition(event: Event) -> tuple[str, str, str]:
    try:
        moment = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("TEAM_EVENT_SCHEMA_INVALID") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    utc = moment.astimezone(timezone.utc)
    return utc.strftime("%Y"), utc.strftime("%m"), utc.strftime("%d")


def _payload_hash(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(dict(payload))).hexdigest()


def _validate_team_event_mapping(value: Mapping[str, Any]) -> Event:
    if set(value) != _EVENT_KEYS:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if type(value.get("schema_version")) is not int or value.get("schema_version") != TEAM_EVENT_SCHEMA_VERSION:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or not _EVENT_ID_RE.fullmatch(event_id):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if value.get("event_type") != TEAM_EVENT_TYPE:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    for key in ("occurred_at", "actor", "machine_id", "integrity_sha256", "idempotency_key"):
        if not isinstance(value.get(key), str) or not value[key]:
            _raise("TEAM_EVENT_SCHEMA_INVALID")
    if not re.fullmatch(r"[0-9a-f]{64}", value["integrity_sha256"]):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if not _HASH_RE.fullmatch(value["idempotency_key"]):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    provenance = value.get("provenance")
    if not isinstance(provenance, list) or any(not isinstance(item, str) for item in provenance):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {"algorithm", "canonical_payload_hash"}:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if integrity.get("algorithm") != "sha256" or not isinstance(integrity.get("canonical_payload_hash"), str) or not _HASH_RE.fullmatch(integrity["canonical_payload_hash"]):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    payload = value.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != _TEAM_PAYLOAD_KEYS:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if payload.get("knowledge_scope") != "team" or payload.get("classification") not in {"public", "private-reusable"}:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    for key in ("origin_event_hash", "idempotency_key"):
        if not isinstance(payload.get(key), str) or not _HASH_RE.fullmatch(payload[key]):
            _raise("TEAM_EVENT_SCHEMA_INVALID")
    for key in ("title", "claim", "benefit"):
        if not isinstance(payload.get(key), str) or not payload[key]:
            _raise("TEAM_EVENT_SCHEMA_INVALID")
    if len(payload["title"]) > 160 or len(payload["claim"]) < 20 or len(payload["claim"]) > 1200:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    for key in ("scope", "preconditions", "failure_modes"):
        if not isinstance(payload.get(key), list) or any(not isinstance(item, str) or not item for item in payload[key]):
            _raise("TEAM_EVENT_SCHEMA_INVALID")
    if integrity["canonical_payload_hash"] != _payload_hash(payload):
        _raise("TEAM_EVENT_INTEGRITY_INVALID")
    privacy = inspect_event_payload(
        payload,
        classification=str(payload.get("classification", "private-reusable")),
    )
    if not privacy.valid:
        _raise("TEAM_EVENT_PRIVACY_INVALID")
    try:
        event = Event.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("TEAM_EVENT_SCHEMA_INVALID") from exc
    if event_integrity(event) != event.integrity_sha256:
        _raise("TEAM_EVENT_INTEGRITY_INVALID")
    _event_partition(event)
    return event


def _materialize_team_event(event: Event) -> tuple[Event, bytes]:
    if not isinstance(event, Event):
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if event.schema_version != TEAM_EVENT_SCHEMA_VERSION:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    if event.event_type != TEAM_EVENT_TYPE:
        _raise("TEAM_EVENT_SCHEMA_INVALID")
    integrity = event_integrity(event)
    if event.integrity_sha256 and event.integrity_sha256 != integrity:
        _raise("TEAM_EVENT_INTEGRITY_INVALID")
    materialized = replace(event, integrity_sha256=integrity)
    mapping = materialized.to_dict()
    checked = _validate_team_event_mapping(mapping)
    return checked, (canonical_json(mapping) + b"\n")


def _existing_event(target: Path) -> Event:
    try:
        # Prefer the shared journal reader so ordinary event IDs receive the
        # same privacy/integrity checks as personal events.  The local closed
        # validator also accepts deterministic fixture IDs such as evt_a.
        try:
            return read_event(target)
        except Exception:
            return _validate_team_event_mapping(json.loads(target.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("TEAM_EVENT_EXISTING_INVALID") from exc


def append_team_event(root: Path | str, member_id: str, writer_id: str, event: Event) -> Path:
    """Append one event atomically to a writer shard, preserving collisions."""

    descriptor = inspect_team_store(root)
    member_id = _validate_member_id(member_id)
    writer_id = _validate_writer_id(writer_id)
    materialized, payload = _materialize_team_event(event)
    year, month, day = _event_partition(materialized)
    raw_root = descriptor.root
    target_dir = raw_root / "members" / member_id / "writers" / writer_id / "events" / year / month / day
    try:
        safe_ensure_directory(target_dir, mode=0o700)
        target = assert_safe_target(raw_root, target_dir / f"{materialized.event_id}.json", allow_missing=True)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("TEAM_EVENT_PATH_INVALID") from exc
    expected_hash = event_integrity(materialized)
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            _raise("TEAM_EVENT_PATH_INVALID")
        existing = _existing_event(target)
        if event_integrity(existing) == expected_hash:
            return target
        _raise("TEAM_EVENT_ID_CONFLICT")

    temporary = target.parent / f".partial-{uuid.uuid4().hex}"
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # A concurrent writer may have won the same filename between the
        # initial check and this rename; compare rather than overwrite it.
        if target.exists() or target.is_symlink():
            if target.is_symlink():
                _raise("TEAM_EVENT_PATH_INVALID")
            existing = _existing_event(target)
            if event_integrity(existing) == expected_hash:
                return target
            _raise("TEAM_EVENT_ID_CONFLICT")
        os.replace(temporary, target)
        verified = _existing_event(target)
        if event_integrity(verified) != expected_hash:
            _raise("TEAM_EVENT_WRITE_VERIFY_FAILED")
        return target
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("TEAM_EVENT_WRITE_FAILED") from exc
    finally:
        if temporary.exists():
            try:
                safe_unlink(raw_root, temporary, allow_missing=True)
            except SafeFilesystemError:
                temporary.unlink(missing_ok=True)


def _issue(code: str, root: Path, path: Path | None = None) -> dict[str, object]:
    relative = "." if path is None else path.relative_to(root).as_posix()
    return {"code": code, "reason_code": code, "path": relative}


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.exists():
            return False
        stat_result = path.stat(follow_symlinks=False)
        return bool(getattr(stat_result, "st_reparse_tag", 0)) or bool(getattr(stat_result, "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def _listdir(path: Path) -> tuple[list[Path], OSError | None]:
    try:
        return sorted(path.iterdir(), key=lambda item: item.name), None
    except OSError as exc:
        return [], exc


def _scan_event_file(path: Path, root: Path, events: list[Event], issues: list[Mapping[str, object]]) -> None:
    if _is_reparse(path):
        issues.append(_issue("TEAM_REPARSE_POINT", root, path))
        return
    if path.name.startswith(".partial-") or path.name.startswith(".partial"):
        issues.append(_issue("TEAM_PARTIAL_FILE", root, path))
        return
    lowered = path.name.casefold()
    if "conflict" in lowered or lowered.endswith(".conflicted"):
        issues.append(_issue("TEAM_CONFLICT_COPY", root, path))
        return
    if path.suffix.casefold() != ".json":
        issues.append(_issue("TEAM_UNKNOWN_ENTRY", root, path))
        return
    try:
        if path.stat().st_size > MAX_TEAM_EVENT_BYTES:
            issues.append(_issue("TEAM_EVENT_OVERSIZED", root, path))
            return
        event = _existing_event(path)
        if path.stem != event.event_id:
            issues.append(_issue("TEAM_EVENT_FILENAME_MISMATCH", root, path))
            return
        events.append(event)
    except ValueError as exc:
        code = str(exc)
        if code == "TEAM_EVENT_EXISTING_INVALID":
            code = "TEAM_EVENT_INVALID"
        if code not in {"TEAM_EVENT_INTEGRITY_INVALID", "TEAM_EVENT_SCHEMA_INVALID", "TEAM_EVENT_INVALID"}:
            code = "TEAM_EVENT_INVALID"
        issues.append(_issue(code, root, path))
    except OSError:
        issues.append(_issue("TEAM_EVENT_INVALID", root, path))


def scan_team_events(root: Path | str) -> TeamEventScan:
    """Scan only the allowlisted event layout and retain valid events."""

    try:
        descriptor = inspect_team_store(root)
    except ValueError as exc:
        return TeamEventScan((), ({"code": str(exc), "reason_code": str(exc), "path": "."},))
    root_path = descriptor.root
    events: list[Event] = []
    issues: list[Mapping[str, object]] = []
    members_path = root_path / "members"
    members, error = _listdir(members_path)
    if error is not None:
        return TeamEventScan((), (_issue("TEAM_ROOT_UNAVAILABLE", root_path, members_path),))
    for member_path in members:
        if _is_reparse(member_path):
            issues.append(_issue("TEAM_REPARSE_POINT", root_path, member_path))
            continue
        if not member_path.is_dir() or not _MEMBER_ID_RE.fullmatch(member_path.name):
            issues.append(_issue("TEAM_MEMBER_ID_INVALID", root_path, member_path))
            continue
        writers_path = member_path / "writers"
        if _is_reparse(writers_path) or not writers_path.is_dir():
            issues.append(_issue("TEAM_LAYOUT_INVALID", root_path, writers_path))
            continue
        writers, writer_error = _listdir(writers_path)
        if writer_error is not None:
            issues.append(_issue("TEAM_ROOT_UNAVAILABLE", root_path, writers_path))
            continue
        for writer_path in writers:
            if _is_reparse(writer_path):
                issues.append(_issue("TEAM_REPARSE_POINT", root_path, writer_path))
                continue
            if not writer_path.is_dir() or not _WRITER_ID_RE.fullmatch(writer_path.name):
                issues.append(_issue("TEAM_WRITER_ID_INVALID", root_path, writer_path))
                continue
            events_path = writer_path / "events"
            if _is_reparse(events_path) or not events_path.is_dir():
                issues.append(_issue("TEAM_LAYOUT_INVALID", root_path, events_path))
                continue
            year_paths, year_error = _listdir(events_path)
            if year_error is not None:
                issues.append(_issue("TEAM_ROOT_UNAVAILABLE", root_path, events_path))
                continue
            for year_path in year_paths:
                if _is_reparse(year_path) or not year_path.is_dir() or not re.fullmatch(r"[0-9]{4}", year_path.name):
                    issues.append(_issue("TEAM_LAYOUT_INVALID", root_path, year_path))
                    continue
                month_paths, month_error = _listdir(year_path)
                if month_error is not None:
                    issues.append(_issue("TEAM_ROOT_UNAVAILABLE", root_path, year_path))
                    continue
                for month_path in month_paths:
                    if _is_reparse(month_path) or not month_path.is_dir() or not re.fullmatch(r"[0-9]{2}", month_path.name):
                        issues.append(_issue("TEAM_LAYOUT_INVALID", root_path, month_path))
                        continue
                    day_paths, day_error = _listdir(month_path)
                    if day_error is not None:
                        issues.append(_issue("TEAM_ROOT_UNAVAILABLE", root_path, month_path))
                        continue
                    for day_path in day_paths:
                        if _is_reparse(day_path) or not day_path.is_dir() or not re.fullmatch(r"[0-9]{2}", day_path.name):
                            issues.append(_issue("TEAM_LAYOUT_INVALID", root_path, day_path))
                            continue
                        files, file_error = _listdir(day_path)
                        if file_error is not None:
                            issues.append(_issue("TEAM_ROOT_UNAVAILABLE", root_path, day_path))
                            continue
                        for path in files:
                            _scan_event_file(path, root_path, events, issues)
    events.sort(key=lambda item: (item.occurred_at, item.event_id, event_integrity(item)))
    return TeamEventScan(tuple(events), tuple(issues))


__all__ = [
    "TEAM_EVENT_SCHEMA_VERSION",
    "TEAM_EVENT_TYPE",
    "TEAM_STORE_LAYOUT",
    "TeamEventScan",
    "TeamStoreDescriptor",
    "append_team_event",
    "initialize_team_store",
    "inspect_team_store",
    "load_or_create_writer_identity",
    "scan_team_events",
    "writer_identity_path",
]
