from __future__ import annotations

import hashlib
import json
import os
import re
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .adapters.base import SourceAdapter, SourceRecord, SourceCursor, scan_read_only
from .config import Settings
from .ids import fingerprint, machine_id, stable_hash
from .journal import append_event, read_event
from .capture_contract import CaptureIdentity, CaptureReceipt, capture_key
from .capture_ledger import record_receipt
from .pending_capture import accept_candidate
from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory
from .models import Event, ObservationInput, validate_host_label
from .privacy import inspect_observation


CURSOR_VERSION = 2
_CAPTURE_PATHS = ("agent_direct", "native_memory", "rollout_summary", "migration", "manual")
_FULL_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")

def _persisted_hash(value: str) -> str:
    if not value:
        return ""
    return value if _FULL_HASH.fullmatch(value) else fingerprint(value)


def _capture_path(record: SourceRecord, adapter: SourceAdapter) -> str:
    declared = getattr(adapter, "capture_path", None)
    if isinstance(declared, str) and declared in _CAPTURE_PATHS:
        return declared
    kind = record.source_kind.casefold()
    if kind in {"agent_direct", "transcript_metadata"}:
        return "agent_direct"
    if kind == "rollout_summary":
        return "rollout_summary"
    if kind.startswith("migration") or "migration" in kind:
        return "migration"
    if kind in {"codex_memory", "claude_stable_memory", "gemini_session_metadata", "qwen_session_metadata", "native_memory"}:
        return "native_memory"
    return "manual"


@dataclass(frozen=True)
class IngestResult:
    created_events: int
    skipped_records: int
    parse_skipped: int
    rejected_records: int
    event_ids: tuple[str, ...] = field(default_factory=tuple)
    health: Mapping[str, int] = field(default_factory=dict)


def _cursor_path(settings: Settings) -> Path:
    return settings.paths.local_state_dir / "ingest-cursor.json"


def _load_cursor(path: Path, *, max_bytes: int | None = None) -> dict[str, Any]:
    if not path.exists():
        return {"version": CURSOR_VERSION, "sources": {}}
    if max_bytes is not None:
        assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
        if path.stat().st_size > max_bytes:
            raise ValueError("SOURCE_LEGACY_CURSOR_LIMIT")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("INGEST_CURSOR_INVALID") from exc
    if not isinstance(data, dict):
        raise ValueError("INGEST_CURSOR_INVALID")
    version = data.get("version")
    if version not in {1, CURSOR_VERSION}:
        raise ValueError("INGEST_CURSOR_VERSION_UNSUPPORTED")
    sources = data.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("INGEST_CURSOR_SOURCES_INVALID")
    return {"version": CURSOR_VERSION, "sources": sources}


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _source_key(source_ref: str, source_host_id: str = "", source_host_family: str = "") -> str:
    normalized = unicodedata.normalize("NFKC", source_ref.replace("\\", "/"))
    if source_host_id and source_host_family:
        normalized += "\x1f" + source_host_id + "\x1f" + source_host_family
    return stable_hash(normalized)


def _record_fingerprint(record: SourceRecord, source_host_id: str = "", source_host_family: str = "") -> str:
    fields = (
        record.source_kind,
        record.title.strip(),
        record.claim.strip(),
        record.cwd.strip(),
        record.domain.strip(),
        record.outcome_status.strip(),
        record.benefit.strip(),
        record.classification.strip(),
        "\x1f".join(item.strip() for item in record.applicability),
        record.parser_status,
        source_host_id or record.source_host_id,
        source_host_family or record.source_host_family,
    )
    return "sha256:" + stable_hash("\x1e".join(fields))


def _metadata_for_path(
    path: Path,
    parser_version: str,
    content_hash: str | None = None,
    *,
    source_host_id: str = "",
    source_host_family: str = "",
) -> dict[str, Any]:
    try:
        before = path.stat()
        content = path.read_bytes() if not content_hash else None
        after = path.stat()
    except (OSError, ValueError):
        return {
            "source_path_hash": stable_hash(str(path.resolve(strict=False))),
            "size_bytes": None,
            "mtime_ns": None,
            "content_hash": content_hash or "",
            "parser_version": parser_version,
            "source_host_id": source_host_id,
            "source_host_family": source_host_family,
        }
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError("SOURCE_CHANGED_DURING_READ")
    return {
        "source_path_hash": stable_hash(str(path.resolve())),
        "size_bytes": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "content_hash": content_hash or "sha256:" + hashlib.sha256(content).hexdigest(),
        "parser_version": parser_version,
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
    }


def _metadata_for_record(record: SourceRecord, parser_version: str) -> dict[str, Any]:
    path = Path(record.source_ref)
    if path.exists() and path.is_file():
        return _metadata_for_path(
            path,
            parser_version,
            record.source_hash,
            source_host_id=record.source_host_id,
            source_host_family=record.source_host_family,
        )
    return {
        "source_path_hash": stable_hash(unicodedata.normalize("NFKC", record.source_ref)),
        "size_bytes": None,
        "mtime_ns": None,
        "content_hash": record.source_hash,
        "parser_version": parser_version,
        "source_host_id": record.source_host_id,
        "source_host_family": record.source_host_family,
    }


def _same_source(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    previous_path_hash = previous.get("source_path_hash", previous.get("source_ref_hash"))
    previous_size = previous.get("size_bytes", previous.get("size"))
    return (
        previous_path_hash == current["source_path_hash"]
        and previous_size == current["size_bytes"]
        and previous.get("mtime_ns") == current["mtime_ns"]
        and previous.get("content_hash", previous.get("source_hash", "")) == current["content_hash"]
        and previous.get("parser_version") == current["parser_version"]
        and previous.get("source_host_id", "") == current.get("source_host_id", "")
        and previous.get("source_host_family", "") == current.get("source_host_family", "")
    )


def _event_for_record(
    record: SourceRecord,
    record_fp: str,
    settings: Settings,
    capture_path: str,
    *,
    source_host_id: str = "",
    source_host_family: str = "",
) -> Event:
    observation_id = "obs_" + record_fp.removeprefix("sha256:")[:24]
    provenance_key = record.provenance_key or "source:" + stable_hash(record.source_ref)[:24]
    payload = {
        "observation_id": observation_id,
        "title": record.title,
        "claim": record.claim,
        "source_kind": record.source_kind,
        "source_ref_hash": fingerprint(record.source_ref),
        "source_hash": _persisted_hash(record.source_hash),
        "cwd_fingerprint": fingerprint(record.cwd) if record.cwd else "",
        "domain": record.domain,
        "outcome_status": record.outcome_status,
        "benefit": record.benefit,
        "classification": record.classification,
        "applicability": list(record.applicability),
        "provenance_key": provenance_key,
        "record_fingerprint": record_fp,
        "parser_status": record.parser_status,
        "capture_path": capture_path,
        "source_host_id": source_host_id,
        "source_host_family": source_host_family,
        "applicability_scope": "host",
        "applicable_host_ids": [source_host_id],
        "applicable_host_families": [],
    }
    return Event.create(
        event_type="observation.recorded",
        occurred_at=record.observed_at,
        actor="ingest",
        machine_id=machine_id(),
        payload=payload,
    )


def _adapter_health(adapter: SourceAdapter) -> Mapping[str, int]:
    value = getattr(adapter, "health", {})
    if not isinstance(value, Mapping):
        return {}
    return {key: int(value[key]) for key in value if isinstance(key, str) and type(value[key]) is int and value[key] >= 0}


@contextmanager
def source_coordination(settings: Settings, *, wait: bool = True, budget=None):
    """Lock order: source coordination, then pending/receipt capture lock."""
    if budget is not None:
        budget.check()
    root = safe_ensure_directory(settings.paths.local_state_dir / "source-coordination")
    path = assert_safe_target(root, root / ".source.lock", allow_missing=True, expected_type="file")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    locked = False
    try:
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        opened, current = os.fstat(descriptor), path.stat(follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("SOURCE_LOCK_CHANGED")
        started = time.monotonic()
        while not locked:
            if budget is not None:
                budget.check()
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                if not wait or time.monotonic() - started >= 5:
                    raise
                time.sleep(min(0.01, budget.remaining_ms() / 1000) if budget is not None else 0.01)
        yield root
    finally:
        try:
            if locked:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _record_index(settings, record, parser_version):
    root = safe_ensure_directory(settings.paths.local_state_dir / "source-records")
    key = stable_hash(json.dumps([record.source_ref, record.source_host_id, record.source_host_family,
        parser_version, _record_fingerprint(record)], ensure_ascii=False))
    return root, assert_safe_target(root, root / (key + ".json"), allow_missing=True), key


def _read_record_plan(root, path, observation, budget=None):
    if budget is not None:
        budget.check()
    if not path.exists():
        return None
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    if path.stat().st_size > 16384:
        raise ValueError("SOURCE_INDEX_INVALID")
    value = json.loads(path.read_bytes())
    digest = stable_hash(json.dumps(asdict(observation), sort_keys=True, ensure_ascii=False))
    if not isinstance(value, dict) or value.get("observation_hash") != digest or value.get("route") not in {"event", "capture"}:
        raise ValueError("SOURCE_INDEX_INVALID")
    fields = {"observation_hash", "route", "occurred_at"} | ({"identity"} if value["route"] == "capture" else set())
    if set(value) != fields or not isinstance(value["occurred_at"], str):
        raise ValueError("SOURCE_INDEX_INVALID")
    try:
        moment = datetime.fromisoformat(value["occurred_at"].replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("SOURCE_INDEX_INVALID")
        if value["route"] == "capture" and capture_key(CaptureIdentity(**value["identity"])) is None:
            raise ValueError("SOURCE_INDEX_INVALID")
    except (TypeError, ValueError) as exc:
        raise ValueError("SOURCE_INDEX_INVALID") from exc
    return value


def _write_record_plan(root, path, value, budget=None):
    if budget is not None:
        budget.check()
    safe_atomic_write(root, path, json.dumps(value, sort_keys=True).encode("utf-8"), mode=0o600)


def _bound_identity(settings, record, parser_version, key, *, identity=None, binding_root=None, limit=2_097_152, require_existing=False, budget=None):
    if budget is not None:
        budget.check()
    root = safe_ensure_directory(settings.paths.local_state_dir / "source-bindings")
    scope = [record.source_ref, record.source_host_id, record.source_host_family, parser_version]
    path = assert_safe_target(root, root / (stable_hash(json.dumps(scope)) + ".json"), allow_missing=True)
    value = None
    if path.exists():
        if path.stat().st_size > limit:
            raise ValueError("SOURCE_BINDING_LIMIT")
        value = json.loads(path.read_bytes())
        if (not isinstance(value, dict) or set(value) != {"scope", "root", "host_id", "instance_hash", "store_id", "records"}
                or value["scope"] != fingerprint(scope) or value["host_id"] != record.source_host_id
                or not isinstance(value["records"], dict)):
            raise ValueError("SOURCE_BINDING_INVALID")
        assert_safe_target(Path(value["root"]), Path(record.source_ref), allow_missing=False, expected_type="file")
        capture_key(CaptureIdentity(value["host_id"], value["instance_hash"], value["store_id"], None, None, None))
        if identity is not None and (value["root"] != str(binding_root) or value["instance_hash"] != identity.instance_hash or value["store_id"] != identity.store_id):
            raise ValueError("SOURCE_BINDING_CONFLICT")
    elif require_existing:
        raise ValueError("SOURCE_BINDING_MISSING")
    elif identity is not None:
        value = dict(scope=fingerprint(scope), root=str(binding_root), host_id=identity.host_id,
            instance_hash=identity.instance_hash, store_id=identity.store_id, records={})
    if value is None:
        return None
    if key in value["records"]:
        saved = value["records"][key]
        if not isinstance(saved, list) or len(saved) != 3:
            raise ValueError("SOURCE_BINDING_INVALID")
        selected = CaptureIdentity(value["host_id"], value["instance_hash"], value["store_id"], saved[0], saved[1], saved[2])
    else:
        if not record.stable_record_id:
            raise ValueError("SOURCE_RECORD_ID_UNKNOWN")
        relative = Path(record.source_ref).relative_to(Path(value["root"])).as_posix()
        selected = identity or CaptureIdentity(value["host_id"], value["instance_hash"], value["store_id"],
            fingerprint(record.session_id) if record.session_id else None,
            fingerprint(record.turn_id) if record.turn_id else None,
            fingerprint(json.dumps([relative, parser_version, record.source_hash, record.stable_record_id])))
        value["records"][key] = [selected.session_hash, selected.turn_hash, selected.record_hash]
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")
        if len(encoded) > limit:
            raise ValueError("SOURCE_BINDING_LIMIT")
        _write_record_plan(root, path, value, budget=budget)
    if capture_key(selected) is None:
        raise ValueError("SOURCE_BINDING_INVALID")
    return selected


def _planned_event(settings, record, parser_version, capture_path, key, plan=None, budget=None):
    if budget is not None:
        budget.check()
    event = _event_for_record(record, _record_fingerprint(record), settings, capture_path,
        source_host_id=record.source_host_id, source_host_family=record.source_host_family)
    stamp = datetime.fromisoformat((plan or {}).get("occurred_at", event.occurred_at).replace("Z", "+00:00"))
    event = replace(event, event_id="evt_" + stamp.strftime("%Y%m%dT%H%M%S%fZ") + "_" + key[:12], occurred_at=stamp.isoformat())
    path = settings.paths.event_dir / stamp.strftime("%Y") / stamp.strftime("%m") / (event.event_id + ".json")
    if path.exists():
        assert_safe_target(settings.paths.event_dir, path, allow_missing=False, expected_type="file")
        if path.stat().st_size > 2_097_152:
            raise ValueError("SOURCE_EVENT_LIMIT")
        stored = read_event(path, budget=budget)
        # Unchanged normalized content can outlive a different whole-file version.
        fields = set(event.payload) - {"source_hash", "provenance_key"}
        if stored.event_id != event.event_id or stored.event_type != event.event_type or any(stored.payload.get(k) != event.payload[k] for k in fields):
            raise ValueError("SOURCE_EVENT_MISMATCH")
        return stored, path
    return event, None


def coordinate_record(settings, record, parser_version, capture_path, observation, *, identity=None, binding_root=None, now=None, metadata_limit=2_097_152, budget=None):
    """The caller holds source_coordination. Route ownership precedes payload writes."""
    now = now or datetime.now(timezone.utc)
    if budget is not None:
        budget.check()
    root, path, key = _record_index(settings, record, parser_version)
    plan = _read_record_plan(root, path, observation, budget=budget)
    bound = _bound_identity(settings, record, parser_version, key, identity=identity, binding_root=binding_root,
        limit=metadata_limit, require_existing=plan is not None and plan["route"] == "capture", budget=budget)
    if plan is None:
        _, existing = _planned_event(settings, record, parser_version, capture_path, key, budget=budget)
        # A legacy cursor fingerprint alone cannot establish durable success.
        # Unverifiable historical records defer rather than creating a second copy.
        if budget is not None:
            budget.check()
        cursor = _load_cursor(_cursor_path(settings), max_bytes=metadata_limit)
        previous = cursor["sources"].get(_source_key(record.source_ref, record.source_host_id, record.source_host_family), {})
        if existing is None and previous.get("parser_version") == parser_version and _record_fingerprint(record) in previous.get("record_fingerprints", []):
            raise ValueError("SOURCE_LEGACY_EVIDENCE_UNKNOWN")
        plan = {"observation_hash": stable_hash(json.dumps(asdict(observation), sort_keys=True, ensure_ascii=False)),
                "route": "capture" if bound is not None and existing is None else "event", "occurred_at": record.observed_at}
        if plan["route"] == "capture":
            plan["identity"] = asdict(bound)
        _write_record_plan(root, path, plan, budget=budget)
    if plan["route"] == "capture":
        trusted = CaptureIdentity(**plan["identity"])
        if trusted.host_id != record.source_host_id or capture_key(trusted) is None or bound != trusted:
            raise ValueError("SOURCE_INDEX_IDENTITY_INVALID")
        result = accept_candidate(settings, trusted, observation, now=now, budget=budget, origin="NATIVE_SOURCE")
        if identity is not None and result.state == "SECURED" and capture_key(identity) != result.capture_id:
            result = record_receipt(settings, replace(result, capture_id=capture_key(identity), covered_target_ids=()), budget=budget)
        return result, None, False
    event, existing = _planned_event(settings, record, parser_version, capture_path, key, plan, budget=budget)
    if existing is None:
        if budget is not None:
            budget.check()
        append_event(event, settings.paths.event_dir, budget=budget)
    if identity is not None:
        receipt = record_receipt(settings, CaptureReceipt(capture_key(identity), "SECURED", (event.event_id,), (),
            "SOURCE_EVENT_SECURED", now, ((event.event_id, fingerprint(json.dumps(event.payload, sort_keys=True))),)), budget=budget)
        return receipt, event, existing is None
    return None, event, existing is None


def ingest_sources(settings: Settings, adapters: Iterable[SourceAdapter]) -> IngestResult:
    with source_coordination(settings):
        return _ingest_sources(settings, adapters)


def _ingest_sources(settings: Settings, adapters: Iterable[SourceAdapter]) -> IngestResult:
    """Ingest normalized records idempotently while preserving source immutability."""
    cursor_path = _cursor_path(settings)
    cursor = _load_cursor(cursor_path)
    sources = cursor.setdefault("sources", {})
    created = 0
    skipped = 0
    parse_skipped = 0
    rejected = 0
    event_ids: list[str] = []
    health: dict[str, int] = {
        "parsed": 0,
        "excluded": 0,
        "unknown": 0,
        "parse_skipped": 0,
        "rejected": 0,
        **{capture_path: 0 for capture_path in _CAPTURE_PATHS},
    }

    for adapter in adapters:
        try:
            records = list(adapter.iter_records(cursor))
        except (OSError, UnicodeError, ValueError, TypeError):
            records = []
            parse_skipped += 1
            health["parse_skipped"] += 1
            health["unknown"] += 1
        adapter_health = _adapter_health(adapter)
        parse_count = max(int(getattr(adapter, "parse_skipped", 0)), adapter_health.get("parse_skipped", 0))
        parse_skipped += parse_count
        health["parse_skipped"] += parse_count
        health["excluded"] += adapter_health.get("excluded", 0)
        health["unknown"] += adapter_health.get("unsupported_format", 0)

        by_source: dict[str, list[SourceRecord]] = {}
        adapter_host_id = getattr(adapter, "host_id", "")
        adapter_host_family = getattr(adapter, "host_family", "")
        if not isinstance(adapter_host_id, str) or not isinstance(adapter_host_family, str):
            adapter_host_id = ""
            adapter_host_family = ""
        for record in records:
            if not isinstance(record, SourceRecord):
                parse_skipped += 1
                health["parse_skipped"] += 1
                continue
            health[_capture_path(record, adapter)] += 1
            by_source.setdefault(record.source_ref, []).append(record)
        source_paths = tuple(getattr(adapter, "sources", ()))
        known_refs = set(by_source)
        for raw_path in source_paths:
            if isinstance(raw_path, Path):
                known_refs.add(str(raw_path.resolve(strict=False)))
        for source_ref in sorted(known_refs):
            source_records = by_source.get(source_ref, [])
            parser_version = getattr(adapter, "parser_version", "unknown")
            adapter_pair: tuple[str, str] | None = None
            try:
                if adapter_host_id and adapter_host_family:
                    validate_host_label(adapter_host_id, field="source_host_id")
                    validate_host_label(adapter_host_family, field="source_host_family")
                    adapter_pair = (adapter_host_id, adapter_host_family)
            except ValueError:
                adapter_pair = None
            record_pairs: list[tuple[str, str] | None] = []
            for record in source_records:
                pair: tuple[str, str] | None = None
                record_host_id = record.source_host_id
                record_host_family = record.source_host_family
                try:
                    if bool(record_host_id) != bool(record_host_family):
                        raise ValueError("HOST_SOURCE_PAIR_INVALID")
                    if record_host_id and record_host_family:
                        validate_host_label(record_host_id, field="source_host_id")
                        validate_host_label(record_host_family, field="source_host_family")
                        pair = (record_host_id, record_host_family)
                        if adapter_pair is not None and pair != adapter_pair:
                            raise ValueError("HOST_SOURCE_PAIR_CONFLICT")
                    elif adapter_pair is not None:
                        pair = adapter_pair
                    else:
                        raise ValueError("HOST_SOURCE_PAIR_REQUIRED")
                except ValueError:
                    rejected += 1
                    health["rejected"] += 1
                record_pairs.append(pair)
            valid_pairs = [pair for pair in record_pairs if pair is not None]
            source_pair = adapter_pair or (valid_pairs[0] if valid_pairs else None)
            source_host_id, source_host_family = source_pair or ("", "")
            if source_records:
                metadata_source = next((record for record, pair in zip(source_records, record_pairs, strict=True) if pair is not None), None)
                if metadata_source is not None:
                    metadata = _metadata_for_record(metadata_source, parser_version)
                else:
                    metadata = _metadata_for_path(
                        Path(source_ref),
                        parser_version,
                        source_host_id=source_host_id,
                        source_host_family=source_host_family,
                    )
            else:
                try:
                    metadata = _metadata_for_path(
                        Path(source_ref),
                        parser_version,
                        source_host_id=adapter_host_id,
                        source_host_family=adapter_host_family,
                    )
                except (OSError, ValueError):
                    metadata = {
                        "source_path_hash": stable_hash(source_ref),
                        "size_bytes": None,
                        "mtime_ns": None,
                        "content_hash": "",
                        "parser_version": parser_version,
                        "source_host_id": adapter_host_id,
                        "source_host_family": adapter_host_family,
                    }
            metadata["source_host_id"] = source_host_id
            metadata["source_host_family"] = source_host_family
            key = _source_key(source_ref, source_host_id, source_host_family)
            legacy_key = _source_key(source_ref)
            previous = sources.get(key, {})
            migrated_legacy = False
            if key not in sources and legacy_key != key and legacy_key in sources:
                previous = dict(sources.pop(legacy_key))
                previous["source_host_id"] = source_host_id
                previous["source_host_family"] = source_host_family
                migrated_legacy = True
            if not isinstance(previous, Mapping):
                previous = {}
            if _same_source(previous, metadata) and all(pair is not None for pair in record_pairs):
                if migrated_legacy:
                    sources[key] = dict(previous)
                skipped += len(source_records)
                continue
            previous_fingerprints = (
                set(previous.get("record_fingerprints", []))
                if previous.get("parser_version") == parser_version
                else set()
            )
            current_fingerprints: list[str] = []
            last_event_id = ""
            deferred = False
            for record, pair in zip(source_records, record_pairs, strict=True):
                if pair is None:
                    continue
                source_host_id, source_host_family = pair
                record_fp = _record_fingerprint(record, source_host_id, source_host_family)
                current_fingerprints.append(record_fp)
                if record.parser_status != "parsed":
                    skipped += 1
                    health["excluded"] += 1
                    continue
                if record_fp in previous_fingerprints:
                    skipped += 1
                    continue
                observation = ObservationInput(
                    title=record.title,
                    claim=record.claim,
                    source_kind=record.source_kind,
                    source_ref=record.source_ref,
                    cwd=record.cwd,
                    domain=record.domain,
                    outcome_status=record.outcome_status,
                    benefit=record.benefit,
                    classification=record.classification,
                    applicability=record.applicability,
                    source_host_id=source_host_id,
                    source_host_family=source_host_family,
                )
                decision = inspect_observation(observation)
                if not decision.allow_private_sync or decision.classification.value in {"secret", "client-confidential", "machine-local"}:
                    rejected += 1
                    health["rejected"] += 1
                    continue
                scoped_record = replace(record, source_host_id=source_host_id, source_host_family=source_host_family)
                receipt, event, was_created = coordinate_record(settings, scoped_record, parser_version, _capture_path(record, adapter), observation)
                if receipt is not None and receipt.state != "SECURED":
                    deferred = True
                    current_fingerprints.remove(record_fp)
                    health["unknown"] += 1
                    continue
                if event is None:
                    skipped += 1
                    continue
                created += int(was_created)
                health["parsed"] += 1
                event_ids.append(event.event_id)
                last_event_id = event.event_id
            if deferred:
                continue
            sources[key] = {
                **dict(metadata),
                "source_ref_hash": fingerprint(source_ref),
                "parser_version": parser_version,
                "record_fingerprints": sorted(set(current_fingerprints)),
                "last_record_fingerprint": current_fingerprints[-1] if current_fingerprints else "",
                "last_event_id": last_event_id,
            }

    _atomic_write_json(cursor_path, cursor)
    return IngestResult(
        created_events=created,
        skipped_records=skipped,
        parse_skipped=parse_skipped,
        rejected_records=rejected,
        event_ids=tuple(event_ids),
        health=dict(sorted(health.items())),
    )


__all__ = ["CURSOR_VERSION", "IngestResult", "ingest_sources", "scan_read_only"]
