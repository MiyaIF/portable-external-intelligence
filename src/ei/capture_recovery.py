"""Bounded recovery from explicitly authorized structured sources."""
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .adapters.base import SourceAdapter, SourceRecord, is_readable_metadata_path
from .capture_contract import CaptureIdentity, CaptureReceipt, capture_key
from .capture_ledger import record_receipt
from .config import Settings
from .models import ObservationInput, validate_host_label
from .privacy import inspect_observation
from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory
from .ingest import source_coordination, coordinate_record
from .operation_runtime import OperationBudget


@dataclass(frozen=True)
class RecoverySource:
    source_id: str
    host_id: str
    instance_hash: str | None
    store_id: str | None
    root: Path
    adapter: SourceAdapter
    enumeration_verified: bool = False


@dataclass(frozen=True)
class RecoveryPage:
    scanned: int
    secured: int
    rejected: int
    coverage: str
    cursor_committed: bool
    reason_code: str
    created_events: int = 0


def unsupported_page() -> RecoveryPage:
    return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_ENUMERATION_UNVERIFIED")


class _SourceParseError(ValueError):
    """A format failure in an already-verified source byte stream."""


def _parsed_records(adapter, path, content, metadata, deadline):
    """Only format errors from the bytes-only parser are soft failures."""
    try:
        _before_deadline(deadline)
        records = iter(adapter.read_verified(path, content, metadata))
        while True:
            _before_deadline(deadline)
            try:
                record = next(records)
            except StopIteration:
                return
            yield record
    except TimeoutError:
        raise
    except (UnicodeError, ValueError) as exc:
        _before_deadline(deadline)
        raise _SourceParseError("SOURCE_PARTIAL") from exc


def recover_page(settings: Settings, source: RecoverySource, *, now: datetime,
                 max_records: int = 100, max_bytes: int = 2_097_152,
                 max_ms: int = 5000, budget=None) -> RecoveryPage:
    if not source.enumeration_verified:
        return unsupported_page()
    try:
        budget = OperationBudget(max_ms, deadline=budget.deadline if budget is not None else None)
        budget.check()
        with source_coordination(settings, wait=False, budget=budget):
            return _recover_page(settings, source, now=now, max_records=max_records, max_bytes=max_bytes, max_ms=max_ms, budget=budget)
    except TimeoutError:
        return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_TIME_LIMIT")
    except (OSError, ValueError, RuntimeError):
        return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_COORDINATION_UNAVAILABLE")


def _recover_page(settings: Settings, source: RecoverySource, *, now: datetime,
                  max_records: int, max_bytes: int, max_ms: int, budget=None) -> RecoveryPage:
    if not source.enumeration_verified:
        return unsupported_page()
    if not callable(getattr(source.adapter, "read_verified", None)) or not callable(getattr(source.adapter, "accepts_path", None)):
        return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_BYTES_UNSUPPORTED")
    if any(type(value) is not int or value <= 0 for value in (max_records, max_bytes, max_ms)):
        raise ValueError("SOURCE_BUDGET_INVALID")
    legacy = source.instance_hash is None and source.store_id is None
    if legacy:
        validate_host_label(source.host_id)
    else:
        capture_key(CaptureIdentity(source.host_id, source.instance_hash, source.store_id, None, None, None))
    deadline = budget.deadline
    scanned = secured = rejected = total_bytes = created_events = 0
    committed = False
    code = "SOURCE_CORRELATION_UNKNOWN"
    try:
        selected = assert_safe_target(source.root.parent, source.root, allow_missing=False)
        exact_file = selected.is_file()
        if exact_file and not is_readable_metadata_path(selected):
            raise ValueError("SOURCE_PATH_UNAUTHORIZED")
        root = selected.parent if exact_file else assert_safe_target(selected, selected, allow_root=True, allow_missing=False, expected_type="dir")
        state_root = safe_ensure_directory(settings.paths.local_state_dir / "capture-recovery")
        source_key = _hash(json.dumps([source.source_id, source.host_id, source.instance_hash, source.store_id, str(selected), source.adapter.parser_version]))
        cursor_path = state_root / (source_key[7:] + ".json")
        state = _load_state(state_root, cursor_path, max_bytes, budget=budget)
        if exact_file and state["frontier"] not in ([], [[selected.name, "file"]]):
            raise ValueError("SOURCE_CURSOR_INVALID")
        if not state["frontier"]:
            state = {"frontier": [[selected.name, "file"]] if exact_file else [[".", "dir"]], "file_version": "", "record_offset": 0}
        while state["frontier"]:
            _before_deadline(deadline)
            if scanned >= max_records:
                code = "SOURCE_RECORD_LIMIT"
                break
            relative, kind = state["frontier"][0]
            path = assert_safe_target(root, root / relative, allow_root=True, allow_missing=True, expected_type=kind)
            try:
                path.stat(follow_symlinks=False)
            except FileNotFoundError:
                # Only a confirmed disappearance retires a traversal entry.
                # Permission/type/reparse errors retain it for safe retry. This
                # is inventory repair, never an acknowledged candidate cursor.
                assert_safe_target(root, root, allow_root=True, allow_missing=False, expected_type="dir")
                assert_safe_target(root, path, allow_root=True, allow_missing=True, expected_type=kind)
                _before_deadline(deadline)
                state["frontier"].pop(0)
                state.update(file_version="", record_offset=0)
                _save_state(state_root, cursor_path, state, max_bytes)
                code = "SOURCE_ENTRY_MISSING"
                continue
            if kind == "dir":
                entries = []
                with os.scandir(path) as iterator:
                    for entry in iterator:
                        _before_deadline(deadline)
                        child = path / entry.name
                        # Denied directories are never traversed, including raw transcripts.
                        if not is_readable_metadata_path(child / "probe.md") and entry.is_dir(follow_symlinks=False):
                            continue
                        assert_safe_target(root, child, allow_missing=False)
                        if entry.is_dir(follow_symlinks=False):
                            entries.append([child.relative_to(root).as_posix(), "dir"])
                        elif entry.is_file(follow_symlinks=False) and is_readable_metadata_path(child) and source.adapter.accepts_path(child):
                            entries.append([child.relative_to(root).as_posix(), "file"])
                        _bounded_state({**state, "frontier": entries + state["frontier"][1:]}, max_bytes)
                state["frontier"] = sorted(entries) + state["frontier"][1:]
                _before_deadline(deadline)
                _save_state(state_root, cursor_path, state, max_bytes)
                continue
            before = path.stat(follow_symlinks=False)
            if before.st_size > max_bytes - total_bytes:
                code = "SOURCE_BYTE_LIMIT"
                break
            content, metadata = _read_verified(root, path, before, max_bytes - total_bytes, deadline)
            total_bytes += len(content)
            version = _hash(content)
            offset = state["record_offset"] if state["file_version"] == version else 0
            state["file_version"] = version
            state["record_offset"] = offset
            completed = True
            for index, record in enumerate(_parsed_records(source.adapter, path, content, metadata, deadline)):
                _before_deadline(deadline)
                if index < offset:
                    continue
                if scanned >= max_records:
                    code, completed = "SOURCE_RECORD_LIMIT", False
                    break
                scanned += 1
                if not isinstance(record, SourceRecord) or not record.stable_record_id or record.parser_status != "parsed":
                    code, completed = "SOURCE_RECORD_ID_UNKNOWN", False
                    break
                if record.source_host_id != source.host_id or record.source_ref != str(path) or record.source_hash != version:
                    code, completed = "SOURCE_RECORD_SCOPE_MISMATCH", False
                    break
                identity = None if legacy else CaptureIdentity(source.host_id, source.instance_hash, source.store_id,
                    _hash(record.session_id) if record.session_id else None,
                    _hash(record.turn_id) if record.turn_id else None,
                    _hash(json.dumps([relative, source.adapter.parser_version, version, record.stable_record_id])))
                observation = _observation(record)
                privacy = inspect_observation(observation)
                if legacy and (not privacy.allow_private_sync or privacy.classification.value in {"secret", "client-confidential", "machine-local"}):
                    rejected += 1
                else:
                    result, event, was_created = coordinate_record(settings, record, source.adapter.parser_version,
                        source.adapter.capture_path, observation, identity=identity, binding_root=root,
                        now=now, metadata_limit=max_bytes, budget=budget)
                    budget.check()
                    if result is not None and result.state == "SECURED" or result is None and event is not None:
                        secured += 1
                        created_events += int(event is not None and was_created)
                    elif identity is not None and (not privacy.allow_private_sync or observation.classification not in {"public", "private-reusable"}):
                        result = record_receipt(settings, CaptureReceipt(capture_key(identity), "UNAVAILABLE", (), (), "SOURCE_PRIVACY_REJECTED", now), budget=budget)
                        rejected += 1
                    else:
                        code, completed = result.reason_code if result is not None else "SOURCE_DURABILITY_UNKNOWN", False
                        break
                state["record_offset"] = index + 1
                budget.check()
                _save_state(state_root, cursor_path, state, max_bytes)
                committed = True
            if not completed:
                break
            _before_deadline(deadline)
            state["frontier"].pop(0)
            state.update(file_version="", record_offset=0)
            _save_state(state_root, cursor_path, state, max_bytes)
    except TimeoutError:
        code = "SOURCE_TIME_LIMIT"
    except _SourceParseError:
        code = "SOURCE_PARTIAL"
        source.adapter.parse_skipped += 1
        health = getattr(source.adapter, "health", None)
        if isinstance(health, dict):
            for name in ("parse_skipped", "unsupported_format"):
                health[name] = int(health.get(name, 0)) + 1
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        code = str(exc) if str(exc) in {"SOURCE_FRONTIER_LIMIT", "SOURCE_BINDING_LIMIT", "SOURCE_BINDING_MISSING", "SOURCE_BINDING_INVALID", "SOURCE_BINDING_CONFLICT", "SOURCE_LEGACY_CURSOR_LIMIT", "SOURCE_LEGACY_EVIDENCE_UNKNOWN", "SOURCE_INDEX_INVALID", "SOURCE_EVENT_MISMATCH", "SOURCE_CHANGED_DURING_READ"} else "SOURCE_READ_OR_STATE_UNAVAILABLE"
    return RecoveryPage(scanned, secured, rejected, "UNKNOWN", committed, code, created_events)


def _hash(value: str | bytes) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _before_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("SOURCE_TIME_LIMIT")


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _read_verified(root: Path, path: Path, before: os.stat_result, limit: int, deadline: float) -> tuple[bytes, os.stat_result]:
    """Validate parents, handle identity and metadata before reading any bytes."""
    _before_deadline(deadline)
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    if before.st_size > limit or _signature(path.stat(follow_symlinks=False)) != _signature(before):
        raise ValueError("SOURCE_CHANGED_DURING_READ")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if not stat.S_ISREG(opened.st_mode) or _signature(opened) != _signature(before) or _signature(path.stat(follow_symlinks=False)) != _signature(before):
            raise ValueError("SOURCE_CHANGED_DURING_READ")
        chunks = []
        remaining = before.st_size
        while remaining:
            _before_deadline(deadline)
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise ValueError("SOURCE_CHANGED_DURING_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if _signature(os.fstat(stream.fileno())) != _signature(before) or _signature(path.stat(follow_symlinks=False)) != _signature(before):
            raise ValueError("SOURCE_CHANGED_DURING_READ")
    _before_deadline(deadline)
    return b"".join(chunks), before


def _bounded_state(state: dict, limit: int) -> bytes:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > limit:
        raise ValueError("SOURCE_FRONTIER_LIMIT")
    return encoded


def _load_state(root: Path, path: Path, limit: int, budget=None) -> dict:
    if budget is not None:
        budget.check()
    assert_safe_target(root, path, allow_missing=True, expected_type="file")
    if not path.exists():
        return {"frontier": [], "file_version": "", "record_offset": 0}
    if path.stat().st_size > limit:
        raise ValueError("SOURCE_FRONTIER_LIMIT")
    state = json.loads(path.read_bytes())
    if (not isinstance(state, dict) or set(state) != {"frontier", "file_version", "record_offset"}
            or not isinstance(state["frontier"], list) or not isinstance(state["file_version"], str)
            or type(state["record_offset"]) is not int or state["record_offset"] < 0):
        raise ValueError("SOURCE_CURSOR_INVALID")
    for entry in state["frontier"]:
        if budget is not None:
            budget.check()
        if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str) or entry[1] not in {"file", "dir"}:
            raise ValueError("SOURCE_CURSOR_INVALID")
    return state


def _save_state(root: Path, path: Path, state: dict, limit: int) -> None:
    safe_atomic_write(root, path, _bounded_state(state, limit), mode=0o600)


def _observation(record: SourceRecord) -> ObservationInput:
    return ObservationInput(title=record.title, claim=record.claim, source_kind=record.source_kind,
        source_ref=record.source_ref, cwd=record.cwd, domain=record.domain,
        outcome_status=record.outcome_status, benefit=record.benefit, classification=record.classification,
        applicability=record.applicability, source_host_id=record.source_host_id, source_host_family=record.source_host_family)
