"""Bounded recovery from explicitly authorized structured sources."""
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from .adapters.base import SourceAdapter, SourceRecord, is_readable_metadata_path
from .capture_contract import CaptureIdentity, CaptureReceipt, capture_key
from .capture_ledger import record_receipt
from .config import Settings
from .models import ObservationInput, validate_host_label
from .privacy import inspect_observation
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory
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


@dataclass(frozen=True)
class WorkRecordTail:
    """A bounded complete-line slice from one verified append-only session."""

    root: Path
    path: Path
    cursor_path: Path
    source_key: str
    namespace_hash: str
    file_id: tuple[int, int]
    offset: int
    data: bytes
    complete_end: int
    partial_tail: bool
    metadata_hash: str
    session_hash: str
    project_hash: str
    session_no_save: bool
    data_offset: int
    scan_offset: int
    scan_end: int
    raw_data: bytes
    oversized_turn: bool
    discarding_line: bool
    next_discarding_line: bool
    overflow_line: bool
    page_full: bool
    pending_capture_id: str = ""
    pending_content_hash: str = ""


def unsupported_page() -> RecoveryPage:
    return RecoveryPage(0, 0, 0, "UNKNOWN", False, "SOURCE_ENUMERATION_UNVERIFIED")


class _SourceParseError(ValueError):
    """A format failure in an already-verified source byte stream."""


def _canonical_source_path(root: Path, target: Path) -> Path:
    """Canonicalize only while the validated lexical source identity remains stable."""
    lexical = assert_safe_target(root, target, allow_missing=False)

    def identity(path: Path) -> tuple[int, int, int]:
        info = path.stat(follow_symlinks=False)
        return info.st_dev, info.st_ino, info.st_mode

    before = identity(lexical)
    canonical = lexical.resolve(strict=True)
    resolved = identity(canonical)
    try:
        checked = assert_safe_target(root, target, allow_missing=False)
    except SafeFilesystemError as exc:
        raise ValueError("SOURCE_CHANGED_DURING_READ") from exc
    after = identity(checked)
    if before != resolved or before != after:
        raise ValueError("SOURCE_CHANGED_DURING_READ")
    return canonical


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
        selected = _canonical_source_path(source.root.parent, source.root)
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


def _read_work_record_cursor(root: Path, path: Path, *, budget=None) -> dict | None:
    selected = assert_safe_target(root, path, allow_missing=True, expected_type="file")
    if not selected.exists():
        return None
    before = selected.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > 262144:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    raw, _ = _read_range_verified(root, selected, before, 0, before.st_size, budget=budget)
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("WORK_RECORD_CURSOR_INVALID") from exc
    old_fields = {"schema_version", "source_key", "namespace_hash", "file_id", "offset", "anchor_hash",
                  "metadata_hash", "session_hash", "project_hash"}
    fields_v2 = old_fields | {"session_no_save"}
    fields_v3 = fields_v2 | {"scan_offset", "scan_anchor_hash", "scan_segments", "oversized_turn", "discarding_line"}
    fields_v4 = fields_v3 | {"pending_capture_id", "pending_content_hash"}
    if (not isinstance(state, dict) or frozenset(state) not in {frozenset(old_fields), frozenset(fields_v2), frozenset(fields_v3), frozenset(fields_v4)}
            or state["schema_version"] not in {1, 2, 3, 4}
            or any(not isinstance(state[name], str) for name in ("source_key", "namespace_hash", "anchor_hash"))
            or not isinstance(state["file_id"], list) or len(state["file_id"]) != 2
            or any(type(value) is not int for value in state["file_id"])
            or type(state["offset"]) is not int or state["offset"] < 0
            or any(not isinstance(state[name], str) for name in ("metadata_hash", "session_hash", "project_hash"))):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if "session_no_save" not in state:
        state["session_no_save"] = False
    if type(state["session_no_save"]) is not bool:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if "scan_offset" not in state:
        state.update(scan_offset=state["offset"], scan_anchor_hash=state["anchor_hash"], scan_segments=[],
                     oversized_turn=False, discarding_line=False)
    if (type(state["scan_offset"]) is not int or state["scan_offset"] < state["offset"]
            or not isinstance(state["scan_anchor_hash"], str)
            or not isinstance(state["scan_segments"], list) or len(state["scan_segments"]) > 4096
            or type(state["oversized_turn"]) is not bool or type(state["discarding_line"]) is not bool):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    scan_position = state["offset"]
    for segment in state["scan_segments"]:
        if (not isinstance(segment, list) or len(segment) != 3 or type(segment[0]) is not int
                or type(segment[1]) is not int or segment[0] != scan_position or segment[1] <= segment[0]
                or segment[1] > state["scan_offset"] or not isinstance(segment[2], str)
                or not segment[2].startswith("sha256:")):
            raise ValueError("WORK_RECORD_CURSOR_INVALID")
        scan_position = segment[1]
    if scan_position != state["scan_offset"]:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if state["offset"] == 0 and state["anchor_hash"] != _hash(b""):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if state["scan_offset"] == 0 and state["scan_anchor_hash"] != _hash(b""):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if "pending_capture_id" not in state:
        state.update(pending_capture_id="", pending_content_hash="")
    pending_id = state["pending_capture_id"]
    pending_hash = state["pending_content_hash"]
    if (not isinstance(pending_id, str) or not isinstance(pending_hash, str)
            or bool(pending_id) != bool(pending_hash)
            or (pending_id and (len(pending_id) != 71 or not pending_id.startswith("sha256:")
                                or any(char not in "0123456789abcdef" for char in pending_id[7:])))
            or (pending_hash and (len(pending_hash) != 71 or not pending_hash.startswith("sha256:")
                                  or any(char not in "0123456789abcdef" for char in pending_hash[7:])))):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    return state


def _valid_work_record_relative_path(value: str) -> bool:
    if (not isinstance(value, str) or not value or len(value) > 1024 or "\\" in value):
        return False
    path = PurePosixPath(value)
    parts = path.parts
    return (not path.is_absolute() and path.as_posix() == value and len(parts) == 4
            and len(parts[0]) == 4 and parts[0].isdigit()
            and len(parts[1]) == 2 and parts[1].isdigit()
            and len(parts[2]) == 2 and parts[2].isdigit()
            and parts[3].startswith("rollout-") and parts[3].casefold().endswith(".jsonl"))


def read_work_record_page_cursor(settings: Settings, namespace_hash: str, *, budget=None) -> str:
    if not isinstance(namespace_hash, str) or not namespace_hash.startswith("sha256:"):
        raise ValueError("WORK_RECORD_NAMESPACE_INVALID")
    root = safe_ensure_directory(settings.paths.local_state_dir / "capture-recovery")
    path = root / ("work-record-page-" + namespace_hash[7:] + ".json")
    selected = assert_safe_target(root, path, allow_missing=True, expected_type="file")
    if not selected.exists():
        return ""
    before = selected.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > 1024:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    raw, _ = _read_range_verified(root, selected, before, 0, before.st_size, budget=budget)
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("WORK_RECORD_CURSOR_INVALID") from exc
    if (isinstance(state, dict) and set(state) == {"schema_version", "namespace_hash", "last_path_hash"}
            and state["schema_version"] == 1 and state["namespace_hash"] == namespace_hash
            and isinstance(state["last_path_hash"], str)
            and (not state["last_path_hash"] or state["last_path_hash"].startswith("sha256:"))):
        return ""
    if (not isinstance(state, dict) or set(state) != {"schema_version", "namespace_hash", "last_relative_path"}
            or state["schema_version"] != 2 or state["namespace_hash"] != namespace_hash
            or (state["last_relative_path"] and not _valid_work_record_relative_path(state["last_relative_path"]))):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    return state["last_relative_path"]


def commit_work_record_page_cursor(settings: Settings, namespace_hash: str, last_relative_path: str, *, budget=None) -> None:
    if (not isinstance(namespace_hash, str) or not namespace_hash.startswith("sha256:")
            or not isinstance(last_relative_path, str)
            or (last_relative_path and not _valid_work_record_relative_path(last_relative_path))):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if budget is not None:
        budget.check()
    root = safe_ensure_directory(settings.paths.local_state_dir / "capture-recovery")
    path = root / ("work-record-page-" + namespace_hash[7:] + ".json")
    state = {"schema_version": 2, "namespace_hash": namespace_hash, "last_relative_path": last_relative_path}
    safe_atomic_write(root, path, _bounded_state(state, 1024), mode=0o600)


def read_work_record_tail(settings: Settings, source_root: Path, path: Path, *, host_id: str,
                          namespace: tuple[str, str], max_bytes: int = 1_048_576,
                          budget=None) -> WorkRecordTail:
    """Read only new complete JSONL lines and a small verified metadata anchor.

    Cursor state is versioned in the existing capture-recovery directory and
    contains hashes/offsets only, never conversation text.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= 2_097_152:
        raise ValueError("WORK_RECORD_BUDGET_INVALID")
    if (not isinstance(namespace, tuple) or len(namespace) != 2
            or any(not isinstance(item, str) or not item.startswith("sha256:") for item in namespace)):
        raise ValueError("WORK_RECORD_NAMESPACE_INVALID")
    root = assert_safe_target(source_root.parent, source_root, allow_root=False, allow_missing=False, expected_type="dir")
    selected = _canonical_source_path(root, path)
    relative = selected.relative_to(root).as_posix()
    if not selected.name.startswith("rollout-") or selected.suffix.casefold() != ".jsonl":
        raise ValueError("WORK_RECORD_SOURCE_UNAUTHORIZED")
    before = selected.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("WORK_RECORD_SOURCE_UNAUTHORIZED")
    file_id = (before.st_dev, before.st_ino)
    namespace_hash = _hash(json.dumps(namespace, separators=(",", ":")))
    source_key = _hash(json.dumps([host_id, namespace_hash, relative], separators=(",", ":")))
    state_root = safe_ensure_directory(settings.paths.local_state_dir / "capture-recovery")
    cursor_path = state_root / ("work-record-" + source_key[7:] + ".json")
    assert_safe_target(state_root, cursor_path, allow_missing=True, expected_type="file")
    if budget is not None:
        budget.check()
    state = _read_work_record_cursor(state_root, cursor_path, budget=budget)
    if state is not None:
        if state["source_key"] != source_key or state["namespace_hash"] != namespace_hash:
            raise ValueError("WORK_RECORD_CURSOR_INVALID")
        if tuple(state["file_id"]) != file_id or before.st_size < state["scan_offset"]:
            raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    else:
        state = {"schema_version": 4, "source_key": source_key, "namespace_hash": namespace_hash,
                 "file_id": list(file_id), "offset": 0, "anchor_hash": _hash(b""),
                 "metadata_hash": "", "session_hash": "", "project_hash": "", "session_no_save": False,
                 "scan_offset": 0, "scan_anchor_hash": _hash(b""), "scan_segments": [],
                 "oversized_turn": False, "discarding_line": False,
                 "pending_capture_id": "", "pending_content_hash": ""}

    # The first metadata line is the CLI/session/project anchor. Recheck its
    # digest after restart instead of trusting the path or an organizer ID.
    first_line, _ = _read_range_verified(root, selected, before, 0, min(before.st_size, 65537), budget=budget)
    first_end = first_line.find(b"\n")
    if first_end < 0:
        raise ValueError("WORK_RECORD_METADATA_INCOMPLETE")
    metadata_hash = _hash(first_line[:first_end + 1])
    if state["metadata_hash"] and state["metadata_hash"] != metadata_hash:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    offset = state["offset"]
    anchor_start = max(0, offset - 128)
    anchor, _ = _read_range_verified(root, selected, before, anchor_start, offset - anchor_start, budget=budget)
    if _hash(anchor) != state["anchor_hash"] or (offset and not anchor.endswith(b"\n")):
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    scan_offset = state["scan_offset"]
    scan_anchor_start = max(0, scan_offset - 128)
    scan_anchor, _ = _read_range_verified(root, selected, before, scan_anchor_start,
        scan_offset - scan_anchor_start, budget=budget)
    if _hash(scan_anchor) != state["scan_anchor_hash"]:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    remaining = before.st_size - scan_offset
    raw, _ = _read_range_verified(root, selected, before, scan_offset, min(remaining, max_bytes), budget=budget)
    complete = b""
    data_offset = scan_offset
    scan_end = scan_offset
    next_discarding_line = state["discarding_line"]
    overflow_line = state["discarding_line"]
    page_full = len(raw) == max_bytes and remaining > len(raw)
    if state["discarding_line"]:
        newline = raw.find(b"\n")
        if newline >= 0:
            skipped_line_end = scan_offset + newline + 1
            suffix = raw[newline + 1:]
            suffix_newline = suffix.rfind(b"\n")
            complete = suffix[:suffix_newline + 1] if suffix_newline >= 0 else b""
            data_offset = skipped_line_end
            scan_end = data_offset + len(complete)
            next_discarding_line = False
        elif page_full:
            scan_end = scan_offset + len(raw)
        else:
            next_discarding_line = True
            scan_end = scan_offset + len(raw)
    elif raw:
        last_newline = raw.rfind(b"\n")
        if last_newline >= 0:
            complete = raw[:last_newline + 1]
            scan_end = scan_offset + len(complete)
            # A JSONL record larger than the extraction text budget cannot be
            # retained as a partial conversation. Stop at its start so the
            # next bounded pass can discard it while preserving later turns.
            partial_record = len(raw) - last_newline - 1
            if page_full and partial_record > min(32768, max_bytes // 32):
                overflow_line = True
        elif page_full:
            if scan_offset == 0:
                raise ValueError("WORK_RECORD_METADATA_LIMIT")
            overflow_line = True
            next_discarding_line = True
            scan_end = scan_offset + len(raw)
    raw_data = raw[:max(0, scan_end - scan_offset)]
    return WorkRecordTail(root, selected, cursor_path, source_key, namespace_hash, file_id, offset, complete,
                          data_offset + len(complete), scan_end < scan_offset + len(raw), metadata_hash,
                          state["session_hash"], state["project_hash"], state["session_no_save"],
                          data_offset, scan_offset, scan_end, raw_data, state["oversized_turn"],
                          state["discarding_line"], next_discarding_line, overflow_line, page_full,
                          state["pending_capture_id"], state["pending_content_hash"])


def commit_work_record_cursor(settings: Settings, tail: WorkRecordTail, offset: int, *,
                              session_hash: str, project_hash: str, session_no_save: bool | None = None,
                              budget=None) -> None:
    """Acknowledge a processed newline boundary after durable handoff/valid zero."""
    if (type(offset) is not int or not tail.offset <= offset <= tail.complete_end
            or (offset != tail.offset and (offset <= tail.scan_offset
                or tail.raw_data[offset - tail.scan_offset - 1:offset - tail.scan_offset] != b"\n"))
            or not isinstance(session_hash, str) or not session_hash.startswith("sha256:")
            or not isinstance(project_hash, str) or not project_hash.startswith("sha256:")):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if budget is not None:
        budget.check()
    existing = _read_work_record_cursor(tail.cursor_path.parent, tail.cursor_path, budget=budget)
    durable_no_save = (existing["session_no_save"] if existing is not None else tail.session_no_save)
    if session_no_save is not None:
        if type(session_no_save) is not bool:
            raise ValueError("WORK_RECORD_CURSOR_INVALID")
        durable_no_save = durable_no_save or session_no_save
    current = tail.path.stat(follow_symlinks=False)
    if existing is not None:
        if (existing["source_key"] != tail.source_key or existing["namespace_hash"] != tail.namespace_hash
                or tuple(existing["file_id"]) != tail.file_id or existing["metadata_hash"] != tail.metadata_hash
                or existing["offset"] < tail.offset or existing["offset"] > offset
                or existing["scan_offset"] < tail.scan_offset or existing["scan_offset"] > offset
                or existing["session_hash"] not in {"", session_hash}
                or existing["project_hash"] not in {"", project_hash}):
            raise ValueError("WORK_RECORD_CURSOR_INVALID")
    elif tail.offset != 0 or tail.scan_offset != 0:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if (current.st_dev, current.st_ino) != tail.file_id or current.st_size < offset:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    before = current
    metadata, _ = _read_range_verified(tail.root, tail.path, before, 0, min(before.st_size, 65537), budget=budget)
    metadata_end = metadata.find(b"\n")
    if metadata_end < 0 or _hash(metadata[:metadata_end + 1]) != tail.metadata_hash:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    # The bytes scanned but not yet acknowledged are represented by hashes in
    # this same cursor. Re-read and compare them before allowing durable ACK.
    if existing is not None:
        for start, end, digest in existing["scan_segments"]:
            if budget is not None:
                budget.check()
            segment, _ = _read_range_verified(tail.root, tail.path, before, start, end - start, budget=budget)
            if _hash(segment) != digest:
                raise ValueError("WORK_RECORD_SOURCE_CHANGED")
        scan_anchor_start = max(0, existing["scan_offset"] - 128)
        scan_anchor, _ = _read_range_verified(tail.root, tail.path, before, scan_anchor_start,
            existing["scan_offset"] - scan_anchor_start, budget=budget)
        if _hash(scan_anchor) != existing["scan_anchor_hash"]:
            raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    expected_size = offset - tail.scan_offset
    if expected_size < 0 or expected_size > len(tail.raw_data):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    actual, _ = _read_range_verified(tail.root, tail.path, before, tail.scan_offset, expected_size, budget=budget)
    if actual != tail.raw_data[:expected_size]:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if budget is not None:
        budget.check()
    if _signature(tail.path.stat(follow_symlinks=False)) != _signature(before):
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    anchor_start = max(0, offset - 128)
    anchor, _ = _read_range_verified(tail.root, tail.path, before, anchor_start, offset - anchor_start, budget=budget)
    if budget is not None:
        budget.check()
    state = {"schema_version": 4, "source_key": tail.source_key,
             "namespace_hash": tail.namespace_hash,
             "file_id": list(tail.file_id), "offset": offset, "anchor_hash": _hash(anchor),
             "metadata_hash": tail.metadata_hash, "session_hash": session_hash, "project_hash": project_hash,
             "session_no_save": durable_no_save, "scan_offset": offset,
             "scan_anchor_hash": _hash(anchor), "scan_segments": [],
             "oversized_turn": False, "discarding_line": False,
             "pending_capture_id": "", "pending_content_hash": ""}
    safe_atomic_write(tail.cursor_path.parent, tail.cursor_path,
                      _bounded_state(state, 262144), mode=0o600)


def stage_work_record_pending_capture(settings: Settings, tail: WorkRecordTail, end_offset: int, *,
                                     capture_id: str, content_hash: str, session_hash: str,
                                     project_hash: str, session_no_save: bool, budget=None) -> None:
    """Persist only a deterministic pending-intent reference before queue handoff."""
    def valid_hash(value):
        return (isinstance(value, str) and len(value) == 71 and value.startswith("sha256:")
                and all(char in "0123456789abcdef" for char in value[7:]))

    relative_end = end_offset - tail.scan_offset
    if (not valid_hash(capture_id) or not valid_hash(content_hash)
            or not isinstance(session_hash, str) or not session_hash.startswith("sha256:")
            or not isinstance(project_hash, str) or not project_hash.startswith("sha256:")
            or type(session_no_save) is not bool or relative_end <= 0 or relative_end > len(tail.raw_data)
            or tail.raw_data[relative_end - 1:relative_end] != b"\n"):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if budget is not None:
        budget.check()
    root = tail.cursor_path.parent
    existing = _read_work_record_cursor(root, tail.cursor_path, budget=budget)
    if existing is not None:
        if (existing["source_key"] != tail.source_key or existing["namespace_hash"] != tail.namespace_hash
                or tuple(existing["file_id"]) != tail.file_id or existing["metadata_hash"] != tail.metadata_hash
                or existing["offset"] < tail.offset or existing["offset"] >= end_offset
                or existing["scan_offset"] < tail.scan_offset or existing["scan_offset"] > end_offset
                or existing["session_hash"] not in {"", session_hash}
                or existing["project_hash"] not in {"", project_hash}
                or (existing["pending_capture_id"] and
                    (existing["pending_capture_id"], existing["pending_content_hash"]) != (capture_id, content_hash))):
            raise ValueError("WORK_RECORD_CURSOR_INVALID")
    elif tail.offset != 0 or tail.scan_offset != 0:
        raise ValueError("WORK_RECORD_CURSOR_INVALID")

    before = tail.path.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino) != tail.file_id or before.st_size < end_offset:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    metadata, _ = _read_range_verified(tail.root, tail.path, before, 0, min(before.st_size, 65537), budget=budget)
    metadata_end = metadata.find(b"\n")
    if metadata_end < 0 or _hash(metadata[:metadata_end + 1]) != tail.metadata_hash:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if existing is not None:
        for start, end, digest in existing["scan_segments"]:
            if budget is not None:
                budget.check()
            segment, _ = _read_range_verified(tail.root, tail.path, before, start, end - start, budget=budget)
            if _hash(segment) != digest:
                raise ValueError("WORK_RECORD_SOURCE_CHANGED")
        scan_anchor_start = max(0, existing["scan_offset"] - 128)
        scan_anchor, _ = _read_range_verified(tail.root, tail.path, before, scan_anchor_start,
            existing["scan_offset"] - scan_anchor_start, budget=budget)
        if _hash(scan_anchor) != existing["scan_anchor_hash"]:
            raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    expected_size = relative_end
    actual, _ = _read_range_verified(tail.root, tail.path, before, tail.scan_offset, expected_size, budget=budget)
    if actual != tail.raw_data[:expected_size]:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if budget is not None:
        budget.check()
    if _signature(tail.path.stat(follow_symlinks=False)) != _signature(before):
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")

    if existing is None:
        anchor = _read_range_verified(tail.root, tail.path, before, 0, 0, budget=budget)[0]
        state = {"schema_version": 4, "source_key": tail.source_key,
                 "namespace_hash": tail.namespace_hash, "file_id": list(tail.file_id),
                 "offset": 0, "anchor_hash": _hash(anchor), "metadata_hash": tail.metadata_hash,
                 "session_hash": "", "project_hash": "",
                 "session_no_save": tail.session_no_save or session_no_save,
                 "scan_offset": 0, "scan_anchor_hash": _hash(anchor), "scan_segments": [],
                 "oversized_turn": tail.oversized_turn, "discarding_line": tail.discarding_line,
                 "pending_capture_id": capture_id, "pending_content_hash": content_hash}
    else:
        state = dict(existing)
        state.update(schema_version=4,
            session_no_save=existing["session_no_save"] or tail.session_no_save or session_no_save,
            pending_capture_id=capture_id, pending_content_hash=content_hash)
    safe_atomic_write(root, tail.cursor_path, _bounded_state(state, 262144), mode=0o600)


def clear_work_record_pending_capture(settings: Settings, tail: WorkRecordTail, *,
                                      capture_id: str, content_hash: str, budget=None) -> None:
    """Clear a staged hash-only reference only after exact intent absence is verified."""
    if (not isinstance(capture_id, str) or not capture_id.startswith("sha256:")
            or not isinstance(content_hash, str) or not content_hash.startswith("sha256:")):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if budget is not None:
        budget.check()
    existing = _read_work_record_cursor(tail.cursor_path.parent, tail.cursor_path, budget=budget)
    if (existing is None or existing["source_key"] != tail.source_key
            or existing["namespace_hash"] != tail.namespace_hash or tuple(existing["file_id"]) != tail.file_id
            or (existing["pending_capture_id"], existing["pending_content_hash"]) != (capture_id, content_hash)):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    state = dict(existing)
    state.update(schema_version=4, pending_capture_id="", pending_content_hash="")
    safe_atomic_write(tail.cursor_path.parent, tail.cursor_path,
                      _bounded_state(state, 262144), mode=0o600)


def advance_work_record_scan(settings: Settings, tail: WorkRecordTail, end_offset: int, *,
                              session_hash: str, project_hash: str, oversized_turn: bool,
                              discarding_line: bool, session_no_save: bool, budget=None) -> None:
    """Persist hash-only scan progress without acknowledging an incomplete turn."""
    if (type(end_offset) is not int or end_offset != tail.scan_end or end_offset <= tail.scan_offset
            or len(tail.raw_data) != end_offset - tail.scan_offset
            or not isinstance(session_hash, str) or not session_hash.startswith("sha256:")
            or not isinstance(project_hash, str) or not project_hash.startswith("sha256:")
            or type(oversized_turn) is not bool or type(discarding_line) is not bool
            or type(session_no_save) is not bool):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    if budget is not None:
        budget.check()
    root = tail.cursor_path.parent
    existing = _read_work_record_cursor(root, tail.cursor_path, budget=budget)
    if existing is not None and (existing["source_key"] != tail.source_key
            or existing["namespace_hash"] != tail.namespace_hash or tuple(existing["file_id"]) != tail.file_id
            or existing["offset"] != tail.offset or existing["scan_offset"] != tail.scan_offset
            or existing["metadata_hash"] != tail.metadata_hash):
        raise ValueError("WORK_RECORD_CURSOR_INVALID")
    current = tail.path.stat(follow_symlinks=False)
    if (current.st_dev, current.st_ino) != tail.file_id or current.st_size < end_offset:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    metadata, _ = _read_range_verified(tail.root, tail.path, current, 0, min(current.st_size, 65537), budget=budget)
    metadata_end = metadata.find(b"\n")
    if metadata_end < 0 or _hash(metadata[:metadata_end + 1]) != tail.metadata_hash:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    current_page, _ = _read_range_verified(tail.root, tail.path, current, tail.scan_offset,
        len(tail.raw_data), budget=budget)
    if current_page != tail.raw_data:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    anchor_start = max(0, end_offset - 128)
    scan_anchor, _ = _read_range_verified(tail.root, tail.path, current, anchor_start,
        end_offset - anchor_start, budget=budget)
    if budget is not None:
        budget.check()
    offset = tail.offset
    anchor = _read_range_verified(tail.root, tail.path, current, max(0, offset - 128),
        offset - max(0, offset - 128), budget=budget)[0]
    segments = list(existing["scan_segments"] if existing is not None else [])
    segments.append([tail.scan_offset, end_offset, _hash(current_page)])
    state = {"schema_version": 4, "source_key": tail.source_key,
             "namespace_hash": tail.namespace_hash, "file_id": list(tail.file_id),
             "offset": offset, "anchor_hash": _hash(anchor), "metadata_hash": tail.metadata_hash,
             "session_hash": session_hash, "project_hash": project_hash,
             "session_no_save": (existing["session_no_save"] if existing is not None else tail.session_no_save) or session_no_save,
             "scan_offset": end_offset, "scan_anchor_hash": _hash(scan_anchor),
             "scan_segments": segments, "oversized_turn": oversized_turn,
             "discarding_line": discarding_line,
             "pending_capture_id": (existing["pending_capture_id"] if existing is not None else tail.pending_capture_id),
             "pending_content_hash": (existing["pending_content_hash"] if existing is not None else tail.pending_content_hash)}
    safe_atomic_write(root, tail.cursor_path, _bounded_state(state, 262144), mode=0o600)


def _read_range_verified(root: Path, path: Path, before: os.stat_result, offset: int,
                         size: int, *, budget=None) -> tuple[bytes, os.stat_result]:
    if offset < 0 or size < 0 or offset + size > before.st_size:
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if budget is not None:
        budget.check()
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    if _signature(path.stat(follow_symlinks=False)) != _signature(before):
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or _signature(opened) != _signature(before):
            raise ValueError("WORK_RECORD_SOURCE_CHANGED")
        stream.seek(offset)
        data = stream.read(size)
        if len(data) != size or _signature(os.fstat(stream.fileno())) != _signature(before):
            raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if _signature(path.stat(follow_symlinks=False)) != _signature(before):
        raise ValueError("WORK_RECORD_SOURCE_CHANGED")
    if budget is not None:
        budget.check()
    return data, before


def _observation(record: SourceRecord) -> ObservationInput:
    return ObservationInput(title=record.title, claim=record.claim, source_kind=record.source_kind,
        source_ref=record.source_ref, cwd=record.cwd, domain=record.domain,
        outcome_status=record.outcome_status, benefit=record.benefit, classification=record.classification,
        applicability=record.applicability, source_host_id=record.source_host_id, source_host_family=record.source_host_family)
