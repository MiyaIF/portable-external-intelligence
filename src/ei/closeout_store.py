"""Bounded, body-free recovery metadata for closeout associations.

All mutation methods require the caller to hold the shared capture-ledger lock.
The inventory is a small explicit allow-list; recovery never repairs it by
scanning directories.
"""

from __future__ import annotations

import json
import os
import re
import stat
from bisect import bisect_right
from pathlib import Path
from typing import Any, Mapping

from .journal import validate_schema
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory


_RECORD_ID_RE = re.compile(r"co_[0-9a-f]{64}")
_MAX_RECORD_BYTES = 16 * 1024
_MAX_ACTIVE = 64
_MAX_ACTIVE_BYTES = 1024 * 1024
_MAX_INDEX_BYTES = 16 * 1024
_MAX_CURSOR_BYTES = 1024


class CloseoutStoreError(RuntimeError):
    """Fixed-code error from the bounded closeout metadata store."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _encoded(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class CloseoutStore:
    """Safe record/index I/O; caller owns the capture lock for mutations."""

    def __init__(self, settings: Any, *, budget):
        self.settings = settings
        self.budget = budget

    @property
    def root(self) -> Path:
        runtime = Path(self.settings.paths.runtime_dir)
        return runtime / "state" / "closeout-associations"

    def _ensure_root(self, *, create: bool) -> Path | None:
        runtime = Path(self.settings.paths.runtime_dir)
        if create:
            runtime = safe_ensure_directory(runtime, mode=0o700)
            assert_safe_target(runtime, runtime, allow_root=True, allow_missing=False, expected_type="dir")
            state = safe_ensure_directory(runtime / "state", mode=0o700)
            assert_safe_target(runtime, state, allow_missing=False, expected_type="dir")
            root = safe_ensure_directory(state / "closeout-associations", mode=0o700)
            return assert_safe_target(state, root, allow_missing=False, expected_type="dir")
        state = runtime / "state"
        if not state.exists():
            return None
        safe_state = assert_safe_target(runtime, state, allow_missing=False, expected_type="dir")
        root = safe_state / "closeout-associations"
        safe_root = assert_safe_target(safe_state, root, allow_missing=True)
        if not safe_root.exists() and not safe_root.is_symlink():
            return None
        return assert_safe_target(safe_state, safe_root, allow_missing=False, expected_type="dir")

    def _path(self, root: Path, name: str) -> Path:
        return assert_safe_target(root, root / name, allow_missing=True)

    def _read_json(self, root: Path, path: Path, limit: int) -> dict[str, Any] | None:
        self.budget.check()
        safe = assert_safe_target(root, path, allow_missing=True, expected_type="file")
        if not safe.exists():
            return None
        try:
            signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            before = safe.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
            descriptor = os.open(
                safe,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
                chunks: list[bytes] = []
                total = 0
                while total <= limit:
                    self.budget.check()
                    chunk = stream.read(min(65536, limit + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                finished = os.fstat(stream.fileno())
            after = safe.stat(follow_symlinks=False)
            assert_safe_target(root, safe, allow_missing=False, expected_type="file")
            if len({signature(item) for item in (before, opened, finished, after)}) != 1:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
            raw = b"".join(chunks)
        except TimeoutError:
            raise
        except CloseoutStoreError:
            raise
        except (OSError, SafeFilesystemError, ValueError) as exc:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN") from exc
        self.budget.check()
        if len(raw) > limit:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN") from exc
        if not isinstance(value, dict):
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return value

    @staticmethod
    def _validate_index(value: Mapping[str, Any]) -> list[str]:
        if set(value) != {"schema_version", "active"} or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        active = value.get("active")
        if not isinstance(active, list) or len(active) > _MAX_ACTIVE:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        if any(not isinstance(item, str) or _RECORD_ID_RE.fullmatch(item) is None for item in active):
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        if active != sorted(set(active)):
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return active

    @staticmethod
    def _validate_cursor(value: Mapping[str, Any]) -> str | None:
        if set(value) != {"schema_version", "last_record_id"} or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        record_id = value.get("last_record_id")
        if record_id is not None and (not isinstance(record_id, str) or _RECORD_ID_RE.fullmatch(record_id) is None):
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return record_id

    def _read_record_path(self, root: Path, record_id: str) -> dict[str, Any] | None:
        if not isinstance(record_id, str) or _RECORD_ID_RE.fullmatch(record_id) is None:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID")
        value = self._read_json(root, self._path(root, record_id + ".json"), _MAX_RECORD_BYTES)
        if value is None:
            return None
        try:
            validate_schema("closeout-association", value)
        except (ValueError, TypeError) as exc:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN") from exc
        if value.get("record_id") != record_id:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return value

    def _inventory(self, *, create: bool = False) -> tuple[Path | None, list[str], dict[str, Any], dict[str, dict[str, Any]]]:
        root = self._ensure_root(create=create)
        if root is None:
            return None, [], {"schema_version": 1, "last_record_id": None}, {}
        index = self._read_json(root, self._path(root, "index.json"), _MAX_INDEX_BYTES)
        cursor = self._read_json(root, self._path(root, "cursor.json"), _MAX_CURSOR_BYTES)
        if index is None and cursor is None and create:
            index = {"schema_version": 1, "active": []}
            cursor = {"schema_version": 1, "last_record_id": None}
            self._write_json(root, "index.json", index, _MAX_INDEX_BYTES)
            self._write_json(root, "cursor.json", cursor, _MAX_CURSOR_BYTES)
        if index is None or cursor is None:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        active = self._validate_index(index)
        last_record_id = self._validate_cursor(cursor)
        if last_record_id is not None:
            cursor_record = self._read_record_path(root, last_record_id)
            if cursor_record is None:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
            if last_record_id not in active and cursor_record["status"] not in {"COMMITTED", "LOST"}:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        records: dict[str, dict[str, Any]] = {}
        total = 0
        for record_id in active:
            self.budget.check()
            record = self._read_record_path(root, record_id)
            if record is None:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
            records[record_id] = record
            total += len(_encoded(record))
            if total > _MAX_ACTIVE_BYTES:
                raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return root, active, {"schema_version": 1, "last_record_id": last_record_id}, records

    def _write_json(self, root: Path, name: str, value: Mapping[str, Any], limit: int) -> None:
        data = _encoded(value)
        if len(data) > limit:
            raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        path = self._path(root, name)
        self.budget.check()
        safe_atomic_write(root, path, data, mode=0o600)
        self.budget.check()

    def reserve(self, record: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(record)
        try:
            validate_schema("closeout-association", value)
        except (ValueError, TypeError) as exc:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID") from exc
        if value["status"] != "PREPARING" or value["spool_ref"] is not None:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID")
        encoded = _encoded(value)
        if len(encoded) > _MAX_RECORD_BYTES:
            raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        existed = self.root.exists() or self.root.is_symlink()
        root, active, _, records = self._inventory(create=not existed)
        assert root is not None
        record_id = value["record_id"]
        if record_id in active or self._read_record_path(root, record_id) is not None:
            raise CloseoutStoreError("CLOSEOUT_RECORD_EXISTS")
        total = sum(len(_encoded(item)) for item in records.values()) + len(encoded)
        if len(active) >= _MAX_ACTIVE or total > _MAX_ACTIVE_BYTES:
            raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        updated = {"schema_version": 1, "active": sorted((*active, record_id))}
        # Index first: a crash can only leave a listed-missing record, which is
        # detected as UNKNOWN; it cannot silently create an unlisted intent.
        self._write_json(root, "index.json", updated, _MAX_INDEX_BYTES)
        self._write_json(root, record_id + ".json", value, _MAX_RECORD_BYTES)
        self._inventory()
        return value

    def read_record(self, record_id: str) -> dict[str, Any] | None:
        root, active, _, _ = self._inventory()
        if root is None:
            return None
        value = self._read_record_path(root, record_id)
        if value is not None and record_id not in active and value["status"] not in {"COMMITTED", "LOST"}:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return value

    def active_records(self, *, max_records: int = 64) -> list[dict[str, Any]]:
        if type(max_records) is not int or not 1 <= max_records <= _MAX_ACTIVE:
            raise CloseoutStoreError("CLOSEOUT_RECOVERY_LIMIT")
        _, active, cursor, records = self._inventory()
        if not active:
            return []
        last = cursor["last_record_id"]
        start = bisect_right(active, last) if last is not None else 0
        if start == len(active):
            start = 0
        order = active[start:] + active[:start]
        return [records[item] for item in order[:max_records]]

    def write_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(record)
        try:
            validate_schema("closeout-association", value)
        except (ValueError, TypeError) as exc:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID") from exc
        encoded = _encoded(value)
        if len(encoded) > _MAX_RECORD_BYTES:
            raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        root, active, _, records = self._inventory()
        if root is None or (value["record_id"] not in active and self._read_record_path(root, value["record_id"]) is None):
            raise CloseoutStoreError("CLOSEOUT_RECORD_UNKNOWN")
        if value["record_id"] in active:
            total = sum(len(_encoded(item)) for key, item in records.items() if key != value["record_id"]) + len(encoded)
            if total > _MAX_ACTIVE_BYTES:
                raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        self._write_json(root, value["record_id"] + ".json", value, _MAX_RECORD_BYTES)
        self._read_record_path(root, value["record_id"])
        return value

    def advance_cursor(self, record_id: str) -> None:
        if not isinstance(record_id, str) or _RECORD_ID_RE.fullmatch(record_id) is None:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID")
        root, _, _, _ = self._inventory()
        if root is None:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        self._write_json(root, "cursor.json", {"schema_version": 1, "last_record_id": record_id}, _MAX_CURSOR_BYTES)
        self._read_cursor(root)

    def _read_cursor(self, root: Path) -> str | None:
        cursor = self._read_json(root, self._path(root, "cursor.json"), _MAX_CURSOR_BYTES)
        if cursor is None:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return self._validate_cursor(cursor)

    def finish(self, record: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(record)
        if value.get("status") not in {"COMMITTED", "LOST"}:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID")
        try:
            validate_schema("closeout-association", value)
        except (ValueError, TypeError) as exc:
            raise CloseoutStoreError("CLOSEOUT_RECORD_INVALID") from exc
        encoded = _encoded(value)
        if len(encoded) > _MAX_RECORD_BYTES:
            raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        root, active, _, records = self._inventory()
        if root is None:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        existing = records.get(value["record_id"])
        if existing is None:
            existing = self._read_record_path(root, value["record_id"])
        if existing is None:
            raise CloseoutStoreError("CLOSEOUT_RECORD_UNKNOWN")
        if value["record_id"] in active:
            total = sum(len(_encoded(item)) for key, item in records.items() if key != value["record_id"]) + len(encoded)
            if total > _MAX_ACTIVE_BYTES:
                raise CloseoutStoreError("CLOSEOUT_CAPACITY")
        self._write_json(root, value["record_id"] + ".json", value, _MAX_RECORD_BYTES)
        if value["record_id"] in active:
            self._write_json(root, "index.json", {"schema_version": 1, "active": [item for item in active if item != value["record_id"]]}, _MAX_INDEX_BYTES)
        self._write_json(root, "cursor.json", {"schema_version": 1, "last_record_id": value["record_id"]}, _MAX_CURSOR_BYTES)
        if self._read_record_path(root, value["record_id"]) != value or self._read_cursor(root) != value["record_id"]:
            raise CloseoutStoreError("CLOSEOUT_INDEX_UNKNOWN")
        return value


__all__ = ["CloseoutStore", "CloseoutStoreError"]
