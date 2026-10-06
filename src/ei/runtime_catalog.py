"""Runtime-local metadata inventory; payloads remain authoritative files.

The caller serializes file mutations with its existing entry-root lock. SQLite
transactions make migration checkpoints durable, not a second payload store.
Unknown inventory never establishes capacity or capture coverage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory, safe_replace, safe_unlink
from .operation_runtime import OperationBudget


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DATABASE = ".runtime-catalog.sqlite"
_MAX_ENTRY_BYTES = 4 * 1024 * 1024
_PURPOSES = frozenset({"unknown", "legacy", "pending", "validated-result", "queue", "intent"})


class CatalogUnknown(ValueError):
    """The runtime inventory cannot establish safe admission accounting."""


def check(budget):
    if budget is not None:
        budget.check()


def managed_path(root: Path, entry_id: str, *, create=False) -> Path:
    if not isinstance(entry_id, str) or not _ID.fullmatch(entry_id):
        raise CatalogUnknown("RUNTIME_ID_INVALID")
    prefix = hashlib.sha256(entry_id.encode("ascii")).hexdigest()[:2]
    path = root / "managed" / prefix / (entry_id + ".json")
    assert_safe_target(root, path, allow_missing=True, expected_type="file")
    if create:
        safe_ensure_directory(path.parent, mode=0o700)
    return path


def read_entry(root, path, budget=None):
    """Read a bounded regular file, checking the opened handle and path identity."""
    check(budget)
    assert_safe_target(root, path, allow_missing=False, expected_type="file")
    before = path.stat(follow_symlinks=False)
    if before.st_size > _MAX_ENTRY_BYTES:
        raise CatalogUnknown("RUNTIME_ENTRY_TOO_LARGE")
    def signature(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    chunks = []
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if not stat.S_ISREG(opened.st_mode) or signature(opened) != signature(before) or signature(path.stat(follow_symlinks=False)) != signature(before):
            raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
        remaining = before.st_size
        while remaining:
            check(budget)
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
            chunks.append(chunk)
            remaining -= len(chunk)
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        if signature(os.fstat(stream.fileno())) != signature(before) or signature(path.stat(follow_symlinks=False)) != signature(before):
            raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
    check(budget)
    return b"".join(chunks)


def _digest(root, path, budget):
    data = read_entry(root, path, budget)
    return hashlib.sha256(data).hexdigest(), len(data)


def lookup(root: Path, entry_id: str, *, budget=None) -> Path:
    check(budget)
    managed = managed_path(root, entry_id)
    flat = assert_safe_target(root, root / (entry_id + ".json"), allow_missing=True, expected_type="file")
    if managed.exists():
        if flat.exists() and _digest(root, flat, budget) != _digest(root, managed, budget):
            raise CatalogUnknown("RUNTIME_DUPLICATE_MISMATCH")
        return managed
    return flat


def inventory_paths(root: Path, *, prefix="", budget=None):
    """Read-only compatibility enumeration; bounded consumers use catalog pages."""
    check(budget)
    if not root.exists():
        return
    for path in root.glob(prefix + "*.json"):
        check(budget)
        if not path.name.startswith("."):
            yield assert_safe_target(root, path, allow_missing=False, expected_type="file")
    managed = root / "managed"
    assert_safe_target(root, managed, allow_missing=True, expected_type="dir")
    if managed.exists():
        for directory in managed.iterdir():
            check(budget)
            assert_safe_target(root, directory, allow_missing=False, expected_type="dir")
            for path in directory.glob(prefix + "*.json"):
                check(budget)
                if path != managed_path(root, path.stem):
                    raise CatalogUnknown("RUNTIME_PATH_INVALID")
                flat = root / path.name
                if not flat.exists():
                    yield assert_safe_target(root, path, allow_missing=False, expected_type="file")
                elif _digest(root, flat, budget) != _digest(root, path, budget):
                    raise CatalogUnknown("RUNTIME_DUPLICATE_MISMATCH")


@dataclass(frozen=True)
class InventoryPage:
    paths: tuple[Path, ...]
    complete: bool
    reason_code: str


def _budget(value):
    return value if value is not None else OperationBudget(5000)


class RuntimeCatalog:
    def __init__(self, root: Path, *, prefix="", clean_temporary=None):
        self.root = Path(root)
        self.prefix = prefix
        self.clean_temporary = clean_temporary

    @contextmanager
    def _connection(self, budget=None):
        check(budget)
        safe_ensure_directory(self.root, mode=0o700)
        path = assert_safe_target(self.root, self.root / _DATABASE, allow_missing=True, expected_type="file")
        initialize = not path.exists()
        if initialize and (self.root / "managed").exists():
            raise CatalogUnknown("RUNTIME_CATALOG_MISSING")
        for suffix in ("-journal", "-wal", "-shm"):
            assert_safe_target(self.root, Path(str(path) + suffix), allow_missing=True, expected_type="file")
        connection = None
        try:
            timeout = min(5000, budget.remaining_ms()) if budget is not None else 5000
            connection = sqlite3.connect(path, timeout=timeout / 1000, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.set_progress_handler(lambda: int(budget is not None and budget.remaining_ms() <= 0), 100)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            objects = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 11")}
            if not initialize and version == 0 and not objects and not (self.root / "managed").exists():
                initialize = True  # a transaction interrupted before first schema commit
            if initialize:
                connection.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE entries (id TEXT PRIMARY KEY, shard TEXT NOT NULL,
                        phase TEXT NOT NULL CHECK(phase IN ('prepared','writing','registered','deleting')),
                        digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0),
                        purpose TEXT NOT NULL, target_size INTEGER NOT NULL CHECK(target_size>=0),
                        old_digest TEXT NOT NULL DEFAULT '', tag TEXT NOT NULL DEFAULT '',
                        retry_tag TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '', expires_at TEXT NOT NULL DEFAULT '');
                    CREATE INDEX entries_tag ON entries(tag);
                    CREATE INDEX entries_phase ON entries(phase,id);
                    CREATE INDEX entries_shard ON entries(shard,id);
                    CREATE INDEX entries_purpose ON entries(purpose,id);
                    CREATE TABLE state (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE accounting (purpose TEXT PRIMARY KEY, items INTEGER NOT NULL CHECK(items>=0), bytes INTEGER NOT NULL CHECK(bytes>=0));
                    CREATE TRIGGER entry_add AFTER INSERT ON entries BEGIN
                        INSERT INTO accounting VALUES (NEW.purpose,CASE WHEN NEW.purpose='validated-result' THEN 0 ELSE 1 END,NEW.size)
                        ON CONFLICT(purpose) DO UPDATE SET items=items+excluded.items,bytes=bytes+excluded.bytes; END;
                    CREATE TRIGGER entry_remove AFTER DELETE ON entries BEGIN
                        UPDATE accounting SET items=items-CASE WHEN OLD.purpose='validated-result' THEN 0 ELSE 1 END,bytes=bytes-OLD.size WHERE purpose=OLD.purpose; END;
                    CREATE TRIGGER entry_update AFTER UPDATE OF size,purpose ON entries BEGIN
                        UPDATE accounting SET items=items-CASE WHEN OLD.purpose='validated-result' THEN 0 ELSE 1 END,bytes=bytes-OLD.size WHERE purpose=OLD.purpose;
                        INSERT INTO accounting VALUES (NEW.purpose,CASE WHEN NEW.purpose='validated-result' THEN 0 ELSE 1 END,NEW.size)
                        ON CONFLICT(purpose) DO UPDATE SET items=items+excluded.items,bytes=bytes+excluded.bytes; END;
                    PRAGMA user_version=1;
                    COMMIT;
                """)
            required = {"entries", "state", "accounting", "entries_tag", "entries_phase", "entries_shard", "entries_purpose", "entry_add", "entry_remove", "entry_update"}
            objects = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 11")}
            if connection.execute("PRAGMA user_version").fetchone()[0] != 1 or objects != required:
                raise CatalogUnknown("RUNTIME_CATALOG_UNAVAILABLE")
            check(budget)
            yield connection
        except sqlite3.Error as exc:
            check(budget)
            raise CatalogUnknown("RUNTIME_CATALOG_UNAVAILABLE") from exc
        finally:
            if connection is not None:
                connection.close()

    @contextmanager
    def _transaction(self, connection, budget):
        check(budget)
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            check(budget)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

    @staticmethod
    def _get(connection, name, default=""):
        row = connection.execute("SELECT value FROM state WHERE name=?", (name,)).fetchone()
        return row[0] if row else default

    @staticmethod
    def _set(connection, name, value):
        connection.execute("INSERT INTO state VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, value))

    def _repair(self, connection, row, budget):
        check(budget)
        entry_id = row["id"]
        self._membership_except(connection, budget, {row["shard"]})
        target = managed_path(self.root, entry_id, create=True)
        flat = assert_safe_target(self.root, self.root / (entry_id + ".json"), allow_missing=True, expected_type="file")
        expected = row["digest"], row["size"]
        present = [path for path in (flat, target) if path.exists()]
        if not present or any(_digest(self.root, path, budget) != expected for path in present):
            raise CatalogUnknown("RUNTIME_PREPARED_MISMATCH")
        if flat.exists():
            check(budget)
            if target.exists():
                safe_unlink(self.root, flat, allow_missing=False)
            else:
                safe_replace(self.root, flat, self.root, target, source_type="file", replace_existing=False)
        self._settle(connection, row, budget)

    def _membership(self, budget):
        """Bounded shard metadata, a change detector rather than authentication."""
        check(budget)
        managed = self.root / "managed"
        assert_safe_target(self.root, managed, allow_missing=True, expected_type="dir")
        values = {}
        if managed.exists():
            with os.scandir(managed) as entries:
                for entry in entries:
                    check(budget)
                    if not re.fullmatch("[0-9a-f]{2}", entry.name):
                        raise CatalogUnknown("RUNTIME_MEMBERSHIP_UNKNOWN")
                    path = assert_safe_target(self.root, managed / entry.name, allow_missing=False, expected_type="dir")
                    info = path.stat(follow_symlinks=False)
                    values[entry.name] = [info.st_ino, info.st_mtime_ns]
        return values

    def _membership_except(self, connection, budget, touched=()):
        previous = json.loads(self._get(connection, "membership", "{}"))
        current = self._membership(budget)
        if {k: v for k, v in previous.items() if k not in touched} != {k: v for k, v in current.items() if k not in touched}:
            raise CatalogUnknown("RUNTIME_MEMBERSHIP_UNKNOWN")
        return current

    def _validate_shard(self, connection, prefix, budget, *, absent_id=None):
        path = self.root / "managed" / prefix
        assert_safe_target(self.root, path, allow_missing=True, expected_type="dir")
        hint = self._get(connection, "temporary:" + prefix)
        if hint and self.clean_temporary:
            if Path(hint).name != hint or not hint.endswith(".tmp"):
                raise CatalogUnknown("RUNTIME_CATALOG_UNAVAILABLE")
            temporary = assert_safe_target(self.root, path / hint, allow_missing=True, expected_type="file")
            if temporary.exists():
                # Recheck only the remembered owner. Its exit is relevant state
                # even when the directory stamp itself did not change.
                self.clean_temporary(temporary)
        info = path.stat(follow_symlinks=False) if path.exists() else None
        stamp = f"{info.st_ino}:{info.st_mtime_ns}" if info else "missing"
        stamp += ":" + self._get(connection, "revision:" + prefix, "0")
        allowance = budget.remaining_ms() if budget is not None else 2**63 - 1
        name = "blocked:" + prefix
        previous = self._get(connection, name)
        if previous:
            saved_stamp, saved_allowance = previous.rsplit("/", 1)
            previous_allowance = int(saved_allowance)
            if saved_stamp == stamp and allowance < previous_allowance + max(100, previous_allowance // 2):
                raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
        check(budget)
        self._set(connection, name, stamp + "/" + str(allowance))
        seen = set()
        try:
            # A cleanup mutation requires a second stable direct-membership
            # pass inside the same allowance. No recursive tree traversal.
            for attempt in range(2):
                removed = False
                seen.clear()
                info = path.stat(follow_symlinks=False) if path.exists() else None
                if info:
                    with os.scandir(path) as entries:
                        for entry in entries:
                            check(budget)
                            candidate = assert_safe_target(self.root, path / entry.name, allow_missing=False, expected_type="file")
                            if candidate.suffix == ".tmp" and self.clean_temporary:
                                check(budget)
                                self._set(connection, "temporary:" + prefix, candidate.name)
                                if self.clean_temporary(candidate):
                                    removed = True
                                    continue
                            if candidate.suffix != ".json" or managed_path(self.root, candidate.stem) != candidate:
                                raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
                            if connection.execute("SELECT 1 FROM entries WHERE id=? AND shard=?", (candidate.stem, prefix)).fetchone() is None:
                                raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
                            seen.add(candidate.stem)
                if not removed:
                    break
                if attempt == 1:
                    raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
            for row in connection.execute("SELECT id,phase FROM entries WHERE shard=? ORDER BY id", (prefix,)):
                check(budget)
                if row["id"] not in seen and row["id"] != absent_id and row["phase"] not in {"prepared", "writing"}:
                    raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
            check(budget)
            after = path.stat(follow_symlinks=False) if path.exists() else None
            if (None if info is None else (info.st_ino, info.st_mtime_ns)) != (None if after is None else (after.st_ino, after.st_mtime_ns)):
                raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
        except (OSError, ValueError) as exc:
            # The start allowance was durably recorded before enumeration. No
            # extra allowance or exhausted-deadline bookkeeping is used here.
            raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN") from exc
        # A completed scan is not an incomplete-replay marker even when the
        # later atomic settlement is interrupted.
        check(budget)
        connection.execute("DELETE FROM state WHERE name=?", (name,))
        connection.execute("DELETE FROM state WHERE name=?", ("temporary:" + prefix,))
        return None if after is None else [after.st_ino, after.st_mtime_ns]

    def _root_entries(self, connection, budget):
        ignored = 0
        with os.scandir(self.root) as entries:
            for entry in entries:
                check(budget)
                if not (entry.name.endswith(".json") and not entry.name.startswith(".") and entry.name.startswith(self.prefix)):
                    ignored += 1
                    if ignored > 256:
                        self._set(connection, "halted", "RUNTIME_ROOT_INVENTORY_UNKNOWN")
                        raise CatalogUnknown("RUNTIME_ROOT_INVENTORY_UNKNOWN")
                yield entry

    def _settle(self, connection, row, budget, *, deleted=False):
        current = self._membership_except(connection, budget, {row["shard"]})
        stamp = self._validate_shard(connection, row["shard"], budget, absent_id=row["id"] if deleted else None)
        after = self._membership(budget)
        if after.get(row["shard"]) != stamp or {k: v for k, v in current.items() if k != row["shard"]} != {k: v for k, v in after.items() if k != row["shard"]}:
            raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
        with self._transaction(connection, budget):
            if deleted:
                connection.execute("DELETE FROM entries WHERE id=?", (row["id"],))
            else:
                connection.execute("UPDATE entries SET phase='registered',size=target_size,old_digest='' WHERE id=?", (row["id"],))
            connection.execute("DELETE FROM state WHERE name=?", ("blocked:" + row["shard"],))
            self._set(connection, "membership", json.dumps(after, sort_keys=True, separators=(",", ":")))

    def _pending(self, connection, *, exclude_id=""):
        for phase in ("deleting", "prepared", "writing"):
            row = connection.execute("SELECT * FROM entries WHERE phase=? AND id!=? ORDER BY id LIMIT 1", (phase, exclude_id)).fetchone()
            if row is not None:
                return row
        return None

    def _accounting(self, connection, budget):
        rows = connection.execute("SELECT purpose,items,bytes FROM accounting LIMIT 7").fetchall()
        totals = {}
        for row in rows:
            check(budget)
            if row["purpose"] not in _PURPOSES or any(type(row[key]) is not int or row[key] < 0 for key in ("items", "bytes")):
                raise CatalogUnknown("RUNTIME_ACCOUNTING_UNKNOWN")
            totals[row["purpose"]] = (row["items"], row["bytes"])
        for purpose in _PURPOSES:
            check(budget)
            present = connection.execute("SELECT 1 FROM entries WHERE purpose=? LIMIT 1", (purpose,)).fetchone() is not None
            items, size = totals.get(purpose, (0, 0))
            if (present and (purpose not in totals or size == 0 or (purpose != "validated-result" and items == 0))) or (not present and (items or size)) or (purpose == "validated-result" and items):
                raise CatalogUnknown("RUNTIME_ACCOUNTING_UNKNOWN")
        return totals

    def _restore_update(self, connection, row, path, budget, inspect_update):
        """Cancel only a proven-unapplied replacement; never a missing delete."""
        # The caller holds the root lock. Keep incomplete-scan evidence durable
        # outside the restoration transaction, as in ordinary _settle.
        self._known(connection, budget, replay=row)
        metadata = inspect_update(path)
        expected = {key: row[key] for key in ("purpose", "tag", "retry_tag", "created_at", "expires_at")}
        if metadata != expected:
            raise CatalogUnknown("RUNTIME_UPDATE_METADATA_UNKNOWN")
        digest, size = _digest(self.root, path, budget)
        if not row["old_digest"] or digest != row["old_digest"]:
            raise CatalogUnknown("RUNTIME_WRITE_UNCONFIRMED")
        current = self._membership_except(connection, budget, {row["shard"]})
        stamp = self._validate_shard(connection, row["shard"], budget)
        after = self._membership(budget)
        if after.get(row["shard"]) != stamp or {k: v for k, v in current.items() if k != row["shard"]} != {k: v for k, v in after.items() if k != row["shard"]}:
            raise CatalogUnknown("RUNTIME_SHARD_INVENTORY_UNKNOWN")
        with self._transaction(connection, budget):
            check(budget)
            connection.execute("UPDATE entries SET phase='registered',digest=?,size=?,target_size=?,old_digest='' WHERE id=?", (digest, size, size, row["id"]))
            self._set(connection, "membership", json.dumps(after, sort_keys=True, separators=(",", ":")))

    def _repair_writes(self, connection, budget, limit, inspect_update=None):
        rows = connection.execute("SELECT * FROM entries WHERE phase='writing' ORDER BY id LIMIT ?", (limit,)).fetchall()
        for row in rows:
            check(budget)
            path = managed_path(self.root, row["id"])
            if not path.exists():
                continue
            actual = _digest(self.root, path, budget)
            if actual != (row["digest"], row["target_size"]):
                if actual[0] == row["old_digest"]:
                    if inspect_update is not None:
                        self._restore_update(connection, row, path, budget, inspect_update)
                    continue
                raise CatalogUnknown("RUNTIME_WRITE_UNCONFIRMED")
            self._settle(connection, row, budget)
        return rows

    def _known(self, connection, budget, *, replay=None):
        check(budget)
        pending = self._pending(connection, exclude_id=replay["id"] if replay else "")
        if pending is not None:
            raise CatalogUnknown("RUNTIME_DELETE_UNCONFIRMED" if pending["phase"] == "deleting" else "RUNTIME_PREPARED_UNRESOLVED")
        halted = self._get(connection, "halted")
        if halted:
            raise CatalogUnknown(halted)
        if self._get(connection, "complete") != "1":
            raise CatalogUnknown("RUNTIME_CAPACITY_UNKNOWN")
        self._membership_except(connection, budget, {replay["shard"]} if replay else ())
        if replay:
            self._validate_shard(connection, replay["shard"], budget)
        for entry in self._root_entries(connection, budget):
            if entry.name.endswith(".json") and not entry.name.startswith(".") and entry.name.startswith(self.prefix):
                raise CatalogUnknown("RUNTIME_INVENTORY_PARTIAL")
        return self._accounting(connection, budget)

    def migrate_page(self, *, limit=64, budget=None, inspect_metadata=None, inspect_update=None):
        budget = _budget(budget)
        if type(limit) is not int or limit <= 0:
            raise ValueError("RUNTIME_PAGE_LIMIT_INVALID")
        paths = []
        with self._connection(budget) as connection:
            halted = self._get(connection, "halted")
            if halted:
                raise CatalogUnknown(halted)
            try:
                self._accounting(connection, budget)
                deleting = connection.execute("SELECT id FROM entries WHERE phase='deleting' ORDER BY id LIMIT 1").fetchone()
                if deleting:
                    raise CatalogUnknown("RUNTIME_DELETE_UNCONFIRMED")
                self._repair_writes(connection, budget, limit, inspect_update)
                for row in connection.execute("SELECT * FROM entries WHERE phase='prepared' ORDER BY id LIMIT ?", (limit,)).fetchall():
                    self._repair(connection, row, budget)
                    paths.append(managed_path(self.root, row["id"]))
                complete = True
                entries = self._root_entries(connection, budget)
                try:
                    for entry in entries:
                        check(budget)
                        if entry.name.endswith(".tmp") and self.clean_temporary:
                            self.clean_temporary(self.root / entry.name)
                            continue
                        if not entry.name.endswith(".json") or entry.name.startswith(".") or not entry.name.startswith(self.prefix):
                            continue
                        if len(paths) >= limit:
                            complete = False
                            break
                        path = self.root / entry.name
                        entry_id = path.stem
                        managed_path(self.root, entry_id)
                        digest, size = _digest(self.root, path, budget)
                        metadata = inspect_metadata(path) if inspect_metadata else "unknown"
                        purpose, tag = metadata if isinstance(metadata, tuple) else (metadata, "")
                        existing = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
                        if existing is not None and (existing["digest"], existing["size"]) != (digest, size):
                            raise CatalogUnknown("RUNTIME_DUPLICATE_MISMATCH")
                        check(budget)
                        if purpose not in _PURPOSES:
                            raise CatalogUnknown("RUNTIME_PURPOSE_INVALID")
                        shard = managed_path(self.root, entry_id).parent.name
                        self._membership_except(connection, budget)
                        connection.execute("INSERT INTO entries (id,shard,phase,digest,size,purpose,target_size,tag) VALUES (?, ?, 'prepared', ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET phase='prepared'", (entry_id, shard, digest, size, purpose, size, tag))
                        row = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
                        self._repair(connection, row, budget)
                        paths.append(managed_path(self.root, entry_id))
                finally:
                    entries.close()
                check(budget)
                self._set(connection, "complete", "1" if complete else "0")
                pending = self._pending(connection)
                self._membership_except(connection, budget, {pending["shard"]} if pending else ())
                complete = complete and pending is None
                return InventoryPage(tuple(paths), complete, "RUNTIME_INVENTORY_COMPLETE" if complete else "RUNTIME_INVENTORY_PARTIAL")
            except (OSError, ValueError) as exc:
                if isinstance(exc, TimeoutError):
                    raise
                resumable = {"RUNTIME_SHARD_INVENTORY_UNKNOWN", "RUNTIME_MEMBERSHIP_UNKNOWN", "RUNTIME_DELETE_UNCONFIRMED"}
                if not isinstance(exc, CatalogUnknown) or str(exc) not in resumable:
                    check(budget)
                    self._set(connection, "halted", str(exc) if isinstance(exc, CatalogUnknown) else "RUNTIME_INVENTORY_UNSAFE")
                raise CatalogUnknown(str(exc) if isinstance(exc, CatalogUnknown) else "RUNTIME_INVENTORY_UNSAFE") from exc

    def page(self, consumer: str, *, limit=64, budget=None, advance=True):
        budget = _budget(budget)
        if type(limit) is not int or limit <= 0:
            raise ValueError("RUNTIME_PAGE_LIMIT_INVALID")
        with self._connection(budget) as connection:
            cursor = self._get(connection, "cursor:" + consumer)
            rows = connection.execute("SELECT id FROM entries WHERE phase='registered' AND id>? ORDER BY id LIMIT ?", (cursor, limit)).fetchall()
            if not rows:
                rows = connection.execute("SELECT id FROM entries WHERE phase='registered' ORDER BY id LIMIT ?", (limit,)).fetchall()
            check(budget)
            if rows and advance:
                self._set(connection, "cursor:" + consumer, rows[-1][0])
            try:
                self._known(connection, budget)
                complete = True
                reason = "RUNTIME_INVENTORY_COMPLETE"
            except CatalogUnknown as exc:
                complete = False
                reason = str(exc)
            return InventoryPage(tuple(managed_path(self.root, row[0]) for row in rows), complete, reason)

    def advance(self, consumer, entry_id, *, budget=None):
        budget = _budget(budget)
        check(budget)
        with self._connection(budget) as connection:
            self._set(connection, "cursor:" + consumer, entry_id)

    def capacity(self, purpose, *, budget=None):
        budget = _budget(budget)
        with self._connection(budget) as connection:
            totals = self._known(connection, budget)
            check(budget)
            return totals.get(purpose, (0, 0))

    def validate_page(self, *, limit=16, budget=None):
        budget = _budget(budget)
        page = self.page("validate", limit=limit, budget=budget, advance=False)
        with self._connection(budget) as connection:
            for path in page.paths:
                check(budget)
                row = connection.execute("SELECT * FROM entries WHERE id=?", (path.stem,)).fetchone()
                if _digest(self.root, path, budget) != (row["digest"], row["size"]):
                    raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
                self._set(connection, "cursor:validate", path.stem)

    def find_tag(self, tag, *, budget=None):
        budget = _budget(budget)
        if not tag:
            raise CatalogUnknown("RUNTIME_TAG_INVALID")
        with self._connection(budget) as connection:
            rows = connection.execute("SELECT id FROM entries WHERE tag=? LIMIT 2", (tag,)).fetchall()
            if len(rows) > 1:
                raise CatalogUnknown("RUNTIME_DUPLICATE_MISMATCH")
            return lookup(self.root, rows[0][0], budget=budget) if rows else None

    def tagged_paths(self, tag, *, limit=64, budget=None):
        """Complete bounded tag lookup; callers validate their derived tag too."""
        budget = _budget(budget)
        if not isinstance(tag, str) or not tag or type(limit) is not int or limit <= 0:
            raise CatalogUnknown("RUNTIME_TAG_INVALID")
        with self._connection(budget) as connection:
            self._known(connection, budget)
            if connection.execute("SELECT 1 FROM entries WHERE tag='' LIMIT 1").fetchone():
                raise CatalogUnknown("RUNTIME_TAG_INVENTORY_UNKNOWN")
            rows = connection.execute("SELECT * FROM entries WHERE tag=? ORDER BY id LIMIT ?", (tag, limit + 1)).fetchall()
            check(budget)
            if len(rows) > limit:
                raise CatalogUnknown("RUNTIME_TAG_INVENTORY_PARTIAL")
            paths = []
            for row in rows:
                check(budget)
                path = lookup(self.root, row["id"], budget=budget)
                if _digest(self.root, path, budget) != (row["digest"], row["size"]):
                    raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
                paths.append(path)
            self._known(connection, budget)
            check(budget)
            return tuple(paths)

    def reservation(self, entry_id, *, budget=None):
        """Metadata only; callers must still reconcile inventory before admission."""
        budget = _budget(budget)
        managed_path(self.root, entry_id)
        with self._connection(budget) as connection:
            row = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
            return dict(row) if row else None

    def mark_unknown(self, reason="RUNTIME_ENTRY_UNVERIFIED", *, budget=None):
        """Remember an observed unsafe body; caller holds the entry-root lock."""
        if reason not in {"RUNTIME_ENTRY_UNVERIFIED", "RUNTIME_ENTRY_CHANGED", "RUNTIME_INVENTORY_UNSAFE"}:
            raise ValueError("RUNTIME_REASON_INVALID")
        budget = _budget(budget)
        with self._connection(budget) as connection:
            check(budget)
            self._set(connection, "halted", reason)

    def write(self, entry_id, data: bytes, *, purpose="unknown", budget=None, writer=None, tag="", retry_tag="", created_at="", expires_at=""):
        budget = _budget(budget)
        check(budget)
        if purpose not in _PURPOSES:
            raise CatalogUnknown("RUNTIME_PURPOSE_INVALID")
        digest = hashlib.sha256(data).hexdigest()
        target = managed_path(self.root, entry_id)
        with self._connection(budget) as connection:
            existing = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
            if existing is not None and existing["purpose"] != purpose:
                raise CatalogUnknown("RUNTIME_PURPOSE_MISMATCH")
            replay = existing is not None and existing["phase"] == "writing"
            if replay:
                exact = (existing["digest"], existing["target_size"], existing["purpose"], existing["tag"], existing["retry_tag"], existing["created_at"], existing["expires_at"]) == (digest, len(data), purpose, tag, retry_tag, created_at, expires_at)
                semantic = bool(retry_tag and re.fullmatch(r"sha256:[0-9a-f]{64}", retry_tag) and created_at and expires_at) and (existing["purpose"], existing["retry_tag"], existing["created_at"], existing["expires_at"]) == (purpose, retry_tag, created_at, expires_at)
                if not exact and (not semantic or target.exists() or existing["old_digest"] or len(data) > existing["size"]):
                    raise CatalogUnknown("RUNTIME_RETRY_MISMATCH")
                self._known(connection, budget, replay=existing)
                if target.exists():
                    actual = _digest(self.root, target, budget)
                    if actual == (existing["digest"], existing["target_size"]):
                        self._settle(connection, existing, budget)
                        return target
                    if actual[0] != existing["old_digest"]:
                        raise CatalogUnknown("RUNTIME_WRITE_UNCONFIRMED")
            else:
                self._known(connection, budget)
            if existing is not None and not replay:
                path = lookup(self.root, entry_id, budget=budget)
                if _digest(self.root, path, budget) != (existing["digest"], existing["size"]):
                    raise CatalogUnknown("RUNTIME_ENTRY_CHANGED")
            check(budget)
            with self._transaction(connection, budget):
                connection.execute("INSERT INTO entries (id,shard,phase,digest,size,purpose,target_size,old_digest,tag,retry_tag,created_at,expires_at) VALUES (?, ?, 'writing', ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET phase='writing',digest=excluded.digest,size=MAX(entries.size,excluded.size),target_size=excluded.target_size,old_digest=excluded.old_digest,purpose=excluded.purpose,tag=excluded.tag,retry_tag=excluded.retry_tag,created_at=excluded.created_at,expires_at=excluded.expires_at", (entry_id, target.parent.name, digest, len(data), purpose, len(data), existing["old_digest"] if replay else existing["digest"] if existing else "", tag, retry_tag, created_at, expires_at))
                self._set(connection, "revision:" + target.parent.name, str(int(self._get(connection, "revision:" + target.parent.name, "0")) + 1))
            target = managed_path(self.root, entry_id, create=True)
            if writer is None:
                safe_atomic_write(self.root, target, data, mode=0o600)
            else:
                writer(target)
            check(budget)
            if _digest(self.root, target, budget) != (digest, len(data)):
                raise CatalogUnknown("RUNTIME_WRITE_UNCONFIRMED")
            row = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
            self._settle(connection, row, budget)
            return target

    def delete(self, entry_id, *, budget=None):
        budget = _budget(budget)
        with self._connection(budget) as connection:
            row = connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
            path = lookup(self.root, entry_id, budget=budget)
            if row is None and not path.exists():
                return False
            if (self.root / (entry_id + ".json")).exists():
                raise CatalogUnknown("RUNTIME_DUPLICATE_UNRESOLVED")
            if row is None or not path.exists() or _digest(self.root, path, budget) != (row["digest"], row["size"]):
                raise CatalogUnknown("RUNTIME_DELETE_UNCONFIRMED")
            self._membership_except(connection, budget, {row["shard"]})
            self._validate_shard(connection, row["shard"], budget)
            check(budget)
            connection.execute("UPDATE entries SET phase='deleting' WHERE id=?", (entry_id,))
            safe_unlink(self.root, path, allow_missing=False)
            check(budget)
            self._settle(connection, row, budget, deleted=True)
            return True
