from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from .ids import fingerprint
from .safe_fs import assert_no_reparse_components, assert_safe_target, safe_atomic_write, safe_ensure_directory


def _check(budget):
    if budget is not None:
        budget.check()


def _checked(items, budget):
    _check(budget)
    for item in items:
        _check(budget)
        yield item
    _check(budget)


@dataclass(frozen=True)
class UsageTotals:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    turns: int = 0

    @property
    def uncached_input_tokens(self) -> int:
        return max(0, self.input_tokens - self.cached_input_tokens)


@dataclass(frozen=True)
class UsageAggregate:
    user_environment: UsageTotals
    external_reference: UsageTotals
    excluded: UsageTotals

    def to_dict(self) -> dict[str, Any]:
        return _aggregate_dict(self)


@dataclass(frozen=True)
class SchemaInspection:
    status: str
    table: str | None
    columns: tuple[str, ...]
    reason_code: str
    schema_sha256: str = ""


@dataclass(frozen=True)
class UsageReadResult:
    status: str
    rows: tuple[dict[str, Any], ...]
    schema: SchemaInspection
    database_sha256: str

    @property
    def aggregate(self) -> UsageAggregate:
        return aggregate_usage(self.rows)

    @property
    def source_status(self) -> str:
        return "verified" if self.status == "OK" else "unknown"

    @property
    def user_environment(self) -> UsageTotals:
        return self.aggregate.user_environment

    @property
    def external_reference(self) -> UsageTotals:
        return self.aggregate.external_reference

    @property
    def excluded(self) -> UsageTotals:
        return self.aggregate.excluded


@dataclass(frozen=True)
class LocalMetricsResult:
    status: str
    discovered_databases: int
    known_databases: int
    unsupported_databases: int
    read_errors: int
    aggregate: UsageAggregate
    database_hashes: tuple[str, ...]
    schema_hashes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "source_status": "verified" if self.status == "OK" else "partial" if self.status == "PARTIAL" else "unknown",
            "databases": {
                "discovered": self.discovered_databases,
                "known": self.known_databases,
                "unsupported": self.unsupported_databases,
                "read_errors": self.read_errors,
            },
            "database_hashes": list(self.database_hashes),
            "schema_hashes": list(self.schema_hashes),
            "aggregate": _aggregate_dict(self.aggregate),
        }


def _database_hash(path: Path, *, budget=None) -> str:
    _check(budget)
    assert_no_reparse_components(path)
    before = path.stat(follow_symlinks=False)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            _check(budget)
            raw = stream.read(65536)
            if not raw:
                break
            digest.update(raw)
    after = path.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("METRICS_DATABASE_CHANGED")
    _check(budget)
    return digest.hexdigest()


def _schema_hash(rows: Iterable[tuple[Any, ...]], *, budget=None) -> str:
    material = [
        {
            "type": row[0] if len(row) > 0 and isinstance(row[0], str) else "",
            "name_hash": fingerprint(row[1] if len(row) > 1 else ""),
            "table_name_hash": fingerprint(row[2] if len(row) > 2 else ""),
            "sql_hash": fingerprint(row[3] if len(row) > 3 else ""),
        }
        for row in _checked(rows, budget)
    ]
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def inspect_sqlite_schema(connection: sqlite3.Connection, *, budget=None) -> SchemaInspection:
    _check(budget)
    schema_rows = list(_checked(connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','index','view','trigger') ORDER BY type, name"
    ), budget))
    schema_hash = _schema_hash(schema_rows, budget=budget)
    tables = [row[1] for row in schema_rows if row[0] == "table" and isinstance(row[1], str)]
    if "turn_usage" not in tables:
        return SchemaInspection("UNSUPPORTED", None, (), "SQLITE_SCHEMA_UNSUPPORTED", schema_hash)
    columns = tuple(
        row[1]
        for row in _checked(connection.execute("PRAGMA table_info(turn_usage)"), budget)
        if len(row) > 1 and isinstance(row[1], str)
    )
    required = {"id", "input_tokens", "cached_input_tokens", "created_at"}
    if not required.issubset(columns):
        return SchemaInspection("UNSUPPORTED", "turn_usage", columns, "SQLITE_SCHEMA_UNSUPPORTED", schema_hash)
    return SchemaInspection("OK", "turn_usage", columns, "KNOWN_TURN_USAGE_SCHEMA", schema_hash)


def _known_optional_columns(columns: tuple[str, ...]) -> tuple[str, ...]:
    allowed = (
        "host_id",
        "session_id_hash",
        "session_id",
        "turn_id_hash",
        "turn_id",
        "source_key",
        "source",
        "classification",
    )
    return tuple(name for name in allowed if name in columns)


def _source_classification(values: Mapping[str, object]) -> str:
    for key in ("classification", "source", "source_key"):
        value = str(values.get(key, "")).casefold()
        if value in {"external_article_copy", "external-reference", "external_reference"}:
            return "external_article_copy"
        if "external_article" in value or "external-reference" in value:
            return "external_article_copy"
    return "local_sqlite"


def _safe_row_key(values: Mapping[str, object], optional: tuple[str, ...]) -> str:
    key_columns = tuple(name for name in ("host_id", "session_id_hash", "session_id", "turn_id_hash", "turn_id", "source_key", "source") if name in optional)
    components = [str(values.get(name, "")) for name in key_columns if str(values.get(name, ""))]
    if not components:
        components = [str(values.get("id", ""))]
    return fingerprint("\x1f".join(components))


def read_deduplicated_usage(db_path: Path, settings: Any | None = None, *, budget=None) -> UsageReadResult:
    del settings
    _check(budget)
    assert_no_reparse_components(db_path)
    path = Path(db_path).resolve()
    database_hash = _database_hash(path, budget=budget)
    uri = "file:" + quote(path.as_posix(), safe="/:\\") + "?mode=ro"
    _check(budget)
    connection = sqlite3.connect(uri, uri=True, timeout=min(5.0, budget.remaining_ms() / 1000) if budget is not None else 5.0)
    interrupted = False

    def progress():
        nonlocal interrupted
        try:
            _check(budget)
            return 0
        except TimeoutError:
            interrupted = True
            return 1

    try:
        if budget is not None:
            connection.set_progress_handler(progress, 100)
        schema = inspect_sqlite_schema(connection, budget=budget)
        if schema.status != "OK":
            return UsageReadResult("SQLITE_SCHEMA_UNSUPPORTED", (), schema, database_hash)
        optional = _known_optional_columns(schema.columns)
        selected = ("id", "input_tokens", "cached_input_tokens", "created_at") + optional
        quoted = ", ".join('"' + column + '"' for column in selected)
        rows: dict[str, dict[str, Any]] = {}
        for raw in _checked(connection.execute(f"SELECT {quoted} FROM turn_usage ORDER BY id"), budget):
            values = dict(zip(selected, raw))
            row_key = _safe_row_key(values, optional)
            if row_key in rows:
                continue
            try:
                input_tokens = int(values["input_tokens"])
                cached_tokens = int(values["cached_input_tokens"])
            except (TypeError, ValueError):
                continue
            if input_tokens < 0 or cached_tokens < 0 or cached_tokens > input_tokens:
                continue
            source = _source_classification(values)
            rows[row_key] = {
                "id": row_key,
                "dedup_key": row_key,
                "source": source,
                "input": input_tokens,
                "cached": cached_tokens,
                "created_at": str(values["created_at"]),
            }
        _check(budget)
        return UsageReadResult("OK", tuple(rows.values()), schema, database_hash)
    except sqlite3.OperationalError as exc:
        if interrupted:
            raise TimeoutError("OPERATION_BUDGET_EXHAUSTED") from exc
        raise
    finally:
        connection.close()


def _row_totals(rows: Iterable[Mapping[str, Any]], *, budget=None) -> UsageAggregate:
    buckets = {"user": [0, 0, 0], "external": [0, 0, 0], "excluded": [0, 0, 0]}
    seen: set[tuple[str, str]] = set()
    for row in _checked(rows, budget):
        row_id = str(row.get("dedup_key", row.get("id", "")))
        source = str(row.get("source", "unknown"))
        key = (source, row_id)
        if key in seen:
            continue
        seen.add(key)
        try:
            input_tokens = int(row.get("input", 0))
            cached_tokens = int(row.get("cached", 0))
        except (TypeError, ValueError):
            buckets["excluded"][2] += 1
            continue
        if input_tokens < 0 or cached_tokens < 0 or cached_tokens > input_tokens:
            buckets["excluded"][2] += 1
            continue
        if source in {"external_article_copy", "external_reference", "external-reference"}:
            bucket = "external"
        elif source in {"local_sqlite", "local_usage"}:
            bucket = "user"
        else:
            bucket = "excluded"
        buckets[bucket][0] += input_tokens
        buckets[bucket][1] += cached_tokens
        buckets[bucket][2] += 1
    return UsageAggregate(
        user_environment=UsageTotals(*buckets["user"]),
        external_reference=UsageTotals(*buckets["external"]),
        excluded=UsageTotals(*buckets["excluded"]),
    )


def aggregate_usage(rows: Iterable[Mapping[str, Any]], *, budget=None) -> UsageAggregate:
    return _row_totals(rows, budget=budget)


def _json_totals(value: UsageTotals) -> dict[str, Any]:
    return {
        "input_tokens": value.input_tokens,
        "cached_input_tokens": value.cached_input_tokens,
        "uncached_input_tokens": value.uncached_input_tokens,
        "turns": value.turns,
    }


def _aggregate_dict(value: UsageAggregate) -> dict[str, Any]:
    return {
        "user_environment": _json_totals(value.user_environment),
        "external_reference": _json_totals(value.external_reference),
        "excluded": _json_totals(value.excluded),
    }


def _databases(home, budget):
    _check(budget)
    assert_no_reparse_components(home)
    if not home.exists():
        return []
    pending = [home]
    found = []
    while pending:
        _check(budget)
        directory = pending.pop()
        assert_safe_target(home, directory, allow_root=True, allow_missing=False, expected_type="dir")
        with os.scandir(directory) as entries:
            for entry in _checked(entries, budget):
                if entry.name.casefold() == ".git":
                    continue
                path = Path(entry.path)
                # Refuse a link/junction instead of following it outside the
                # selected host. No partial discovery is published as complete.
                assert_safe_target(home, path, allow_missing=False)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False) and path.suffix.casefold() in {".sqlite", ".sqlite3", ".db"}:
                    found.append(path)
    _check(budget)
    return sorted(found)


def collect_local_metrics(codex_home: Path, runtime_dir: Path, *, budget=None) -> LocalMetricsResult:
    _check(budget)
    assert_no_reparse_components(codex_home)
    home = Path(codex_home).resolve()
    candidates = _databases(home, budget)
    rows: list[dict[str, Any]] = []
    database_hashes: list[str] = []
    schema_hashes: list[str] = []
    known = 0
    unsupported = 0
    read_errors = 0
    for database in _checked(candidates, budget):
        try:
            result = read_deduplicated_usage(database, budget=budget)
        except TimeoutError:
            raise
        except (OSError, sqlite3.Error, ValueError):
            read_errors += 1
            continue
        database_hashes.append(result.database_sha256)
        if result.schema.schema_sha256:
            schema_hashes.append(result.schema.schema_sha256)
        if result.status == "OK":
            known += 1
            rows.extend({**row, "id": f"{result.database_sha256}:{row['id']}", "dedup_key": f"{result.database_sha256}:{row['dedup_key']}"} for row in _checked(result.rows, budget))
        else:
            unsupported += 1
    aggregate = aggregate_usage(rows, budget=budget)
    status = "OK" if candidates and known and not read_errors and not unsupported else "PARTIAL" if known or read_errors or unsupported else "UNAVAILABLE"
    result = LocalMetricsResult(
        status,
        len(candidates),
        known,
        unsupported,
        read_errors,
        aggregate,
        tuple(sorted(database_hashes)),
        tuple(sorted(schema_hashes)),
    )
    write_local_snapshot({"schema_version": 2, **result.to_dict()}, runtime_dir, budget=budget)
    return result


def write_local_snapshot(snapshot: UsageAggregate | Mapping[str, Any], runtime_dir: Path, *, budget=None) -> Path:
    _check(budget)
    path = Path(runtime_dir) / "usage-latest.json"
    if isinstance(snapshot, UsageAggregate):
        value = {"schema_version": 2, **_aggregate_dict(snapshot)}
    else:
        value = dict(snapshot)
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _check(budget)
    safe_ensure_directory(path.parent)
    _check(budget)
    safe_atomic_write(path.parent, path, raw)
    return path
