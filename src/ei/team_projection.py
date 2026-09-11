"""Build a machine-local projection of the append-only team event store.

The shared directory is read-only from this module's point of view.  A team
event is accepted only once per idempotency key, and a conflicting key is
excluded as a whole.  The resulting ``pattern.*`` events are deterministic
derived inputs to the existing personal projection writer.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .index import build_index, read_index_items
from .journal import event_integrity
from .models import Event, KnowledgeIndex
from .project import project_events
from .team_store import TeamEventScan, scan_team_events


_STORE_ID_RE = re.compile(r"^team_[0-9a-f]{16,64}$")
_SAFE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_.-]{1,79}$")
_CURSOR_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class TeamProjectionPaths:
    """Canonical locations for one machine's team projection cache."""

    root: Path
    knowledge_dir: Path
    index_path: Path
    cursor_path: Path


@dataclass(frozen=True)
class TeamProjectionResult:
    """Outcome of one refresh, including a last-known-good index when offline."""

    paths: TeamProjectionPaths
    index: KnowledgeIndex | None
    issues: tuple[Mapping[str, object], ...] = ()
    status: str = "UNCHANGED"
    accepted_event_count: int = 0

    @property
    def knowledge_dir(self) -> Path:
        return self.paths.knowledge_dir

    @property
    def index_path(self) -> Path:
        return self.paths.index_path

    @property
    def cursor_path(self) -> Path:
        return self.paths.cursor_path


def _validate_store_id(store_id: object) -> str:
    if not isinstance(store_id, str) or not _STORE_ID_RE.fullmatch(store_id):
        raise ValueError("TEAM_STORE_ID_INVALID")
    return store_id


def team_cache_paths(runtime_root: Path | str, store_id: str) -> TeamProjectionPaths:
    """Return paths without creating directories or touching the shared root."""

    store_id = _validate_store_id(store_id)
    root = Path(runtime_root).expanduser() / "team-cache" / store_id
    knowledge_dir = root / "knowledge"
    return TeamProjectionPaths(root, knowledge_dir, knowledge_dir / "index.json", root / "cursor.json")


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _safe_code(value: object, fallback: str = "TEAM_SCAN_ISSUE") -> str:
    code = str(value or "")
    return code if _SAFE_CODE_RE.fullmatch(code) else fallback


def _issue(code: object) -> dict[str, object]:
    safe = _safe_code(code)
    return {"code": safe, "reason_code": safe}


def _sanitize_issues(issues: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(issues, (list, tuple)):
        return ()
    return tuple(_issue(item.get("code") if isinstance(item, Mapping) else item) for item in issues)


def _issue_counts(issues: tuple[Mapping[str, object], ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in issues:
        code = _safe_code(item.get("code"), "TEAM_SCAN_ISSUE")
        counts[code] = counts.get(code, 0) + 1
    return dict(sorted(counts.items()))


def _read_cursor(paths: TeamProjectionPaths, store_id: str) -> dict[str, object] | None:
    try:
        value = json.loads(paths.cursor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping):
        return None
    if value.get("schema_version") != _CURSOR_SCHEMA_VERSION or value.get("store_id") != store_id:
        return None
    key = value.get("last_total_order_key")
    if key is not None and (not isinstance(key, list) or len(key) != 3 or any(not isinstance(item, str) for item in key)):
        return None
    accepted = value.get("accepted_event_count")
    if type(accepted) is not int or accepted < 0:
        return None
    projection_hash = value.get("projection_hash")
    if not isinstance(projection_hash, str):
        return None
    issue_counts = value.get("issue_counts", {})
    if not isinstance(issue_counts, Mapping) or any(not isinstance(key, str) or type(count) is not int or count < 0 for key, count in issue_counts.items()):
        return None
    return dict(value)


def _load_existing_index(paths: TeamProjectionPaths) -> KnowledgeIndex | None:
    try:
        return build_index(paths.knowledge_dir, paths.index_path)
    except (OSError, UnicodeError, ValueError):
        return None


def _order_key(event: Event) -> tuple[str, str, str]:
    return (event.occurred_at, event.event_id, event_integrity(event))


def _event_digest(event: Event, store_id: str) -> str:
    material = f"{store_id}\0{event.idempotency_key}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _derived_pattern_id(event: Event, store_id: str) -> str:
    return "pat_team_" + _event_digest(event, store_id)[:32]


def _derived_event_id(event: Event, store_id: str) -> str:
    return "evt_team_" + _event_digest(event, store_id)[:32]


def _list_value(value: object, fallback: str = "general") -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else [fallback]
    if isinstance(value, (list, tuple, set, frozenset)):
        result = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        return list(dict.fromkeys(result)) or [fallback]
    return [fallback]


def _derived_pattern_event(event: Event, store_id: str) -> Event:
    payload = event.payload
    scopes = _list_value(payload.get("scope"))
    preconditions = _list_value(payload.get("preconditions"), "同じ問題構造が再発している")
    failure_modes = _list_value(payload.get("failure_modes"), "検証を省略して再作業になる")
    pattern_id = _derived_pattern_id(event, store_id)
    derived_payload = {
        "pattern_id": pattern_id,
        "cluster_id": "cluster_" + pattern_id.removeprefix("pat_"),
        "rule": str(payload.get("claim", "")),
        "provenances": [str(payload.get("origin_event_hash", ""))],
        "scopes": scopes,
        "applicability": scopes,
        "benefit_count": 1,
        "classification": str(payload.get("classification", "private-reusable")),
        "precondition": " / ".join(preconditions),
        "failure_mode": " / ".join(failure_modes),
        "version_constraint": None,
    }
    return Event.create(
        "pattern.promoted",
        event.occurred_at,
        actor="team-projection",
        machine_id="team-projection",
        payload=derived_payload,
        event_id=_derived_event_id(event, store_id),
    )


def _accepted_events(events: tuple[Event, ...], store_id: str) -> tuple[tuple[Event, ...], tuple[Mapping[str, object], ...]]:
    groups: dict[str, list[Event]] = {}
    issues: list[Mapping[str, object]] = []
    for event in events:
        key = event.idempotency_key
        payload_key = event.payload.get("idempotency_key")
        if not isinstance(key, str) or payload_key != key:
            issues.append(_issue("TEAM_IDEMPOTENCY_CONFLICT"))
            continue
        groups.setdefault(key, []).append(event)
    accepted: list[Event] = []
    for key, group in sorted(groups.items()):
        by_hash: dict[str, Event] = {}
        for event in group:
            by_hash.setdefault(event_integrity(event), event)
        if len(by_hash) > 1:
            issues.append(_issue("TEAM_IDEMPOTENCY_CONFLICT"))
            continue
        accepted.append(min(by_hash.values(), key=_order_key))
    accepted.sort(key=_order_key)
    return tuple(accepted), tuple(issues)


def _existing_pattern_events(index: KnowledgeIndex | None) -> tuple[Event, ...]:
    if index is None:
        return ()
    ids = tuple(index.active_pattern_ids) + tuple(index.archive_pattern_ids)
    # Candidate IDs are not included in ``archive_pattern_ids`` and must be
    # retained for a stable incremental rebuild.
    document_ids = ids + tuple(getattr(index, "candidate_pattern_ids", ()))
    if not document_ids:
        return ()
    try:
        items = read_index_items(index, list(dict.fromkeys(document_ids)))
    except (OSError, UnicodeError, ValueError, KeyError):
        return ()
    result: list[Event] = []
    for item in items:
        pattern_id = item.get("pattern_id") or item.get("item_id")
        if not isinstance(pattern_id, str) or not pattern_id:
            continue
        status = str(item.get("status", "active")).casefold()
        event_type = {
            "candidate": "pattern.candidate_created",
            "deprecated": "pattern.deprecated",
            "superseded": "pattern.superseded",
            "tombstoned": "pattern.tombstoned",
        }.get(status, "pattern.promoted")
        occurred_at = str(item.get("updated_at") or "1970-01-01T00:00:00Z")
        payload = {
            "pattern_id": pattern_id,
            "cluster_id": str(item.get("cluster_id") or pattern_id),
            "rule": str(item.get("rule", "")),
            "provenances": list(item.get("provenances", ())),
            "scopes": list(item.get("scopes", item.get("applicability", ()))),
            "applicability": list(item.get("applicability", ())),
            "benefit_count": int(item.get("benefit_count", 0) or 0),
            "classification": str(item.get("classification", "private-reusable")),
            "precondition": str(item.get("precondition", "") or ""),
            "failure_mode": str(item.get("failure_mode", "") or ""),
            "version_constraint": item.get("version_constraint"),
        }
        digest = hashlib.sha256((pattern_id + "\0" + occurred_at).encode("utf-8")).hexdigest()[:32]
        result.append(Event.create(event_type, occurred_at, "team-cache", "team-cache", payload, event_id="evt_cached_" + digest))
    return tuple(result)


def _write_cursor(
    paths: TeamProjectionPaths,
    store_id: str,
    accepted: tuple[Event, ...],
    index: KnowledgeIndex | None,
    issues: tuple[Mapping[str, object], ...],
    previous: Mapping[str, object] | None,
    *,
    accepted_count: int | None = None,
) -> None:
    previous_key = previous.get("last_total_order_key") if previous else None
    current_key = list(_order_key(accepted[-1])) if accepted else None
    if previous_key and current_key:
        last_key = max(tuple(previous_key), tuple(current_key))
        last_key = list(last_key)
    else:
        last_key = current_key or previous_key
    total = len(accepted) if accepted_count is None else accepted_count
    if previous and total == 0:
        total = int(previous.get("accepted_event_count", 0) or 0)
    projection_hash = index.manifest_sha256 if index is not None else str(previous.get("projection_hash", "") if previous else "")
    value = {
        "schema_version": _CURSOR_SCHEMA_VERSION,
        "store_id": store_id,
        "last_total_order_key": last_key,
        "accepted_event_count": total,
        "projection_hash": projection_hash,
        "issue_counts": _issue_counts(issues),
    }
    _atomic_json(paths.cursor_path, value)


def _unavailable(paths: TeamProjectionPaths, issue: str, previous: Mapping[str, object] | None, existing: KnowledgeIndex | None) -> TeamProjectionResult:
    accepted_count = int(previous.get("accepted_event_count", 0) or 0) if previous else 0
    return TeamProjectionResult(paths, existing, (_issue(issue),), "UNAVAILABLE", accepted_count)


def refresh_team_projection(
    shared_root: Path | str,
    runtime_root: Path | str,
    store_id: str,
    *,
    scan_fn: Callable[[Path | str], TeamEventScan] | None = None,
) -> TeamProjectionResult:
    """Refresh one local team cache while preserving it during offline periods."""

    store_id = _validate_store_id(store_id)
    paths = team_cache_paths(runtime_root, store_id)
    previous = _read_cursor(paths, store_id)
    existing = _load_existing_index(paths)
    source = Path(shared_root).expanduser()
    try:
        if not source.is_dir():
            return _unavailable(paths, "TEAM_KNOWLEDGE_UNAVAILABLE", previous, existing)
    except OSError:
        return _unavailable(paths, "TEAM_KNOWLEDGE_UNAVAILABLE", previous, existing)

    scanner = scan_fn or scan_team_events
    try:
        scanned = scanner(source)
    except (OSError, TypeError, ValueError):
        return _unavailable(paths, "TEAM_KNOWLEDGE_UNAVAILABLE", previous, existing)
    if not isinstance(scanned, TeamEventScan):
        return _unavailable(paths, "TEAM_KNOWLEDGE_UNAVAILABLE", previous, existing)
    scan_issues = _sanitize_issues(scanned.issues)
    if any(item.get("code") in {"TEAM_ROOT_UNAVAILABLE", "TEAM_KNOWLEDGE_UNAVAILABLE"} for item in scan_issues):
        return _unavailable(paths, "TEAM_KNOWLEDGE_UNAVAILABLE", previous, existing)

    accepted, conflict_issues = _accepted_events(tuple(sorted(scanned.events, key=_order_key)), store_id)
    issues = tuple(scan_issues) + tuple(conflict_issues)
    known_ids = {item_id for item_id in (tuple(existing.active_pattern_ids) + tuple(existing.archive_pattern_ids) + tuple(getattr(existing, "candidate_pattern_ids", ())))} if existing else set()
    new_events = tuple(event for event in accepted if _derived_pattern_id(event, store_id) not in known_ids)
    previous_count = int(previous.get("accepted_event_count", 0) or 0) if previous else 0
    accepted_count = max(len(accepted), previous_count + len(new_events))
    if existing is not None and not new_events:
        _write_cursor(paths, store_id, accepted, existing, issues, previous, accepted_count=accepted_count)
        return TeamProjectionResult(paths, existing, issues, "UNCHANGED", accepted_count)

    derived = _existing_pattern_events(existing) + tuple(_derived_pattern_event(event, store_id) for event in new_events)
    index = project_events(derived, paths.knowledge_dir)
    _write_cursor(paths, store_id, accepted, index, issues, previous, accepted_count=accepted_count)
    status = "UPDATED" if new_events or existing is None else "UNCHANGED"
    return TeamProjectionResult(paths, index, issues, status, accepted_count)


__all__ = ["TeamProjectionPaths", "TeamProjectionResult", "refresh_team_projection", "team_cache_paths"]
