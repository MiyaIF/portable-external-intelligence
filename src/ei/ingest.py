from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .adapters.base import SourceAdapter, SourceRecord, SourceCursor, scan_read_only
from .config import Settings
from .ids import fingerprint, machine_id, stable_hash
from .journal import append_event
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


def _load_cursor(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": CURSOR_VERSION, "sources": {}}
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


def ingest_sources(settings: Settings, adapters: Iterable[SourceAdapter]) -> IngestResult:
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
                event = _event_for_record(
                    record,
                    record_fp,
                    settings,
                    _capture_path(record, adapter),
                    source_host_id=source_host_id,
                    source_host_family=source_host_family,
                )
                append_event(event, settings.paths.event_dir)
                created += 1
                health["parsed"] += 1
                event_ids.append(event.event_id)
                last_event_id = event.event_id
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
