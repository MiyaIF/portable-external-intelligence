"""Deterministic checkpoints for the journal inputs of knowledge projections."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import Event


def validate_source_state(value: Any) -> None:
    if (not isinstance(value, Mapping)
            or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or type(value.get("event_count")) is not int or value["event_count"] < 0
            or not isinstance(value.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]) is None):
        raise ValueError("PROJECTION_SOURCE_STATE_INVALID")


def projection_source_state(events: Iterable[Event]) -> dict[str, Any]:
    rows = [event.to_dict() for event in events
            if event.event_type == "observation.recorded" or event.event_type.startswith("pattern.")]
    rows.sort(key=lambda row: row["event_id"])
    encoded = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"schema_version": 1, "event_count": len(rows),
            "digest": "sha256:" + hashlib.sha256(encoded).hexdigest()}


def projection_freshness(recorded: Mapping[str, Any] | None, current: Mapping[str, Any]) -> str:
    validate_source_state(current)
    if recorded is None:
        return "UNKNOWN"
    validate_source_state(recorded)
    return "CURRENT" if all(recorded[key] == current[key] for key in ("event_count", "digest")) else "STALE"


def projection_freshness_report(index_path: Path, events: Iterable[Event]) -> dict[str, Any]:
    """Read freshness without regenerating anything; callers also check file hashes."""
    events = list(events)
    document = json.loads(Path(index_path).read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("INDEX_JSON_INVALID")
    if "source_state" in document:
        validate_source_state(document["source_state"])
    current = projection_source_state(events)
    freshness = projection_freshness(document.get("source_state"), current)
    return {
        "freshness": freshness,
        "reason_code": {"CURRENT": None, "STALE": "PROJECTION_STALE",
                        "UNKNOWN": "PROJECTION_FRESHNESS_UNKNOWN"}[freshness],
        "source_event_count": current["event_count"],
        "source_observation_count": len({event.payload.get("observation_id", event.event_id)
                                         for event in events if event.event_type == "observation.recorded"}),
    }
