from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .base import SourceCursor, SourceRecord, fingerprint_source, scan_read_only


class GeminiAdapter:
    """Read stable Gemini session metadata records only."""

    parser_version = "gemini-cli-session-metadata-v1"
    capture_path = "native_memory"
    host_id = "gemini-cli"
    host_family = "gemini-compatible"
    _NAMES = frozenset({"session-metadata.json", "sessions.json", "stable-session-metadata.json"})

    def __init__(self, sources: Iterable[Path]):
        self.sources = tuple(Path(source) for source in sources)
        self.parse_skipped = 0
        self.health: dict[str, int] = {
            "parsed": 0,
            "parse_skipped": 0,
            "unsupported_format": 0,
            "excluded": 0,
        }

    @classmethod
    def discover(cls, root: Path) -> Sequence[Path]:
        return tuple(
            path
            for path in scan_read_only(root)
            if path.suffix.casefold() == ".json" and path.name.casefold() in cls._NAMES
        )

    def fingerprint(self, source: Path) -> SourceCursor:
        return fingerprint_source(Path(source), self.parser_version)

    @staticmethod
    def _hash(content: bytes) -> str:
        return "sha256:" + hashlib.sha256(content).hexdigest()

    @staticmethod
    def _text(value: object, required: bool = False) -> str | None:
        if not isinstance(value, str):
            return None
        text = value.strip()
        return text if text or not required else None

    def _record(
        self,
        entry: Mapping[str, Any],
        source: Path,
        source_hash: str,
        observed_at: str,
        session_id: str,
    ) -> SourceRecord | None:
        if any(key in entry for key in ("prompt", "response", "messages", "transcript", "tool_output")):
            self.health["excluded"] += 1
            return None
        title = self._text(entry.get("title"), True)
        claim = self._text(entry.get("claim", entry.get("rule", entry.get("content"))), True)
        if title is None or claim is None:
            self.parse_skipped += 1
            self.health["parse_skipped"] += 1
            return None
        domain = self._text(entry.get("domain")) or "general"
        outcome = self._text(entry.get("outcome_status")) or "unknown"
        benefit = self._text(entry.get("benefit")) or "reduced_search"
        entry_id = self._text(entry.get("id")) or hashlib.sha256((session_id + title).encode("utf-8")).hexdigest()[:20]
        cwd = self._text(entry.get("cwd_fingerprint", entry.get("scope_hash"))) or ""
        classification = self._text(entry.get("classification")) or "private-reusable"
        self.health["parsed"] += 1
        return SourceRecord(
            source_kind="gemini_session_metadata",
            source_ref=str(source.resolve()),
            source_hash=source_hash,
            observed_at=observed_at,
            title=title,
            claim=claim,
            cwd=cwd,
            domain=domain,
            outcome_status=outcome,
            benefit=benefit,
            classification=classification,
            applicability=(domain,),
            provenance_key=f"gemini:{session_id or entry_id}",
            source_host_id=self.host_id,
            source_host_family=self.host_family,
        )

    def read(self, source: Path) -> Iterable[SourceRecord]:
        path = Path(source)
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("SOURCE_CHANGED_DURING_READ")
        document = json.loads(content.decode("utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise ValueError("UNSUPPORTED_FORMAT")
        if document.get("host", "gemini-cli") != "gemini-cli":
            raise ValueError("UNSUPPORTED_FORMAT")
        entries = document.get("sessions", document.get("records"))
        if not isinstance(entries, list):
            raise ValueError("UNSUPPORTED_FORMAT")
        source_hash = self._hash(content)
        observed_at = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()
        for session in entries:
            if not isinstance(session, dict):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            session_id = self._text(session.get("session_id", session.get("id")), True)
            if session_id is None:
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            observations = session.get("observations", session.get("entries"))
            if not isinstance(observations, list):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            session_scope = self._text(session.get("cwd_fingerprint", session.get("scope_hash"))) or ""
            for raw in observations:
                if not isinstance(raw, dict):
                    self.parse_skipped += 1
                    self.health["parse_skipped"] += 1
                    continue
                item = dict(raw)
                if session_scope and "cwd_fingerprint" not in item and "scope_hash" not in item:
                    item["cwd_fingerprint"] = session_scope
                record = self._record(item, path, source_hash, observed_at, session_id)
                if record is not None:
                    yield record

    def iter_records(self, cursor: Mapping[str, Any]) -> Iterable[SourceRecord]:
        del cursor
        self.parse_skipped = 0
        self.health.update({"parsed": 0, "parse_skipped": 0, "unsupported_format": 0, "excluded": 0})
        for source in self.sources:
            try:
                yield from self.read(source)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                self.health["unsupported_format"] += 1


GeminiCliAdapter = GeminiAdapter
