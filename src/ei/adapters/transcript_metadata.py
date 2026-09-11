from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .base import SourceCursor, SourceRecord, fingerprint_source
from ..models import validate_host_label


class TranscriptMetadataAdapter:
    """Accept hook metadata only; never opens transcript content."""

    parser_version = "transcript-metadata-v2"
    capture_path = "agent_direct"
    host_id = ""
    host_family = ""

    def __init__(
        self,
        metadata: Iterable[Mapping[str, Any]],
        *,
        source_host_id: str = "",
        source_host_family: str = "",
    ):
        raw_metadata = tuple(metadata)
        self.metadata = tuple(item for item in raw_metadata if isinstance(item, Mapping))
        try:
            self.host_id = validate_host_label(source_host_id, field="source_host_id", allow_empty=True)
            self.host_family = validate_host_label(source_host_family, field="source_host_family", allow_empty=True)
        except ValueError:
            self.host_id = ""
            self.host_family = ""
        if bool(self.host_id) != bool(self.host_family):
            self.host_id = ""
            self.host_family = ""
        self.parse_skipped = len(raw_metadata) - len(self.metadata)
        self.health: dict[str, int] = {
            "parsed": 0,
            "parse_skipped": self.parse_skipped,
            "unsupported_format": 0,
            "excluded": 0,
            "rejected": 0,
        }

    @staticmethod
    def _hash_ref(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()

    @staticmethod
    def _observed_at(value: Any) -> str:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                return datetime.fromtimestamp(value, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                return datetime.now(timezone.utc).isoformat()
        if isinstance(value, str) and value.strip():
            return value.strip()
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def discover(cls, root: Path) -> Sequence[Path]:
        del root
        return ()

    def fingerprint(self, source: Path) -> SourceCursor:
        return fingerprint_source(Path(source), self.parser_version)

    def read(self, source: Path) -> Iterable[SourceRecord]:
        del source
        return ()

    def iter_records(self, cursor: Mapping[str, Any]) -> Iterable[SourceRecord]:
        del cursor
        self.parse_skipped = 0
        self.health.update({"parsed": 0, "parse_skipped": 0, "unsupported_format": 0, "excluded": 0, "rejected": 0})
        if not self.host_id or not self.host_family:
            rejected = len(self.metadata)
            self.health["rejected"] += rejected
            self.parse_skipped += rejected
            self.health["parse_skipped"] += rejected
            return
        for item in self.metadata:
            session_id = item.get("session_id")
            turn_id = item.get("turn_id")
            if not isinstance(session_id, str) or not session_id.strip() or not isinstance(turn_id, str) or not turn_id.strip():
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            cwd = item.get("cwd", "")
            domain = item.get("domain", "general")
            transcript_path = item.get("transcript_path", "")
            if not isinstance(cwd, str) or not isinstance(domain, str) or not isinstance(transcript_path, str):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            session_id = session_id.strip()
            turn_id = turn_id.strip()
            cwd = cwd.strip()
            domain = domain.strip() or "general"
            transcript_path = transcript_path.strip()
            path = Path(transcript_path) if transcript_path else None
            exists = False
            mtime_ns: int | None = None
            size: int | None = None
            if path is not None:
                try:
                    stat = path.stat()
                    exists = path.is_file()
                    mtime_ns = stat.st_mtime_ns if exists else None
                    size = stat.st_size if exists else None
                except OSError:
                    exists = False
            self.health["parsed"] += 1
            yield SourceRecord(
                source_kind="transcript_metadata",
                source_ref=transcript_path or f"session:{session_id}/turn:{turn_id}",
                source_hash=self._hash_ref(transcript_path or turn_id),
                observed_at=self._observed_at(item.get("observed_at")),
                title=f"transcript:{session_id}:{turn_id}",
                claim="",
                cwd=cwd,
                domain=domain,
                outcome_status="unknown",
                benefit="",
                classification="machine-local",
                parser_status="unsupported_format",
                provenance_key=f"transcript:{session_id}",
                applicability=(
                    f"transcript_exists={str(exists).lower()}",
                    f"transcript_mtime_ns={mtime_ns if mtime_ns is not None else 'unknown'}",
                    f"transcript_size={size if size is not None else 'unknown'}",
                    f"model={item.get('model').strip() if isinstance(item.get('model'), str) and item.get('model').strip() else 'unknown'}",
                ),
                source_host_id=self.host_id,
                source_host_family=self.host_family,
            )
