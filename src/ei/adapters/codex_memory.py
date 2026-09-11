from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .base import (
    SourceCursor,
    SourceRecord,
    fingerprint_source,
    observed_at_from_mtime,
    scan_read_only,
)


class CodexMemoryAdapter:
    """Parse only known Markdown memory sections without modifying sources."""

    parser_version = "codex-memory-v2"
    capture_path = "native_memory"
    host_id = "codex-cli"
    host_family = "codex-compatible"
    _KNOWN_SECTIONS = {
        "reusable knowledge": ("success", "reduced_rework"),
        "failures and how to do differently": ("failed", "avoided_failure"),
        "failures": ("failed", "avoided_failure"),
    }
    _BULLET = re.compile(r"^\s*[-*+]\s+(?P<text>\S.*)$")
    _HEADING = re.compile(r"^\s*#{1,6}\s+(?P<text>\S.*)$")

    def __init__(self, sources: Iterable[Path]):
        self.sources = tuple(Path(source) for source in sources)
        self.parse_skipped = 0
        self.health: dict[str, int] = {
            "parsed": 0,
            "parse_skipped": 0,
            "unsupported_format": 0,
            "excluded": 0,
        }

    @staticmethod
    def _normalize_heading(value: str) -> str:
        value = unicodedata.normalize("NFKC", value).strip().casefold()
        value = re.sub(r"[：:]+$", "", value)
        return re.sub(r"\s+", " ", value)

    @staticmethod
    def _sha256(content: bytes) -> str:
        return "sha256:" + hashlib.sha256(content).hexdigest()

    @staticmethod
    def _domain(path: Path) -> str:
        stem = re.sub(r"[^a-z0-9_-]+", "-", path.stem.casefold()).strip("-")
        return stem or "memory"

    @classmethod
    def discover(cls, root: Path) -> Sequence[Path]:
        return tuple(
            path
            for path in scan_read_only(root)
            if path.suffix.casefold() == ".md"
            and path.name.casefold() in {"memory.md", "memory_summary.md", "raw_memories.md"}
        )

    def fingerprint(self, source: Path) -> SourceCursor:
        return fingerprint_source(Path(source), self.parser_version)

    def read(self, source: Path) -> Iterable[SourceRecord]:
        path = Path(source)
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("SOURCE_CHANGED_DURING_READ")
        text = content.decode("utf-8", errors="strict")
        source_hash = self._sha256(content)
        observed_at = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()
        domain = self._domain(path)
        section: tuple[str, str] | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            heading = self._HEADING.match(line)
            if heading:
                section = self._KNOWN_SECTIONS.get(self._normalize_heading(heading.group("text")))
                continue
            bullet = self._BULLET.match(line)
            if not bullet:
                continue
            if section is None:
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            claim = bullet.group("text").strip()
            if not claim:
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            outcome_status, benefit = section
            self.health["parsed"] += 1
            yield SourceRecord(
                source_kind="codex_memory",
                source_ref=str(path.resolve()),
                source_hash=source_hash,
                observed_at=observed_at,
                title=f"{domain}:{line_number}",
                claim=claim,
                cwd="",
                domain=domain,
                outcome_status=outcome_status,
                benefit=benefit,
                classification="private-reusable",
                provenance_key=f"memory:{source_hash}",
                source_host_id=self.host_id,
                source_host_family=self.host_family,
            )

    def iter_records(self, cursor: Mapping[str, Any]) -> Iterable[SourceRecord]:
        del cursor
        self.parse_skipped = 0
        self.health.update({"parsed": 0, "parse_skipped": 0, "unsupported_format": 0, "excluded": 0})
        for source in self.sources:
            try:
                yield from self.read(source)
            except (OSError, UnicodeError, ValueError):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                self.health["unsupported_format"] += 1
                continue
