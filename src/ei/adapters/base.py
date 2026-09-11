from __future__ import annotations

import hashlib
import os
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence


_DENIED_COMPONENTS = frozenset(
    {
        ".env",
        "auth",
        "auth.json",
        "authentication",
        "browser",
        "browser-state",
        "cookie",
        "cookies",
        "credentials",
        "sqlite",
        "spool",
        "transcript",
        "transcripts",
        "raw-transcript",
        "raw_transcript",
        ".ei-local",
    }
)


def _normalized_parts(path: Path) -> tuple[str, ...]:
    text = unicodedata.normalize("NFKC", str(path)).replace("\\", "/")
    return tuple(part for part in text.split("/") if part not in {"", "."})


def is_readable_metadata_path(path: Path) -> bool:
    parts = tuple(part.casefold() for part in _normalized_parts(Path(path)))
    if any(part.startswith(".env") or part.endswith((".sqlite", ".sqlite3", ".db")) for part in parts):
        return False
    if any(part in _DENIED_COMPONENTS or "transcript" in part or "browser" in part for part in parts):
        return False
    return Path(path).suffix.casefold() in {".md", ".json", ".jsonl"}


def scan_read_only(root: Path) -> Sequence[Path]:
    """List documented metadata candidates without opening or modifying them."""
    if not isinstance(root, Path):
        raise ValueError("SOURCE_ROOT_INVALID")
    candidate_root = root.expanduser().resolve(strict=False)
    if not candidate_root.exists() or not candidate_root.is_dir():
        return ()
    result: list[Path] = []
    for path in sorted(candidate_root.rglob("*")):
        junction = getattr(path, "is_junction", None)
        if path.is_symlink() or (callable(junction) and junction()):
            continue
        if path.is_file() and is_readable_metadata_path(path):
            result.append(path.resolve())
    return tuple(result)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def fingerprint_source(path: Path, parser_version: str) -> "SourceCursor":
    if not isinstance(path, Path):
        raise ValueError("SOURCE_PATH_INVALID")
    if not is_readable_metadata_path(path):
        raise ValueError("SOURCE_PATH_DENIED")
    try:
        junction = getattr(path, "is_junction", None)
        if path.is_symlink() or (callable(junction) and junction()):
            raise ValueError("SOURCE_PATH_REPARSE")
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
    except (OSError, ValueError) as exc:
        raise ValueError("SOURCE_READ_FAILED") from exc
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError("SOURCE_CHANGED_DURING_READ")
    return SourceCursor(
        source_path_hash="sha256:" + _sha256_bytes(str(path.resolve()).encode("utf-8")),
        size_bytes=len(content),
        mtime_ns=after.st_mtime_ns,
        content_hash="sha256:" + _sha256_bytes(content),
        parser_version=parser_version,
    )


@dataclass(frozen=True)
class SourceCursor:
    """Machine-local source fingerprint; never a Git event payload."""

    source_path_hash: str
    size_bytes: int
    mtime_ns: int
    content_hash: str
    parser_version: str
    last_record_fingerprint: str = ""
    last_event_id: str = ""

    @property
    def path_hash(self) -> str:
        return self.source_path_hash

    @property
    def size(self) -> int:
        return self.size_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path_hash": self.source_path_hash,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
            "content_hash": self.content_hash,
            "parser_version": self.parser_version,
            "last_record_fingerprint": self.last_record_fingerprint,
            "last_event_id": self.last_event_id,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SourceCursor":
        if not isinstance(value, Mapping):
            raise ValueError("SOURCE_CURSOR_INVALID")
        required = ("source_path_hash", "size_bytes", "mtime_ns", "content_hash", "parser_version")
        if any(name not in value for name in required):
            raise ValueError("SOURCE_CURSOR_FIELDS_MISSING")
        if (
            not isinstance(value["source_path_hash"], str)
            or type(value["size_bytes"]) is not int
            or type(value["mtime_ns"]) is not int
            or not isinstance(value["content_hash"], str)
            or not isinstance(value["parser_version"], str)
        ):
            raise ValueError("SOURCE_CURSOR_INVALID")
        for name in ("last_record_fingerprint", "last_event_id"):
            if name in value and not isinstance(value[name], str):
                raise ValueError("SOURCE_CURSOR_INVALID")
        return cls(
            source_path_hash=value["source_path_hash"],
            size_bytes=value["size_bytes"],
            mtime_ns=value["mtime_ns"],
            content_hash=value["content_hash"],
            parser_version=value["parser_version"],
            last_record_fingerprint=value.get("last_record_fingerprint", ""),
            last_event_id=value.get("last_event_id", ""),
        )


@dataclass(frozen=True)
class SourceRecord:
    """A normalized observation; candidate_text is transient and never serialized."""

    source_kind: str
    source_ref: str
    source_hash: str
    observed_at: str
    title: str
    claim: str
    cwd: str
    domain: str
    outcome_status: str
    benefit: str
    classification: str
    applicability: tuple[str, ...] = ()
    parser_status: str = "parsed"
    provenance_key: str = ""
    candidate_text: str | None = None
    source_host_id: str = ""
    source_host_family: str = ""

    def __post_init__(self) -> None:
        text_fields = (
            self.source_kind,
            self.source_ref,
            self.source_hash,
            self.observed_at,
            self.title,
            self.claim,
            self.cwd,
            self.domain,
            self.outcome_status,
            self.benefit,
            self.classification,
            self.parser_status,
            self.provenance_key,
            self.source_host_id,
            self.source_host_family,
        )
        if any(not isinstance(value, str) for value in text_fields):
            raise TypeError("SOURCE_RECORD_TEXT_INVALID")
        if not isinstance(self.applicability, tuple) or any(not isinstance(item, str) for item in self.applicability):
            raise TypeError("SOURCE_RECORD_APPLICABILITY_INVALID")
        if self.candidate_text is not None and not isinstance(self.candidate_text, str):
            raise TypeError("SOURCE_RECORD_CANDIDATE_INVALID")
        if bool(self.source_host_id) != bool(self.source_host_family):
            raise ValueError("SOURCE_RECORD_HOST_PAIR_INVALID")

    @property
    def record_text(self) -> str:
        return self.claim

    def event_fields(self) -> dict[str, Any]:
        """Return only normalized reusable fields; transient candidate_text is excluded."""
        return {
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "source_hash": self.source_hash,
            "observed_at": self.observed_at,
            "title": self.title,
            "claim": self.claim,
            "cwd": self.cwd,
            "domain": self.domain,
            "outcome_status": self.outcome_status,
            "benefit": self.benefit,
            "classification": self.classification,
            "applicability": list(self.applicability),
            "parser_status": self.parser_status,
            "provenance_key": self.provenance_key,
            "source_host_id": self.source_host_id,
            "source_host_family": self.source_host_family,
        }


class SourceAdapter(Protocol):
    """Read-only adapter contract shared by all host/source implementations."""

    parser_version: str
    capture_path: str
    parse_skipped: int
    host_id: str
    host_family: str

    def discover(self, root: Path) -> Sequence[Path]:
        ...

    def fingerprint(self, source: Path) -> SourceCursor:
        ...

    def read(self, source: Path) -> Iterable[SourceRecord]:
        ...

    def iter_records(self, cursor: Mapping[str, Any]) -> Iterable[SourceRecord]:
        ...


def observed_at_from_mtime(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    except (OSError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def stable_source_hash(path: Path, content: bytes) -> str:
    return "sha256:" + _sha256_bytes(content)


def sanitized_parse_failure() -> str:
    return "unsupported_format"
