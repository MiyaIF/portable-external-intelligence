from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .ids import stable_hash
from .privacy import inspect_text


TERMINAL_DISPOSITIONS = frozenset(
    {
        "imported",
        "referenced_only",
        "duplicate",
        "skipped_with_reason",
        "rejected_privacy",
        "rejected_secret",
        "unsupported_format",
    }
)
_ARTICLE_MARKERS = ("48.35m", "48,350,000", "98.7%", "4,772", "4,800万", "4,835万")
_MEMORY_HEADINGS = re.compile(
    r"^\s*#{1,6}\s+(reusable knowledge|failures|failures and how to do differently)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_ARTICLE_PATH_MARKER = re.compile(r"(?:^|[-_ ])(?:external[-_ ]?)?article(?:[-_ ]|$)", re.IGNORECASE)
_KNOWN_METADATA_NAMES = {
    "agents.md": "global_agents_metadata",
    "config.toml": "config_metadata",
    "hooks.json": "hooks_metadata",
}


class SourceAuthorizationError(ValueError):
    """Raised before source enumeration when a source root is not authorized."""


@dataclass(frozen=True)
class SourceDisposition:
    source_kind: str
    normalized_path_hash: str
    content_hash: str
    size_bytes: int
    provenance: str
    disposition: str
    reason_code: str
    produced_event_ids: tuple[str, ...] = ()
    historical: bool = False
    source_path: Path | None = field(default=None, repr=False, compare=False)
    source_root_hash: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("source_path", None)
        value.pop("source_root_hash", None)
        value["produced_event_ids"] = list(self.produced_event_ids)
        return value


@dataclass(frozen=True)
class SourceInventory:
    rows: tuple[SourceDisposition, ...]
    discovered: int
    imported: int
    referenced: int
    skipped_with_reason: int
    rejected: int
    unclassified: int
    historical_pending_review: int
    inventory_hash: str
    schema_version: int = 2
    source_root_hashes: tuple[str, ...] = ()
    privacy_scan_complete: bool = True
    source_roots: tuple[Path, ...] = field(default_factory=tuple, repr=False, compare=False)

    @property
    def disposition_counts(self) -> dict[str, int]:
        return {
            disposition: sum(1 for row in self.rows if row.disposition == disposition)
            for disposition in sorted(TERMINAL_DISPOSITIONS)
        }

    @property
    def balance_holds(self) -> bool:
        counts = self.disposition_counts
        return (
            self.discovered == sum(counts.values())
            and self.unclassified == 0
            and all(row.disposition in TERMINAL_DISPOSITIONS for row in self.rows)
        )

    def to_dict(self) -> dict[str, object]:
        exact_counts = self.disposition_counts
        return {
            "schema_version": self.schema_version,
            "rows": [row.to_dict() for row in self.rows],
            "counts": {
                "discovered": self.discovered,
                **exact_counts,
                # Compatibility aggregates retained for pre-Task-15 consumers.
                "referenced": exact_counts["referenced_only"],
                "skipped_with_reason": exact_counts["skipped_with_reason"] + exact_counts["duplicate"] + exact_counts["unsupported_format"],
                "rejected": exact_counts["rejected_privacy"] + exact_counts["rejected_secret"],
                "unclassified": self.unclassified,
                "historical_pending_review": self.historical_pending_review,
            },
            "source_root_hashes": list(self.source_root_hashes),
            "privacy_scan_complete": self.privacy_scan_complete,
            "balance_holds": self.balance_holds,
            "inventory_hash": self.inventory_hash,
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_root(value: Path | str) -> Path:
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED") from exc


def _path_key(path: Path) -> str:
    value = os.path.normpath(os.path.abspath(str(path)))
    return os.path.normcase(value).rstrip("\\/") or value


def _migration_file_category(relative: str) -> str | None:
    parts = PurePosixPath(relative).parts
    if not parts:
        return None
    if relative == "knowledge-repository.json":
        return "manifest"
    if relative == ".gitignore":
        return "repository_metadata"
    if parts[0] == "events" and len(parts) >= 2 and relative.casefold().endswith(".json"):
        return "event"
    if parts[0] == "knowledge" and len(parts) >= 2 and Path(parts[-1]).suffix.casefold() in {".md", ".json"}:
        return "knowledge_projection"
    if len(parts) >= 3 and parts[0] == "policies" and parts[1] == "user-overrides":
        return "user_policy"
    if parts[0] == "experiments" and len(parts) >= 2 and Path(parts[-1]).suffix.casefold() in {".json", ".jsonl", ".md"}:
        return "experiment"
    return None


def authorized_migration_files(root_value: Path | str) -> tuple[tuple[str, Path, str], ...]:
    """Enumerate only sanitized files permitted in a combined-root migration."""
    root = _canonical_root(root_value)
    if not root.is_dir() or _has_reparse_component(root):
        raise SourceAuthorizationError("MIGRATION_SOURCE_ROOT_INVALID")
    result: list[tuple[str, Path, str]] = []
    paths = sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if ".git" in PurePosixPath(relative).parts:
            continue
        if _has_reparse_component(path):
            raise SourceAuthorizationError("UNSAFE_REPARSE_POINT")
        if not path.is_file():
            continue
        category = _migration_file_category(relative)
        if category is None:
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise SourceAuthorizationError("MIGRATION_SOURCE_READ_FAILED") from exc
        decision = inspect_text(text, "private-reusable", relative)
        if not decision.allow_private_sync and decision.reason_code != "CLASSIFIED":
            raise SourceAuthorizationError("MIGRATION_PRIVACY_REJECTED")
        result.append((relative, path, category))
    return tuple(result)


def _within(candidate: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_path_key(candidate), _path_key(root))) == _path_key(root)
    except (OSError, ValueError):
        return False


def _has_reparse_component(path: Path) -> bool:
    current = path
    parts = list(path.parents)[::-1] + [path]
    for candidate in parts:
        try:
            if candidate.is_symlink():
                return True
            is_junction = getattr(candidate, "is_junction", None)
            if callable(is_junction) and is_junction():
                return True
        except OSError:
            return True
    return False


def _settings_paths(settings: Any) -> Any:
    paths = getattr(settings, "paths", None)
    if paths is None:
        raise SourceAuthorizationError("SOURCE_SETTINGS_REQUIRED")
    return paths


def _configured_roots(settings: Any) -> tuple[Path, ...]:
    for name in ("migration_source_roots", "authorized_source_roots", "source_roots"):
        configured = getattr(settings, name, None)
        if configured:
            return tuple(_canonical_root(value) for value in configured)
    return ()


def _approval_recorded(settings: Any, approval_path: Path | None = None) -> bool:
    if bool(getattr(settings, "task19_approval", False)) or bool(getattr(settings, "global_source_approved", False)):
        return True
    paths = _settings_paths(settings)
    candidates: list[Path] = []
    if approval_path is not None:
        candidates.append(_canonical_root(approval_path))
    runtime = getattr(paths, "runtime_root", None)
    if runtime is not None:
        runtime_path = _canonical_root(runtime)
        candidates.extend(
            (
                runtime_path / "state" / "task19-approval.json",
                runtime_path / "state" / "production-approval.json",
                runtime_path / "task19-approval.json",
            )
        )
    repo = getattr(paths, "repo_root", None)
    if repo is not None:
        repo_path = _canonical_root(repo)
        candidates.extend(
            (
                repo_path / "release" / "production-approval.json",
                repo_path / "release" / "task19-approval.json",
            )
        )
    for candidate in candidates:
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, Mapping):
            continue
        if value.get("approved") is True or value.get("task19_approved") is True:
            scope = value.get("scope")
            if scope is None or scope in {"migration", "global-source", "production", "task19"}:
                return True
    return False


def resolve_source_roots(
    roots: Sequence[Path | str] | Path | str,
    settings: Any,
    *,
    allow_global_source: bool = False,
    approval_path: Path | None = None,
) -> tuple[Path, ...]:
    """Resolve and authorize roots before any directory enumeration occurs."""
    if isinstance(roots, (str, Path)):
        raw_roots: tuple[Path | str, ...] = (roots,)
    elif isinstance(roots, Sequence) and not isinstance(roots, (bytes, bytearray)):
        raw_roots = tuple(roots)
    else:
        raise SourceAuthorizationError("SOURCE_ROOT_REQUIRED")
    if not raw_roots:
        raise SourceAuthorizationError("SOURCE_ROOT_REQUIRED")

    paths = _settings_paths(settings)
    repo = _canonical_root(getattr(paths, "repo_root"))
    runtime = _canonical_root(getattr(paths, "runtime_root", getattr(paths, "runtime_dir", repo / ".ei-local")))
    codex_home = _canonical_root(getattr(paths, "codex_home", runtime.parent))
    configured_roots = _configured_roots(settings)
    global_roots = (codex_home / "memories", codex_home / "memory")
    is_auto = any(isinstance(value, str) and value.strip().casefold() == "auto" for value in raw_roots)
    if is_auto:
        if len(raw_roots) != 1 or not allow_global_source or not _approval_recorded(settings, approval_path):
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        candidates = tuple(root for root in global_roots if root.exists())
        if not candidates:
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_FOUND")
    else:
        candidates = tuple(_canonical_root(value) for value in raw_roots)

    authorized: list[Path] = []
    for root in candidates:
        if not root.exists() or not root.is_dir():
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_FOUND")
        if _has_reparse_component(root):
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        if root == repo or _within(repo, root):
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        if root == runtime:
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        if configured_roots and not any(_within(root, configured) or _within(configured, root) for configured in configured_roots):
            raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        if any(_within(root, global_root) or _within(global_root, root) for global_root in global_roots):
            if not allow_global_source or not _approval_recorded(settings, approval_path):
                raise SourceAuthorizationError("SOURCE_ROOT_NOT_AUTHORIZED")
        authorized.append(root)
    return tuple(dict.fromkeys(authorized))


def _legacy_context(first: Any, second: Any) -> tuple[tuple[Path, ...], Any, bool]:
    if hasattr(second, "paths"):
        return tuple(), second, False
    if isinstance(first, (Path, str)) and isinstance(second, (Path, str)):
        # Compatibility for the original inventory_existing_state(codex_home, memory_root) API.
        return (_canonical_root(second),), {"codex_home": _canonical_root(first)}, True
    raise SourceAuthorizationError("SOURCE_SETTINGS_REQUIRED")


def _source_root_hash(root: Path) -> str:
    return "sha256:" + _sha256(str(root).encode("utf-8"))


def _relative_hash(root: Path, path: Path) -> str:
    return stable_hash(path.relative_to(root).as_posix())


def _provenance(source_kind: str, content_hash: str, path_hash: str) -> str:
    basis = content_hash + "\0" + path_hash
    return f"{source_kind}:{stable_hash(basis)[:24]}"


def _article_text(content: bytes) -> str:
    return content[:200_000].decode("utf-8", errors="ignore").casefold()


def _is_article(relative: str, content: bytes) -> bool:
    text = _article_text(content)
    path_match = bool(_ARTICLE_PATH_MARKER.search(relative.replace("\\", "/")))
    explicit_marker = "[external_article_copy]" in text or "external article reference" in text
    numeric_marker = any(marker.casefold() in text for marker in _ARTICLE_MARKERS)
    return path_match or explicit_marker or (numeric_marker and "article" in text)


def _source_kind(relative: str, content: bytes) -> str:
    normalized = relative.replace("\\", "/")
    lowered = normalized.casefold()
    name = Path(normalized).name.casefold()
    if _is_article(normalized, content):
        return "external_article_copy"
    if name in {"memory.md", "memory_summary.md", "raw_memories.md"}:
        return "memory_markdown"
    if lowered.startswith("patterns/"):
        if name in {"promotion-criteria.md", "retention-policy.md", "privacy-policy.md", "retrieval-policy.md"}:
            return "policy_provenance"
        return "patterns_evidence"
    if lowered.startswith("skills/") and name == "skill.md":
        return "skill_instruction"
    if lowered.startswith("rollout_summaries/") and name.endswith(".jsonl"):
        return "rollout_summary"
    if lowered.startswith("extensions/ad_hoc/notes/"):
        return "ad_hoc_note"
    if Path(normalized).suffix.casefold() == ".md":
        try:
            if _MEMORY_HEADINGS.search(content.decode("utf-8")):
                return "memory_markdown"
        except UnicodeDecodeError:
            return "unknown"
    return "unknown"


def _privacy_reason(source_kind: str, relative: str, content: bytes) -> str | None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "INVALID_UTF8"
    if source_kind == "external_article_copy":
        # The source is retained as an external reference, but secret scanning still applies.
        decision = inspect_text(text, "private-reusable", relative)
    else:
        decision = inspect_text(text, source_kind, relative)
    if decision.reason_code == "SECRET_PATTERN_MATCH":
        return "SECRET_PATTERN_MATCH"
    if decision.reason_code in {"CLIENT_CONFIDENTIAL_LOCAL_ONLY", "MACHINE_LOCAL_SOURCE", "MACHINE_LOCAL_PATH"}:
        return decision.reason_code
    return None


def _current_row(
    root: Path,
    path: Path,
    source_kind: str,
    content: bytes,
    disposition: str,
    reason_code: str,
    *,
    source_root_hash: str,
    root_index: int,
) -> SourceDisposition:
    path_hash = stable_hash(f"{root_index}:{path.relative_to(root).as_posix()}")
    content_hash = _sha256(content)
    return SourceDisposition(
        source_kind,
        path_hash,
        content_hash,
        len(content),
        _provenance(source_kind, content_hash, path_hash),
        disposition,
        reason_code,
        source_path=path,
        source_root_hash=source_root_hash,
    )


def _iter_current_entries(root: Path) -> Iterable[tuple[Path, bytes | None, str | None]]:
    for path in sorted(root.rglob("*")):
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if ".git" in {part.casefold() for part in relative_parts}:
            continue
        if path.is_symlink() or (callable(getattr(path, "is_junction", None)) and path.is_junction()):
            if path.is_file():
                yield path, None, "SYMLINK_SKIPPED"
            continue
        if path.is_file():
            try:
                yield path, path.read_bytes(), None
            except OSError:
                yield path, None, "READ_FAILED"


def _metadata_row(path: Path, source_kind: str, content_hash: str, size: int, reason: str, disposition: str) -> SourceDisposition:
    path_hash = stable_hash(str(path))
    return SourceDisposition(
        source_kind,
        path_hash,
        content_hash,
        size,
        _provenance(source_kind, content_hash, path_hash),
        disposition,
        reason,
        source_path=path,
    )


def _metadata_paths(settings: Any, codex_home: Path) -> tuple[tuple[Path, str], ...]:
    candidates: list[tuple[Path, str]] = [
        (codex_home / name, kind) for name, kind in sorted(_KNOWN_METADATA_NAMES.items())
    ]
    for host in getattr(settings, "hosts", {}).values() if settings is not None else ():
        for attribute in ("global_context_path", "hook_config_path"):
            value = getattr(host, attribute, None)
            if isinstance(value, Path):
                candidates.append((value, "host_metadata"))
    unique: dict[str, tuple[Path, str]] = {}
    for path, kind in candidates:
        unique.setdefault(str(path.resolve(strict=False)), (path, kind))
    return tuple(unique.values())


def _sqlite_schema(path: Path) -> tuple[str, str]:
    try:
        uri = "file:" + str(path.resolve()).replace("\\", "/").replace("?", "%3F") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            rows = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('table','index','view','trigger') ORDER BY type, name"
            ).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        return "", type(exc).__name__
    metadata = [
        {
            "type": row[0] if isinstance(row[0], str) else "",
            "name_hash": stable_hash(row[1] if isinstance(row[1], str) else ""),
            "table_name_hash": stable_hash(row[2] if isinstance(row[2], str) else ""),
            "sql_hash": stable_hash(row[3] if isinstance(row[3], str) else ""),
        }
        for row in rows
    ]
    return _sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")), ""


def _sqlite_rows(codex_home: Path) -> list[SourceDisposition]:
    rows: list[SourceDisposition] = []
    if not codex_home.exists():
        return rows
    for path in sorted(codex_home.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".sqlite", ".sqlite3", ".db"}:
            continue
        if ".git" in {part.casefold() for part in path.relative_to(codex_home).parts}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            rows.append(_metadata_row(path, "sqlite_schema_metadata", _sha256(b""), 0, "STAT_FAILED", "skipped_with_reason"))
            continue
        schema_hash, error = _sqlite_schema(path)
        if error:
            rows.append(_metadata_row(path, "sqlite_schema_metadata", _sha256(error.encode("utf-8")), size, "SQLITE_SCHEMA_READ_FAILED", "skipped_with_reason"))
        else:
            rows.append(_metadata_row(path, "sqlite_schema_metadata", schema_hash, size, "SQLITE_SCHEMA_ONLY", "referenced_only"))
    return rows


def _git_history(root: Path, root_index: int) -> list[SourceDisposition]:
    git_dir = root / ".git"
    if not git_dir.exists():
        return []
    command = ["git", "-C", str(root), "log", "--all", "--format=COMMIT:%H", "--name-status", "--", "."]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    commit = ""
    candidates: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        if line.startswith("COMMIT:"):
            commit = line[7:].strip()
            continue
        if not commit or not line.strip() or line.startswith(" "):
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[0][0] in "AMD":
            candidates.append((commit, parts[-1]))
        elif len(parts) >= 3 and parts[0].startswith("R"):
            candidates.append((commit, parts[-1]))
    rows: list[SourceDisposition] = []
    seen: set[tuple[str, str]] = set()
    for commit, relative in candidates:
        relative = relative.replace("\\", "/")
        key = (commit, relative)
        if key in seen or relative.startswith(".git/"):
            continue
        seen.add(key)
        try:
            blob = subprocess.run(
                ["git", "-C", str(root), "show", f"{commit}:{relative}"],
                capture_output=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if blob.returncode != 0:
            continue
        content_hash = "sha256:" + _sha256(blob.stdout)
        path_hash = stable_hash(f"{root_index}:{relative}")
        rows.append(
            SourceDisposition(
                "historical_git",
                path_hash,
                content_hash,
                len(blob.stdout),
                f"git:{commit[:24]}",
                "referenced_only",
                "HISTORICAL_BLOB_PENDING_REVIEW",
                historical=True,
                source_root_hash=_source_root_hash(root),
            )
        )
    return rows


def _build_inventory(roots: tuple[Path, ...], settings: Any, codex_home: Path) -> SourceInventory:
    rows: list[SourceDisposition] = []
    seen_content: set[str] = set()
    privacy_scan_complete = True
    root_hashes = tuple(_source_root_hash(root) for root in roots)

    for root_index, root in enumerate(roots):
        for path, content, read_error in _iter_current_entries(root):
            relative = path.relative_to(root).as_posix()
            if read_error is not None:
                rows.append(
                    _current_row(
                        root,
                        path,
                        "unknown",
                        b"",
                        "skipped_with_reason",
                        read_error,
                        source_root_hash=root_hashes[root_index],
                        root_index=root_index,
                    )
                )
                privacy_scan_complete = False if read_error == "READ_FAILED" else privacy_scan_complete
                continue
            assert content is not None
            kind = _source_kind(relative, content)
            content_hash = _sha256(content)
            if path.suffix.casefold() not in {".md", ".jsonl"}:
                disposition, reason = "unsupported_format", "UNSUPPORTED_SOURCE_KIND"
            elif kind == "unknown":
                disposition, reason = "unsupported_format", "UNSUPPORTED_SOURCE_KIND"
            else:
                privacy_reason = _privacy_reason(kind, relative, content)
                if privacy_reason == "INVALID_UTF8":
                    disposition, reason = "unsupported_format", privacy_reason
                    privacy_scan_complete = False
                elif privacy_reason == "SECRET_PATTERN_MATCH":
                    disposition, reason = "rejected_secret", privacy_reason
                elif privacy_reason:
                    disposition, reason = "rejected_privacy", privacy_reason
                elif kind == "external_article_copy":
                    disposition, reason = "referenced_only", "EXTERNAL_ARTICLE_REFERENCE"
                elif kind == "skill_instruction":
                    disposition, reason = "referenced_only", "SKILL_REFERENCE_ONLY"
                elif content_hash in seen_content:
                    disposition, reason = "duplicate", "DUPLICATE_CONTENT"
                else:
                    disposition, reason = "imported", "IMPORTABLE_SOURCE"
            row = _current_row(
                root,
                path,
                kind,
                content,
                disposition,
                reason,
                source_root_hash=root_hashes[root_index],
                root_index=root_index,
            )
            rows.append(row)
            if disposition == "imported":
                seen_content.add(content_hash)

        rows.extend(_git_history(root, root_index))

    for path, kind in _metadata_paths(settings, codex_home):
        if not path.exists() or not path.is_file():
            continue
        try:
            content = path.read_bytes()
            size = path.stat().st_size
        except OSError:
            rows.append(_metadata_row(path, kind, _sha256(b""), 0, "READ_FAILED", "skipped_with_reason"))
            privacy_scan_complete = False
            continue
        privacy_reason = _privacy_reason(kind, path.name, content)
        if privacy_reason == "INVALID_UTF8":
            disposition, reason = "unsupported_format", privacy_reason
            privacy_scan_complete = False
        elif privacy_reason == "SECRET_PATTERN_MATCH":
            disposition, reason = "rejected_secret", privacy_reason
        elif privacy_reason:
            disposition, reason = "rejected_privacy", privacy_reason
        else:
            disposition, reason = "referenced_only", "OPERATIONAL_METADATA_ONLY"
        rows.append(_metadata_row(path, kind, _sha256(content), size, reason, disposition))

    rows.extend(_sqlite_rows(codex_home))
    rows = sorted(rows, key=lambda row: (row.source_kind, row.normalized_path_hash, row.content_hash, row.historical))
    exact_counts = {name: sum(1 for row in rows if row.disposition == name) for name in TERMINAL_DISPOSITIONS}
    unclassified = sum(1 for row in rows if row.disposition not in TERMINAL_DISPOSITIONS)
    referenced = exact_counts["referenced_only"]
    skipped = exact_counts["skipped_with_reason"] + exact_counts["duplicate"] + exact_counts["unsupported_format"]
    rejected = exact_counts["rejected_privacy"] + exact_counts["rejected_secret"]
    material = {
        "schema_version": 2,
        "rows": [row.to_dict() for row in rows],
        "source_root_hashes": list(root_hashes),
        "privacy_scan_complete": privacy_scan_complete,
    }
    inventory_hash = stable_hash(json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return SourceInventory(
        tuple(rows),
        len(rows),
        exact_counts["imported"],
        referenced,
        skipped,
        rejected,
        unclassified,
        sum(1 for row in rows if row.historical and row.reason_code == "HISTORICAL_BLOB_PENDING_REVIEW"),
        inventory_hash,
        2,
        root_hashes,
        privacy_scan_complete,
        roots,
    )


def inventory_existing_state(
    roots: Sequence[Path | str] | Path | str,
    settings_or_memory_root: Any,
    *,
    allow_global_source: bool = False,
    approval_path: Path | None = None,
) -> SourceInventory:
    """Create a sanitized, balanced inventory after source authorization.

    New API: inventory_existing_state(roots, settings).
    Legacy API: inventory_existing_state(codex_home, memory_root).
    """
    source_roots, settings, legacy = _legacy_context(roots, settings_or_memory_root)
    if legacy:
        # The first argument is the legacy codex home; source_roots was built from the second.
        codex_home = _canonical_root(roots)
    else:
        source_roots = resolve_source_roots(
            roots,
            settings,
            allow_global_source=allow_global_source,
            approval_path=approval_path,
        )
        paths = _settings_paths(settings)
        codex_home = _canonical_root(getattr(paths, "codex_home", getattr(paths, "runtime_root").parent))
    return _build_inventory(source_roots, settings if not legacy else None, codex_home)


def write_inventory_report(inventory: SourceInventory, path: Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(
        json.dumps(inventory.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(target)
    return target
