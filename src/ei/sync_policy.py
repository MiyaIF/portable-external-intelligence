from __future__ import annotations

import json
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


"""The repository boundary used by automatic external-intelligence sync.

The allowlist is deliberately small and structural.  A caller may not widen it
through a runtime setting: changes to source, policy, schema, Skill, hook
templates, tests, or documentation require a reviewed feature branch.
"""


DEFAULT_MANAGED_PATHS: tuple[str, ...] = ("events/**", "knowledge/**")
MANAGED_ROOTS: frozenset[str] = frozenset({"events", "knowledge"})
REVIEW_REQUIRED_ROOTS: frozenset[str] = frozenset(
    {
        "config",
        "docs",
        "hooks",
        "policies",
        "schemas",
        "scripts",
        "skills",
        "src",
        "templates",
        "tests",
    }
)
REVIEW_REQUIRED_FILES: frozenset[str] = frozenset(
    {
        ".gitignore",
        "AGENTS.md",
        "README.md",
        "pyproject.toml",
        "requirements-build.lock",
        "requirements-ci.lock",
        "requirements-runtime.lock",
    }
)
MACHINE_LOCAL_COMPONENTS: frozenset[str] = frozenset(
    {
        ".ei-local",
        ".ei-runtime",
        "backups",
        "body",
        "body.json",
        "cache",
        "cursor",
        "emergency-spool",
        "install-manifest.json",
        "key",
        "key.json",
        "locks",
        "logs",
        "queue",
        "quarantine",
        "spool",
        "state",
        "transcripts",
    }
)
ALLOWED_KNOWLEDGE_SUFFIXES: frozenset[str] = frozenset({".md", ".json"})


def normalize_repo_path(value: str) -> str:
    """Return a safe repository-relative POSIX path or raise ``ValueError``."""

    if not isinstance(value, str):
        raise ValueError("SYNC_PATH_INVALID")
    normalized = unicodedata.normalize("NFKC", value).replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ValueError("SYNC_PATH_INVALID")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("SYNC_PATH_INVALID")
    return "/".join(pure.parts)


def path_root(value: str) -> str:
    try:
        return normalize_repo_path(value).split("/", 1)[0].casefold()
    except ValueError:
        return ""


def is_managed_path(value: str) -> bool:
    """Whether *value* is an engine-generated path eligible for auto-sync."""

    try:
        normalized = normalize_repo_path(value)
    except ValueError:
        return False
    parts = normalized.split("/")
    root = parts[0].casefold()
    if root == "events":
        return len(parts) >= 2 and parts[-1].casefold().endswith(".json")
    if root == "knowledge":
        return len(parts) >= 2 and Path(parts[-1]).suffix.casefold() in ALLOWED_KNOWLEDGE_SUFFIXES
    return False


def managed_path_reason(value: str) -> str:
    """Classify a status path without revealing file contents."""

    try:
        normalized = normalize_repo_path(value)
    except ValueError:
        return "SYNC_PATH_INVALID"
    lowered = normalized.casefold()
    root = path_root(normalized)
    if root in MACHINE_LOCAL_COMPONENTS or any(
        part in MACHINE_LOCAL_COMPONENTS for part in lowered.split("/")
    ):
        return "MACHINE_LOCAL_PATH"
    if is_managed_path(normalized):
        return "MANAGED_ENGINE_PATH"
    if normalized.casefold() in REVIEW_REQUIRED_FILES or root in REVIEW_REQUIRED_ROOTS:
        return "REVIEW_REQUIRED_SOURCE_CHANGE"
    return "UNRELATED_WORKTREE_CHANGES"


def validate_managed_path_config(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("SYNC_MANAGED_PATHS_INVALID")
    normalized = tuple(str(item) for item in value)
    if normalized != DEFAULT_MANAGED_PATHS:
        raise ValueError("SYNC_MANAGED_PATHS_INVALID")
    return normalized


def configured_managed_paths(repo_root: Path) -> tuple[str, ...]:
    """Read the locked allowlist and reject attempts to widen it."""

    path = Path(repo_root) / "config" / "defaults.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("SYNC_DEFAULTS_READ_FAILED") from exc
    if not isinstance(document, Mapping):
        raise ValueError("SYNC_DEFAULTS_INVALID")
    sync = document.get("sync", {})
    if not isinstance(sync, Mapping):
        raise ValueError("SYNC_DEFAULTS_INVALID")
    configured = sync.get("managed_paths", list(DEFAULT_MANAGED_PATHS))
    return validate_managed_path_config(configured)


def protected_change(value: str) -> bool:
    return managed_path_reason(value) == "REVIEW_REQUIRED_SOURCE_CHANGE"


__all__ = [
    "ALLOWED_KNOWLEDGE_SUFFIXES",
    "DEFAULT_MANAGED_PATHS",
    "MANAGED_ROOTS",
    "REVIEW_REQUIRED_FILES",
    "REVIEW_REQUIRED_ROOTS",
    "configured_managed_paths",
    "is_managed_path",
    "managed_path_reason",
    "normalize_repo_path",
    "path_root",
    "protected_change",
    "validate_managed_path_config",
]
