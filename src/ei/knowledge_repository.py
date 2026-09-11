from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_no_reparse_components,
    assert_safe_target,
    canonical_path,
    safe_atomic_write,
    safe_ensure_directory,
    safe_mkdir,
    tree_digest,
)


KNOWLEDGE_DIRECTORIES: tuple[str, ...] = (
    "events",
    "knowledge",
    "knowledge/operational-rules",
    "knowledge/reusable-intelligence",
    "knowledge/decision-surface",
    "policies/user-overrides",
    "experiments",
)
REQUIRED_FILES: tuple[str, ...] = ("knowledge-repository.json", "README.md", ".gitignore")
MANIFEST_SCHEMA_VERSION = 1


class KnowledgeRepositoryError(ValueError):
    """Raised when the private knowledge repository contract cannot be met."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}:{detail}")


@dataclass(frozen=True)
class KnowledgeRepositoryStatus:
    root: Path
    initialized: bool
    git_initialized: bool
    manifest_valid: bool
    required_paths_present: bool
    sync_enabled: bool
    remote_names: tuple[str, ...] = ()
    dirty: bool | None = None
    root_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "initialized": self.initialized,
            "git_initialized": self.git_initialized,
            "manifest_valid": self.manifest_valid,
            "required_paths_present": self.required_paths_present,
            "sync_enabled": self.sync_enabled,
            "remote_names": list(self.remote_names),
            "dirty": self.dirty,
            "root_digest": self.root_digest,
        }


def _resolve_root(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or not str(value).strip():
        raise KnowledgeRepositoryError("KNOWLEDGE_ROOT_REQUIRED")
    try:
        raw = assert_no_reparse_components(absolute_path(value))
        return canonical_path(raw)
    except SafeFilesystemError as exc:
        code = "KNOWLEDGE_REPARSE_POINT" if exc.code == "UNSAFE_REPARSE_POINT" else "KNOWLEDGE_ROOT_INVALID"
        raise KnowledgeRepositoryError(code) from exc


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _assert_separate(root: Path, *, engine_root: Path | str | None, runtime_root: Path | str | None) -> None:
    for name, other_value in (("ENGINE", engine_root), ("RUNTIME", runtime_root)):
        if other_value is None:
            continue
        other = _resolve_root(other_value)
        if root == other or _is_within(other, root) or _is_within(root, other):
            raise KnowledgeRepositoryError(f"KNOWLEDGE_ROOT_OVERLAPS_{name}_ROOT")


def _translate_fs_error(exc: SafeFilesystemError, *, default: str = "KNOWLEDGE_PATH_INVALID") -> None:
    code = "KNOWLEDGE_REPARSE_POINT" if exc.code == "UNSAFE_REPARSE_POINT" else default
    raise KnowledgeRepositoryError(code, exc.code) from exc


def _safe_target(root: Path, target: Path, *, expected_type: str | None = None, allow_missing: bool = False) -> Path:
    try:
        return assert_safe_target(
            root,
            target,
            allow_root=target == root,
            allow_missing=allow_missing,
            expected_type=expected_type,
        )
    except SafeFilesystemError as exc:
        _translate_fs_error(exc)


def _git(root: Path, *arguments: str, environment: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in arguments):
        raise KnowledgeRepositoryError("GIT_ARGUMENT_INVALID")
    try:
        process_environment = os.environ.copy()
        if environment is not None:
            process_environment.update({str(key): str(value) for key, value in environment.items()})
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=30,
            env=process_environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KnowledgeRepositoryError("GIT_UNAVAILABLE") from exc


def _manifest(root: Path) -> dict[str, Any]:
    path = _safe_target(root, root / "knowledge-repository.json", expected_type="file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KnowledgeRepositoryError("KNOWLEDGE_MANIFEST_INVALID") from exc
    if not isinstance(value, dict) or value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise KnowledgeRepositoryError("KNOWLEDGE_MANIFEST_INVALID")
    if value.get("repository_kind") != "private-knowledge":
        raise KnowledgeRepositoryError("KNOWLEDGE_MANIFEST_KIND_INVALID")
    if value.get("sync_enabled") is not False:
        raise KnowledgeRepositoryError("KNOWLEDGE_SYNC_MUST_START_DISABLED")
    return value


def _layout_present(root: Path) -> bool:
    try:
        for relative in KNOWLEDGE_DIRECTORIES:
            assert_safe_target(root, root / relative, allow_missing=False, expected_type="dir")
        for relative in REQUIRED_FILES:
            assert_safe_target(root, root / relative, allow_missing=False, expected_type="file")
    except SafeFilesystemError as exc:
        if exc.code in {"SAFE_PATH_MISSING", "SAFE_TYPE_MISMATCH"}:
            return False
        _translate_fs_error(exc)
    return True


def _tree_digest(root: Path) -> str | None:
    rows: list[tuple[str, str, int]] = []

    def visit(directory: Path, relative_directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise KnowledgeRepositoryError("KNOWLEDGE_TREE_READ_FAILED") from exc
        for entry in entries:
            relative = relative_directory / entry.name
            if relative.parts and relative.parts[0] == ".git":
                continue
            child = directory / entry.name
            try:
                assert_no_reparse_components(child)
                if entry.is_dir(follow_symlinks=False):
                    visit(child, relative)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise KnowledgeRepositoryError("KNOWLEDGE_REPARSE_POINT")
                path = assert_safe_target(root, child, allow_missing=False, expected_type="file")
                raw = path.read_bytes()
            except SafeFilesystemError as exc:
                _translate_fs_error(exc, default="KNOWLEDGE_TREE_READ_FAILED")
            except OSError as exc:
                raise KnowledgeRepositoryError("KNOWLEDGE_TREE_READ_FAILED") from exc
            rows.append((relative.as_posix(), hashlib.sha256(raw).hexdigest(), len(raw)))

    try:
        visit(root, Path())
    except KnowledgeRepositoryError:
        raise
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def inspect_knowledge_repository(root_value: Path | str, *, engine_root: Path | str | None = None, runtime_root: Path | str | None = None) -> KnowledgeRepositoryStatus:
    root = _resolve_root(root_value)
    _assert_separate(root, engine_root=engine_root, runtime_root=runtime_root)
    if not root.exists():
        return KnowledgeRepositoryStatus(root, False, False, False, False, False)
    _safe_target(root, root, expected_type="dir")
    git_dir = root / ".git"
    git_initialized = git_dir.exists() and (git_dir.is_dir() or git_dir.is_file())
    manifest_valid = False
    sync_enabled = False
    try:
        value = _manifest(root)
        manifest_valid = True
        sync_enabled = value.get("sync_enabled") is True
    except KnowledgeRepositoryError:
        manifest_valid = False
        sync_enabled = False
    remote_names: tuple[str, ...] = ()
    dirty: bool | None = None
    if git_initialized:
        remotes = _git(root, "remote")
        if remotes.returncode == 0:
            remote_names = tuple(sorted(item.strip() for item in remotes.stdout.splitlines() if item.strip()))
        status = _git(root, "status", "--porcelain", "--untracked-files=all")
        if status.returncode == 0:
            dirty = bool(status.stdout.strip())
    return KnowledgeRepositoryStatus(
        root,
        True,
        git_initialized,
        manifest_valid,
        _layout_present(root),
        sync_enabled,
        remote_names,
        dirty,
        _tree_digest(root) if manifest_valid else None,
    )


def bootstrap_knowledge_repository(
    root_value: Path | str,
    *,
    engine_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
    template_root: Path | str | None = None,
    initialize_git: bool = True,
) -> KnowledgeRepositoryStatus:
    root = _resolve_root(root_value)
    _assert_separate(root, engine_root=engine_root, runtime_root=runtime_root)
    was_absent = not root.exists()
    was_empty = root.is_dir() and next(root.iterdir(), None) is None if root.exists() else False
    if root.exists():
        _safe_target(root, root, expected_type="dir")
    try:
        root = safe_ensure_directory(root, mode=0o700)
    except SafeFilesystemError as exc:
        _translate_fs_error(exc, default="KNOWLEDGE_ROOT_NOT_DIRECTORY")
    source = _resolve_root(template_root) if template_root is not None else Path(__file__).resolve().parents[2] / "templates" / "knowledge-repository"
    try:
        assert_no_reparse_components(source)
        assert_safe_target(source, source, allow_root=True, allow_missing=False, expected_type="dir")
        tree_digest(source)
    except SafeFilesystemError as exc:
        raise KnowledgeRepositoryError("KNOWLEDGE_TEMPLATE_MISSING", exc.code) from exc
    for relative in REQUIRED_FILES:
        source_path = _safe_target(source, source / relative, expected_type="file")
        target = root / relative
        if not source_path.is_file():
            raise KnowledgeRepositoryError("KNOWLEDGE_TEMPLATE_MISSING", relative)
        if target.exists():
            _safe_target(root, target, expected_type="file")
            continue
        try:
            safe_atomic_write(root, target, source_path.read_bytes(), mode=0o600)
        except SafeFilesystemError as exc:
            _translate_fs_error(exc, default="KNOWLEDGE_TARGET_INVALID")
    for relative in KNOWLEDGE_DIRECTORIES:
        target = root / relative
        try:
            safe_mkdir(root, target, parents=True, mode=0o700)
        except SafeFilesystemError as exc:
            _translate_fs_error(exc, default="KNOWLEDGE_TARGET_INVALID")
    for source_path in sorted(source.rglob("*")):
        if not source_path.is_file():
            continue
        source_path = _safe_target(source, source_path, expected_type="file")
        relative = source_path.relative_to(source).as_posix()
        target = root / relative
        if target.exists():
            _safe_target(root, target, expected_type="file")
            continue
        try:
            parent = target.parent
            safe_mkdir(root, parent, parents=True, mode=0o700)
            safe_atomic_write(root, target, source_path.read_bytes(), mode=0o600)
        except SafeFilesystemError as exc:
            _translate_fs_error(exc, default="KNOWLEDGE_TARGET_INVALID")
    if initialize_git:
        git_dir = root / ".git"
        if not git_dir.exists():
            result = _git(root, "-c", "init.defaultBranch=main", "init")
            if result.returncode != 0:
                raise KnowledgeRepositoryError("KNOWLEDGE_GIT_INIT_FAILED")
            if was_absent or was_empty:
                added = _git(root, "add", "--", ".")
                if added.returncode != 0:
                    raise KnowledgeRepositoryError("KNOWLEDGE_GIT_INIT_FAILED")
                committed = _git(
                    root,
                    "commit",
                    "--no-gpg-sign",
                    "-m",
                    "chore: initialize private knowledge repository",
                    environment={
                        "GIT_AUTHOR_NAME": "External Intelligence Engine",
                        "GIT_AUTHOR_EMAIL": "external-intelligence@invalid",
                        "GIT_COMMITTER_NAME": "External Intelligence Engine",
                        "GIT_COMMITTER_EMAIL": "external-intelligence@invalid",
                    },
                )
                if committed.returncode != 0:
                    raise KnowledgeRepositoryError("KNOWLEDGE_GIT_INIT_FAILED")
        else:
            _safe_target(root, git_dir, expected_type="dir" if git_dir.is_dir() else "file")
    status = inspect_knowledge_repository(root, engine_root=engine_root, runtime_root=runtime_root)
    if not status.git_initialized and initialize_git:
        raise KnowledgeRepositoryError("KNOWLEDGE_GIT_INIT_FAILED")
    if not status.manifest_valid or not status.required_paths_present:
        raise KnowledgeRepositoryError("KNOWLEDGE_LAYOUT_INVALID")
    return status


def init_knowledge_repository(*args: Any, **kwargs: Any) -> KnowledgeRepositoryStatus:
    """Compatibility name for callers that expose a ``knowledge init`` command."""

    return bootstrap_knowledge_repository(*args, **kwargs)


__all__ = [
    "KNOWLEDGE_DIRECTORIES",
    "KnowledgeRepositoryError",
    "KnowledgeRepositoryStatus",
    "bootstrap_knowledge_repository",
    "init_knowledge_repository",
    "inspect_knowledge_repository",
]
