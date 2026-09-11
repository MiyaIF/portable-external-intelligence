"""Create a deterministic, sanitized public repository root.

The development repository contains planning material, private operational
templates, and historical evidence that must never be pushed to the public
repository.  This module intentionally works from the tracked tree at an
exact source commit and copies only paths selected by an explicit allowlist.
The destination receives a new Git repository and a single owner-authored
root commit; the private repository is never rewritten.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .ids import canonical_json
from .publication_audit import contains_private_key_material
from .publication_policy import load_publication_policy, policy_digest
from .safe_fs import SafeFilesystemError, canonical_path, safe_atomic_write, safe_ensure_directory


ALLOWLIST_SCHEMA_VERSION = 1
EXPORT_SCHEMA_VERSION = 1
EXPORT_TOOL_VERSION = "ei-public-export/1"
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TEXT_SUFFIXES = frozenset(
    {
        ".bash",
        ".cfg",
        ".cmd",
        ".gitattributes",
        ".gitignore",
        ".ini",
        ".in",
        ".json",
        ".lock",
        ".md",
        ".ps1",
        ".psm1",
        ".py",
        ".sh",
        ".toml",
        ".txt",
        ".yml",
        ".yaml",
    }
)
_TEXT_FILENAMES = frozenset({".gitattributes", ".gitignore", "LICENSE", "SECURITY.md"})
_VALIDATION_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "USERNAME",
    "USERDOMAIN",
)
_ALLOWLIST_KEYS = frozenset(
    {
        "schema_version",
        "include",
        "exclude",
        "text_suffixes",
        "executable_patterns",
        "required_paths",
    }
)


class PublicExportError(ValueError):
    """Raised when a public export cannot be proven safe and complete."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


@dataclass(frozen=True)
class GitTreeEntry:
    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class PublicExportResult:
    destination: Path
    receipt: dict[str, Any]
    selected_paths: tuple[str, ...]


def _fail(code: str, detail: str = "") -> None:
    raise PublicExportError(code, detail)


def _normalise_relative(value: object, code: str = "PUBLIC_EXPORT_PATH_INVALID") -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(code)
    text = value.replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or text.startswith("//") or ":" in path.parts[0] or ".." in path.parts:
        _fail(code)
    normalised = path.as_posix()
    if normalised in {"", "."} or normalised.startswith("../"):
        _fail(code)
    return normalised


def _normalise_pattern(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail("PUBLIC_EXPORT_PATTERN_INVALID")
    text = value.replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text) or any(part == ".." for part in text.split("/")):
        _fail("PUBLIC_EXPORT_PATTERN_INVALID")
    if text.startswith("./"):
        text = text[2:]
    if not text:
        _fail("PUBLIC_EXPORT_PATTERN_INVALID")
    return text


def _unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted(set(values), key=lambda item: (item.casefold(), item))


def validate_public_export_allowlist(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and canonicalize an export allowlist."""

    if not isinstance(value, Mapping) or set(value) - _ALLOWLIST_KEYS:
        _fail("PUBLIC_EXPORT_ALLOWLIST_SCHEMA_INVALID")
    if value.get("schema_version") != ALLOWLIST_SCHEMA_VERSION:
        _fail("PUBLIC_EXPORT_ALLOWLIST_VERSION_INVALID")

    include = value.get("include")
    exclude = value.get("exclude", [])
    required = value.get("required_paths", [])
    executable = value.get("executable_patterns", [])
    suffixes = value.get("text_suffixes", sorted(_TEXT_SUFFIXES))
    for name, collection in (
        ("include", include),
        ("exclude", exclude),
        ("required_paths", required),
        ("executable_patterns", executable),
        ("text_suffixes", suffixes),
    ):
        if not isinstance(collection, list) or any(not isinstance(item, str) or not item for item in collection):
            _fail("PUBLIC_EXPORT_ALLOWLIST_FIELD_INVALID", name)

    if not include:
        _fail("PUBLIC_EXPORT_ALLOWLIST_EMPTY")
    include_patterns = _unique_sorted(_normalise_pattern(item) for item in include)
    exclude_patterns = _unique_sorted(_normalise_pattern(item) for item in exclude)
    required_paths = _unique_sorted(_normalise_relative(item) for item in required)
    executable_patterns = _unique_sorted(_normalise_pattern(item) for item in executable)
    normalised_suffixes = _unique_sorted(
        "." + item.removeprefix(".").casefold() for item in suffixes
    )
    if any(not item or item == "." for item in normalised_suffixes):
        _fail("PUBLIC_EXPORT_ALLOWLIST_FIELD_INVALID", "text_suffixes")
    return {
        "schema_version": ALLOWLIST_SCHEMA_VERSION,
        "include": include_patterns,
        "exclude": exclude_patterns,
        "text_suffixes": normalised_suffixes,
        "executable_patterns": executable_patterns,
        "required_paths": required_paths,
    }


def load_public_export_allowlist(path: Path | str) -> dict[str, Any]:
    target = Path(path).expanduser()
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicExportError("PUBLIC_EXPORT_ALLOWLIST_READ_FAILED") from exc
    return validate_public_export_allowlist(value)


def allowlist_digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(validate_public_export_allowlist(value))).hexdigest()


def _glob_match(path: str, pattern: str) -> bool:
    """Match slash-separated globs with a portable ``**`` implementation."""

    path = _normalise_relative(path)
    pattern = _normalise_pattern(pattern)
    expression = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            expression.append("(?:[^/]+/)*")
            index += 3
            continue
        if pattern.startswith("**", index):
            expression.append(".*")
            index += 2
            continue
        char = pattern[index]
        if char == "*":
            expression.append("[^/]*")
        elif char == "?":
            expression.append("[^/]")
        else:
            expression.append(re.escape(char))
        index += 1
    expression.append("$")
    return re.match("".join(expression), path) is not None


def select_public_paths(paths: Iterable[str], allowlist: Mapping[str, Any]) -> tuple[str, ...]:
    selected: list[str] = []
    normalised = validate_public_export_allowlist(allowlist)
    for raw_path in paths:
        path = _normalise_relative(raw_path)
        if any(_glob_match(path, pattern) for pattern in normalised["include"]):
            if not any(_glob_match(path, pattern) for pattern in normalised["exclude"]):
                selected.append(path)
    selected_set = set(selected)
    missing = [path for path in normalised["required_paths"] if path not in selected_set]
    if missing:
        _fail("PUBLIC_EXPORT_REQUIRED_PATH_MISSING", missing[0])
    return tuple(sorted(selected, key=lambda item: (item.casefold(), item)))


def _absolute(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or isinstance(value, bool):
        _fail("PUBLIC_EXPORT_PATH_INVALID")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _fail("PUBLIC_EXPORT_PATH_INVALID")
    try:
        return Path(os.path.abspath(os.path.expanduser(raw)))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise PublicExportError("PUBLIC_EXPORT_PATH_INVALID") from exc


def _within(candidate: Path, root: Path, *, allow_equal: bool = True) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return False
    return allow_equal or bool(relative.parts)


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & 0x400)


def _assert_no_reparse_components(path: Path) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts:
        if path.anchor and part == path.anchor:
            continue
        current = current / part
        if current.exists() or current.is_symlink():
            if _is_reparse(current):
                _fail("PUBLIC_EXPORT_REPARSE_POINT")


def _safe_existing_public_path(
    value: Path | str,
    *,
    expected_type: str,
    invalid_code: str,
) -> Path:
    target = _absolute(value)
    _assert_no_reparse_components(target)
    if expected_type == "file" and not target.is_file():
        _fail(invalid_code)
    if expected_type == "dir" and not target.is_dir():
        _fail(invalid_code)
    return target


def validate_export_destination(
    source: Path | str,
    destination: Path | str,
    *,
    knowledge_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
) -> tuple[Path, Path]:
    """Validate that destination is a new, isolated, reparse-free directory."""

    source_path = _absolute(source)
    destination_path = _absolute(destination)
    if source_path.is_symlink() or not source_path.is_dir():
        _fail("PUBLIC_EXPORT_SOURCE_DIRECTORY_INVALID")
    _assert_no_reparse_components(source_path)
    _assert_no_reparse_components(destination_path)
    if _within(destination_path, source_path) or _within(source_path, destination_path):
        _fail("PUBLIC_EXPORT_DESTINATION_NOT_ISOLATED")
    for name, raw_root in (("knowledge", knowledge_root), ("runtime", runtime_root)):
        if raw_root is None:
            continue
        root = _absolute(raw_root)
        if _within(destination_path, root) or _within(root, destination_path):
            _fail("PUBLIC_EXPORT_DESTINATION_NOT_ISOLATED", name)
    if destination_path.exists() or destination_path.is_symlink():
        if destination_path.is_symlink() or not destination_path.is_dir():
            _fail("PUBLIC_EXPORT_DESTINATION_INVALID")
        try:
            entries = list(os.scandir(destination_path))
        except OSError as exc:
            raise PublicExportError("PUBLIC_EXPORT_DESTINATION_READ_FAILED") from exc
        if entries:
            _fail("PUBLIC_EXPORT_DESTINATION_NOT_EMPTY")
    return source_path, destination_path


def validate_resume_destination(
    source: Path | str,
    destination: Path | str,
    *,
    knowledge_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
) -> tuple[Path, Path]:
    """Validate an existing export root before deterministic re-verification."""

    source_path = _absolute(source)
    destination_path = _absolute(destination)
    if source_path.is_symlink() or not source_path.is_dir():
        _fail("PUBLIC_EXPORT_SOURCE_DIRECTORY_INVALID")
    if destination_path.is_symlink() or not destination_path.is_dir():
        _fail("PUBLIC_EXPORT_RESUME_DESTINATION_INVALID")
    _assert_no_reparse_components(source_path)
    _assert_no_reparse_components(destination_path)
    if _within(destination_path, source_path) or _within(source_path, destination_path):
        _fail("PUBLIC_EXPORT_DESTINATION_NOT_ISOLATED")
    for name, raw_root in (("knowledge", knowledge_root), ("runtime", runtime_root)):
        if raw_root is None:
            continue
        root = _absolute(raw_root)
        _assert_no_reparse_components(root)
        if _within(destination_path, root) or _within(root, destination_path):
            _fail("PUBLIC_EXPORT_DESTINATION_NOT_ISOLATED", name)
    return source_path, destination_path


def _run(
    argv: Sequence[str | Path],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = 120.0,
    code: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            [str(item) for item in argv],
            cwd=str(cwd),
            env=dict(env or os.environ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicExportError(code) from exc
    if completed.returncode != 0:
        raise PublicExportError(code)
    return completed


def _git(repo: Path, *arguments: str, timeout: float = 120.0) -> bytes:
    return _run(["git", "-C", repo, *arguments], cwd=repo, timeout=timeout, code="PUBLIC_EXPORT_GIT_COMMAND_FAILED").stdout


def _decode(raw: bytes, code: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicExportError(code) from exc


def _source_revision(source: Path, expected_source_commit: str | None) -> tuple[str, str, str]:
    top = _decode(_git(source, "rev-parse", "--show-toplevel"), "PUBLIC_EXPORT_SOURCE_NOT_GIT").strip()
    try:
        if Path(top).resolve() != source.resolve():
            _fail("PUBLIC_EXPORT_SOURCE_NOT_REPOSITORY_ROOT")
    except (OSError, RuntimeError, ValueError) as exc:
        raise PublicExportError("PUBLIC_EXPORT_SOURCE_NOT_GIT") from exc
    status = _git(source, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        _fail("PUBLIC_EXPORT_SOURCE_WORKTREE_DIRTY")
    commit = _decode(_git(source, "rev-parse", "--verify", "HEAD"), "PUBLIC_EXPORT_SOURCE_REVISION_INVALID").strip().lower()
    tree = _decode(_git(source, "rev-parse", "--verify", "HEAD^{tree}"), "PUBLIC_EXPORT_SOURCE_REVISION_INVALID").strip().lower()
    if not _SHA40_RE.fullmatch(commit) or not _SHA40_RE.fullmatch(tree):
        _fail("PUBLIC_EXPORT_SOURCE_REVISION_INVALID")
    if expected_source_commit is not None:
        expected = str(expected_source_commit).lower()
        if not _SHA40_RE.fullmatch(expected):
            _fail("PUBLIC_EXPORT_EXPECTED_SHA_INVALID")
        if expected != commit:
            _fail("PUBLIC_EXPORT_SOURCE_SHA_MISMATCH")
    date = _decode(_git(source, "show", "-s", "--format=%cI", "HEAD"), "PUBLIC_EXPORT_SOURCE_DATE_INVALID").strip()
    if not date:
        _fail("PUBLIC_EXPORT_SOURCE_DATE_INVALID")
    return commit, tree, date


def _tracked_entries(source: Path) -> tuple[GitTreeEntry, ...]:
    raw = _git(source, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    entries: list[GitTreeEntry] = []
    for record in raw.split(b"\0"):
        if not record or b"\t" not in record:
            continue
        header, encoded_path = record.split(b"\t", 1)
        fields = header.split()
        if len(fields) != 3:
            _fail("PUBLIC_EXPORT_GIT_TREE_INVALID")
        mode, object_type, object_id = (item.decode("ascii", "replace") for item in fields)
        path = _normalise_relative(_decode(encoded_path, "PUBLIC_EXPORT_PATH_ENCODING_INVALID"))
        if mode == "120000" or mode == "160000" or object_type != "blob" or not _SHA40_RE.fullmatch(object_id):
            _fail("PUBLIC_EXPORT_UNSAFE_TREE_ENTRY", path)
        entries.append(GitTreeEntry(mode, object_type, object_id, path))
    if not entries:
        _fail("PUBLIC_EXPORT_SOURCE_TREE_EMPTY")
    return tuple(sorted(entries, key=lambda item: (item.path.casefold(), item.path)))


def _tree_listing_digest(repo: Path, revision: str) -> str:
    raw = _git(repo, "ls-tree", "-r", "-z", "--full-tree", revision)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _tree_id(repo: Path, revision: str = "HEAD") -> str:
    value = _decode(_git(repo, "rev-parse", "--verify", f"{revision}^{{tree}}"), "PUBLIC_EXPORT_TREE_ID_INVALID").strip().lower()
    if not _SHA40_RE.fullmatch(value):
        _fail("PUBLIC_EXPORT_TREE_ID_INVALID")
    return value


def _normalise_text(data: bytes, path: str, suffixes: Sequence[str]) -> bytes:
    suffix = Path(path).suffix.casefold()
    if suffix not in set(suffixes) and Path(path).name not in _TEXT_FILENAMES:
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicExportError("PUBLIC_EXPORT_TEXT_ENCODING_INVALID", path) from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _is_executable(path: str, patterns: Sequence[str]) -> bool:
    return any(_glob_match(path, pattern) for pattern in patterns)


def _copy_selected_files(
    source: Path,
    destination: Path,
    entries: Mapping[str, GitTreeEntry],
    selected: Sequence[str],
    allowlist: Mapping[str, Any],
) -> None:
    try:
        safe_ensure_directory(destination)
        for relative in selected:
            entry = entries[relative]
            if entry.object_type != "blob" or not _SHA40_RE.fullmatch(entry.object_id):
                _fail("PUBLIC_EXPORT_SOURCE_FILE_INVALID", relative)
            data = _git(source, "cat-file", "blob", entry.object_id)
            if contains_private_key_material(data):
                _fail("PUBLIC_EXPORT_PRIVATE_KEY_DETECTED", relative)
            data = _normalise_text(data, relative, allowlist["text_suffixes"])
            target = destination.joinpath(*PurePosixPath(relative).parts)
            safe_ensure_directory(target.parent)
            mode = 0o755 if _is_executable(relative, allowlist["executable_patterns"]) else 0o644
            safe_atomic_write(destination, target, data, mode=mode)
    except SafeFilesystemError as exc:
        raise PublicExportError(exc.code) from exc


def _git_configure(destination: Path, author: Mapping[str, str]) -> None:
    _run(["git", "-C", destination, "init", "--quiet"], cwd=destination, code="PUBLIC_EXPORT_GIT_INIT_FAILED")
    _run(["git", "-C", destination, "branch", "-M", "main"], cwd=destination, code="PUBLIC_EXPORT_GIT_INIT_FAILED")
    for key, value in (
        ("core.autocrlf", "false"),
        ("core.filemode", "true"),
        ("commit.gpgSign", "false"),
        ("user.name", str(author["name"])),
        ("user.email", str(author["email"])),
    ):
        _run(["git", "-C", destination, "config", key, value], cwd=destination, code="PUBLIC_EXPORT_GIT_CONFIG_FAILED")


def _set_index_modes(destination: Path, selected: Sequence[str], executable_patterns: Sequence[str]) -> None:
    _run(
        ["git", "-C", destination, "add", "--all", "--", "."],
        cwd=destination,
        code="PUBLIC_EXPORT_GIT_ADD_FAILED",
    )
    for relative in selected:
        mode_flag = "+x" if _is_executable(relative, executable_patterns) else "-x"
        _run(
            ["git", "-C", destination, "update-index", "--chmod=" + mode_flag, "--", relative],
            cwd=destination,
            code="PUBLIC_EXPORT_GIT_INDEX_FAILED",
        )


def _commit_root(destination: Path, *, author: Mapping[str, str], source_date: str) -> tuple[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": str(author["name"]),
            "GIT_AUTHOR_EMAIL": str(author["email"]),
            "GIT_COMMITTER_NAME": str(author["name"]),
            "GIT_COMMITTER_EMAIL": str(author["email"]),
            "GIT_AUTHOR_DATE": source_date,
            "GIT_COMMITTER_DATE": source_date,
        }
    )
    _run(["git", "-C", destination, "add", "--all", "--", "."], cwd=destination, env=env, code="PUBLIC_EXPORT_GIT_ADD_FAILED")
    _run(
        ["git", "-C", destination, "commit", "--quiet", "--no-gpg-sign", "-m", "chore: create sanitized public root"],
        cwd=destination,
        env=env,
        code="PUBLIC_EXPORT_GIT_COMMIT_FAILED",
    )
    commit = _decode(_git(destination, "rev-parse", "--verify", "HEAD"), "PUBLIC_EXPORT_ROOT_COMMIT_INVALID").strip().lower()
    tree = _tree_id(destination)
    count = _decode(_git(destination, "rev-list", "--count", "--all"), "PUBLIC_EXPORT_ROOT_COMMIT_INVALID").strip()
    if not _SHA40_RE.fullmatch(commit) or not _SHA40_RE.fullmatch(tree) or count != "1":
        _fail("PUBLIC_EXPORT_ROOT_COMMIT_INVALID")
    return commit, tree


def _hash_basis(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def validate_public_export_receipt(value: Mapping[str, Any]) -> bool:
    required = {
        "receipt_type",
        "schema_version",
        "tool_version",
        "status",
        "source_commit_sha",
        "source_tree_id",
        "source_tree_sha256",
        "public_root_sha",
        "public_tree_id",
        "public_tree_sha256",
        "selected_paths_sha256",
        "allowlist_sha256",
        "publication_policy_sha256",
        "selected_file_count",
        "root_commit_count",
        "author",
        "validation",
        "generated_at",
        "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        _fail("PUBLIC_EXPORT_RECEIPT_SCHEMA_INVALID")
    for key in ("source_commit_sha", "source_tree_id", "public_root_sha", "public_tree_id"):
        if not isinstance(value.get(key), str) or not _SHA40_RE.fullmatch(value[key]):
            _fail("PUBLIC_EXPORT_RECEIPT_SHA_INVALID")
    for key in (
        "source_tree_sha256",
        "public_tree_sha256",
        "selected_paths_sha256",
        "allowlist_sha256",
        "publication_policy_sha256",
    ):
        if not isinstance(value.get(key), str) or not _SHA256_RE.fullmatch(value[key]):
            _fail("PUBLIC_EXPORT_RECEIPT_HASH_INVALID")
    if value.get("receipt_type") != "public_export" or value.get("schema_version") != EXPORT_SCHEMA_VERSION:
        _fail("PUBLIC_EXPORT_RECEIPT_TYPE_INVALID")
    if value.get("status") not in {"exported_unvalidated", "validated"}:
        _fail("PUBLIC_EXPORT_RECEIPT_STATUS_INVALID")
    if type(value.get("selected_file_count")) is not int or value["selected_file_count"] < 1:
        _fail("PUBLIC_EXPORT_RECEIPT_COUNT_INVALID")
    if value.get("root_commit_count") != 1:
        _fail("PUBLIC_EXPORT_RECEIPT_ROOT_COUNT_INVALID")
    author = value.get("author")
    if not isinstance(author, Mapping) or set(author) != {"name", "email"} or not all(isinstance(item, str) and item for item in author.values()):
        _fail("PUBLIC_EXPORT_RECEIPT_AUTHOR_INVALID")
    validation = value.get("validation")
    if not isinstance(validation, Mapping) or set(validation) != {"status", "step_digests"}:
        _fail("PUBLIC_EXPORT_RECEIPT_VALIDATION_INVALID")
    if validation.get("status") not in {"not_run", "passed"} or not isinstance(validation.get("step_digests"), Mapping):
        _fail("PUBLIC_EXPORT_RECEIPT_VALIDATION_INVALID")
    for digest in validation["step_digests"].values():
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            _fail("PUBLIC_EXPORT_RECEIPT_VALIDATION_INVALID")
    if not isinstance(value.get("generated_at"), str) or not value["generated_at"].endswith("Z"):
        _fail("PUBLIC_EXPORT_RECEIPT_TIME_INVALID")
    basis = {key: value[key] for key in sorted(required - {"receipt_sha256"})}
    if value.get("receipt_sha256") != _hash_basis(basis):
        _fail("PUBLIC_EXPORT_RECEIPT_HASH_MISMATCH")
    return True


def _make_receipt(
    *,
    source_commit: str,
    source_tree: str,
    source_tree_sha256: str,
    public_root_sha: str,
    public_tree_id: str,
    public_tree_sha256: str,
    selected: Sequence[str],
    allowlist: Mapping[str, Any],
    policy: Mapping[str, Any],
    validation: Mapping[str, Any],
    source_date: str,
) -> dict[str, Any]:
    try:
        generated_at = datetime.fromisoformat(source_date.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError) as exc:
        raise PublicExportError("PUBLIC_EXPORT_SOURCE_DATE_INVALID") from exc
    value: dict[str, Any] = {
        "receipt_type": "public_export",
        "schema_version": EXPORT_SCHEMA_VERSION,
        "tool_version": EXPORT_TOOL_VERSION,
        "status": "validated" if validation["status"] == "passed" else "exported_unvalidated",
        "source_commit_sha": source_commit,
        "source_tree_id": source_tree,
        "source_tree_sha256": source_tree_sha256,
        "public_root_sha": public_root_sha,
        "public_tree_id": public_tree_id,
        "public_tree_sha256": public_tree_sha256,
        "selected_paths_sha256": "sha256:" + hashlib.sha256(canonical_json(list(selected))).hexdigest(),
        "allowlist_sha256": allowlist_digest(allowlist),
        "publication_policy_sha256": policy_digest(policy),
        "selected_file_count": len(selected),
        "root_commit_count": 1,
        "author": {
            "name": str(policy["public_author"]["name"]),
            "email": str(policy["public_author"]["email"]),
        },
        "validation": {
            "status": str(validation["status"]),
            "step_digests": dict(sorted((str(key), str(value)) for key, value in validation["step_digests"].items())),
        },
        "generated_at": generated_at,
    }
    value["receipt_sha256"] = _hash_basis(value)
    validate_public_export_receipt(value)
    return value


def _parse_json_output(raw: bytes, code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(_decode(raw, code))
    except json.JSONDecodeError as exc:
        raise PublicExportError(code) from exc
    if not isinstance(value, Mapping):
        _fail(code)
    return value


def _validation_environment(destination: Path) -> dict[str, str]:
    inherited = {key.casefold(): value for key, value in os.environ.items()}
    environment = {
        key: inherited[key.casefold()]
        for key in _VALIDATION_ENV_KEYS
        if key.casefold() in inherited
    }
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join((str(destination / "src"), str(destination))),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def run_public_export_validation(destination: Path, *, python_executable: Path | str | None = None, timeout_seconds: float = 300.0) -> dict[str, Any]:
    """Run public-tree, source, workflow, lock, and clean-clone validation."""

    if type(timeout_seconds) not in {int, float} or timeout_seconds <= 0:
        _fail("PUBLIC_EXPORT_VALIDATION_TIMEOUT_INVALID")
    destination = _safe_existing_public_path(
        destination,
        expected_type="dir",
        invalid_code="PUBLIC_EXPORT_DESTINATION_INVALID",
    )
    executable = _safe_existing_public_path(
        python_executable or sys.executable,
        expected_type="file",
        invalid_code="PUBLIC_EXPORT_VALIDATION_PYTHON_MISSING",
    )
    env = _validation_environment(destination)
    step_digests: dict[str, str] = {}
    public = _run(
        [executable, "-B", "scripts/audit-public-release.py", "--repo", ".", "--policy", "release/publication-policy.json", "--working-tree", "--reachable-history", "--json"],
        cwd=destination,
        env=env,
        timeout=timeout_seconds,
        code="PUBLIC_EXPORT_PUBLIC_AUDIT_FAILED",
    )
    public_value = _parse_json_output(public.stdout, "PUBLIC_EXPORT_PUBLIC_AUDIT_OUTPUT_INVALID")
    if public_value.get("status") != "passed":
        _fail("PUBLIC_EXPORT_PUBLIC_AUDIT_FAILED")
    step_digests["public_audit"] = str(public_value.get("report_digest", ""))
    source = _run(
        [executable, "-B", "scripts/audit-production-source.py", "--repo", ".", "--json"],
        cwd=destination,
        env=env,
        timeout=timeout_seconds,
        code="PUBLIC_EXPORT_SOURCE_AUDIT_FAILED",
    )
    source_value = _parse_json_output(source.stdout, "PUBLIC_EXPORT_SOURCE_AUDIT_OUTPUT_INVALID")
    if source_value.get("status") != "passed":
        _fail("PUBLIC_EXPORT_SOURCE_AUDIT_FAILED")
    source_digest = source_value.get("report_digest")
    if not isinstance(source_digest, str):
        source_digest = "sha256:" + hashlib.sha256(source.stdout).hexdigest()
    step_digests["production_source"] = source_digest
    dependency = _run(
        [executable, "-B", "scripts/verify-dependency-lock.py", "--pyproject", "pyproject.toml", "--build-lock", "requirements-build.lock", "--runtime-lock", "requirements-runtime.lock", "--ci-lock", "requirements-ci.lock", "--workflow-dir", ".github/workflows"],
        cwd=destination,
        env=env,
        timeout=timeout_seconds,
        code="PUBLIC_EXPORT_DEPENDENCY_AUDIT_FAILED",
    )
    step_digests["dependency_locks"] = "sha256:" + hashlib.sha256(dependency.stdout).hexdigest()
    workflow = _run(
        [executable, "-B", "-m", "ei.cli", "public-release", "workflows", "verify", "--workflow-dir", ".github/workflows", "--json"],
        cwd=destination,
        env=env,
        timeout=timeout_seconds,
        code="PUBLIC_EXPORT_WORKFLOW_AUDIT_FAILED",
    )
    workflow_value = _parse_json_output(workflow.stdout, "PUBLIC_EXPORT_WORKFLOW_OUTPUT_INVALID")
    if workflow_value.get("status") != "passed":
        _fail("PUBLIC_EXPORT_WORKFLOW_AUDIT_FAILED")
    workflow_digest = workflow_value.get("workflow_sha256")
    if not isinstance(workflow_digest, str) or not _SHA256_RE.fullmatch(workflow_digest):
        _fail("PUBLIC_EXPORT_WORKFLOW_OUTPUT_INVALID")
    step_digests["workflow_security"] = workflow_digest

    with tempfile.TemporaryDirectory(prefix="ei-public-export-certification-") as temporary:
        receipt_path = Path(temporary) / "public-clone-receipt.json"
        certification = _run(
            [executable, "-B", "scripts/certify-public-clone.py", "--source", ".", "--output", receipt_path, "--offline-fixtures", "--timeout-seconds", str(timeout_seconds)],
            cwd=destination,
            env=env,
            # The certifier runs package setup, the complete bounded test
            # inventory, and lifecycle checks.  Its outer deadline must cover
            # several independently bounded phases, not just one child task.
            timeout=max(timeout_seconds * 6, 1800.0),
            code="PUBLIC_EXPORT_CLEAN_CLONE_FAILED",
        )
        del certification
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PublicExportError("PUBLIC_EXPORT_CLEAN_CLONE_RECEIPT_INVALID") from exc
        if not isinstance(receipt, Mapping) or receipt.get("status") != "PASSED":
            _fail("PUBLIC_EXPORT_CLEAN_CLONE_FAILED")
        receipt_hash = receipt.get("receipt_sha256")
        if not isinstance(receipt_hash, str) or not _SHA256_RE.fullmatch(receipt_hash):
            _fail("PUBLIC_EXPORT_CLEAN_CLONE_RECEIPT_INVALID")
        step_digests["clean_clone_certification"] = receipt_hash
    return {"status": "passed", "step_digests": step_digests}


def _write_public_export_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    try:
        safe_ensure_directory(path.parent)
        safe_atomic_write(
            path.parent,
            path,
            (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
    except SafeFilesystemError as exc:
        raise PublicExportError(exc.code) from exc


def _receipt_identity_matches(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    excluded = {"receipt_sha256", "status", "validation"}
    keys = set(expected) - excluded
    return set(actual) == set(expected) and all(actual.get(key) == expected.get(key) for key in keys)


def _verify_resumable_export(destination: Path, expected: Mapping[str, Any]) -> None:
    top = _decode(_git(destination, "rev-parse", "--show-toplevel"), "PUBLIC_EXPORT_RESUME_NOT_GIT").strip()
    try:
        top_path = _absolute(top)
        _assert_no_reparse_components(top_path)
        if canonical_path(top_path, require_exists=True) != canonical_path(destination, require_exists=True):
            _fail("PUBLIC_EXPORT_RESUME_NOT_GIT")
    except (SafeFilesystemError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise PublicExportError("PUBLIC_EXPORT_RESUME_NOT_GIT") from exc
    status = _git(
        destination,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        _fail("PUBLIC_EXPORT_RESUME_DESTINATION_DIRTY")
    count = _decode(_git(destination, "rev-list", "--count", "--all"), "PUBLIC_EXPORT_RESUME_HISTORY_INVALID").strip()
    if count != "1":
        _fail("PUBLIC_EXPORT_RESUME_HISTORY_INVALID")
    root_sha = _decode(_git(destination, "rev-parse", "--verify", "HEAD"), "PUBLIC_EXPORT_RESUME_HISTORY_INVALID").strip().lower()
    tree_id = _tree_id(destination)
    tree_sha256 = _tree_listing_digest(destination, "HEAD")
    if (
        root_sha != expected.get("public_root_sha")
        or tree_id != expected.get("public_tree_id")
        or tree_sha256 != expected.get("public_tree_sha256")
    ):
        _fail("PUBLIC_EXPORT_RESUME_CONTENT_MISMATCH")


def resume_public_export_validation(
    source: Path | str,
    destination: Path | str,
    *,
    policy_path: Path | str,
    allowlist_path: Path | str,
    receipt_path: Path | str | None = None,
    expected_source_commit: str | None = None,
    knowledge_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
    python_executable: Path | str | None = None,
    timeout_seconds: float = 300.0,
) -> PublicExportResult:
    """Resume validation only for an exact, clean, deterministic export root."""

    source_path, destination_path = validate_resume_destination(
        source,
        destination,
        knowledge_root=knowledge_root,
        runtime_root=runtime_root,
    )
    safe_policy_path = _safe_existing_public_path(
        policy_path,
        expected_type="file",
        invalid_code="PUBLIC_EXPORT_POLICY_READ_FAILED",
    )
    safe_allowlist_path = _safe_existing_public_path(
        allowlist_path,
        expected_type="file",
        invalid_code="PUBLIC_EXPORT_ALLOWLIST_READ_FAILED",
    )
    safe_receipt_path: Path | None = None
    if receipt_path is not None:
        safe_receipt_path = _absolute(receipt_path)
        _assert_no_reparse_components(safe_receipt_path)
        if safe_receipt_path.exists() and not safe_receipt_path.is_file():
            _fail("PUBLIC_EXPORT_RECEIPT_PATH_INVALID")

    policy = load_publication_policy(safe_policy_path)
    allowlist = load_public_export_allowlist(safe_allowlist_path)
    with tempfile.TemporaryDirectory(prefix=".ei-public-resume-", dir=str(destination_path.parent)) as temporary:
        reference = create_public_export(
            source_path,
            Path(temporary),
            policy_path=safe_policy_path,
            allowlist_path=safe_allowlist_path,
            expected_source_commit=expected_source_commit,
            knowledge_root=knowledge_root,
            runtime_root=runtime_root,
            validate=False,
        )

    _verify_resumable_export(destination_path, reference.receipt)
    if safe_receipt_path is not None and safe_receipt_path.exists():
        try:
            existing = json.loads(safe_receipt_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PublicExportError("PUBLIC_EXPORT_RECEIPT_READ_FAILED") from exc
        validate_public_export_receipt(existing)
        if not _receipt_identity_matches(existing, reference.receipt):
            _fail("PUBLIC_EXPORT_RECEIPT_IDENTITY_MISMATCH")
        if existing.get("status") == "validated":
            return PublicExportResult(destination_path, dict(existing), reference.selected_paths)

    validation = run_public_export_validation(
        destination_path,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
    )
    receipt = _make_receipt(
        source_commit=str(reference.receipt["source_commit_sha"]),
        source_tree=str(reference.receipt["source_tree_id"]),
        source_tree_sha256=str(reference.receipt["source_tree_sha256"]),
        public_root_sha=str(reference.receipt["public_root_sha"]),
        public_tree_id=str(reference.receipt["public_tree_id"]),
        public_tree_sha256=str(reference.receipt["public_tree_sha256"]),
        selected=reference.selected_paths,
        allowlist=allowlist,
        policy=policy,
        validation=validation,
        source_date=str(reference.receipt["generated_at"]),
    )
    if safe_receipt_path is not None:
        _write_public_export_receipt(safe_receipt_path, receipt)
    return PublicExportResult(destination_path, receipt, reference.selected_paths)


def create_public_export(
    source: Path | str,
    destination: Path | str,
    *,
    policy_path: Path | str,
    allowlist_path: Path | str,
    receipt_path: Path | str | None = None,
    expected_source_commit: str | None = None,
    knowledge_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
    validate: bool = True,
    python_executable: Path | str | None = None,
    timeout_seconds: float = 300.0,
) -> PublicExportResult:
    """Create an isolated public root from a clean, exact source revision."""

    source_path, destination_path = validate_export_destination(
        source,
        destination,
        knowledge_root=knowledge_root,
        runtime_root=runtime_root,
    )
    safe_policy_path = _safe_existing_public_path(
        policy_path,
        expected_type="file",
        invalid_code="PUBLIC_EXPORT_POLICY_READ_FAILED",
    )
    safe_allowlist_path = _safe_existing_public_path(
        allowlist_path,
        expected_type="file",
        invalid_code="PUBLIC_EXPORT_ALLOWLIST_READ_FAILED",
    )
    safe_receipt_path: Path | None = None
    if receipt_path is not None:
        safe_receipt_path = _absolute(receipt_path)
        _assert_no_reparse_components(safe_receipt_path)
    policy = load_publication_policy(safe_policy_path)
    allowlist = load_public_export_allowlist(safe_allowlist_path)
    source_commit, source_tree, source_date = _source_revision(source_path, expected_source_commit)
    entries = {entry.path: entry for entry in _tracked_entries(source_path)}
    selected = select_public_paths(entries, allowlist)
    if not selected:
        _fail("PUBLIC_EXPORT_SELECTED_TREE_EMPTY")
    _copy_selected_files(source_path, destination_path, entries, selected, allowlist)
    _git_configure(destination_path, policy["public_author"])
    _set_index_modes(destination_path, selected, allowlist["executable_patterns"])
    public_root_sha, public_tree_id = _commit_root(destination_path, author=policy["public_author"], source_date=source_date)
    source_tree_sha256 = _tree_listing_digest(source_path, "HEAD")
    public_tree_sha256 = _tree_listing_digest(destination_path, "HEAD")
    validation = {"status": "not_run", "step_digests": {}}
    if validate:
        validation = run_public_export_validation(
            destination_path,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
        )
    receipt = _make_receipt(
        source_commit=source_commit,
        source_tree=source_tree,
        source_tree_sha256=source_tree_sha256,
        public_root_sha=public_root_sha,
        public_tree_id=public_tree_id,
        public_tree_sha256=public_tree_sha256,
        selected=selected,
        allowlist=allowlist,
        policy=policy,
        validation=validation,
        source_date=source_date,
    )
    if safe_receipt_path is not None:
        _write_public_export_receipt(safe_receipt_path, receipt)
    return PublicExportResult(destination_path, receipt, selected)


__all__ = [
    "ALLOWLIST_SCHEMA_VERSION",
    "EXPORT_SCHEMA_VERSION",
    "EXPORT_TOOL_VERSION",
    "GitTreeEntry",
    "PublicExportError",
    "PublicExportResult",
    "allowlist_digest",
    "create_public_export",
    "load_public_export_allowlist",
    "resume_public_export_validation",
    "run_public_export_validation",
    "select_public_paths",
    "validate_public_export_allowlist",
    "validate_public_export_receipt",
    "validate_export_destination",
    "validate_resume_destination",
]
