"""Fail-closed filesystem primitives for managed destructive operations.

The public engine never treats a caller supplied path as authoritative.  Every
operation below validates canonical containment and reparse-point state both
before the operation and immediately before the final mutation.  Ownership
records are deliberately machine-local and are useful only for artifacts that
this process created (temporary worktrees, transaction backups, and staging
directories).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class SafeFilesystemError(ValueError):
    """Raised when a managed filesystem operation cannot be proven safe."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise SafeFilesystemError(code)


def _absolute_without_following(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or isinstance(value, bool):
        _fail("SAFE_PATH_INVALID")
    text = os.fspath(value)
    if not isinstance(text, str) or not text or "\x00" in text:
        _fail("SAFE_PATH_INVALID")
    try:
        return Path(os.path.abspath(os.path.expanduser(text)))
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("SAFE_PATH_INVALID")


def canonical_path(value: Path | str, *, require_exists: bool = False) -> Path:
    raw = _absolute_without_following(value)
    try:
        resolved = raw.resolve(strict=require_exists)
    except (OSError, RuntimeError, ValueError):
        _fail("SAFE_PATH_INVALID")
    if require_exists and not resolved.exists():
        _fail("SAFE_PATH_MISSING")
    return resolved


def absolute_path(value: Path | str) -> Path:
    """Return an absolute lexical path without following its final component."""

    return _absolute_without_following(value)


def assert_no_reparse_components(value: Path | str, *, allow_final_reparse: bool = False) -> Path:
    """Return an absolute lexical path only when every existing component is safe.

    Callers that later canonicalize a user-selected root must use this check
    first.  Otherwise ``Path.resolve`` erases the fact that the lexical path
    traversed a symbolic link or Windows junction.
    """

    raw = _absolute_without_following(value)
    _reparse_components(raw, allow_final_reparse=allow_final_reparse)
    return raw


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.exists():
            return False
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        info = path.stat(follow_symlinks=False)
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attributes & reparse_flag) or bool(getattr(info, "st_reparse_tag", 0))
    except (OSError, ValueError):
        return True


def _reparse_components(path: Path, *, allow_final_reparse: bool = False) -> None:
    raw = _absolute_without_following(path)
    current = Path(raw.anchor) if raw.anchor else Path()
    parts = raw.parts
    for index, part in enumerate(parts):
        if index == 0 and raw.anchor:
            continue
        current = current / part
        if not current.exists() and not current.is_symlink():
            continue
        if _is_reparse(current) and not (allow_final_reparse and current == raw):
            _fail("UNSAFE_REPARSE_POINT")


def _contains(root: Path, candidate: Path, *, allow_root: bool = False) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return False
    return allow_root or bool(relative.parts)


def _canonical_contained_paths(
    root: Path | str,
    target: Path | str,
    *,
    allow_root: bool = True,
) -> tuple[Path, Path]:
    """Return root and target in the same canonical path coordinate system."""

    root_path = canonical_path(root, require_exists=True)
    target_path = canonical_path(target)
    if not _contains(root_path, target_path, allow_root=allow_root):
        _fail("SAFE_PATH_OUTSIDE_ROOT")
    return root_path, target_path


def _same_volume(left: Path, right: Path) -> bool:
    if os.name == "nt":
        return left.drive.casefold() == right.drive.casefold()
    try:
        left_stat = left.stat()
        right_stat = right.stat()
    except OSError:
        return True
    return left_stat.st_dev == right_stat.st_dev


def assert_safe_target(
    root: Path | str,
    target: Path | str,
    *,
    allow_root: bool = False,
    allow_missing: bool = True,
    expected_type: str | None = None,
    allow_final_symlink: bool = False,
) -> Path:
    """Validate and return the non-following absolute target path."""

    root_raw = _absolute_without_following(root)
    _reparse_components(root_raw)
    root_path = canonical_path(root)
    target_raw = _absolute_without_following(target)
    if _is_reparse(root_path):
        _fail("UNSAFE_REPARSE_POINT")
    _reparse_components(root_path)
    _reparse_components(target_raw, allow_final_reparse=allow_final_symlink)
    try:
        target_resolved = target_raw.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        _fail("SAFE_PATH_INVALID")
    if not _contains(root_path, target_resolved, allow_root=allow_root):
        _fail("SAFE_PATH_OUTSIDE_ROOT")
    exists = target_raw.exists() or target_raw.is_symlink()
    if not exists:
        if not allow_missing:
            _fail("SAFE_PATH_MISSING")
        return target_raw
    final_reparse = _is_reparse(target_raw)
    if final_reparse and not allow_final_symlink:
        _fail("UNSAFE_REPARSE_POINT")
    if expected_type == "file" and (final_reparse or not target_raw.is_file()):
        _fail("SAFE_TYPE_MISMATCH")
    if expected_type == "dir" and (final_reparse or not target_raw.is_dir()):
        _fail("SAFE_TYPE_MISMATCH")
    if expected_type not in {None, "file", "dir"}:
        _fail("SAFE_TYPE_INVALID")
    return target_raw


def _file_digest(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except (OSError, ValueError):
        _fail("SAFE_READ_FAILED")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def tree_digest(path: Path | str) -> str:
    root = assert_safe_target(path, path, allow_root=True, allow_missing=False, expected_type="dir")
    digest = hashlib.sha256()

    def visit(directory: Path, relative: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            _fail("SAFE_READ_FAILED")
        for entry in entries:
            child = directory / entry.name
            child_relative = relative / entry.name
            if _is_reparse(child):
                _fail("UNSAFE_REPARSE_POINT")
            try:
                if entry.is_dir(follow_symlinks=False):
                    visit(child, child_relative)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    _fail("SAFE_TYPE_MISMATCH")
                data = child.read_bytes()
                mode = stat.S_IMODE(child.stat(follow_symlinks=False).st_mode)
            except OSError:
                _fail("SAFE_READ_FAILED")
            encoded = child_relative.as_posix().encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)

    visit(root, Path())
    return "sha256:" + digest.hexdigest()


def _owner_root(value: Mapping[str, Any]) -> Path:
    root = value.get("root")
    if not isinstance(root, str) or not root:
        _fail("SAFE_OWNERSHIP_INVALID")
    return canonical_path(root)


def _owner_target(value: Mapping[str, Any]) -> Path:
    target = value.get("target")
    if not isinstance(target, str) or not target:
        _fail("SAFE_OWNERSHIP_INVALID")
    return _absolute_without_following(target)


def create_ownership_record(
    root: Path | str,
    target: Path | str,
    *,
    kind: str,
    expected_digest: str | None = None,
    authority_roots: Mapping[str, Path | str] | None = None,
) -> dict[str, Any]:
    if not isinstance(kind, str) or not kind or "\x00" in kind:
        _fail("SAFE_OWNERSHIP_INVALID")
    root_path = canonical_path(root)
    target_path = assert_safe_target(root_path, target, allow_missing=True)
    record: dict[str, Any] = {
        "schema_version": 1,
        "token": uuid.uuid4().hex,
        "kind": kind,
        "root": str(root_path),
        "target": str(target_path),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expected_digest": expected_digest,
    }
    if authority_roots:
        record["authority_roots"] = {
            str(name): str(canonical_path(value))
            for name, value in sorted(authority_roots.items())
            if isinstance(name, str)
        }
    return record


def create_link_ownership_record(
    root: Path | str,
    target: Path | str,
    link_target: Path | str,
    *,
    kind: str,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Create an ownership receipt for a link entry whose target is external."""

    if not isinstance(kind, str) or not kind or "\x00" in kind:
        _fail("SAFE_OWNERSHIP_INVALID")
    root_path = canonical_path(root)
    target_raw = _absolute_without_following(target)
    parent = target_raw.parent
    assert_safe_target(root_path, parent, allow_root=True, allow_missing=False, expected_type="dir")
    if not target_raw.is_symlink():
        _fail("SAFE_LINK_REQUIRED")
    expected_link_target = canonical_path(link_target)
    if target_raw.resolve(strict=False) != expected_link_target:
        _fail("SAFE_LINK_TARGET_MISMATCH")
    return {
        "schema_version": 1,
        "token": uuid.uuid4().hex,
        "kind": kind,
        "root": str(root_path),
        "target": str(target_raw),
        "link_target": str(expected_link_target),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expected_digest": expected_digest,
    }


def validate_ownership_record(
    record: Mapping[str, Any],
    root: Path | str,
    target: Path | str,
    *,
    kind: str | None = None,
    expected_digest: str | None = None,
) -> None:
    if not isinstance(record, Mapping) or record.get("schema_version") != 1:
        _fail("SAFE_OWNERSHIP_INVALID")
    token = record.get("token")
    if not isinstance(token, str) or len(token) != 32 or any(char not in "0123456789abcdef" for char in token):
        _fail("SAFE_OWNERSHIP_INVALID")
    expected_root = canonical_path(root)
    expected_target = assert_safe_target(expected_root, target, allow_missing=True)
    if _owner_root(record) != expected_root or _owner_target(record) != expected_target:
        _fail("SAFE_OWNERSHIP_MISMATCH")
    if kind is not None and record.get("kind") != kind:
        _fail("SAFE_OWNERSHIP_MISMATCH")
    recorded_digest = record.get("expected_digest")
    if expected_digest is not None and recorded_digest not in {None, expected_digest}:
        _fail("SAFE_OWNERSHIP_MISMATCH")


def validate_link_ownership_record(
    record: Mapping[str, Any],
    root: Path | str,
    target: Path | str,
    link_target: Path | str | None = None,
    *,
    kind: str | None = None,
    expected_digest: str | None = None,
) -> None:
    """Validate a receipt for an exact symbolic-link directory entry."""

    if not isinstance(record, Mapping) or record.get("schema_version") != 1:
        _fail("SAFE_OWNERSHIP_INVALID")
    token = record.get("token")
    if not isinstance(token, str) or len(token) != 32 or any(char not in "0123456789abcdef" for char in token):
        _fail("SAFE_OWNERSHIP_INVALID")
    root_path = canonical_path(root)
    target_raw = _absolute_without_following(target)
    parent = target_raw.parent
    assert_safe_target(root_path, parent, allow_root=True, allow_missing=False, expected_type="dir")
    if _owner_root(record) != root_path or _owner_target(record) != target_raw:
        _fail("SAFE_OWNERSHIP_MISMATCH")
    if kind is not None and record.get("kind") != kind:
        _fail("SAFE_OWNERSHIP_MISMATCH")
    if link_target is not None:
        expected_link_target = canonical_path(link_target)
        if record.get("link_target") != str(expected_link_target) or not target_raw.is_symlink() or target_raw.resolve(strict=False) != expected_link_target:
            _fail("SAFE_OWNERSHIP_MISMATCH")
    if expected_digest is not None and record.get("expected_digest") not in {None, expected_digest}:
        _fail("SAFE_OWNERSHIP_MISMATCH")
def safe_unlink(
    root: Path | str,
    target: Path | str,
    *,
    expected_digest: str | None = None,
    owner: Mapping[str, Any] | None = None,
    kind: str | None = None,
    allow_missing: bool = False,
    allow_final_symlink: bool = False,
) -> bool:
    path = assert_safe_target(
        root,
        target,
        allow_missing=True,
        expected_type=None if allow_final_symlink else "file",
        allow_final_symlink=allow_final_symlink,
    )
    if owner is not None:
        validate_ownership_record(owner, root, path, kind=kind, expected_digest=expected_digest)
    if not (path.exists() or path.is_symlink()):
        if allow_missing:
            return False
        _fail("SAFE_PATH_MISSING")
    if expected_digest is not None:
        if _is_reparse(path) or _file_digest(path) != expected_digest:
            _fail("SAFE_DIGEST_MISMATCH")
    # Last-moment validation prevents a replacement with a directory or link
    # from turning a file deletion into an unintended traversal.
    assert_safe_target(
        root,
        path,
        allow_missing=False,
        expected_type=None if allow_final_symlink else "file",
        allow_final_symlink=allow_final_symlink,
    )
    try:
        path.unlink()
    except FileNotFoundError:
        if allow_missing:
            return False
        _fail("SAFE_PATH_MISSING")
    except OSError:
        _fail("SAFE_DELETE_FAILED")
    return True


def safe_unlink_link(
    root: Path | str,
    target: Path | str,
    *,
    expected_target: Path | str | None = None,
    allow_missing: bool = False,
) -> bool:
    """Remove one managed symbolic link without following its final target.

    A link is safe to unlink when its own directory entry is contained by the
    managed root.  The target may live outside that root; that is expected for
    a copied Skill installation implemented as a link.  This function never
    removes the target of the link.
    """

    root_raw = _absolute_without_following(root)
    _reparse_components(root_raw)
    root_path = canonical_path(root)
    _reparse_components(root_path)
    target_raw = _absolute_without_following(target)
    parent = target_raw.parent
    _reparse_components(parent)
    try:
        parent_resolved = parent.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        _fail("SAFE_PATH_INVALID")
    if not _contains(root_path, parent_resolved, allow_root=True):
        _fail("SAFE_PATH_OUTSIDE_ROOT")
    if not target_raw.is_symlink():
        if allow_missing and not target_raw.exists():
            return False
        _fail("SAFE_LINK_REQUIRED")
    if expected_target is not None:
        try:
            if target_raw.resolve(strict=False) != canonical_path(expected_target):
                _fail("SAFE_LINK_TARGET_MISMATCH")
        except (OSError, RuntimeError, ValueError):
            _fail("SAFE_LINK_TARGET_MISMATCH")
    # Recheck the exact directory entry and its parent immediately before the
    # unlink.  No operation below follows the final link.
    _reparse_components(parent)
    if not target_raw.is_symlink():
        if allow_missing and not target_raw.exists():
            return False
        _fail("SAFE_LINK_REQUIRED")
    try:
        target_raw.unlink()
    except FileNotFoundError:
        if allow_missing:
            return False
        _fail("SAFE_PATH_MISSING")
    except OSError:
        _fail("SAFE_DELETE_FAILED")
    return True


def safe_symlink(
    root: Path | str,
    target: Path | str,
    link_target: Path | str,
) -> Path:
    """Create one directory symlink at a contained, verified link entry."""

    root_path = assert_safe_target(root, root, allow_root=True, allow_missing=False, expected_type="dir")
    target_raw = _absolute_without_following(target)
    parent = target_raw.parent
    assert_safe_target(root_path, parent, allow_root=True, allow_missing=False, expected_type="dir")
    assert_safe_target(root_path, target_raw, allow_missing=True)
    source_path = canonical_path(link_target, require_exists=True)
    if not source_path.is_dir() or _is_reparse(source_path):
        _fail("SAFE_LINK_TARGET_INVALID")
    try:
        target_raw.symlink_to(source_path, target_is_directory=True)
    except FileExistsError:
        _fail("SAFE_DESTINATION_EXISTS")
    except (OSError, NotImplementedError):
        _fail("SAFE_LINK_CREATE_FAILED")
    # The final entry is rechecked without following it; only this exact link
    # can be removed by safe_unlink_link.
    if not target_raw.is_symlink():
        _fail("SAFE_LINK_CREATE_FAILED")
    return target_raw


def safe_move(
    source_root: Path | str,
    source: Path | str,
    destination_root: Path | str,
    destination: Path | str,
) -> Path:
    """Move one contained file, directory, or symbolic link entry safely."""

    source_raw = _absolute_without_following(source)
    destination_raw = _absolute_without_following(destination)
    source_parent = source_raw.parent
    destination_parent = destination_raw.parent
    assert_safe_target(source_root, source_parent, allow_root=True, allow_missing=False, expected_type="dir")
    assert_safe_target(destination_root, destination_parent, allow_root=True, allow_missing=False, expected_type="dir")
    assert_safe_target(destination_root, destination_raw, allow_missing=True)
    if destination_raw.exists() or destination_raw.is_symlink():
        _fail("SAFE_DESTINATION_EXISTS")
    if not (source_raw.exists() or source_raw.is_symlink()):
        _fail("SAFE_PATH_MISSING")
    if not _same_volume(canonical_path(source_parent), canonical_path(destination_parent)):
        _fail("SAFE_CROSS_VOLUME_OPERATION")
    if source_raw.is_symlink():
        _reparse_components(source_parent)
        if not source_raw.is_symlink():
            _fail("SAFE_LINK_REQUIRED")
        source_is_link = True
    else:
        source_type = "dir" if source_raw.is_dir() else "file" if source_raw.is_file() else None
        if source_type is None:
            _fail("SAFE_TYPE_MISMATCH")
        assert_safe_target(source_root, source_raw, allow_missing=False, expected_type=source_type)
        source_is_link = False
    if not source_is_link:
        assert_safe_target(source_root, source_raw, allow_missing=False)
    assert_safe_target(destination_root, destination_raw, allow_missing=True)
    if source_is_link:
        _reparse_components(source_parent)
    else:
        assert_safe_target(source_root, source_raw, allow_missing=False)
    try:
        os.replace(source_raw, destination_raw)
    except OSError:
        _fail("SAFE_MOVE_FAILED")
    return destination_raw


def safe_mkdir(
    root: Path | str,
    target: Path | str,
    *,
    parents: bool = False,
    mode: int | None = None,
) -> Path:
    """Create a directory only below an existing, reparse-free root."""

    root_raw = assert_safe_target(root, root, allow_root=True, allow_missing=False, expected_type="dir")
    target_raw = _absolute_without_following(target)
    _reparse_components(target_raw)
    root_path, target_path = _canonical_contained_paths(root_raw, target_raw)
    if target_raw.exists() or target_raw.is_symlink():
        path = assert_safe_target(root_path, target_raw, allow_root=True, allow_missing=False, expected_type="dir")
        path = canonical_path(path, require_exists=True)
        if mode is not None:
            safe_chmod(root_path, path, mode, allow_root=True)
        return path
    if not parents and target_path.parent != root_path:
        _fail("SAFE_PARENT_MISSING")
    missing: list[Path] = []
    current = target_path
    while current != root_path and not (current.exists() or current.is_symlink()):
        missing.append(current)
        current = current.parent
    assert_safe_target(root_path, current, allow_root=True, allow_missing=False, expected_type="dir")
    for path in reversed(missing):
        assert_safe_target(root_path, path.parent, allow_root=True, allow_missing=False, expected_type="dir")
        try:
            path.mkdir()
        except FileExistsError:
            existing = path
            if not (existing.exists() and not existing.is_symlink() and existing.is_dir()):
                _fail("SAFE_MKDIR_FAILED")
        except OSError:
            _fail("SAFE_MKDIR_FAILED")
        assert_safe_target(root_path, path, allow_missing=False, expected_type="dir")
    result = assert_safe_target(root_path, target_path, allow_root=True, allow_missing=False, expected_type="dir")
    if mode is not None:
        safe_chmod(root_path, result, mode, allow_root=True)
    return result


def safe_ensure_directory(target: Path | str, *, mode: int | None = None) -> Path:
    """Create a directory below its nearest existing, reparse-free ancestor."""

    target_raw = _absolute_without_following(target)
    anchor = target_raw
    while not (anchor.exists() or anchor.is_symlink()):
        parent = anchor.parent
        if parent == anchor:
            _fail("SAFE_PARENT_MISSING")
        anchor = parent
    if anchor.is_symlink() or not anchor.is_dir():
        _fail("UNSAFE_REPARSE_POINT" if anchor.is_symlink() else "SAFE_TYPE_MISMATCH")
    return safe_mkdir(anchor, target_raw, parents=True, mode=mode)


def _tree_entries(root: Path) -> tuple[list[Path], list[Path]]:
    files: list[Path] = []
    directories: list[Path] = []

    def visit(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            _fail("SAFE_READ_FAILED")
        for entry in entries:
            child = directory / entry.name
            if _is_reparse(child):
                _fail("UNSAFE_REPARSE_POINT")
            try:
                if entry.is_dir(follow_symlinks=False):
                    visit(child)
                    directories.append(child)
                elif entry.is_file(follow_symlinks=False):
                    files.append(child)
                else:
                    _fail("SAFE_TYPE_MISMATCH")
            except OSError:
                _fail("SAFE_READ_FAILED")

    visit(root)
    return files, directories


def safe_remove_tree(
    root: Path | str,
    target: Path | str,
    *,
    expected_digest: str | None = None,
    owner: Mapping[str, Any] | None = None,
    kind: str | None = None,
    allow_missing: bool = False,
) -> bool:
    path = assert_safe_target(root, target, allow_missing=True, expected_type="dir")
    if owner is not None:
        validate_ownership_record(owner, root, path, kind=kind, expected_digest=expected_digest)
    if not path.exists():
        if allow_missing:
            return False
        _fail("SAFE_PATH_MISSING")
    if expected_digest is not None and tree_digest(path) != expected_digest:
        _fail("SAFE_DIGEST_MISMATCH")
    files, directories = _tree_entries(path)
    # Rebuild the inventory and validate containment immediately before each
    # mutation.  os.unlink/rmdir operate on the exact path and never follow a
    # child symlink, while the preflight rejects all such children anyway.
    for child in sorted(files, key=lambda item: len(item.parts), reverse=True):
        safe_unlink(path, child, expected_digest=None, allow_missing=False)
    for child in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        assert_safe_target(path, child, allow_missing=False, expected_type="dir")
        try:
            child.rmdir()
        except OSError:
            _fail("SAFE_DELETE_FAILED")
    assert_safe_target(root, path, allow_missing=False, expected_type="dir")
    try:
        path.rmdir()
    except OSError:
        _fail("SAFE_DELETE_FAILED")
    return True


def safe_replace(
    source_root: Path | str,
    source: Path | str,
    destination_root: Path | str,
    destination: Path | str,
    *,
    source_type: str | None = None,
    replace_existing: bool = True,
) -> Path:
    source_path = assert_safe_target(source_root, source, allow_missing=False, expected_type=source_type)
    destination_path = assert_safe_target(
        destination_root,
        destination,
        allow_missing=True,
        expected_type=None,
    )
    if not _same_volume(canonical_path(source_root), canonical_path(destination_root)):
        _fail("SAFE_CROSS_VOLUME_OPERATION")
    if not replace_existing and (destination_path.exists() or destination_path.is_symlink()):
        _fail("SAFE_DESTINATION_EXISTS")
    # A replacement target may be overwritten only when it is a regular file
    # or directory; replacing a link would hide an ownership/path error.
    if destination_path.exists() or destination_path.is_symlink():
        assert_safe_target(destination_root, destination_path, allow_missing=False, allow_final_symlink=False)
    assert_safe_target(source_root, source_path, allow_missing=False, expected_type=source_type)
    try:
        os.replace(source_path, destination_path)
    except OSError:
        _fail("SAFE_REPLACE_FAILED")
    return destination_path


def _cleanup_temporary(root: Path | str, temporary: Path) -> None:
    """Remove a temporary file, preserving fail-closed cleanup errors."""

    safe_unlink(root, temporary, allow_missing=True)


def safe_atomic_write(
    root: Path | str,
    target: Path | str,
    data: bytes,
    *,
    mode: int | None = None,
) -> Path:
    if not isinstance(data, bytes):
        _fail("SAFE_WRITE_DATA_INVALID")
    destination = assert_safe_target(root, target, allow_missing=True)
    parent = destination.parent
    assert_safe_target(root, parent, allow_root=True, allow_missing=False, expected_type="dir")
    temporary = parent / f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    assert_safe_target(root, temporary, allow_missing=True)
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            safe_chmod(root, temporary, mode)
        safe_replace(root, temporary, root, destination, source_type="file")
    except SafeFilesystemError:
        _cleanup_temporary(root, temporary)
        raise
    except OSError:
        _cleanup_temporary(root, temporary)
        _fail("SAFE_WRITE_FAILED")
    return destination


def safe_copy_file(
    source_root: Path | str,
    source: Path | str,
    destination_root: Path | str,
    destination: Path | str,
    *,
    expected_digest: str | None = None,
    mode: int | None = None,
) -> Path:
    source_path = assert_safe_target(source_root, source, allow_missing=False, expected_type="file")
    if expected_digest is not None and _file_digest(source_path) != expected_digest:
        _fail("SAFE_DIGEST_MISMATCH")
    destination_path = assert_safe_target(destination_root, destination, allow_missing=True)
    parent = destination_path.parent
    assert_safe_target(destination_root, parent, allow_root=True, allow_missing=False, expected_type="dir")
    temporary = parent / f".{destination_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    assert_safe_target(destination_root, temporary, allow_missing=True)
    try:
        shutil.copyfile(source_path, temporary)
        if mode is not None:
            safe_chmod(destination_root, temporary, mode)
        safe_replace(destination_root, temporary, destination_root, destination_path, source_type="file")
    except SafeFilesystemError:
        _cleanup_temporary(destination_root, temporary)
        raise
    except OSError:
        _cleanup_temporary(destination_root, temporary)
        _fail("SAFE_COPY_FAILED")
    return destination_path


def safe_copy_tree(
    source_root: Path | str,
    source: Path | str,
    destination_root: Path | str,
    destination: Path | str,
) -> Path:
    """Copy a regular, reparse-free directory tree through a safe staging tree."""

    source_path = assert_safe_target(source_root, source, allow_missing=False, expected_type="dir")
    destination_path = assert_safe_target(destination_root, destination, allow_missing=True)
    files, directories = _tree_entries(source_path)
    temporary = destination_path.parent / f".{destination_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    assert_safe_target(destination_path.parent, temporary, allow_missing=True)
    try:
        temporary.mkdir()
        copied = temporary / source_path.name
        copied.mkdir()
        for directory in sorted(directories, key=lambda item: len(item.relative_to(source_path).parts)):
            relative = directory.relative_to(source_path)
            target_directory = copied / relative
            assert_safe_target(temporary, target_directory, allow_missing=True)
            target_directory.mkdir()
        for file_path in files:
            relative = file_path.relative_to(source_path)
            target_file = copied / relative
            safe_copy_file(source_path, file_path, temporary, target_file)
        safe_replace(temporary, copied, destination_path.parent, destination_path, source_type="dir")
    except SafeFilesystemError:
        if temporary.exists():
            safe_remove_tree(destination_path.parent, temporary, allow_missing=True)
        raise
    except OSError:
        if temporary.exists():
            safe_remove_tree(destination_path.parent, temporary, allow_missing=True)
        _fail("SAFE_COPY_FAILED")
    if temporary.exists():
        safe_remove_tree(destination_path.parent, temporary, allow_missing=True)
    return destination_path


def safe_chmod(root: Path | str, target: Path | str, mode: int, *, allow_root: bool = False) -> Path:
    if type(mode) is not int or mode < 0 or mode > 0o7777:
        _fail("SAFE_MODE_INVALID")
    path = assert_safe_target(root, target, allow_root=allow_root, allow_missing=False)
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (OSError, NotImplementedError, TypeError):
        if os.name == "nt" and isinstance(path, Path) and not _is_reparse(path):
            try:
                os.chmod(path, mode)
            except OSError:
                _fail("SAFE_CHMOD_FAILED")
        else:
            _fail("SAFE_CHMOD_FAILED")
    return path


def read_ownership_record(path: Path | str, *, root: Path | str) -> dict[str, Any]:
    target = assert_safe_target(root, path, allow_missing=False, expected_type="file")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail("SAFE_OWNERSHIP_INVALID")
    if not isinstance(value, dict):
        _fail("SAFE_OWNERSHIP_INVALID")
    return value


def write_ownership_record(path: Path | str, record: Mapping[str, Any], *, root: Path | str) -> Path:
    if not isinstance(record, Mapping):
        _fail("SAFE_OWNERSHIP_INVALID")
    try:
        data = (json.dumps(dict(record), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError):
        _fail("SAFE_OWNERSHIP_INVALID")
    return safe_atomic_write(root, path, data, mode=0o600)


__all__ = [
    "SafeFilesystemError",
    "absolute_path",
    "assert_no_reparse_components",
    "assert_safe_target",
    "canonical_path",
    "create_ownership_record",
    "create_link_ownership_record",
    "read_ownership_record",
    "safe_atomic_write",
    "safe_chmod",
    "safe_copy_file",
    "safe_copy_tree",
    "safe_ensure_directory",
    "safe_mkdir",
    "safe_move",
    "safe_remove_tree",
    "safe_replace",
    "safe_symlink",
    "safe_unlink",
    "safe_unlink_link",
    "tree_digest",
    "validate_ownership_record",
    "validate_link_ownership_record",
    "write_ownership_record",
]
