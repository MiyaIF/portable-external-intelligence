from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import HostSpec
from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    safe_copy_tree,
    safe_ensure_directory,
    safe_move,
    safe_remove_tree,
    safe_symlink,
    safe_unlink_link,
    tree_digest,
)


SkillInstallMode = Literal["copy", "link"]


@dataclass(frozen=True)
class SkillInstallResult:
    host_id: str
    mode: SkillInstallMode
    source: Path
    destination: Path
    source_hash: str
    installed_hash: str
    changed: bool
    backup_path: Path | None = None
    discovered: bool = False
    reason_code: str = "SKILL_INSTALLED"

    def to_dict(self) -> dict[str, object]:
        return {
            "host_id": self.host_id,
            "mode": self.mode,
            "source": str(self.source),
            "destination": str(self.destination),
            "source_hash": self.source_hash,
            "installed_hash": self.installed_hash,
            "changed": self.changed,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "discovered": self.discovered,
            "reason_code": self.reason_code,
        }


def _sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _regular_tree(source: Path) -> list[Path]:
    if not source.is_dir():
        raise ValueError("SKILL_SOURCE_NOT_DIRECTORY")
    files: list[Path] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if "__pycache__" in relative.parts or path.suffix.casefold() in {".pyc", ".pyo"}:
            raise ValueError("SKILL_SOURCE_RUNTIME_ARTIFACT")
        if path.is_symlink():
            resolved = path.resolve()
            if not _within(source, resolved):
                raise ValueError("SKILL_SOURCE_SYMLINK_ESCAPE")
            if resolved.is_file():
                files.append(path)
            continue
        if path.is_file():
            files.append(path)
    if not (source / "SKILL.md").is_file():
        raise ValueError("SKILL_ENTRYPOINT_MISSING")
    return files


def canonical_tree_hash(source: Path) -> str:
    source = Path(source).expanduser().resolve()
    files = _regular_tree(source)
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(source).as_posix().encode("utf-8")
        resolved = path.resolve()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = resolved.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return "sha256:" + digest.hexdigest()


def _destination(host: HostSpec, source: Path) -> Path:
    roots = tuple(absolute_path(root) for root in host.skill_roots)
    if not roots:
        raise ValueError("SKILL_ROOT_UNAVAILABLE")
    root = roots[0]
    return root / source.name


def _copy_tree(source: Path, destination: Path) -> None:
    safe_ensure_directory(destination.parent)
    safe_copy_tree(source.parent, source, destination.parent, destination)


def _backup_destination(destination: Path) -> Path | None:
    if not destination.exists() and not destination.is_symlink():
        return None
    timestamp = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = destination.with_name(destination.name + ".before-ei-" + timestamp)
    safe_move(destination.parent, destination, destination.parent, backup)
    return backup


def install_skill(source: Path, host: HostSpec, mode: SkillInstallMode = "copy", *, previous_hash: str | None = None) -> SkillInstallResult:
    source = Path(source).expanduser().resolve()
    if mode not in {"copy", "link"}:
        raise ValueError("SKILL_MODE_INVALID")
    source_hash = canonical_tree_hash(source)
    destination = _destination(host, source)
    safe_ensure_directory(destination.parent)
    if destination.is_symlink():
        resolved = destination.resolve()
        if mode == "link" and resolved == source:
            return SkillInstallResult(host.host_id, mode, source, destination, source_hash, source_hash, False, None, True, "SKILL_ALREADY_LINKED")
        raise ValueError("SKILL_DESTINATION_CONFLICT")
    if destination.exists():
        installed_hash = canonical_tree_hash(destination)
        if installed_hash == source_hash:
            return SkillInstallResult(host.host_id, mode, source, destination, source_hash, installed_hash, False, None, True, "SKILL_ALREADY_CURRENT")
        if previous_hash is None or installed_hash != previous_hash:
            raise ValueError("SKILL_INSTALL_CONFLICT")
    else:
        installed_hash = ""
    if mode == "link":
        try:
            safe_symlink(destination.parent, destination, source)
        except SafeFilesystemError as exc:
            if exc.code == "SAFE_LINK_CREATE_FAILED":
                raise ValueError("SKILL_LINK_UNAVAILABLE") from exc
            raise ValueError(exc.code) from exc
        return SkillInstallResult(host.host_id, mode, source, destination, source_hash, source_hash, True, None, True, "SKILL_LINKED")
    backup = _backup_destination(destination)
    try:
        _copy_tree(source, destination)
        installed_hash = canonical_tree_hash(destination)
    except Exception:
        if destination.is_symlink():
            safe_unlink_link(destination.parent, destination, allow_missing=True)
        elif destination.exists():
            safe_remove_tree(destination.parent, destination, allow_missing=True)
        if backup and (backup.exists() or backup.is_symlink()):
            safe_move(backup.parent, backup, destination.parent, destination)
        raise
    return SkillInstallResult(host.host_id, mode, source, destination, source_hash, installed_hash, True, backup, True, "SKILL_INSTALLED")


def remove_installed_skill(destination: Path, expected_hash: str | None, *, force: bool = False) -> dict[str, object]:
    destination = absolute_path(destination)
    if not destination.exists() and not destination.is_symlink():
        return {"removed": False, "reason_code": "SKILL_NOT_INSTALLED", "path": str(destination)}
    if destination.is_symlink():
        if expected_hash and destination.resolve().is_dir() and canonical_tree_hash(destination.resolve()) != expected_hash and not force:
            return {"removed": False, "reason_code": "UNINSTALL_CONFLICT", "path": str(destination)}
        try:
            safe_unlink_link(destination.parent, destination, expected_target=destination.resolve())
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
        return {"removed": True, "reason_code": "SKILL_REMOVED", "path": str(destination)}
    current_hash = canonical_tree_hash(destination)
    if expected_hash and current_hash != expected_hash and not force:
        return {"removed": False, "reason_code": "UNINSTALL_CONFLICT", "path": str(destination), "current_hash": current_hash, "expected_hash": expected_hash}
    expected_tree_digest = tree_digest(destination)
    try:
        safe_remove_tree(destination.parent, destination, expected_digest=expected_tree_digest)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    return {"removed": True, "reason_code": "SKILL_REMOVED", "path": str(destination), "current_hash": current_hash}


__all__ = ["SkillInstallMode", "SkillInstallResult", "canonical_tree_hash", "install_skill", "remove_installed_skill"]
