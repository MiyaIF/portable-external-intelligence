"""Machine-local, data-only profiles for compatible CLI hosts.

Profiles describe only the small amount of host metadata needed to reuse an
existing public hook adapter.  They deliberately cannot carry commands,
environment values, or executable code.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

from .safe_fs import SafeFilesystemError, assert_no_reparse_components, assert_safe_target, safe_atomic_write, safe_ensure_directory, safe_unlink


PUBLIC_ADAPTER_FAMILIES = {
    "codex-cli": "codex-compatible",
    "claude-code": "claude-compatible",
    "gemini-cli": "gemini-compatible",
    "qwen-code": "qwen-compatible",
}
PUBLIC_HOST_IDS = frozenset(PUBLIC_ADAPTER_FAMILIES)
HOST_FAMILIES = frozenset(PUBLIC_ADAPTER_FAMILIES.values())
BUILTIN_HOST_ALIASES = {
    "codex": "codex-cli",
    "claude": "claude-code",
    "gemini": "gemini-cli",
    "qwen": "qwen-code",
}
LEGACY_RESERVED_HOST_IDS = frozenset({"codex-app"})
PROFILE_KEYS = frozenset(
    {
        "schema_version",
        "host_id",
        "display_name",
        "host_family",
        "adapter_id",
        "executable_names",
        "hook_config_path",
        "global_context_path",
        "skill_roots",
    }
)
CUSTOM_HOST_ID_PATTERN = r"^(?!\.|.*[. ]$)(?!con(?:\..*)?$|prn(?:\..*)?$|aux(?:\..*)?$|nul(?:\..*)?$|com[1-9](?:\..*)?$|lpt[1-9](?:\..*)?$)[a-z0-9][a-z0-9._-]{0,159}$"
_SAFE_ID = re.compile(CUSTOM_HOST_ID_PATTERN)
_SAFE_EXECUTABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$")
_SHELL_META = frozenset("&|;<>`$(){}[]!*?'\"\\/")


@dataclass(frozen=True)
class HostProfile:
    schema_version: int
    host_id: str
    display_name: str
    host_family: str
    adapter_id: str
    executable_names: tuple[str, ...]
    hook_config_path: Path
    global_context_path: Path
    skill_roots: tuple[Path, ...]


def is_custom_host_id(value: object) -> bool:
    """Return whether ``value`` is a canonical, Windows-safe custom ID."""

    if not isinstance(value, str) or value != value.casefold():
        return False
    if value in PUBLIC_HOST_IDS or value in BUILTIN_HOST_ALIASES or value in LEGACY_RESERVED_HOST_IDS:
        return False
    return _SAFE_ID.fullmatch(value) is not None


def canonical_host_id(value: object) -> str:
    """Canonicalize built-in aliases and require lowercase custom IDs."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("HOST_ID_INVALID")
    folded = value.casefold()
    if folded in BUILTIN_HOST_ALIASES:
        return BUILTIN_HOST_ALIASES[folded]
    if folded in PUBLIC_HOST_IDS or folded in LEGACY_RESERVED_HOST_IDS:
        return folded
    if value != folded:
        raise ValueError("HOST_ID_NON_CANONICAL")
    if is_custom_host_id(value):
        return value
    raise ValueError("HOST_ID_INVALID")


def _invalid() -> ValueError:
    return ValueError("HOST_PROFILE_INVALID")


def _path_invalid() -> ValueError:
    return ValueError("HOST_PROFILE_PATH_INVALID")


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(data), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def host_profile_hash(data: Mapping[str, Any]) -> str:
    """Return the digest of the validated, detached profile document."""

    return "sha256:" + hashlib.sha256(_canonical_json(data)).hexdigest()


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or any(ord(char) < 0x20 for char in value):
        raise _invalid()
    if field == "display_name" and len(value) > 256:
        raise _invalid()
    return value


def _relative_path(value: object) -> str:
    text = _text(value, field="path")
    if ":" in text:
        raise _path_invalid()
    # Validate both grammars because a profile can be moved between Windows
    # and POSIX machines.  The stored spelling remains the user's relative
    # spelling and never contains a machine-local absolute root.
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        raise _path_invalid()
    if any(part in {"", ".", ".."} for part in (*posix.parts, *windows.parts)):
        # A leading "./" is needlessly ambiguous in a portable profile, and
        # parent traversal is never permitted.
        raise _path_invalid()
    if any(ord(char) < 0x20 for char in text):
        raise _path_invalid()
    return text


def _bound_path(host_home: Path, relative: str) -> Path:
    try:
        home = Path(host_home).expanduser().resolve()
        candidate = (home / relative).resolve()
        if not candidate.is_relative_to(home):
            raise _path_invalid()
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc) == "HOST_PROFILE_PATH_INVALID":
            raise
        raise _path_invalid() from exc
    return candidate


def _sequence(value: object, *, field: str, executable: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise _invalid()
    values: list[str] = []
    for item in value:
        text = _text(item, field=field)
        if executable:
            if not _SAFE_EXECUTABLE.fullmatch(text) or any(char in _SHELL_META or char.isspace() for char in text):
                raise _invalid()
        values.append(text)
    if len(set(values)) != len(values):
        raise _invalid()
    return tuple(values)


def build_host_profile(data: Mapping[str, Any], host_home: Path) -> HostProfile:
    """Validate a data-only profile and bind its relative paths to ``host_home``."""

    if not isinstance(data, Mapping) or set(data) != PROFILE_KEYS:
        raise _invalid()
    if type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
        raise _invalid()
    host_id = _text(data.get("host_id"), field="host_id")
    try:
        host_id = canonical_host_id(host_id)
    except ValueError as exc:
        raise _invalid() from exc
    if not is_custom_host_id(host_id):
        raise _invalid()
    display_name = _text(data.get("display_name"), field="display_name")
    host_family = _text(data.get("host_family"), field="host_family")
    adapter_id = _text(data.get("adapter_id"), field="adapter_id")
    if adapter_id not in PUBLIC_ADAPTER_FAMILIES or host_family != PUBLIC_ADAPTER_FAMILIES[adapter_id]:
        raise _invalid()
    executable_names = _sequence(data.get("executable_names"), field="executable_names", executable=True)
    hook_config = _relative_path(data.get("hook_config_path"))
    context = _relative_path(data.get("global_context_path"))
    skill_values = _sequence(data.get("skill_roots"), field="skill_roots")
    skill_roots = tuple(_bound_path(Path(host_home), _relative_path(item)) for item in skill_values)
    return HostProfile(
        schema_version=1,
        host_id=host_id,
        display_name=display_name,
        host_family=host_family,
        adapter_id=adapter_id,
        executable_names=executable_names,
        hook_config_path=_bound_path(Path(host_home), hook_config),
        global_context_path=_bound_path(Path(host_home), context),
        skill_roots=skill_roots,
    )


def _read_profile(path: Path) -> dict[str, Any]:
    try:
        source = assert_no_reparse_components(Path(path).expanduser())
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 256 * 1024:
            raise OSError("profile unavailable")
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, SafeFilesystemError) as exc:
        raise ValueError("HOST_PROFILE_READ_FAILED") from exc
    if not isinstance(value, dict):
        raise _invalid()
    return value


def read_host_profile_document(path: Path) -> dict[str, Any]:
    """Read a profile document without writing or binding it to a runtime."""

    return _read_profile(Path(path))


def host_profile_bytes(data: Mapping[str, Any]) -> bytes:
    """Return the deterministic runtime representation of a validated document."""

    return (json.dumps(dict(data), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def load_host_profile(path: Path, host_home: Path) -> HostProfile:
    return build_host_profile(_read_profile(Path(path)), Path(host_home))


def _atomic_write(path: Path, raw: bytes) -> None:
    target = assert_no_reparse_components(path)
    safe_ensure_directory(target.parent)
    safe_atomic_write(target.parent, target, raw)


def install_host_profiles(profile_paths: Sequence[Path], runtime_root: Path) -> Mapping[str, HostProfile]:
    """Validate and atomically copy profiles into machine-local runtime."""

    if isinstance(profile_paths, (str, bytes)):
        raise _invalid()
    try:
        runtime = assert_no_reparse_components(Path(runtime_root).expanduser())
        if runtime.exists():
            assert_safe_target(runtime.parent, runtime, allow_root=True, allow_missing=False, expected_type="dir")
        destination = runtime / "host-profiles"
        assert_no_reparse_components(destination)
        if destination.exists():
            assert_safe_target(runtime, destination, allow_root=False, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_RUNTIME_WRITE_FAILED") from exc
    result: dict[str, HostProfile] = {}
    documents: dict[str, dict[str, Any]] = {}
    for raw_path in profile_paths:
        document = _read_profile(Path(raw_path))
        profile = build_host_profile(document, runtime)
        if profile.host_id in result:
            raise ValueError("HOST_PROFILE_DUPLICATE")
        result[profile.host_id] = profile
        documents[profile.host_id] = {key: document[key] for key in sorted(PROFILE_KEYS)}
    planned_targets: dict[str, Path] = {}
    try:
        for host_id in documents:
            target = destination / f"{host_id}.json"
            assert_no_reparse_components(target)
            if destination.exists():
                assert_safe_target(destination, target, allow_missing=True)
            planned_targets[host_id] = target
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_RUNTIME_WRITE_FAILED") from exc
    destination_existed = destination.exists()
    try:
        safe_ensure_directory(runtime)
        safe_ensure_directory(destination)
        assert_safe_target(runtime, destination, allow_root=False, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_RUNTIME_WRITE_FAILED") from exc
    snapshots: dict[Path, bytes | None] = {}
    try:
        for host_id, document in documents.items():
            target = planned_targets[host_id]
            if target.exists():
                if target.is_symlink() or not target.is_file():
                    raise OSError("profile target is not a regular file")
                snapshots[target] = target.read_bytes()
            else:
                snapshots[target] = None
        for host_id, document in documents.items():
            _atomic_write(planned_targets[host_id], host_profile_bytes(document))
    except (OSError, ValueError, SafeFilesystemError) as exc:
        rollback_error: Exception | None = None
        for target, previous in reversed(tuple(snapshots.items())):
            try:
                if previous is None:
                    safe_unlink(destination, target, allow_missing=True)
                else:
                    _atomic_write(target, previous)
            except (OSError, ValueError, SafeFilesystemError) as rollback_exc:
                rollback_error = rollback_exc
                break
        if not destination_existed and destination.is_dir():
            try:
                if not any(destination.iterdir()):
                    destination.rmdir()
            except OSError:
                # Best-effort cleanup must not mask the original write failure.
                destination_existed = True
        if rollback_error is not None:
            raise ValueError("HOST_PROFILE_RUNTIME_ROLLBACK_FAILED") from rollback_error
        raise ValueError("HOST_PROFILE_RUNTIME_WRITE_FAILED") from exc
    return result


def load_installed_host_profiles(runtime_root: Path) -> Mapping[str, HostProfile]:
    try:
        runtime = assert_no_reparse_components(Path(runtime_root).expanduser())
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
    directory = runtime / "host-profiles"
    try:
        assert_no_reparse_components(directory)
        if directory.exists():
            assert_safe_target(runtime, directory, allow_root=False, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
    if not directory.exists():
        return {}
    if not directory.is_dir():
        raise ValueError("HOST_PROFILE_RUNTIME_INVALID")
    result: dict[str, HostProfile] = {}
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
        profile = load_host_profile(path, runtime)
        if path.stem != profile.host_id:
            raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
        if profile.host_id in result:
            raise ValueError("HOST_PROFILE_DUPLICATE")
        result[profile.host_id] = profile
    return result


__all__ = [
    "HOST_FAMILIES",
    "BUILTIN_HOST_ALIASES",
    "CUSTOM_HOST_ID_PATTERN",
    "HostProfile",
    "canonical_host_id",
    "host_profile_bytes",
    "is_custom_host_id",
    "PUBLIC_ADAPTER_FAMILIES",
    "PUBLIC_HOST_IDS",
    "build_host_profile",
    "host_profile_hash",
    "install_host_profiles",
    "load_host_profile",
    "load_installed_host_profiles",
    "read_host_profile_document",
]
