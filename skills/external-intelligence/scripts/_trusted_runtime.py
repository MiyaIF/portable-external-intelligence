from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_MAX_MANIFEST_BYTES = 1024 * 1024
_BINDING_NAME = ".external-intelligence-binding.json"
_OWNERSHIP = {
    "engine_root": "public-source-read-only",
    "knowledge_root": "private-knowledge-git-or-local",
    "runtime_root": "machine-local-git-forbidden",
}
_BINDING_KEYS_V1 = frozenset(
    {
        "schema_version",
        "host_id",
        "engine_root",
        "knowledge_root",
        "runtime_root",
        "python_exe",
        "skill_destination",
        "installed_skill_hash",
    }
)
_BINDING_KEYS_V2 = frozenset(
    {
        "schema_version",
        "host_id",
        "engine_root",
        "personal_knowledge_root",
        "team_knowledge_root",
        "knowledge_root",
        "runtime_root",
        "python_exe",
        "skill_destination",
        "installed_skill_hash",
    }
)
_TEAM_STORE_ID = re.compile(r"^team_[0-9a-f]{16,64}$")
_TEAM_WRITER_ID = re.compile(r"^writer_[0-9a-f]{16,64}$")
_TEAM_MEMBER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_PERSONAL_STORE_KEYS = frozenset(
    {
        "enabled",
        "status",
        "mode",
        "root",
        "remote_name",
        "remote_fingerprint",
        "remote_classification",
        "branch",
        "connected",
        "initial_push_complete",
        "sync_enabled",
    }
)
_PERSONAL_REPOSITORY_KEYS = _PERSONAL_STORE_KEYS - {"enabled"}
_CLI_BOOTSTRAP = (
    "import runpy,sys;"
    "source=sys.argv.pop(1);"
    "sys.path.insert(0,source);"
    "runpy.run_module('ei.cli',run_name='__main__')"
)


class BindingError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RuntimeBinding:
    engine_root: Path
    personal_knowledge_root: Path
    runtime_root: Path
    python_exe: Path
    team_knowledge_root: Path | None = None

    @property
    def knowledge_root(self) -> Path:
        """Compatibility view of the personal knowledge root."""

        return self.personal_knowledge_root


def _canonicalize_transitional_v8_providers(value: dict[str, object]) -> None:
    """Collapse a legacy v8 provider list only around a valid ready organizer."""

    organizer = value.get("organizer")
    providers = value.get("providers")
    work_hosts = value.get("work_hosts")
    hosts = value.get("hosts")
    if (
        not isinstance(organizer, dict)
        or set(organizer) != {"status", "provider_id", "host_id", "reason_code"}
        or organizer.get("status") != "READY"
        or not isinstance(providers, list)
        or any(not isinstance(item, str) or not _SAFE_ID.fullmatch(item) for item in providers)
        or not isinstance(work_hosts, list)
        or not work_hosts
        or any(not isinstance(item, str) or not item for item in work_hosts)
        or len(set(work_hosts)) != len(work_hosts)
        or not isinstance(hosts, dict)
        or not set(work_hosts).issubset(set(hosts))
    ):
        return
    provider_id = organizer.get("provider_id")
    host_id = organizer.get("host_id")
    reason_code = organizer.get("reason_code")
    if not isinstance(provider_id, str) or not _SAFE_ID.fullmatch(provider_id) or reason_code is not None:
        return
    if provider_id == "subscription-cli":
        if not isinstance(host_id, str) or not _SAFE_ID.fullmatch(host_id) or host_id not in hosts:
            return
        allowed_difference = {host_id}
    else:
        if host_id is not None:
            return
        allowed_difference = set()
    if provider_id not in providers or set(hosts) - set(work_hosts) - allowed_difference:
        return
    value["providers"] = [provider_id]


def add_binding_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine-root", "--repo", dest="engine_root", default=None)
    parser.add_argument("--runtime-root", required=True)


def _directory(value: object, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BindingError(code)
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise BindingError(code)
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BindingError(code) from exc
    if not resolved.is_dir():
        raise BindingError(code)
    return resolved


def _file(value: object, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BindingError(code)
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise BindingError(code)
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BindingError(code) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BindingError(code)
    return resolved


def _inside(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _lexical_absolute(value: str | Path) -> Path:
    return Path(os.path.abspath(str(Path(value).expanduser())))


def invocation_script_path() -> Path:
    return _lexical_absolute(sys.argv[0])


def _same_lexical(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(str(_lexical_absolute(left))) == os.path.normcase(str(_lexical_absolute(right)))


def _tree_hash(skill_destination: Path) -> str:
    source = skill_destination.resolve(strict=True)
    if not source.is_dir():
        raise BindingError("SKILL_BINDING_DESTINATION_INVALID")
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        relative_path = path.relative_to(source)
        if "__pycache__" in relative_path.parts or path.suffix.casefold() in {".pyc", ".pyo"}:
            raise BindingError("SKILL_RUNTIME_ARTIFACT_PRESENT")
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        try:
            relative = relative_path.as_posix().encode("utf-8")
            resolved.relative_to(source)
        except ValueError as exc:
            raise BindingError("SKILL_BINDING_DESTINATION_INVALID") from exc
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = resolved.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return "sha256:" + digest.hexdigest()


def _read_binding(script_path: str | Path | None) -> tuple[dict[str, object], bytes, Path, Path]:
    script = _lexical_absolute(script_path or invocation_script_path())
    if script.parent.name != "scripts" or script.parent.parent.name != "external-intelligence":
        raise BindingError("SKILL_BINDING_LOCATION_INVALID")
    destination = script.parent.parent
    target = destination.parent / _BINDING_NAME
    try:
        if target.is_symlink() or not target.is_file() or target.stat().st_size > _MAX_MANIFEST_BYTES:
            raise BindingError("SKILL_BINDING_MISSING")
        raw = target.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except BindingError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BindingError("SKILL_BINDING_INVALID") from exc
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2}:
        raise BindingError("SKILL_BINDING_INVALID")
    expected_keys = _BINDING_KEYS_V1 if value.get("schema_version") == 1 else _BINDING_KEYS_V2
    if set(value) != expected_keys:
        raise BindingError("SKILL_BINDING_INVALID")
    configured_destination = value.get("skill_destination")
    if not isinstance(configured_destination, str) or not _same_lexical(configured_destination, destination):
        raise BindingError("SKILL_BINDING_DESTINATION_INVALID")
    return value, raw, target, destination


def load_binding(
    runtime_root: str | Path | None,
    expected_engine_root: str | Path | None = None,
    *,
    script_path: str | Path | None = None,
) -> RuntimeBinding:
    binding, binding_raw, binding_path, skill_destination = _read_binding(script_path)
    bound_engine = _directory(binding.get("engine_root"), "SKILL_BINDING_INVALID")
    schema_version = binding.get("schema_version")
    if schema_version == 2:
        personal_value = binding.get("personal_knowledge_root")
        legacy_value = binding.get("knowledge_root")
        if not isinstance(personal_value, str) or not isinstance(legacy_value, str) or not _same_lexical(personal_value, legacy_value):
            raise BindingError("SKILL_BINDING_PERSONAL_ROOT_MISMATCH")
    else:
        personal_value = binding.get("knowledge_root")
        legacy_value = personal_value
    bound_knowledge = _directory(personal_value, "SKILL_BINDING_INVALID")
    bound_team_raw: object = binding.get("team_knowledge_root") if schema_version == 2 else None
    bound_team: Path | None = None
    if bound_team_raw is not None:
        if not isinstance(bound_team_raw, str) or not Path(bound_team_raw).expanduser().is_absolute():
            raise BindingError("SKILL_BINDING_INVALID")
    bound_runtime = _directory(binding.get("runtime_root"), "SKILL_BINDING_INVALID")
    bound_python = _file(binding.get("python_exe"), "SKILL_BINDING_INVALID")
    if runtime_root is not None:
        requested_runtime = _directory(str(runtime_root), "ACTIVE_MANIFEST_RUNTIME_INVALID")
        if requested_runtime != bound_runtime:
            raise BindingError("SKILL_RUNTIME_MISMATCH")
    if expected_engine_root is not None:
        expected = _directory(str(expected_engine_root), "ACTIVE_MANIFEST_ENGINE_MISMATCH")
        if expected != bound_engine:
            raise BindingError("ACTIVE_MANIFEST_ENGINE_MISMATCH")
    runtime = bound_runtime
    target = runtime / "install-manifest.json"
    try:
        if target.is_symlink() or not target.is_file() or target.stat().st_size > _MAX_MANIFEST_BYTES:
            raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
        value = json.loads(target.read_text(encoding="utf-8"))
    except BindingError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    manifest_version = value.get("schema_version") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or manifest_version not in {6, 7, 8}
        or value.get("status") != "INSTALLED"
        or value.get("root_ownership") != _OWNERSHIP
    ):
        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
    if manifest_version == 8:
        _canonicalize_transitional_v8_providers(value)
    engine = _directory(value.get("engine_root"), "ACTIVE_MANIFEST_ROOTS_INVALID")
    knowledge = _directory(value.get("knowledge_root"), "ACTIVE_MANIFEST_ROOTS_INVALID")
    manifest_runtime = _directory(value.get("runtime_root"), "ACTIVE_MANIFEST_ROOTS_INVALID")
    if manifest_runtime != runtime:
        raise BindingError("ACTIVE_MANIFEST_RUNTIME_MISMATCH")
    if any(_inside(left, right) for left, right in ((engine, knowledge), (engine, runtime), (knowledge, runtime))):
        raise BindingError("ACTIVE_MANIFEST_ROOTS_INVALID")
    manifest_team: Path | None = None
    manifest_team_enabled = False
    if manifest_version in {7, 8}:
        if manifest_version == 8:
            organizer = value.get("organizer")
            work_hosts = value.get("work_hosts")
            providers = value.get("providers")
            hosts = value.get("hosts")
            if (
                not isinstance(organizer, dict)
                or set(organizer) != {"status", "provider_id", "host_id", "reason_code"}
                or organizer.get("status") not in {"READY", "SELECTION_REQUIRED"}
                or not isinstance(work_hosts, list)
                or any(not isinstance(item, str) or not item for item in work_hosts)
                or len(set(work_hosts)) != len(work_hosts)
                or not isinstance(providers, list)
                or any(not isinstance(item, str) or not item for item in providers)
                or len(set(providers)) != len(providers)
                or not isinstance(hosts, dict)
                or not set(work_hosts).issubset(set(hosts))
            ):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            provider_id = organizer.get("provider_id")
            host_id = organizer.get("host_id")
            reason_code = organizer.get("reason_code")
            if provider_id is not None and (not isinstance(provider_id, str) or not _SAFE_ID.fullmatch(provider_id)):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            if host_id is not None and (not isinstance(host_id, str) or not _SAFE_ID.fullmatch(host_id)):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            if reason_code is not None and (not isinstance(reason_code, str) or not reason_code):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            if organizer.get("status") == "READY":
                if provider_id not in providers:
                    raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
                if provider_id == "subscription-cli":
                    if host_id is None or host_id not in hosts:
                        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
                    allowed_difference = {host_id}
                else:
                    if host_id is not None:
                        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
                    allowed_difference = set()
            else:
                if provider_id is not None or host_id is not None or not isinstance(reason_code, str) or not reason_code:
                    raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
                allowed_difference = set()
            if set(hosts) - set(work_hosts) - allowed_difference:
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            reconciliation = value.get("reconciliation")
            if not isinstance(reconciliation, dict) or set(reconciliation) != {"desired_state_digest"} or not isinstance(reconciliation.get("desired_state_digest"), str) or not _SHA256.fullmatch(reconciliation["desired_state_digest"]):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
        stores = value.get("knowledge_stores")
        if not isinstance(stores, dict) or set(stores) != {"personal", "team"}:
            raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
        personal_store = stores.get("personal")
        if not isinstance(personal_store, dict) or set(personal_store) != _PERSONAL_STORE_KEYS or personal_store.get("enabled") is not True:
            raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
        personal_root = personal_store.get("root")
        if not isinstance(personal_root, str) or not _same_lexical(personal_root, value.get("knowledge_root", "")):
            raise BindingError("ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH")
        repository = value.get("knowledge_repository")
        expected_repository = {key: personal_store.get(key) for key in personal_store if key != "enabled"}
        if not isinstance(repository, dict) or set(repository) != _PERSONAL_REPOSITORY_KEYS or repository != expected_repository:
            raise BindingError("ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH")
        team_descriptor = stores.get("team")
        if team_descriptor is not None:
            if not isinstance(team_descriptor, dict):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            required_team = {
                "enabled",
                "root",
                "store_id",
                "layout",
                "team_member_id",
                "writer_id",
                "transport",
                "transport_managed",
                "status",
            }
            if set(team_descriptor) != required_team or not isinstance(team_descriptor.get("enabled"), bool):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            manifest_team_enabled = team_descriptor.get("enabled") is True
            if (
                not isinstance(team_descriptor.get("root"), str)
                or not Path(team_descriptor["root"]).expanduser().is_absolute()
                or not isinstance(team_descriptor.get("store_id"), str)
                or not _TEAM_STORE_ID.fullmatch(team_descriptor["store_id"])
                or not isinstance(team_descriptor.get("team_member_id"), str)
                or not _TEAM_MEMBER_ID.fullmatch(team_descriptor["team_member_id"])
                or not isinstance(team_descriptor.get("writer_id"), str)
                or not _TEAM_WRITER_ID.fullmatch(team_descriptor["writer_id"])
                or team_descriptor.get("layout") != "member-writer-events-v1"
                or team_descriptor.get("transport") != "external-shared-folder"
                or team_descriptor.get("transport_managed") is not False
                or team_descriptor.get("status") != ("READY" if manifest_team_enabled else "DISABLED")
            ):
                raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
            if manifest_team_enabled:
                if bound_team_raw is None:
                    raise BindingError("SKILL_BINDING_TEAM_ROOT_MISMATCH")
                bound_team = _directory(bound_team_raw, "SKILL_BINDING_INVALID")
                manifest_team = _directory(team_descriptor["root"], "ACTIVE_MANIFEST_ROOTS_INVALID")
                if bound_team is None or manifest_team != bound_team:
                    raise BindingError("SKILL_BINDING_TEAM_ROOT_MISMATCH")
            elif bound_team_raw is not None:
                raise BindingError("SKILL_BINDING_TEAM_ROOT_MISMATCH")
        elif bound_team_raw is not None:
            raise BindingError("SKILL_BINDING_TEAM_ROOT_MISMATCH")
    elif bound_team_raw is not None:
        raise BindingError("SKILL_BINDING_TEAM_ROOT_MISMATCH")
    if bound_team is not None and any(_inside(left, right) for left, right in ((engine, bound_team), (knowledge, bound_team), (runtime, bound_team))):
        raise BindingError("ACTIVE_MANIFEST_ROOTS_INVALID")
    repo_value = _directory(value.get("repo_root"), "ACTIVE_INSTALL_MANIFEST_INVALID")
    if repo_value != engine:
        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
    repository = value.get("knowledge_repository")
    if not isinstance(repository, dict) or repository.get("status") != "READY":
        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
    nested_knowledge = _directory(repository.get("root"), "ACTIVE_INSTALL_MANIFEST_INVALID")
    if nested_knowledge != knowledge:
        raise BindingError("ACTIVE_INSTALL_MANIFEST_INVALID")
    if not (engine / "src" / "ei" / "cli.py").is_file() or not (engine / "config" / "defaults.json").is_file():
        raise BindingError("ACTIVE_MANIFEST_ENGINE_INVALID")
    python_exe = _file(value.get("python_exe"), "ACTIVE_MANIFEST_PYTHON_INVALID")
    if (engine, knowledge, runtime, python_exe) != (bound_engine, bound_knowledge, bound_runtime, bound_python):
        raise BindingError("SKILL_BINDING_MANIFEST_MISMATCH")
    host_id = binding.get("host_id")
    installed_hash = binding.get("installed_skill_hash")
    hosts = value.get("hosts")
    record = hosts.get(host_id) if isinstance(hosts, dict) and isinstance(host_id, str) else None
    binding_hash = "sha256:" + hashlib.sha256(binding_raw).hexdigest()
    if not isinstance(record, dict) or not isinstance(installed_hash, str):
        raise BindingError("SKILL_BINDING_INTEGRITY_INVALID")
    if record.get("installed_skill_hash") != installed_hash:
        raise BindingError("SKILL_BINDING_SKILL_HASH_MISMATCH")
    if record.get("skill_binding_hash") != binding_hash:
        raise BindingError("SKILL_BINDING_HASH_MISMATCH")
    if not isinstance(record.get("skill_binding_path"), str) or not _same_lexical(str(record["skill_binding_path"]), binding_path):
        raise BindingError("SKILL_BINDING_PATH_MISMATCH")
    if not isinstance(record.get("skill_destination"), str) or not _same_lexical(str(record["skill_destination"]), skill_destination):
        raise BindingError("SKILL_BINDING_DESTINATION_MISMATCH")
    if _tree_hash(skill_destination) != installed_hash:
        raise BindingError("SKILL_BINDING_TREE_HASH_MISMATCH")
    return RuntimeBinding(engine, knowledge, runtime, python_exe, bound_team)


def isolated_environment(binding: RuntimeBinding) -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.upper().startswith("PYTHON") or key in {
            "EI_ENGINE_ROOT",
            "EI_PERSONAL_KNOWLEDGE_ROOT",
            "EI_KNOWLEDGE_ROOT",
            "EI_TEAM_KNOWLEDGE_ROOT",
            "EI_REPO_ROOT",
            "EI_RUNTIME_ROOT",
            "__PYVENV_LAUNCHER__",
        }:
            environment.pop(key, None)
    environment.update(
        {
            "EI_ENGINE_ROOT": str(binding.engine_root),
            "EI_PERSONAL_KNOWLEDGE_ROOT": str(binding.personal_knowledge_root),
            "EI_KNOWLEDGE_ROOT": str(binding.personal_knowledge_root),
            "EI_RUNTIME_ROOT": str(binding.runtime_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUTF8": "1",
        }
    )
    if binding.team_knowledge_root is not None:
        environment["EI_TEAM_KNOWLEDGE_ROOT"] = str(binding.team_knowledge_root)
    return environment


def _python_prefix(binding: RuntimeBinding) -> list[str]:
    return [str(binding.python_exe), "-I", "-B", "-X", "utf8"]


def run_cli(
    binding: RuntimeBinding,
    arguments: Sequence[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    command = [
        *_python_prefix(binding),
        "-c",
        _CLI_BOOTSTRAP,
        str(binding.engine_root / "src"),
        *[str(item) for item in arguments],
    ]
    return subprocess.run(
        command,
        cwd=str(binding.engine_root),
        env=isolated_environment(binding),
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def is_isolated_python(binding: RuntimeBinding) -> bool:
    if sys.flags.isolated != 1 or not sys.dont_write_bytecode:
        return False
    try:
        current = Path(sys.executable).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return current == binding.python_exe


def is_trusted_child(binding: RuntimeBinding) -> bool:
    return os.environ.get("EI_SKILL_TRUSTED_CHILD") == "1" and is_isolated_python(binding)


def require_trusted_child(binding: RuntimeBinding) -> None:
    if not is_trusted_child(binding):
        raise BindingError("SKILL_LAUNCHER_REQUIRED")


def activate_engine(binding: RuntimeBinding) -> None:
    if not is_trusted_child(binding):
        raise BindingError("TRUSTED_SKILL_CHILD_REQUIRED")
    source = str(binding.engine_root / "src")
    if source not in sys.path:
        sys.path.insert(0, source)


def root_arguments(binding: RuntimeBinding) -> list[str]:
    return [
        "--engine-root",
        str(binding.engine_root),
        "--knowledge-root",
        str(binding.personal_knowledge_root),
        "--runtime-root",
        str(binding.runtime_root),
    ]


__all__ = [
    "BindingError",
    "RuntimeBinding",
    "activate_engine",
    "add_binding_arguments",
    "is_trusted_child",
    "invocation_script_path",
    "is_isolated_python",
    "isolated_environment",
    "load_binding",
    "root_arguments",
    "require_trusted_child",
    "run_cli",
]
