from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .install_manifest import normalize_install_manifest, validate_install_manifest
from .host_profiles import (
    PUBLIC_ADAPTER_FAMILIES,
    HostProfile,
    canonical_host_id,
    host_profile_hash,
    is_custom_host_id,
    load_host_profile,
    read_host_profile_document,
)
from .safe_fs import SafeFilesystemError, absolute_path, assert_no_reparse_components, assert_safe_target, canonical_path
from .setup_contract import OrganizerSelection, organizer_from_mapping, resolve_organizer


# The public release supports CLI agents only.  ``codex-app`` remains a
# recognised legacy identifier so an older private installation can be read
# and migrated, but it is deliberately absent from the public host manifest.
PUBLIC_CLI_HOST_IDS = (
    "codex-cli",
    "claude-code",
    "gemini-cli",
    "qwen-code",
)
LEGACY_UNSUPPORTED_HOST_IDS = ("codex-app",)

_HOST_HOME_ENV = {
    "codex-cli": "CODEX_HOME",
    "codex-app": "CODEX_HOME",
    "claude-code": "CLAUDE_CONFIG_DIR",
    "gemini-cli": "GEMINI_HOME",
    "qwen-code": "QWEN_HOME",
}

_HOST_FIELDS = frozenset(
    {
        "host_id",
        "display_name",
        "host_family",
        "adapter_id",
        "executable_names",
        "hook_config_path",
        "global_context_path",
        "skill_roots",
        "event_mapping",
        "hook_feature_key",
        "hook_feature_default",
        "skill_activation_mode",
        "capture_primary_path",
        "capture_order",
        "minimum_supported_version",
    }
)
_CAPTURE_PRIMARY_PATHS = frozenset({"HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"})
_SKILL_ACTIVATION_MODES = frozenset({"AUTO_ALLOWED", "CONSENT_REQUIRED", "MANUAL_ONLY", "UNAVAILABLE"})
_DEFAULT_PROVIDER_ORDER = [
    "local-openai-compatible",
    "ollama",
    "subscription-cli",
    "cloud-api",
]


def _resolve_path(value: Path | str) -> Path:
    return Path(value).expanduser().resolve()


@dataclass(frozen=True)
class KnowledgeStorePaths:
    scope: Literal["personal", "team"]
    root: Path
    event_dir: Path
    knowledge_dir: Path | None


@dataclass(frozen=True)
class KnowledgeStores:
    personal: KnowledgeStorePaths
    team: KnowledgeStorePaths | None


@dataclass(frozen=True, init=False)
class RuntimePaths:
    """Canonical engine, private knowledge, and machine-local runtime paths."""

    engine_root: Path
    personal_knowledge_root: Path
    team_knowledge_root: Path | None
    runtime_root: Path
    queue_dir: Path
    spool_dir: Path
    emergency_spool_dir: Path
    cursor_dir: Path
    lock_dir: Path
    cache_dir: Path
    log_dir: Path
    backup_dir: Path
    install_manifest_path: Path

    def __init__(
        self,
        engine_root: Path | str | None = None,
        knowledge_root: Path | str | None = None,
        runtime_root: Path | str | None = None,
        *args: object,
        personal_knowledge_root: Path | str | None = None,
        team_knowledge_root: Path | str | None = None,
        **kwargs: object,
    ) -> None:
        canonical_names = (
            "runtime_root",
            "queue_dir",
            "spool_dir",
            "emergency_spool_dir",
            "cursor_dir",
            "lock_dir",
            "cache_dir",
            "log_dir",
            "backup_dir",
            "install_manifest_path",
        )
        legacy_names = (
            "codex_home",
            "runtime_dir",
            "event_dir",
            "knowledge_dir",
            "local_state_dir",
            "metrics_dir",
            "cache_dir",
            "locks_dir",
            "config_path",
            "hooks_path",
            "agents_path",
        )
        values: dict[str, object] = {}
        legacy_repo = kwargs.pop("repo_root", None)
        legacy_layout = legacy_repo is not None or bool(args)
        if legacy_repo is not None:
            if engine_root is not None:
                raise TypeError("RuntimePaths received duplicate engine_root/repo_root")
            engine_root = legacy_repo  # type: ignore[assignment]
        if args:
            positional_legacy = (knowledge_root, runtime_root, *args)
            if len(positional_legacy) != len(legacy_names):
                raise TypeError("RuntimePaths received an invalid legacy positional layout")
            values.update(dict(zip(legacy_names, positional_legacy)))
            knowledge_root = None
            runtime_root = None
        allowed = set(canonical_names) | set(legacy_names) | {"repo_root"}
        unknown = set(kwargs) - allowed | (set(values) & set(kwargs))
        if unknown:
            name = sorted(unknown)[0]
            raise TypeError(f"RuntimePaths got an unexpected or duplicate keyword argument {name!r}")
        values.update(kwargs)

        if engine_root is None:
            raise ValueError("ENGINE_ROOT_REQUIRED")
        engine = _resolve_path(engine_root)
        if knowledge_root is None and personal_knowledge_root is None and not legacy_layout:
            raise ValueError("KNOWLEDGE_ROOT_REQUIRED")
        if personal_knowledge_root is not None:
            personal = _resolve_path(personal_knowledge_root)
            if knowledge_root is not None and _resolve_path(knowledge_root) != personal:
                raise ValueError("PERSONAL_KNOWLEDGE_ROOT_CONFLICT")
        else:
            personal = _resolve_path(knowledge_root if knowledge_root is not None else engine)
        team = _resolve_path(team_knowledge_root) if team_knowledge_root is not None else None
        legacy_home = values.get("codex_home")
        codex_home = _resolve_path(legacy_home) if legacy_home is not None else None
        configured_runtime = runtime_root if runtime_root is not None else values.get("runtime_root", values.get("runtime_dir"))
        if configured_runtime is None:
            configured_runtime = os.environ.get("EI_RUNTIME_ROOT")
        if configured_runtime is None:
            if codex_home is None:
                codex_home = discover_home("codex-cli")
            configured_runtime = codex_home / "external-intelligence"
        runtime = _resolve_path(configured_runtime)

        derived = {
            "engine_root": engine,
            "personal_knowledge_root": personal,
            "team_knowledge_root": team,
            "runtime_root": runtime,
            "queue_dir": _resolve_path(values.get("queue_dir", runtime / "queue")),
            "spool_dir": _resolve_path(values.get("spool_dir", runtime / "spool")),
            "emergency_spool_dir": _resolve_path(values.get("emergency_spool_dir", runtime / "emergency-spool")),
            "cursor_dir": _resolve_path(values.get("cursor_dir", runtime / "cursor")),
            "lock_dir": _resolve_path(values.get("lock_dir", values.get("locks_dir", runtime / "locks"))),
            "cache_dir": _resolve_path(values.get("cache_dir", runtime / "cache")),
            "log_dir": _resolve_path(values.get("log_dir", runtime / "logs")),
            "backup_dir": _resolve_path(values.get("backup_dir", runtime / "backups")),
            "install_manifest_path": _resolve_path(values.get("install_manifest_path", runtime / "install-manifest.json")),
        }
        for name, value in derived.items():
            object.__setattr__(self, name, value)

        if codex_home is None:
            codex_home = runtime.parent
        object.__setattr__(self, "_codex_home", codex_home)
        object.__setattr__(self, "_event_dir", _resolve_path(values.get("event_dir", personal / "events")))
        object.__setattr__(self, "_knowledge_dir", _resolve_path(values.get("knowledge_dir", personal / "knowledge")))
        object.__setattr__(self, "_local_state_dir", _resolve_path(values.get("local_state_dir", runtime / "state")))
        object.__setattr__(self, "_metrics_dir", _resolve_path(values.get("metrics_dir", runtime / "metrics")))
        object.__setattr__(self, "_config_path", _resolve_path(values.get("config_path", codex_home / "config.toml")))
        object.__setattr__(self, "_hooks_path", _resolve_path(values.get("hooks_path", codex_home / "hooks.json")))
        object.__setattr__(self, "_agents_path", _resolve_path(values.get("agents_path", codex_home / "AGENTS.md")))
        object.__setattr__(self, "_legacy_layout", legacy_layout)

    @property
    def repo_root(self) -> Path:
        """Read-only compatibility view; new writes must use explicit roots."""
        return self.engine_root

    @property
    def knowledge_root(self) -> Path:
        """Read-only compatibility view of the personal knowledge root."""
        return self.personal_knowledge_root

    @property
    def legacy_layout(self) -> bool:
        return bool(self._legacy_layout)

    @property
    def codex_home(self) -> Path:
        return self._codex_home

    @property
    def runtime_dir(self) -> Path:
        return self.runtime_root

    @property
    def event_dir(self) -> Path:
        return self._event_dir

    @property
    def knowledge_dir(self) -> Path:
        return self._knowledge_dir

    @property
    def local_state_dir(self) -> Path:
        return self._local_state_dir

    @property
    def metrics_dir(self) -> Path:
        return self._metrics_dir

    @property
    def locks_dir(self) -> Path:
        return self.lock_dir

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def hooks_path(self) -> Path:
        return self._hooks_path

    @property
    def agents_path(self) -> Path:
        return self._agents_path

    def assert_write_allowed(self, target: Path | str) -> None:
        candidate = _resolve_path(target)
        if candidate == self.engine_root or candidate.is_relative_to(self.engine_root):
            raise RootInvariantError("ENGINE_ROOT_WRITE_FORBIDDEN")
        allowed_roots = (self.personal_knowledge_root, self.runtime_root)
        if self.team_knowledge_root is not None:
            allowed_roots += (self.team_knowledge_root,)
        allowed = any(candidate == root or candidate.is_relative_to(root) for root in allowed_roots)
        if not allowed:
            raise RootInvariantError("WRITE_ROOT_UNAUTHORIZED")


class RootInvariantError(ValueError):
    """Raised when canonical root roles are missing, overlapping, or unsafe."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_runtime_roots(paths: RuntimePaths) -> None:
    if paths.legacy_layout:
        raise RootInvariantError("ROOTS_MUST_BE_DISTINCT")
    roots = (paths.engine_root, paths.personal_knowledge_root, paths.runtime_root)
    if paths.team_knowledge_root is not None:
        roots += (paths.team_knowledge_root,)
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root == other:
                raise RootInvariantError("ROOTS_MUST_BE_DISTINCT")
            if root.is_relative_to(other) or other.is_relative_to(root):
                raise RootInvariantError("ROOTS_MUST_NOT_OVERLAP")


@dataclass(frozen=True)
class HostSpec:
    host_id: str
    display_name: str
    executable_names: Sequence[str]
    hook_config_path: Path
    global_context_path: Path
    skill_roots: Sequence[Path]
    event_mapping: Mapping[str, str]
    hook_feature_key: str | None
    hook_feature_default: bool
    skill_activation_mode: str
    capture_primary_path: str
    capture_order: Sequence[str]
    minimum_supported_version: str | None
    host_family: str = ""
    adapter_id: str = ""
    profile_hash: str | None = None


@dataclass(frozen=True, init=False)
class Settings:
    paths: RuntimePaths
    knowledge_stores: KnowledgeStores
    hosts: Mapping[str, HostSpec]
    organizer: OrganizerSelection
    provider_order: Sequence[str]
    privacy_policy_path: Path
    capture_policy_path: Path
    promotion_policy_path: Path
    retrieval_policy_path: Path
    budget_policy_path: Path
    experiment_policy_path: Path
    curation_max_attempts: int
    curation_retry_delay_seconds: int
    schema_version: str
    machine_id_hash: str

    def __init__(
        self,
        paths: RuntimePaths,
        knowledge_stores: KnowledgeStores | None = None,
        hosts: Mapping[str, HostSpec] | None = None,
        organizer: OrganizerSelection | None = None,
        provider_order: Sequence[str] | None = None,
        privacy_policy_path: Path | None = None,
        capture_policy_path: Path | None = None,
        promotion_policy_path: Path | None = None,
        retrieval_policy_path: Path | None = None,
        budget_policy_path: Path | None = None,
        experiment_policy_path: Path | None = None,
        schema_version: str | int = "1",
        machine_id_hash: str | None = None,
        **legacy: Any,
    ) -> None:
        known_legacy = {
            "retrieval_max_chars",
            "retrieval_max_results",
            "retrieval_min_score",
            "session_start_budget_ms",
            "prompt_budget_ms",
            "stop_budget_ms",
            "session_end_budget_ms",
            "sync_enabled",
            "sync_remote",
            "sync_branch",
            "sync_remote_fingerprint",
            "sync_remote_classification",
            "capture_max_per_session",
            "capture_max_payload_bytes",
            "scheduler_task_name",
            "scheduler_interval_minutes",
            "scheduler_timeout_seconds",
            "scheduler_log_max_bytes",
            "scheduler_log_retention_files",
            "experiment_enabled",
            "experiment_id",
            "cloud_spend_cap",
            "prompt_max_chars",
            "always_on_hard_cap_chars",
            "privacy_profile",
            "curation_max_attempts",
            "curation_retry_delay_seconds",
        }
        unknown = set(legacy) - known_legacy
        if unknown:
            raise TypeError(f"Settings got an unexpected keyword argument {sorted(unknown)[0]!r}")

        # ``dataclasses.replace`` supplies every init field, including the
        # derived store view from the original instance.  Rebuild that view
        # from the supplied paths so replacing ``paths`` cannot retain stale
        # personal/team roots.
        del knowledge_stores

        repo = paths.engine_root
        policy_root = repo / "policies"
        object.__setattr__(self, "paths", paths)
        personal_store = KnowledgeStorePaths(
            scope="personal",
            root=paths.personal_knowledge_root,
            event_dir=paths.event_dir,
            knowledge_dir=paths.knowledge_dir,
        )
        team_store = None
        if paths.team_knowledge_root is not None:
            team_store = KnowledgeStorePaths(
                scope="team",
                root=paths.team_knowledge_root,
                event_dir=paths.team_knowledge_root / "events",
                knowledge_dir=None,
            )
        object.__setattr__(self, "knowledge_stores", KnowledgeStores(personal=personal_store, team=team_store))
        object.__setattr__(self, "hosts", dict(hosts or {}))
        object.__setattr__(self, "organizer", organizer or OrganizerSelection("SELECTION_REQUIRED", None, None, "ORGANIZER_SELECTION_REQUIRED"))
        object.__setattr__(self, "provider_order", tuple(provider_order or ()))
        object.__setattr__(self, "privacy_policy_path", _resolve_path(privacy_policy_path or policy_root / "privacy-policy.json"))
        object.__setattr__(self, "capture_policy_path", _resolve_path(capture_policy_path or policy_root / "capture-policy.json"))
        object.__setattr__(self, "promotion_policy_path", _resolve_path(promotion_policy_path or policy_root / "promotion-policy.json"))
        object.__setattr__(self, "retrieval_policy_path", _resolve_path(retrieval_policy_path or policy_root / "retrieval-policy.json"))
        object.__setattr__(self, "budget_policy_path", _resolve_path(budget_policy_path or policy_root / "budget-policy.json"))
        object.__setattr__(self, "experiment_policy_path", _resolve_path(experiment_policy_path or policy_root / "experiment-policy.json"))
        object.__setattr__(self, "schema_version", str(schema_version))
        object.__setattr__(self, "machine_id_hash", machine_id_hash or _machine_id_hash())

        defaults = {
            "retrieval_max_chars": 5000,
            "retrieval_max_results": 5,
            "retrieval_min_score": 0.35,
            "session_start_budget_ms": 2000,
            "prompt_budget_ms": 1000,
            "stop_budget_ms": 300,
            "session_end_budget_ms": 3000,
            "sync_enabled": False,
            "sync_remote": "origin",
            "sync_branch": "main",
            "sync_remote_fingerprint": None,
            "sync_remote_classification": None,
            "capture_max_per_session": 3,
            "capture_max_payload_bytes": 32768,
            "scheduler_task_name": "CodexExternalIntelligenceMaintenance-v1",
            "scheduler_interval_minutes": 30,
            "scheduler_timeout_seconds": 600,
            "scheduler_log_max_bytes": 1048576,
            "scheduler_log_retention_files": 5,
            "experiment_enabled": False,
            "experiment_id": "retrieval-v1",
            "cloud_spend_cap": 0,
            "prompt_max_chars": 5000,
            "always_on_hard_cap_chars": 12000,
            "privacy_profile": "private-reusable",
            "curation_max_attempts": 3,
            "curation_retry_delay_seconds": 300,
        }
        defaults.update(legacy)
        for name, value in defaults.items():
            object.__setattr__(self, f"_{name}", value)

    @property
    def repo_config_path(self) -> Path:
        return self.paths.engine_root / "config"

    @property
    def policy_path(self) -> Path:
        return self.paths.engine_root / "policies"

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        private_name = f"_{name}"
        try:
            return object.__getattribute__(self, private_name)
        except AttributeError as exc:
            raise AttributeError(name) from exc


def _machine_id_hash() -> str:
    source = "|".join((platform.system(), platform.node(), socket.gethostname())).encode("utf-8", "replace")
    return "sha256:" + hashlib.sha256(source).hexdigest()


def discover_home(host_id: str = "codex-cli", explicit_home: Path | str | None = None) -> Path:
    if explicit_home is not None:
        return _resolve_path(explicit_home)
    env_name = _HOST_HOME_ENV.get(host_id)
    if env_name is None:
        raise ValueError("HOST_UNSUPPORTED")
    configured = os.environ.get(env_name)
    if configured:
        return _resolve_path(configured)
    raise ValueError("HOST_HOME_REQUIRED")


def discover_codex_home() -> Path:
    return discover_home("codex-cli")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"CONFIG_READ_FAILED: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"CONFIG_OBJECT_REQUIRED: {path.name}")
    return value


def _manifest_path(home: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("HOST_MANIFEST_INVALID")
    candidate = Path(value).expanduser()
    return candidate.resolve() if candidate.is_absolute() else (home / candidate).resolve()


def _validate_string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("HOST_MANIFEST_INVALID")
    return tuple(value)


def _canonical_host_homes(value: Mapping[str, Path | str] | None) -> dict[str, Path | str]:
    result: dict[str, Path | str] = {}
    for raw_id, home in dict(value or {}).items():
        try:
            host_id = canonical_host_id(raw_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("HOST_HOME_FORMAT_INVALID") from exc
        if host_id in result:
            raise ValueError("HOST_HOME_COLLISION")
        result[host_id] = home
    return result


def _load_hosts(
    repo: Path,
    host_homes: Mapping[str, Path | str] | None,
    runtime_root: Path | None = None,
    manifest_hosts: Mapping[str, Any] | None = None,
    profile_sources: Mapping[str, tuple[HostProfile, str]] | None = None,
) -> dict[str, HostSpec]:
    path = repo / "config" / "hosts.json"
    if not path.exists():
        return {}
    try:
        manifest = _read_json(path)
        if set(manifest) - {"schema_version", "hosts"} or "hosts" not in manifest:
            raise ValueError("HOST_MANIFEST_INVALID")
        entries = manifest["hosts"]
        if not isinstance(entries, dict):
            raise ValueError("HOST_MANIFEST_INVALID")
        result: dict[str, HostSpec] = {}
        explicit_homes = _canonical_host_homes(host_homes)
        expected_profiles = dict(manifest_hosts or {})
        source_profiles = dict(profile_sources or {})
        for host_id, raw in entries.items():
            if not isinstance(host_id, str) or not isinstance(raw, dict):
                raise ValueError("HOST_MANIFEST_INVALID")
            if host_id not in PUBLIC_CLI_HOST_IDS and host_id not in LEGACY_UNSUPPORTED_HOST_IDS:
                raise ValueError("HOST_MANIFEST_INVALID")
            if set(raw) != _HOST_FIELDS or raw.get("host_id") != host_id:
                raise ValueError("HOST_MANIFEST_INVALID")
            if raw.get("adapter_id") != host_id or raw.get("host_family") != PUBLIC_ADAPTER_FAMILIES.get(host_id):
                raise ValueError("HOST_MANIFEST_INVALID")
            executable_names = _validate_string_sequence(raw["executable_names"])
            skill_roots_raw = _validate_string_sequence(raw["skill_roots"])
            event_mapping = raw["event_mapping"]
            if not isinstance(event_mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in event_mapping.items()):
                raise ValueError("HOST_MANIFEST_INVALID")
            hook_feature_key = raw["hook_feature_key"]
            if hook_feature_key is not None and (not isinstance(hook_feature_key, str) or not hook_feature_key):
                raise ValueError("HOST_MANIFEST_INVALID")
            activation = raw["skill_activation_mode"]
            primary = raw["capture_primary_path"]
            capture_order = _validate_string_sequence(raw["capture_order"])
            if activation not in _SKILL_ACTIVATION_MODES or primary not in _CAPTURE_PRIMARY_PATHS or any(item not in _CAPTURE_PRIMARY_PATHS for item in capture_order) or primary not in capture_order:
                raise ValueError("HOST_MANIFEST_INVALID")
            if not isinstance(raw["display_name"], str) or not raw["display_name"] or not isinstance(raw["hook_feature_default"], bool):
                raise ValueError("HOST_MANIFEST_INVALID")
            minimum = raw["minimum_supported_version"]
            if minimum is not None and (not isinstance(minimum, str) or not minimum):
                raise ValueError("HOST_MANIFEST_INVALID")
            try:
                home = discover_home(host_id, explicit_homes.get(host_id))
            except ValueError as exc:
                if str(exc) == "HOST_UNSUPPORTED":
                    raise ValueError("HOST_MANIFEST_INVALID") from exc
                if str(exc) == "HOST_HOME_REQUIRED" and explicit_homes:
                    suffix = {"codex-cli": ".codex", "codex-app": ".codex", "claude-code": ".claude", "gemini-cli": ".gemini", "qwen-code": ".qwen"}.get(host_id)
                    if suffix is None:
                        raise ValueError("HOST_MANIFEST_INVALID") from exc
                    home = (Path.home() / suffix).resolve()
                else:
                    raise
            result[host_id] = HostSpec(
                host_id=host_id,
                display_name=raw["display_name"],
                executable_names=executable_names,
                hook_config_path=_manifest_path(home, raw["hook_config_path"]),
                global_context_path=_manifest_path(home, raw["global_context_path"]),
                skill_roots=tuple(_manifest_path(home, item) for item in skill_roots_raw),
                event_mapping=dict(event_mapping),
                hook_feature_key=hook_feature_key,
                hook_feature_default=raw["hook_feature_default"],
                skill_activation_mode=activation,
                capture_primary_path=primary,
                capture_order=capture_order,
                minimum_supported_version=minimum,
                host_family=raw["host_family"],
                adapter_id=raw["adapter_id"],
                profile_hash=host_profile_hash(raw),
            )
        def add_profile(profile: HostProfile, profile_digest: str) -> None:
            if not is_custom_host_id(profile.host_id) or profile.host_id in result:
                raise ValueError("HOST_PROFILE_INVALID")
            if profile.adapter_id == "gemini-cli":
                profile_event_mapping = {"SessionStart": "session.start", "BeforeAgent": "prompt.before", "AfterAgent": "turn.stop", "SessionEnd": "session.end"}
                profile_activation = "CONSENT_REQUIRED"
            else:
                profile_event_mapping = {"SessionStart": "session.start", "UserPromptSubmit": "prompt.before", "Stop": "turn.stop", "SessionEnd": "session.end"}
                profile_activation = "AUTO_ALLOWED"
            result[profile.host_id] = HostSpec(
                host_id=profile.host_id,
                display_name=profile.display_name,
                executable_names=profile.executable_names,
                hook_config_path=profile.hook_config_path,
                global_context_path=profile.global_context_path,
                skill_roots=profile.skill_roots,
                event_mapping=profile_event_mapping,
                hook_feature_key=None,
                hook_feature_default=False,
                skill_activation_mode=profile_activation,
                capture_primary_path="HOOK_DIRECT",
                capture_order=("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
                minimum_supported_version=None,
                host_family=profile.host_family,
                adapter_id=profile.adapter_id,
                profile_hash=profile_digest,
            )

        # Selection-time profiles are validated and bound in memory.  They
        # become active HostSpecs before the runtime copy is committed.
        for profile_id, source in source_profiles.items():
            if not isinstance(profile_id, str) or not isinstance(source, tuple) or len(source) != 2:
                raise ValueError("HOST_PROFILE_INVALID")
            profile, profile_digest = source
            if profile_id != profile.host_id or not isinstance(profile_digest, str):
                raise ValueError("HOST_PROFILE_INVALID")
            add_profile(profile, profile_digest)

        if runtime_root is not None:
            try:
                runtime_path = assert_no_reparse_components(Path(runtime_root).expanduser())
                if runtime_path.exists():
                    assert_safe_target(runtime_path.parent, runtime_path, allow_root=True, allow_missing=False, expected_type="dir")
                profile_dir = runtime_path / "host-profiles"
                assert_no_reparse_components(profile_dir)
                if profile_dir.exists():
                    assert_safe_target(runtime_path, profile_dir, allow_root=False, allow_missing=False, expected_type="dir")
            except SafeFilesystemError as exc:
                raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
            if profile_dir.is_dir():
                for profile_path in sorted(profile_dir.glob("*.json")):
                    try:
                        assert_safe_target(profile_dir, profile_path, allow_missing=False, expected_type="file")
                    except SafeFilesystemError as exc:
                        raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
                    try:
                        raw_profile = read_host_profile_document(profile_path)
                    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                        raise ValueError("HOST_PROFILE_READ_FAILED") from exc
                    if not isinstance(raw_profile, dict):
                        raise ValueError("HOST_PROFILE_INVALID")
                    profile_id = raw_profile.get("host_id")
                    if not isinstance(profile_id, str) or profile_path.stem != profile_id:
                        raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
                    expected_record = expected_profiles.get(profile_id)
                    if expected_record is not None and (
                        not isinstance(expected_record, Mapping)
                        or expected_record.get("profile_path") != f"host-profiles/{profile_id}.json"
                    ):
                        raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
                    if profile_id in result:
                        # A selection-time source is the pending replacement;
                        # still validate the runtime locator above so a wrong
                        # filename cannot be hidden by the override.
                        continue
                    if not is_custom_host_id(profile_id):
                        raise ValueError("HOST_PROFILE_INVALID")
                    configured_home = explicit_homes.get(profile_id)
                    if configured_home is None:
                        # A registered profile is available to setup/status,
                        # but it cannot become an active HostSpec until its
                        # machine-local home is explicitly bound.
                        continue
                    profile = load_host_profile(profile_path, Path(configured_home))
                    profile_digest = host_profile_hash(raw_profile)
                    if expected_record is not None and profile.host_id not in source_profiles:
                        if (
                            expected_record.get("profile_hash") != profile_digest
                        ):
                            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
                    add_profile(profile, profile_digest)
        return result
    except ValueError as exc:
        if str(exc) == "HOST_MANIFEST_INVALID" or str(exc).startswith("HOST_PROFILE_"):
            raise
        raise ValueError("HOST_MANIFEST_INVALID") from exc


def _provider_order(repo: Path, defaults: Mapping[str, Any]) -> tuple[str, ...]:
    configured = defaults.get("providers", {})
    if isinstance(configured, dict):
        order = configured.get("order")
    else:
        order = None
    if order is None:
        order = defaults.get("provider_order")
    provider_path = repo / "config" / "inference-providers.json"
    if order is None and provider_path.exists():
        provider_config = _read_json(provider_path)
        order = provider_config.get("provider_order", provider_config.get("order"))
    if order is None:
        order = _DEFAULT_PROVIDER_ORDER
    if not isinstance(order, list) or any(not isinstance(item, str) or not item for item in order) or len(set(order)) != len(order):
        raise ValueError("PROVIDER_ORDER_INVALID")
    return tuple(order)


def _configured_provider_ids(repo: Path, defaults: Mapping[str, Any]) -> tuple[str, ...]:
    """Return repository provider identifiers for explicit organizer checks."""

    provider_path = repo / "config" / "inference-providers.json"
    if provider_path.exists():
        provider_config = _read_json(provider_path)
        configured = provider_config.get("providers")
        if isinstance(configured, Mapping):
            return tuple(str(item) for item in configured if isinstance(item, str) and item)
    configured = defaults.get("providers")
    if isinstance(configured, Mapping):
        order = configured.get("order")
        if isinstance(order, list):
            return tuple(str(item) for item in order if isinstance(item, str) and item)
    order = defaults.get("provider_order")
    if isinstance(order, list):
        return tuple(str(item) for item in order if isinstance(item, str) and item)
    return _DEFAULT_PROVIDER_ORDER.copy()


_ACTIVE_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "installed_at",
        "uninstalled_at",
        "repo_root",
        "engine_root",
        "knowledge_root",
        "runtime_root",
        "root_ownership",
        "supported_hosts",
        "hosts",
        "organizer",
        "work_hosts",
        "legacy_host_migrations",
        "managed_marker",
        "managed_hook_ids",
        "providers",
        "privacy_profile",
        "sync_enabled",
        "experiment_enabled",
        "scheduler_requested",
        "skill_source",
        "skill_source_hash",
        "hook_schema_hash",
        "skip_venv",
        "venv_created",
        "python_exe",
        "transaction_id",
        "agents_block_version",
        "config_backup",
        "hooks_backup",
        "agents_backup",
        "agents_original_sha256",
        "agents_installed_sha256",
        "knowledge_repository",
        "knowledge_retained",
    }
)
_ACTIVE_MANIFEST_REQUIRED = _ACTIVE_MANIFEST_KEYS - {"uninstalled_at", "knowledge_retained"}
_ACTIVE_KNOWLEDGE_KEYS = frozenset(
    {
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
_MANIFEST_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CUSTOM_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")


def _active_manifest_directory(value: Path | str, reason_code: str) -> Path:
    try:
        raw = assert_no_reparse_components(value)
        resolved = canonical_path(raw, require_exists=True)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError(reason_code) from exc
    if not resolved.is_dir():
        raise ValueError(reason_code)
    return resolved


def load_active_install_manifest(
    runtime_root: Path,
    expected_engine_root: Path | str | None = None,
    *,
    allow_uninstalled: bool = False,
) -> dict[str, Any]:
    if type(allow_uninstalled) is not bool:
        raise ValueError("ACTIVE_MANIFEST_STATUS_POLICY_INVALID")
    if isinstance(runtime_root, bool) or not isinstance(runtime_root, (Path, str)) or not str(runtime_root):
        raise ValueError("ACTIVE_MANIFEST_RUNTIME_INVALID")
    try:
        raw_runtime = assert_no_reparse_components(runtime_root)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_MANIFEST_RUNTIME_INVALID") from exc
    if not raw_runtime.exists() or not raw_runtime.is_dir():
        raise ValueError("ACTIVE_MANIFEST_RUNTIME_INVALID")
    runtime = canonical_path(raw_runtime, require_exists=True)
    target = raw_runtime / "install-manifest.json"
    if not target.exists() and not target.is_symlink():
        raise ValueError("ACTIVE_INSTALL_MANIFEST_MISSING")
    try:
        target = assert_safe_target(raw_runtime, target, allow_missing=False, expected_type="file")
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    try:
        value = validate_install_manifest(
            normalize_install_manifest(value),
            require_live_personal=False,
        )
    except ValueError:
        raise
    if value.get("status") not in ({"INSTALLED", "UNINSTALLED"} if allow_uninstalled else {"INSTALLED"}):
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    root_values: dict[str, Path] = {}
    for key in ("engine_root", "knowledge_root", "runtime_root"):
        raw = value.get(key)
        if not isinstance(raw, str) or not raw:
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
        try:
            root_values[key] = assert_no_reparse_components(raw)
        except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID") from exc
    try:
        manifest_runtime = canonical_path(root_values["runtime_root"])
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID") from exc
    if manifest_runtime != runtime:
        raise ValueError("ACTIVE_MANIFEST_RUNTIME_MISMATCH")
    if expected_engine_root is not None:
        try:
            expected_engine_value = _active_manifest_directory(
                expected_engine_root,
                "ACTIVE_MANIFEST_ENGINE_MISMATCH",
            )
            manifest_engine_value = canonical_path(root_values["engine_root"])
        except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError("ACTIVE_MANIFEST_ENGINE_MISMATCH") from exc
        if manifest_engine_value != expected_engine_value:
            raise ValueError("ACTIVE_MANIFEST_ENGINE_MISMATCH")
    roots = {
        key: _active_manifest_directory(raw, "ACTIVE_MANIFEST_ROOTS_INVALID")
        for key, raw in root_values.items()
    }
    try:
        validate_runtime_roots(RuntimePaths(roots["engine_root"], roots["knowledge_root"], roots["runtime_root"]))
    except (RootInvariantError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID") from exc
    ownership = value.get("root_ownership")
    if ownership != {
        "engine_root": "public-source-read-only",
        "knowledge_root": "private-knowledge-git-or-local",
        "runtime_root": "machine-local-git-forbidden",
    }:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    knowledge = value.get("knowledge_repository")
    if not isinstance(knowledge, dict) or set(knowledge) != _ACTIVE_KNOWLEDGE_KEYS:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    nested_root = knowledge.get("root")
    if not isinstance(nested_root, str) or not nested_root:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    try:
        nested_root_value = assert_no_reparse_components(nested_root)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    nested_knowledge_root = _active_manifest_directory(nested_root_value, "ACTIVE_MANIFEST_ROOTS_INVALID")
    if nested_knowledge_root != roots["knowledge_root"]:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    mode = knowledge.get("mode")
    fingerprint = knowledge.get("remote_fingerprint")
    classification = knowledge.get("remote_classification")
    if (
        knowledge.get("status") != "READY"
        or mode not in {"local", "github-new", "github-existing"}
        or nested_knowledge_root != roots["knowledge_root"]
        or type(knowledge.get("connected")) is not bool
        or type(knowledge.get("initial_push_complete")) is not bool
        or type(knowledge.get("sync_enabled")) is not bool
        or knowledge.get("sync_enabled") != value.get("sync_enabled")
    ):
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    if mode == "local":
        if any(knowledge.get(key) is not None for key in ("remote_name", "remote_fingerprint", "remote_classification", "branch")):
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
        if knowledge.get("connected") or knowledge.get("initial_push_complete") or knowledge.get("sync_enabled"):
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    else:
        if (
            not isinstance(knowledge.get("remote_name"), str)
            or not knowledge["remote_name"]
            or not isinstance(knowledge.get("branch"), str)
            or not knowledge["branch"]
            or not isinstance(fingerprint, str)
            or not _MANIFEST_DIGEST.fullmatch(fingerprint)
            or classification not in {"local_path", "private_verified", "private_attested"}
            or knowledge.get("connected") is not True
            or knowledge.get("initial_push_complete") is not True
        ):
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    providers = value.get("providers")
    hosts = value.get("hosts")
    organizer = value.get("organizer")
    work_hosts = value.get("work_hosts")
    if (
        not isinstance(providers, list)
        or any(not isinstance(item, str) or not item for item in providers)
        or len(set(providers)) != len(providers)
        or value.get("privacy_profile") not in {"public", "private-reusable", "client-confidential", "machine-local"}
        or type(value.get("sync_enabled")) is not bool
        or type(value.get("experiment_enabled")) is not bool
        or type(value.get("scheduler_requested")) is not bool
        or not isinstance(hosts, dict)
        or not isinstance(work_hosts, list)
    ):
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    for host_id, record in hosts.items():
        if (host_id not in PUBLIC_CLI_HOST_IDS and not is_custom_host_id(host_id)) or not isinstance(record, dict):
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
        if not isinstance(record.get("home"), str) or not record["home"]:
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
        _active_manifest_directory(record["home"], "ACTIVE_INSTALL_MANIFEST_INVALID")
    try:
        organizer_selection = organizer_from_mapping(organizer) if isinstance(organizer, Mapping) else None
    except ValueError as exc:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    if organizer_selection is None or organizer_selection.status not in {"READY", "SELECTION_REQUIRED"}:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    if not set(work_hosts).issubset(set(hosts)):
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    return json.loads(json.dumps(value, ensure_ascii=False))


def load_settings(
    repo_root: Path | str | None = None,
    codex_home: Path | str | None = None,
    *,
    engine_root: Path | str | None = None,
    knowledge_root: Path | str | None = None,
    personal_knowledge_root: Path | str | None = None,
    team_knowledge_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
    host_homes: Mapping[str, Path | str] | None = None,
    profile_sources: Mapping[str, tuple[HostProfile, str]] | None = None,
    allow_uninstalled_manifest: bool = False,
) -> Settings:
    if type(allow_uninstalled_manifest) is not bool:
        raise ValueError("ACTIVE_MANIFEST_STATUS_POLICY_INVALID")
    configured_engine = engine_root if engine_root is not None else os.environ.get("EI_ENGINE_ROOT")
    configured_legacy_knowledge = knowledge_root if knowledge_root is not None else os.environ.get("EI_KNOWLEDGE_ROOT")
    if personal_knowledge_root is not None and configured_legacy_knowledge is not None:
        if _resolve_path(personal_knowledge_root) != _resolve_path(configured_legacy_knowledge):
            raise ValueError("PERSONAL_KNOWLEDGE_ROOT_CONFLICT")
    configured_knowledge = personal_knowledge_root if personal_knowledge_root is not None else configured_legacy_knowledge
    user_explicit_roots = configured_engine is not None or configured_knowledge is not None
    if user_explicit_roots and repo_root is not None:
        raise ValueError("ENGINE_ROOT_DUPLICATE")
    if configured_knowledge is not None and configured_engine is None:
        raise ValueError("ENGINE_ROOT_REQUIRED")
    configured_repo = repo_root if repo_root is not None else os.environ.get("EI_REPO_ROOT")
    if configured_engine is not None:
        configured_repo = configured_engine
    configured_runtime = runtime_root if runtime_root is not None else os.environ.get("EI_RUNTIME_ROOT")
    active_manifest: dict[str, Any] | None = None
    runtime_candidate: Path | None = None
    if configured_runtime is not None:
        try:
            runtime_lexical = assert_no_reparse_components(configured_runtime)
            runtime_candidate = canonical_path(runtime_lexical)
        except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError("ACTIVE_MANIFEST_RUNTIME_INVALID") from exc
        if (runtime_lexical / "install-manifest.json").exists():
            active_manifest = load_active_install_manifest(
                runtime_lexical,
                expected_engine_root=configured_repo,
                allow_uninstalled=allow_uninstalled_manifest,
            )
            manifest_engine = _resolve_path(str(active_manifest["engine_root"]))
            manifest_knowledge = _resolve_path(str(active_manifest["knowledge_root"]))
            if configured_knowledge is not None:
                configured_knowledge_root = _active_manifest_directory(
                    configured_knowledge,
                    "ACTIVE_MANIFEST_KNOWLEDGE_MISMATCH",
                )
                if configured_knowledge_root != manifest_knowledge:
                    raise ValueError("ACTIVE_MANIFEST_KNOWLEDGE_MISMATCH")
            configured_repo = manifest_engine
            configured_engine = manifest_engine
            configured_knowledge = manifest_knowledge
    explicit_roots = user_explicit_roots or active_manifest is not None
    repo = _resolve_path(configured_repo if configured_repo is not None else Path.cwd())
    defaults_path = repo / "config" / "defaults.json"
    defaults = _read_json(defaults_path)
    retrieval = defaults.get("retrieval", {})
    hooks = defaults.get("hooks", {})
    sync = defaults.get("sync", {})
    capture = defaults.get("capture", {})
    scheduler = defaults.get("scheduler", {})
    experiment = defaults.get("experiment", {})
    context = defaults.get("context", {})
    providers = defaults.get("providers", {})
    curation = defaults.get("curation", {})
    if not all(isinstance(section, dict) for section in (retrieval, hooks, sync, capture, scheduler, experiment, context, curation)):
        raise ValueError("DEFAULTS_INVALID")
    max_attempts = curation.get("max_attempts", 3)
    retry_delay_seconds = curation.get("retry_delay_seconds", 300)
    if type(max_attempts) is not int or max_attempts < 1 or type(retry_delay_seconds) is not int or retry_delay_seconds < 0:
        raise ValueError("DEFAULTS_INVALID")

    explicit_homes = _canonical_host_homes(host_homes)
    if active_manifest is not None:
        manifest_hosts = active_manifest.get("hosts", {})
        if isinstance(manifest_hosts, Mapping):
            for host_id, record in manifest_hosts.items():
                if isinstance(record, Mapping) and isinstance(record.get("home"), str):
                    explicit_homes.setdefault(str(host_id), str(record["home"]))
    if "codex-cli" in explicit_homes and "codex-app" not in explicit_homes:
        explicit_homes["codex-app"] = explicit_homes["codex-cli"]
    if "codex-app" in explicit_homes and "codex-cli" not in explicit_homes:
        explicit_homes["codex-cli"] = explicit_homes["codex-app"]
    if codex_home is not None:
        codex = _resolve_path(codex_home)
        explicit_homes.setdefault("codex-cli", codex)
        explicit_homes.setdefault("codex-app", codex)
    explicit_codex_home = explicit_homes.get("codex-cli")
    if codex_home is not None:
        home_for_runtime = _resolve_path(codex_home)
    elif explicit_codex_home is not None:
        home_for_runtime = _resolve_path(explicit_codex_home)
    elif configured_runtime is not None:
        # An explicit runtime root is a complete isolated invocation context.
        home_for_runtime = runtime_candidate.parent
    else:
        home_for_runtime = discover_home("codex-cli")
    runtime = runtime_candidate if runtime_candidate is not None else home_for_runtime / "external-intelligence"
    if explicit_roots:
        paths = RuntimePaths(
            engine_root=repo,
            knowledge_root=configured_knowledge,
            personal_knowledge_root=personal_knowledge_root,
            team_knowledge_root=team_knowledge_root,
            runtime_root=runtime,
            codex_home=home_for_runtime,
        )
        validate_runtime_roots(paths)
    else:
        paths = RuntimePaths(
            repo_root=repo,
            runtime_root=runtime,
            personal_knowledge_root=personal_knowledge_root,
            team_knowledge_root=team_knowledge_root,
            codex_home=home_for_runtime,
        )
    manifest_hosts = active_manifest.get("hosts") if isinstance(active_manifest, Mapping) else None
    hosts = _load_hosts(
        repo,
        explicit_homes,
        runtime,
        manifest_hosts if isinstance(manifest_hosts, Mapping) else None,
        profile_sources,
    )
    if isinstance(manifest_hosts, Mapping):
        for host_id in manifest_hosts:
            if host_id not in PUBLIC_CLI_HOST_IDS and host_id not in hosts:
                raise ValueError("HOST_PROFILE_REQUIRED")
    if not hosts and codex_home is None and explicit_codex_home is None and not os.environ.get("CODEX_HOME"):
        raise ValueError("HOST_HOME_REQUIRED")
    manifest_providers = active_manifest.get("providers") if active_manifest is not None else None
    provider_order = tuple(manifest_providers) if isinstance(manifest_providers, list) and manifest_providers else _provider_order(repo, defaults)
    if active_manifest is not None and isinstance(active_manifest.get("organizer"), Mapping):
        try:
            organizer = organizer_from_mapping(active_manifest["organizer"])
        except ValueError as exc:
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
    else:
        organizer = resolve_organizer(None, None, (), _configured_provider_ids(repo, defaults))
    manifest_knowledge = active_manifest.get("knowledge_repository", {}) if active_manifest is not None else {}
    restored_sync_enabled = bool(active_manifest.get("sync_enabled")) if active_manifest is not None else bool(sync.get("enabled", False))
    restored_sync_remote = str(manifest_knowledge.get("remote_name") or sync.get("remote", "origin"))
    restored_sync_branch = str(manifest_knowledge.get("branch") or sync.get("branch", "main"))
    restored_sync_fingerprint = manifest_knowledge.get("remote_fingerprint") if active_manifest is not None else None
    restored_sync_classification = manifest_knowledge.get("remote_classification") if active_manifest is not None else None
    restored_experiment = bool(active_manifest.get("experiment_enabled")) if active_manifest is not None else bool(experiment.get("enabled", False))
    restored_privacy = str(active_manifest.get("privacy_profile")) if active_manifest is not None else "private-reusable"
    policy_root = repo / "policies"
    cloud_spend_cap = providers.get("cloud_spend_cap", 0) if isinstance(providers, dict) else 0
    return Settings(
        paths=paths,
        hosts=hosts,
        organizer=organizer,
        provider_order=provider_order,
        privacy_policy_path=policy_root / "privacy-policy.json",
        capture_policy_path=policy_root / "capture-policy.json",
        promotion_policy_path=policy_root / "promotion-policy.json",
        retrieval_policy_path=policy_root / "retrieval-policy.json",
        budget_policy_path=policy_root / "budget-policy.json",
        experiment_policy_path=policy_root / "experiment-policy.json",
        curation_max_attempts=max_attempts,
        curation_retry_delay_seconds=retry_delay_seconds,
        schema_version=str(defaults.get("schema_version", 1)),
        machine_id_hash=_machine_id_hash(),
        retrieval_max_chars=int(retrieval.get("max_chars", 5000)),
        retrieval_max_results=int(retrieval.get("max_results", 5)),
        retrieval_min_score=float(retrieval.get("min_score", 0.35)),
        session_start_budget_ms=int(hooks.get("session_start_budget_ms", 2000)),
        prompt_budget_ms=int(hooks.get("prompt_budget_ms", 1000)),
        stop_budget_ms=int(hooks.get("stop_budget_ms", 300)),
        session_end_budget_ms=int(hooks.get("session_end_budget_ms", 3000)),
        sync_enabled=restored_sync_enabled,
        sync_remote=restored_sync_remote,
        sync_branch=restored_sync_branch,
        sync_remote_fingerprint=restored_sync_fingerprint,
        sync_remote_classification=restored_sync_classification,
        capture_max_per_session=int(capture.get("max_per_session", 3)),
        capture_max_payload_bytes=int(capture.get("max_payload_bytes", 32768)),
        scheduler_task_name=str(scheduler.get("task_name", "CodexExternalIntelligenceMaintenance-v1")),
        scheduler_interval_minutes=int(scheduler.get("interval_minutes", 30)),
        scheduler_timeout_seconds=int(scheduler.get("timeout_seconds", 600)),
        scheduler_log_max_bytes=int(scheduler.get("log_max_bytes", 1048576)),
        scheduler_log_retention_files=int(scheduler.get("log_retention_files", 5)),
        experiment_enabled=restored_experiment,
        experiment_id=str(experiment.get("experiment_id", "retrieval-v1")),
        cloud_spend_cap=cloud_spend_cap,
        prompt_max_chars=int(context.get("prompt_max_chars", retrieval.get("max_chars", 5000))),
        always_on_hard_cap_chars=int(context.get("always_on_hard_cap_chars", 12000)),
        privacy_profile=restored_privacy,
    )
