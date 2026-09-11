from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canary import read_hook_status
from .command_quote import build_hook_argv, quote_command, quote_posix_command, quote_windows_command
from .config import LEGACY_UNSUPPORTED_HOST_IDS, PUBLIC_CLI_HOST_IDS, HostSpec, RuntimePaths, Settings, load_settings
from .doctor import run_doctor
from .install_agents import BEGIN_MARKER, END_MARKER, install_global_agents, merge_managed_context, remove_managed_context, render_managed_context
from .install_config import MANAGED_HOOK_IDS, merge_config_toml, merge_hooks, remove_managed_hooks, validate_hook_commands
from .knowledge_setup import (
    KNOWLEDGE_MODES,
    KnowledgeSetupPlan,
    KnowledgeSetupResult,
    KnowledgeSetupSelection,
    apply_knowledge_setup,
    plan_knowledge_setup,
)
from .knowledge_repository import inspect_knowledge_repository
from .host_profiles import (
    HostProfile,
    PUBLIC_ADAPTER_FAMILIES,
    build_host_profile,
    canonical_host_id,
    host_profile_bytes,
    host_profile_hash,
    is_custom_host_id,
    load_host_profile,
    read_host_profile_document,
)
from .remote_assurance import remote_fingerprint
from .skill_installer import SkillInstallResult, canonical_tree_hash, install_skill, remove_installed_skill
from .team_store import initialize_team_store, inspect_team_store, load_or_create_writer_identity
from .install_manifest import (
    INSTALL_MANIFEST_SCHEMA_VERSION,
    normalize_install_manifest,
    validate_install_manifest,
)
from .setup_contract import OrganizerSelection, migrate_legacy_organizer, organizer_from_mapping, resolve_organizer
from .setup_reconciliation import (
    ReconciliationAction,
    SetupReconciliationPlan,
    assert_plan_current,
    build_desired_state,
    plan_setup_reconciliation,
    state_digest,
)
from .stdio import write_utf8
from .setup_ui import (
    SetupChoice,
    parse_multiple_choices,
    parse_single_choice,
    render_intro,
    render_multiple_choices,
    render_setup_summary,
    render_single_choice,
)
from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_no_reparse_components,
    assert_safe_target,
    create_link_ownership_record,
    create_ownership_record,
    read_ownership_record,
    safe_atomic_write,
    safe_chmod,
    safe_copy_file,
    safe_ensure_directory,
    safe_move,
    safe_remove_tree,
    safe_unlink,
    safe_unlink_link,
    tree_digest,
    validate_link_ownership_record,
    validate_ownership_record,
    write_ownership_record,
)


HOST_TEMPLATE_NAMES = {"codex-cli": "codex", "codex-app": "codex", "claude-code": "claude", "gemini-cli": "gemini", "qwen-code": "qwen"}
SUPPORTED_HOSTS = frozenset(PUBLIC_CLI_HOST_IDS)
LEGACY_HOSTS = frozenset(LEGACY_UNSUPPORTED_HOST_IDS)
KNOWN_HOSTS = SUPPORTED_HOSTS | LEGACY_HOSTS
CODEX_SETTINGS_HOST_IDS = frozenset({"codex-cli", "codex-app"})
RUNTIME_DIRECTORY_NAMES = ("queue", "spool", "emergency-spool", "cursor", "locks", "cache", "logs", "backups", "state", "transactions")
TEAM_RUNTIME_DIRECTORY_NAMES = ("team-cache", "team-outbox", "team-identities")
SKILL_BINDING_NAME = ".external-intelligence-binding.json"
PRIVACY_PROFILES = frozenset({"public", "private-reusable", "client-confidential", "machine-local"})
_TEAM_MEMBER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve(value: Path | str) -> Path:
    return Path(value).expanduser().resolve()


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash_path(path: Path) -> str | None:
    path = absolute_path(path)
    if path.is_symlink():
        return None
    try:
        return _sha256(path.read_bytes()) if path.is_file() else None
    except OSError:
        return None


def _dir_hash(path: Path) -> str | None:
    path = absolute_path(path)
    if path.is_symlink():
        return None
    try:
        return canonical_tree_hash(path) if path.is_dir() else None
    except (OSError, ValueError):
        return None


def _managed_hook_hash(path: Path, managed_ids: Sequence[str]) -> str | None:
    """Hash only this installation's hook entries, excluding user entries."""

    path = absolute_path(path)
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    hooks = value.get("hooks") if isinstance(value, Mapping) else None
    if not isinstance(hooks, Mapping):
        return None
    wanted = {str(item) for item in managed_ids}
    projected: dict[str, list[Mapping[str, Any]]] = {}
    for event_name, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        selected = [dict(entry) for entry in entries if isinstance(entry, Mapping) and str(entry.get("id")) in wanted]
        if selected:
            projected[str(event_name)] = selected
    return _sha256(json.dumps({"hooks": projected}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _canonicalize_managed_hook_order(value: Mapping[str, Any], managed_ids: Sequence[str]) -> dict[str, Any]:
    """Sort managed entries while preserving the user's hook entry order."""

    result = copy.deepcopy(dict(value))
    hooks = result.get("hooks")
    if not isinstance(hooks, dict):
        return result
    wanted = {str(item) for item in managed_ids}
    for event_name, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        positions = [
            index
            for index, entry in enumerate(entries)
            if isinstance(entry, Mapping) and str(entry.get("id")) in wanted
        ]
        if len(positions) < 2:
            continue
        managed = sorted(
            (entries[index] for index in positions),
            key=lambda entry: (
                str(entry.get("id")),
                json.dumps(dict(entry), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ),
        )
        for index, entry in zip(positions, managed):
            entries[index] = entry
    return result


def _atomic_write(path: Path, raw: bytes) -> None:
    try:
        path = absolute_path(path)
        safe_ensure_directory(path.parent)
        safe_atomic_write(path.parent, path, raw)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc


def _text_style(raw: bytes) -> str:
    if b"\r\n" in raw:
        return "\r\n"
    if b"\r" in raw:
        return "\r"
    return "\n"


def _json_bytes(value: Mapping[str, Any], style: str = "\n") -> bytes:
    text = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    return text.replace("\n", style).encode("utf-8") if style != "\n" else text.encode("utf-8")


def _read_json(path: Path, default: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not path.exists():
        return dict(default or {})
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("JSON_CONFIGURATION_INVALID") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON_CONFIGURATION_OBJECT_REQUIRED")
    return value


def _load_text(path: Path) -> tuple[str, str]:
    if not path.exists():
        return "", "\n"
    raw = path.read_bytes()
    return raw.decode("utf-8"), _text_style(raw)


def _parse_values(values: Sequence[str] | str | None, *, deduplicate: bool = True) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    result: list[str] = []
    for value in values:
        result.extend(item.strip() for item in str(value).split(",") if item.strip())
    return tuple(dict.fromkeys(result)) if deduplicate else tuple(result)


def _parse_host_ids(values: Sequence[str] | str | None) -> tuple[str, ...]:
    """Parse selected host IDs using one canonical, collision-safe rule."""

    raw_values = _parse_values(values, deduplicate=False)
    result: list[str] = []
    for raw in raw_values:
        try:
            host_id = canonical_host_id(raw)
        except ValueError as exc:
            raise ValueError("HOST_ID_INVALID:" + str(raw)) from exc
        if host_id in result:
            raise ValueError("HOST_ID_COLLISION:" + host_id)
        result.append(host_id)
    return tuple(result)


def _configured_provider_ids(repo: Path) -> tuple[str, ...]:
    provider_path = repo / "config" / "inference-providers.json"
    if provider_path.is_file():
        value = _read_json(provider_path)
        providers = value.get("providers")
        if isinstance(providers, Mapping):
            return tuple(str(item) for item in providers if isinstance(item, str) and item)
    defaults_path = repo / "config" / "defaults.json"
    defaults = _read_json(defaults_path, {}) if defaults_path.is_file() else {}
    providers = defaults.get("providers")
    if isinstance(providers, Mapping) and isinstance(providers.get("order"), list):
        return tuple(str(item) for item in providers["order"] if isinstance(item, str) and item)
    if isinstance(defaults.get("provider_order"), list):
        return tuple(str(item) for item in defaults["provider_order"] if isinstance(item, str) and item)
    return ("local-openai-compatible", "ollama", "subscription-cli", "cloud-api")


def _default_home(host_id: str) -> Path:
    env_names = {"codex-cli": "CODEX_HOME", "codex-app": "CODEX_HOME", "claude-code": "CLAUDE_CONFIG_DIR", "gemini-cli": "GEMINI_HOME", "qwen-code": "QWEN_HOME"}
    suffixes = {"codex-cli": ".codex", "codex-app": ".codex", "claude-code": ".claude", "gemini-cli": ".gemini", "qwen-code": ".qwen"}
    if host_id not in suffixes:
        raise ValueError("HOST_UNSUPPORTED")
    return _resolve(os.environ.get(env_names[host_id]) or (Path.home() / suffixes[host_id]))


def _default_runtime_root() -> Path:
    """Return the one user-local runtime location used by guided setup."""

    return _resolve(Path.home() / ".external-intelligence" / "runtime")


def _parse_host_homes(
    values: Mapping[str, Path | str] | Sequence[str] | None,
    *,
    allowed_hosts: Sequence[str] | None = None,
) -> dict[str, Path]:
    if values is None:
        return {}
    accepted = frozenset(allowed_hosts or KNOWN_HOSTS)
    if isinstance(values, Mapping):
        result: dict[str, Path] = {}
        for key, value in values.items():
            try:
                host_id = canonical_host_id(str(key))
            except ValueError as exc:
                raise ValueError("HOST_HOME_FORMAT_INVALID") from exc
            if host_id not in accepted or not value:
                raise ValueError("HOST_HOME_FORMAT_INVALID")
            if host_id in result:
                raise ValueError("HOST_HOME_COLLISION")
            result[host_id] = _resolve(value)
        return result
    result: dict[str, Path] = {}
    for item in values:
        text = str(item)
        if "=" not in text:
            raise ValueError("HOST_HOME_FORMAT_INVALID")
        host_id, raw_path = text.split("=", 1)
        try:
            host_id = canonical_host_id(host_id)
        except ValueError as exc:
            raise ValueError("HOST_HOME_FORMAT_INVALID") from exc
        if host_id not in accepted or not raw_path:
            raise ValueError("HOST_HOME_FORMAT_INVALID")
        if host_id in result:
            raise ValueError("HOST_HOME_COLLISION")
        result[host_id] = _resolve(raw_path)
    return result


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class SetupSelection:
    engine_root: Path | str | None = None
    knowledge_root: Path | str | None = None
    repo_root: Path | str | None = None
    runtime_root: Path | str | None = None
    hosts: tuple[str, ...] | Sequence[str] = ()
    work_hosts: tuple[str, ...] | Sequence[str] = ()
    include_codex_app: bool = False
    host_homes: Mapping[str, Path | str] | Sequence[str] | None = None
    host_profiles: tuple[Path | str, ...] | Sequence[Path | str] = ()
    python_exe: Path | str | None = None
    providers: tuple[str, ...] | Sequence[str] = ()
    organizer_provider: str | None = None
    organizer_host: str | None = None
    privacy_profile: str = "private-reusable"
    sync: bool = False
    experiment: bool = False
    scheduler: bool = False
    skill_mode: str = "copy"
    skip_venv: bool = False
    non_interactive: bool = False
    legacy_host_migrations: tuple[Mapping[str, Any], ...] | Sequence[Mapping[str, Any]] = ()
    knowledge_mode: str | None = None
    github_repository: str | None = None
    github_executable: Path | str = "gh"
    remote_name: str = "origin"
    branch: str = "main"
    accept_plan: bool = False
    confirm_github_create: str | None = None
    compatibility_notices: tuple[str, ...] | Sequence[str] = ()
    preserve_existing_knowledge: bool = False
    personal_knowledge_root: Path | str | None = None
    team_knowledge_root: Path | str | None = None
    team_member_id: str | None = None
    team_knowledge: bool | None = None
    # Internal update-only escape hatch: an existing team descriptor may be
    # retained while its external shared root is temporarily unavailable.
    defer_team_validation: bool = False
    # Interactive setup can collect a data-only profile before the approved
    # transaction.  Keep the document in memory until that transaction so
    # rejected setup never leaves a profile file behind.
    host_profile_documents: Mapping[str, Mapping[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.personal_knowledge_root is not None and self.knowledge_root is not None:
            try:
                personal_text = os.path.normcase(os.path.abspath(os.fspath(self.personal_knowledge_root)))
                legacy_text = os.path.normcase(os.path.abspath(os.fspath(self.knowledge_root)))
            except (TypeError, ValueError, OSError) as exc:
                raise ValueError("PERSONAL_KNOWLEDGE_ROOT_CONFLICT") from exc
            if personal_text != legacy_text:
                raise ValueError("PERSONAL_KNOWLEDGE_ROOT_CONFLICT")
        if self.team_knowledge is not None and type(self.team_knowledge) is not bool:
            raise ValueError("TEAM_KNOWLEDGE_SELECTION_INVALID")
        if self.team_member_id is not None:
            if not isinstance(self.team_member_id, str) or not _TEAM_MEMBER_ID_RE.fullmatch(self.team_member_id):
                raise ValueError("TEAM_MEMBER_ID_INVALID")
        team_enabled = self.team_knowledge
        if self.team_knowledge_root is not None:
            if team_enabled is False:
                raise ValueError("TEAM_SELECTION_CONFLICT")
            team_enabled = True
        if self.team_member_id is not None and team_enabled is False:
            raise ValueError("TEAM_SELECTION_CONFLICT")
        if self.team_member_id is not None and team_enabled is None:
            raise ValueError("TEAM_KNOWLEDGE_ROOT_REQUIRED")
        if team_enabled is True:
            if self.team_knowledge_root is None:
                raise ValueError("TEAM_KNOWLEDGE_ROOT_REQUIRED")
            if self.team_member_id is None:
                raise ValueError("TEAM_MEMBER_ID_REQUIRED")
        object.__setattr__(self, "team_knowledge", team_enabled)
        profile_paths = tuple(Path(item).expanduser() for item in (self.host_profiles or ()))
        profile_ids: list[str] = []
        for profile_path in profile_paths:
            profile = load_host_profile(profile_path, Path("."))
            if profile.host_id in profile_ids:
                raise ValueError("HOST_PROFILE_DUPLICATE")
            profile_ids.append(profile.host_id)
        inline_documents: dict[str, Mapping[str, Any]] = {}
        if self.host_profile_documents is not None:
            if not isinstance(self.host_profile_documents, Mapping):
                raise ValueError("HOST_PROFILE_INVALID")
            for raw_id, raw_document in self.host_profile_documents.items():
                if not isinstance(raw_id, str) or not isinstance(raw_document, Mapping):
                    raise ValueError("HOST_PROFILE_INVALID")
                try:
                    inline_id = canonical_host_id(raw_id)
                except ValueError as exc:
                    raise ValueError("HOST_PROFILE_INVALID") from exc
                if not is_custom_host_id(inline_id) or inline_id in inline_documents or inline_id in profile_ids:
                    raise ValueError("HOST_PROFILE_DUPLICATE")
                document_id = raw_document.get("host_id")
                if document_id != inline_id:
                    raise ValueError("HOST_PROFILE_INVALID")
                inline_documents[inline_id] = dict(raw_document)
        profile_ids.extend(inline_documents)
        parsed_homes = _parse_host_homes(self.host_homes, allowed_hosts=KNOWN_HOSTS | frozenset(profile_ids))
        for profile_id in profile_ids:
            if profile_id not in parsed_homes:
                raise ValueError("HOST_HOME_REQUIRED:" + profile_id)
        for profile_id, document in inline_documents.items():
            try:
                build_host_profile(document, parsed_homes[profile_id])
            except (TypeError, ValueError) as exc:
                raise ValueError("HOST_PROFILE_INVALID") from exc
        allowed_hosts = SUPPORTED_HOSTS | frozenset(profile_ids)
        legacy_hosts = _parse_host_ids(self.hosts)
        requested_work_hosts = _parse_host_ids(self.work_hosts)
        if legacy_hosts and requested_work_hosts and legacy_hosts != requested_work_hosts:
            raise ValueError("WORK_HOSTS_CONFLICT")
        hosts = requested_work_hosts or legacy_hosts
        if self.include_codex_app and "codex-cli" in hosts and "codex-app" not in hosts:
            hosts += ("codex-app",)
        migrations: list[dict[str, Any]] = []
        for item in self.legacy_host_migrations:
            if not isinstance(item, Mapping):
                continue
            migration = dict(item)
            for key in ("from_host_id", "to_host_id"):
                value = migration.get(key)
                if value is None and key == "to_host_id":
                    continue
                try:
                    migration[key] = canonical_host_id(value)
                except ValueError as exc:
                    raise ValueError("HOST_ID_INVALID:" + str(value)) from exc
            migrations.append(migration)
        legacy = tuple(item for item in hosts if item in LEGACY_HOSTS)
        if legacy:
            for host_id in legacy:
                if not any(str(item.get("from_host_id")) == host_id for item in migrations):
                    migrations.append(
                        {
                            "from_host_id": host_id,
                            "to_host_id": "codex-cli" if host_id == "codex-app" else None,
                            "status": "MIGRATED_TO_CLI" if host_id == "codex-app" else "UNSUPPORTED",
                            "reason_code": "HOST_UNSUPPORTED",
                        }
                    )
            hosts = tuple(item for item in hosts if item not in LEGACY_HOSTS)
            if "codex-app" in legacy and "codex-cli" not in hosts:
                hosts = ("codex-cli",) + hosts
        unknown = set(hosts) - allowed_hosts
        if unknown:
            raise ValueError("HOST_UNSUPPORTED:" + sorted(unknown)[0])
        organizer_host = self.organizer_host
        if organizer_host is not None:
            try:
                organizer_host = canonical_host_id(organizer_host)
            except ValueError as exc:
                raise ValueError("HOST_ID_INVALID:" + str(organizer_host)) from exc
            if organizer_host not in allowed_hosts | LEGACY_HOSTS:
                raise ValueError("HOST_UNSUPPORTED:" + str(organizer_host))
            if organizer_host in LEGACY_HOSTS:
                migrations.append(
                    {
                        "from_host_id": organizer_host,
                        "to_host_id": "codex-cli" if organizer_host == "codex-app" else None,
                        "status": "MIGRATED_TO_CLI" if organizer_host == "codex-app" else "UNSUPPORTED",
                        "reason_code": "HOST_UNSUPPORTED",
                    }
                )
                organizer_host = "codex-cli"
        organizer_provider = self.organizer_provider
        if organizer_provider is not None and (not isinstance(organizer_provider, str) or not organizer_provider):
            raise ValueError("ORGANIZER_PROVIDER_INVALID")
        if self.privacy_profile not in PRIVACY_PROFILES:
            raise ValueError("PRIVACY_PROFILE_INVALID")
        if self.skill_mode not in {"copy", "link"}:
            raise ValueError("SKILL_MODE_INVALID")
        notices = list(_parse_values(self.compatibility_notices))
        knowledge_mode = self.knowledge_mode
        if knowledge_mode is None:
            knowledge_mode = "local"
            notices.append("KNOWLEDGE_MODE_DEFAULTED_LOCAL")
        if knowledge_mode not in KNOWLEDGE_MODES:
            raise ValueError("KNOWLEDGE_MODE_INVALID")
        if type(self.accept_plan) is not bool:
            raise ValueError("SETUP_PLAN_ACCEPTANCE_INVALID")
        if type(self.preserve_existing_knowledge) is not bool:
            raise ValueError("SETUP_KNOWLEDGE_PRESERVATION_INVALID")
        if type(self.defer_team_validation) is not bool:
            raise ValueError("SETUP_TEAM_VALIDATION_POLICY_INVALID")
        object.__setattr__(self, "hosts", hosts)
        object.__setattr__(self, "work_hosts", hosts)
        object.__setattr__(self, "organizer_provider", organizer_provider)
        object.__setattr__(self, "organizer_host", organizer_host)
        object.__setattr__(self, "providers", _parse_values(self.providers, deduplicate=False))
        object.__setattr__(self, "host_homes", parsed_homes)
        object.__setattr__(self, "host_profiles", profile_paths)
        object.__setattr__(self, "host_profile_documents", inline_documents or None)
        object.__setattr__(self, "legacy_host_migrations", tuple(migrations))
        object.__setattr__(self, "knowledge_mode", knowledge_mode)
        object.__setattr__(self, "github_executable", str(self.github_executable))
        object.__setattr__(self, "compatibility_notices", tuple(dict.fromkeys(notices)))

    @property
    def managed_hosts(self) -> tuple[str, ...]:
        """All hosts whose integration is managed, including organizer-only host."""

        if self.organizer_host is None or self.organizer_host in self.work_hosts:
            return tuple(self.work_hosts)
        return tuple(dict.fromkeys((*self.work_hosts, self.organizer_host)))


@dataclass(frozen=True)
class UninstallOptions:
    restore_config_backup: bool = False
    remove_skills: bool = True
    remove_runtime: bool = False
    remove_runtime_cache: bool = False
    remove_scheduler: bool = True
    remove_venv: bool = False
    force: bool = False
    check_only: bool = False


@dataclass(frozen=True)
class InstallPlanItem:
    target: Path
    action: str
    before_hash: str | None
    after_hash: str | None
    backup_path: Path | None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"target": str(self.target), "action": self.action, "before_hash": self.before_hash, "after_hash": self.after_hash, "backup_path": str(self.backup_path) if self.backup_path else None, "details": dict(self.details)}


@dataclass(frozen=True)
class SetupResult:
    ok: bool
    status: str
    manifest_path: Path | None = None
    plan: tuple[InstallPlanItem, ...] = ()
    changed_paths: tuple[Path, ...] = ()
    backups: tuple[Path, ...] = ()
    hosts: tuple[Mapping[str, Any], ...] = ()
    doctor: Mapping[str, Any] | None = None
    errors: tuple[Mapping[str, Any], ...] = ()
    rollback: Mapping[str, Any] | None = None
    message: str = ""
    preflight: Mapping[str, Any] | None = None
    host_migrations: tuple[Mapping[str, Any], ...] = ()
    knowledge: Mapping[str, Any] = field(default_factory=dict)
    sync: Mapping[str, Any] = field(default_factory=dict)
    scheduler: Mapping[str, Any] = field(default_factory=dict)
    team: Mapping[str, Any] = field(default_factory=dict)
    # Setup itself never calls a team provider or emits prompt content.  Keep
    # the counters explicit so JSON consumers can distinguish software setup
    # from later team retrieval/routing activity.
    team_activity: Mapping[str, int] = field(
        default_factory=lambda: {"filesystem": 0, "provider": 0, "prompt_chars": 0}
    )
    reconciliation: Mapping[str, Any] = field(default_factory=dict)
    knowledge_stores: Mapping[str, Any] = field(default_factory=dict)
    actions_required: tuple[Mapping[str, Any], ...] = ()
    compatibility_notices: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "manifest_path": str(self.manifest_path) if self.manifest_path else None,
            "plan": [item.to_dict() for item in self.plan],
            "changed_paths": [str(path) for path in self.changed_paths],
            "backups": [str(path) for path in self.backups],
            "hosts": [dict(item) for item in self.hosts],
            "doctor": dict(self.doctor) if self.doctor else None,
            "errors": [dict(item) for item in self.errors],
            "rollback": dict(self.rollback) if self.rollback else None,
            "message": self.message,
            "preflight": dict(self.preflight) if self.preflight else None,
            "host_migrations": [dict(item) for item in self.host_migrations],
            "knowledge": dict(self.knowledge),
            "sync": dict(self.sync),
            "scheduler": dict(self.scheduler),
            "team": dict(self.team),
            "team_activity": dict(self.team_activity),
            "reconciliation": dict(self.reconciliation),
            "knowledge_stores": dict(self.knowledge_stores),
            "actions_required": [dict(item) for item in self.actions_required],
            "compatibility_notices": list(self.compatibility_notices),
        }

def _validate_transaction_owner(entry: Mapping[str, Any], target: Path) -> Mapping[str, Any]:
    owner = entry.get("ownership")
    if not isinstance(owner, Mapping):
        raise SafeFilesystemError("SAFE_OWNERSHIP_MISSING")
    kind = "transaction-skill" if entry.get("kind") == "skill" else "transaction-file"
    link_target = owner.get("link_target")
    if entry.get("kind") == "skill" and isinstance(link_target, str):
        if target.exists() or target.is_symlink():
            if not target.is_symlink():
                raise SafeFilesystemError("SAFE_OWNERSHIP_MISMATCH")
            validate_link_ownership_record(owner, target.parent, target, link_target, kind=kind)
        else:
            validate_link_ownership_record(owner, target.parent, target, kind=kind)
    else:
        validate_ownership_record(owner, target.parent, target, kind=kind)
    return owner


def _transaction_current_hash(entry: Mapping[str, Any], target: Path) -> str | None:
    owner = entry.get("ownership")
    if isinstance(owner, Mapping) and isinstance(owner.get("link_target"), str) and target.is_symlink():
        return canonical_tree_hash(target.resolve())
    return _dir_hash(target) if entry.get("kind") == "skill" else _hash_path(target)


def _restore_transaction_entries(entries: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    restored: list[str] = []
    conflicts: list[str] = []
    for entry in reversed(entries):
        if not isinstance(entry, Mapping):
            conflicts.append("<invalid-entry>")
            continue
        raw_target = entry.get("target")
        if not isinstance(raw_target, str) or not raw_target:
            conflicts.append("<invalid-target>")
            continue
        target = absolute_path(raw_target)
        try:
            owner = _validate_transaction_owner(entry, target)
            current = _transaction_current_hash(entry, target)
            if current != entry.get("after_hash") and (target.exists() or target.is_symlink()):
                conflicts.append(str(target))
                continue
            if entry.get("kind") == "file":
                if entry.get("existed") is True:
                    raw_backup = entry.get("backup_path")
                    if not isinstance(raw_backup, str) or not raw_backup:
                        raise SafeFilesystemError("SAFE_BACKUP_MISSING")
                    backup = absolute_path(raw_backup)
                    assert_safe_target(target.parent, backup, allow_missing=False, expected_type="file")
                    safe_copy_file(target.parent, backup, target.parent, target)
                    restored.append(str(target))
                elif target.exists() or target.is_symlink():
                    safe_unlink(target.parent, target, allow_missing=True)
                    restored.append(str(target))
            elif entry.get("kind") == "skill":
                if target.is_symlink():
                    link_target = owner.get("link_target")
                    if not isinstance(link_target, str):
                        raise SafeFilesystemError("SAFE_OWNERSHIP_MISMATCH")
                    safe_unlink_link(target.parent, target, expected_target=link_target)
                elif target.exists():
                    expected_tree = owner.get("expected_digest")
                    safe_remove_tree(target.parent, target, expected_digest=expected_tree if isinstance(expected_tree, str) else None)
                if entry.get("existed") is True:
                    raw_backup = entry.get("backup_path")
                    if not isinstance(raw_backup, str) or not raw_backup:
                        raise SafeFilesystemError("SAFE_BACKUP_MISSING")
                    backup = absolute_path(raw_backup)
                    if not (backup.exists() or backup.is_symlink()):
                        raise SafeFilesystemError("SAFE_BACKUP_MISSING")
                    safe_move(target.parent, backup, target.parent, target)
                restored.append(str(target))
            else:
                raise SafeFilesystemError("SAFE_TRANSACTION_KIND_INVALID")
        except (OSError, ValueError) as exc:
            del exc
            conflicts.append(str(target))
    return restored, conflicts


class _Transaction:
    def __init__(self, runtime_root: Path) -> None:
        self.runtime_root = absolute_path(runtime_root)
        self.transaction_id = "tx_" + uuid.uuid4().hex
        self.journal_path = self.runtime_root / "transactions" / (self.transaction_id + ".json")
        self.entries: list[dict[str, Any]] = []
        self.status = "IN_PROGRESS"
        safe_ensure_directory(self.journal_path.parent)
        self._persist()

    def _persist(self) -> None:
        _atomic_write(self.journal_path, _json_bytes({"schema_version": 1, "transaction_id": self.transaction_id, "status": self.status, "started_at": _now().isoformat(), "entries": self.entries}))

    def _backup_file(self, target: Path) -> Path:
        target = absolute_path(target)
        backup = target.with_name(target.name + ".before-ei-" + self.transaction_id)
        try:
            safe_copy_file(target.parent, target, target.parent, backup)
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
        return backup

    def mutate_file(self, target: Path, raw: bytes, *, details: Mapping[str, Any] | None = None) -> Path | None:
        target = absolute_path(target)
        safe_ensure_directory(target.parent)
        try:
            assert_safe_target(target.parent, target, allow_missing=True, expected_type="file")
        except SafeFilesystemError as exc:
            raise ValueError("MANAGED_TARGET_SYMLINK" if exc.code == "UNSAFE_REPARSE_POINT" else exc.code) from exc
        before = target.read_bytes() if target.exists() else None
        if before == raw:
            return None
        backup = self._backup_file(target) if before is not None else None
        _atomic_write(target, raw)
        after_hash = _sha256(raw)
        owner = create_ownership_record(target.parent, target, kind="transaction-file", expected_digest=after_hash)
        self.entries.append({"kind": "file", "target": str(target), "existed": before is not None, "before_hash": _sha256(before) if before is not None else None, "after_hash": after_hash, "backup_path": str(backup) if backup else None, "ownership": owner, "details": dict(details or {})})
        self._persist()
        return backup

    def register_skill(self, result: SkillInstallResult, existed_before: bool) -> None:
        if not result.changed:
            return
        destination = absolute_path(result.destination)
        if result.mode == "link":
            owner = create_link_ownership_record(destination.parent, destination, result.source, kind="transaction-skill", expected_digest=result.installed_hash)
        else:
            owner = create_ownership_record(destination.parent, destination, kind="transaction-skill", expected_digest=tree_digest(destination))
        self.entries.append({"kind": "skill", "target": str(destination), "existed": existed_before, "after_hash": result.installed_hash, "backup_path": str(result.backup_path) if result.backup_path else None, "ownership": owner, "details": {"host_id": result.host_id, "mode": result.mode}})
        self._persist()

    def remove_file(self, target: Path, expected_hash: str | None = None, *, details: Mapping[str, Any] | None = None) -> Path | None:
        """Move an owned file aside so a later rollback can restore it."""

        target = absolute_path(target)
        if not (target.exists() or target.is_symlink()):
            return None
        if target.is_symlink() or not target.is_file():
            raise ValueError("MANAGED_TARGET_CONFLICT")
        before_hash = _hash_path(target)
        if expected_hash is not None and before_hash != expected_hash:
            raise ValueError("MANAGED_TARGET_CONFLICT")
        try:
            assert_safe_target(target.parent, target, allow_missing=False, expected_type="file")
            owner = create_ownership_record(target.parent, target, kind="transaction-file", expected_digest=before_hash)
            backup = target.with_name(target.name + ".before-ei-" + self.transaction_id)
            safe_move(target.parent, target, target.parent, backup)
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
        self.entries.append({"kind": "file", "target": str(target), "existed": True, "before_hash": before_hash, "after_hash": before_hash, "backup_path": str(backup), "ownership": owner, "details": dict(details or {})})
        self._persist()
        return backup

    def remove_skill(self, destination: Path, expected_hash: str | None = None, *, details: Mapping[str, Any] | None = None) -> Path | None:
        """Move an owned installed Skill aside with a rollback journal entry."""

        destination = absolute_path(destination)
        if not (destination.exists() or destination.is_symlink()):
            return None
        try:
            if destination.is_symlink():
                resolved = destination.resolve(strict=False)
                current_hash = canonical_tree_hash(resolved) if resolved.is_dir() else None
                if expected_hash is not None and current_hash != expected_hash:
                    raise ValueError("MANAGED_TARGET_CONFLICT")
                owner = create_link_ownership_record(destination.parent, destination, resolved, kind="transaction-skill", expected_digest=current_hash)
            else:
                current_hash = canonical_tree_hash(destination)
                if expected_hash is not None and current_hash != expected_hash:
                    raise ValueError("MANAGED_TARGET_CONFLICT")
                owner = create_ownership_record(destination.parent, destination, kind="transaction-skill", expected_digest=tree_digest(destination))
            backup = destination.with_name(destination.name + ".before-ei-" + self.transaction_id)
            safe_move(destination.parent, destination, destination.parent, backup)
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
        self.entries.append({"kind": "skill", "target": str(destination), "existed": True, "before_hash": current_hash, "after_hash": current_hash, "backup_path": str(backup), "ownership": owner, "details": dict(details or {})})
        self._persist()
        return backup

    def commit(self) -> None:
        self.status = "COMMITTED"
        self._persist()

    def rollback(self) -> dict[str, Any]:
        if self.status == "COMMITTED":
            return {
                "status": "COMMITTED",
                "rolled_back": False,
                "restored": [],
                "conflicts": [],
                "journal": str(self.journal_path),
                "reason_codes": ["TRANSACTION_COMMITTED"],
            }
        restored, conflicts = _restore_transaction_entries(self.entries)
        self.status = "ROLLED_BACK" if not conflicts else "ROLLBACK_CONFLICT"
        self._persist()
        return {"status": self.status, "restored": restored, "conflicts": conflicts, "journal": str(self.journal_path)}


def _recover_pending_transactions(runtime_root: Path) -> list[dict[str, Any]]:
    runtime_root = absolute_path(runtime_root)
    directory = runtime_root / "transactions"
    try:
        assert_safe_target(runtime_root, directory, allow_missing=True, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    if not directory.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for path in sorted(directory.glob("tx_*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("status") != "IN_PROGRESS" or not isinstance(value.get("entries"), list):
            continue
        restored, conflicts = _restore_transaction_entries(value["entries"])
        value["status"] = "RECOVERED" if not conflicts else "RECOVERY_CONFLICT"
        value["recovered_at"] = _now().isoformat()
        _atomic_write(path, _json_bytes(value))
        results.append({"journal": str(path), "status": value["status"], "restored": restored, "conflicts": conflicts})
    return results


def _replace_placeholders(value: Any, substitutions: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in substitutions.items():
            result = result.replace("{{" + key + "}}", replacement)
        return result
    if isinstance(value, list):
        return [_replace_placeholders(item, substitutions) for item in value]
    if isinstance(value, dict):
        return {key: _replace_placeholders(item, substitutions) for key, item in value.items()}
    return value


def _template_for(repo: Path, host_id: str) -> Path:
    name = HOST_TEMPLATE_NAMES.get(host_id)
    if not name:
        raise ValueError("HOST_UNSUPPORTED")
    path = repo / "hooks" / name / "hooks.template.json"
    if not path.is_file():
        raise ValueError("HOOK_TEMPLATE_MISSING:" + host_id)
    return path


def _render_hook_fragment(
    repo: Path,
    host: HostSpec,
    host_id: str,
    python_exe: Path,
    selected_hosts: tuple[str, ...],
    knowledge_root: Path | None = None,
    runtime_root: Path | None = None,
    *,
    personal_knowledge_root: Path | None = None,
    team_knowledge_root: Path | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    personal = personal_knowledge_root if personal_knowledge_root is not None else knowledge_root
    if personal is None or runtime_root is None:
        raise ValueError("HOOK_ROOTS_REQUIRED")
    host_home = _resolve(host.hook_config_path.parent)
    if host_id in HOST_TEMPLATE_NAMES:
        try:
            value = json.loads(_template_for(repo, host_id).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("HOOK_TEMPLATE_INVALID:" + host_id) from exc
        if not isinstance(value, dict):
            raise ValueError("HOOK_TEMPLATE_OBJECT_REQUIRED:" + host_id)
    else:
        if settings is None:
            raise ValueError("HOST_PROFILE_SETTINGS_REQUIRED")
        from .hooks.registry import get_adapter

        adapter = get_adapter(host_id, settings)
        command_fragment = adapter.config_fragment(
            python_exe,
            repo,
            Path(personal),
            Path(runtime_root),
        )
        value = {
            "hooks": {
                event_name: [
                    {
                        "id": f"ei-{host_id}-{event_name.casefold()}-v1",
                        "matcher": "*",
                        "hooks": [
                            {
                                **{key: value for key, value in command_fragment.items() if key != "id"},
                                "timeout": 3,
                                "statusMessage": f"External intelligence: {host.display_name}",
                            }
                        ],
                    }
                ]
                for event_name in host.event_mapping
            }
        }
    argv = build_hook_argv(
        python_exe,
        host_id=host_id,
        engine_root=repo,
        personal_knowledge_root=personal,
        team_knowledge_root=team_knowledge_root,
        runtime_root=runtime_root,
        host_home=host_home,
    )
    # Keep the legacy flag in installed host configuration as a personal-only
    # alias.  The command builder's explicit API remains the canonical source
    # for new integrations, while older host validators and wrappers continue
    # to parse the established option.
    if "--knowledge-root" not in argv:
        personal_index = argv.index("--personal-knowledge-root") + 2
        argv = (*argv[:personal_index], "--knowledge-root", str(personal), *argv[personal_index:])
    substitutions = {
        "PYTHON_EXE": str(python_exe),
        "REPO_ROOT": str(repo),
        "ENGINE_ROOT": str(repo),
        "KNOWLEDGE_ROOT": str(personal),
        "PERSONAL_KNOWLEDGE_ROOT": str(personal),
        "TEAM_KNOWLEDGE_ROOT": str(team_knowledge_root) if team_knowledge_root is not None else "",
        "HOST_HOME": str(host_home),
        "RUNTIME_ROOT": str(runtime_root),
        "HOST_ID": host_id,
        "HOOK_COMMAND_POSIX": quote_posix_command(argv),
        "HOOK_COMMAND_WINDOWS": quote_windows_command(argv),
        "HOOK_COMMAND": quote_command(argv),
    }
    rendered = _replace_placeholders(value, substitutions)
    try:
        if host_id in HOST_TEMPLATE_NAMES:
            validate_hook_commands(rendered)
        else:
            from .hooks.base import extract_hook_command_fields, validate_hook_command_fields

            hooks = rendered.get("hooks", {})
            for entries in hooks.values():
                for entry in entries:
                    for handler in entry.get("hooks", ()):
                        validate_hook_command_fields(
                            extract_hook_command_fields(handler),
                            expected_host_id=host_id,
                        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("HOOK_TEMPLATE_COMMAND_INVALID:" + host_id) from exc
    if host_id == "codex-app" and "codex-cli" in selected_hosts:
        hooks = rendered.get("hooks")
        if isinstance(hooks, dict):
            for entries in hooks.values():
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                            entry["id"] += "-codex-app"
    return rendered


def _hook_targets(settings: Settings, selected_hosts: tuple[str, ...], repo: Path, python_exe: Path) -> tuple[dict[Path, dict[str, Any]], set[str]]:
    fragments: dict[Path, dict[str, Any]] = {}
    managed_ids: set[str] = set()
    for host_id in selected_hosts:
        host = settings.hosts.get(host_id)
        if host is None:
            raise ValueError("HOST_UNSUPPORTED:" + host_id)
        target = settings.paths.hooks_path if host_id in CODEX_SETTINGS_HOST_IDS else _resolve(host.hook_config_path)
        fragment = _render_hook_fragment(
            repo,
            host,
            host_id,
            python_exe,
            selected_hosts,
            runtime_root=settings.paths.runtime_root,
            personal_knowledge_root=settings.paths.personal_knowledge_root,
            team_knowledge_root=settings.paths.team_knowledge_root,
            settings=settings,
        )
        combined = fragments.setdefault(target, {"hooks": {}})
        hooks = fragment.get("hooks", {})
        if not isinstance(hooks, Mapping):
            raise ValueError("HOOK_TEMPLATE_INVALID:" + host_id)
        for event_name, entries in hooks.items():
            if not isinstance(entries, list):
                raise ValueError("HOOK_TEMPLATE_EVENT_INVALID:" + host_id)
            combined["hooks"].setdefault(event_name, []).extend(copy.deepcopy(entries))
            managed_ids.update(str(entry["id"]) for entry in entries if isinstance(entry, Mapping) and isinstance(entry.get("id"), str))
    return fragments, managed_ids


def _managed_hook_ids_for_host(
    selection: SetupSelection,
    settings: Settings,
    repo: Path,
    python_exe: Path,
    host_id: str,
) -> set[str]:
    """Return only the ownership IDs belonging to one host instance."""

    host = settings.hosts.get(host_id)
    if host is None:
        raise ValueError("HOST_UNSUPPORTED:" + host_id)
    fragment = _render_hook_fragment(
        repo,
        host,
        host_id,
        python_exe,
        selection.managed_hosts,
        runtime_root=settings.paths.runtime_root,
        personal_knowledge_root=settings.paths.personal_knowledge_root,
        team_knowledge_root=settings.paths.team_knowledge_root,
        settings=settings,
    )
    hooks = fragment.get("hooks", {})
    if not isinstance(hooks, Mapping):
        raise ValueError("HOOK_TEMPLATE_INVALID:" + host_id)
    return {
        str(entry["id"])
        for entries in hooks.values()
        if isinstance(entries, list)
        for entry in entries
        if isinstance(entry, Mapping) and isinstance(entry.get("id"), str)
    }


def _hook_target_ownership(
    selection: SetupSelection,
    settings: Settings,
    repo: Path,
    python_exe: Path,
) -> dict[Path, dict[str, Any]]:
    """Collect deterministic owners for each physical managed hook target."""

    owners: dict[Path, dict[str, Any]] = {}
    for host_id in selection.managed_hosts:
        host = settings.hosts.get(host_id)
        if host is None:
            raise ValueError("HOST_UNSUPPORTED:" + host_id)
        target = settings.paths.hooks_path if host_id in CODEX_SETTINGS_HOST_IDS else _resolve(host.hook_config_path)
        entry = owners.setdefault(target, {"host_ids": set(), "managed_hook_ids": set()})
        entry["host_ids"].add(host_id)
        entry["managed_hook_ids"].update(_managed_hook_ids_for_host(selection, settings, repo, python_exe, host_id))
    return owners

def _profile_sources_for_selection(selection: SetupSelection) -> dict[str, tuple[HostProfile, str]]:
    """Validate selected profiles without touching the runtime filesystem."""

    configured = dict(selection.host_homes or {})
    result: dict[str, tuple[HostProfile, str]] = {}
    for profile_path in selection.host_profiles:
        document = read_host_profile_document(profile_path)
        host_id = document.get("host_id")
        if not isinstance(host_id, str) or host_id not in configured:
            raise ValueError("HOST_HOME_REQUIRED:" + str(host_id or ""))
        profile = load_host_profile(profile_path, configured[host_id])
        if profile.host_id in result:
            raise ValueError("HOST_PROFILE_DUPLICATE")
        result[profile.host_id] = (profile, host_profile_hash(document))
    for host_id, raw_document in (selection.host_profile_documents or {}).items():
        if host_id in result:
            raise ValueError("HOST_PROFILE_DUPLICATE")
        document = dict(raw_document)
        if document.get("host_id") != host_id or host_id not in configured:
            raise ValueError("HOST_HOME_REQUIRED:" + str(host_id))
        try:
            profile = build_host_profile(document, configured[host_id])
        except (TypeError, ValueError) as exc:
            raise ValueError("HOST_PROFILE_INVALID") from exc
        result[profile.host_id] = (profile, host_profile_hash(document))
    return result


def _settings_for_selection(selection: SetupSelection) -> Settings:
    repo = _resolve(selection.engine_root or selection.repo_root or Path.cwd())
    runtime = _resolve(selection.runtime_root or _default_runtime_root())
    # ``load_settings`` validates an active manifest, including the optional
    # team root.  A requested team disable is allowed to proceed even when
    # that retained root is missing, malformed, or inaccessible, so load a
    # detached settings view without the active manifest and then restore the
    # actual runtime paths without opening the team root.
    bypass_team_manifest = selection.team_knowledge is False and _manifest_path(runtime).is_file()
    settings_runtime = runtime / ".team-disabled-settings-probe" if bypass_team_manifest else runtime
    if bypass_team_manifest:
        active = normalize_install_manifest(_read_json(_manifest_path(runtime)))
        stores = active.get("knowledge_stores")
        team = stores.get("team") if isinstance(stores, Mapping) else None
        validation_active = active
        if isinstance(stores, Mapping) and isinstance(team, Mapping):
            validation_active = copy.deepcopy(active)
            detached_team = dict(team)
            detached_team["root"] = str(runtime.parent / ".team-disabled-settings-validation-root")
            validation_active["knowledge_stores"] = {**dict(stores), "team": detached_team}
        validate_install_manifest(validation_active, require_live_personal=False)
        if _resolve(str(active.get("engine_root"))) != repo:
            raise ValueError("ACTIVE_MANIFEST_ENGINE_MISMATCH")
        personal_root = _resolve(selection.personal_knowledge_root or selection.knowledge_root)
        if _resolve(str(active.get("knowledge_root"))) != personal_root:
            raise ValueError("ACTIVE_MANIFEST_KNOWLEDGE_MISMATCH")
        if _resolve(str(active.get("runtime_root"))) != runtime:
            raise ValueError("ACTIVE_MANIFEST_RUNTIME_MISMATCH")
    configured = dict(selection.host_homes or {})
    profile_sources = _profile_sources_for_selection(selection)
    primary = configured.get("codex-cli") or configured.get("codex-app") or _default_home("codex-cli")
    all_homes: dict[str, Path] = {}
    hosts_path = repo / "config" / "hosts.json"
    if hosts_path.is_file():
        manifest = _read_json(hosts_path)
        entries = manifest.get("hosts", {})
        if isinstance(entries, Mapping):
            for host_id in entries:
                all_homes[str(host_id)] = configured.get(str(host_id), runtime / ".unused-host-home" / str(host_id))
    all_homes.update(configured)
    all_homes.setdefault("codex-cli", primary)
    if selection.engine_root is not None or selection.knowledge_root is not None:
        loaded = load_settings(
            engine_root=repo,
            knowledge_root=_resolve(selection.knowledge_root) if selection.knowledge_root is not None else None,
            personal_knowledge_root=_resolve(selection.personal_knowledge_root) if selection.personal_knowledge_root is not None else None,
            team_knowledge_root=_resolve(selection.team_knowledge_root) if selection.team_knowledge_root is not None else None,
            codex_home=primary,
            runtime_root=settings_runtime,
            host_homes=all_homes,
            profile_sources=profile_sources,
            allow_uninstalled_manifest=True,
        )
    else:
        loaded = load_settings(
            repo,
            primary,
            runtime_root=settings_runtime,
            host_homes=all_homes,
            profile_sources=profile_sources,
            allow_uninstalled_manifest=True,
        )
    if not bypass_team_manifest:
        return loaded
    paths = RuntimePaths(
        engine_root=loaded.paths.engine_root,
        personal_knowledge_root=loaded.paths.personal_knowledge_root,
        runtime_root=runtime,
        codex_home=loaded.paths.codex_home,
    )
    active_organizer = active.get("organizer")
    organizer = organizer_from_mapping(active_organizer) if isinstance(active_organizer, Mapping) else loaded.organizer
    active_providers = active.get("providers")
    provider_order = tuple(active_providers) if isinstance(active_providers, list) else loaded.provider_order
    restored = replace(loaded, paths=paths, organizer=organizer, provider_order=provider_order)
    knowledge = active.get("knowledge_repository")
    if isinstance(knowledge, Mapping):
        restored_values = {
            "_sync_enabled": bool(active.get("sync_enabled")),
            "_sync_remote": knowledge.get("remote_name"),
            "_sync_branch": knowledge.get("branch"),
            "_sync_remote_fingerprint": knowledge.get("remote_fingerprint"),
            "_sync_remote_classification": knowledge.get("remote_classification"),
            "_experiment_enabled": bool(active.get("experiment_enabled")),
            "_privacy_profile": active.get("privacy_profile"),
        }
        for name, value in restored_values.items():
            object.__setattr__(restored, name, value)
    return restored


def _source_skill(repo: Path) -> Path:
    source = repo / "skills" / "external-intelligence"
    canonical_tree_hash(source)
    return source


def _normalise_selection(selection: SetupSelection | Mapping[str, Any]) -> SetupSelection:
    if isinstance(selection, SetupSelection):
        selected = selection
    elif isinstance(selection, Mapping):
        selected = SetupSelection(**dict(selection))
    else:
        raise TypeError("SETUP_SELECTION_REQUIRED")
    if selected.non_interactive and ((selected.engine_root is None and selected.repo_root is None) or selected.runtime_root is None or not selected.work_hosts):
        raise ValueError("SETUP_NON_INTERACTIVE_PATHS_AND_HOSTS_REQUIRED")
    if not selected.work_hosts:
        raise ValueError("SETUP_WORK_HOSTS_REQUIRED")
    personal_value = selected.personal_knowledge_root if selected.personal_knowledge_root is not None else selected.knowledge_root
    explicit_roots = selected.engine_root is not None or personal_value is not None
    repo = _resolve(selected.engine_root or selected.repo_root or Path.cwd())
    if explicit_roots and personal_value is None:
        raise ValueError("KNOWLEDGE_ROOT_REQUIRED")
    knowledge = _resolve(personal_value) if personal_value is not None else None
    homes = dict(selected.host_homes or {})
    if "codex-app" in homes:
        homes.setdefault("codex-cli", homes["codex-app"])
    for host_id in selected.managed_hosts:
        if host_id in SUPPORTED_HOSTS:
            homes.setdefault(host_id, _default_home(host_id))
        elif host_id not in homes:
            raise ValueError("HOST_HOME_REQUIRED:" + host_id)
    explicit_organizer = selected.organizer_provider is not None or selected.organizer_host is not None
    legacy_organizer = migrate_legacy_organizer(selected.providers, selected.work_hosts)
    configured_provider_ids = _configured_provider_ids(repo)
    if selected.organizer_provider is not None or selected.organizer_host is not None:
        organizer = resolve_organizer(
            selected.organizer_provider,
            selected.organizer_host,
            selected.work_hosts,
            configured_provider_ids,
        )
    else:
        organizer = legacy_organizer
    if organizer.status == "READY":
        organizer_provider = organizer.provider_id
        organizer_host = organizer.host_id
    elif explicit_organizer:
        organizer_provider = selected.organizer_provider
        organizer_host = selected.organizer_host
    else:
        organizer_provider = None
        organizer_host = None
    if organizer.status == "READY" and organizer.provider_id is not None:
        normalized_providers = (organizer.provider_id,)
    elif explicit_organizer:
        normalized_providers = ()
    else:
        normalized_providers = tuple(selected.providers)
    runtime = _resolve(selected.runtime_root or _default_runtime_root())
    if runtime == repo or _within(repo, runtime):
        raise ValueError("RUNTIME_ROOT_MUST_BE_OUTSIDE_REPOSITORY")
    if knowledge is None:
        knowledge = _resolve(runtime.parent / (repo.name + "-knowledge"))
    if knowledge == repo or _within(repo, knowledge) or knowledge == runtime or _within(runtime, knowledge) or _within(knowledge, runtime):
        raise ValueError("ROOTS_MUST_BE_DISTINCT")
    team_root = _resolve(selected.team_knowledge_root) if selected.team_knowledge_root is not None else None
    team_enabled = selected.team_knowledge
    if team_root is not None:
        team_enabled = True
    if team_enabled is True:
        if team_root is None:
            raise ValueError("TEAM_KNOWLEDGE_ROOT_REQUIRED")
        if selected.team_member_id is None:
            raise ValueError("TEAM_MEMBER_ID_REQUIRED")
        roots = (repo, knowledge, runtime, team_root)
        for index, root in enumerate(roots):
            for other in roots[index + 1:]:
                if root == other or _within(root, other) or _within(other, root):
                    raise ValueError("ROOTS_MUST_BE_DISTINCT")
    python = absolute_path(selected.python_exe or sys.executable)
    if not selected.skip_venv and not python.is_file():
        raise ValueError("PYTHON_EXE_INVALID")
    return SetupSelection(
        engine_root=repo,
        knowledge_root=knowledge,
        repo_root=None,
        runtime_root=runtime,
        hosts=tuple(selected.hosts),
        work_hosts=tuple(selected.work_hosts),
        host_homes=homes,
        host_profiles=selected.host_profiles,
        host_profile_documents=selected.host_profile_documents,
        python_exe=python,
        providers=normalized_providers,
        organizer_provider=organizer_provider,
        organizer_host=organizer_host,
        privacy_profile=selected.privacy_profile,
        sync=selected.sync,
        experiment=selected.experiment,
        scheduler=selected.scheduler,
        skill_mode=selected.skill_mode,
        skip_venv=selected.skip_venv,
        non_interactive=selected.non_interactive,
        legacy_host_migrations=selected.legacy_host_migrations,
        knowledge_mode=selected.knowledge_mode,
        github_repository=selected.github_repository,
        github_executable=selected.github_executable,
        remote_name=selected.remote_name,
        branch=selected.branch,
        accept_plan=selected.accept_plan,
        confirm_github_create=selected.confirm_github_create,
        compatibility_notices=selected.compatibility_notices,
        preserve_existing_knowledge=selected.preserve_existing_knowledge,
        personal_knowledge_root=knowledge,
        team_knowledge_root=team_root,
        team_member_id=selected.team_member_id,
        team_knowledge=team_enabled,
        defer_team_validation=selected.defer_team_validation,
    )


def _knowledge_selection(selection: SetupSelection) -> KnowledgeSetupSelection:
    return KnowledgeSetupSelection(
        mode=str(selection.knowledge_mode),
        engine_root=_resolve(selection.engine_root or selection.repo_root),
        knowledge_root=_resolve(selection.knowledge_root),
        runtime_root=_resolve(selection.runtime_root),
        github_repository=selection.github_repository,
        github_executable=str(selection.github_executable),
        remote_name=selection.remote_name,
        branch=selection.branch,
        sync_enabled=selection.sync,
        confirm_github_create=selection.confirm_github_create,
    )


def _planned_knowledge_view(plan: KnowledgeSetupPlan) -> dict[str, Any]:
    return {
        "mode": plan.selection.mode,
        "status": "PLANNED",
        "stage": "PLANNED",
        "plan": plan.to_dict(),
        "repository": {
            "root": str(plan.selection.knowledge_root),
            "status": "PLANNED",
            "git_initialized": False,
            "root_digest": None,
        },
        "remote": {
            "repository": plan.selection.github_repository,
            "remote_name": plan.selection.remote_name if plan.selection.github_repository else None,
            "fingerprint": plan.remote_fingerprint,
            "classification": None,
            "branch": plan.selection.branch if plan.selection.github_repository else None,
            "connected": False,
            "initial_push_complete": False,
        },
        "errors": [],
    }


def _team_setup_view(selection: SetupSelection, previous: Mapping[str, Any], *, check_only: bool) -> dict[str, Any]:
    """Return a read-only team section for setup-plan/result JSON.

    Task 5 only exposes the selection surface; actual shared-store creation is
    implemented by the later transactional task.  Therefore this view never
    claims transport or ACL management and never opens a retained team root.
    """

    previous_team: Mapping[str, Any] | None = None
    stores = previous.get("knowledge_stores") if isinstance(previous, Mapping) else None
    if isinstance(stores, Mapping) and isinstance(stores.get("team"), Mapping):
        previous_team = stores["team"]
    elif isinstance(previous.get("team"), Mapping):
        previous_team = previous["team"]
    enabled = selection.team_knowledge
    if enabled is None:
        enabled = previous_team.get("enabled") is True if previous_team is not None else False
    root = selection.team_knowledge_root
    if root is None and previous_team is not None and isinstance(previous_team.get("root"), str):
        root = previous_team["root"]
    store_id = previous_team.get("store_id") if previous_team is not None else None
    writer_id = previous_team.get("writer_id") if previous_team is not None else None
    member_id = selection.team_member_id or (previous_team.get("team_member_id") if previous_team is not None else None)
    if enabled:
        if check_only:
            status = "PLANNED"
        elif selection.defer_team_validation and root is not None and Path(root).exists():
            status = "READY"
        else:
            status = "DEFERRED"
        lifecycle = "REUSE" if previous_team is not None else "CREATE"
    else:
        status = "PRESERVED" if previous_team is not None else "DISABLED"
        lifecycle = "RETAIN"
    result = {
        "enabled": bool(enabled),
        "status": status,
        "root": str(root) if root is not None else None,
        "store_id": store_id,
        "team_member_id": member_id,
        "writer_id": writer_id,
        "create_or_reuse": lifecycle,
        "transport": "external-shared-folder",
        "transport_managed": False,
        "access_control_verified": False,
        "destructive_mutation": False,
    }
    if (
        enabled
        and not check_only
        and selection.defer_team_validation
        and root is not None
        and not Path(root).exists()
        and not Path(root).is_symlink()
    ):
        result["reason_code"] = "TEAM_STORE_VALIDATION_DEFERRED"
    return result


def _manifest_state(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Project an active manifest into the detached reconciliation state."""

    normalized = normalize_install_manifest(manifest)
    if normalized.get("status") != "INSTALLED":
        return {}
    stores = normalized.get("knowledge_stores")
    stores_map = stores if isinstance(stores, Mapping) else {}
    personal = stores_map.get("personal") if isinstance(stores_map.get("personal"), Mapping) else normalized.get("knowledge_repository")
    team = stores_map.get("team") if "team" in stores_map else None
    state: dict[str, Any] = {
        "manifest_schema_version": normalized.get("schema_version"),
        "engine_root": normalized.get("engine_root"),
        "personal_knowledge_root": normalized.get("knowledge_root"),
        "knowledge_root": normalized.get("knowledge_root"),
        "runtime_root": normalized.get("runtime_root"),
        "personal": copy.deepcopy(dict(personal)) if isinstance(personal, Mapping) else None,
        "team": copy.deepcopy(dict(team)) if isinstance(team, Mapping) else None,
        "providers": copy.deepcopy(normalized.get("providers", [])),
        "organizer": copy.deepcopy(normalized.get("organizer")),
        "work_hosts": copy.deepcopy(normalized.get("work_hosts", [])),
        "privacy_profile": normalized.get("privacy_profile"),
        "sync_enabled": normalized.get("sync_enabled"),
        "experiment_enabled": normalized.get("experiment_enabled"),
        "hosts": copy.deepcopy(normalized.get("hosts", {})),
        "scheduler": {"enabled": normalized.get("scheduler_requested") is True},
    }
    managed: dict[str, Any] = {}
    target_records: dict[tuple[str, str], dict[str, Any]] = {}
    hosts = normalized.get("hosts")
    runtime_root = normalized.get("runtime_root") if isinstance(normalized.get("runtime_root"), str) else None
    if isinstance(hosts, Mapping):
        for host_id, record in hosts.items():
            if not isinstance(record, Mapping):
                continue
            for component in _managed_target_components(str(host_id), record, runtime_root=runtime_root):
                target = component["target"]
                kind = component["kind"]
                item = target_records.setdefault(
                    (target, kind),
                    {
                        "hashes": set(),
                        "host_ids": set(),
                        "managed_ids": set(),
                        "components": [],
                        "kind": kind,
                        "target": target,
                        "target_types": set(),
                    },
                )
                item["hashes"].add(component["hash"])
                item["host_ids"].add(str(host_id))
                item["managed_ids"].update(component["managed_ids"])
                item["target_types"].add(kind)
                item["components"].append(
                    {
                        "host_id": str(host_id),
                        "hash": component["hash"],
                        "kind": kind,
                        "managed_hook_ids": list(component["managed_ids"]) if kind == "hook" else [],
                    }
                )

    # One physical target/type has one ownership record.  Older manifests
    # carried a different per-host hash for a shared target, so a plain
    # first-record projection made an unchanged target appear conflicting.
    # Keep the old document untouched and normalize only this detached state:
    # union/sort owners and managed IDs, then derive the same aggregate hash
    # used by the current installer.  A target used as two different managed
    # types is retained as a conflict marker rather than silently combining
    # unrelated bytes.
    by_target: dict[str, list[dict[str, Any]]] = {}
    for (target, _kind), item in target_records.items():
        by_target.setdefault(target, []).append(item)
    for target, entries in by_target.items():
        entries.sort(key=lambda item: str(item["kind"]))
        item = entries[0]
        owner_ids = sorted({owner for entry in entries for owner in entry["host_ids"]})
        managed_ids = sorted({item_id for entry in entries for item_id in entry["managed_ids"]})
        expected_hashes = {expected for entry in entries for expected in entry["hashes"]}
        kind = str(item["kind"])
        aggregate_hash = min(expected_hashes)
        if len(expected_hashes) > 1 or len(entries) > 1:
            if len(entries) == 1 and kind == "hook":
                aggregate_hash = _managed_hook_hash(Path(target), managed_ids) or min(expected_hashes)
            else:
                # Generic pre-fix records stored one ownership digest per
                # host, while the physical target has one byte digest.  When
                # the live digest is one of those legacy values it is the
                # only safe aggregate to retain.  If none matches, retain a
                # deterministic fallback; the live-vs-planned comparison
                # below will fail closed instead of silently adopting changed
                # bytes during a read-time migration.
                live_hash = _target_live_hash(target, {"kind": kind})
                aggregate_hash = live_hash if live_hash in expected_hashes else min(expected_hashes)
        record = {
            "hash": aggregate_hash,
            "ownership_hash": aggregate_hash,
            "owned": True,
            "kind": kind,
            "host_id": owner_ids[0],
            "host_ids": owner_ids,
            "managed_hook_ids": managed_ids if kind == "hook" else [],
            "target_type": kind,
        }
        if len(entries) > 1:
            record["target_type_conflict"] = True
            record["target_types"] = sorted({str(entry["kind"]) for entry in entries})
        if len(expected_hashes) > 1:
            record["legacy_hashes"] = sorted(
                [component for entry in entries for component in entry["components"]],
                key=lambda component: (
                    component["host_id"],
                    component["kind"],
                    component["hash"],
                    component["managed_hook_ids"],
                ),
            )
        managed[target] = record
    # Keep the detached per-host projection consistent with the aggregate
    # target record as well.  Otherwise the reconciliation planner would see
    # a host update solely because a pre-fix document carried different
    # ownership hashes, even though the physical target is current.  This is
    # an in-memory projection only; the legacy manifest bytes remain untouched
    # until an actual setup update is approved.
    state_hosts = state.get("hosts")
    if isinstance(state_hosts, Mapping):
        normalized_hosts = copy.deepcopy(dict(state_hosts))
        for host_id, host_record in normalized_hosts.items():
            if not isinstance(host_record, Mapping):
                continue
            for component in _managed_target_components(str(host_id), host_record, runtime_root=runtime_root):
                target_record = managed.get(component["target"])
                hash_key = component.get("hash_key")
                if (
                    isinstance(target_record, Mapping)
                    and target_record.get("target_type_conflict") is not True
                    and isinstance(hash_key, str)
                    and not hash_key.startswith("managed:")
                    and isinstance(target_record.get("hash"), str)
                ):
                    host_record[hash_key] = target_record["hash"]
        state["hosts"] = normalized_hosts
    state["managed_targets"] = managed
    return state


def _current_setup_state(previous: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(previous, Mapping) or not previous:
        return {}
    try:
        return _manifest_state(previous)
    except (OSError, ValueError, TypeError):
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")


def _effective_team_selection(selected: SetupSelection, previous: Mapping[str, Any]) -> SetupSelection:
    """Preserve omitted team options on rerun without touching disabled roots."""

    if selected.team_knowledge is not None:
        return selected
    current = _current_setup_state(previous)
    team = current.get("team") if isinstance(current, Mapping) else None
    if isinstance(team, Mapping) and team.get("enabled") is True:
        root = team.get("root")
        member = team.get("team_member_id")
        if isinstance(root, str) and isinstance(member, str):
            return replace(selected, team_knowledge=True, team_knowledge_root=root, team_member_id=member)
    # Fresh setup and an explicitly retained disabled descriptor both remain
    # disabled.  The descriptor itself is carried by the manifest builder.
    return replace(selected, team_knowledge=False, team_knowledge_root=None, team_member_id=None)


def _team_member_continuity_notice(selected: SetupSelection, previous: Mapping[str, Any]) -> str | None:
    """Return the stable notice emitted when a retained team shard changes."""

    if selected.team_knowledge is not True:
        return None
    try:
        current = _current_setup_state(previous)
    except (OSError, TypeError, ValueError):
        return None
    team = current.get("team") if isinstance(current, Mapping) else None
    if not isinstance(team, Mapping):
        return None
    old_member = team.get("team_member_id")
    new_member = selected.team_member_id
    if isinstance(old_member, str) and isinstance(new_member, str) and old_member != new_member:
        return "TEAM_MEMBER_CONTINUITY_CHANGED"
    return None


def _organizer_for_selection(selection: SetupSelection, repo: Path) -> OrganizerSelection:
    configured = _configured_provider_ids(repo)
    if selection.organizer_provider is not None or selection.organizer_host is not None:
        return resolve_organizer(
            selection.organizer_provider,
            selection.organizer_host,
            selection.work_hosts,
            configured,
        )
    legacy = migrate_legacy_organizer(selection.providers, selection.work_hosts)
    if legacy.status == "READY" and legacy.provider_id in configured:
        return legacy
    if legacy.status == "READY":
        return OrganizerSelection("SELECTION_REQUIRED", None, None, "ORGANIZER_PROVIDER_NOT_CONFIGURED")
    return legacy


def _manifest_providers(organizer: OrganizerSelection) -> list[str]:
    if organizer.status == "READY" and organizer.provider_id is not None:
        return [organizer.provider_id]
    return []


def _desired_setup_state(selected: SetupSelection, current: Mapping[str, Any], settings: Settings) -> dict[str, Any]:
    desired = copy.deepcopy(dict(current)) if isinstance(current, Mapping) else {}
    source_skill_hash = canonical_tree_hash(_source_skill(Path(settings.paths.engine_root)))
    desired_hosts: dict[str, Any] = {}
    for host_id in selected.managed_hosts:
        host = copy.deepcopy((desired.get("hosts") or {}).get(host_id, {"runtime_root": str(settings.paths.runtime_root)}))
        host["source_skill_hash"] = source_skill_hash
        host["installed_skill_hash"] = source_skill_hash
        if host_id not in PUBLIC_CLI_HOST_IDS:
            host["profile_hash"] = settings.hosts[host_id].profile_hash
            host["profile_path"] = f"host-profiles/{host_id}.json"
        desired_hosts[host_id] = host
    personal = dict(desired.get("personal") or {})
    personal.update(
        {
            "enabled": True,
            "status": "READY",
            "mode": str(selected.knowledge_mode),
            "root": str(settings.paths.personal_knowledge_root),
            "sync_enabled": bool(selected.sync),
        }
    )
    if not personal.get("remote_name") and selected.remote_name and selected.github_repository:
        personal["remote_name"] = selected.remote_name
    organizer = _organizer_for_selection(selected, Path(settings.paths.engine_root))
    desired.update(
        {
            "manifest_schema_version": INSTALL_MANIFEST_SCHEMA_VERSION,
            "engine_root": str(settings.paths.engine_root),
            "personal_knowledge_root": str(settings.paths.personal_knowledge_root),
            "knowledge_root": str(settings.paths.personal_knowledge_root),
            "runtime_root": str(settings.paths.runtime_root),
            "personal": personal,
            "providers": _manifest_providers(organizer),
            "organizer": organizer.to_dict(),
            "work_hosts": list(selected.work_hosts),
            "privacy_profile": selected.privacy_profile,
            "sync_enabled": bool(selected.sync),
            "experiment_enabled": bool(selected.experiment),
            "hosts": desired_hosts,
            "scheduler": {"enabled": bool(selected.scheduler)},
        }
    )
    current_team = desired.get("team") if isinstance(desired.get("team"), Mapping) else None
    if selected.team_knowledge is True:
        team = dict(current_team or {})
        team.update(
            {
                "enabled": True,
                "root": str(settings.paths.team_knowledge_root),
                "team_member_id": selected.team_member_id,
                "status": "READY",
                "layout": team.get("layout", "member-writer-events-v1"),
                "transport": team.get("transport", "external-shared-folder"),
                "transport_managed": False,
            }
        )
        desired["team"] = team
    elif selected.team_knowledge is False:
        if current_team is not None:
            team = dict(current_team)
            team["enabled"] = False
            team["status"] = "DISABLED"
            desired["team"] = team
        else:
            desired["team"] = None
    desired = build_desired_state(current=desired, explicit={})
    desired["manifest_schema_version"] = INSTALL_MANIFEST_SCHEMA_VERSION
    desired["desired_state_digest"] = state_digest(desired)
    return desired


def _target_live_hash(target: str, record: Mapping[str, Any]) -> str | None:
    path = Path(target)
    if record.get("kind") == "profile":
        try:
            value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        return host_profile_hash(value) if isinstance(value, Mapping) else None
    if record.get("kind") == "skill" and path.is_symlink():
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return None
        return _dir_hash(resolved)
    if record.get("kind") == "skill" or path.is_dir():
        return _dir_hash(path)
    return _hash_path(path)


_LEGACY_TARGET_MISMATCH = "__LEGACY_COMPONENT_HASH_MISMATCH__"


def _managed_target_components(
    host_id: str,
    record: Mapping[str, Any],
    *,
    runtime_root: str | None = None,
) -> list[dict[str, Any]]:
    """Return the managed path/hash pairs carried by one host record.

    The four fields below are the schema-v8 public shape.  The small generic
    suffix scan is intentional: compatible adapters may add a managed
    ``*_path``/``*_hash`` pair without requiring reconciliation to know the
    adapter's display name.  This helper only projects detached manifest data;
    it does not write or normalize the source document.
    """

    known: tuple[tuple[str, str, str], ...] = (
        ("hook_config_path", "hook_config_hash", "hook"),
        ("context_path", "context_hash", "context"),
        ("skill_destination", "installed_skill_hash", "skill"),
        ("skill_binding_path", "skill_binding_hash", "binding"),
    )
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(path_key: str, hash_key: str, kind: str, value: Any, expected: Any, managed_ids: Any = ()) -> None:
        if not isinstance(value, str) or not value or not isinstance(expected, str):
            return
        target = value
        # Runtime profile locators are deliberately relative in the manifest;
        # the installed copy is the physical managed target.  This also keeps
        # profile binding ownership in the same detached state model as the
        # other host files.
        if path_key == "profile_path" and runtime_root is not None and not Path(target).is_absolute():
            target = str(_resolve(Path(runtime_root) / target))
        else:
            target = str(_resolve(target))
        key = (target, kind)
        if key in seen:
            return
        seen.add(key)
        ids = sorted({str(item) for item in managed_ids if isinstance(item, str)})
        components.append(
            {
                "target": target,
                "path_key": path_key,
                "hash_key": hash_key,
                "kind": kind,
                "host_id": str(host_id),
                "hash": expected,
                "managed_ids": ids,
            }
        )

    for path_key, hash_key, kind in known:
        add(path_key, hash_key, kind, record.get(path_key), record.get(hash_key), record.get("managed_hook_ids", ()) if kind == "hook" else ())

    # Custom host profile copies are machine-local managed files.  They are
    # not shared by valid schema records, but including them here prevents a
    # future adapter/profile binding from bypassing the ownership check.
    add("profile_path", "profile_hash", "profile", record.get("profile_path"), record.get("profile_hash"))

    extras = record.get("managed_targets")
    if isinstance(extras, Mapping):
        for name, value in sorted(extras.items(), key=lambda item: str(item[0])):
            if not isinstance(value, Mapping):
                continue
            path_value = value.get("path") or value.get("target")
            hash_value = value.get("hash") or value.get("ownership_hash") or value.get("expected_hash")
            raw_kind = value.get("kind") or value.get("type") or str(name)
            kind = str(raw_kind) if isinstance(raw_kind, str) and raw_kind else "file"
            add(f"managed:{name}:path", f"managed:{name}:hash", kind, path_value, hash_value, value.get("managed_ids", value.get("managed_hook_ids", ())))

    # Adapter-defined fields use a stable path/hash suffix pair.  Ignore
    # ordinary host metadata such as ``capture_primary_path`` unless its
    # corresponding digest is explicitly present.
    known_keys = {path_key for path_key, _, _ in known} | {"profile_path"}
    for path_key in sorted(record):
        if path_key in known_keys or not isinstance(path_key, str):
            continue
        if path_key.endswith("_path"):
            hash_key = path_key[:-5] + "_hash"
        elif path_key.endswith("_destination"):
            hash_key = path_key[:-12] + "_hash"
        else:
            continue
        if hash_key not in record:
            continue
        stem = path_key.rsplit("_", 1)[0].casefold()
        if "hook" in stem:
            kind = "hook"
            managed_ids = record.get("managed_hook_ids", ())
        elif "skill" in stem:
            kind = "skill"
            managed_ids = ()
        elif "binding" in stem or "profile" in stem:
            kind = "binding"
            managed_ids = ()
        elif "context" in stem:
            kind = "context"
            managed_ids = ()
        else:
            kind = "file"
            managed_ids = ()
        add(path_key, hash_key, kind, record.get(path_key), record.get(hash_key), managed_ids)
    return components


def _managed_target_type_conflict(target: str, record: Mapping[str, Any]) -> bool:
    """Return whether an existing managed target has the wrong physical type."""

    path = Path(target)
    if path.is_symlink():
        # Link-mode Skills are an explicit supported installation shape.  A
        # managed file target may not be a reparse point, but a Skill link is
        # validated by the Skill installer and remains a valid target type.
        return record.get("kind") != "skill"
    try:
        if not path.exists():
            return False
        if record.get("kind") == "skill":
            return not path.is_dir()
        return not path.is_file()
    except OSError:
        # The hash probe will report ``None`` below, which is the repair path;
        # only a positively observed wrong type is a content/ownership conflict.
        return False


def read_live_setup_state(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    inspect_team: bool | None = None,
) -> dict[str, Any]:
    """Read hashes and identities needed by the pure reconciliation planner."""

    current = _current_setup_state(previous)
    live = copy.deepcopy(current)
    live["engine_root"] = desired.get("engine_root", live.get("engine_root"))
    live["personal_knowledge_root"] = desired.get("personal_knowledge_root", live.get("personal_knowledge_root"))
    live["knowledge_root"] = desired.get("knowledge_root", live.get("knowledge_root"))
    live["runtime_root"] = desired.get("runtime_root", live.get("runtime_root"))
    runtime = Path(str(live.get("runtime_root"))) if live.get("runtime_root") else None
    if runtime is not None:
        state_path = runtime / "scheduler-state.json"
        if state_path.is_file():
            try:
                scheduler_state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                scheduler_state = None
            if isinstance(scheduler_state, Mapping):
                live["scheduler"] = {"enabled": scheduler_state.get("registered") is True, "identity": copy.deepcopy(dict(scheduler_state))}
            else:
                live["scheduler"] = {"enabled": False, "identity": None}
        elif isinstance(live.get("scheduler"), Mapping) and live["scheduler"].get("enabled") is True:
            # A manifest claiming a registered scheduler is not sufficient;
            # the machine-local receipt is the live identity source.
            live["scheduler"] = {"enabled": False, "identity": None}
    managed_live: dict[str, Any] = {}
    current_managed = current.get("managed_targets") if isinstance(current.get("managed_targets"), Mapping) else {}
    desired_managed = desired.get("managed_targets") if isinstance(desired.get("managed_targets"), Mapping) else {}
    for target, record in current_managed.items():
        if not isinstance(target, str) or not isinstance(record, Mapping):
            continue
        item = dict(record)
        target_type_conflict = record.get("target_type_conflict") is True
        target_type_conflict = target_type_conflict or _managed_target_type_conflict(target, record)
        item["hash"] = _managed_hook_hash(target, record.get("managed_hook_ids", ())) if record.get("kind") == "hook" else _target_live_hash(target, record)
        # ``current`` and ``desired`` are detached at different points in the
        # setup flow.  For a legacy record, ``_manifest_state`` derives the
        # aggregate from the bytes observed while building ``desired``.  Use
        # that aggregate as the expected content so a concurrent edit still
        # fails closed, without requiring every old per-host hash to equal the
        # one physical target hash.
        planned = desired_managed.get(target) if isinstance(desired_managed, Mapping) else None
        planned_hash = planned.get("hash") if isinstance(planned, Mapping) else None
        if (
            not target_type_conflict
            and item["hash"] is not None
            and isinstance(planned_hash, str)
            and item["hash"] != planned_hash
        ):
            target_type_conflict = True
        if target_type_conflict:
            item["hash"] = _LEGACY_TARGET_MISMATCH
        legacy_hashes = record.get("legacy_hashes")
        # Hooks have an ownership-aware projection for each managed ID set, so
        # retain their per-host verification.  Context, Skill, binding, and
        # adapter-defined file/tree targets only had a single physical byte
        # stream in the pre-fix format; distinct old hashes are expected and
        # must not be treated as a conflict merely because they differ.
        if item["hash"] is not None and item["hash"] != _LEGACY_TARGET_MISMATCH and record.get("kind") == "hook" and isinstance(legacy_hashes, list):
            for component in legacy_hashes:
                if not isinstance(component, Mapping) or not isinstance(component.get("hash"), str):
                    continue
                component_hash = _managed_hook_hash(target, component.get("managed_hook_ids", ()))
                if component_hash is not None and component_hash != component["hash"]:
                    # Keep the aggregate hash for diagnostics, but make the
                    # planner's ownership comparison fail closed when any
                    # legacy per-host projection no longer matches live data.
                    item["hash"] = _LEGACY_TARGET_MISMATCH
                    break
        managed_live[target] = item
    live["managed_targets"] = managed_live
    hosts = live.get("hosts")
    if isinstance(hosts, Mapping):
        live_hosts: dict[str, Any] = {}
        for key, value in hosts.items():
            if not isinstance(value, Mapping):
                live_hosts[key] = value
                continue
            item = {**dict(value), "runtime_root": str(live["runtime_root"])}
            binding_path = value.get("skill_binding_path")
            if isinstance(binding_path, str) and Path(binding_path).is_file():
                try:
                    binding = json.loads(Path(binding_path).read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    binding = None
                if isinstance(binding, Mapping):
                    bound_runtime = binding.get("runtime_root") or binding.get("binding_runtime_root")
                    if isinstance(bound_runtime, str):
                        item["runtime_root"] = bound_runtime
            live_hosts[key] = item
        live["hosts"] = live_hosts
    if inspect_team is None:
        desired_team = desired.get("team")
        inspect_team = not isinstance(desired_team, Mapping) or desired_team.get("enabled") is True
    team = live.get("team")
    if inspect_team and isinstance(team, Mapping) and team.get("enabled") is True:
        root = team.get("root")
        if isinstance(root, str) and Path(root).is_dir():
            try:
                descriptor = inspect_team_store(root, expected_store_id=str(team.get("store_id")) if team.get("store_id") else None)
                live["team"] = {**dict(team), "store_id": descriptor.store_id}
            except (OSError, TypeError, ValueError) as exc:
                live["team"] = {**dict(team), "live_error": str(exc) if isinstance(exc, ValueError) else "TEAM_ROOT_UNAVAILABLE"}
        else:
            live["team"] = {**dict(team), "live_error": "TEAM_ROOT_CONTRACT_INVALID"}
    return live


def _reconciliation_live_state(
    selected: SetupSelection,
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
) -> dict[str, Any]:
    """Read live state, allowing update to proceed with an offline team root.

    The reconciliation planner normally fails closed on a team ``live_error``.
    An update is the one lifecycle operation allowed to repair managed host
    files while an existing external shared folder is disconnected.  In that
    narrow case remove only the transient availability marker; malformed or
    mismatched roots remain blocking errors.
    """

    live = read_live_setup_state(previous, desired, inspect_team=selected.team_knowledge is not False)
    if not selected.defer_team_validation:
        return live
    team = live.get("team")
    if not isinstance(team, Mapping) or team.get("enabled") is not True:
        return live
    error = team.get("live_error")
    root = team.get("root")
    offline = error == "TEAM_ROOT_UNAVAILABLE" or (
        error == "TEAM_ROOT_CONTRACT_INVALID"
        and isinstance(root, str)
        and not Path(root).exists()
        and not Path(root).is_symlink()
    )
    if offline:
        retained = dict(team)
        retained.pop("live_error", None)
        live["team"] = retained
    return live


def _reconciliation_view(plan: SetupReconciliationPlan) -> dict[str, Any]:
    return {
        "status": plan.status,
        "desired_state_digest": plan.desired_state_digest,
        "live_state_digest": plan.live_state_digest,
        "actions": [item.to_dict() for item in plan.actions],
        "changed_paths": list(plan.changed_paths),
        "retained_paths": list(plan.retained_paths),
        "errors": [dict(item) for item in plan.errors],
    }


def _knowledge_stores_result(personal: Mapping[str, Any] | None, team: Mapping[str, Any] | None, *, team_status: str | None = None) -> dict[str, Any]:
    personal_view = {"status": "READY", **dict(personal or {})}
    if team is None:
        team_view: dict[str, Any] = {"status": team_status or "DISABLED", "enabled": False}
    else:
        team_view = dict(team)
        team_view["status"] = team_status or ("READY" if team_view.get("enabled") is True else "DISABLED")
    return {"personal": personal_view, "team": team_view}


def blocked_setup_result(plan: SetupReconciliationPlan, *, manifest_path: Path | None = None, knowledge_stores: Mapping[str, Any] | None = None) -> SetupResult:
    return SetupResult(
        False,
        "SETUP_BLOCKED",
        manifest_path,
        changed_paths=(),
        errors=tuple(dict(item) for item in plan.errors),
        message="Setup was blocked before any managed mutation",
        reconciliation=_reconciliation_view(plan),
        knowledge_stores=dict(knowledge_stores or {}),
    )


def check_only_setup_result(plan: SetupReconciliationPlan, *, manifest_path: Path | None = None, knowledge_stores: Mapping[str, Any] | None = None) -> SetupResult:
    return SetupResult(
        True,
        "CHECK_ONLY",
        manifest_path,
        changed_paths=(),
        message="check-only did not mutate repository, host configuration, Skill, runtime, scheduler, or Git state",
        reconciliation=_reconciliation_view(plan),
        knowledge_stores=dict(knowledge_stores or {}),
    )


def already_current_setup_result(previous: Mapping[str, Any], plan: SetupReconciliationPlan, *, manifest_path: Path | None = None, knowledge_stores: Mapping[str, Any] | None = None) -> SetupResult:
    return SetupResult(
        True,
        "SETUP_COMPLETE",
        manifest_path,
        changed_paths=(),
        message="Setup is already current; only an append-only operation receipt was recorded",
        reconciliation=_reconciliation_view(plan),
        knowledge_stores=dict(knowledge_stores or {}),
    )


def _setup_receipt_path(runtime: Path, plan: SetupReconciliationPlan) -> Path:
    return runtime / "setup-operations" / ("setup-" + plan.desired_state_digest.removeprefix("sha256:") + "-" + uuid.uuid4().hex + ".json")


def append_setup_receipt(runtime: Path, plan: SetupReconciliationPlan, *, status: str) -> Path:
    safe_ensure_directory(runtime / "setup-operations", mode=0o700)
    path = _setup_receipt_path(runtime, plan)
    receipt = {
        "schema_version": 2,
        "operation": "setup-reconciliation",
        "plan_digest": plan.desired_state_digest,
        "status": status,
        "started_at": _now().isoformat(),
        "completed_at": _now().isoformat(),
        "reconciliation": _reconciliation_view(plan),
        "changed_paths": list(plan.changed_paths),
        "retained_paths": list(plan.retained_paths),
    }
    _atomic_write(path, _json_bytes(receipt))
    return path


def _completed_knowledge_view(plan: KnowledgeSetupPlan, result: KnowledgeSetupResult) -> dict[str, Any]:
    repository = dict(result.repository)
    repository["operation_status"] = repository.get("status")
    repository["status"] = "READY" if result.ok else "NOT_READY"
    return {
        "mode": plan.selection.mode,
        "status": result.status,
        "stage": result.stage,
        "plan_digest": plan.plan_digest,
        "repository": repository,
        "remote": dict(result.remote),
        "actions": [dict(item) for item in result.actions],
        "recovery": dict(result.recovery),
        "errors": [dict(item) for item in result.errors],
    }


def _preserved_knowledge_views(
    selection: SetupSelection,
    previous: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], KnowledgeSetupResult]:
    expected = previous.get("knowledge_repository")
    if not isinstance(expected, Mapping) or expected.get("status") != "READY":
        raise ValueError("UPDATE_KNOWLEDGE_MANIFEST_INVALID")
    root = _resolve(selection.knowledge_root)
    if not isinstance(expected.get("root"), str) or _resolve(str(expected["root"])) != root:
        raise ValueError("UPDATE_KNOWLEDGE_ROOT_MISMATCH")
    status = inspect_knowledge_repository(
        root,
        engine_root=_resolve(selection.engine_root or selection.repo_root),
        runtime_root=_resolve(selection.runtime_root),
    )
    if not (status.git_initialized and status.manifest_valid and status.required_paths_present):
        raise ValueError("UPDATE_KNOWLEDGE_REPOSITORY_INVALID")
    remote_name = expected.get("remote_name")
    fingerprint = expected.get("remote_fingerprint")
    classification = expected.get("remote_classification")
    connected = expected.get("connected") is True
    if connected:
        if not isinstance(remote_name, str) or not remote_name or remote_name not in status.remote_names:
            raise ValueError("UPDATE_KNOWLEDGE_REMOTE_MISSING")
        completed = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", remote_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise ValueError("UPDATE_KNOWLEDGE_REMOTE_MISSING")
        if remote_fingerprint(completed.stdout.strip().splitlines()[0]) != fingerprint:
            raise ValueError("UPDATE_KNOWLEDGE_REMOTE_CHANGED")
    document = {
        "mode": expected.get("mode"),
        "root": str(root),
        "remote_name": remote_name,
        "remote_fingerprint": fingerprint,
        "remote_classification": classification,
        "branch": expected.get("branch"),
        "connected": connected,
        "initial_push_complete": expected.get("initial_push_complete") is True,
        "sync_enabled": expected.get("sync_enabled") is True,
        "root_digest": status.root_digest,
    }
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plan_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    remote = {
        "repository": None,
        "remote_name": remote_name,
        "fingerprint": fingerprint,
        "classification": classification,
        "branch": expected.get("branch"),
        "connected": connected,
        "initial_push_complete": expected.get("initial_push_complete") is True,
    }
    repository = {
        "root": str(root),
        "status": "ALREADY_CURRENT",
        "git_initialized": status.git_initialized,
        "root_digest": status.root_digest,
    }
    action = {
        "kind": "reuse-existing",
        "target": str(root),
        "status": "COMPLETED",
        "completed_at": _now().isoformat(),
    }
    stage = "INITIAL_PUSH_VERIFIED" if connected else "KNOWLEDGE_LOCAL_READY"
    result = KnowledgeSetupResult(
        ok=True,
        status="COMPLETE",
        stage=stage,
        repository=repository,
        remote=remote,
        actions=(action,),
        recovery={"retryable": False, "resume_stage": None, "external_repository_retained": connected, "command": None},
    )
    plan = {
        "selection": {key: value for key, value in document.items() if key != "root_digest"},
        "actions": [{"kind": "reuse-existing", "target": str(root), "mutates": False, "details": {"root_digest": status.root_digest}}],
        "remote_fingerprint": fingerprint,
        "plan_digest": plan_digest,
    }
    planned = {
        "mode": expected.get("mode"),
        "status": "PLANNED",
        "stage": "PLANNED",
        "plan": plan,
        "repository": {**repository, "status": "PLANNED"},
        "remote": remote,
        "errors": [],
    }
    completed_view = {
        "mode": expected.get("mode"),
        "status": result.status,
        "stage": result.stage,
        "plan_digest": plan_digest,
        "repository": {**repository, "operation_status": "ALREADY_CURRENT", "status": "READY"},
        "remote": remote,
        "actions": [action],
        "recovery": dict(result.recovery),
        "errors": [],
    }
    return planned, completed_view, result


def _sync_view(selection: SetupSelection, knowledge: Mapping[str, Any]) -> dict[str, Any]:
    remote = knowledge.get("remote") if isinstance(knowledge.get("remote"), Mapping) else {}
    return {
        "enabled": selection.sync,
        "remote_name": remote.get("remote_name"),
        "branch": remote.get("branch"),
        "connected": remote.get("connected") is True,
        "assurance": remote.get("classification"),
        "status": "CONNECTED" if remote.get("connected") is True else "DISABLED" if not selection.sync else "NOT_CONNECTED",
    }


def _manifest_path(runtime: Path) -> Path:
    return runtime / "install-manifest.json"


def _build_host_migration_receipt(migrations: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Create the explicit, path-free receipt for a legacy host selection.

    The receipt is deliberately written to machine-local runtime state.  It
    records the user-visible migration decision without copying old host
    configuration or any transcript data into the knowledge repository.
    """
    entries = [
        {
            "from_host_id": str(item.get("from_host_id", "")),
            "to_host_id": str(item.get("to_host_id")) if item.get("to_host_id") else None,
            "status": str(item.get("status", "UNSUPPORTED")),
            "reason_code": str(item.get("reason_code", "HOST_UNSUPPORTED")),
        }
        for item in migrations
        if isinstance(item, Mapping) and str(item.get("from_host_id", ""))
    ]
    if not entries:
        return None
    entries.sort(key=lambda item: (item["from_host_id"], str(item["to_host_id"] or "")))
    basis = {
        "schema_version": 1,
        "receipt_type": "legacy-host-selection-migration",
        "status": "MIGRATED",
        "entries": entries,
    }
    return {
        **basis,
        "generated_at": _now().isoformat(),
        "receipt_sha256": _sha256(_json_bytes(basis)),
    }


def _previous_manifest(runtime: Path) -> dict[str, Any]:
    path = _manifest_path(runtime)
    return _read_json(path, {}) if path.is_file() else {}


def _previous_manifest_for_selection(runtime: Path, selection: SetupSelection, repo: Path) -> dict[str, Any]:
    """Find a prior instance when an explicit runtime path was moved.

    The scan is deliberately bounded to configured host defaults and the
    runtime's immediate parent.  A candidate is accepted only when its engine
    and personal roots match, so an unrelated installation cannot be adopted.
    """

    current = _previous_manifest(runtime)
    if current:
        return current
    candidates: set[Path] = set()
    for home in (selection.host_homes or {}).values():
        candidates.add(_resolve(home) / "external-intelligence" / "install-manifest.json")
    parent = runtime.parent
    try:
        if parent.is_dir():
            candidates.update(child / "install-manifest.json" for child in parent.iterdir() if child.is_dir())
    except OSError:
        return {}
    expected_engine = _resolve(repo)
    expected_personal = _resolve(selection.personal_knowledge_root or selection.knowledge_root)
    for candidate in sorted(candidates, key=str):
        if candidate == _manifest_path(runtime) or not candidate.is_file():
            continue
        try:
            value = _read_json(candidate, {})
            if value.get("status") != "INSTALLED":
                continue
            if _resolve(str(value.get("engine_root"))) != expected_engine:
                continue
            if _resolve(str(value.get("knowledge_root"))) != expected_personal:
                continue
            return value
        except (OSError, TypeError, ValueError):
            continue
    return {}


def _hook_template_hash(repo: Path, host_id: str, runtime_root: Path | None = None) -> str:
    if host_id in HOST_TEMPLATE_NAMES:
        return _sha256(_template_for(repo, host_id).read_bytes())
    if runtime_root is None:
        raise ValueError("HOST_PROFILE_RUNTIME_INVALID")
    profile = _resolve(runtime_root) / "host-profiles" / f"{host_id}.json"
    return _hash_path(profile) or ""


def _profile_change_specs(
    selection: SetupSelection,
    previous: Mapping[str, Any] | None,
    runtime: Path,
) -> list[dict[str, Any]]:
    """Plan profile files without writing them.

    The returned descriptors are consumed by both the check-only plan and the
    approved transaction.  Every custom host has one deterministic locator;
    stale managed profiles are removed only after their manifest hash matches.
    """

    runtime = _resolve(runtime)
    profile_sources = _profile_sources_for_selection(selection)
    documents: dict[str, dict[str, Any]] = {}
    for profile_path in selection.host_profiles:
        document = read_host_profile_document(profile_path)
        host_id = document.get("host_id")
        if isinstance(host_id, str):
            documents[host_id] = document
    for host_id, document in (selection.host_profile_documents or {}).items():
        if host_id in documents:
            raise ValueError("HOST_PROFILE_DUPLICATE")
        documents[host_id] = dict(document)
    changes: list[dict[str, Any]] = []
    desired_ids = set(profile_sources)
    previous_hosts = previous.get("hosts") if isinstance(previous, Mapping) and isinstance(previous.get("hosts"), Mapping) else {}
    for host_id, (profile, profile_digest) in profile_sources.items():
        target = runtime / "host-profiles" / f"{host_id}.json"
        document = documents.get(host_id)
        if not isinstance(document, Mapping):
            raise ValueError("HOST_PROFILE_INVALID")
        if host_profile_hash(document) != profile_digest:
            raise ValueError("HOST_PROFILE_SOURCE_CHANGED")
        raw = host_profile_bytes(document)
        before_hash = _hash_path(target)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
        previous_record = previous_hosts.get(host_id) if isinstance(previous_hosts, Mapping) else None
        if previous_record is not None and (
            not isinstance(previous_record, Mapping)
            or previous_record.get("profile_path") != f"host-profiles/{host_id}.json"
        ):
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        if target.is_file():
            current_document = read_host_profile_document(target)
            current_profile = load_host_profile(target, dict(selection.host_homes or {})[host_id])
            if target.stem != current_profile.host_id or current_profile.host_id != host_id:
                raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
            current_profile_digest = host_profile_hash(current_document)
            if isinstance(previous_record, Mapping) and current_profile_digest != previous_record.get("profile_hash"):
                raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
            if current_profile_digest != profile_digest:
                action = "update"
            else:
                action = "unchanged"
        else:
            action = "create"
        changes.append(
            {
                "target": target,
                "raw": raw,
                "action": action,
                "before_hash": before_hash,
                "after_hash": _sha256(raw),
                "details": {"kind": "host-profile", "host_id": host_id, "profile_hash": profile_digest, "profile_path": f"host-profiles/{host_id}.json"},
                "remove": False,
            }
        )

    for host_id, record in sorted(previous_hosts.items(), key=lambda item: str(item[0])):
        if host_id in PUBLIC_CLI_HOST_IDS or host_id in desired_ids or not is_custom_host_id(host_id):
            continue
        if not isinstance(record, Mapping) or record.get("profile_path") != f"host-profiles/{host_id}.json":
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        target = runtime / "host-profiles" / f"{host_id}.json"
        if target.is_symlink() or not target.is_file():
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        current_document = read_host_profile_document(target)
        try:
            current_profile = load_host_profile(target, runtime)
        except ValueError as exc:
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH") from exc
        if target.stem != current_profile.host_id or current_profile.host_id != host_id:
            raise ValueError("HOST_PROFILE_LOCATOR_INVALID")
        current_hash = host_profile_hash(current_document)
        if current_hash != record.get("profile_hash"):
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        changes.append(
            {
                "target": target,
                "raw": b"",
                "action": "remove",
                "before_hash": _hash_path(target),
                "after_hash": None,
                "details": {"kind": "host-profile-remove", "host_id": host_id, "profile_hash": current_hash, "profile_path": f"host-profiles/{host_id}.json"},
                "remove": True,
            }
        )
    return changes


def _apply_profile_changes(
    changes: Sequence[Mapping[str, Any]],
    transaction: _Transaction,
) -> tuple[list[InstallPlanItem], list[Path], list[Path]]:
    plans: list[InstallPlanItem] = []
    changed: list[Path] = []
    backups: list[Path] = []
    for change in changes:
        target = _resolve(change["target"])
        action = str(change.get("action", "unchanged"))
        before = _hash_path(target)
        if before != change.get("before_hash"):
            raise ValueError("HOST_PROFILE_PLAN_STALE")
        if bool(change.get("remove")):
            if before is None:
                raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
            backup = transaction.remove_file(target, expected_hash=before, details=change.get("details"))
            after = _hash_path(target)
            action = "remove"
        elif action in {"create", "update"}:
            raw = change.get("raw")
            if not isinstance(raw, bytes):
                raise ValueError("HOST_PROFILE_INVALID")
            backup = transaction.mutate_file(target, raw, details=change.get("details"))
            after = _hash_path(target)
        else:
            backup = None
            after = before
        plans.append(InstallPlanItem(target, action, before, after, backup, change.get("details", {})))
        if before != after:
            changed.append(target)
        if backup:
            backups.append(backup)
    return plans, changed, backups


def _hook_schema_hash(repo: Path) -> str | None:
    path = _resolve(repo) / "schemas" / "hook-event.schema.json"
    return _hash_path(path)


def _build_target_contents(
    selection: SetupSelection,
    settings: Settings,
    repo: Path,
    python_exe: Path,
    source_skill: Path,
    *,
    prune_hook_ids: Mapping[Path, set[str]] | None = None,
) -> tuple[list[tuple[Path, bytes, dict[str, Any]]], set[str]]:
    targets: list[tuple[Path, bytes, dict[str, Any]]] = []
    hook_fragments, managed_ids = _hook_targets(settings, tuple(selection.managed_hosts), repo, python_exe)
    hook_owners = _hook_target_ownership(selection, settings, repo, python_exe)
    if any(host_id in CODEX_SETTINGS_HOST_IDS for host_id in selection.managed_hosts):
        config_path = settings.paths.config_path
        existing, _ = _load_text(config_path)
        targets.append((config_path, merge_config_toml(existing).encode("utf-8"), {"kind": "codex-config", "hosts": [item for item in selection.managed_hosts if item in CODEX_SETTINGS_HOST_IDS]}))
    for target, fragment in sorted(hook_fragments.items(), key=lambda item: str(item[0])):
        existing = _read_json(target, {"hooks": {}})
        merged = merge_hooks(existing, fragment)
        stale_ids = prune_hook_ids.get(target, set()) if isinstance(prune_hook_ids, Mapping) else set()
        if stale_ids:
            # The merged bytes are the one final operation for a retained
            # shared hook.  Remove stale owners before writing, rather than
            # mutating the same physical target once for the build and again
            # for the owner-removal pass.
            merged = remove_managed_hooks(merged, stale_ids)
        owners = hook_owners.get(target, {})
        merged = _canonicalize_managed_hook_order(merged, owners.get("managed_hook_ids", managed_ids))
        style = _text_style(target.read_bytes()) if target.exists() else "\n"
        targets.append(
            (
                target,
                _json_bytes(merged, style),
                {
                    "kind": "hook-config",
                    "hosts": sorted(owners.get("host_ids", ())),
                    "managed_hook_ids": sorted(owners.get("managed_hook_ids", managed_ids)),
                },
            )
        )
    seen_context: set[Path] = set()
    for host_id in selection.managed_hosts:
        host = settings.hosts[host_id]
        context_path = _resolve(host.global_context_path)
        owners = [
            item
            for item in selection.managed_hosts
            if _resolve(settings.hosts[item].global_context_path) == context_path
        ]
        if context_path in seen_context:
            continue
        context_owner_id = min(owners) if owners else host_id
        context_owner = settings.hosts[context_owner_id]
        destination = _resolve(context_owner.skill_roots[0]) / source_skill.name
        context_template_host = context_owner_id if context_owner_id in HOST_TEMPLATE_NAMES else context_owner.adapter_id
        rendered = render_managed_context(
            context_template_host,
            python_exe,
            repo,
            settings.paths.runtime_root,
            destination,
            settings.paths.knowledge_root,
            personal_knowledge_root=settings.paths.personal_knowledge_root,
            team_knowledge_root=settings.paths.team_knowledge_root,
        )
        existing, style = _load_text(context_path)
        merged = merge_managed_context(context_path, rendered).content
        if style != "\n":
            merged = merged.replace("\n", style)
        targets.append((context_path, merged.encode("utf-8"), {"kind": "managed-context", "host_id": context_owner_id, "hosts": sorted(owners), "skill_destination": str(destination)}))
        seen_context.add(context_path)
    return targets, managed_ids


def render_install_plan(
    selection: SetupSelection | Mapping[str, Any],
    previous: Mapping[str, Any] | None = None,
    profile_changes: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[InstallPlanItem, ...]:
    selected = _normalise_selection(selection)
    repo = _resolve(selected.engine_root or selected.repo_root)
    settings = _settings_for_selection(selected)
    python = absolute_path(selected.python_exe or sys.executable)
    source = _source_skill(repo)
    targets, managed_ids = _build_target_contents(selected, settings, repo, python, source)
    plans: list[InstallPlanItem] = []
    profile_specs = list(profile_changes) if profile_changes is not None else _profile_change_specs(selected, previous or {}, _resolve(selected.runtime_root))
    for change in profile_specs:
        plans.append(
            InstallPlanItem(
                _resolve(change["target"]),
                str(change.get("action", "unchanged")),
                change.get("before_hash"),
                change.get("after_hash"),
                None,
                change.get("details", {}),
            )
        )
    for target, raw, details in targets:
        plans.append(InstallPlanItem(_resolve(target), "create" if not target.exists() else "update", _hash_path(target), _sha256(raw), None, details))
    source_hash = canonical_tree_hash(source)
    seen_skill_destinations: set[Path] = set()
    seen_binding_targets: set[Path] = set()
    for host_id in selected.managed_hosts:
        destination = _resolve(settings.hosts[host_id].skill_roots[0]) / source.name
        if destination not in seen_skill_destinations:
            plans.append(InstallPlanItem(destination, "skill-link" if selected.skill_mode == "link" else "skill-copy", _dir_hash(destination), source_hash, None, {"host_id": host_id, "mode": selected.skill_mode, "source_hash": source_hash}))
            seen_skill_destinations.add(destination)
        binding_target = destination.parent / SKILL_BINDING_NAME
        if binding_target not in seen_binding_targets:
            plans.append(InstallPlanItem(binding_target, "create-or-update", _hash_path(binding_target), None, None, {"host_id": host_id, "kind": "skill-binding"}))
            seen_binding_targets.add(binding_target)
    runtime = _resolve(selected.runtime_root)
    organizer = _organizer_for_selection(selected, repo)
    plans.append(InstallPlanItem(_manifest_path(runtime), "create-or-update", _hash_path(_manifest_path(runtime)), None, None, {"hosts": list(selected.managed_hosts), "work_hosts": list(selected.work_hosts), "organizer_provider": organizer.provider_id, "organizer_host": organizer.host_id, "managed_hook_ids": sorted(managed_ids), "providers": _manifest_providers(organizer), "privacy_profile": selected.privacy_profile, "sync": selected.sync, "experiment": selected.experiment, "scheduler": selected.scheduler, "scheduler_task_name": "CodexExternalIntelligenceMaintenance-v1"}))
    migration = _build_host_migration_receipt(selected.legacy_host_migrations)
    if migration is not None:
        migration_path = runtime / "host-migration-receipt.json"
        migration_raw = _json_bytes(migration)
        plans.append(InstallPlanItem(migration_path, "create-or-update", _hash_path(migration_path), _sha256(migration_raw), None, {"kind": "legacy-host-migration", "from_host_ids": [item["from_host_id"] for item in migration["entries"]], "to_host_ids": [item["to_host_id"] for item in migration["entries"] if item["to_host_id"]]}))
    return tuple(plans)


def _ensure_venv(selection: SetupSelection, python: Path) -> tuple[Path, bool]:
    if selection.skip_venv:
        return absolute_path(python), False
    repo = _resolve(selection.engine_root or selection.repo_root)
    venv = repo / ".venv"
    runtime = _resolve(selection.runtime_root)
    isolated_environment = os.environ.copy()
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONEXECUTABLE", "__PYVENV_LAUNCHER__"):
        isolated_environment.pop(key, None)
    isolated_environment.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
    )
    try:
        assert_safe_target(repo, venv, allow_missing=True)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    executable = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    created = not executable.is_file()
    if created:
        subprocess.run([str(python), "-m", "venv", str(venv)], env=isolated_environment, check=True)
        try:
            assert_safe_target(repo, venv, allow_missing=False, expected_type="dir")
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
    if not executable.is_file():
        raise ValueError("VENV_PYTHON_MISSING")
    lock = repo / "requirements-runtime.lock"
    purelib_result = subprocess.run(
        [str(executable), "-B", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=venv,
        env=isolated_environment,
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    purelib = _resolve(purelib_result.stdout.strip())
    try:
        assert_safe_target(venv, purelib, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("VENV_PURELIB_INVALID") from exc
    source_root = repo / "src"
    package_init = source_root / "ei" / "__init__.py"
    if not package_init.is_file():
        raise ValueError("ENGINE_PACKAGE_MISSING")
    bootstrap = purelib / "portable_external_intelligence_source.pth"
    relative_source = os.path.relpath(source_root.resolve(), purelib)
    lock_hash = _hash_path(lock) if lock.is_file() else None
    bootstrap_hash = _hash_path(bootstrap)
    bootstrap_state_path = runtime / "venv-bootstrap-state.json"
    bootstrap_state: Mapping[str, Any] = {}
    if bootstrap_state_path.is_file():
        try:
            loaded_state = json.loads(bootstrap_state_path.read_text(encoding="utf-8"))
            if isinstance(loaded_state, Mapping):
                bootstrap_state = loaded_state
        except (OSError, UnicodeError, json.JSONDecodeError):
            bootstrap_state = {}
    same_bootstrap = (
        not created
        and bootstrap_hash is not None
        and bootstrap_state.get("python_exe") == str(executable.resolve())
        and bootstrap_state.get("runtime_lock_sha256") == lock_hash
        and bootstrap_state.get("source_pth_sha256") == bootstrap_hash
    )
    if lock.is_file() and not same_bootstrap:
        subprocess.run(
            [str(executable), "-m", "pip", "install", "--disable-pip-version-check", "--requirement", str(lock)],
            env=isolated_environment,
            check=True,
        )
    try:
        bootstrap_raw = (relative_source + "\n").encode("ascii")
        if not bootstrap.is_file() or bootstrap.read_bytes() != bootstrap_raw:
            safe_atomic_write(venv, bootstrap, bootstrap_raw)
    except SafeFilesystemError as exc:
        raise ValueError("VENV_SOURCE_BOOTSTRAP_FAILED") from exc
    bootstrap_hash = _hash_path(bootstrap)
    try:
        safe_ensure_directory(runtime, mode=0o700)
        state_raw = _json_bytes(
            {
                "schema_version": 1,
                "python_exe": str(executable.resolve()),
                "runtime_lock_sha256": lock_hash,
                "source_pth_sha256": bootstrap_hash,
            }
        )
        if not bootstrap_state_path.is_file() or bootstrap_state_path.read_bytes() != state_raw:
            _atomic_write(bootstrap_state_path, state_raw)
    except (OSError, SafeFilesystemError) as exc:
        raise ValueError("VENV_BOOTSTRAP_STATE_WRITE_FAILED") from exc
    import_result = subprocess.run(
        [str(executable), "-B", "-c", "import pathlib, ei; print(pathlib.Path(ei.__file__).resolve())"],
        cwd=venv,
        env=isolated_environment,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    imported = _resolve(import_result.stdout.strip()) if import_result.returncode == 0 and import_result.stdout.strip() else None
    if imported != package_init.resolve():
        raise ValueError("VENV_SOURCE_IMPORT_FAILED")
    return absolute_path(executable), created


def _make_runtime_dirs(runtime: Path) -> None:
    safe_ensure_directory(runtime, mode=0o700)
    for name in RUNTIME_DIRECTORY_NAMES:
        path = runtime / name
        safe_ensure_directory(path, mode=0o700)


def _skill_binding(
    host_id: str,
    result: SkillInstallResult,
    settings: Settings,
    python: Path,
) -> tuple[Path, bytes]:
    destination = absolute_path(result.destination)
    target = destination.parent / SKILL_BINDING_NAME
    payload = {
        "schema_version": 2,
        "host_id": host_id,
        "engine_root": str(settings.paths.engine_root),
        "personal_knowledge_root": str(settings.paths.personal_knowledge_root),
        "team_knowledge_root": str(settings.paths.team_knowledge_root) if settings.paths.team_knowledge_root is not None else None,
        "knowledge_root": str(settings.paths.knowledge_root),
        "runtime_root": str(settings.paths.runtime_root),
        "python_exe": str(absolute_path(python)),
        "skill_destination": str(destination),
        "installed_skill_hash": result.installed_hash,
    }
    return target, _json_bytes(payload)


def _build_manifest(
    selection: SetupSelection,
    settings: Settings,
    repo: Path,
    python: Path,
    source: Path,
    skill_results: Mapping[str, SkillInstallResult],
    skill_bindings: Mapping[str, Mapping[str, str]],
    managed_ids: set[str],
    tx: _Transaction,
    previous: Mapping[str, Any],
    venv_created: bool,
    knowledge: KnowledgeSetupResult,
    team_store: Mapping[str, Any] | None = None,
    desired_state_digest: str | None = None,
) -> dict[str, Any]:
    hosts: dict[str, Any] = {}
    host_managed_ids = {
        host_id: _managed_hook_ids_for_host(selection, settings, repo, python, host_id)
        for host_id in selection.managed_hosts
    }
    for host_id in selection.managed_hosts:
        host = settings.hosts[host_id]
        result = skill_results[host_id]
        binding = skill_bindings[host_id]
        context = _resolve(host.global_context_path)
        hook_path = _resolve(settings.paths.hooks_path if host_id in CODEX_SETTINGS_HOST_IDS else host.hook_config_path)
        configured_home = dict(selection.host_homes or {}).get(host_id)
        host_record = {
            "host_id": host_id,
            "home": str(_resolve(configured_home)) if host_id not in PUBLIC_CLI_HOST_IDS and configured_home is not None else str(_resolve(host.hook_config_path.parent)),
            "hook_config_path": str(hook_path),
            "context_path": str(context),
            "skill_destination": str(result.destination),
            "skill_root": str(absolute_path(result.destination).parent),
            "skill_mode": result.mode,
            "source_skill_hash": result.source_hash,
            "installed_skill_hash": result.installed_hash,
            "skill_binding_path": binding["path"],
            "skill_binding_hash": binding["hash"],
            "hook_config_hash": _managed_hook_hash(hook_path, sorted(host_managed_ids[host_id])),
            "hook_template_hash": _hook_template_hash(repo, host_id, settings.paths.runtime_root),
            "context_hash": _hash_path(context),
            "skill_activation_mode": host.skill_activation_mode,
            "capture_primary_path": host.capture_primary_path,
            "managed_hook_ids": sorted(host_managed_ids[host_id]),
        }
        if host_id not in PUBLIC_CLI_HOST_IDS:
            host_record["profile_hash"] = host.profile_hash
            host_record["profile_path"] = f"host-profiles/{host_id}.json"
        hosts[host_id] = host_record
    # A shared physical hook file has one ownership hash: it covers the
    # merged managed entries for every selected owner.  Keep per-host ID
    # lists above for safe staged removal, but make all records point at the
    # same aggregate hash so reconciliation can compare one target once.
    hook_owner_ids: dict[Path, set[str]] = {}
    for host_id, record in hosts.items():
        target = record.get("hook_config_path")
        if not isinstance(target, str) or not target:
            continue
        target_path = _resolve(target)
        hook_owner_ids.setdefault(target_path, set()).update(
            item for item in record.get("managed_hook_ids", ()) if isinstance(item, str)
        )
    for target, owner_ids in hook_owner_ids.items():
        aggregate_hash = _managed_hook_hash(target, sorted(owner_ids))
        if aggregate_hash is None:
            # Preserve a nullable hash for a missing target; validation and
            # the live probe will then request a repair rather than claiming
            # that an absent file is current.
            aggregate_hash = None
        for record in hosts.values():
            if _resolve(str(record.get("hook_config_path", ""))) == target:
                record["hook_config_hash"] = aggregate_hash
    file_backups = {str(entry.get("target")): entry.get("backup_path") for entry in tx.entries if entry.get("kind") == "file" and entry.get("backup_path")}
    config_backup = next((value for target, value in file_backups.items() if target.endswith("config.toml")), None)
    hook_backups = [value for target, value in file_backups.items() if target.endswith("hooks.json") or target.endswith("settings.json")]
    context_backups = [value for target, value in file_backups.items() if target.endswith(("AGENTS.md", "CLAUDE.md", "GEMINI.md", "QWEN.md"))]
    codex_record = hosts.get("codex-cli") or hosts.get("codex-app") or {}
    agents_target = str(codex_record.get("context_path", ""))
    agents_installed_hash = _hash_path(Path(agents_target)) if agents_target else previous.get("agents_installed_sha256")
    config_backup = config_backup or previous.get("config_backup")
    hook_backup = hook_backups[0] if hook_backups else previous.get("hooks_backup")
    agents_backup = context_backups[0] if context_backups else previous.get("agents_backup")
    agents_original = (_hash_path(Path(agents_backup)) if agents_backup and Path(str(agents_backup)).is_file() else previous.get("agents_original_sha256"))
    remote = dict(knowledge.remote)
    knowledge_repository = {
        "status": "READY",
        "mode": str(selection.knowledge_mode),
        "root": str(settings.paths.knowledge_root),
        "remote_name": remote.get("remote_name"),
        "remote_fingerprint": remote.get("fingerprint"),
        "remote_classification": remote.get("classification"),
        "branch": remote.get("branch"),
        "connected": remote.get("connected") is True,
        "initial_push_complete": remote.get("initial_push_complete") is True,
        "sync_enabled": selection.sync,
    }
    personal_store = {"enabled": True, **knowledge_repository}
    if team_store is None:
        previous_stores = previous.get("knowledge_stores") if isinstance(previous, Mapping) else None
        previous_team = previous_stores.get("team") if isinstance(previous_stores, Mapping) else None
        if isinstance(previous_team, Mapping) and previous_team.get("enabled") is not True and selection.team_knowledge is False:
            team_store = dict(previous_team)
            team_store["enabled"] = False
            team_store["status"] = "DISABLED"
    organizer = _organizer_for_selection(selection, repo)
    manifest = {
        "schema_version": INSTALL_MANIFEST_SCHEMA_VERSION,
        "status": "INSTALLED",
        "installed_at": previous.get("installed_at", _now().isoformat()),
        "repo_root": str(repo),
        "engine_root": str(settings.paths.engine_root),
        "knowledge_root": str(settings.paths.knowledge_root),
        "runtime_root": str(settings.paths.runtime_root),
        "root_ownership": {
            "engine_root": "public-source-read-only",
            "knowledge_root": "private-knowledge-git-or-local",
            "runtime_root": "machine-local-git-forbidden",
        },
        "supported_hosts": list(PUBLIC_CLI_HOST_IDS),
        "hosts": hosts,
        "organizer": organizer.to_dict(),
        "work_hosts": list(selection.work_hosts),
        "legacy_host_migrations": [dict(item) for item in selection.legacy_host_migrations],
        "managed_marker": {"begin": BEGIN_MARKER, "end": END_MARKER, "version": "v1"},
        "managed_hook_ids": sorted(managed_ids),
        "providers": _manifest_providers(organizer),
        "privacy_profile": selection.privacy_profile,
        "sync_enabled": selection.sync,
        "experiment_enabled": selection.experiment,
        "scheduler_requested": selection.scheduler,
        "skill_source": str(source),
        "skill_source_hash": canonical_tree_hash(source),
        "hook_schema_hash": _hook_schema_hash(repo),
        "skip_venv": selection.skip_venv,
        "venv_created": bool(venv_created or previous.get("venv_created") is True),
        "python_exe": str(python),
        "transaction_id": tx.transaction_id,
        "agents_block_version": "v1",
        "config_backup": config_backup,
        "hooks_backup": hook_backup,
        "agents_backup": agents_backup,
        "agents_original_sha256": agents_original,
        "agents_installed_sha256": agents_installed_hash,
        "knowledge_repository": knowledge_repository,
        "knowledge_stores": {"personal": personal_store, "team": dict(team_store) if isinstance(team_store, Mapping) else None},
        "reconciliation": {"desired_state_digest": desired_state_digest or state_digest({"engine_root": str(repo), "personal_knowledge_root": str(settings.paths.personal_knowledge_root), "runtime_root": str(settings.paths.runtime_root), "team": dict(team_store) if isinstance(team_store, Mapping) else None})},
    }
    return manifest


def _setup_scheduler(settings: Settings, python: Path, requested: bool) -> dict[str, Any]:
    if not requested:
        return {"ok": True, "requested": False, "status": "NOT_REQUESTED", "registered": False, "retryable": False}
    from .task_scheduler import build_maintenance_action, register_scheduler
    try:
        action = build_maintenance_action(settings, python)
        return register_scheduler(settings, action, settings.paths.engine_root)
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        return {
            "ok": False,
            "requested": True,
            "status": "REGISTRATION_FAILED",
            "reason_code": str(exc) if isinstance(exc, ValueError) else "SCHEDULER_REGISTRATION_FAILED",
            "registered": False,
            "retryable": True,
        }


def prepare_personal_store(plan: KnowledgeSetupPlan, runtime: Path | None = None, transaction: _Transaction | None = None) -> KnowledgeSetupResult:
    """Prepare the existing personal repository without touching host files."""

    del runtime, transaction
    if not isinstance(plan, KnowledgeSetupPlan):
        raise ValueError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
    return apply_knowledge_setup(plan)


def prepare_or_validate_team_store(
    selection: SetupSelection,
    previous: Mapping[str, Any] | None = None,
    runtime: Path | None = None,
    transaction: _Transaction | None = None,
    *,
    check_only: bool = False,
) -> dict[str, Any] | None:
    """Create/reuse an enabled team store, or preserve a disabled descriptor.

    The disabled branch intentionally never stats or opens the retained root.
    """

    del transaction
    previous = previous if isinstance(previous, Mapping) else {}
    previous_state = _current_setup_state(previous)
    previous_team = previous_state.get("team") if isinstance(previous_state.get("team"), Mapping) else None
    if selection.team_knowledge is not True:
        if previous_team is None:
            return None
        retained = dict(previous_team)
        retained["enabled"] = False
        retained["status"] = "DISABLED"
        return retained
    root = selection.team_knowledge_root
    member_id = selection.team_member_id
    if root is None:
        raise ValueError("TEAM_ROOT_REQUIRED")
    if member_id is None:
        raise ValueError("TEAM_MEMBER_ID_REQUIRED")
    root = _resolve(root)
    expected_store_id = str(previous_team.get("store_id")) if isinstance(previous_team, Mapping) and previous_team.get("store_id") else None
    if check_only:
        # Only inspect an existing root.  A missing root is a planned create;
        # check-only must not create a directory, manifest, or writer identity.
        if root.exists():
            descriptor = inspect_team_store(root, expected_store_id=expected_store_id)
            store_id = descriptor.store_id
            writer_id = str(previous_team.get("writer_id")) if isinstance(previous_team, Mapping) and previous_team.get("writer_id") else None
        else:
            store_id = expected_store_id
            writer_id = str(previous_team.get("writer_id")) if isinstance(previous_team, Mapping) and previous_team.get("writer_id") else None
        return {
            "enabled": True,
            "root": str(root),
            "store_id": store_id,
            "layout": "member-writer-events-v1",
            "team_member_id": member_id,
            "writer_id": writer_id,
            "transport": "external-shared-folder",
            "transport_managed": False,
            "status": "PLANNED",
        }
    # An update must be able to repair managed files while an externally
    # mounted shared folder is offline.  Keep the previously validated
    # descriptor byte-for-byte in that case and let the operation result carry
    # the deferred validation status.  A present but malformed root still
    # fails closed and is never silently replaced.
    if selection.defer_team_validation and isinstance(previous_team, Mapping) and previous_team.get("enabled") is True and not root.exists() and not root.is_symlink():
        retained = dict(previous_team)
        retained["enabled"] = True
        retained["status"] = "READY"
        retained["_validation_deferred"] = True
        return retained
    descriptor = initialize_team_store(root, expected_store_id=expected_store_id)
    runtime_root = _resolve(runtime or selection.runtime_root)
    writer_id = load_or_create_writer_identity(runtime_root, descriptor.store_id)
    return {
        "enabled": True,
        "root": str(descriptor.root),
        "store_id": descriptor.store_id,
        "layout": descriptor.layout,
        "team_member_id": member_id,
        "writer_id": writer_id,
        "transport": "external-shared-folder",
        "transport_managed": False,
        "status": "READY",
    }


def apply_owned_host_actions(
    selected: SetupSelection,
    settings: Settings,
    repo: Path,
    python: Path,
    source: Path,
    previous: Mapping[str, Any],
    transaction: _Transaction,
) -> tuple[list[InstallPlanItem], list[Path], list[Path], dict[str, SkillInstallResult], dict[str, dict[str, str]], set[str]]:
    """Apply managed host additions/updates and remove only owned old hosts."""

    result_plans: list[InstallPlanItem] = []
    changed: list[Path] = []
    backups: list[Path] = []

    previous_hosts = previous.get("hosts") if isinstance(previous, Mapping) and isinstance(previous.get("hosts"), Mapping) else {}
    previous_managed = _current_setup_state(previous).get("managed_targets", {}) if previous else {}

    removed_hosts = sorted(set(previous_hosts) - set(selected.managed_hosts)) if isinstance(previous_hosts, Mapping) else []

    # Build the complete old ownership graph before mutating anything.  A
    # shared physical target must be reconciled once against its final owner
    # set; walking removed hosts one at a time would remove the same target,
    # then compare the already-mutated bytes against the old aggregate hash.
    removal_groups: dict[tuple[str, str], dict[str, Any]] = {}
    if isinstance(previous_hosts, Mapping):
        for raw_host_id, raw_record in previous_hosts.items():
            host_id = str(raw_host_id)
            if not isinstance(raw_record, Mapping):
                continue
            for component in _managed_target_components(host_id, raw_record, runtime_root=str(settings.paths.runtime_root)):
                kind = str(component.get("kind"))
                # Profile copies have their own validated lifecycle and are
                # removed by _apply_profile_changes before this function.
                if kind == "profile":
                    continue
                target = component.get("target")
                if not isinstance(target, str) or not target:
                    continue
                group = removal_groups.setdefault(
                    (target, kind),
                    {
                        "target": target,
                        "kind": kind,
                        "owner_ids": set(),
                        "removed_ids": set(),
                        "managed_ids": set(),
                        "components": [],
                    },
                )
                group["owner_ids"].add(host_id)
                if host_id in removed_hosts:
                    group["removed_ids"].add(host_id)
                group["managed_ids"].update(component.get("managed_ids", ()))
                group["components"].append((host_id, raw_record, component))

    def _hook_ids_for_owner(host_id: str, record: Mapping[str, Any], component: Mapping[str, Any]) -> set[str]:
        managed = {item for item in component.get("managed_ids", ()) if isinstance(item, str)}
        # Older manifests sometimes copied the union of shared IDs into each
        # host record.  If the removed host is still reconstructible, narrow
        # that union to the IDs emitted by its own template before removing.
        try:
            old_hosts = tuple(str(item) for item in previous_hosts if isinstance(item, str))
            old_host = settings.hosts.get(host_id)
            if old_host is not None:
                fragment = _render_hook_fragment(
                    repo,
                    old_host,
                    host_id,
                    python,
                    old_hosts,
                    runtime_root=settings.paths.runtime_root,
                    personal_knowledge_root=settings.paths.personal_knowledge_root,
                    team_knowledge_root=settings.paths.team_knowledge_root,
                )
                template_ids = {
                    str(entry.get("id"))
                    for entries in (fragment.get("hooks") or {}).values()
                    if isinstance(entries, list)
                    for entry in entries
                    if isinstance(entry, Mapping) and isinstance(entry.get("id"), str)
                }
                if template_ids:
                    managed &= template_ids
        except (OSError, TypeError, ValueError):
            # The manifest's owned IDs remain the safe fallback for a legacy
            # or unavailable source template.
            managed = set(managed)
        return managed

    def _validate_removal_group(group: Mapping[str, Any]) -> tuple[Path, str | None]:
        target = str(group["target"])
        kind = str(group["kind"])
        candidate = previous_managed.get(target) if isinstance(previous_managed, Mapping) else None
        if not isinstance(candidate, Mapping):
            candidate = {"kind": kind}
        if candidate.get("target_type_conflict") is True or candidate.get("kind") != kind:
            raise ValueError("MANAGED_TARGET_CONFLICT")
        target_path = _resolve(target)
        if _managed_target_type_conflict(target, candidate):
            raise ValueError("MANAGED_TARGET_CONFLICT")
        expected = candidate.get("ownership_hash", candidate.get("hash"))
        if not isinstance(expected, str):
            hashes = sorted({item.get("hash") for _, _, item in group.get("components", ()) if isinstance(item, Mapping) and isinstance(item.get("hash"), str)})
            expected = hashes[0] if hashes else None
        if kind == "hook":
            managed_ids = sorted({item for item in group.get("managed_ids", ()) if isinstance(item, str)})
            actual = _managed_hook_hash(target_path, managed_ids)
        else:
            actual = _target_live_hash(target, candidate)
        # A missing target is a repair/no-op path.  An existing target whose
        # content no longer matches its detached aggregate is a fail-closed
        # tamper conflict, before any remove or mutate operation is attempted.
        if expected is not None and actual is not None and actual != expected:
            raise ValueError("MANAGED_TARGET_CONFLICT")
        return target_path, expected

    # Validate and process each canonical target/type exactly once.  The
    # selected hosts are the final owner set for this transaction.  Retained
    # hooks are pruned as part of their one final build write below.
    retained_hook_removals: dict[Path, set[str]] = {}
    for group in sorted(removal_groups.values(), key=lambda item: (str(item["target"]), str(item["kind"]))):
        removed_ids = group["removed_ids"]
        if not removed_ids:
            continue
        target_path, expected = _validate_removal_group(group)
        kind = str(group["kind"])
        remaining_ids = set(group["owner_ids"]) - set(removed_ids)
        if kind == "hook":
            removed_managed_ids: set[str] = set()
            for host_id, record, component in group["components"]:
                if host_id in removed_ids:
                    removed_managed_ids.update(_hook_ids_for_owner(host_id, record, component))
            if not removed_managed_ids:
                removed_managed_ids = set(group["managed_ids"]) if not remaining_ids else set()
            if remaining_ids:
                if removed_managed_ids:
                    retained_hook_removals.setdefault(target_path, set()).update(removed_managed_ids)
                continue
            if target_path.is_file() and removed_managed_ids:
                current = _read_json(target_path, {"hooks": {}})
                raw = _json_bytes(remove_managed_hooks(current, removed_managed_ids), _text_style(target_path.read_bytes()))
                before = _hash_path(target_path)
                backup = transaction.mutate_file(
                    target_path,
                    raw,
                    details={"kind": "hook-remove", "host_ids": sorted(removed_ids), "remaining_host_ids": sorted(remaining_ids)},
                )
                after = _hash_path(target_path)
                if before != after:
                    changed.append(target_path)
                if backup:
                    backups.append(backup)
            continue
        # A retained owner keeps a shared context/Skill/binding/file alive;
        # the selected-host build/install path owns its final bytes.  No
        # second mutation is necessary here, and in particular no old hash
        # must be checked after that final-content write.
        if remaining_ids:
            continue
        if kind == "skill":
            backup = transaction.remove_skill(
                target_path,
                expected,
                details={"kind": "skill-remove", "host_ids": sorted(removed_ids)},
            )
        elif kind == "context":
            if not target_path.is_file():
                continue
            text, style = _load_text(target_path)
            raw_text = remove_managed_context(text.replace("\r\n", "\n").replace("\r", "\n"))
            if style != "\n":
                raw_text = raw_text.replace("\n", style)
            before = _hash_path(target_path)
            backup = transaction.mutate_file(
                target_path,
                raw_text.encode("utf-8"),
                details={"kind": "context-remove", "host_ids": sorted(removed_ids)},
            )
            after = _hash_path(target_path)
            if before != after:
                changed.append(target_path)
        else:
            backup = transaction.remove_file(
                target_path,
                expected,
                details={"kind": "skill-binding-remove" if kind == "binding" else "managed-target-remove", "host_ids": sorted(removed_ids), "component_type": kind},
            )
        if backup:
            changed.append(target_path)
            backups.append(backup)

    # Read the target bytes only after all all-owner removals have been moved
    # aside.  This lets the selected-host build render final shared content
    # from the post-removal state and keeps each retained target to one write.
    targets, managed_ids = _build_target_contents(
        selected,
        settings,
        repo,
        python,
        source,
        prune_hook_ids=retained_hook_removals,
    )
    for target, raw, details in targets:
        before = _hash_path(target)
        backup = transaction.mutate_file(target, raw, details=details)
        after = _hash_path(target)
        result_plans.append(InstallPlanItem(target, "create" if before is None else "update", before, after, backup, details))
        if before != after:
            changed.append(target)
        if backup:
            backups.append(backup)
    skill_results: dict[str, SkillInstallResult] = {}
    skill_bindings: dict[str, dict[str, str]] = {}
    processed_skill_destinations: dict[Path, SkillInstallResult] = {}
    processed_binding_targets: dict[Path, dict[str, str]] = {}
    previous_skill_hashes: dict[Path, str] = {}
    previous_binding_hashes: dict[Path, str] = {}
    if isinstance(previous_managed, Mapping):
        for target, managed_record in previous_managed.items():
            if not isinstance(target, str) or not isinstance(managed_record, Mapping):
                continue
            expected = managed_record.get("ownership_hash", managed_record.get("hash"))
            if not isinstance(expected, str):
                continue
            target_path = _resolve(target)
            if managed_record.get("kind") == "skill":
                previous_skill_hashes[target_path] = expected
            elif managed_record.get("kind") == "binding":
                previous_binding_hashes[target_path] = expected
    if isinstance(previous_hosts, Mapping):
        for record in previous_hosts.values():
            if not isinstance(record, Mapping):
                continue
            destination_value = record.get("skill_destination")
            installed_hash = record.get("installed_skill_hash")
            if isinstance(destination_value, str) and isinstance(installed_hash, str):
                previous_skill_hashes.setdefault(_resolve(destination_value), installed_hash)
            binding_value = record.get("skill_binding_path")
            binding_hash = record.get("skill_binding_hash")
            if isinstance(binding_value, str) and isinstance(binding_hash, str):
                previous_binding_hashes.setdefault(_resolve(binding_value), binding_hash)
    skill_owner_ids: dict[Path, list[str]] = {}
    for host_id in selected.managed_hosts:
        destination = _resolve(settings.hosts[host_id].skill_roots[0]) / source.name
        skill_owner_ids.setdefault(destination, []).append(host_id)
    for host_id in selected.managed_hosts:
        host = settings.hosts[host_id]
        destination = _resolve(host.skill_roots[0]) / source.name
        if destination in processed_skill_destinations:
            # Two custom profiles may intentionally share one skill root.  A
            # physical installation and binding are applied once, while each
            # host receives its own manifest ownership record.
            installed = replace(processed_skill_destinations[destination], host_id=host_id)
            skill_results[host_id] = installed
            binding = processed_binding_targets.get(destination.parent / SKILL_BINDING_NAME)
            if binding is None:
                raise ValueError("SKILL_BINDING_WRITE_FAILED")
            skill_bindings[host_id] = dict(binding)
            continue
        existed = destination.exists() or destination.is_symlink()
        previous_record = previous.get("hosts", {}).get(host_id, {}) if isinstance(previous.get("hosts"), Mapping) else {}
        old_hash = previous_record.get("installed_skill_hash") if isinstance(previous_record, Mapping) else None
        if not isinstance(old_hash, str):
            old_hash = previous_skill_hashes.get(destination)
        installed = install_skill(source, host, selected.skill_mode, previous_hash=str(old_hash) if old_hash else None)
        skill_results[host_id] = installed
        processed_skill_destinations[destination] = installed
        transaction.register_skill(installed, existed)
        result_plans.append(InstallPlanItem(destination, installed.reason_code, _dir_hash(destination) if existed else None, installed.installed_hash, installed.backup_path, installed.to_dict()))
        if installed.changed:
            changed.append(destination)
        if installed.backup_path:
            backups.append(installed.backup_path)
        binding_owner_id = min(skill_owner_ids.get(destination, [host_id]))
        binding_target, binding_raw = _skill_binding(binding_owner_id, installed, settings, python)
        current_binding_hash = _hash_path(binding_target)
        previous_binding_path = previous_record.get("skill_binding_path") if isinstance(previous_record, Mapping) else None
        previous_binding_hash = previous_record.get("skill_binding_hash") if isinstance(previous_record, Mapping) else None
        known_binding_hash = previous_binding_hashes.get(binding_target)
        shared_existing_binding = current_binding_hash is not None and known_binding_hash == current_binding_hash
        if current_binding_hash is not None and not shared_existing_binding and (previous_binding_path != str(binding_target) or previous_binding_hash != current_binding_hash):
            raise ValueError("SKILL_BINDING_CONFLICT")
        if shared_existing_binding and previous_binding_path != str(binding_target):
            binding = {"path": str(binding_target), "hash": current_binding_hash}
            skill_bindings[host_id] = binding
            processed_binding_targets[binding_target] = dict(binding)
            result_plans.append(InstallPlanItem(binding_target, "SKILL_ALREADY_CURRENT", current_binding_hash, current_binding_hash, None, {"kind": "skill-binding", "host_id": host_id}))
            continue
        desired_binding_hash = _sha256(binding_raw)
        if shared_existing_binding and current_binding_hash == desired_binding_hash:
            binding = {"path": str(binding_target), "hash": current_binding_hash}
            skill_bindings[host_id] = binding
            processed_binding_targets[binding_target] = dict(binding)
            result_plans.append(InstallPlanItem(binding_target, "SKILL_ALREADY_CURRENT", current_binding_hash, current_binding_hash, None, {"kind": "skill-binding", "host_id": host_id}))
            continue
        binding_backup = transaction.mutate_file(binding_target, binding_raw, details={"kind": "skill-binding", "host_id": host_id})
        binding_hash = _hash_path(binding_target)
        if binding_hash is None:
            raise ValueError("SKILL_BINDING_WRITE_FAILED")
        skill_bindings[host_id] = {"path": str(binding_target), "hash": binding_hash}
        result_plans.append(InstallPlanItem(binding_target, "create" if current_binding_hash is None else "update", current_binding_hash, binding_hash, binding_backup, {"kind": "skill-binding", "host_id": host_id}))
        if current_binding_hash != binding_hash:
            changed.append(binding_target)
        if binding_backup:
            backups.append(binding_backup)
        processed_binding_targets[binding_target] = dict(skill_bindings[host_id])
    return result_plans, changed, backups, skill_results, skill_bindings, managed_ids


def write_schema_v7_manifest(
    plan: SetupReconciliationPlan,
    transaction: _Transaction,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    previous_raw: bytes | None = None,
) -> tuple[Path | None, bytes]:
    """Write a validated schema-v8 manifest through the active transaction."""

    value = normalize_install_manifest(manifest)
    if value.get("schema_version") != INSTALL_MANIFEST_SCHEMA_VERSION:
        raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")
    value["reconciliation"] = {"desired_state_digest": plan.desired_state_digest}
    # A disabled team descriptor is retained for a future re-enable, but its
    # external root is deliberately not part of this operation's trust
    # boundary.  Validate its shape with a detached lexical root so a missing,
    # malformed, or inaccessible shared folder cannot block the local disable.
    validation_value = value
    stores = value.get("knowledge_stores")
    team = stores.get("team") if isinstance(stores, Mapping) else None
    if isinstance(stores, Mapping) and isinstance(team, Mapping) and team.get("enabled") is False:
        validation_value = copy.deepcopy(value)
        detached_team = dict(team)
        detached_team["root"] = str(manifest_path.parent.parent / ".team-disabled-validation-root")
        validation_value["knowledge_stores"] = {**dict(stores), "team": detached_team}
    validate_install_manifest(validation_value, require_live_personal=False)
    if previous_raw is not None:
        try:
            previous_value = json.loads(previous_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID") from exc
        if isinstance(previous_value, Mapping) and previous_value.get("schema_version") in {6, 7}:
            backup_dir = manifest_path.parent / "backups"
            safe_ensure_directory(backup_dir, mode=0o700)
            previous_version = previous_value.get("schema_version")
            backup_path = backup_dir / (f"install-manifest-v{previous_version}-" + hashlib.sha256(previous_raw).hexdigest() + ".json")
            if not backup_path.exists():
                # Preserve the source bytes exactly, including the original
                # newline style/order, so migration recovery can reproduce
                # the pre-v7 document byte-for-byte.
                _atomic_write(backup_path, previous_raw)
    raw = _json_bytes(value)
    backup = transaction.mutate_file(manifest_path, raw, details={"kind": "install-manifest", "schema_version": INSTALL_MANIFEST_SCHEMA_VERSION})
    return backup, raw


def apply_scheduler_transition(
    settings: Settings,
    python: Path,
    requested: bool,
    previous: Mapping[str, Any] | None = None,
    *,
    check_only: bool = False,
) -> dict[str, Any]:
    """Apply the requested scheduler state after managed host preparation."""

    del previous
    if check_only:
        if not requested:
            return {"ok": True, "requested": False, "status": "NOT_REQUESTED", "registered": False, "retryable": False}
        from .task_scheduler import build_maintenance_action, register_scheduler

        return register_scheduler(settings, build_maintenance_action(settings, python), settings.paths.engine_root, check_only=True)
    if requested:
        return _setup_scheduler(settings, python, True)
    # A fresh/never-registered setup should report NOT_REQUESTED and avoid a
    # needless unregister mutation.  If a prior registration exists, remove
    # it so disabling scheduler remains an actual reconciliation transition.
    scheduler_state_path = settings.paths.runtime_root / "scheduler-state.json"
    if not scheduler_state_path.is_file():
        return {"ok": True, "requested": False, "status": "NOT_REQUESTED", "registered": False, "retryable": False}
    try:
        state = _read_json(scheduler_state_path, {})
    except ValueError:
        state = {}
    if state.get("registered") is not True:
        return {"ok": True, "requested": False, "status": "NOT_REQUESTED", "registered": False, "retryable": False}
    from .task_scheduler import unregister_scheduler

    return unregister_scheduler(settings)


def rollback_scheduler_transition(receipt: Mapping[str, Any] | None, settings: Settings) -> dict[str, Any]:
    """Best-effort scheduler rollback guarded by the current receipt identity."""

    if not isinstance(receipt, Mapping) or not receipt.get("registered"):
        return {"ok": True, "status": "NOT_REQUIRED"}
    try:
        from .task_scheduler import unregister_scheduler

        result = unregister_scheduler(settings)
        return {"ok": bool(result.get("ok")), "status": result.get("status", "UNKNOWN"), "result": result}
    except (OSError, TypeError, ValueError) as exc:
        return {"ok": False, "status": "ROLLBACK_FAILED", "reason_code": str(exc)}

def _setup_reconciled(selection: SetupSelection | Mapping[str, Any], check_only: bool = False) -> SetupResult:
    selected = _normalise_selection(selection)
    repo = _resolve(selected.engine_root or selected.repo_root)
    organizer = _organizer_for_selection(selected, repo)
    if organizer.status != "READY":
        manifest_path = _manifest_path(_resolve(selected.runtime_root))
        return SetupResult(
            False,
            "SELECTION_REQUIRED",
            manifest_path,
            errors=(
                {
                    "error_code": organizer.reason_code or "ORGANIZER_SELECTION_REQUIRED",
                    "stage": "organizer",
                    "retryable": False,
                },
            ),
            message="Organizer selection is required before setup can be applied",
            compatibility_notices=tuple(selected.compatibility_notices),
        )
    if not check_only and not selected.accept_plan:
        raise ValueError("SETUP_PLAN_ACCEPTANCE_REQUIRED")
    runtime = _resolve(selected.runtime_root)
    previous = _previous_manifest_for_selection(runtime, selected, repo)
    selected = _effective_team_selection(selected, previous)
    continuity_notice = _team_member_continuity_notice(selected, previous)
    if continuity_notice is not None:
        selected = replace(selected, compatibility_notices=(*selected.compatibility_notices, continuity_notice))
    source = _source_skill(repo)
    settings = _settings_for_selection(selected)
    profile_changes = _profile_change_specs(selected, previous, runtime)
    python = absolute_path(selected.python_exe or sys.executable)
    current_state = _current_setup_state(previous)
    desired_state = _desired_setup_state(selected, current_state, settings)
    live_state = _reconciliation_live_state(selected, previous, desired_state)
    reconciliation = plan_setup_reconciliation(current_state, desired_state, live_state)
    if previous and previous.get("schema_version") != INSTALL_MANIFEST_SCHEMA_VERSION and reconciliation.status == "ALREADY_CURRENT":
        migration_action = ReconciliationAction("write-manifest", "install-manifest", state_digest(current_state), reconciliation.desired_state_digest, True)
        reconciliation = replace(reconciliation, status="UPDATED", actions=(migration_action,), changed_paths=("install-manifest",))
    manifest_path = _manifest_path(runtime)
    team_view = _team_setup_view(selected, previous, check_only=check_only)
    current_personal = current_state.get("personal") if isinstance(current_state.get("personal"), Mapping) else None
    current_team = current_state.get("team") if isinstance(current_state.get("team"), Mapping) else None
    planned_stores = _knowledge_stores_result(current_personal, current_team, team_status=team_view.get("status"))
    if selected.team_knowledge is True and isinstance(desired_state.get("team"), Mapping):
        planned_stores["team"] = {**dict(desired_state["team"]), "status": "PLANNED" if check_only else "DEFERRED"}
    if reconciliation.status == "BLOCKED":
        return replace(blocked_setup_result(reconciliation, manifest_path=manifest_path, knowledge_stores=planned_stores), team=team_view, compatibility_notices=tuple(selected.compatibility_notices))

    knowledge_plan: KnowledgeSetupPlan | None = None
    preserved_completed: dict[str, Any] | None = None
    preserved_result: KnowledgeSetupResult | None = None
    if selected.preserve_existing_knowledge and previous:
        knowledge_view, preserved_completed, preserved_result = _preserved_knowledge_views(selected, previous)
    else:
        knowledge_plan = plan_knowledge_setup(_knowledge_selection(selected))
        knowledge_view = _planned_knowledge_view(knowledge_plan)
    if not check_only and knowledge_plan is not None and knowledge_plan.selection.mode == "github-new" and knowledge_plan.selection.confirm_github_create != knowledge_plan.selection.github_repository:
        raise ValueError("GITHUB_CREATE_CONFIRMATION_REQUIRED")
    install_plan = render_install_plan(selected, previous=previous, profile_changes=profile_changes)
    planned_scheduler = {"requested": selected.scheduler, "status": "PLANNED" if selected.scheduler else "NOT_REQUESTED"}
    result_plan = () if reconciliation.status == "ALREADY_CURRENT" else install_plan
    if check_only:
        return replace(check_only_setup_result(reconciliation, manifest_path=manifest_path, knowledge_stores=planned_stores), plan=result_plan, host_migrations=tuple(selected.legacy_host_migrations), knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=planned_scheduler, team=team_view, compatibility_notices=tuple(selected.compatibility_notices))
    if reconciliation.status == "ALREADY_CURRENT":
        append_setup_receipt(runtime, reconciliation, status="ALREADY_CURRENT")
        completed_stores = _knowledge_stores_result(
            current_personal,
            current_team,
            team_status="DEFERRED" if selected.team_knowledge is not False and selected.defer_team_validation and current_team and current_team.get("enabled") is True and isinstance(current_team.get("root"), str) and not Path(str(current_team["root"])).exists() and not Path(str(current_team["root"])).is_symlink() else ("READY" if current_team and current_team.get("enabled") is True else "DISABLED"),
        )
        return replace(already_current_setup_result(previous, reconciliation, manifest_path=manifest_path, knowledge_stores=completed_stores), plan=result_plan, knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler={"requested": selected.scheduler, "status": "ALREADY_CURRENT", "registered": selected.scheduler}, team=team_view, compatibility_notices=tuple(selected.compatibility_notices))

    # Re-read every planner input immediately before any personal/team or host
    # mutation.  A concurrent edit therefore fails closed as a stale plan and
    # cannot be mistaken for an approved managed update.
    assert_plan_current(reconciliation, _reconciliation_live_state(selected, previous, desired_state))

    if preserved_result is not None and preserved_completed is not None:
        knowledge_result = preserved_result
        knowledge_view = preserved_completed
    else:
        if knowledge_plan is None:
            raise ValueError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
        knowledge_result = prepare_personal_store(knowledge_plan, runtime)
        knowledge_view = _completed_knowledge_view(knowledge_plan, knowledge_result)
    if not knowledge_result.ok:
        errors = tuple({"error_code": str(item.get("code", "KNOWLEDGE_SETUP_FAILED")), "stage": str(item.get("stage", knowledge_result.stage)), "retryable": item.get("retryable") is True} for item in knowledge_result.errors)
        return SetupResult(False, "KNOWLEDGE_SETUP_BLOCKED" if knowledge_result.status == "BLOCKED" else "KNOWLEDGE_SETUP_FAILED", manifest_path, plan=install_plan, errors=errors, rollback={"status": "NOT_STARTED", "reason_codes": ["HOST_INSTALL_NOT_STARTED"]}, message="Knowledge destination did not complete; host integration was not modified", host_migrations=tuple(selected.legacy_host_migrations), knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=planned_scheduler, team=team_view, reconciliation=_reconciliation_view(reconciliation), knowledge_stores=planned_stores, compatibility_notices=tuple(selected.compatibility_notices))

    team_store: dict[str, Any] | None = None
    team_validation_deferred = False
    try:
        team_store = prepare_or_validate_team_store(selected, previous, runtime)
        if isinstance(team_store, Mapping) and team_store.pop("_validation_deferred", False) is True:
            team_validation_deferred = True
            team_view = {
                **team_view,
                "status": "DEFERRED",
                "reason_code": "TEAM_STORE_VALIDATION_DEFERRED",
            }
        elif isinstance(team_store, Mapping) and team_store.get("enabled") is True:
            team_view = {**team_view, "status": "READY"}
    except (OSError, TypeError, ValueError) as exc:
        code = str(exc) if isinstance(exc, ValueError) else "TEAM_SETUP_BLOCKED"
        return SetupResult(False, "TEAM_SETUP_BLOCKED", manifest_path, errors=({"error_code": code, "stage": "team", "retryable": True},), rollback={"status": "KNOWLEDGE_RETAINED", "reason_codes": ["TEAM_ROOT_RETAINED"]}, message="Personal setup completed, but the selected team store could not be prepared", knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=planned_scheduler, team={**team_view, "status": "BLOCKED"}, reconciliation=_reconciliation_view(reconciliation), knowledge_stores=_knowledge_stores_result(current_personal or {"status": "READY"}, team_store, team_status="BLOCKED"), compatibility_notices=tuple(selected.compatibility_notices))
    if team_store is not None:
        desired_state["team"] = dict(team_store)
        desired_state["desired_state_digest"] = state_digest(desired_state)
        reconciliation = replace(reconciliation, desired_state_digest=desired_state["desired_state_digest"])

    recovery = _recover_pending_transactions(runtime)
    if not python.is_file():
        raise ValueError("PYTHON_EXE_INVALID")
    tx = _Transaction(runtime)
    created_venv = False
    changed: list[Path] = []
    backups: list[Path] = []
    result_plans: list[InstallPlanItem] = []
    scheduler: dict[str, Any] = planned_scheduler
    manifest_target = manifest_path
    try:
        python, created_venv = _ensure_venv(selected, python)
        _make_runtime_dirs(runtime)
        profile_plans, profile_changed, profile_backups = _apply_profile_changes(profile_changes, tx)
        result_plans.extend(profile_plans)
        changed.extend(profile_changed)
        backups.extend(profile_backups)
        host_plans, host_changed, host_backups, skill_results, skill_bindings, managed_ids = apply_owned_host_actions(selected, settings, repo, python, source, previous, tx)
        result_plans.extend(host_plans)
        changed.extend(host_changed)
        backups.extend(host_backups)
        migration = _build_host_migration_receipt(selected.legacy_host_migrations)
        if migration is not None:
            migration_target = runtime / "host-migration-receipt.json"
            migration_raw = _json_bytes(migration)
            before = _hash_path(migration_target)
            backup = tx.mutate_file(migration_target, migration_raw, details={"kind": "legacy-host-migration"})
            after = _hash_path(migration_target)
            result_plans.append(InstallPlanItem(migration_target, "create" if before is None else "update", before, after, backup, {"kind": "legacy-host-migration"}))
            if before != after:
                changed.append(migration_target)
            if backup:
                backups.append(backup)
        scheduler = apply_scheduler_transition(settings, python, selected.scheduler, previous)
        if isinstance(scheduler.get("state_path"), str):
            changed.append(Path(str(scheduler["state_path"])))
        knowledge_result_view = knowledge_result
        manifest = _build_manifest(selected, settings, repo, python, source, skill_results, skill_bindings, managed_ids, tx, previous, created_venv, knowledge_result_view, team_store=team_store, desired_state_digest=reconciliation.desired_state_digest)
        old_raw = manifest_target.read_bytes() if manifest_target.is_file() else None
        manifest_backup, _ = write_schema_v7_manifest(reconciliation, tx, manifest_target, manifest, old_raw)
        before = _hash_path(manifest_target)
        after = _hash_path(manifest_target)
        result_plans.append(InstallPlanItem(manifest_target, "create" if before is None else "update", before, after, manifest_backup, {"kind": "install-manifest", "schema_version": INSTALL_MANIFEST_SCHEMA_VERSION}))
        if before != after:
            changed.append(manifest_target)
        if manifest_backup:
            backups.append(manifest_backup)
        tx.commit()
        append_setup_receipt(runtime, reconciliation, status="UPDATED" if previous else "CREATED")
        effective_settings = _settings_for_selection(selected)
        doctor = run_doctor(effective_settings, strict=False)
        capabilities: list[dict[str, Any]] = []
        for host_id in selected.managed_hosts:
            host = effective_settings.hosts[host_id]
            try:
                status = read_hook_status(host_id, host_id, effective_settings)
                record = status.to_dict()
            except (OSError, TypeError, ValueError) as exc:
                record = {"host_id": host_id, "host_instance_id": host_id, "hook_status": "HOOK_UNVERIFIED", "skill_discovery_status": "UNVERIFIED", "skill_activation_mode": host.skill_activation_mode, "capture_primary_path": host.capture_primary_path, "reason_codes": [type(exc).__name__]}
            record["host_id"] = host_id
            record["host_instance_id"] = host_id
            capabilities.append(record)
        actions_required = tuple({"code": "HOST_TRUST_OR_CONSENT_REQUIRED", "host_id": str(record.get("host_id")), "hook_status": str(record.get("hook_status", "HOOK_UNVERIFIED")), "skill_activation_mode": str(record.get("skill_activation_mode", "UNVERIFIED"))} for record in capabilities if record.get("hook_status") != "HOOK_VERIFIED" or record.get("skill_activation_mode") in {"CONSENT_REQUIRED", "UNVERIFIED"})
        scheduler_ok = bool(scheduler.get("ok", not selected.scheduler))
        manifest_stores = manifest.get("knowledge_stores") if isinstance(manifest.get("knowledge_stores"), Mapping) else {}
        completed_stores = _knowledge_stores_result(manifest_stores.get("personal") if isinstance(manifest_stores.get("personal"), Mapping) else None, team_store, team_status="DEFERRED" if team_validation_deferred else ("READY" if team_store and team_store.get("enabled") is True else "DISABLED"))
        return SetupResult(scheduler_ok, "SETUP_COMPLETE" if scheduler_ok else "SCHEDULER_SETUP_BLOCKED", manifest_target, plan=tuple(result_plans), changed_paths=tuple(dict.fromkeys(changed)), backups=tuple(dict.fromkeys(backups)), hosts=tuple(capabilities), doctor=doctor.to_dict(), errors=() if scheduler_ok else ({"error_code": str(scheduler.get("reason_code") or "SCHEDULER_REGISTRATION_FAILED"), "stage": "scheduler", "retryable": scheduler.get("retryable") is True},), rollback={"transaction": tx.transaction_id, "recovered_transactions": recovery, "scheduler": scheduler} if scheduler_ok else {"status": "INSTALLATION_RETAINED", "transaction": tx.transaction_id, "recovered_transactions": recovery, "reason_codes": ["SCHEDULER_RETRY_REQUIRED"]}, message="Setup completed; Hook verification remains receipt-based and Skill activation is reported independently" if scheduler_ok else "Knowledge and host installation completed, but the selected scheduler must be retried", host_migrations=tuple(selected.legacy_host_migrations), knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=scheduler, team=team_view, reconciliation=_reconciliation_view(reconciliation), knowledge_stores=completed_stores, actions_required=actions_required, compatibility_notices=tuple(selected.compatibility_notices))
    except Exception as exc:
        if tx.status == "COMMITTED":
            code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            return SetupResult(False, "DIAGNOSTICS_BLOCKED", manifest_target, plan=tuple(result_plans), changed_paths=tuple(dict.fromkeys(changed)), backups=tuple(dict.fromkeys(backups)), errors=({"error_code": code, "stage": "diagnostics", "retryable": True},), rollback={"status": "INSTALLATION_RETAINED", "rolled_back": False, "transaction": tx.transaction_id, "recovered_transactions": recovery, "reason_codes": ["DIAGNOSTICS_BLOCKED", "INSTALLATION_RETAINED"]}, message="Installation was committed, but post-commit diagnostics are blocked; rerun diagnostics without reinstalling", knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=scheduler, team=team_view, reconciliation=_reconciliation_view(reconciliation), knowledge_stores=_knowledge_stores_result(current_personal, team_store, team_status="DEFERRED" if team_validation_deferred else None), compatibility_notices=tuple(selected.compatibility_notices))
        rollback = tx.rollback()
        code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        return SetupResult(False, str(rollback["status"]), manifest_target, plan=tuple(result_plans), changed_paths=tuple(changed), backups=tuple(backups), errors=({"error_code": code, "stage": "setup"},), rollback={**rollback, "reason_codes": list(dict.fromkeys([*rollback.get("reason_codes", []), "KNOWLEDGE_RETAINED_FOR_RETRY"]))}, message="Host setup failed; this invocation's host changes were rolled back and valid knowledge was retained", knowledge=knowledge_view, sync=_sync_view(selected, knowledge_view), scheduler=planned_scheduler, team=team_view, reconciliation=_reconciliation_view(reconciliation), knowledge_stores=_knowledge_stores_result(current_personal, team_store), compatibility_notices=tuple(selected.compatibility_notices))


def setup(selection: SetupSelection | Mapping[str, Any], check_only: bool = False) -> SetupResult:
    return _setup_reconciled(selection, check_only)


def _legacy_setup_unused(selection: SetupSelection | Mapping[str, Any], check_only: bool = False) -> SetupResult:
    selected = _normalise_selection(selection)
    if not check_only and not selected.accept_plan:
        raise ValueError("SETUP_PLAN_ACCEPTANCE_REQUIRED")
    repo = _resolve(selected.engine_root or selected.repo_root)
    runtime = _resolve(selected.runtime_root)
    source = _source_skill(repo)
    settings = _settings_for_selection(selected)
    python = absolute_path(selected.python_exe or sys.executable)
    previous = _previous_manifest(runtime)
    team_view = _team_setup_view(selected, previous, check_only=check_only)
    preserved_completed: dict[str, Any] | None = None
    preserved_result: KnowledgeSetupResult | None = None
    if selected.preserve_existing_knowledge:
        knowledge_view, preserved_completed, preserved_result = _preserved_knowledge_views(selected, previous)
        knowledge_plan: KnowledgeSetupPlan | None = None
    else:
        knowledge_plan = plan_knowledge_setup(_knowledge_selection(selected))
        knowledge_view = _planned_knowledge_view(knowledge_plan)
    if (
        not check_only
        and knowledge_plan is not None
        and knowledge_plan.selection.mode == "github-new"
        and knowledge_plan.selection.confirm_github_create != knowledge_plan.selection.github_repository
    ):
        raise ValueError("GITHUB_CREATE_CONFIRMATION_REQUIRED")
    plan = render_install_plan(selected)
    planned_scheduler = {"requested": selected.scheduler, "status": "PLANNED" if selected.scheduler else "NOT_REQUESTED"}
    if check_only:
        return SetupResult(
            ok=True,
            status="CHECK_ONLY",
            manifest_path=_manifest_path(runtime),
            plan=plan,
            message="check-only did not mutate repository, host configuration, Skill, runtime, scheduler, or Git state",
            host_migrations=tuple(selected.legacy_host_migrations),
            knowledge=knowledge_view,
            sync=_sync_view(selected, knowledge_view),
            scheduler=planned_scheduler,
            team=team_view,
            compatibility_notices=tuple(selected.compatibility_notices),
        )
    if preserved_result is not None and preserved_completed is not None:
        knowledge_result = preserved_result
        knowledge_view = preserved_completed
    else:
        if knowledge_plan is None:
            raise ValueError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
        knowledge_result = apply_knowledge_setup(knowledge_plan)
        knowledge_view = _completed_knowledge_view(knowledge_plan, knowledge_result)
    if not knowledge_result.ok:
        errors = tuple(
            {
                "error_code": str(item.get("code", "KNOWLEDGE_SETUP_FAILED")),
                "stage": str(item.get("stage", knowledge_result.stage)),
                "retryable": item.get("retryable") is True,
            }
            for item in knowledge_result.errors
        )
        return SetupResult(
            ok=False,
            status="KNOWLEDGE_SETUP_BLOCKED" if knowledge_result.status == "BLOCKED" else "KNOWLEDGE_SETUP_FAILED",
            manifest_path=_manifest_path(runtime),
            plan=plan,
            errors=errors,
            rollback={"status": "NOT_STARTED", "reason_codes": ["HOST_INSTALL_NOT_STARTED"]},
            message="Knowledge destination did not complete; host integration was not modified",
            host_migrations=tuple(selected.legacy_host_migrations),
            knowledge=knowledge_view,
            sync=_sync_view(selected, knowledge_view),
            scheduler=planned_scheduler,
            team=team_view,
            compatibility_notices=tuple(selected.compatibility_notices),
        )
    recovery = _recover_pending_transactions(runtime)
    if not python.is_file():
        raise ValueError("PYTHON_EXE_INVALID")
    tx = _Transaction(runtime)
    created_venv = False
    changed: list[Path] = []
    if knowledge_result.repository.get("status") in {"CREATED", "RESTORED"}:
        if knowledge_plan is None:
            raise ValueError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
        changed.append(knowledge_plan.selection.knowledge_root)
    backups: list[Path] = []
    result_plans: list[InstallPlanItem] = list(plan)
    skill_results: dict[str, SkillInstallResult] = {}
    skill_bindings: dict[str, dict[str, str]] = {}
    scheduler = planned_scheduler
    try:
        python, created_venv = _ensure_venv(selected, python)
        targets, managed_ids = _build_target_contents(selected, settings, repo, python, source)
        result_plans = []
        for target, raw, details in targets:
            before = _hash_path(target)
            backup = tx.mutate_file(target, raw, details=details)
            after = _hash_path(target)
            result_plans.append(InstallPlanItem(target, "create" if before is None else "update", before, after, backup, details))
            if before != after:
                changed.append(target)
            if backup:
                backups.append(backup)
        for host_id in selected.managed_hosts:
            host = settings.hosts[host_id]
            destination = _resolve(host.skill_roots[0]) / source.name
            existed = destination.exists() or destination.is_symlink()
            previous_record = previous.get("hosts", {}).get(host_id, {}) if isinstance(previous.get("hosts"), Mapping) else {}
            old_hash = previous_record.get("installed_skill_hash") if isinstance(previous_record, Mapping) else None
            installed = install_skill(source, host, selected.skill_mode, previous_hash=str(old_hash) if old_hash else None)
            skill_results[host_id] = installed
            tx.register_skill(installed, existed)
            result_plans.append(InstallPlanItem(destination, installed.reason_code, _dir_hash(destination) if existed else None, installed.installed_hash, installed.backup_path, installed.to_dict()))
            if installed.changed:
                changed.append(destination)
            if installed.backup_path:
                backups.append(installed.backup_path)
            binding_target, binding_raw = _skill_binding(host_id, installed, settings, python)
            if any(record.get("path") == str(binding_target) for record in skill_bindings.values()):
                raise ValueError("SKILL_BINDING_TARGET_CONFLICT")
            current_binding_hash = _hash_path(binding_target)
            previous_binding_path = previous_record.get("skill_binding_path") if isinstance(previous_record, Mapping) else None
            previous_binding_hash = previous_record.get("skill_binding_hash") if isinstance(previous_record, Mapping) else None
            if current_binding_hash is not None and (
                previous_binding_path != str(binding_target)
                or previous_binding_hash != current_binding_hash
            ):
                raise ValueError("SKILL_BINDING_CONFLICT")
            binding_backup = tx.mutate_file(
                binding_target,
                binding_raw,
                details={"kind": "skill-binding", "host_id": host_id},
            )
            binding_hash = _hash_path(binding_target)
            if binding_hash is None:
                raise ValueError("SKILL_BINDING_WRITE_FAILED")
            skill_bindings[host_id] = {"path": str(binding_target), "hash": binding_hash}
            result_plans.append(
                InstallPlanItem(
                    binding_target,
                    "create" if current_binding_hash is None else "update",
                    current_binding_hash,
                    binding_hash,
                    binding_backup,
                    {"kind": "skill-binding", "host_id": host_id},
                )
            )
            if current_binding_hash != binding_hash:
                changed.append(binding_target)
            if binding_backup:
                backups.append(binding_backup)
        _make_runtime_dirs(runtime)
        migration = _build_host_migration_receipt(selected.legacy_host_migrations)
        if migration is not None:
            migration_target = runtime / "host-migration-receipt.json"
            migration_raw = _json_bytes(migration)
            before = _hash_path(migration_target)
            backup = tx.mutate_file(migration_target, migration_raw, details={"kind": "legacy-host-migration"})
            after = _hash_path(migration_target)
            result_plans.append(InstallPlanItem(migration_target, "create" if before is None else "update", before, after, backup, {"kind": "legacy-host-migration"}))
            if before != after:
                changed.append(migration_target)
            if backup:
                backups.append(backup)
        manifest = _build_manifest(selected, settings, repo, python, source, skill_results, skill_bindings, managed_ids, tx, previous, created_venv, knowledge_result)
        manifest_target = _manifest_path(runtime)
        old_raw = manifest_target.read_bytes() if manifest_target.is_file() else None
        candidate_raw = _json_bytes(manifest)
        if previous and _manifest_equivalent(previous, manifest) and old_raw is not None:
            candidate_raw = old_raw
        before = _hash_path(manifest_target)
        backup = tx.mutate_file(manifest_target, candidate_raw, details={"kind": "install-manifest"})
        after = _hash_path(manifest_target)
        result_plans.append(InstallPlanItem(manifest_target, "create" if before is None else "update", before, after, backup, {"kind": "install-manifest"}))
        if before != after:
            changed.append(manifest_target)
        if backup:
            backups.append(backup)
        tx.commit()
        effective_settings = load_settings(repo, runtime_root=runtime)
        scheduler = _setup_scheduler(effective_settings, python, selected.scheduler)
        if isinstance(scheduler.get("state_path"), str):
            changed.append(Path(str(scheduler["state_path"])))
        doctor = run_doctor(effective_settings, strict=False)
        capabilities: list[dict[str, Any]] = []
        for host_id in selected.managed_hosts:
            host = effective_settings.hosts[host_id]
            try:
                status = read_hook_status(host_id, host_id, effective_settings)
                record = status.to_dict()
            except (OSError, TypeError, ValueError) as exc:
                record = {"host_id": host_id, "host_instance_id": host_id, "hook_status": "HOOK_UNVERIFIED", "skill_discovery_status": "UNVERIFIED", "skill_activation_mode": host.skill_activation_mode, "capture_primary_path": host.capture_primary_path, "reason_codes": [type(exc).__name__]}
            record["host_id"] = host_id
            record["host_instance_id"] = host_id
            capabilities.append(record)
        actions_required = tuple(
            {
                "code": "HOST_TRUST_OR_CONSENT_REQUIRED",
                "host_id": str(record.get("host_id")),
                "hook_status": str(record.get("hook_status", "HOOK_UNVERIFIED")),
                "skill_activation_mode": str(record.get("skill_activation_mode", "UNVERIFIED")),
            }
            for record in capabilities
            if record.get("hook_status") != "HOOK_VERIFIED"
            or record.get("skill_activation_mode") in {"CONSENT_REQUIRED", "UNVERIFIED"}
        )
        scheduler_ok = bool(scheduler.get("ok", not selected.scheduler))
        return SetupResult(
            ok=scheduler_ok,
            status="SETUP_COMPLETE" if scheduler_ok else "SCHEDULER_SETUP_BLOCKED",
            manifest_path=manifest_target,
            plan=tuple(result_plans),
            changed_paths=tuple(dict.fromkeys(changed)),
            backups=tuple(dict.fromkeys(backups)),
            hosts=tuple(capabilities),
            doctor=doctor.to_dict(),
            errors=() if scheduler_ok else ({"error_code": str(scheduler.get("reason_code") or "SCHEDULER_REGISTRATION_FAILED"), "stage": "scheduler", "retryable": scheduler.get("retryable") is True},),
            rollback=(
                {"transaction": tx.transaction_id, "recovered_transactions": recovery, "scheduler": scheduler}
                if scheduler_ok
                else {"status": "INSTALLATION_RETAINED", "transaction": tx.transaction_id, "recovered_transactions": recovery, "reason_codes": ["SCHEDULER_RETRY_REQUIRED"]}
            ),
            message=(
                "Setup completed; Hook verification remains receipt-based and Skill activation is reported independently"
                if scheduler_ok
                else "Knowledge and host installation completed, but the selected scheduler must be retried"
            ),
            host_migrations=tuple(selected.legacy_host_migrations),
            knowledge=knowledge_view,
            sync=_sync_view(selected, knowledge_view),
            scheduler=scheduler,
            team=team_view,
            actions_required=actions_required,
            compatibility_notices=tuple(selected.compatibility_notices),
        )
    except Exception as exc:
        if tx.status == "COMMITTED":
            code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            return SetupResult(
                ok=False,
                status="DIAGNOSTICS_BLOCKED",
                manifest_path=manifest_target if "manifest_target" in locals() else _manifest_path(runtime),
                plan=tuple(result_plans),
                changed_paths=tuple(dict.fromkeys(changed)),
                backups=tuple(dict.fromkeys(backups)),
                errors=({"error_code": code, "stage": "diagnostics", "retryable": True},),
                rollback={
                    "status": "INSTALLATION_RETAINED",
                    "rolled_back": False,
                    "transaction": tx.transaction_id,
                    "recovered_transactions": recovery,
                    "reason_codes": ["DIAGNOSTICS_BLOCKED", "INSTALLATION_RETAINED"],
                },
                message="Installation was committed, but post-commit diagnostics are blocked; rerun diagnostics without reinstalling",
                host_migrations=tuple(selected.legacy_host_migrations),
                knowledge=knowledge_view,
                sync=_sync_view(selected, knowledge_view),
                scheduler=scheduler,
                team=team_view,
                compatibility_notices=tuple(selected.compatibility_notices),
            )
        rollback = tx.rollback()
        if created_venv:
            repo_root = _resolve(selected.engine_root or selected.repo_root)
            venv = repo_root / ".venv"
            if venv.exists():
                try:
                    safe_remove_tree(repo_root, venv, allow_missing=True)
                except SafeFilesystemError:
                    rollback = {**rollback, "venv_cleanup": "SAFE_VENV_CLEANUP_BLOCKED"}
        code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        retained_rollback = {
            **rollback,
            "reason_codes": list(dict.fromkeys([*rollback.get("reason_codes", []), "KNOWLEDGE_RETAINED_FOR_RETRY"])),
        }
        return SetupResult(
            ok=False,
            status=str(rollback["status"]),
            manifest_path=_manifest_path(runtime),
            plan=tuple(result_plans),
            changed_paths=tuple(changed),
            backups=tuple(backups),
            errors=({"error_code": code, "stage": "setup"},),
            rollback=retained_rollback,
            message="Host setup failed; this invocation's host changes were rolled back and valid knowledge was retained",
            host_migrations=tuple(selected.legacy_host_migrations),
            knowledge=knowledge_view,
            sync=_sync_view(selected, knowledge_view),
            scheduler=planned_scheduler,
            team=team_view,
            compatibility_notices=tuple(selected.compatibility_notices),
        )


def _manifest_equivalent(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    a = copy.deepcopy(dict(left))
    b = copy.deepcopy(dict(right))
    for value in (a, b):
        value.pop("transaction_id", None)
        value.pop("manifest_sha256", None)
    return a == b


def _manifest_host_records(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    hosts = manifest.get("hosts", {})
    return {str(key): value for key, value in hosts.items()} if isinstance(hosts, Mapping) else {}


def _manifest_path_value(record: Mapping[str, Any], key: str) -> Path:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("MANIFEST_PATH_INVALID")
    return absolute_path(value)


def _manifest_profile_paths(
    manifest: Mapping[str, Any],
    runtime: Path,
    records: Mapping[str, Any] | None = None,
) -> tuple[Path, ...]:
    """Rehydrate custom profiles only from their fixed runtime locators."""

    host_records = records if isinstance(records, Mapping) else _manifest_host_records(manifest)
    custom_records = {
        host_id: record
        for host_id, record in host_records.items()
        if host_id not in PUBLIC_CLI_HOST_IDS and host_id not in LEGACY_HOSTS
    }
    if not custom_records:
        return ()
    try:
        runtime_path = assert_no_reparse_components(runtime)
        assert_safe_target(runtime_path.parent, runtime_path, allow_root=True, allow_missing=False, expected_type="dir")
        profile_dir = runtime_path / "host-profiles"
        assert_safe_target(runtime_path, profile_dir, allow_root=False, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
    paths: list[Path] = []
    for host_id, record in custom_records.items():
        if not is_custom_host_id(host_id) or not isinstance(record, Mapping):
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        expected_path = f"host-profiles/{host_id}.json"
        if record.get("profile_path") != expected_path:
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        target = profile_dir / f"{host_id}.json"
        try:
            assert_safe_target(profile_dir, target, allow_missing=False, expected_type="file")
            document = read_host_profile_document(target)
        except (SafeFilesystemError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc).startswith("HOST_PROFILE_"):
                raise
            raise ValueError("HOST_PROFILE_LOCATOR_INVALID") from exc
        if document.get("host_id") != host_id or record.get("profile_hash") != host_profile_hash(document):
            raise ValueError("HOST_PROFILE_MANIFEST_MISMATCH")
        home = record.get("home")
        if not isinstance(home, str) or not home:
            raise ValueError("HOST_HOME_FORMAT_INVALID")
        try:
            load_host_profile(target, absolute_path(home))
        except ValueError:
            raise
        paths.append(target)
    return tuple(paths)


def _uninstall_from_manifest(manifest_path: Path, options: UninstallOptions) -> SetupResult:
    manifest_path = absolute_path(manifest_path)
    try:
        assert_safe_target(manifest_path.parent, manifest_path, allow_missing=False, expected_type="file")
    except SafeFilesystemError as exc:
        raise ValueError("MANIFEST_INVALID") from exc
    manifest = _read_json(manifest_path)
    repo = absolute_path(str(manifest.get("engine_root") or manifest.get("repo_root", "")))
    knowledge_value = manifest.get("knowledge_root")
    knowledge = absolute_path(knowledge_value) if isinstance(knowledge_value, str) and knowledge_value else None
    runtime = absolute_path(str(manifest.get("runtime_root", "")))
    try:
        assert_safe_target(repo.parent, repo, allow_root=True, allow_missing=False, expected_type="dir")
        assert_safe_target(runtime.parent, runtime, allow_root=True, allow_missing=False, expected_type="dir")
        if runtime != manifest_path.parent:
            raise ValueError("MANIFEST_RUNTIME_MISMATCH")
        if knowledge is not None:
            # A disabled/private-local setup may record a knowledge root before
            # that root is initialized.  Uninstall must validate its lexical
            # separation without requiring an absent, untouched root to exist.
            assert_safe_target(knowledge.parent, knowledge, allow_root=True, allow_missing=True, expected_type="dir")
    except (SafeFilesystemError, ValueError) as exc:
        raise ValueError("MANIFEST_INVALID") from exc
    if runtime == repo or _within(repo, runtime) or (knowledge is not None and (knowledge == repo or _within(repo, knowledge) or knowledge == runtime or _within(runtime, knowledge) or _within(knowledge, runtime))):
        raise ValueError("MANIFEST_INVALID")
    knowledge_record = manifest.get("knowledge_repository") if isinstance(manifest.get("knowledge_repository"), Mapping) else {}
    knowledge_status = (
        inspect_knowledge_repository(knowledge, engine_root=repo, runtime_root=runtime)
        if knowledge is not None and knowledge.is_dir()
        else None
    )
    knowledge_retention = {
        "retained": True,
        "root": str(knowledge) if knowledge is not None else None,
        "root_digest": knowledge_status.root_digest if knowledge_status is not None else None,
        "remote_names": list(knowledge_status.remote_names) if knowledge_status is not None else [],
        "remote_fingerprint": knowledge_record.get("remote_fingerprint"),
        "remote_classification": knowledge_record.get("remote_classification"),
        "external_repository_deleted": False,
    }
    stores = manifest.get("knowledge_stores") if isinstance(manifest.get("knowledge_stores"), Mapping) else {}
    manifest_team = stores.get("team") if isinstance(stores, Mapping) else None
    retained_personal = {"enabled": True, **knowledge_retention, "status": "RETAINED"}
    if isinstance(manifest_team, Mapping):
        retained_team = dict(manifest_team)
        retained_team["status"] = "RETAINED" if retained_team.get("enabled") is True else "DISABLED"
        retained_team["knowledge_retained"] = True
        if retained_team.get("enabled") is True:
            retained_team["reason_code"] = "UNINSTALL_KNOWLEDGE_RETAINED"
    else:
        retained_team = {"status": "DISABLED", "enabled": False}
    retained_stores = {"personal": retained_personal, "team": retained_team}
    records = _manifest_host_records(manifest)
    host_homes = {
        host_id: absolute_path(record["home"])
        for host_id, record in records.items()
        if isinstance(record, Mapping) and isinstance(record.get("home"), str) and record.get("home")
    }
    profile_paths = _manifest_profile_paths(manifest, runtime, records)
    uninstall_settings = _settings_for_selection(
        SetupSelection(
            engine_root=repo,
            knowledge_root=knowledge or runtime.parent / (repo.name + "-knowledge"),
            runtime_root=runtime,
            hosts=tuple(records),
            host_homes=host_homes,
            host_profiles=profile_paths,
            skip_venv=True,
            non_interactive=True,
        )
    )
    scheduler_result: dict[str, Any] = {
        "ok": True,
        "requested": options.remove_scheduler,
        "status": "NOT_REQUESTED" if not options.remove_scheduler else "PLANNED",
        "reason_code": "NOT_REQUESTED" if not options.remove_scheduler else "PLANNED",
        "registered": False,
        "removed": False,
        "job_removed": False,
    }
    if options.remove_scheduler and options.check_only:
        from .task_scheduler import unregister_scheduler

        scheduler_result = unregister_scheduler(uninstall_settings, check_only=True)
    targets: dict[Path, tuple[bytes, dict[str, Any]]] = {}
    hook_ids_by_path: dict[Path, set[str]] = {}
    hook_details_by_path: dict[Path, dict[str, Any]] = {}
    for host_id, record in records.items():
        hook_path = _manifest_path_value(record, "hook_config_path")
        if hook_path.is_file():
            try:
                assert_safe_target(hook_path.parent, hook_path, allow_missing=False, expected_type="file")
            except SafeFilesystemError as exc:
                raise ValueError("MANIFEST_TARGET_INVALID") from exc
            managed = {item for item in record.get("managed_hook_ids", ()) if isinstance(item, str)}
            hook_ids_by_path.setdefault(hook_path, set()).update(managed)
            hook_details_by_path.setdefault(hook_path, {"kind": "hook-remove", "host_id": host_id})
        context_path = _manifest_path_value(record, "context_path")
        if context_path.is_file():
            try:
                assert_safe_target(context_path.parent, context_path, allow_missing=False, expected_type="file")
            except SafeFilesystemError as exc:
                raise ValueError("MANIFEST_TARGET_INVALID") from exc
            text, style = _load_text(context_path)
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            removed = remove_managed_context(normalized)
            if removed != text:
                if style != "\n":
                    removed = removed.replace("\n", style)
                targets[context_path] = (removed.encode("utf-8"), {"kind": "context-remove", "host_id": host_id})
    for hook_path, managed in hook_ids_by_path.items():
        current = _read_json(hook_path, {"hooks": {}})
        raw = _json_bytes(remove_managed_hooks(current, managed or set(MANAGED_HOOK_IDS)), _text_style(hook_path.read_bytes()))
        targets[hook_path] = (raw, hook_details_by_path[hook_path])
    codex_record = records.get("codex-cli") or records.get("codex-app")
    config_backup = manifest.get("config_backup")
    if options.restore_config_backup and codex_record and isinstance(config_backup, str) and absolute_path(config_backup).is_file():
        config_path = _manifest_path_value(codex_record, "home") / "config.toml"
        backup_path = absolute_path(config_backup)
        try:
            assert_safe_target(config_path.parent, backup_path, allow_missing=False, expected_type="file")
        except SafeFilesystemError as exc:
            raise ValueError("MANIFEST_BACKUP_INVALID") from exc
        targets[config_path] = (backup_path.read_bytes(), {"kind": "config-restore"})
    if options.check_only:
        plans = tuple(InstallPlanItem(path, "remove-or-restore", _hash_path(path), _sha256(raw), None, details) for path, (raw, details) in sorted(targets.items(), key=lambda item: str(item[0])))
        scheduler_ok = bool(scheduler_result.get("ok"))
        return SetupResult(
            scheduler_ok,
            "CHECK_ONLY" if scheduler_ok else "SCHEDULER_UNINSTALL_BLOCKED",
            manifest_path,
            plan=plans,
            errors=() if scheduler_ok else ({"error_code": str(scheduler_result.get("reason_code") or "SCHEDULER_UNREGISTER_FAILED"), "stage": "scheduler"},),
            message="uninstall check-only did not mutate managed, runtime, knowledge, or scheduler paths",
            knowledge=knowledge_retention,
            scheduler=scheduler_result,
            team=retained_team,
            knowledge_stores=retained_stores,
        )
    tx = _Transaction(runtime)
    changed: list[Path] = []
    backups: list[Path] = []
    errors: list[Mapping[str, Any]] = []
    skill_results: list[dict[str, Any]] = []
    try:
        for path, (raw, details) in targets.items():
            before = _hash_path(path)
            backup = tx.mutate_file(path, raw, details=details)
            after = _hash_path(path)
            if before != after:
                changed.append(path)
            if backup:
                backups.append(backup)
        if options.remove_skills:
            for host_id, record in records.items():
                destination_value = record.get("skill_destination")
                if not isinstance(destination_value, str):
                    continue
                destination = absolute_path(destination_value)
                skill_root_value = record.get("skill_root")
                skill_root = absolute_path(skill_root_value) if isinstance(skill_root_value, str) and skill_root_value else destination.parent
                try:
                    assert_safe_target(skill_root.parent, skill_root, allow_root=True, allow_missing=False, expected_type="dir")
                    if destination.parent != skill_root:
                        raise ValueError("MANIFEST_SKILL_ROOT_MISMATCH")
                    if destination.is_symlink():
                        assert_safe_target(skill_root, destination.parent, allow_root=True, allow_missing=False, expected_type="dir")
                    else:
                        assert_safe_target(skill_root, destination, allow_missing=True, expected_type="dir")
                except (SafeFilesystemError, ValueError) as exc:
                    raise ValueError("MANIFEST_SKILL_TARGET_INVALID") from exc
                binding_path: Path | None = None
                binding_value = record.get("skill_binding_path")
                binding_expected = record.get("skill_binding_hash")
                if isinstance(binding_value, str) and binding_value:
                    binding_path = absolute_path(binding_value)
                    try:
                        if binding_path.parent != skill_root:
                            raise ValueError("MANIFEST_SKILL_BINDING_ROOT_MISMATCH")
                        assert_safe_target(skill_root, binding_path, allow_missing=True, expected_type="file")
                    except (SafeFilesystemError, ValueError) as exc:
                        raise ValueError("MANIFEST_SKILL_BINDING_INVALID") from exc
                    current_binding = _hash_path(binding_path)
                    if current_binding is not None and (
                        not isinstance(binding_expected, str)
                        or current_binding != binding_expected
                    ):
                        errors.append({"error_code": "UNINSTALL_CONFLICT", "host_id": host_id, "path": str(binding_path)})
                        skill_results.append({"host_id": host_id, "removed": False, "reason_code": "UNINSTALL_CONFLICT", "path": str(destination)})
                        continue
                expected = record.get("installed_skill_hash")
                removed = remove_installed_skill(destination, str(expected) if isinstance(expected, str) else None, force=options.force)
                skill_results.append({"host_id": host_id, **removed})
                if removed.get("removed"):
                    changed.append(destination)
                    if binding_path is not None:
                        try:
                            binding_removed = safe_unlink(
                                skill_root,
                                binding_path,
                                expected_digest=str(binding_expected) if isinstance(binding_expected, str) else None,
                                allow_missing=True,
                            )
                        except SafeFilesystemError as exc:
                            raise ValueError("SKILL_BINDING_REMOVE_FAILED") from exc
                        if binding_removed:
                            changed.append(binding_path)
                elif removed.get("reason_code") == "UNINSTALL_CONFLICT":
                    errors.append({"error_code": "UNINSTALL_CONFLICT", "host_id": host_id, "path": str(destination)})
        if options.remove_scheduler:
            from .task_scheduler import unregister_scheduler

            scheduler_result = unregister_scheduler(uninstall_settings)
            if not scheduler_result.get("ok"):
                raise ValueError(str(scheduler_result.get("reason_code") or "SCHEDULER_UNREGISTER_FAILED"))
            if scheduler_result.get("removed") and isinstance(scheduler_result.get("state_path"), str):
                changed.append(Path(str(scheduler_result["state_path"])))
            changed.extend(Path(str(path)) for path in scheduler_result.get("removed_artifacts", ()) if isinstance(path, str))
        tx.commit()
        if options.remove_runtime_cache:
            for name in ("cache", "team-cache"):
                cache = runtime / name
                if cache.is_dir():
                    safe_remove_tree(runtime, cache)
                    changed.append(cache)
        if options.remove_runtime:
            for name in (*RUNTIME_DIRECTORY_NAMES, *TEAM_RUNTIME_DIRECTORY_NAMES):
                child = runtime / name
                if child.exists():
                    safe_remove_tree(runtime, child)
                    changed.append(child)
        if options.remove_venv:
            venv = repo / ".venv"
            if manifest.get("venv_created") and _within(repo, venv) and venv.is_dir():
                safe_remove_tree(repo, venv)
                changed.append(venv)
        updated = dict(manifest)
        updated["status"] = "UNINSTALLED"
        updated["uninstalled_at"] = _now().isoformat()
        updated["knowledge_retained"] = True
        _atomic_write(manifest_path, _json_bytes(updated))
        ok = not errors
        return SetupResult(ok, "UNINSTALLED" if ok else "UNINSTALL_CONFLICT", manifest_path, changed_paths=tuple(dict.fromkeys(changed)), backups=tuple(dict.fromkeys(backups)), errors=tuple(errors), rollback={"transaction": tx.transaction_id, "skills": skill_results}, message="Managed Hook/context/Skill targets were processed; the personal and team knowledge stores were retained", knowledge=knowledge_retention, scheduler=scheduler_result, team=retained_team, knowledge_stores=retained_stores)
    except Exception as exc:
        rollback = tx.rollback()
        return SetupResult(False, "ROLLED_BACK", manifest_path, errors=({"error_code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__},), rollback=rollback, knowledge=knowledge_retention, team=retained_team, knowledge_stores=retained_stores)


def uninstall(settings_or_manifest: Settings | Path | str, options: UninstallOptions | bool = UninstallOptions(), remove_runtime_cache: bool = False) -> SetupResult | dict[str, Any]:
    if isinstance(settings_or_manifest, Settings):
        if isinstance(options, bool):
            options = UninstallOptions(restore_config_backup=options, remove_runtime_cache=remove_runtime_cache)
        return _uninstall_from_manifest(settings_or_manifest.paths.install_manifest_path, options)
    manifest_path = _resolve(settings_or_manifest)
    if isinstance(options, bool):
        options = UninstallOptions(restore_config_backup=options, remove_runtime_cache=remove_runtime_cache)
    result = _uninstall_from_manifest(manifest_path, options)
    manifest = _read_json(manifest_path)
    codex = _manifest_host_records(manifest).get("codex-cli", {})
    return {"ok": result.ok, "hooks_path": codex.get("hook_config_path"), "agents_path": codex.get("context_path"), "agents_changed": bool(result.changed_paths), "restored_config": options.restore_config_backup, "removed_runtime_paths": [str(path) for path in result.changed_paths if "cache" in str(path).casefold()], "result": result.to_dict()}


def _git_update_metadata(repo: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "NOT_A_GIT_REPOSITORY",
        "head": None,
        "working_tree_dirty": None,
        "remote_names": [],
    }
    try:
        probe = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        result["status"] = "GIT_PROBE_FAILED"
        result["reason_code"] = type(exc).__name__
        return result
    if probe.returncode != 0 or probe.stdout.strip().casefold() != "true":
        return result
    result["status"] = "OK"
    try:
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        result["head"] = head.stdout.strip() if head.returncode == 0 and head.stdout.strip() else None
        dirty = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        result["working_tree_dirty"] = bool(dirty.stdout.strip()) if dirty.returncode == 0 else None
        remotes = subprocess.run(
            ["git", "-C", str(repo), "remote"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        result["remote_names"] = sorted({line.strip() for line in remotes.stdout.splitlines() if line.strip()}) if remotes.returncode == 0 else []
    except (OSError, subprocess.SubprocessError) as exc:
        result["status"] = "GIT_METADATA_PARTIAL"
        result["reason_code"] = type(exc).__name__
    return result


def _migration_update_metadata(settings: Settings) -> dict[str, Any]:
    source_root = Path(settings.paths.codex_home) / "memories"
    if not source_root.is_dir():
        return {"status": "NOT_CONFIGURED", "source_root": str(source_root), "planned_items": 0}
    try:
        from .migrate import plan_migration

        plan = plan_migration(source_root, settings)
        return {
            "status": "DRY_RUN",
            "source_root": str(source_root),
            "plan_hash": plan.plan_hash,
            "planned_items": len(plan.items),
            "source_hashes": dict(sorted(plan.source_hashes.items())),
            "inventory_hash": plan.inventory.inventory_hash if plan.inventory else None,
        }
    except (OSError, UnicodeError, ValueError) as exc:
        return {"status": "BLOCKED", "source_root": str(source_root), "planned_items": 0, "reason_code": str(exc)}

def _build_update_preflight(selection: SetupSelection, settings: Settings, previous: Mapping[str, Any]) -> dict[str, Any]:
    repo = _resolve(selection.engine_root or selection.repo_root)
    source = _source_skill(repo)
    source_hash = canonical_tree_hash(source)
    current_templates = {host_id: _hook_template_hash(repo, host_id, selection.runtime_root) for host_id in selection.managed_hosts}
    installed_skills: dict[str, str | None] = {}
    previous_hosts = previous.get("hosts", {}) if isinstance(previous.get("hosts"), Mapping) else {}
    for host_id in selection.managed_hosts:
        record = previous_hosts.get(host_id, {}) if isinstance(previous_hosts, Mapping) else {}
        destination = Path(str(record.get("skill_destination", ""))).expanduser() if isinstance(record, Mapping) and record.get("skill_destination") else _resolve(settings.hosts[host_id].skill_roots[0]) / source.name
        installed_skills[host_id] = _dir_hash(destination)
    stored_templates = {
        host_id: str(record.get("hook_template_hash"))
        for host_id, record in previous_hosts.items()
        if isinstance(record, Mapping) and isinstance(record.get("hook_template_hash"), str)
    }
    stored_skills = {
        host_id: str(record.get("installed_skill_hash"))
        for host_id, record in previous_hosts.items()
        if isinstance(record, Mapping) and isinstance(record.get("installed_skill_hash"), str)
    }
    template_changes = sorted(
        host_id for host_id, value in current_templates.items()
        if stored_templates.get(host_id) not in {None, value}
    )
    skill_changes = sorted(
        host_id for host_id, value in installed_skills.items()
        if stored_skills.get(host_id) not in {None, value}
    )
    stored_schema = previous.get("hook_schema_hash")
    current_schema = _hook_schema_hash(repo)
    backup_targets = [
        item.to_dict()
        for item in render_install_plan(selection)
        if item.target != _manifest_path(selection.runtime_root or _resolve(settings.paths.runtime_root))
        and item.before_hash != item.after_hash
    ]
    previous_context_version = previous.get("agents_block_version")
    if previous_context_version is None and isinstance(previous.get("managed_marker"), Mapping):
        previous_context_version = previous["managed_marker"].get("version")
    return {
        "schema_version": 1,
        "generated_at": _now().isoformat(),
        "git": _git_update_metadata(repo),
        "current": {
            "source_skill_hash": source_hash,
            "hook_template_hashes": current_templates,
            "hook_schema_hash": current_schema,
            "managed_context_version": "v1",
        },
        "previous": {
            "source_skill_hash": previous.get("skill_source_hash"),
            "hook_template_hashes": stored_templates,
            "hook_schema_hash": stored_schema,
            "managed_context_version": previous_context_version,
        },
        "comparison": {
            "source_skill_changed": previous.get("skill_source_hash") not in {None, source_hash},
            "hook_templates_changed": template_changes,
            "hook_schema_changed": stored_schema not in {None, current_schema},
            "installed_skills_changed": skill_changes,
            "managed_context_changed": previous_context_version not in {None, "v1"},
        },
        "migration": _migration_update_metadata(settings),
        "backup_required": bool(backup_targets),
        "backup_targets": backup_targets,
    }


def update(settings: Settings | SetupSelection | Mapping[str, Any], check_only: bool = False) -> SetupResult:
    manifest: dict[str, Any] = {}
    if isinstance(settings, Settings):
        manifest_path = settings.paths.install_manifest_path
        manifest = _read_json(manifest_path)
        if not manifest:
            raise ValueError("UPDATE_MANIFEST_REQUIRED")
        records = _manifest_host_records(manifest)
        knowledge_record = manifest.get("knowledge_repository") if isinstance(manifest.get("knowledge_repository"), Mapping) else {}
        work_hosts = _parse_values(manifest.get("work_hosts", ()))
        if not work_hosts:
            raise ValueError("UPDATE_WORK_HOSTS_REQUIRED")
        organizer_record = manifest.get("organizer") if isinstance(manifest.get("organizer"), Mapping) else {}
        homes = {host_id: _resolve(str(record.get("home"))) for host_id, record in records.items() if isinstance(record.get("home"), str)}
        profile_paths = _manifest_profile_paths(manifest, settings.paths.runtime_root, records)
        skill_mode = next((str(record.get("skill_mode")) for record in records.values() if isinstance(record, Mapping) and record.get("skill_mode") in {"copy", "link"}), "copy")
        stores = manifest.get("knowledge_stores") if isinstance(manifest.get("knowledge_stores"), Mapping) else {}
        team_record = stores.get("team") if isinstance(stores, Mapping) else None
        team_enabled = team_record.get("enabled") if isinstance(team_record, Mapping) and type(team_record.get("enabled")) is bool else None
        team_root = team_record.get("root") if team_enabled is True and isinstance(team_record, Mapping) and isinstance(team_record.get("root"), str) else None
        team_member = team_record.get("team_member_id") if team_enabled is True and isinstance(team_record, Mapping) and isinstance(team_record.get("team_member_id"), str) else None
        selection = SetupSelection(
            engine_root=settings.paths.engine_root,
            knowledge_root=settings.paths.knowledge_root,
            runtime_root=settings.paths.runtime_root,
            hosts=work_hosts,
            work_hosts=work_hosts,
            host_homes=homes,
            host_profiles=profile_paths,
            python_exe=manifest.get("python_exe") or sys.executable,
            providers=manifest.get("providers", ()),
            organizer_provider=organizer_record.get("provider_id") if organizer_record.get("status") == "READY" else None,
            organizer_host=organizer_record.get("host_id") if organizer_record.get("status") == "READY" else None,
            privacy_profile=str(manifest.get("privacy_profile", "private-reusable")),
            sync=bool(manifest.get("sync_enabled", False)),
            experiment=bool(manifest.get("experiment_enabled", False)),
            scheduler=bool(manifest.get("scheduler_requested", False)),
            skill_mode=skill_mode,
            skip_venv=bool(manifest.get("skip_venv", True)),
            non_interactive=True,
            accept_plan=True,
            knowledge_mode=str(knowledge_record.get("mode", "local")),
            remote_name=str(knowledge_record.get("remote_name") or "origin"),
            branch=str(knowledge_record.get("branch") or "main"),
            preserve_existing_knowledge=True,
            team_knowledge_root=team_root,
            team_member_id=team_member,
            team_knowledge=team_enabled,
            defer_team_validation=True,
        )
    elif isinstance(settings, SetupSelection):
        selection = settings
    elif isinstance(settings, Mapping):
        selection = SetupSelection(**dict(settings))
    else:
        raise TypeError("UPDATE_SETTINGS_REQUIRED")
    if not selection.accept_plan:
        selection = replace(selection, accept_plan=True)
    selection = _normalise_selection(selection)
    runtime = _resolve(selection.runtime_root or _resolve(_settings_for_selection(selection).paths.runtime_root))
    update_settings = _settings_for_selection(selection)
    if not manifest:
        manifest = _previous_manifest(runtime)
    if not manifest:
        raise ValueError("UPDATE_MANIFEST_REQUIRED")
    knowledge_record = manifest.get("knowledge_repository")
    if not isinstance(knowledge_record, Mapping):
        raise ValueError("UPDATE_KNOWLEDGE_MANIFEST_INVALID")
    manifest_engine = _resolve(str(manifest.get("engine_root") or manifest.get("repo_root", "")))
    manifest_knowledge = _resolve(str(manifest.get("knowledge_root", "")))
    manifest_runtime = _resolve(str(manifest.get("runtime_root", "")))
    if (
        _resolve(selection.engine_root or selection.repo_root) != manifest_engine
        or _resolve(selection.knowledge_root) != manifest_knowledge
        or runtime != manifest_runtime
    ):
        raise ValueError("UPDATE_ROOT_MISMATCH")
    selection = replace(
        selection,
        knowledge_mode=str(knowledge_record.get("mode", "local")),
        github_repository=None,
        remote_name=str(knowledge_record.get("remote_name") or "origin"),
        branch=str(knowledge_record.get("branch") or "main"),
        sync=knowledge_record.get("sync_enabled") is True,
        preserve_existing_knowledge=True,
        accept_plan=True,
        defer_team_validation=True,
    )
    update_settings = _settings_for_selection(selection)
    preflight = _build_update_preflight(selection, update_settings, manifest)
    result = setup(selection, check_only)
    if not result.ok:
        return replace(result, preflight=preflight)
    if not check_only and result.manifest_path:
        artifact_path = result.manifest_path.parent / "update-preflight.json"
        artifact = {**preflight, "applied_status": result.status, "changed_paths": [str(path) for path in result.changed_paths]}
        invalidation_path = result.manifest_path.parent / "canary-invalidation.json"
        diagnostic_paths: list[Path] = []
        try:
            _atomic_write(artifact_path, _json_bytes(artifact))
            diagnostic_paths.append(artifact_path)
            preflight = {**preflight, "artifact_path": str(artifact_path), "artifact_sha256": _hash_path(artifact_path)}
            changed_paths = tuple(dict.fromkeys((*result.changed_paths, *diagnostic_paths)))
            _atomic_write(invalidation_path, _json_bytes({"schema_version": 1, "invalidated_at": _now().isoformat(), "reason": "UPDATE_APPLIED", "changed_paths": [str(path) for path in changed_paths]}))
            diagnostic_paths.append(invalidation_path)
            result = replace(result, changed_paths=tuple(dict.fromkeys((*changed_paths, invalidation_path))), preflight=preflight)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and str(exc) else type(exc).__name__
            diagnostic_errors = (*result.errors, {"error_code": reason, "stage": "diagnostics", "retryable": True})
            retained_rollback = dict(result.rollback or {})
            retained_rollback.update(
                {
                    "status": "INSTALLATION_RETAINED",
                    "rolled_back": False,
                    "reason_codes": list(dict.fromkeys([*retained_rollback.get("reason_codes", ()), "DIAGNOSTICS_BLOCKED", "INSTALLATION_RETAINED"])),
                }
            )
            blocked_preflight = {
                **preflight,
                "diagnostics_status": "BLOCKED",
                "diagnostics_error": reason,
                "diagnostics_paths": [str(path) for path in diagnostic_paths],
            }
            return replace(
                result,
                ok=False,
                status="DIAGNOSTICS_BLOCKED",
                changed_paths=tuple(dict.fromkeys((*result.changed_paths, *diagnostic_paths))),
                errors=diagnostic_errors,
                rollback=retained_rollback,
                message="Update core installation committed, but diagnostic artifact write failed; rerun diagnostics without reinstalling",
                preflight=blocked_preflight,
            )
    else:
        result = replace(result, preflight=preflight)
    return result

def install(repo_root: Path, codex_home: Path, python_exe: Path, skip_venv: bool = False, check_only: bool = False, *, organizer_provider: str | None = None, organizer_host: str | None = None) -> dict[str, Any]:
    selection = SetupSelection(repo_root=repo_root, runtime_root=_resolve(codex_home) / "external-intelligence", hosts=("codex-cli",), host_homes={"codex-cli": codex_home}, python_exe=python_exe, organizer_provider=organizer_provider, organizer_host=organizer_host, skip_venv=skip_venv, non_interactive=True, accept_plan=True)
    result = setup(selection, check_only)
    if not result.ok:
        raise RuntimeError(json.dumps(result.to_dict(), ensure_ascii=False))
    return {"ok": True, "manifest": str(result.manifest_path), "doctor": dict(result.doctor or {}), "agents_changed": any(str(path).endswith("AGENTS.md") for path in result.changed_paths), "agents_path": str(_resolve(codex_home) / "AGENTS.md"), "trust_instruction": "Run the host Hook trust/consent flow in the official UI. Static setup never claims real Hook verification.", "status": result.status, "plan": [item.to_dict() for item in result.plan]}


def _guided_interactive_selection(args: argparse.Namespace) -> SetupSelection:
    """Collect a plain-language setup selection without mutating the machine.

    This is deliberately separate from the non-interactive compatibility path.
    It keeps the old flags useful for scripts while making the human flow
    explicit about the one organizer and the many work hosts.
    """

    def prompt_text(label: str, default: str | None = None, *, example: str | None = None) -> str:
        suffix = f"（例: {example}）" if example else ""
        if default is not None and not Path(default).is_absolute():
            suffix = f" [{default}]" + suffix
        write_utf8(f"{label}{suffix}: ", end="")
        answer = input().strip()
        return answer or (default or "")

    def prompt_required(label: str, *, example: str) -> str:
        answer = prompt_text(label, example=example)
        if not answer:
            raise ValueError("INTERACTIVE_VALUE_REQUIRED")
        return answer

    def prompt_bool(label: str, default: bool) -> bool:
        default_text = "Y/n" if default else "y/N"
        answer = prompt_text(f"{label} ({default_text})", "yes" if default else "no").casefold()
        if answer in {"y", "yes", "1", "true"}:
            return True
        if answer in {"n", "no", "0", "false"}:
            return False
        raise ValueError("INTERACTIVE_BOOLEAN_INVALID")

    def available_index(choices: Sequence[SetupChoice], preferred: str | None = None) -> int:
        if preferred:
            for index, choice in enumerate(choices, 1):
                if choice.value == preferred and choice.selectable:
                    return index
        for index, choice in enumerate(choices, 1):
            if choice.selectable:
                return index
        raise ValueError("SETUP_CHOICES_REQUIRED")

    def prompt_single(title: str, choices: Sequence[SetupChoice], *, preferred: str | None = None) -> str:
        rendered = render_single_choice(title, choices)
        write_utf8(rendered)
        default = str(available_index(choices, preferred))
        answer = input().strip() or default
        # Numeric input is the documented form.  Accepting a value is useful
        # for migration from the old wizard and does not expose private data.
        if not answer.isdecimal():
            for choice in choices:
                if choice.value == answer and choice.selectable:
                    return choice.value
        return parse_single_choice(answer, choices)

    def prompt_multiple(title: str, choices: Sequence[SetupChoice], *, preferred: Sequence[str] = ()) -> tuple[str, ...]:
        rendered = render_multiple_choices(title, choices)
        write_utf8(rendered)
        default_values = [
            str(index)
            for index, choice in enumerate(choices, 1)
            if choice.selectable and (not preferred or choice.value in preferred)
        ]
        if not default_values:
            default_values = [str(available_index(choices))]
        answer = input().strip() or ",".join(default_values)
        if not any(character.isdecimal() for character in answer):
            selected = tuple(item.strip() for item in answer.split(",") if item.strip())
            if selected and all(any(choice.value == item and choice.selectable for choice in choices) for item in selected):
                return tuple(dict.fromkeys(selected))
        return parse_multiple_choices(answer, choices)

    def read_manifest(path: Path | None) -> dict[str, Any]:
        if path is None:
            return {}
        try:
            value = _read_json(path, {}) if path.is_file() else {}
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def previous_values(manifest: Mapping[str, Any]) -> tuple[tuple[str, ...], dict[str, Path], tuple[str | None, str | None]]:
        raw_hosts = manifest.get("work_hosts")
        if isinstance(raw_hosts, (list, tuple)):
            hosts = tuple(str(item) for item in raw_hosts if isinstance(item, str) and item)
        else:
            records = manifest.get("hosts")
            hosts = tuple(str(item) for item in records if isinstance(item, str) and item) if isinstance(records, Mapping) else ()
        homes: dict[str, Path] = {}
        records = manifest.get("hosts")
        if isinstance(records, Mapping):
            for host_id, record in records.items():
                if isinstance(record, Mapping) and isinstance(record.get("home"), str) and record["home"]:
                    homes[str(host_id)] = Path(str(record["home"])).expanduser()
        organizer = manifest.get("organizer")
        if isinstance(organizer, Mapping):
            provider = organizer.get("provider_id") if isinstance(organizer.get("provider_id"), str) else None
            host = organizer.get("host_id") if isinstance(organizer.get("host_id"), str) else None
        else:
            provider, host = None, None
        return hosts, homes, (provider, host)

    def executable_names(host_id: str) -> tuple[str, ...]:
        return {
            "codex-cli": ("codex",),
            "claude-code": ("claude",),
            "gemini-cli": ("gemini",),
            "qwen-code": ("qwen",),
        }.get(host_id, (host_id,))

    def host_choices(homes: Mapping[str, Path], previous_hosts: Sequence[str], profile_ids: Sequence[str]) -> tuple[SetupChoice, ...]:
        values = list(PUBLIC_CLI_HOST_IDS)
        values.extend(item for item in profile_ids if item not in values)
        values.extend(item for item in previous_hosts if item not in values)
        choices: list[SetupChoice] = []
        for host_id in values:
            if host_id in homes or any(shutil.which(name) for name in executable_names(host_id)):
                status = "AVAILABLE"
                help_text = "このCLIを選択できます。"
            elif is_custom_host_id(host_id):
                status = "NOT_FOUND"
                help_text = "実行ファイルとhost homeを確認してください。"
            else:
                status = "NOT_FOUND"
                help_text = "実行ファイルをインストールしてから選択してください。"
            choices.append(SetupChoice(host_id, {"codex-cli": "Codex CLI", "claude-code": "Claude Code", "gemini-cli": "Gemini CLI", "qwen-code": "Qwen Code"}.get(host_id, host_id), status, status == "AVAILABLE", help_text))
        return tuple(choices)

    setup_flow = getattr(args, "command", None) == "setup" or bool(getattr(args, "setup", False))
    if not setup_flow:
        raise ValueError("SETUP_COMMAND_REQUIRED")

    explicit_profile_paths = tuple(Path(item).expanduser() for item in (getattr(args, "host_profile", ()) or ()))
    profile_ids: list[str] = []
    for path in explicit_profile_paths:
        profile_ids.append(load_host_profile(path, Path(".")).host_id)

    raw_host_homes = list(getattr(args, "host_home", ()) or ())
    legacy_codex_home = getattr(args, "codex_home", None)
    if legacy_codex_home:
        raw_host_homes.append("codex-cli=" + str(legacy_codex_home))
    requested_homes = _parse_host_homes(raw_host_homes, allowed_hosts=KNOWN_HOSTS | frozenset(profile_ids))
    explicit_runtime = getattr(args, "runtime_root", None)
    # Resolve the effective runtime before showing any defaults.  The guided
    # apply path uses this same location when the flag is omitted, so an
    # existing manifest can restore every omitted answer (including profiles
    # and team settings) without probing unrelated host directories.
    runtime_hint = Path(explicit_runtime).expanduser() if explicit_runtime else _default_runtime_root()
    previous = read_manifest(_manifest_path(runtime_hint))
    expected_engine = _resolve(getattr(args, "engine_root", None) or getattr(args, "repo", None) or Path.cwd())
    manifest_engine = previous.get("engine_root") or previous.get("repo_root") if isinstance(previous, Mapping) else None
    # The default runtime is shared by the user's installations.  Restore
    # values only from an active manifest belonging to this checkout; an
    # unrelated project must not change this wizard's defaults or prompt
    # sequence.
    if (
        previous.get("status") != "INSTALLED"
        or not isinstance(manifest_engine, str)
        or _resolve(manifest_engine) != expected_engine
    ):
        previous = {}
    previous_hosts, previous_homes, previous_organizer = previous_values(previous)
    requested_homes = {**previous_homes, **requested_homes}

    # Rehydrate custom profiles from the machine-local runtime when rerunning
    # setup.  The source path is never displayed and is only read after the
    # user chooses to retain the existing host.
    runtime_for_profiles = runtime_hint
    for host_id in previous_hosts:
        if is_custom_host_id(host_id) and host_id not in profile_ids:
            profile_path = _resolve(runtime_for_profiles) / "host-profiles" / f"{host_id}.json"
            if profile_path.is_file():
                explicit_profile_paths += (profile_path,)
                profile_ids.append(host_id)

    # 1-3. Organizer first, then (only for subscription organizers) its host.
    write_utf8(render_intro())
    organizer_provider = getattr(args, "organizer_provider", None)
    organizer_host = getattr(args, "organizer_host", None)
    legacy_wizard = False
    organizer_choices = (
        SetupChoice("subscription-cli", "サブスクリプション型のAI", "AVAILABLE", True, "選択後に使用する公開CLIを1つ選びます。"),
        SetupChoice("ollama", "OllamaのAI", "AVAILABLE" if shutil.which("ollama") else "NOT_CONFIGURED", bool(shutil.which("ollama")), "Ollamaを起動してから選択してください。"),
        SetupChoice("local-openai-compatible", "接続したローカルAI", "NOT_CONFIGURED", False, "ローカルAIの接続設定を先に用意してください。"),
    )
    if organizer_provider is None:
        # A raw provider value is accepted only as a narrow compatibility
        # bridge for the pre-guided wizard; it is not shown in the UI.
        write_utf8(render_single_choice("記憶の整理AI（候補を整理・統合するAI。1つだけ選びます）", organizer_choices))
        organizer_answer = input().strip()
        if organizer_answer in {"ollama", "subscription-cli", "local-openai-compatible", "cloud-api"}:
            organizer_provider = organizer_answer
            legacy_wizard = True
        elif not organizer_answer and previous_organizer[0]:
            # On a rerun an empty answer means "keep the current organizer".
            # This also retains an older provider that is not currently
            # selectable, so setup never changes it by accident.
            organizer_provider = previous_organizer[0]
        else:
            organizer_provider = parse_single_choice(organizer_answer or "1", organizer_choices)
    if organizer_provider == "subscription-cli" and organizer_host is None:
        choices = host_choices(requested_homes, previous_hosts, profile_ids)
        previous_host = previous_organizer[1]
        write_utf8(render_single_choice("サブスクリプション型整理AIで使うCLI（1つだけ選びます）", choices))
        organizer_answer = input().strip()
        if organizer_answer in {"ollama", "subscription-cli", "local-openai-compatible", "cloud-api"}:
            # Old callers supplied the provider in the second prompt.  Keep
            # that invocation readable while preserving its requested mode.
            organizer_provider = organizer_answer
            organizer_host = None
            legacy_wizard = True
        elif not organizer_answer and previous_host and not any(choice.value == previous_host and choice.selectable for choice in choices):
            organizer_host = previous_host
        else:
            organizer_host = parse_single_choice(organizer_answer or str(available_index(choices, previous_host)), choices)

    requested_work_hosts = _parse_host_ids(getattr(args, "work_hosts", ()))
    legacy_hosts = _parse_host_ids(getattr(args, "hosts", ()))
    if legacy_hosts and requested_work_hosts and legacy_hosts != requested_work_hosts:
        raise ValueError("WORK_HOSTS_CONFLICT")
    explicit_work_hosts = requested_work_hosts or legacy_hosts
    if not explicit_work_hosts:
        if legacy_wizard:
            explicit_work_hosts = previous_hosts or ("codex-cli",)
        else:
            choices = host_choices(requested_homes, previous_hosts, profile_ids)
            selected_work_hosts = prompt_multiple(
                "作業・記憶取得CLI（hookで経験を送り、作業前に記憶を取得します。複数選べます）",
                choices,
                preferred=previous_hosts,
            )
            # Existing values are retained unless the user later uses an
            # explicit lifecycle removal operation.
            explicit_work_hosts = tuple(dict.fromkeys((*selected_work_hosts, *previous_hosts)))

    custom_documents: dict[str, Mapping[str, Any]] = {}
    if not legacy_wizard and prompt_bool("互換性のあるカスタムCLIを追加しますか", False):
        mode_answer = prompt_text("追加方法（new または existing）", "new")
        mode = mode_answer.casefold()
        pending_display_name: str | None = None
        # The concise guided variant can go directly from "yes" to the
        # display name.  Treat an unrecognised mode token as that name so an
        # older scripted prompt sequence remains understandable.
        if mode not in {"new", "1", "existing", "2", "既存", "import", "取り込み"}:
            pending_display_name = mode_answer
            mode = "new"
        if mode in {"existing", "2", "既存", "import", "取り込み"}:
            profile_path = Path(prompt_required("既存profileの場所", example="profile.json")).expanduser()
            host_home = Path(prompt_required("そのCLIのhost home", example="CLIの設定フォルダ")).expanduser()
            profile = load_host_profile(profile_path, host_home)
            if profile_path not in explicit_profile_paths:
                explicit_profile_paths += (profile_path,)
            profile_ids.append(profile.host_id)
            requested_homes[profile.host_id] = _resolve(host_home)
            explicit_work_hosts = tuple(dict.fromkeys((*explicit_work_hosts, profile.host_id)))
        else:
            adapter_choices = tuple(
                SetupChoice(host_id, {"codex-cli": "Codex CLI互換", "claude-code": "Claude Code互換", "gemini-cli": "Gemini CLI互換", "qwen-code": "Qwen Code互換"}[host_id], "AVAILABLE", True, "この公開CLIのhook形式を互換元にします。")
                for host_id in PUBLIC_CLI_HOST_IDS
            )
            adapter_id = prompt_single("互換元の公開CLI", adapter_choices)
            display_name = pending_display_name or prompt_required("表示名", example="My Compatible CLI")
            seed = re.sub(r"[^a-z0-9]+", "-", display_name.casefold()).strip("-") or "custom-cli"
            if not is_custom_host_id(seed):
                seed = seed + "-custom"
            host_id = seed
            executable_name = prompt_required("実行ファイル名", example=seed)
            host_home = prompt_required("host home", example="CLIの設定フォルダ")
            hook_path = prompt_required("hook設定の相対path", example=f".config/{seed}/settings.json")
            context_path = prompt_required("context相対path", example=f".config/{seed}/context.md")
            skill_root = prompt_required("Skill root相対path", example=f".config/{seed}/skills")
            document: dict[str, Any] = {
                "schema_version": 1,
                "host_id": host_id,
                "display_name": display_name,
                "host_family": PUBLIC_ADAPTER_FAMILIES[adapter_id],
                "adapter_id": adapter_id,
                "executable_names": [executable_name],
                "hook_config_path": hook_path,
                "global_context_path": context_path,
                "skill_roots": [skill_root],
            }
            try:
                build_host_profile(document, Path(host_home))
            except (TypeError, ValueError) as exc:
                raise ValueError("HOST_PROFILE_INVALID") from exc
            custom_documents[host_id] = document
            requested_homes[host_id] = _resolve(host_home)
            explicit_work_hosts = tuple(dict.fromkeys((*explicit_work_hosts, host_id)))

    previous_knowledge_record = previous.get("knowledge_repository") if isinstance(previous.get("knowledge_repository"), Mapping) else {}
    previous_knowledge_mode = previous_knowledge_record.get("mode") if isinstance(previous_knowledge_record.get("mode"), str) else None
    knowledge_mode = getattr(args, "knowledge_mode", None)
    if knowledge_mode is None:
        mode_choices = (
            SetupChoice("local", "このPCの個人ナレッジ", "AVAILABLE", True, "個人ナレッジをローカルに保存します。"),
            SetupChoice("github-new", "新しい非公開GitHubナレッジ", "AVAILABLE", True, "非公開リポジトリを作成して保存します。"),
            SetupChoice("github-existing", "既存の非公開GitHubナレッジ", "AVAILABLE", True, "既存の非公開リポジトリを使います。"),
        )
        write_utf8(render_single_choice("個人ナレッジの保存先", mode_choices))
        mode_answer = input().strip()
        if mode_answer in {choice.value for choice in mode_choices}:
            knowledge_mode = mode_answer
        else:
            knowledge_mode = parse_single_choice(
                mode_answer or str(available_index(mode_choices, previous_knowledge_mode)),
                mode_choices,
            )
    previous_knowledge = previous.get("knowledge_root")
    if not isinstance(previous_knowledge, str):
        repository = previous.get("knowledge_repository")
        previous_knowledge = repository.get("root") if isinstance(repository, Mapping) else None
    knowledge_root = getattr(args, "knowledge_root", None) or getattr(args, "personal_knowledge_root", None) or previous_knowledge
    runtime_root = runtime_hint
    default_base = Path.home() / ".external-intelligence"
    if knowledge_root is None:
        knowledge_root = prompt_text("個人ナレッジの保存先", str(default_base / "knowledge"))
    # A fresh invocation may still choose a custom runtime.  On a rerun the
    # effective default was resolved and loaded above, so do not ask again or
    # consume an answer that could silently reset the active installation.
    if not explicit_runtime and not previous:
        runtime_root = prompt_text("このPCだけで使うruntime保存先", str(runtime_hint))

    previous_team = previous.get("knowledge_stores", {}).get("team") if isinstance(previous.get("knowledge_stores"), Mapping) else previous.get("team")
    previous_team_enabled = isinstance(previous_team, Mapping) and previous_team.get("enabled") is True
    team_knowledge = getattr(args, "team_knowledge", None)
    if team_knowledge is None:
        team_knowledge = prompt_bool("任意のチームナレッジも使いますか（個人ナレッジとは別）", previous_team_enabled)
    team_knowledge_root = getattr(args, "team_knowledge_root", None)
    team_member_id = getattr(args, "team_member_id", None)
    if team_knowledge:
        if team_knowledge_root is None and isinstance(previous_team, Mapping) and isinstance(previous_team.get("root"), str):
            team_knowledge_root = previous_team["root"]
        if team_member_id is None and isinstance(previous_team, Mapping) and isinstance(previous_team.get("team_member_id"), str):
            team_member_id = previous_team["team_member_id"]
        if team_knowledge_root is None:
            team_knowledge_root = prompt_text("チームナレッジの保存先", str(default_base / "team-knowledge"))
        if team_member_id is None:
            team_member_id = prompt_text("チーム内での識別名", "member")

    # The compatibility branch keeps the old optional prompts consumable for
    # callers that still automate the original wizard.  The guided flow uses
    # safe defaults and does not burden users with settings unrelated to the
    # organizer/host choice.
    if legacy_wizard:
        github_repository = getattr(args, "github_repository", None)
        if knowledge_mode in {"github-new", "github-existing"} and not github_repository:
            github_repository = prompt_text("非公開GitHubリポジトリ（OWNER/REPOSITORY）", "owner/external-intelligence-knowledge")
        providers = _parse_values(getattr(args, "providers", ()), deduplicate=False)
        if not providers:
            providers = _parse_values(prompt_text("推論プロバイダの優先順", "local-openai-compatible,ollama,subscription-cli"), deduplicate=False)
        privacy_profile = getattr(args, "privacy_profile", "private-reusable")
        if privacy_profile == "private-reusable":
            privacy_profile = prompt_text("プライバシープロファイル", privacy_profile)
        sync_selection = getattr(args, "sync", None)
        sync = bool(sync_selection) if sync_selection is not None else prompt_bool("Git同期を有効にしますか", knowledge_mode in {"github-new", "github-existing"})
        experiment = bool(getattr(args, "experiment", False)) or prompt_bool("A/B測定を有効にしますか", False)
        scheduler = bool(getattr(args, "scheduler", False)) or prompt_bool("任意の保守schedulerを有効にしますか", False)
        skill_mode = getattr(args, "skill_mode", "copy")
        if skill_mode == "copy":
            skill_mode = prompt_text("Skillの導入方法（copy/link）", skill_mode)
    else:
        github_repository = getattr(args, "github_repository", None)
        providers = _parse_values(getattr(args, "providers", ()), deduplicate=False)
        privacy_profile = getattr(args, "privacy_profile", "private-reusable")
        sync_arg = getattr(args, "sync", None)
        sync = bool(sync_arg) if sync_arg is not None else (previous_knowledge_record.get("sync_enabled") is True if previous else knowledge_mode in {"github-new", "github-existing"})
        experiment = bool(getattr(args, "experiment", False)) or (previous.get("experiment_enabled") is True if previous else False)
        scheduler = bool(getattr(args, "scheduler", False)) or (previous.get("scheduler_requested") is True if previous else False)
        if previous and privacy_profile == "private-reusable" and isinstance(previous.get("privacy_profile"), str):
            privacy_profile = str(previous["privacy_profile"])
        skill_mode = getattr(args, "skill_mode", "copy")
        if previous and skill_mode == "copy":
            previous_hosts_record = previous.get("hosts") if isinstance(previous.get("hosts"), Mapping) else {}
            for previous_record in previous_hosts_record.values():
                if isinstance(previous_record, Mapping) and previous_record.get("skill_mode") in {"copy", "link"}:
                    skill_mode = str(previous_record["skill_mode"])
                    break
        if knowledge_mode in {"github-new", "github-existing"} and not github_repository and (not previous or knowledge_mode != previous_knowledge_mode):
            github_repository = prompt_text("非公開GitHubリポジトリ（OWNER/REPOSITORY）", "owner/external-intelligence-knowledge")

    remote_name = getattr(args, "remote_name", "origin")
    branch = getattr(args, "branch", "main")
    if previous and knowledge_mode == previous_knowledge_mode:
        if remote_name == "origin" and isinstance(previous_knowledge_record.get("remote_name"), str):
            remote_name = str(previous_knowledge_record["remote_name"])
        if branch == "main" and isinstance(previous_knowledge_record.get("branch"), str):
            branch = str(previous_knowledge_record["branch"])
    preserve_existing_knowledge = bool(previous and knowledge_mode == previous_knowledge_mode)

    parsed_homes = _parse_host_homes(requested_homes, allowed_hosts=KNOWN_HOSTS | frozenset(profile_ids) | frozenset(custom_documents))
    selection = SetupSelection(
        engine_root=getattr(args, "engine_root", None),
        knowledge_root=knowledge_root,
        personal_knowledge_root=knowledge_root,
        repo_root=getattr(args, "repo", None),
        runtime_root=runtime_root,
        team_knowledge_root=team_knowledge_root,
        team_member_id=team_member_id,
        team_knowledge=bool(team_knowledge),
        hosts=explicit_work_hosts,
        work_hosts=explicit_work_hosts,
        include_codex_app=bool(getattr(args, "include_codex_app", False)),
        host_homes=parsed_homes,
        host_profiles=explicit_profile_paths,
        host_profile_documents=custom_documents or None,
        python_exe=getattr(args, "python_exe", None),
        providers=providers,
        organizer_provider=organizer_provider,
        organizer_host=organizer_host,
        privacy_profile=privacy_profile,
        sync=sync,
        experiment=experiment,
        scheduler=scheduler,
        skill_mode=skill_mode,
        skip_venv=bool(getattr(args, "skip_venv", False)),
        non_interactive=False,
        knowledge_mode=knowledge_mode,
        github_repository=github_repository,
        github_executable=getattr(args, "github_executable", "gh"),
        remote_name=remote_name,
        branch=branch,
        accept_plan=False,
        confirm_github_create=getattr(args, "confirm_github_create", None),
        preserve_existing_knowledge=preserve_existing_knowledge,
    )
    normalized = _normalise_selection(selection)
    previous_for_summary = previous
    actions = render_install_plan(normalized, previous=previous_for_summary)
    # Keep the stable heading consumed by older callers; the guided summary
    # below intentionally contains labels only and never path values.
    write_utf8("\nSetup plan")
    write_utf8(render_setup_summary(normalized, previous_for_summary, actions))
    check_only = bool(getattr(args, "check_only", False) or getattr(args, "dry_run", False))
    if not check_only and not prompt_bool("この内容を適用しますか", False):
        raise ValueError("SETUP_PLAN_NOT_ACCEPTED")
    confirmation = normalized.confirm_github_create
    if not check_only and normalized.knowledge_mode == "github-new":
        confirmation = normalized.github_repository
    return replace(normalized, accept_plan=not check_only, confirm_github_create=confirmation)


def _interactive_selection(args: argparse.Namespace) -> SetupSelection:
    setup_flow = getattr(args, "command", None) == "setup" or bool(getattr(args, "setup", False))
    non_interactive = bool(getattr(args, "non_interactive", False))
    json_mode = bool(getattr(args, "json_mode", False))
    check_only = bool(getattr(args, "check_only", False) or getattr(args, "dry_run", False))
    if setup_flow and json_mode and not non_interactive:
        raise ValueError("SETUP_JSON_REQUIRES_NON_INTERACTIVE")
    interactive = bool(setup_flow and sys.stdin.isatty() and not non_interactive)
    if interactive:
        return _guided_interactive_selection(args)

    def prompt_text(label: str, default: str) -> str:
        write_utf8(f"{label} [{default}]:", end=" ")
        return input().strip() or default

    def prompt_bool(label: str, default: bool) -> bool:
        default_text = "Y/n" if default else "y/N"
        answer = prompt_text(f"{label} ({default_text})", "yes" if default else "no").casefold()
        if answer in {"y", "yes", "1", "true"}:
            return True
        if answer in {"n", "no", "0", "false"}:
            return False
        raise ValueError("INTERACTIVE_BOOLEAN_INVALID")

    legacy_hosts = _parse_host_ids(getattr(args, "hosts", ()))
    requested_work_hosts = _parse_host_ids(getattr(args, "work_hosts", ()))
    if legacy_hosts and requested_work_hosts and legacy_hosts != requested_work_hosts:
        raise ValueError("WORK_HOSTS_CONFLICT")
    explicit_work_hosts = requested_work_hosts or legacy_hosts
    if setup_flow and non_interactive and (
        getattr(args, "knowledge_root", None) is None
        and getattr(args, "personal_knowledge_root", None) is None
        or getattr(args, "runtime_root", None) is None
        or not explicit_work_hosts
    ):
        raise ValueError("SETUP_NON_INTERACTIVE_PATHS_AND_HOSTS_REQUIRED")
    if not explicit_work_hosts:
        explicit_work_hosts = _parse_values(prompt_text("Select CLI work hosts (codex-cli, claude-code, gemini-cli, qwen-code), comma separated", "codex-cli")) if interactive else ()
    organizer_provider = getattr(args, "organizer_provider", None)
    organizer_host = getattr(args, "organizer_host", None)
    if setup_flow and non_interactive and not organizer_provider:
        raise ValueError("ORGANIZER_PROVIDER_REQUIRED")
    if interactive and not organizer_provider:
        organizer_provider = prompt_text("Organizer provider", "subscription-cli")
    if interactive and organizer_provider == "subscription-cli" and not organizer_host:
        organizer_host = prompt_text("Organizer host", explicit_work_hosts[0] if explicit_work_hosts else "codex-cli")
    legacy_providers = _parse_values(getattr(args, "providers", ()), deduplicate=False)
    if setup_flow and len(legacy_providers) > 1 and not bool(getattr(args, "_providers_from_manifest", False)):
        raise ValueError("ORGANIZER_SELECTION_REQUIRED")
    # The public setup flow is CLI-only.  The hidden legacy flag is accepted
    # solely to turn an old Codex-App selection into an explicit migration
    # receipt; it is never prompted or advertised as a supported host.
    include_codex_app = bool(getattr(args, "include_codex_app", False))
    knowledge_mode = getattr(args, "knowledge_mode", None)
    if interactive and knowledge_mode is None:
        knowledge_mode = prompt_text("Knowledge destination mode (local/github-new/github-existing)", "local")
    if setup_flow and non_interactive and knowledge_mode is None:
        raise ValueError("KNOWLEDGE_MODE_REQUIRED")
    knowledge_mode = knowledge_mode or "local"
    knowledge_root = getattr(args, "knowledge_root", None)
    personal_knowledge_root = getattr(args, "personal_knowledge_root", None)
    if personal_knowledge_root is not None and knowledge_root is None:
        knowledge_root = personal_knowledge_root
    runtime_root = getattr(args, "runtime_root", None)
    default_base = Path.home() / ".external-intelligence"
    if interactive and knowledge_root is None:
        knowledge_root = prompt_text("Knowledge root", str(default_base / "knowledge"))
    if interactive and runtime_root is None:
        runtime_root = prompt_text("Machine-local runtime root", str(default_base / "runtime"))
    team_knowledge_root = getattr(args, "team_knowledge_root", None)
    team_member_id = getattr(args, "team_member_id", None)
    team_knowledge = getattr(args, "team_knowledge", None)
    if interactive and team_knowledge is None:
        team_knowledge = prompt_bool("Use team external intelligence?", False)
    if team_knowledge_root is not None:
        if team_knowledge is False:
            raise ValueError("TEAM_SELECTION_CONFLICT")
        team_knowledge = True
    if interactive and team_knowledge is True:
        if team_knowledge_root is None:
            team_knowledge_root = prompt_text("Team knowledge root", str(default_base / "team-knowledge"))
        if team_member_id is None:
            team_member_id = prompt_text("Team member ID", "member")
    github_repository = getattr(args, "github_repository", None)
    if interactive and knowledge_mode in {"github-new", "github-existing"} and not github_repository:
        github_repository = prompt_text("Private GitHub repository (OWNER/REPOSITORY)", "owner/external-intelligence-knowledge")
    providers = legacy_providers
    if interactive and not providers:
        providers = _parse_values(prompt_text("Inference providers in priority order", "local-openai-compatible,ollama,subscription-cli"), deduplicate=False)
    privacy_profile = getattr(args, "privacy_profile", "private-reusable")
    if interactive and privacy_profile == "private-reusable":
        privacy_profile = prompt_text("Privacy profile (public/private-reusable/client-confidential/machine-local)", privacy_profile)
    sync_selection = getattr(args, "sync", None)
    sync_default = knowledge_mode in {"github-new", "github-existing"}
    sync_enabled = sync_default if sync_selection is None else bool(sync_selection)
    if interactive and sync_selection is None:
        sync_enabled = prompt_bool("Enable Git synchronization", sync_default)
    experiment_enabled = bool(getattr(args, "experiment", False))
    if interactive and not getattr(args, "experiment", False):
        experiment_enabled = prompt_bool("Enable A/B measurement", False)
    scheduler_enabled = bool(getattr(args, "scheduler", False))
    if interactive and not getattr(args, "scheduler", False):
        scheduler_enabled = prompt_bool("Enable optional maintenance scheduler", False)
    skill_mode = getattr(args, "skill_mode", "copy")
    if interactive and skill_mode == "copy":
        skill_mode = prompt_text("Skill installation mode (copy/link)", skill_mode)
    profile_paths = tuple(Path(item).expanduser() for item in getattr(args, "host_profile", ()))
    profile_ids = tuple(load_host_profile(path, Path(".")).host_id for path in profile_paths)
    parsed_host_homes = _parse_host_homes(
        getattr(args, "host_home", ()),
        allowed_hosts=KNOWN_HOSTS | frozenset(profile_ids),
    )
    if setup_flow and non_interactive:
        if (knowledge_root is None and personal_knowledge_root is None) or runtime_root is None or not explicit_work_hosts:
            raise ValueError("SETUP_NON_INTERACTIVE_PATHS_AND_HOSTS_REQUIRED")
        if not check_only and not bool(getattr(args, "accept_plan", False)):
            raise ValueError("SETUP_PLAN_ACCEPTANCE_REQUIRED")
    selection = SetupSelection(
        engine_root=getattr(args, "engine_root", None),
        knowledge_root=knowledge_root,
        personal_knowledge_root=personal_knowledge_root,
        repo_root=getattr(args, "repo", None),
        runtime_root=runtime_root,
        team_knowledge_root=team_knowledge_root,
        team_member_id=team_member_id,
        team_knowledge=team_knowledge,
        hosts=explicit_work_hosts,
        work_hosts=explicit_work_hosts,
        include_codex_app=include_codex_app,
        host_homes=parsed_host_homes,
        host_profiles=profile_paths,
        python_exe=getattr(args, "python_exe", None),
        providers=providers,
        organizer_provider=organizer_provider,
        organizer_host=organizer_host,
        privacy_profile=privacy_profile,
        sync=sync_enabled,
        experiment=experiment_enabled,
        scheduler=scheduler_enabled,
        skill_mode=skill_mode,
        skip_venv=bool(getattr(args, "skip_venv", False)),
        non_interactive=non_interactive,
        knowledge_mode=knowledge_mode,
        github_repository=github_repository,
        github_executable=getattr(args, "github_executable", "gh"),
        remote_name=getattr(args, "remote_name", "origin"),
        branch=getattr(args, "branch", "main"),
        accept_plan=bool(getattr(args, "accept_plan", False)),
        confirm_github_create=getattr(args, "confirm_github_create", None),
    )
    if interactive:
        normalized = _normalise_selection(selection)
        knowledge_plan = plan_knowledge_setup(_knowledge_selection(normalized))
        host_plan = render_install_plan(normalized)
        write_utf8("\nSetup plan")
        write_utf8(f"  Engine:    {normalized.engine_root}")
        write_utf8(f"  Knowledge: {normalized.knowledge_root} ({normalized.knowledge_mode})")
        if normalized.team_knowledge is True:
            write_utf8(f"  Team knowledge: {normalized.team_knowledge_root} (member {normalized.team_member_id})")
        write_utf8(f"  Runtime:   {normalized.runtime_root}")
        write_utf8(f"  Work hosts: {', '.join(normalized.work_hosts)}")
        if normalized.organizer_provider:
            write_utf8(f"  Organizer: {normalized.organizer_provider}{' @ ' + normalized.organizer_host if normalized.organizer_host else ''}")
        if normalized.github_repository:
            write_utf8(f"  GitHub:    {normalized.github_repository}")
        write_utf8(f"  Actions:   {len(knowledge_plan.actions) + len(host_plan)}")
        if not check_only and not prompt_bool("Apply this complete plan", False):
            raise ValueError("SETUP_PLAN_NOT_ACCEPTED")
        confirmation = normalized.confirm_github_create
        if not check_only and normalized.knowledge_mode == "github-new":
            confirmation = normalized.github_repository
        return replace(normalized, accept_plan=not check_only, confirm_github_create=confirmation)
    if setup_flow and non_interactive:
        normalized = _normalise_selection(selection)
        knowledge_plan = plan_knowledge_setup(_knowledge_selection(normalized))
        if (
            not check_only
            and knowledge_plan.selection.mode == "github-new"
            and knowledge_plan.selection.confirm_github_create != knowledge_plan.selection.github_repository
        ):
            raise ValueError("GITHUB_CREATE_CONFIRMATION_REQUIRED")
        return normalized
    return selection


def _print(value: Any, json_mode: bool) -> None:
    write_utf8(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, default=str) if json_mode or isinstance(value, (dict, list)) else value)


def _main() -> int:
    parser = argparse.ArgumentParser(prog="ei.installer")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--repo", "--repo-root", dest="repo")
    parser.add_argument("--engine-root")
    parser.add_argument("--knowledge-root")
    parser.add_argument("--personal-knowledge-root")
    team_group = parser.add_mutually_exclusive_group()
    team_group.add_argument("--team-knowledge-root")
    team_group.add_argument("--no-team-knowledge", dest="team_knowledge", action="store_false")
    parser.set_defaults(team_knowledge=None)
    parser.add_argument("--team-member-id")
    parser.add_argument("--runtime-root")
    parser.add_argument("--codex-home")
    parser.add_argument("--python-exe")
    parser.add_argument("--work-host", dest="work_hosts", action="append", default=[])
    parser.add_argument("--hosts", action="append", default=[], help="deprecated alias of --work-host")
    parser.add_argument("--host-home", action="append", default=[])
    parser.add_argument("--host-profile", action="append", default=[])
    parser.add_argument("--include-codex-app", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--providers", action="append", default=[])
    parser.add_argument("--organizer-provider")
    parser.add_argument("--organizer-host")
    parser.add_argument("--privacy-profile", default="private-reusable")
    parser.add_argument("--knowledge-mode", choices=("local", "github-new", "github-existing"))
    parser.add_argument("--github-repository")
    parser.add_argument("--github-executable", default="gh")
    parser.add_argument("--remote-name", default="origin")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--accept-plan", action="store_true")
    parser.add_argument("--confirm-github-create")
    sync_group = parser.add_mutually_exclusive_group()
    sync_group.add_argument("--sync", dest="sync", action="store_true")
    sync_group.add_argument("--no-sync", dest="sync", action="store_false")
    parser.set_defaults(sync=None)
    parser.add_argument("--experiment", action="store_true")
    parser.add_argument("--scheduler", action="store_true")
    parser.add_argument("--skill-mode", choices=("copy", "link"), default="copy")
    parser.add_argument("--skip-venv", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_mode")
    parser.add_argument("--manifest")
    parser.add_argument("--confirm-manifest-sha256")
    parser.add_argument("--restore-config-backup", action="store_true")
    parser.add_argument("--remove-runtime-cache", action="store_true")
    parser.add_argument("--remove-skills", action="store_true")
    parser.add_argument("--keep-skills", action="store_true")
    parser.add_argument("--no-scheduled-task", action="store_true")
    parser.add_argument("--remove-runtime", action="store_true")
    parser.add_argument("--remove-venv", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        if args.uninstall:
            if not args.manifest:
                raise ValueError("MANIFEST_REQUIRED")
            manifest_path = _resolve(args.manifest)
            manifest_sha256 = _sha256(manifest_path.read_bytes())
            if not args.check_only and args.confirm_manifest_sha256 != manifest_sha256:
                raise ValueError("UNINSTALL_CONFIRMATION_REQUIRED")
            options = UninstallOptions(restore_config_backup=args.restore_config_backup, remove_skills=not args.keep_skills, remove_runtime=args.remove_runtime, remove_runtime_cache=args.remove_runtime_cache, remove_scheduler=not args.no_scheduled_task, remove_venv=args.remove_venv, force=args.force, check_only=args.check_only)
            result = uninstall(manifest_path, options)
            result["manifest_sha256"] = manifest_sha256
            _print(result, args.json_mode)
            return 0 if result["ok"] else 3
        if args.update:
            manifest = _read_json(_resolve(args.manifest)) if args.manifest and not args.repo else {}
            if manifest:
                args.repo = manifest.get("repo_root")
                args.engine_root = manifest.get("engine_root")
                args.knowledge_root = manifest.get("knowledge_root")
                args.runtime_root = manifest.get("runtime_root")
                args.work_hosts = list(manifest.get("work_hosts", ()))
                if not args.work_hosts:
                    raise ValueError("UPDATE_WORK_HOSTS_REQUIRED")
                args.hosts = []
                args.host_home = [str(key) + "=" + str(value.get("home")) for key, value in manifest.get("hosts", {}).items() if isinstance(value, Mapping) and isinstance(value.get("home"), str)]
                args.python_exe = manifest.get("python_exe") or args.python_exe
                knowledge_record = manifest.get("knowledge_repository") if isinstance(manifest.get("knowledge_repository"), Mapping) else {}
                args.knowledge_mode = knowledge_record.get("mode") or "local"
                args.remote_name = knowledge_record.get("remote_name") or "origin"
                args.branch = knowledge_record.get("branch") or "main"
                args.sync = knowledge_record.get("sync_enabled") is True
                args.providers = list(manifest.get("providers", ()))
                organizer_record = manifest.get("organizer") if isinstance(manifest.get("organizer"), Mapping) else {}
                args.organizer_provider = organizer_record.get("provider_id") if organizer_record.get("status") == "READY" else None
                args.organizer_host = organizer_record.get("host_id") if organizer_record.get("status") == "READY" else None
                args._providers_from_manifest = True
                args.privacy_profile = manifest.get("privacy_profile", "private-reusable")
                args.experiment = manifest.get("experiment_enabled") is True
                args.scheduler = manifest.get("scheduler_requested") is True
                stores = manifest.get("knowledge_stores") if isinstance(manifest.get("knowledge_stores"), Mapping) else {}
                team = stores.get("team") if isinstance(stores, Mapping) else None
                if isinstance(team, Mapping):
                    args.team_knowledge = team.get("enabled") is True
                    args.team_knowledge_root = team.get("root") if args.team_knowledge else None
                    args.team_member_id = team.get("team_member_id") if args.team_knowledge else None
            if not (args.repo or args.engine_root) or not args.runtime_root:
                raise ValueError("UPDATE_REPO_OR_MANIFEST_REQUIRED")
            selection = _interactive_selection(args)
            result = update(selection, args.check_only)
            _print(result.to_dict(), args.json_mode)
            return 0 if result.ok else 1
        if args.setup or (not args.repo and not args.codex_home):
            result = setup(_interactive_selection(args), args.check_only)
            _print(result.to_dict(), args.json_mode)
            return 0 if result.ok else 1
        if not args.repo or not args.codex_home:
            raise ValueError("INSTALL_PATHS_REQUIRED")
        result = install(Path(args.repo), Path(args.codex_home), Path(args.python_exe or sys.executable), args.skip_venv, args.check_only, organizer_provider=args.organizer_provider, organizer_host=args.organizer_host)
        _print(result, args.json_mode)
        return 0
    except (ValueError, TypeError) as exc:
        _print({"ok": False, "error_code": str(exc)}, True)
        return 2
    except subprocess.CalledProcessError as exc:
        _print({"ok": False, "error_code": "DEPENDENCY_INSTALL_FAILED", "returncode": exc.returncode}, True)
        return 5
    except Exception as exc:
        _print({"ok": False, "error_code": type(exc).__name__}, True)
        return 6


if __name__ == "__main__":
    raise SystemExit(_main())
