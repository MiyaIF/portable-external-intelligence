"""Closed install-manifest validation and v6/v7-to-v8 migration helpers."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .ids import canonical_json
from .host_profiles import is_custom_host_id
from .safe_fs import SafeFilesystemError, assert_no_reparse_components, canonical_path
from .setup_contract import OrganizerSelection, organizer_from_mapping, migrate_legacy_organizer


INSTALL_MANIFEST_SCHEMA_VERSION = 8
LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION = 6
PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION = 7

_TOP_LEVEL_KEYS = frozenset(
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
        "knowledge_stores",
        "reconciliation",
    }
)
_TOP_LEVEL_REQUIRED_V6 = _TOP_LEVEL_KEYS - {"uninstalled_at", "knowledge_retained", "knowledge_stores", "reconciliation", "organizer", "work_hosts"}
_TOP_LEVEL_REQUIRED_V7 = _TOP_LEVEL_KEYS - {"uninstalled_at", "knowledge_retained", "organizer", "work_hosts"}
_TOP_LEVEL_REQUIRED_V8 = _TOP_LEVEL_KEYS - {"uninstalled_at", "knowledge_retained"}
_KNOWLEDGE_REPOSITORY_KEYS = frozenset(
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
_PERSONAL_STORE_KEYS = _KNOWLEDGE_REPOSITORY_KEYS | {"enabled"}
_TEAM_STORE_KEYS = frozenset(
    {
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
)
_RECONCILIATION_KEYS = frozenset({"desired_state_digest"})
_ORGANIZER_KEYS = frozenset({"status", "provider_id", "host_id", "reason_code"})
_HOST_KEYS = frozenset(
    {
        "host_id",
        "home",
        "hook_config_path",
        "context_path",
        "skill_destination",
        "skill_root",
        "skill_mode",
        "source_skill_hash",
        "installed_skill_hash",
        "skill_binding_path",
        "skill_binding_hash",
        "hook_template_hash",
        "context_hash",
        "skill_activation_mode",
        "capture_primary_path",
        "managed_hook_ids",
    }
)
_HOST_KEYS_V7 = _HOST_KEYS | {"hook_config_hash"}
_HOST_PROFILE_KEYS = frozenset({"profile_hash", "profile_path"})
_LEGACY_HOST_MIGRATION_KEYS = frozenset({"from_host_id", "to_host_id", "status", "reason_code"})
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_PROFILE_PATH_RE = re.compile(r"^host-profiles/[a-z0-9][a-z0-9._-]{0,159}\.json$")
_STORE_ID_RE = re.compile(r"^team_[0-9a-f]{16,64}$")
_WRITER_ID_RE = re.compile(r"^writer_[0-9a-f]{16,64}$")
_MEMBER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_PUBLIC_HOST_IDS = frozenset({"codex-cli", "claude-code", "gemini-cli", "qwen-code"})
_PRIVACY_PROFILES = frozenset({"public", "private-reusable", "client-confidential", "machine-local"})
_ROOT_OWNERSHIP = {
    "engine_root": "public-source-read-only",
    "knowledge_root": "private-knowledge-git-or-local",
    "runtime_root": "machine-local-git-forbidden",
}


def _invalid() -> None:
    raise ValueError("ACTIVE_INSTALL_MANIFEST_INVALID")


def _require_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _invalid()
    return value


def _require_string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _invalid()
    return value


def _require_datetime(value: Any) -> str:
    text = _require_string(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _invalid()
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _invalid()
    return text


def _require_hash(value: Any, *, nullable: bool = True) -> str | None:
    if value is None and nullable:
        return None
    text = _require_string(value)
    if not _HASH_RE.fullmatch(text):
        _invalid()
    return text


def _require_bool(value: Any) -> bool:
    if type(value) is not bool:
        _invalid()
    return value


def _require_unique_strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        _invalid()
    if len(set(value)) != len(value):
        _invalid()
    return value


def _safe_root(value: Any, *, require_exists: bool = False) -> tuple[Path, Path]:
    text = _require_string(value)
    try:
        raw = assert_no_reparse_components(text)
        resolved = canonical_path(raw, require_exists=require_exists)
    except (SafeFilesystemError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID") from exc
    if require_exists and not resolved.is_dir():
        raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID")
    return raw, resolved


def _validate_document_shape(value: Mapping[str, Any], *, version: int) -> None:
    if version == LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION:
        required = _TOP_LEVEL_REQUIRED_V6
        allowed = _TOP_LEVEL_KEYS - {"knowledge_stores", "reconciliation", "organizer", "work_hosts"}
    elif version == PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION:
        required = _TOP_LEVEL_REQUIRED_V7
        allowed = _TOP_LEVEL_KEYS - {"organizer", "work_hosts"}
    elif version == INSTALL_MANIFEST_SCHEMA_VERSION:
        required = _TOP_LEVEL_REQUIRED_V8
        allowed = _TOP_LEVEL_KEYS
    else:
        _invalid()
    if set(value) - allowed or not required.issubset(value) or type(value.get("schema_version")) is not int or value.get("schema_version") != version:
        _invalid()
    if value.get("status") not in {"INSTALLED", "UNINSTALLED"}:
        _invalid()
    _require_datetime(value.get("installed_at"))
    if "uninstalled_at" in value and value["uninstalled_at"] is not None:
        _require_datetime(value["uninstalled_at"])
    for key in ("repo_root", "engine_root", "knowledge_root", "runtime_root", "skill_source", "python_exe", "transaction_id", "agents_block_version"):
        _require_string(value.get(key))


def _validate_repository(value: Mapping[str, Any], *, personal: bool) -> None:
    if set(value) != _KNOWLEDGE_REPOSITORY_KEYS:
        _invalid()
    if value.get("status") != "READY":
        _invalid()
    if value.get("mode") not in {"local", "github-new", "github-existing"}:
        _invalid()
    _require_string(value.get("root"))
    remote_name = value.get("remote_name")
    fingerprint = value.get("remote_fingerprint")
    classification = value.get("remote_classification")
    branch = value.get("branch")
    connected = _require_bool(value.get("connected"))
    initial_push = _require_bool(value.get("initial_push_complete"))
    sync_enabled = _require_bool(value.get("sync_enabled"))
    if value.get("mode") == "local":
        if any(value.get(key) is not None for key in ("remote_name", "remote_fingerprint", "remote_classification", "branch")):
            _invalid()
        if connected or initial_push or sync_enabled:
            _invalid()
    else:
        if not isinstance(remote_name, str) or not remote_name:
            _invalid()
        _require_hash(fingerprint, nullable=False)
        if classification not in {"local_path", "private_verified", "private_attested"}:
            _invalid()
        if not isinstance(branch, str) or not branch:
            _invalid()
        if not connected or not initial_push:
            _invalid()


def _validate_personal_store(value: Mapping[str, Any]) -> None:
    if set(value) != _PERSONAL_STORE_KEYS or value.get("enabled") is not True:
        _invalid()
    _validate_repository({key: value[key] for key in _KNOWLEDGE_REPOSITORY_KEYS}, personal=True)


def _validate_team_store(value: Mapping[str, Any]) -> tuple[Path, Path]:
    if set(value) != _TEAM_STORE_KEYS:
        _invalid()
    enabled = _require_bool(value.get("enabled"))
    raw_root, resolved_root = _safe_root(value.get("root"), require_exists=False)
    store_id = _require_string(value.get("store_id"))
    writer_id = _require_string(value.get("writer_id"))
    if not _STORE_ID_RE.fullmatch(store_id) or not _WRITER_ID_RE.fullmatch(writer_id):
        _invalid()
    member_id = _require_string(value.get("team_member_id"))
    if not _MEMBER_ID_RE.fullmatch(member_id):
        _invalid()
    if value.get("layout") != "member-writer-events-v1" or value.get("transport") != "external-shared-folder":
        _invalid()
    if value.get("transport_managed") is not False:
        _invalid()
    expected_status = "READY" if enabled else "DISABLED"
    if value.get("status") != expected_status:
        _invalid()
    return raw_root, resolved_root


def _validate_hosts(value: Any, *, version: int = INSTALL_MANIFEST_SCHEMA_VERSION) -> None:
    hosts = _require_mapping(value)
    for host_id, record_value in hosts.items():
        if not isinstance(host_id, str) or (host_id not in _PUBLIC_HOST_IDS and not is_custom_host_id(host_id)):
            _invalid()
        record = _require_mapping(record_value)
        allowed = _HOST_KEYS_V7 if version in {PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION, INSTALL_MANIFEST_SCHEMA_VERSION} else _HOST_KEYS
        custom = host_id not in _PUBLIC_HOST_IDS
        if custom:
            allowed |= _HOST_PROFILE_KEYS
        if set(record) - allowed or not _HOST_KEYS.issubset(record) or record.get("host_id") != host_id:
            _invalid()
        if custom:
            profile_hash = _require_hash(record.get("profile_hash"), nullable=False)
            profile_path = _require_string(record.get("profile_path"))
            if profile_hash is None or not _PROFILE_PATH_RE.fullmatch(profile_path) or profile_path != f"host-profiles/{host_id}.json":
                _invalid()
        elif set(record) & _HOST_PROFILE_KEYS:
            _invalid()
        for key in ("home", "hook_config_path", "context_path", "skill_destination", "skill_root", "skill_binding_path"):
            _require_string(record.get(key))
        if record.get("skill_mode") not in {"copy", "link"}:
            _invalid()
        for key in ("source_skill_hash", "installed_skill_hash", "skill_binding_hash", "hook_template_hash", "context_hash"):
            _require_hash(record.get(key))
        if "hook_config_hash" in record:
            _require_hash(record.get("hook_config_hash"))
        _require_string(record.get("skill_activation_mode"))
        _require_string(record.get("capture_primary_path"))
        _require_unique_strings(record.get("managed_hook_ids"))


def _validate_legacy_migrations(value: Any) -> None:
    if not isinstance(value, list):
        _invalid()
    for raw in value:
        item = _require_mapping(raw)
        if set(item) != _LEGACY_HOST_MIGRATION_KEYS:
            _invalid()
        _require_string(item.get("from_host_id"))
        if item.get("to_host_id") is not None:
            _require_string(item.get("to_host_id"))
        _require_string(item.get("status"))
        _require_string(item.get("reason_code"))


def _validate_organizer(value: Any, providers: Sequence[str], hosts: Mapping[str, Any], work_hosts: Any) -> OrganizerSelection:
    organizer = _require_mapping(value)
    if set(organizer) != _ORGANIZER_KEYS:
        _invalid()
    try:
        selection = organizer_from_mapping(organizer)
    except ValueError:
        _invalid()
    configured = set(providers)
    if selection.status == "READY" and selection.provider_id not in configured:
        _invalid()
    if not isinstance(work_hosts, list) or not work_hosts or any(not isinstance(item, str) or not item for item in work_hosts) or len(set(work_hosts)) != len(work_hosts):
        _invalid()
    if selection.status == "READY":
        if providers != [selection.provider_id]:
            _invalid()
    elif providers:
        _invalid()
    host_ids = set(hosts)
    if not set(work_hosts).issubset(host_ids):
        _invalid()
    unmanaged = host_ids - set(work_hosts)
    if selection.status == "READY" and selection.provider_id == "subscription-cli" and selection.host_id is not None:
        if selection.host_id not in host_ids:
            _invalid()
        allowed_difference = {selection.host_id}
    else:
        allowed_difference = set()
    if unmanaged - allowed_difference:
        _invalid()
    if selection.status == "SELECTION_REQUIRED" and unmanaged:
        _invalid()
    return selection


def _validate_common_fields(value: Mapping[str, Any], *, version: int = INSTALL_MANIFEST_SCHEMA_VERSION) -> None:
    ownership = value.get("root_ownership")
    if ownership != _ROOT_OWNERSHIP:
        _invalid()
    supported = _require_unique_strings(value.get("supported_hosts"))
    if any(item not in _PUBLIC_HOST_IDS for item in supported):
        _invalid()
    _validate_hosts(value.get("hosts"), version=version)
    _validate_legacy_migrations(value.get("legacy_host_migrations"))
    marker = _require_mapping(value.get("managed_marker"))
    if set(marker) != {"begin", "end", "version"}:
        _invalid()
    for key in ("begin", "end", "version"):
        _require_string(marker.get(key))
    _require_unique_strings(value.get("managed_hook_ids"))
    providers = _require_unique_strings(value.get("providers"))
    if value.get("privacy_profile") not in _PRIVACY_PROFILES:
        _invalid()
    for key in ("sync_enabled", "experiment_enabled", "scheduler_requested", "skip_venv", "venv_created"):
        _require_bool(value.get(key))
    for key in ("skill_source_hash", "hook_schema_hash", "agents_original_sha256", "agents_installed_sha256"):
        _require_hash(value.get(key))
    for key in ("config_backup", "hooks_backup", "agents_backup"):
        if value.get(key) is not None:
            _require_string(value.get(key))
    if version == INSTALL_MANIFEST_SCHEMA_VERSION:
        _validate_organizer(value.get("organizer"), providers, value.get("hosts"), value.get("work_hosts"))


def _reconciliation_digest(value: Mapping[str, Any]) -> str:
    body = copy.deepcopy(dict(value))
    body.pop("reconciliation", None)
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def _canonicalize_transitional_v8_providers(value: dict[str, Any]) -> None:
    """Collapse a pre-fix v8 provider list around a valid ready organizer.

    A v8 manifest written by the first Task 1 implementation could retain the
    old provider priority list alongside the resolved organizer.  Only a
    structurally valid, ready organizer that is present in that list is
    eligible for this compatibility repair.  All ownership and list-shape
    checks are deliberately conservative so malformed manifests remain for
    the strict validator to reject.
    """

    organizer = value.get("organizer")
    providers = value.get("providers")
    work_hosts = value.get("work_hosts")
    hosts = value.get("hosts")
    if (
        not isinstance(organizer, Mapping)
        or set(organizer) != _ORGANIZER_KEYS
        or not isinstance(providers, list)
        or any(not isinstance(item, str) or not _PROVIDER_ID_RE.fullmatch(item) for item in providers)
        or not isinstance(work_hosts, list)
        or not work_hosts
        or any(not isinstance(item, str) or not item for item in work_hosts)
        or len(set(work_hosts)) != len(work_hosts)
        or not isinstance(hosts, Mapping)
        or not set(work_hosts).issubset(set(hosts))
    ):
        return
    try:
        selection = organizer_from_mapping(organizer)
    except ValueError:
        return
    if selection.status != "READY" or selection.provider_id is None:
        return
    if selection.provider_id not in providers:
        return
    if selection.provider_id == "subscription-cli":
        if selection.host_id is None or selection.host_id not in hosts:
            return
        allowed_difference = {selection.host_id}
    else:
        allowed_difference = set()
    if set(hosts) - set(work_hosts) - allowed_difference:
        return
    value["providers"] = [selection.provider_id]


def normalize_install_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached schema-v8 document, mapping v6/v7 selections."""

    if not isinstance(manifest, Mapping):
        _invalid()
    copied = copy.deepcopy(dict(manifest))
    version = copied.get("schema_version")
    if version == INSTALL_MANIFEST_SCHEMA_VERSION:
        # Schema-v8 keeps the legacy ``knowledge_repository`` projection for
        # consumers that still edit/read that field.  During normalization,
        # accept a same-root legacy edit and refresh the detached personal
        # store projection from it.  A root mismatch is intentionally left to
        # strict validation so a foreign knowledge root still fails closed.
        repository = copied.get("knowledge_repository")
        stores = copied.get("knowledge_stores")
        personal = stores.get("personal") if isinstance(stores, Mapping) else None
        if isinstance(repository, Mapping) and isinstance(stores, Mapping) and isinstance(personal, Mapping):
            if repository.get("root") == personal.get("root"):
                copied["knowledge_stores"] = {
                    "personal": {"enabled": True, **copy.deepcopy(dict(repository))},
                    "team": copy.deepcopy(stores.get("team")),
                }
        _canonicalize_transitional_v8_providers(copied)
        return copied
    if version not in {LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION, PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION}:
        _invalid()
    if version == LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION:
        _validate_document_shape(copied, version=LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION)
        repository = copied.get("knowledge_repository")
        if not isinstance(repository, Mapping) or set(repository) != _KNOWLEDGE_REPOSITORY_KEYS:
            _invalid()
        copied["knowledge_stores"] = {
            "personal": {"enabled": True, **copy.deepcopy(dict(repository))},
            "team": None,
        }
    else:
        _validate_document_shape(copied, version=PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION)
        repository = copied.get("knowledge_repository")
        stores = copied.get("knowledge_stores")
        if not isinstance(repository, Mapping) or set(repository) != _KNOWLEDGE_REPOSITORY_KEYS:
            _invalid()
        if not isinstance(stores, Mapping) or set(stores) != {"personal", "team"}:
            _invalid()
    copied["schema_version"] = INSTALL_MANIFEST_SCHEMA_VERSION
    legacy_hosts = copied.get("hosts")
    if not isinstance(legacy_hosts, Mapping):
        _invalid()
    legacy_providers = copied.get("providers")
    if not isinstance(legacy_providers, list):
        _invalid()
    work_hosts = [str(host_id) for host_id in legacy_hosts]
    organizer = migrate_legacy_organizer(legacy_providers, work_hosts)
    copied["work_hosts"] = work_hosts
    copied["organizer"] = organizer.to_dict()
    copied["providers"] = [organizer.provider_id] if organizer.status == "READY" and organizer.provider_id is not None else []
    copied["reconciliation"] = {"desired_state_digest": _reconciliation_digest(copied)}
    return copied


def validate_install_manifest(
    manifest: Mapping[str, Any],
    *,
    require_live_personal: bool = True,
) -> dict[str, Any]:
    """Validate a closed schema-v8 manifest without opening a team root."""

    if type(require_live_personal) is not bool or not isinstance(manifest, Mapping):
        _invalid()
    value = copy.deepcopy(dict(manifest))
    _validate_document_shape(value, version=INSTALL_MANIFEST_SCHEMA_VERSION)
    _validate_common_fields(value)
    root_values: dict[str, Path] = {}
    for key in ("engine_root", "knowledge_root", "runtime_root"):
        _, root_values[key] = _safe_root(value.get(key), require_exists=False)
    stores = _require_mapping(value.get("knowledge_stores"))
    if set(stores) != {"personal", "team"}:
        _invalid()
    personal = _require_mapping(stores.get("personal"))
    team_value = stores.get("team")
    _validate_personal_store(personal)
    if value.get("knowledge_root") != personal.get("root"):
        raise ValueError("ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH")
    personal_raw, personal_canonical = _safe_root(personal.get("root"), require_exists=require_live_personal)
    repository = _require_mapping(value.get("knowledge_repository"))
    expected_repository = {key: personal[key] for key in personal if key != "enabled"}
    if dict(repository) != expected_repository:
        raise ValueError("ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH")
    team_canonical: Path | None = None
    if team_value is not None:
        team_descriptor = _require_mapping(team_value)
        _, team_canonical = _validate_team_store(team_descriptor)
    roots = [root_values["engine_root"], personal_canonical, root_values["runtime_root"]]
    if team_canonical is not None:
        roots.append(team_canonical)
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root == other or root.is_relative_to(other) or other.is_relative_to(root):
                raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID")
    reconciliation = _require_mapping(value.get("reconciliation"))
    if set(reconciliation) != _RECONCILIATION_KEYS or not _HASH_RE.fullmatch(_require_string(reconciliation.get("desired_state_digest"))):
        _invalid()
    if personal_raw != personal_canonical and require_live_personal:
        raise ValueError("ACTIVE_MANIFEST_ROOTS_INVALID")
    return value


def migration_backup_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 bytes for the pre-migration manifest backup."""

    if not isinstance(manifest, Mapping):
        _invalid()
    return (json.dumps(copy.deepcopy(dict(manifest)), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def manifest_knowledge_stores(
    manifest: Mapping[str, Any],
    *,
    require_live_personal: bool = False,
) -> dict[str, Any]:
    """Return detached personal/team descriptors from a validated manifest."""

    normalized = normalize_install_manifest(manifest)
    validated = validate_install_manifest(normalized, require_live_personal=require_live_personal)
    return copy.deepcopy(dict(validated["knowledge_stores"]))


__all__ = [
    "INSTALL_MANIFEST_SCHEMA_VERSION",
    "LEGACY_INSTALL_MANIFEST_SCHEMA_VERSION",
    "PREVIOUS_INSTALL_MANIFEST_SCHEMA_VERSION",
    "manifest_knowledge_stores",
    "migration_backup_bytes",
    "normalize_install_manifest",
    "validate_install_manifest",
]
