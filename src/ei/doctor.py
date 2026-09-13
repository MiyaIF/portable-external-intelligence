from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .canary import read_hook_status, skill_discovery_canary, static_canary
from .config import Settings, load_settings
from .index import build_index
from .journal import iter_events
from .projection_state import projection_freshness_report
from .reconciliation import candidate_diagnostics
from .install_agents import inspect_global_agents, managed_block_sha256, render_managed_context
from .knowledge_repository import KnowledgeRepositoryError, inspect_knowledge_repository
from .remote_assurance import RemoteAssuranceError, assure_remote, load_remote_assurance_receipt, remote_fingerprint
from .skill_installer import canonical_tree_hash
from .task_scheduler import inspect_registered_task
from .queue import QueueError, list_queue_items, queue_health
from .spool import SpoolError, spool_health
from .maintainer import team_status_snapshot


_SAFE_REASON = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_FORBIDDEN_KEYS = frozenset({
    "prompt", "query", "query_text", "raw_prompt", "raw_query", "transcript",
    "tool_output", "raw_tool_output", "response", "raw_response", "secret",
    "api_key", "access_token", "password",
})
_SKILL_BINDING_NAME = ".external-intelligence-binding.json"
_MAX_SKILL_BINDING_BYTES = 1024 * 1024


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[dict[str, Any], ...]
    repair_plan: tuple[Mapping[str, Any], ...] = ()
    knowledge_stores: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    organizer: Mapping[str, Any] = field(default_factory=dict)
    work_hosts: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return all(bool(check.get("ok")) for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [dict(check) for check in self.checks],
            "repair_plan": [dict(item) for item in self.repair_plan],
            "organizer": dict(self.organizer),
            "work_hosts": list(self.work_hosts),
            "knowledge_stores": {
                "personal": dict((self.knowledge_stores or {}).get("personal", {"status": "READY"})),
                "team": dict((self.knowledge_stores or {}).get("team", {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})),
            },
        }


def _reason(value: object, fallback: str = "DOCTOR_CHECK_FAILED") -> str:
    text = str(value or "")
    return text if _SAFE_REASON.fullmatch(text) else fallback


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    moment = value or _now()
    if moment.tzinfo is None or moment.utcoffset() is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _hash_file(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _manifest_path(settings: Settings) -> Path:
    return Path(settings.paths.install_manifest_path).expanduser().resolve()


def _read_manifest(settings: Settings) -> dict[str, Any]:
    return _read_json(_manifest_path(settings))


def _hook_ids(path: Path) -> tuple[set[str], bool]:
    value = _read_json(path)
    if not isinstance(value.get("hooks"), Mapping):
        return set(), False
    found: set[str] = set()
    for entries in value["hooks"].values():
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                    found.add(item["id"])
    return found, True


def _manifest_hosts(settings: Settings, manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    hosts = manifest.get("hosts")
    if isinstance(hosts, Mapping) and hosts:
        return {
            str(host_id): record
            for host_id, record in hosts.items()
            if isinstance(record, Mapping)
        }
    return {str(host_id): {} for host_id in getattr(settings, "hosts", {})}


def _lexical_absolute(value: str | Path) -> Path:
    return Path(os.path.abspath(str(Path(value).expanduser())))


def _same_lexical(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(str(_lexical_absolute(left))) == os.path.normcase(str(_lexical_absolute(right)))


def _skill_binding_check(
    host_id: str,
    record: Mapping[str, Any],
    settings: Settings,
    manifest: Mapping[str, Any],
    destination: Path | None,
    installed_hash: str,
) -> dict[str, Any]:
    binding_value = record.get("skill_binding_path")
    expected_hash = record.get("skill_binding_hash")
    if not isinstance(binding_value, str) or not binding_value or not isinstance(expected_hash, str) or not expected_hash:
        return {
            "ok": False,
            "reason_code": "SKILL_BINDING_MANIFEST_INVALID",
            "path": binding_value if isinstance(binding_value, str) else None,
            "expected_hash": expected_hash if isinstance(expected_hash, str) else None,
            "actual_hash": None,
        }
    binding_path = _lexical_absolute(binding_value)
    if (
        destination is None
        or not Path(binding_value).expanduser().is_absolute()
        or binding_path.name != _SKILL_BINDING_NAME
        or binding_path.parent != _lexical_absolute(destination).parent
    ):
        return {
            "ok": False,
            "reason_code": "SKILL_BINDING_PATH_INVALID",
            "path": str(binding_path),
            "expected_hash": expected_hash,
            "actual_hash": None,
        }
    try:
        if binding_path.is_symlink() or not binding_path.is_file():
            return {
                "ok": False,
                "reason_code": "SKILL_BINDING_MISSING",
                "path": str(binding_path),
                "expected_hash": expected_hash,
                "actual_hash": None,
            }
        if binding_path.stat().st_size > _MAX_SKILL_BINDING_BYTES:
            raise ValueError("SKILL_BINDING_INVALID")
        raw = binding_path.read_bytes()
        actual_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        binding = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return {
            "ok": False,
            "reason_code": "SKILL_BINDING_INVALID",
            "path": str(binding_path),
            "expected_hash": expected_hash,
            "actual_hash": None,
        }
    if actual_hash != expected_hash:
        return {
            "ok": False,
            "reason_code": "SKILL_BINDING_HASH_MISMATCH",
            "path": str(binding_path),
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
        }
    schema_version = binding.get("schema_version") if isinstance(binding, dict) else None
    expected = {
        "schema_version": schema_version,
        "host_id": host_id,
        "engine_root": str(settings.paths.engine_root),
        "knowledge_root": str(settings.paths.knowledge_root),
        "runtime_root": str(settings.paths.runtime_root),
        "python_exe": str(manifest.get("python_exe", "")),
        "skill_destination": str(_lexical_absolute(destination)),
        "installed_skill_hash": installed_hash,
    }
    if schema_version == 2:
        expected.update(
            {
                "personal_knowledge_root": str(settings.paths.personal_knowledge_root),
                "team_knowledge_root": (
                    str(settings.paths.team_knowledge_root)
                    if settings.paths.team_knowledge_root is not None
                    else None
                ),
            }
        )
    content_ok = schema_version in {1, 2} and all(
        binding.get(key) == value for key, value in expected.items()
    )
    return {
        "ok": content_ok,
        "reason_code": None if content_ok else "SKILL_BINDING_CONTENT_MISMATCH",
        "path": str(binding_path),
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
    }


def _check(name: str, ok: bool, *, required: bool, reason_code: str | None = None, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "ok": bool(ok),
        "required": bool(required),
        "status": "OK" if ok else "BLOCKED",
    }
    if reason_code:
        result["reason_code"] = _reason(reason_code)
    result.update(details)
    return result


def _path_checks(settings: Settings, strict: bool) -> dict[str, Any]:
    paths = settings.paths
    required = (
        ("repo_root", paths.repo_root, True),
        ("config_defaults", paths.repo_root / "config" / "defaults.json", True),
        ("policies", paths.repo_root / "policies", True),
        ("schemas", paths.repo_root / "schemas", True),
        ("source_skill", paths.repo_root / "skills" / "external-intelligence", True),
        ("knowledge", paths.knowledge_dir, False),
        ("event_dir", paths.event_dir, False),
        ("runtime_root", paths.runtime_root, False),
    )
    rows = [
        {
            "name": name,
            "exists": path.exists(),
            "required": needed,
            "path": str(path),
        }
        for name, path, needed in required
    ]
    return _check(
        "paths",
        all(row["exists"] for row in rows if row["required"]),
        required=True,
        reason_code="REQUIRED_PATH_MISSING" if any(not row["exists"] for row in rows if row["required"]) else None,
        paths=rows,
        strict=strict,
    )


def _dependency_check(settings: Settings, strict: bool) -> dict[str, Any]:
    repo = Path(settings.paths.engine_root)
    required_paths = (
        repo / "pyproject.toml",
        repo / "requirements-runtime.lock",
        repo / "requirements-build.lock",
        repo / "requirements-ci.lock",
    )
    present = [path.name for path in required_paths if path.is_file()]
    missing = [path.name for path in required_paths if not path.is_file()]
    return _check(
        "dependencies",
        not missing or not strict,
        required=strict,
        reason_code="DEPENDENCY_LOCK_MISSING" if missing else None,
        lock_files=present,
        missing=missing,
        python=platform.python_version(),
    )


def _knowledge_repository_check(settings: Settings, manifest: Mapping[str, Any], strict: bool) -> dict[str, Any]:
    expected = manifest.get("knowledge_repository") if isinstance(manifest.get("knowledge_repository"), Mapping) else {}
    required = manifest.get("status") == "INSTALLED"
    try:
        status = inspect_knowledge_repository(
            settings.paths.knowledge_root,
            engine_root=settings.paths.engine_root,
            runtime_root=settings.paths.runtime_root,
        )
    except (KnowledgeRepositoryError, OSError, ValueError) as exc:
        return _check(
            "knowledge_repository",
            not strict and not required,
            required=required or strict,
            reason_code=_reason(getattr(exc, "code", None), "KNOWLEDGE_REPOSITORY_INVALID"),
            initialized=False,
        )
    live_remote: str | None = None
    live_fingerprint: str | None = None
    live_classification: str | None = None
    remote_reason: str | None = None
    remote_name = expected.get("remote_name")
    if isinstance(remote_name, str) and remote_name:
        try:
            process = subprocess.run(
                ["git", "-C", str(status.root), "remote", "get-url", remote_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            if process.returncode == 0 and process.stdout.strip():
                live_remote = process.stdout.strip().splitlines()[0]
                live_fingerprint = remote_fingerprint(live_remote)
                assurance_path = Path(settings.paths.runtime_root) / "remote-assurance" / f"{live_fingerprint.removeprefix('sha256:')}.json"
                if not assurance_path.is_file():
                    remote_reason = "REMOTE_ASSURANCE_MISSING"
                else:
                    assurance = load_remote_assurance_receipt(assurance_path)
                    engine_process = subprocess.run(
                        ["git", "-C", str(settings.paths.engine_root), "remote", "get-url", remote_name],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=20,
                        check=False,
                    )
                    engine_remote = engine_process.stdout.strip().splitlines()[0] if engine_process.returncode == 0 and engine_process.stdout.strip() else None
                    descriptor = assure_remote(
                        live_remote,
                        engine_remote=engine_remote,
                        attestation=assurance,
                        data_classification="private-reusable",
                    )
                    live_classification = descriptor.classification
        except RemoteAssuranceError as exc:
            remote_reason = exc.code
            live_classification = None
        except (OSError, subprocess.SubprocessError, ValueError):
            remote_reason = "KNOWLEDGE_REMOTE_ASSURANCE_MISMATCH"
            live_remote = None
            live_fingerprint = None
            live_classification = None
    expected_fingerprint = expected.get("remote_fingerprint")
    expected_classification = expected.get("remote_classification")
    connected = expected.get("connected") is True
    layout_ready = status.git_initialized and status.manifest_valid and status.required_paths_present
    remote_ready = (
        not connected
        or (
            live_remote is not None
            and live_fingerprint == expected_fingerprint
            and live_classification == expected_classification
        )
    )
    root_matches = not expected or str(expected.get("root")) == str(status.root)
    ready = layout_ready and remote_ready and root_matches and (not expected or expected.get("status") == "READY")
    return _check(
        "knowledge_repository",
        ready or (not strict and not required),
        required=required or strict,
        reason_code=(
            "KNOWLEDGE_LAYOUT_INVALID"
            if not layout_ready
            else "KNOWLEDGE_ROOT_MISMATCH"
            if not root_matches
            else remote_reason or "KNOWLEDGE_REMOTE_ASSURANCE_MISMATCH"
            if not remote_ready
            else None
        ),
        initialized=status.initialized,
        git_initialized=status.git_initialized,
        manifest_valid=status.manifest_valid,
        required_paths_present=status.required_paths_present,
        dirty=status.dirty,
        root_digest=status.root_digest,
        remote_names=list(status.remote_names),
        remote_fingerprint=live_fingerprint,
        remote_classification=live_classification,
        initial_push_complete=expected.get("initial_push_complete") is True,
        sync_enabled=expected.get("sync_enabled") is True,
    )


def _settings_check(settings: Settings, strict: bool) -> dict[str, Any]:
    path = Path(settings.paths.engine_root) / "config" / "defaults.json"
    value = _read_json(path)
    required_sections = (
        "retrieval", "context", "hooks", "providers", "sync", "capture",
        "scheduler", "experiment", "curation",
    )
    missing = [name for name in required_sections if not isinstance(value.get(name), Mapping)]
    schema_version = value.get("schema_version")
    curation = value.get("curation") if isinstance(value.get("curation"), Mapping) else {}
    max_attempts = curation.get("max_attempts")
    retry_delay_seconds = curation.get("retry_delay_seconds")
    configured_max_attempts = getattr(settings, "curation_max_attempts", None)
    configured_retry_delay_seconds = getattr(settings, "curation_retry_delay_seconds", None)
    curation_valid = (
        type(max_attempts) is int
        and max_attempts >= 1
        and type(retry_delay_seconds) is int
        and retry_delay_seconds >= 0
        and configured_max_attempts == max_attempts
        and configured_retry_delay_seconds == retry_delay_seconds
    )
    valid = type(schema_version) is int and schema_version >= 1 and not missing and curation_valid
    return _check(
        "settings_schema",
        valid or not strict,
        required=strict,
        reason_code="DEFAULTS_SCHEMA_INVALID" if not valid else None,
        schema_version=schema_version,
        missing_sections=missing,
        curation={
            "max_attempts": max_attempts,
            "retry_delay_seconds": retry_delay_seconds,
            "configured_max_attempts": configured_max_attempts,
            "configured_retry_delay_seconds": configured_retry_delay_seconds,
            "valid": curation_valid,
        },
        defaults_hash=_hash_file(path),
    )


def _managed_check(settings: Settings, manifest: Mapping[str, Any], strict: bool) -> dict[str, Any]:
    marker = manifest.get("managed_marker")
    valid_marker = (
        isinstance(marker, Mapping)
        and isinstance(marker.get("begin"), str)
        and isinstance(marker.get("end"), str)
        and marker.get("begin") != marker.get("end")
    )
    hosts = _manifest_hosts(settings, manifest)
    host_ids = sorted(hosts)
    has_manifest = bool(manifest)
    valid_status = str(manifest.get("status", "")) in {"INSTALLED", "UNINSTALLED", ""}
    ok = (has_manifest and valid_marker and valid_status) or not strict
    return _check(
        "managed_markers",
        ok,
        required=strict,
        reason_code="INSTALL_MANIFEST_MISSING" if strict and not has_manifest else "MANAGED_MARKER_INVALID" if strict and not valid_marker else None,
        manifest_present=has_manifest,
        manifest_hash=_hash_file(_manifest_path(settings)),
        hosts=host_ids,
        status=manifest.get("status"),
    )


def _host_report(
    host_id: str,
    record: Mapping[str, Any],
    settings: Settings,
    manifest: Mapping[str, Any],
    strict: bool,
    *,
    read_live: bool,
) -> dict[str, Any]:
    host = settings.hosts.get(host_id)
    default_hook = host.hook_config_path if host is not None else settings.paths.hooks_path
    default_context = host.global_context_path if host is not None else settings.paths.agents_path
    hook_path = Path(str(record.get("hook_config_path", default_hook))).expanduser().resolve()
    context_path = Path(str(record.get("context_path", default_context))).expanduser().resolve()
    ids, valid_json = _hook_ids(hook_path)
    required_ids = {
        str(value)
        for value in record.get("managed_hook_ids", ())
        if isinstance(value, str)
    }
    present_ids = sorted(required_ids & ids)
    if not required_ids:
        required_ids = {value for value in ids if value.startswith("ei-")}
        present_ids = sorted(required_ids)
    try:
        static = static_canary(host_id, str(record.get("host_instance_id", host_id)), settings)
        static_data = static.to_dict()
    except (OSError, TypeError, ValueError):
        static_data = {
            "host_id": host_id,
            "status": "STATIC_INVALID",
            "valid": False,
            "reason_codes": ["STATIC_CANARY_FAILED"],
        }
    try:
        discovery = skill_discovery_canary(host_id, str(record.get("host_instance_id", host_id)), settings)
    except (OSError, TypeError, ValueError):
        discovery = "UNVERIFIED"
    agents = inspect_global_agents(context_path)
    source_hash = str(manifest.get("skill_source_hash", ""))
    installed_hash = str(record.get("installed_skill_hash", ""))
    destination_value = record.get("skill_destination")
    configured_destination = _lexical_absolute(destination_value) if isinstance(destination_value, str) and destination_value else None
    destination = configured_destination.resolve() if configured_destination is not None else None
    actual_hash: str | None = None
    if destination is not None and destination.is_dir():
        try:
            actual_hash = canonical_tree_hash(destination)
        except (OSError, ValueError):
            actual_hash = None
    skill_hash_ok = (
        not strict
        or not source_hash
        or bool(installed_hash and actual_hash and installed_hash == actual_hash == source_hash)
    )
    binding = _skill_binding_check(host_id, record, settings, manifest, configured_destination, installed_hash)
    binding_ok = bool(binding.get("ok"))
    live: dict[str, Any] = {
        "hook_status": "HOOK_UNVERIFIED",
        "skill_discovery_status": discovery,
        "skill_activation_mode": host.skill_activation_mode if host is not None else "UNAVAILABLE",
        "capture_primary_path": host.capture_primary_path if host is not None else "NATIVE_SOURCE",
        "reason_codes": ["LIVE_CANARY_NOT_READ"],
    }
    if read_live:
        try:
            status = read_hook_status(host_id, str(record.get("host_instance_id", host_id)), settings)
            live = status.to_dict()
        except (OSError, TypeError, ValueError):
            live["reason_codes"] = ["LIVE_CANARY_UNAVAILABLE"]
    static_ok = bool(static_data.get("valid"))
    try:
        expected_context_hash = managed_block_sha256(
            render_managed_context(
                host_id,
                str(manifest.get("python_exe", "")),
                settings.paths.engine_root,
                settings.paths.runtime_root,
                configured_destination,
                settings.paths.knowledge_root,
            )
        )
    except (OSError, TypeError, ValueError):
        expected_context_hash = None
    managed_context_ok = bool(
        expected_context_hash
        and agents.get("managed_block_sha256") == expected_context_hash
    )
    context_ok = bool(agents.get("marker_pair")) and bool(agents.get("command_exists")) and managed_context_ok
    hook_ok = valid_json and bool(required_ids) and set(required_ids).issubset(ids) and static_ok
    discovery_ok = discovery in {"DISCOVERED", "UNVERIFIED"}
    live_status = str(live.get("hook_status", "HOOK_UNVERIFIED"))
    live_ok = live_status not in {"BROKEN", "DISABLED"}
    host_ok = (
        hook_ok and context_ok and discovery_ok and skill_hash_ok and binding_ok and live_ok
        if strict
        else True
    )
    return {
        "host_id": host_id,
        "host_instance_id": str(record.get("host_instance_id", host_id)),
        "ok": host_ok,
        "hook": {
            "path": str(hook_path),
            "json": valid_json,
            "required_ids": sorted(required_ids),
            "present_ids": present_ids,
            "static": static_data,
            "live": live,
            "ok": hook_ok and live_ok,
        },
        "skill": {
            "status": discovery,
            "source_hash": source_hash,
            "installed_hash": installed_hash,
            "actual_hash": actual_hash,
            "destination": str(configured_destination) if configured_destination is not None else None,
            "binding": binding,
            "ok": discovery_ok and skill_hash_ok and (binding_ok or not strict),
        },
        "context": {
            **dict(agents),
            "path": str(context_path),
            "expected_managed_block_sha256": expected_context_hash,
            "reason_code": None if context_ok else "MANAGED_CONTEXT_MISMATCH" if agents.get("marker_pair") else agents.get("reason_code", "AGENTS_MARKER_MISSING"),
            "ok": context_ok,
        },
        "activation": {
            "mode": live.get("skill_activation_mode", host.skill_activation_mode if host is not None else "UNAVAILABLE"),
            "capture_primary_path": live.get("capture_primary_path", host.capture_primary_path if host is not None else "NATIVE_SOURCE"),
            "instruction_fallback": live_status == "INSTRUCTION_FALLBACK",
        },
        "ok_reason": None if host_ok else "HOST_STATIC_OR_MANAGED_CONTRACT_FAILED",
    }


def _host_checks(settings: Settings, manifest: Mapping[str, Any], strict: bool, *, read_live: bool) -> dict[str, Any]:
    records = _manifest_hosts(settings, manifest)
    reports = [
        _host_report(host_id, record, settings, manifest, strict, read_live=read_live)
        for host_id, record in sorted(records.items())
    ]
    if not reports:
        reports = [{
            "host_id": "codex-cli",
            "ok": not strict,
            "ok_reason": "HOST_CONFIGURATION_NOT_FOUND",
        }]
    return _check(
        "hosts",
        all(bool(item.get("ok")) for item in reports),
        required=strict,
        reason_code="HOST_CONFIGURATION_INVALID" if not all(bool(item.get("ok")) for item in reports) else None,
        hosts=reports,
        live_canary_read=read_live,
    )


def _queue_check(settings: Settings, strict: bool) -> dict[str, Any]:
    try:
        health = queue_health(settings).to_dict()
        organizer_value = health.get("organizer")
        if not isinstance(organizer_value, Mapping):
            organizer_value = {
                "status": health.get("organizer_status", "SELECTION_REQUIRED"),
                "provider_id": None,
                "host_id": None,
                "reason_code": "ORGANIZER_SELECTION_REQUIRED",
            }
        items = list_queue_items(settings, include_terminal=True)
        now = _now()
        stale = 0
        active = 0
        for item in items:
            if item.state.value == "IN_PROGRESS":
                active += 1
                if not item.lease_expires_at:
                    stale += 1
                else:
                    try:
                        expires = datetime.fromisoformat(item.lease_expires_at.replace("Z", "+00:00"))
                        if expires.tzinfo is None or expires <= now:
                            stale += 1
                    except ValueError:
                        stale += 1
        ok = health["corrupt"] == 0 and stale == 0
        return _check(
            "queue",
            ok or not strict,
            required=strict,
            reason_code="QUEUE_CORRUPT_OR_STALE_LEASE" if not ok else None,
            health=health,
            organizer=organizer_value,
            organizer_status=organizer_value.get("status"),
            active_leases=active,
            stale_leases=stale,
        )
    except (OSError, QueueError, ValueError) as exc:
        return _check(
            "queue",
            False if strict else True,
            required=strict,
            reason_code=_reason(str(exc), "QUEUE_HEALTH_UNAVAILABLE"),
            health=None,
        )


def _spool_files(settings: Settings) -> tuple[Path, ...]:
    root = Path(settings.paths.spool_dir).expanduser().resolve()
    if not root.exists():
        return ()
    return tuple(sorted(path for path in root.glob("*.json") if path.is_file() and path.name != ".spool-capacity.json"))


def _spool_check(settings: Settings, strict: bool) -> dict[str, Any]:
    try:
        health = spool_health(settings).to_dict()
        now = _now()
        invalid = 0
        expired = 0
        key_missing = 0
        for path in _spool_files(settings):
            value = _read_json(path)
            if not value or value.get("algorithm") != "AES-256-GCM" or not isinstance(value.get("key_id"), str):
                invalid += 1
                continue
            try:
                expires = datetime.fromisoformat(str(value.get("expires_at", "")).replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    raise ValueError
                if expires <= now:
                    expired += 1
            except ValueError:
                invalid += 1
            if not str(value.get("key_id", "")):
                key_missing += 1
        key_state = "NOT_REQUIRED" if not _spool_files(settings) else "PRESENT_IN_ENVELOPE"
        ok = invalid == 0 and key_missing == 0
        return _check(
            "spool",
            ok or not strict,
            required=strict,
            reason_code="SPOOL_ENVELOPE_INVALID" if invalid else "SPOOL_KEY_ID_MISSING" if key_missing else None,
            health=health,
            invalid_envelopes=invalid,
            expired_envelopes=expired,
            key_state=key_state,
            quarantine=health.get("quarantined", 0),
        )
    except (OSError, SpoolError, ValueError) as exc:
        return _check(
            "spool",
            False if strict else True,
            required=strict,
            reason_code=_reason(str(exc), "SPOOL_HEALTH_UNAVAILABLE"),
            health=None,
        )


def _projection_check(settings: Settings, strict: bool, event_count: int) -> dict[str, Any]:
    knowledge = Path(settings.paths.knowledge_dir).expanduser().resolve()
    index_path = knowledge / "index.json"
    if not knowledge.exists() and event_count == 0:
        return _check("projection", True, required=strict, status="NOT_READY", reason_code=None, index_present=False)
    if not index_path.is_file():
        return _check(
            "projection",
            event_count == 0 or not strict,
            required=strict and event_count > 0,
            reason_code="PROJECTION_INDEX_MISSING" if event_count else None,
            index_present=False,
        )
    try:
        index = build_index(knowledge, index_path)
        events = list(iter_events(settings.paths.event_dir)) if settings.paths.event_dir.exists() else []
        freshness = projection_freshness_report(index_path, events)
        return _check(
            "projection",
            not strict or freshness["freshness"] == "CURRENT"
            or (freshness["freshness"] == "UNKNOWN" and event_count == 0 and index.item_count == 0),
            required=strict,
            **freshness,
            candidate_diagnostics=list(candidate_diagnostics(events)),
            index_present=True,
            item_count=index.item_count,
            active_patterns=len(index.active_pattern_ids),
            candidate_patterns=len(index.candidate_pattern_ids),
            archived_patterns=len(index.archive_pattern_ids),
            observation_count=index.observation_count,
            always_on_chars=index.always_on_chars,
            generation_hash=index.generation_hash,
        )
    except (OSError, ValueError, TypeError) as exc:
        return _check(
            "projection",
            False if strict else True,
            required=strict,
            reason_code=_reason(str(exc), "PROJECTION_INVALID"),
            index_present=True,
        )


def _team_check(settings: Settings, strict: bool) -> dict[str, Any]:
    """Check the optional team store while keeping personal checks separate."""

    try:
        snapshot = team_status_snapshot(settings)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        snapshot = {
            "status": "DEFERRED",
            "reason_code": "DEFERRED_TEAM_STORE",
            "issue_codes": [_reason(str(exc), "TEAM_KNOWLEDGE_UNAVAILABLE")],
            "transport_managed": False,
            "access_control_verified": False,
        }
    status = str(snapshot.get("status", "DEFERRED"))
    # Team is optional: an offline shared folder is a visible deferred state,
    # not a strict doctor failure.  Structural conflicts remain blocking when
    # the caller explicitly requested strict diagnostics.
    blocking = status == "BLOCKED"
    reason = snapshot.get("reason_code") if blocking else None
    details = {
        key: snapshot[key]
        for key in (
            "store_id_hash", "active_patterns", "candidate_patterns",
            "observations", "accepted_event_count", "issue_codes",
            "transport_managed", "access_control_verified",
        )
        if key in snapshot
    }
    details["store_status"] = status
    return _check("team", (not blocking) or not strict, required=blocking and strict, reason_code=reason, **details)


def _read_event_payloads(settings: Settings) -> tuple[int, int]:
    root = Path(settings.paths.event_dir)
    if not root.exists():
        return 0, 0
    count = 0
    privacy_violations = 0
    try:
        from .journal import iter_events

        for event in iter_events(root):
            count += 1
            stack: list[Any] = [event.payload]
            while stack:
                value = stack.pop()
                if isinstance(value, Mapping):
                    if any(str(key).casefold() in _FORBIDDEN_KEYS for key in value):
                        privacy_violations += 1
                    stack.extend(value.values())
                elif isinstance(value, (list, tuple)):
                    stack.extend(value)
    except (OSError, ValueError, RuntimeError):
        return count, max(1, privacy_violations)
    return count, privacy_violations


def _privacy_check(settings: Settings, strict: bool, event_count: int, violations: int) -> dict[str, Any]:
    return _check(
        "privacy",
        violations == 0 or not strict,
        required=strict,
        reason_code="RAW_FIELD_DETECTED" if violations else None,
        event_count=event_count,
        violations=violations,
        policy_hash=_hash_file(Path(settings.privacy_policy_path)),
        raw_content_returned=False,
    )


def _provider_check(settings: Settings, strict: bool, queue_ready: int) -> dict[str, Any]:
    try:
        from .inference.router import ProviderRouter

        router = ProviderRouter(settings=settings)
        organizer = router.organizer.to_dict()
        selected_provider_id = organizer.get("provider_id") if organizer.get("status") == "READY" else None
        rows = []
        for provider in router.providers:
            try:
                available = bool(provider.available())
            except (OSError, RuntimeError, ValueError):
                available = False
            rows.append({
                "provider_id": str(getattr(provider, "provider_id", "")),
                "locality": str(getattr(provider, "locality", "unknown")),
                "available": available,
                "eligible": (
                    organizer.get("status") == "READY"
                    and getattr(provider, "provider_id", "") == selected_provider_id
                    and available
                ),
            })
        eligible = sum(1 for row in rows if row["eligible"])
        # No provider is a valid deferred state when no work is ready.
        ok = eligible > 0 or queue_ready == 0
        return _check(
            "provider",
            ok or not strict,
            required=strict and queue_ready > 0,
            reason_code=(
                organizer.get("reason_code") or "NO_PROVIDER_AVAILABLE"
                if not ok
                else None
            ),
            providers=rows,
            eligible=eligible,
            organizer=organizer,
            organizer_status=organizer.get("status"),
            cloud_spend_cap=getattr(settings, "cloud_spend_cap", None),
            quota_state="DEFERRED" if queue_ready and eligible == 0 else "AVAILABLE" if eligible else "NOT_REQUIRED",
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        configured_organizer = getattr(settings, "organizer", None)
        organizer_value = configured_organizer.to_dict() if hasattr(configured_organizer, "to_dict") else {
            "status": "SELECTION_REQUIRED",
            "provider_id": None,
            "host_id": None,
            "reason_code": "ORGANIZER_SELECTION_REQUIRED",
        }
        return _check(
            "provider",
            queue_ready == 0 or not strict,
            required=strict and queue_ready > 0,
            reason_code=_reason(str(exc), "PROVIDER_STATUS_UNAVAILABLE"),
            providers=[],
            eligible=0,
            organizer=organizer_value,
            organizer_status=organizer_value.get("status"),
            quota_state="UNKNOWN",
        )


def _sync_check(settings: Settings, manifest: Mapping[str, Any], strict: bool) -> dict[str, Any]:
    enabled = bool(getattr(settings, "sync_enabled", False)) or bool(manifest.get("sync_enabled", False))
    remote_names: list[str] = []
    git_status = "NOT_A_GIT_REPOSITORY"
    repo = Path(settings.paths.knowledge_root)
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "remote"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if result.returncode == 0:
            git_status = "OK"
            remote_names = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
    except (OSError, subprocess.SubprocessError):
        git_status = "GIT_PROBE_FAILED"
    ok = bool(remote_names) if enabled else True
    state = _read_json(Path(settings.paths.local_state_dir) / "sync-state.json")
    return _check(
        "sync",
        ok or not strict,
        required=enabled and strict,
        reason_code="GIT_REMOTE_REQUIRED" if enabled and not remote_names else None,
        enabled=enabled,
        git_status=git_status,
        remote_count=len(remote_names),
        remote_names=remote_names,
        last_status=state.get("last_status"),
        next_retry_at=state.get("next_retry_at"),
    )


def _experiment_check(settings: Settings, strict: bool) -> dict[str, Any]:
    policy_path = Path(settings.experiment_policy_path)
    policy = _read_json(policy_path)
    try:
        from .experiment import ExperimentConfig

        config = ExperimentConfig.from_mapping(policy or {})
        report_path = Path(settings.paths.runtime_dir) / "experiment-report.json"
        report = _read_json(report_path)
        effect_validated = bool(report.get("effect_validated")) if report else False
        return _check(
            "experiment",
            True,
            required=False,
            enabled=bool(getattr(settings, "experiment_enabled", False)),
            experiment_id=config.experiment_id,
            protocol_hash=config.protocol_hash,
            effect_validated=effect_validated,
            report_present=bool(report),
            blocking_reasons=list(report.get("audit", {}).get("blocking_reasons", ())) if report else ["NO_REPORT"],
        )
    except (OSError, ValueError, TypeError):
        return _check(
            "experiment",
            False if strict else True,
            required=bool(getattr(settings, "experiment_enabled", False)) and strict,
            reason_code="EXPERIMENT_PROTOCOL_INVALID",
            enabled=bool(getattr(settings, "experiment_enabled", False)),
            effect_validated=False,
        )


def _repair_items(checks: list[dict[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []
    for check in checks:
        if check.get("ok"):
            continue
        name = str(check.get("name", "unknown"))
        reason = _reason(check.get("reason_code"), "DOCTOR_CHECK_FAILED")
        result.append({
            "action": "review_" + re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower(),
            "reason_code": reason,
            "check": name,
            "mutating": False,
            "requires_user_approval": True,
        })
    return tuple(result)



def _recovery_check(settings: Settings, strict: bool) -> dict[str, Any]:
    health = _read_json(Path(settings.paths.runtime_dir) / "recovery-health.json")
    try:
        emergency = queue_health(settings).to_dict()["emergency_items"]
    except (OSError, QueueError, ValueError):
        emergency = None
    recovered = int(health.get("recovered", 0) or 0) if isinstance(health.get("recovered", 0), int) else 0
    deferred = int(health.get("parse_deferred", 0) or 0) if isinstance(health.get("parse_deferred", 0), int) else 0
    ok = emergency in {None, 0} and deferred == 0
    return _check(
        "recovery",
        ok or not strict,
        required=strict,
        reason_code="EMERGENCY_RECOVERY_PENDING" if emergency not in {None, 0} else "RECOVERY_PARSE_DEFERRED" if deferred else None,
        emergency_items=emergency,
        recovered=recovered,
        parse_deferred=deferred,
        policy_excluded=health.get("policy_excluded", 0),
        coverage_unknown=bool(health.get("coverage_unknown", False)),
    )


def maintenance_status(settings: Settings, manifest: Mapping[str, Any], scheduler: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Keep automatic configuration separate from the last manual/automatic result."""
    requested = manifest.get("scheduler_requested")
    health = _read_json(Path(settings.paths.runtime_root) / "health.json")
    last_status = health.get("status")
    if last_status not in {"success", "partial", "failed"}:
        last_status = "unknown"
    if requested is False:
        state, reason = "DISABLED", "AUTOMATIC_MAINTENANCE_DISABLED"
    elif requested is True:
        try:
            scheduler = scheduler if scheduler is not None else inspect_registered_task(settings)
            configured = scheduler.get("registered") is True and scheduler.get("ok") is True
        except (OSError, ValueError, TypeError, RuntimeError):
            configured = False
        state = "CONFIGURED" if configured else "UNVERIFIED"
        reason = None if configured else "AUTOMATIC_MAINTENANCE_UNVERIFIED"
    else:
        state, reason = "UNKNOWN", "AUTOMATIC_MAINTENANCE_UNVERIFIED"
    return {"status": state, "reason_code": reason, "requested": requested if type(requested) is bool else None,
            "last_recorded_status": last_status, "continuous_execution_verified": False}


def run_doctor(
    settings: Settings,
    strict: bool = False,
    repair_plan: Path | str | None = None,
) -> DoctorReport:
    """Inspect the complete local contract without applying repairs.

    repair_plan changes only the requested report artifact. It never trusts
    host configuration, merges global settings, purges data, or pushes Git.
    """
    if not isinstance(settings, Settings):
        raise TypeError("SETTINGS_REQUIRED")
    checks: list[dict[str, Any]] = []
    checks.append(_path_checks(settings, strict))
    checks.append(_dependency_check(settings, strict))
    checks.append(_settings_check(settings, strict))
    manifest = _read_manifest(settings)
    checks.append(_managed_check(settings, manifest, strict))
    checks.append(_knowledge_repository_check(settings, manifest, strict))
    checks.append(_host_checks(settings, manifest, strict, read_live=repair_plan is None))
    event_count, privacy_violations = _read_event_payloads(settings)
    checks.append(_privacy_check(settings, strict, event_count, privacy_violations))
    checks.append(_queue_check(settings, strict))
    checks.append(_recovery_check(settings, strict))
    checks.append(_spool_check(settings, strict))
    checks.append(_projection_check(settings, strict, event_count))
    team_check = _team_check(settings, strict)
    checks.append(team_check)
    queue_ready = 0
    queue_check = next((item for item in checks if item.get("name") == "queue"), {})
    if isinstance(queue_check.get("health"), Mapping):
        queue_ready = int(queue_check["health"].get("ready", 0) or 0)
    checks.append(_provider_check(settings, strict, queue_ready))
    checks.append(_sync_check(settings, manifest, strict))
    checks.append(_experiment_check(settings, strict))
    try:
        scheduler = inspect_registered_task(settings)
        scheduler_required = bool(manifest.get("scheduler_requested", False))
        if scheduler_required and not scheduler.get("registered"):
            scheduler = {
                **scheduler,
                "ok": False if strict else True,
                "required": strict,
                "reason_code": "SCHEDULER_NOT_REGISTERED",
            }
        checks.append({"name": "scheduler", **scheduler, "required": scheduler_required and strict})
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        checks.append(_check(
            "scheduler",
            not strict,
            required=strict,
            reason_code=_reason(str(exc), "SCHEDULER_STATE_INVALID"),
        ))
    scheduler_check = next((item for item in checks if item.get("name") == "scheduler"), {})
    checks.append(_check("maintenance", True, required=False,
                         **maintenance_status(settings, manifest, scheduler_check)))
    repairs = _repair_items(checks)
    if repair_plan is not None and str(repair_plan) != "-":
        target = Path(repair_plan).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema_version": 1,
            "generated_at": _iso(),
            "read_only": True,
            "checks": [dict(item) for item in checks],
            "repair_plan": [dict(item) for item in repairs],
        }
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()
    projection_check = next((item for item in checks if item.get("name") == "projection"), {})
    personal_status = "READY" if projection_check.get("index_present") or event_count == 0 else "NOT_READY"
    knowledge_stores = {
        "personal": {
            "status": personal_status,
            "active_patterns": int(projection_check.get("active_patterns", 0) or 0),
            "observations": int(projection_check.get("observation_count", event_count) or 0),
        },
        "team": {
            key: team_check[key]
            for key in (
                "store_status", "status", "reason_code", "store_id_hash", "active_patterns",
                "candidate_patterns", "observations", "accepted_event_count",
                "issue_codes", "transport_managed", "access_control_verified",
            )
            if key in team_check
        },
    }
    if "store_status" in knowledge_stores["team"]:
        knowledge_stores["team"]["status"] = knowledge_stores["team"].pop("store_status")
    raw_organizer = manifest.get("organizer") if isinstance(manifest.get("organizer"), Mapping) else getattr(settings, "organizer", None)
    if hasattr(raw_organizer, "to_dict"):
        raw_organizer = raw_organizer.to_dict()
    organizer = dict(raw_organizer) if isinstance(raw_organizer, Mapping) else {"status": "UNKNOWN", "provider_id": None, "host_id": None}
    raw_work_hosts = manifest.get("work_hosts")
    work_hosts = tuple(str(item) for item in raw_work_hosts if isinstance(item, str) and item) if isinstance(raw_work_hosts, (list, tuple)) else tuple(sorted(_manifest_hosts(settings, manifest)))
    return DoctorReport(tuple(checks), repairs, knowledge_stores, organizer, work_hosts)


def _main() -> int:
    parser = argparse.ArgumentParser(prog="ei.doctor")
    parser.add_argument("--repo-root", "--repo", dest="repo_root", required=True)
    parser.add_argument("--engine-root")
    parser.add_argument("--knowledge-root")
    parser.add_argument("--codex-home")
    parser.add_argument("--runtime-root")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--repair-plan", nargs="?", const="-")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    settings = load_settings(
        None if args.engine_root else Path(args.repo_root),
        Path(args.codex_home) if args.codex_home else None,
        engine_root=Path(args.engine_root) if args.engine_root else None,
        knowledge_root=Path(args.knowledge_root) if args.knowledge_root else None,
        runtime_root=Path(args.runtime_root) if args.runtime_root else None,
    )
    report = run_doctor(settings, strict=args.strict, repair_plan=args.repair_plan)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["DoctorReport", "run_doctor"]
