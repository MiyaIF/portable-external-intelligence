from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .adapters.codex_memory import CodexMemoryAdapter
from .adapters.rollout_summary import RolloutSummaryAdapter
from .capture import reconcile_fallback, record_agent_observation
from .certification import certify_host, write_certification_artifact
from .release import ReleaseManifest, build_release_manifest, verify_release_attestation
from .config import load_settings
from .context import build_context
from .doctor import run_doctor
from .experiment import ExperimentConfig, render_experiment_report, summarize_experiment
from .ids import fingerprint, machine_id, stable_hash
from .index import build_index
from .ingest import ingest_sources
from .install_agents import _marker_bounds
from .installer import (
    SetupSelection,
    UninstallOptions,
    _interactive_selection,
    setup as installer_setup,
    uninstall as installer_uninstall,
    update as installer_update,
)
from .inventory import SourceAuthorizationError, inventory_existing_state, write_inventory_report
from .journal import append_event, iter_events
from .knowledge_repository import KnowledgeRepositoryError, bootstrap_knowledge_repository, inspect_knowledge_repository
from .maintainer import _RouterAdapter, drain_queue, run_maintenance, team_status_snapshot
from .measurement_events import measurement_paths, read_measurement_records
from .metrics import aggregate_usage, collect_local_metrics, read_deduplicated_usage, write_local_snapshot
from .migrate import (
    apply_root_migration,
    build_root_migration_plan,
    cleanup_legacy_root,
    execute_migration,
    load_root_migration_plan,
    plan_migration,
    rollback_root_migration,
    write_root_migration_plan,
)
from .models import CaptureContext, Event, ObservationInput, validate_host_applicability_mapping, validate_host_label
from .privacy import inspect_observation
from .project import project_events
from .publication_policy import PublicationPolicyError, verify_publication_policy
from .reconciliation import reconcile_lifecycle
from .recovery import inspect_root_migration_recovery, recover_root_migration_staging
from .retrieve import (
    ExposureRecord,
    RetrievalPolicy,
    RetrievalQuery,
    merge_retrieval_hits,
    rank_patterns,
    record_retrieval_exposure,
    search_index,
    search_index_candidates,
)
from .safe_fs import SafeFilesystemError, absolute_path, assert_safe_target, safe_ensure_directory, safe_remove_tree, safe_unlink
from .skill_installer import canonical_tree_hash
from .stdio import write_utf8
from .spool import spool_health
from .queue import queue_health
from .sync import FileLock, SyncResult, sync_once
from .sync import GitRunner, build_sync_plan
from .workflow_security import WorkflowSecurityError, audit_workflows


EXIT_OK = 0
EXIT_INPUT = 2
EXIT_PRIVACY = 3
EXIT_GIT = 4
EXIT_DEPENDENCY = 5
EXIT_INTERNAL = 6


class InputError(ValueError):
    """Raised for invalid CLI input or schema."""


class PrivacyRejected(ValueError):
    """Raised when CLI input cannot cross the privacy boundary."""


def _emit(value: Any, json_mode: bool = False) -> None:
    if json_mode or isinstance(value, (dict, list, tuple)):
        write_utf8(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, default=str))
    else:
        write_utf8(value)


def _error_code(exc: BaseException, fallback: str = "INTERNAL_ERROR") -> str:
    text = str(exc or "")
    candidate = text.split(":", 1)[0].strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", candidate):
        return candidate
    return fallback


def _settings(args: argparse.Namespace):
    engine_value = getattr(args, "engine_root", None)
    knowledge_value = getattr(args, "knowledge_root", None)
    repo_value = getattr(args, "repo", None) or getattr(args, "repo_root", None)
    repo = Path(engine_value or repo_value or ".").expanduser().resolve()
    codex_home_value = getattr(args, "codex_home", None)
    runtime_value = getattr(args, "runtime_root", None)
    host_homes: dict[str, Path] = {}
    team_root_value: Path | None = None
    certificate_home = getattr(args, "certify_host_home", None)
    certificate_host = getattr(args, "host", None)
    if certificate_home and certificate_host:
        host_homes[str(certificate_host)] = Path(certificate_home).expanduser().resolve()
    if runtime_value and not codex_home_value:
        manifest_path = Path(runtime_value).expanduser().resolve() / "install-manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            manifest = {}
        records = manifest.get("hosts", {}) if isinstance(manifest, Mapping) else {}
        if isinstance(records, Mapping):
            for host_id, record in records.items():
                if isinstance(record, Mapping) and isinstance(record.get("home"), str):
                    host_homes[str(host_id)] = Path(record["home"])
        stores = manifest.get("knowledge_stores", {}) if isinstance(manifest, Mapping) else {}
        team = stores.get("team") if isinstance(stores, Mapping) else None
        if isinstance(team, Mapping) and team.get("enabled") is True and isinstance(team.get("root"), str):
            team_root_value = Path(team["root"])
    return load_settings(
        None if engine_value else repo,
        Path(codex_home_value).expanduser() if codex_home_value else None,
        engine_root=Path(engine_value).expanduser() if engine_value else None,
        knowledge_root=Path(knowledge_value).expanduser() if knowledge_value else None,
        team_knowledge_root=team_root_value,
        runtime_root=Path(runtime_value).expanduser() if runtime_value else None,
        host_homes=host_homes,
    )


def _source_paths(settings: Any, values: Iterable[str] | None) -> list[Path]:
    raw = list(values or ())
    if not raw:
        default = Path(settings.paths.codex_home) / "memories"
        return [default] if default.exists() else []
    result: list[Path] = []
    for value in raw:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise InputError("SOURCE_NOT_FOUND")
        if path.is_file():
            result.append(path)
        elif path.is_dir():
            result.extend(sorted(path.rglob("*.md")))
            result.extend(sorted(path.rglob("*.jsonl")))
        else:
            raise InputError("SOURCE_NOT_REGULAR")
    return list(dict.fromkeys(result))


def _adapters(paths: Iterable[Path]):
    for path in paths:
        if path.suffix.casefold() == ".jsonl":
            yield RolloutSummaryAdapter([path])
        elif path.suffix.casefold() == ".md":
            yield CodexMemoryAdapter([path])
        else:
            raise InputError("UNSUPPORTED_SOURCE_FORMAT")


def _read_stdin_limited(limit: int) -> str:
    if type(limit) is not int or limit <= 0:
        raise InputError("INPUT_LIMIT_INVALID")
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(limit + 1)
    if isinstance(raw, str):
        text = raw
        size = len(raw.encode("utf-8"))
    else:
        raw_bytes = bytes(raw)
        size = len(raw_bytes)
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError("INPUT_UTF8_INVALID") from exc
    if size > limit:
        raise InputError("INPUT_TOO_LARGE")
    return text


def _payload_text(payload: Mapping[str, Any], key: str, default: str = "") -> str:
    value = payload.get(key, default)
    if isinstance(value, str):
        return value.strip()
    return str(value).strip() if value is not None else ""


def _strict_payload_text(payload: Mapping[str, Any], key: str, default: str = "") -> str:
    value = payload.get(key, default)
    if not isinstance(value, str):
        raise InputError(f"OBSERVATION_FIELD_INVALID:{key}")
    return value.strip()


def _strict_payload_list(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key, ())
    if not isinstance(value, list):
        raise InputError(f"OBSERVATION_FIELD_INVALID:{key}")
    if any(not isinstance(item, str) for item in value):
        raise InputError(f"OBSERVATION_FIELD_INVALID:{key}")
    return tuple(item.strip() for item in value)


def _direct_observe(args) -> dict[str, Any]:
    try:
        raw = _read_stdin_limited(args.settings.capture_max_payload_bytes)
    except InputError as exc:
        if str(exc) == 'INPUT_TOO_LARGE':
            raise InputError('CAPTURE_PAYLOAD_TOO_LARGE') from exc
        raise
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError("OBSERVATION_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise InputError("OBSERVATION_NOT_OBJECT")
    capture_index = payload.get("capture_index", 0)
    if type(capture_index) is not int:
        raise InputError("OBSERVATION_FIELD_INVALID:capture_index")
    applicability = _strict_payload_list(payload, "applicability") if "applicability" in payload else ()
    observation = ObservationInput(
        _strict_payload_text(payload, "title"),
        _strict_payload_text(payload, "claim"),
        "agent_direct",
        _strict_payload_text(payload, "source_ref", "agent-direct"),
        _strict_payload_text(payload, "cwd"),
        _strict_payload_text(payload, "domain"),
        _strict_payload_text(payload, "outcome_status", "unknown"),
        _strict_payload_text(payload, "benefit"),
        _strict_payload_text(payload, "classification", "private-reusable"),
        applicability,
        _strict_payload_text(payload, "source_host_id"),
        _strict_payload_text(payload, "source_host_family"),
        _strict_payload_text(payload, "applicability_scope", "universal"),
        _strict_payload_list(payload, "applicable_host_ids") if "applicable_host_ids" in payload else (),
        _strict_payload_list(payload, "applicable_host_families") if "applicable_host_families" in payload else (),
    )
    context = CaptureContext(
        _strict_payload_text(payload, "session_id"),
        _strict_payload_text(payload, "turn_id"),
        capture_index,
        _strict_payload_text(payload, "source_host_id"),
        _strict_payload_text(payload, "source_host_family"),
    )
    result = record_agent_observation(observation, context, args.settings)
    return {
        "created": result.created,
        "event_id": result.event_id,
        "reason_code": result.reason_code,
        "status": "created" if result.created else "deferred",
    }


def _observe(args) -> dict[str, Any]:
    raw = args.json_input if args.json_input is not None else _read_stdin_limited(args.settings.capture_max_payload_bytes)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError("OBSERVATION_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise InputError("OBSERVATION_NOT_OBJECT")
    if any(not isinstance(payload.get(key), str) or not payload[key].strip() for key in ("title", "claim", "source_ref")):
        raise InputError("OBSERVATION_FIELDS_MISSING")
    applicability = _strict_payload_list(payload, "applicability") if "applicability" in payload else ()
    applicable_host_ids = _strict_payload_list(payload, "applicable_host_ids") if "applicable_host_ids" in payload else []
    applicable_host_families = _strict_payload_list(payload, "applicable_host_families") if "applicable_host_families" in payload else []
    host_values = {
        "source_host_id": payload.get("source_host_id", ""),
        "source_host_family": payload.get("source_host_family", ""),
        "applicability_scope": payload.get("applicability_scope", "universal"),
        "applicable_host_ids": applicable_host_ids,
        "applicable_host_families": applicable_host_families,
    }
    try:
        host_scope = validate_host_applicability_mapping(host_values, require_source_pair=True)
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    observation = ObservationInput(
        payload["title"],
        payload["claim"],
        _strict_payload_text(payload, "source_kind", "manual"),
        payload["source_ref"],
        _strict_payload_text(payload, "cwd"),
        _strict_payload_text(payload, "domain", "general"),
        _strict_payload_text(payload, "outcome_status", "unknown"),
        _strict_payload_text(payload, "benefit", ""),
        _strict_payload_text(payload, "classification", "private-reusable"),
        applicability,
        host_values["source_host_id"],
        host_values["source_host_family"],
        host_scope.scope,
        host_scope.host_ids,
        host_scope.host_families,
    )
    decision = inspect_observation(observation)
    if not decision.allow_private_sync:
        raise PrivacyRejected(decision.reason_code)
    record_fingerprint = fingerprint(observation.claim + "|" + observation.source_ref)
    event = Event.create(
        "observation.recorded",
        str(payload.get("observed_at", datetime.now(timezone.utc).isoformat())),
        "cli.observe",
        machine_id(),
        {
            "observation_id": "obs_" + record_fingerprint.removeprefix("sha256:")[:24],
            "title": observation.title,
            "claim": observation.claim,
            "source_kind": observation.source_kind,
            "source_ref_hash": fingerprint(observation.source_ref),
            "cwd_fingerprint": fingerprint(observation.cwd) if observation.cwd else "",
            "domain": observation.domain,
            "outcome_status": observation.outcome_status,
            "benefit": observation.benefit,
            "classification": decision.classification.value,
            "record_fingerprint": record_fingerprint,
            "source_hash": "",
            "source_host_id": observation.source_host_id,
            "source_host_family": observation.source_host_family,
            "applicability_scope": observation.applicability_scope,
            "applicable_host_ids": list(observation.applicable_host_ids),
            "applicable_host_families": list(observation.applicable_host_families),
        },
    )
    path = append_event(event, args.settings.paths.event_dir)
    return {"status": "created", "event_id": event.event_id, "path": str(path)}


def _capture_health(settings: Any, events: Sequence[Event]) -> dict[str, Any]:
    direct_events = [
        event
        for event in events
        if event.event_type == "observation.recorded"
        and event.payload.get("capture_path") == "agent_direct"
    ]
    native_events = [
        event
        for event in events
        if event.event_type == "observation.recorded"
        and event.payload.get("capture_path") != "agent_direct"
    ]
    result = reconcile_fallback(settings, direct_events, native_events)
    return {
        "direct_count": result.direct_count,
        "native_count": result.native_count,
        "fallback_recovered": result.recovered,
        "capture_coverage": result.coverage_rate,
        "capture_coverage_unknown": result.coverage_unknown,
    }


def _read_local_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path = Path(path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _rotate_and_write_log(path: Path, value: Mapping[str, Any], max_bytes: int, retention_files: int) -> None:
    if type(max_bytes) is not int or max_bytes < 1024:
        raise ValueError("SCHEDULED_LOG_LIMIT_INVALID")
    if type(retention_files) is not int or retention_files < 1:
        raise ValueError("SCHEDULED_LOG_RETENTION_INVALID")
    encoded = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n").encode("utf-8")
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.stat().st_size + len(encoded) > max_bytes:
        for index in range(retention_files - 1, 0, -1):
            source = target.with_name(f"{target.stem}.{index}{target.suffix}")
            destination = target.with_name(f"{target.stem}.{index + 1}{target.suffix}")
            if source.exists():
                os.replace(source, destination)
        os.replace(target, target.with_name(f"{target.stem}.1{target.suffix}"))
    with target.open("ab") as stream:
        stream.write(encoded)


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None or not str(value).strip():
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("DATETIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InputError("DATETIME_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _events(settings: Any) -> list[Event]:
    root = Path(settings.paths.event_dir)
    return list(iter_events(root)) if root.exists() else []


def _index(settings: Any):
    knowledge = Path(settings.paths.knowledge_dir)
    index_path = knowledge / "index.json"
    if not index_path.is_file():
        return None
    return build_index(knowledge, index_path)


def _team_enabled(settings: Any) -> bool:
    stores = getattr(settings, "knowledge_stores", None)
    team = getattr(stores, "team", None) if stores is not None else None
    if team is None:
        return False
    if isinstance(team, Mapping):
        return team.get("enabled", True) is True
    return True


def _team_projection_descriptor(settings: Any) -> tuple[Path, str] | None:
    if not _team_enabled(settings):
        return None
    stores = getattr(settings, "knowledge_stores", None)
    team = getattr(stores, "team", None) if stores is not None else None
    root_value = team.get("root") if isinstance(team, Mapping) else getattr(team, "root", None)
    root = Path(root_value).expanduser() if isinstance(root_value, (str, os.PathLike)) and str(root_value) else None
    store_id = str(team.get("store_id", "")) if isinstance(team, Mapping) else ""
    manifest_path = Path(settings.paths.runtime_root) / "install-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        manifest = {}
    manifest_stores = manifest.get("knowledge_stores", {}) if isinstance(manifest, Mapping) else {}
    manifest_team = manifest_stores.get("team") if isinstance(manifest_stores, Mapping) else None
    if isinstance(manifest_team, Mapping):
        if root is None and isinstance(manifest_team.get("root"), str):
            root = Path(manifest_team["root"]).expanduser()
        if not store_id and isinstance(manifest_team.get("store_id"), str):
            store_id = manifest_team["store_id"]
    if root is not None and not store_id:
        try:
            team_manifest = json.loads((root / "team-manifest.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            team_manifest = {}
        if isinstance(team_manifest, Mapping) and isinstance(team_manifest.get("store_id"), str):
            store_id = team_manifest["store_id"]
    if root is None or not store_id:
        return None
    return root, store_id


def _team_projection_for_recall(settings: Any) -> tuple[Any | None, dict[str, Any]]:
    if not _team_enabled(settings):
        return None, {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    descriptor = _team_projection_descriptor(settings)
    if descriptor is None:
        return None, {"status": "UNAVAILABLE", "reason_codes": ["TEAM_KNOWLEDGE_UNAVAILABLE"]}
    try:
        from .team_projection import refresh_team_projection
        result = refresh_team_projection(descriptor[0], settings.paths.runtime_root, descriptor[1])
    except (OSError, TypeError, ValueError) as exc:
        return None, {"status": "UNAVAILABLE", "reason_codes": ["TEAM_KNOWLEDGE_UNAVAILABLE"]}
    summary = {
        "status": result.status,
        "reason_codes": sorted({str(item.get("code", "TEAM_SCAN_ISSUE")) for item in result.issues}),
        "accepted_event_count": result.accepted_event_count,
        "active_patterns": len(result.index.active_pattern_ids) if result.index is not None else 0,
    }
    return result.index, summary


def _event_audit(settings: Any, decision: Any, candidate: Mapping[str, Any]) -> None:
    payload = {
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "provider_id": decision.provider_id or "unknown",
        "classification": decision.classification,
        "evidence_count": len(decision.evidence_refs),
        "candidate_id_hash": fingerprint(
            str(candidate.get("candidate_id", candidate.get("title", "candidate")))
        ),
    }
    if decision.source_host_id and decision.source_host_family:
        payload.update(
            {
                "source_host_id": decision.source_host_id,
                "source_host_family": decision.source_host_family,
                "applicability_scope": decision.applicability_scope,
                "applicable_host_ids": list(decision.applicable_host_ids),
                "applicable_host_families": list(decision.applicable_host_families),
            }
        )
    event_id = "evt_gate_" + stable_hash(payload)[:32]
    event = Event.create(
        "gate.decision",
        datetime.now(timezone.utc).isoformat(),
        "external-intelligence",
        machine_id(),
        payload,
        event_id=event_id,
    )
    append_event(event, settings.paths.event_dir)


def _closeout_source_pair(candidate: Mapping[str, Any], *, required: bool) -> tuple[str, str]:
    source_host_id = candidate.get("source_host_id", "")
    source_host_family = candidate.get("source_host_family", "")
    if not isinstance(source_host_id, str) or not isinstance(source_host_family, str):
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID")
    if bool(source_host_id) != bool(source_host_family):
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID")
    if not source_host_id and not source_host_family:
        if required:
            raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_REQUIRED")
        return "", ""
    try:
        validate_host_label(source_host_id, field="source_host_id")
        validate_host_label(source_host_family, field="source_host_family")
    except ValueError as exc:
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID") from exc
    return source_host_id, source_host_family
from .canary import read_hook_status, skill_discovery_canary
from .inference.router import ProviderRouter, ProviderSelectionError
from .spool import gc_expired_spool
from .experiment import assign_arm
from .models import PromotionPolicy
def _read_json_any(path: Path) -> Any:
    target = Path(path).expanduser().resolve()
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise InputError("REPORT_READ_FAILED") from exc
    if target.suffix.casefold() == ".jsonl":
        rows: list[Mapping[str, Any]] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                rows.append(dict(value))
        return rows
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError("JSON_DOCUMENT_INVALID") from exc


def _read_records(path: Path) -> list[Mapping[str, Any]]:
    value = _read_json_any(path)
    if isinstance(value, Mapping):
        return [dict(value)]
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    raise InputError("RECORD_DOCUMENT_INVALID")


def _setup(args: argparse.Namespace) -> int:
    selection = _interactive_selection(args)
    result = installer_setup(selection, check_only=bool(args.check_only or args.dry_run))
    value = result.to_dict()
    _emit(value, True)
    if result.ok:
        return EXIT_OK
    codes = {str(item.get("error_code", "")) for item in result.errors}
    if any(code.startswith(("HOST_", "PRIVACY_", "SKILL_")) for code in codes):
        return EXIT_INPUT
    return EXIT_DEPENDENCY


def _update(args: argparse.Namespace) -> int:
    target_ref = getattr(args, "target_ref", None)
    if target_ref is not None and (
        not isinstance(target_ref, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}", target_ref)
        or ".." in target_ref
    ):
        raise InputError("TARGET_REF_INVALID")
    result = installer_update(args.settings, check_only=bool(args.check_only or args.dry_run))
    value = result.to_dict()
    if target_ref:
        value["target_ref"] = target_ref
        value["target_ref_action"] = "validated_without_checkout"
    _emit(value, True)
    if result.ok:
        return EXIT_OK
    if any(str(item.get("error_code", "")).startswith(("GIT_", "UPDATE_")) for item in result.errors):
        return EXIT_GIT
    return EXIT_DEPENDENCY


def _safe_runtime_child(settings: Any, name: str) -> Path:
    runtime = absolute_path(settings.paths.runtime_root)
    repo = Path(settings.paths.engine_root).expanduser().resolve()
    if runtime == repo or runtime.is_relative_to(repo):
        raise PrivacyRejected("RUNTIME_REPOSITORY_PATH_FORBIDDEN")
    if name not in {"queue", "spool", "emergency-spool"}:
        raise InputError("RUNTIME_COMPONENT_INVALID")
    try:
        safe_ensure_directory(runtime)
        target = assert_safe_target(runtime, runtime / name, allow_missing=True)
    except SafeFilesystemError as exc:
        raise InputError(exc.code) from exc
    return target


def _remove_runtime_component(settings: Any, name: str) -> dict[str, Any]:
    target = _safe_runtime_child(settings, name)
    removed = False
    try:
        if target.is_dir() and not target.is_symlink():
            safe_remove_tree(target.parent, target, allow_missing=True)
            removed = True
        elif target.is_file():
            safe_unlink(target.parent, target, allow_missing=True)
            removed = True
    except SafeFilesystemError as exc:
        raise InputError(exc.code) from exc
    return {"component": name, "removed": removed}


def _uninstall(args: argparse.Namespace) -> int:
    options = UninstallOptions(
        restore_config_backup=bool(args.restore_config_backup),
        remove_skills=not bool(args.keep_skills),
        remove_runtime=bool(args.remove_runtime),
        remove_runtime_cache=bool(args.remove_runtime_cache),
        remove_scheduler=True,
        remove_venv=bool(args.remove_venv),
        force=bool(args.force),
        check_only=bool(args.check_only or args.dry_run),
    )
    source = Path(args.manifest).expanduser().resolve() if args.manifest else args.settings
    manifest_path = source if isinstance(source, Path) else Path(source.paths.install_manifest_path)
    try:
        manifest_sha256 = "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise InputError("MANIFEST_INVALID") from exc
    if not options.check_only and args.confirm_manifest_sha256 != manifest_sha256:
        raise InputError("UNINSTALL_CONFIRMATION_REQUIRED")
    result = installer_uninstall(source, options)
    if hasattr(result, "to_dict"):
        value = result.to_dict()
        ok = bool(result.ok)
    else:
        value = dict(result)
        ok = bool(value.get("ok"))
    value["manifest_sha256"] = manifest_sha256
    removals: list[Mapping[str, Any]] = []
    if ok and not options.check_only:
        for name, requested in (("queue", args.remove_queue), ("spool", args.remove_spool)):
            if requested:
                removals.append(_remove_runtime_component(args.settings, name))
                if name == "spool":
                    removals.append(_remove_runtime_component(args.settings, "emergency-spool"))
    value["explicit_runtime_components"] = removals
    _emit(value, True)
    return EXIT_OK if ok else EXIT_GIT
def _status_host(settings: Any, manifest: Mapping[str, Any], host_id: str) -> dict[str, Any]:
    records = manifest.get("hosts", {}) if isinstance(manifest.get("hosts"), Mapping) else {}
    record = records.get(host_id, {}) if isinstance(records, Mapping) else {}
    if not isinstance(record, Mapping):
        record = {}
    instance_id = str(record.get("host_instance_id", host_id))
    try:
        status = read_hook_status(host_id, instance_id, settings)
        raw = status.to_dict()
        allowed = (
            "host_id", "host_instance_id", "hook_status", "skill_discovery_status",
            "skill_activation_mode", "capture_primary_path", "reason_codes",
            "received_events", "last_received_at", "team",
        )
        hook = {key: raw.get(key) for key in allowed if key in raw}
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        hook = {
            "host_id": host_id,
            "host_instance_id": instance_id,
            "hook_status": "HOOK_UNVERIFIED",
            "skill_discovery_status": "UNVERIFIED",
            "reason_codes": [_error_code(exc, "HOOK_STATUS_UNAVAILABLE")],
        }
    try:
        discovery = skill_discovery_canary(host_id, instance_id, settings)
    except (OSError, TypeError, ValueError, RuntimeError):
        discovery = "UNVERIFIED"
    source_hash = ""
    source = Path(settings.paths.engine_root) / "skills" / "external-intelligence"
    if source.is_dir():
        try:
            source_hash = canonical_tree_hash(source)
        except (OSError, ValueError):
            source_hash = ""
    return {
        "host_id": host_id,
        "hook": hook,
        "skill": {
            "discovery": discovery,
            "source_hash": source_hash,
            "installed_hash": str(record.get("installed_skill_hash", "")),
            "activation": hook.get("skill_activation_mode", "UNAVAILABLE"),
        },
        "capture_primary": hook.get("capture_primary_path", "NATIVE_SOURCE"),
    }


def _provider_status(settings: Any) -> dict[str, Any]:
    try:
        router = ProviderRouter(settings=settings)
        providers: list[dict[str, Any]] = []
        for provider in router.providers:
            try:
                available = bool(provider.available())
            except (OSError, RuntimeError, ValueError):
                available = False
            providers.append({
                "provider_id": str(getattr(provider, "provider_id", "")),
                "locality": str(getattr(provider, "locality", "unknown")),
                "available": available,
            })
        try:
            eligible = [str(item.provider_id) for item in router.eligible_providers()]
        except (OSError, RuntimeError, ValueError):
            eligible = []
        return {
            "status": "ready" if eligible else "deferred",
            "order": [str(item.get("provider_id", "")) for item in providers],
            "providers": providers,
            "eligible": eligible,
            "quota": "available" if eligible else "unverified_or_exhausted",
        }
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "unavailable",
            "providers": [],
            "eligible": [],
            "reason_code": _error_code(exc, "PROVIDER_STATUS_UNAVAILABLE"),
        }


def _projection_status(settings: Any) -> dict[str, Any]:
    index = _index(settings)
    if index is None:
        return {
            "status": "not_ready",
            "active_patterns": 0,
            "candidate_patterns": 0,
            "observations": 0,
        }
    candidate_count = 0
    try:
        document = json.loads(Path(index.index_path).read_text(encoding="utf-8"))
        if isinstance(document, Mapping):
            candidate_count = len(document.get("candidate_pattern_ids", ()))
    except (OSError, UnicodeError, json.JSONDecodeError):
        candidate_count = 0
    return {
        "status": "ready",
        "active_patterns": len(index.active_pattern_ids),
        "candidate_patterns": candidate_count,
        "archived_patterns": len(index.archive_pattern_ids),
        "observations": index.observation_count,
        "always_on_chars": index.always_on_chars,
        "generation_hash": index.generation_hash,
    }
def _status(args: argparse.Namespace) -> int:
    settings = args.settings
    events = _events(settings)
    manifest = _read_local_json(Path(settings.paths.install_manifest_path)) or {}
    records = manifest.get("hosts", {}) if isinstance(manifest.get("hosts"), Mapping) else {}
    configured = {str(item) for item in records}
    configured.update(str(item) for item in getattr(settings, "hosts", {}) if str(item))
    host_ids = list(args.host or sorted(configured) or ["codex-cli"])
    host_rows = [_status_host(settings, manifest, host_id) for host_id in host_ids]
    hook_summary = {row["host_id"]: row["hook"] for row in host_rows}
    skill_summary = {row["host_id"]: row["skill"] for row in host_rows}
    capture = _capture_health(settings, events)
    try:
        queue = queue_health(settings).to_dict()
    except (OSError, RuntimeError, ValueError) as exc:
        queue = {"status": "unavailable", "reason_code": _error_code(exc, "QUEUE_HEALTH_UNAVAILABLE")}
    try:
        spool = spool_health(settings).to_dict()
    except (OSError, RuntimeError, ValueError) as exc:
        spool = {"status": "unavailable", "reason_code": _error_code(exc, "SPOOL_HEALTH_UNAVAILABLE")}
    sync_state = _read_local_json(Path(settings.paths.local_state_dir) / "sync-state.json") or {}
    sync = {
        "enabled": bool(getattr(settings, "sync_enabled", False)),
        "last_status": sync_state.get("last_status"),
        "last_reason_code": sync_state.get("last_reason_code"),
        "next_retry_at": sync_state.get("next_retry_at"),
    }
    measurement = measurement_paths(settings)
    exposures = len(read_measurement_records(measurement["exposures"], "exposure"))
    outcomes = len(read_measurement_records(measurement["outcomes"], "outcome"))
    experiment = {
        "enabled": bool(getattr(settings, "experiment_enabled", False)),
        "experiment_id": str(getattr(settings, "experiment_id", "retrieval-v1")),
        "exposures": exposures,
        "outcomes": outcomes,
        "report_present": (Path(settings.paths.runtime_root) / "experiment-report.json").is_file(),
    }
    personal_projection = _projection_status(settings)
    try:
        team_store = team_status_snapshot(settings)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        team_store = {
            "status": "DEFERRED",
            "reason_code": "DEFERRED_TEAM_STORE",
            "issue_codes": [_error_code(exc, "TEAM_KNOWLEDGE_UNAVAILABLE")],
            "transport_managed": False,
            "access_control_verified": False,
        }
    raw_organizer = manifest.get("organizer") if isinstance(manifest.get("organizer"), Mapping) else getattr(settings, "organizer", None)
    if hasattr(raw_organizer, "to_dict"):
        raw_organizer = raw_organizer.to_dict()
    if isinstance(raw_organizer, Mapping):
        organizer = {
            "status": str(raw_organizer.get("status", "UNKNOWN")),
            "provider_id": raw_organizer.get("provider_id"),
            "host_id": raw_organizer.get("host_id"),
        }
    else:
        organizer = {"status": "UNKNOWN", "provider_id": None, "host_id": None}
    manifest_work_hosts = manifest.get("work_hosts")
    work_hosts = [str(item) for item in manifest_work_hosts if isinstance(item, str) and item] if isinstance(manifest_work_hosts, (list, tuple)) else [row["host_id"] for row in host_rows]
    _emit({
        "status": "ok",
        "organizer": organizer,
        "work_hosts": work_hosts,
        "Hook": {"hosts": hook_summary},
        "Skill": {"hosts": skill_summary},
        "capture_primary": capture,
        "queue": queue,
        "spool": spool,
        "provider": _provider_status(settings),
        "projection": personal_projection,
        "knowledge_stores": {
            "personal": personal_projection,
            "team": team_store,
        },
        "sync": sync,
        "experiment": experiment,
    }, True)
    return EXIT_OK


def _retrieval_policy(settings: Any) -> RetrievalPolicy:
    path = Path(settings.retrieval_policy_path)
    if not path.is_file():
        return RetrievalPolicy(
            max_results=int(getattr(settings, "retrieval_max_results", 5)),
            max_chars=int(getattr(settings, "retrieval_max_chars", 5000)),
            min_score=float(getattr(settings, "retrieval_min_score", 0.35)),
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError("RETRIEVAL_POLICY_READ_FAILED") from exc
    if not isinstance(value, Mapping):
        raise InputError("RETRIEVAL_POLICY_INVALID")
    try:
        return RetrievalPolicy.from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise InputError("RETRIEVAL_POLICY_INVALID") from exc
from .changeset import apply_changeset, validate_changeset
from .curator import curate_candidate
from .gate import decide_inheritance
from .inference.base import InferenceBudget
def _recall(args: argparse.Namespace) -> int:
    query_text = str(args.query or "").strip()
    if not query_text:
        raise InputError("QUERY_REQUIRED")
    if len(query_text) > int(getattr(args.settings, "prompt_max_chars", 5000)):
        raise InputError("QUERY_TOO_LARGE")
    policy = _retrieval_policy(args.settings)
    if args.max_chars is not None:
        if type(args.max_chars) is not int or args.max_chars < 1:
            raise InputError("MAX_CHARS_INVALID")
        values = {name: getattr(policy, name) for name in policy.__dataclass_fields__}
        values["max_chars"] = args.max_chars
        policy = RetrievalPolicy(**values)
    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else None
    host_id = str(args.host or "")
    host_family = _configured_host_family(args.settings, host_id)
    query = RetrievalQuery(
        prompt=query_text,
        cwd_fingerprint=fingerprint(str(cwd)) if cwd else "",
        domain=str(getattr(args, "domain", "") or ""),
        scope_tags=tuple(str(item) for item in (getattr(args, "scope", ()) or ()) if str(item)),
        host_id=host_id,
        host_family=host_family,
        version=str(getattr(args, "version", "") or ""),
        max_chars=policy.max_chars,
    )
    started = __import__("time").monotonic()
    personal_index = _index(args.settings)
    team_index, team_projection = _team_projection_for_recall(args.settings)
    personal_store = {
        "status": "READY" if personal_index is not None else "NOT_READY",
        "active_patterns": len(personal_index.active_pattern_ids) if personal_index is not None else 0,
    }
    team_projection_status = str(team_projection.get("status", "UNAVAILABLE"))
    team_store = {
        "status": "DISABLED" if team_projection_status == "DISABLED" else "DEFERRED" if team_projection_status in {"UNAVAILABLE", "DEFERRED"} else "READY",
        "reason_code": "TEAM_DISABLED" if team_projection_status == "DISABLED" else "DEFERRED_TEAM_STORE" if team_projection_status in {"UNAVAILABLE", "DEFERRED"} else None,
        "active_patterns": int(team_projection.get("active_patterns", 0) or 0),
        "accepted_event_count": int(team_projection.get("accepted_event_count", 0) or 0),
        "issue_codes": list(team_projection.get("reason_codes", ())),
        "transport_managed": False,
        "access_control_verified": False,
    }
    if team_store["reason_code"] is None:
        team_store.pop("reason_code")
    if personal_index is None and team_index is None:
        _emit({
            "status": "unavailable",
            "reason_code": "INDEX_NOT_READY",
            "hits": [],
            "context": "",
            "team_projection": team_projection,
            "knowledge_stores": {"personal": personal_store, "team": team_store},
        }, True)
        return EXIT_OK
    personal_hits = search_index_candidates(personal_index, query, policy) if personal_index is not None else []
    team_hits = search_index_candidates(team_index, query, policy, knowledge_scope="team") if team_index is not None else []
    hits = merge_retrieval_hits(personal_hits, team_hits, policy)
    session_id = str(getattr(args, "session_id", "") or machine_id())
    experiment_config = ExperimentConfig.defaults()
    experiment_path = Path(args.settings.experiment_policy_path)
    if experiment_path.is_file():
        try:
            experiment_config = ExperimentConfig.from_mapping(json.loads(experiment_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise InputError("EXPERIMENT_PROTOCOL_INVALID") from exc
    arm = (
        assign_arm(fingerprint(session_id), experiment_config.experiment_id)
        if bool(getattr(args.settings, "experiment_enabled", False))
        else "treatment"
    )
    candidate_ids = tuple(hit.pattern_id for hit in hits)
    candidate_scopes = tuple(hit.knowledge_scope for hit in hits)
    selected = candidate_ids if arm == "treatment" else ()
    selected_scopes = candidate_scopes if arm == "treatment" else ()
    context = build_context(hits, policy.max_chars) if arm == "treatment" else ""
    elapsed = int((__import__("time").monotonic() - started) * 1000)
    session_hash = fingerprint(session_id)
    query_hash = fingerprint(query_text)
    exposure_id = "exp_" + stable_hash({
        "experiment_id": experiment_config.experiment_id,
        "session_id_hash": session_hash,
        "query_fingerprint": query_hash,
        "host_id": host_id,
        "candidate_ids": list(candidate_ids),
        "selected_ids": list(selected),
    })[:24]
    record_retrieval_exposure(
        ExposureRecord(
            exposure_id=exposure_id,
            experiment_id=experiment_config.experiment_id,
            session_id_hash=session_hash,
            arm=arm,
            candidate_ids=candidate_ids,
            selected_ids=selected,
            query_fingerprint=query_hash,
            injection_chars=len(context),
            retrieval_latency_ms=elapsed,
            host_id=host_id,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            candidate_scopes=candidate_scopes,
            selected_scopes=selected_scopes,
            empty_result=not candidate_ids,
            team_unavailable="TEAM_KNOWLEDGE_UNAVAILABLE" in team_projection.get("reason_codes", []),
        ),
        Path(args.settings.paths.runtime_root) / "recall-exposures.jsonl",
    )
    from .measurement_events import ExposureRecord as MeasurementExposureRecord
    from .measurement_events import record_exposure as record_measurement_exposure
    measurement_exposure = MeasurementExposureRecord(
        experiment_id=experiment_config.experiment_id,
        session_id_hash=session_hash,
        task_id_hash=fingerprint(session_id + ":" + host_id + ":" + (str(cwd) if cwd else "")),
        query_fingerprint=query_hash,
        arm=arm,
        candidate_ids=candidate_ids,
        selected_ids=selected,
        candidate_scopes=candidate_scopes,
        selected_scopes=selected_scopes,
        empty_result=not candidate_ids,
        team_unavailable="TEAM_KNOWLEDGE_UNAVAILABLE" in team_projection.get("reason_codes", []),
        injected_chars=len(context),
        retrieval_latency_ms=elapsed,
        host_id=host_id or "unknown",
        observed_at=datetime.now(timezone.utc).isoformat(),
        protocol_hash=experiment_config.protocol_hash,
        context_injected=bool(context),
    )
    record_measurement_exposure(measurement_exposure, args.settings)
    _emit({
        "status": "ok",
        "arm": arm,
        "hits": [hit.__dict__ for hit in hits],
        "context": context,
        "context_chars": len(context),
        "exposure_id": exposure_id,
        "query_fingerprint": query_hash,
        "team_projection": team_projection,
        "knowledge_stores": {"personal": personal_store, "team": team_store},
    }, True)
    return EXIT_OK
def _closeout(args: argparse.Namespace) -> int:
    if args.input_json is not None:
        input_path = Path(str(args.input_json)).expanduser().resolve()
        if not input_path.is_file():
            raise InputError("INPUT_JSON_FILE_NOT_FOUND")
        try:
            raw_bytes = input_path.read_bytes()
        except OSError as exc:
            raise InputError("INPUT_JSON_FILE_READ_FAILED") from exc
        limit = int(args.settings.capture_max_payload_bytes)
        if len(raw_bytes) > limit:
            raise InputError("CLOSEOUT_PAYLOAD_TOO_LARGE")
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError("CLOSEOUT_UTF8_INVALID") from exc
    else:
        raw = _read_stdin_limited(args.settings.capture_max_payload_bytes)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError("CLOSEOUT_JSON_INVALID") from exc
    if not isinstance(payload, Mapping):
        raise InputError("CLOSEOUT_OBJECT_REQUIRED")
    nested_candidate = payload.get("candidate")
    if nested_candidate is not None and not isinstance(nested_candidate, Mapping):
        raise InputError("CLOSEOUT_CANDIDATE_OBJECT_REQUIRED")
    candidate = {
        str(key): value
        for key, value in (nested_candidate if isinstance(nested_candidate, Mapping) else payload).items()
        if isinstance(key, str)
    }
    gate_input = payload.get("gate_decision") if isinstance(payload.get("gate_decision"), Mapping) else candidate
    try:
        if isinstance(gate_input, Mapping) and isinstance(payload.get("gate_decision"), Mapping):
            from .gate import GateDecision
            source_host_id, source_host_family = _closeout_source_pair(
                candidate,
                required=gate_input.get("decision") == "YES",
            )
            decision = GateDecision.from_mapping(
                gate_input,
                source_host_id=source_host_id,
                source_host_family=source_host_family,
            )
        elif candidate.get("decision") in {"YES", "NO"}:
            from .gate import GateDecision
            source_host_id, source_host_family = _closeout_source_pair(candidate, required=candidate.get("decision") == "YES")
            decision = GateDecision.from_mapping(
                candidate,
                source_host_id=source_host_id,
                source_host_family=source_host_family,
            )
        else:
            budget = InferenceBudget(
                candidate_id=str(candidate.get("candidate_id", "closeout")),
                purpose="inheritance-gate",
                deadline_ms=int(getattr(args.settings, "prompt_budget_ms", 1000)),
            )
            decision = decide_inheritance(
                candidate,
                _RouterAdapter(ProviderRouter(settings=args.settings)),
                budget,
            )
    except ProviderSelectionError:
        raise
    except (ValueError, TypeError) as exc:
        raise InputError(_error_code(exc, "GATE_INPUT_INVALID")) from exc

    if decision.decision in {"YES", "NO"}:
        privacy = inspect_observation(ObservationInput(
            decision.candidate_title,
            decision.candidate_claim,
            "agent_direct",
            str(candidate.get("source_ref", "closeout")),
            "",
            str(candidate.get("domain", "general")),
            "observed",
            decision.benefit,
            decision.classification,
        ))
        if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
            if decision.decision == "YES":
                raise PrivacyRejected(privacy.reason_code)
            from .gate import GateDecision
            decision = GateDecision(
                "NO",
                "secret_or_confidential",
                "",
                "",
                (),
                "",
                "private-reusable",
                1.0,
                decision.provider_id,
                source_host_id=decision.source_host_id,
                source_host_family=decision.source_host_family,
                applicability_scope=decision.applicability_scope,
                applicable_host_ids=decision.applicable_host_ids,
                applicable_host_families=decision.applicable_host_families,
            )
        _event_audit(args.settings, decision, candidate)
    if decision.decision == "NO":
        team_result = {"status": "DISABLED", "reason_code": "TEAM_DISABLED"} if getattr(getattr(args.settings, "knowledge_stores", None), "team", None) is None else {"status": "SKIPPED", "reason_code": "PERSONAL_APPLY_NOT_SUCCESS"}
        _emit({
            "status": "discarded",
            "gate": decision.to_dict(),
            "curation": {"status": "not_run"},
            "personal": {"status": "DISCARDED"},
            "team": team_result,
            "knowledge_stores": {"personal": {"status": "DISCARDED"}, "team": team_result},
        }, True)
        return EXIT_OK
    if decision.decision == "DEFERRED":
        team_result = {"status": "DISABLED", "reason_code": "TEAM_DISABLED"} if getattr(getattr(args.settings, "knowledge_stores", None), "team", None) is None else {"status": "DEFERRED", "reason_code": "DEFERRED_TEAM_STORE"}
        _emit({"status": "deferred", "gate": decision.to_dict(), "personal": {"status": "DEFERRED"}, "team": team_result, "knowledge_stores": {"personal": {"status": "DEFERRED"}, "team": team_result}}, True)
        return EXIT_DEPENDENCY
    if decision.decision == "FAILED":
        team_result = {"status": "DISABLED", "reason_code": "TEAM_DISABLED"} if getattr(getattr(args.settings, "knowledge_stores", None), "team", None) is None else {"status": "SKIPPED", "reason_code": "PERSONAL_APPLY_NOT_SUCCESS"}
        _emit({"status": "failed", "gate": decision.to_dict(), "personal": {"status": "FAILED"}, "team": team_result, "knowledge_stores": {"personal": {"status": "FAILED"}, "team": team_result}}, True)
        retryable = {"NO_PROVIDER_AVAILABLE", "PROVIDER_UNAVAILABLE", "QUOTA_EXHAUSTED"}
        return EXIT_DEPENDENCY if decision.reason_code in retryable else EXIT_INTERNAL

    index = _index(args.settings)
    curator_input = {
        **candidate,
        "decision": "YES",
        "title": decision.candidate_title,
        "claim": decision.candidate_claim,
        "candidate_title": decision.candidate_title,
        "candidate_claim": decision.candidate_claim,
        "benefit": decision.benefit,
        "classification": decision.classification,
        "evidence_refs": list(decision.evidence_refs),
        "source_host_id": decision.source_host_id,
        "source_host_family": decision.source_host_family,
        "applicability_scope": decision.applicability_scope,
        "applicable_host_ids": list(decision.applicable_host_ids),
        "applicable_host_families": list(decision.applicable_host_families),
    }
    changeset = curate_candidate(
        curator_input,
        index,
        {"provider_id": decision.provider_id or "manual-structured"},
        None,
    )
    validation = validate_changeset(changeset, args.settings)
    if not validation.valid:
        code = validation.reason_codes[0] if validation.reason_codes else "CHANGESET_INVALID"
        if code in {"RAW_CONTENT_FORBIDDEN", "PRIVACY_REJECTED"}:
            raise PrivacyRejected(code)
        raise InputError(code)
    applied = apply_changeset(changeset, args.settings)
    team_result: dict[str, Any]
    team_store = getattr(getattr(args.settings, "knowledge_stores", None), "team", None)
    if team_store is None:
        team_result = {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    elif applied.applied:
        from .team_routing import route_applied_personal_knowledge
        team_decision = route_applied_personal_knowledge(
            {
                "applied": applied.applied,
                "changeset_hash": changeset.fingerprint,
                "event_ids": list(applied.event_ids),
                "candidate": curator_input,
                "changeset": changeset.to_dict(),
            },
            args.settings,
        )
        team_result = team_decision.to_dict()
    else:
        team_result = {"status": "SKIPPED", "reason_code": "PERSONAL_APPLY_NOT_SUCCESS"}
    value = {
        "status": "applied" if applied.applied else "failed",
        "gate": decision.to_dict(),
        "curation": {
            "changeset": changeset.to_dict(),
            "applied": applied.applied,
            "reason_code": applied.reason_code,
            "event_ids": list(applied.event_ids),
            "already_applied": applied.already_applied,
        },
        "personal": {
            "status": "READY" if applied.applied else "FAILED",
            "reason_code": applied.reason_code,
        },
        "team": team_result,
        "knowledge_stores": {
            "personal": {"status": "READY" if applied.applied else "FAILED"},
            "team": team_result,
        },
    }
    _emit(value, True)
    return EXIT_OK if applied.applied else EXIT_INTERNAL
def _drain(args: argparse.Namespace) -> int:
    result = drain_queue(
        args.settings,
        max_items=args.max_items,
        time_budget_ms=args.time_budget_ms,
        now=_parse_datetime(args.now),
    )
    _emit(result.to_dict(), True)
    return EXIT_OK if result.status == "success" else EXIT_INTERNAL


def _maintain(args: argparse.Namespace) -> int:
    if args.dry_run:
        try:
            queue = queue_health(args.settings).to_dict()
        except (OSError, RuntimeError, ValueError) as exc:
            queue = {
                "status": "unavailable",
                "reason_code": _error_code(exc, "QUEUE_HEALTH_UNAVAILABLE"),
            }
        _emit({
            "status": "dry-run",
            "source_count": len(getattr(args, "source", ()) or ()),
            "queue": queue,
            "sync_policy": getattr(args, "sync_policy", None) or "disabled",
            "mutations": False,
        }, True)
        return EXIT_OK
    policy = getattr(args, "sync_policy", None)
    if not policy:
        policy = "auto" if bool(args.sync or getattr(args.settings, "sync_enabled", False)) else "disabled"
    source_values = getattr(args, "source", ()) or ()
    source_paths = tuple(_source_paths(args.settings, source_values)) if source_values else ()
    log_path = (
        Path(args.log_file).expanduser().resolve()
        if args.log_file
        else Path(args.settings.paths.log_dir) / "maintenance.jsonl"
    )
    try:
        with FileLock(Path(args.settings.paths.locks_dir) / "maintenance.lock"):
            result = run_maintenance(
                args.settings,
                source_paths=source_paths,
                max_queue_items=args.max_items,
                time_budget_ms=args.time_budget_ms,
                sync_policy=policy,
                now=_parse_datetime(args.now),
            )
    except RuntimeError as exc:
        if str(exc) == "SYNC_LOCK_BUSY":
            raise
        raise InputError(_error_code(exc, "MAINTENANCE_LOCK_FAILED")) from exc
    _rotate_and_write_log(
        log_path,
        result.to_dict(),
        int(args.settings.scheduler_log_max_bytes),
        int(args.settings.scheduler_log_retention_files),
    )
    if not args.quiet:
        _emit(result.to_dict(), True)
    if result.status == "success":
        return EXIT_OK
    codes = {str(item.get("error_code", "")) for item in result.errors}
    if codes and codes <= {"SOURCE_PARTIAL"}:
        return EXIT_OK
    if any(code.startswith(("SYNC_", "GIT_", "REBASE_")) for code in codes) or str(result.blocked_reason or "").startswith("SYNC_"):
        return EXIT_GIT
    if any(code.startswith(("NO_PROVIDER", "QUOTA", "PROVIDER", "AUTH_")) for code in codes):
        return EXIT_DEPENDENCY
    return EXIT_INTERNAL


def _sync(args: argparse.Namespace) -> int:
    if args.dry_run:
        result = SyncResult(True, "DRY_RUN")
    else:
        result = sync_once(args.settings)
    _emit(result.to_dict(), True)
    return EXIT_OK if result.ok else EXIT_GIT
def _inventory(args: argparse.Namespace) -> int:
    if args.memory_root and args.source:
        raise InputError("MEMORY_ROOT_SOURCE_CONFLICT")
    if args.source:
        raw_values = list(args.source)
        if any(str(item).casefold() == "auto" for item in raw_values):
            if not args.allow_global_source:
                raise InputError("GLOBAL_SOURCE_APPROVAL_REQUIRED")
            roots = [Path(args.settings.paths.codex_home) / "memories"]
        else:
            roots = [Path(value).expanduser().resolve() for value in raw_values]
    elif args.memory_root:
        roots = [Path(args.memory_root).expanduser().resolve()]
    else:
        if not args.allow_global_source:
            raise InputError("GLOBAL_SOURCE_APPROVAL_REQUIRED")
        roots = [Path(args.settings.paths.codex_home) / "memories"]
    global_root = (Path(args.settings.paths.codex_home) / "memories").resolve()
    if any(path == global_root for path in roots) and not args.allow_global_source:
        raise InputError("GLOBAL_SOURCE_APPROVAL_REQUIRED")
    inventory_result = inventory_existing_state(
        tuple(roots),
        args.settings,
        allow_global_source=bool(args.allow_global_source),
        approval_path=(
            Path(args.approval_path).expanduser().resolve()
            if args.approval_path
            else None
        ),
    )
    report = (
        Path(args.inventory).expanduser().resolve()
        if args.inventory
        else Path(args.settings.paths.runtime_root) / "inventory.json"
    )
    write_inventory_report(inventory_result, report)
    _emit({**inventory_result.to_dict(), "report": str(report)}, True)
    return EXIT_OK


def _migration_document(plan: Any, mode: str, migration: Any | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "mode": mode,
        "plan_hash": plan.plan_hash,
        "planned_items": len(plan.items),
        "source_hashes": dict(plan.source_hashes),
        "inventory": plan.inventory.to_dict() if plan.inventory else None,
    }
    if migration is not None:
        value.update({
            "imported": migration.imported,
            "skipped": migration.skipped,
            "duplicates": migration.duplicates,
            "external_references": migration.external_references,
            "secret_rejected": migration.secret_rejected,
            "cluster_provenances": {
                key: list(item)
                for key, item in migration.cluster_provenances.items()
            },
            "inventory_hash": migration.inventory_hash,
            "policy_provenance": migration.policy_provenance,
            "resumed": migration.resumed,
            "checkpoint_path": str(migration.checkpoint_path) if migration.checkpoint_path else None,
            "rollback_manifest_path": (
                str(migration.rollback_manifest_path)
                if migration.rollback_manifest_path
                else None
            ),
            "status": migration.status,
        })
    return value


def _migrate(args: argparse.Namespace) -> int:
    if not args.source:
        raise InputError("MIGRATION_SOURCE_REQUIRED")
    if args.dry_run == bool(args.apply):
        raise InputError("CHOOSE_DRY_RUN_OR_APPLY")
    if args.apply and not args.apply_plan_hash:
        raise InputError("MIGRATION_PLAN_HASH_REQUIRED")
    raw_roots = [Path(value).expanduser().resolve() for value in args.source]
    global_root = (Path(args.settings.paths.codex_home) / "memories").resolve()
    if any(path == global_root for path in raw_roots) and not args.allow_global_source:
        raise InputError("GLOBAL_SOURCE_APPROVAL_REQUIRED")
    inventory = None
    if args.inventory:
        inventory = inventory_existing_state(
            tuple(raw_roots),
            args.settings,
            allow_global_source=bool(args.allow_global_source),
        )
        inventory_path = Path(args.inventory).expanduser().resolve()
        if not (args.dry_run and not inventory_path.exists()):
            stored = _read_json_any(inventory_path)
            if not isinstance(stored, Mapping):
                raise InputError("MIGRATION_INVENTORY_INVALID")
            if str(stored.get("inventory_hash", "")) != inventory.inventory_hash:
                raise InputError("MIGRATION_INVENTORY_HASH_MISMATCH")
        plan = plan_migration(inventory, args.settings)
    elif len(raw_roots) == 1:
        plan = plan_migration(
            raw_roots[0],
            args.settings,
            allow_global_source=bool(args.allow_global_source),
        )
    else:
        inventory = inventory_existing_state(
            tuple(raw_roots),
            args.settings,
            allow_global_source=bool(args.allow_global_source),
        )
        plan = plan_migration(inventory, args.settings)
    if args.apply and args.apply_plan_hash != plan.plan_hash:
        raise InputError("MIGRATION_PLAN_HASH_MISMATCH")
    report = (
        Path(args.report).expanduser().resolve()
        if args.report
        else Path(args.settings.paths.runtime_root) / "migration-report.json"
    )
    if args.dry_run:
        if args.inventory and plan.inventory:
            write_inventory_report(plan.inventory, Path(args.inventory))
        value = _migration_document(plan, "dry-run")
    else:
        migration = execute_migration(
            plan,
            inventory=plan.inventory,
            settings=args.settings,
        )
        value = _migration_document(plan, "apply", migration)
    _write_json(report, value)
    _emit({**value, "report": str(report)}, True)
    return EXIT_OK
def _filter_usage_rows(
    rows: Iterable[Mapping[str, Any]],
    start: datetime | None,
    end: datetime | None,
) -> list[Mapping[str, Any]]:
    selected: list[Mapping[str, Any]] = []
    for row in rows:
        value = row.get("created_at")
        try:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if moment.tzinfo is None or moment.utcoffset() is None:
                continue
            moment = moment.astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
        if start is not None and moment < start:
            continue
        if end is not None and moment > end:
            continue
        selected.append(row)
    return selected


def _metrics(args: argparse.Namespace) -> int:
    start = _parse_datetime(args.from_value)
    end = _parse_datetime(args.to_value)
    if start is not None and end is not None and start > end:
        raise InputError("METRIC_RANGE_INVALID")
    if args.sqlite:
        database = Path(args.sqlite).expanduser().resolve()
        if not database.is_file():
            raise FileNotFoundError(str(database))
        read = read_deduplicated_usage(database, args.settings)
        if read.status != "OK":
            value = {
                "status": read.status,
                "source_status": read.source_status,
                "database_sha256": read.database_sha256,
                "schema": {
                    "status": read.schema.status,
                    "table": read.schema.table,
                    "columns": list(read.schema.columns),
                    "reason_code": read.schema.reason_code,
                    "schema_sha256": read.schema.schema_sha256,
                },
                "aggregate": read.aggregate.to_dict(),
            }
            _emit(value, True)
            return EXIT_DEPENDENCY
        rows = _filter_usage_rows(read.rows, start, end)
        aggregate = aggregate_usage(rows)
        snapshot = write_local_snapshot(aggregate, args.settings.paths.metrics_dir)
        value = {
            "status": "success",
            "source_status": read.source_status,
            "database_sha256": read.database_sha256,
            "schema": {
                "status": read.schema.status,
                "table": read.schema.table,
                "columns": list(read.schema.columns),
                "reason_code": read.schema.reason_code,
                "schema_sha256": read.schema.schema_sha256,
            },
            "range": {
                "from": start.isoformat().replace("+00:00", "Z") if start else None,
                "to": end.isoformat().replace("+00:00", "Z") if end else None,
            },
            "row_count": len(rows),
            "aggregate": aggregate.to_dict(),
            "snapshot": str(snapshot),
        }
    else:
        result = collect_local_metrics(
            args.settings.paths.codex_home,
            args.settings.paths.metrics_dir,
        )
        value = result.to_dict()
        value["range"] = {
            "from": start.isoformat().replace("+00:00", "Z") if start else None,
            "to": end.isoformat().replace("+00:00", "Z") if end else None,
        }
    _emit(value, True)
    return EXIT_OK


def _experiment_config(settings: Any, experiment_id: str | None = None) -> ExperimentConfig:
    path = Path(settings.experiment_policy_path)
    raw: Mapping[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InputError("EXPERIMENT_PROTOCOL_READ_FAILED") from exc
        if not isinstance(loaded, Mapping):
            raise InputError("EXPERIMENT_PROTOCOL_INVALID")
        raw = loaded
    if experiment_id:
        raw = {**raw, "experiment_id": experiment_id}
    try:
        return ExperimentConfig.from_mapping(raw)
    except (TypeError, ValueError) as exc:
        raise InputError("EXPERIMENT_PROTOCOL_INVALID") from exc


def _experiment_report(args: argparse.Namespace) -> int:
    paths = measurement_paths(args.settings)
    exposure_path = Path(args.exposures).expanduser().resolve() if args.exposures else paths["exposures"]
    outcome_path = Path(args.outcomes).expanduser().resolve() if args.outcomes else paths["outcomes"]
    if args.exposures:
        exposures = _read_records(exposure_path)
    else:
        exposures = list(read_measurement_records(exposure_path, "exposure"))
    if args.outcomes:
        outcomes = _read_records(outcome_path)
    else:
        outcomes = list(read_measurement_records(outcome_path, "outcome"))
    config = _experiment_config(args.settings, args.experiment_id)
    summary = summarize_experiment(exposures, outcomes, config)
    canonical = Path(args.settings.paths.runtime_root) / "experiment-report.json"
    _write_json(canonical, summary)
    if args.output:
        output = Path(args.output).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix.casefold() == ".json":
            _write_json(output, summary)
        else:
            temporary = output.with_name(output.name + f".{os.getpid()}.tmp")
            temporary.write_text(render_experiment_report(summary), encoding="utf-8", newline="\n")
            try:
                os.replace(temporary, output)
            finally:
                if temporary.exists():
                    temporary.unlink()
    else:
        output = canonical
    _emit({
        "status": "success",
        "experiment_id": config.experiment_id,
        "protocol_hash": config.protocol_hash,
        "summary": summary,
        "report": str(output),
        "canonical_report": str(canonical),
    }, True)
    return EXIT_OK
def _index_patterns(settings: Any) -> list[Mapping[str, Any]]:
    index = _index(settings)
    if index is None:
        return []
    from .index import read_index_items
    try:
        return list(read_index_items(index, list(index.active_pattern_ids) or None))
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise InputError(_error_code(exc, "INDEX_READ_FAILED")) from exc


def _legacy_ingest(args: argparse.Namespace) -> int:
    paths = _source_paths(args.settings, args.source)
    results = [
        ingest_sources(args.settings, [_adapter]).__dict__
        for _adapter in _adapters(paths)
    ]
    _emit({"status": "success", "results": results}, args.json_mode)
    return EXIT_OK


def _legacy_reconcile(args: argparse.Namespace) -> int:
    events = _events(args.settings)
    result = reconcile_lifecycle(events, args.settings.paths.event_dir)
    value = result.__dict__ if hasattr(result, "__dict__") else result
    _emit(value, args.json_mode)
    return EXIT_OK


def _legacy_project(args: argparse.Namespace) -> int:
    events = _events(args.settings)
    result = project_events(events, args.settings.paths.knowledge_dir)
    value = result.__dict__ if hasattr(result, "__dict__") else result
    _emit(value, args.json_mode)
    return EXIT_OK


def _legacy_query(args: argparse.Namespace) -> int:
    patterns = _index_patterns(args.settings)
    policy = _retrieval_policy(args.settings)
    hits = rank_patterns(RetrievalQuery(prompt=args.prompt), patterns, policy)
    _emit({
        "hits": [hit.__dict__ for hit in hits],
        "context": build_context(hits, policy.max_chars),
    }, args.json_mode)
    return EXIT_OK


def _configured_host_family(settings: Any, host_id: str) -> str:
    """Return the configured family for a trusted host id, or empty if unknown."""

    if not host_id:
        return ""
    hosts = getattr(settings, "hosts", {})
    try:
        host = hosts.get(host_id) if isinstance(hosts, Mapping) else None
    except (AttributeError, TypeError):
        host = None
    if isinstance(host, Mapping):
        family = host.get("host_family", "")
    else:
        family = getattr(host, "host_family", "") if host is not None else ""
    return family if isinstance(family, str) else ""


def _certify_host(args: argparse.Namespace) -> int:
    result = certify_host(
        args.host,
        args.instance,
        args.mode,
        args.settings,
        os_profile=args.os_profile,
    )
    value = result.to_dict()
    if args.output:
        output = write_certification_artifact(args.output, result)
        value["artifact"] = str(output)
    _emit(value, True)
    return EXIT_OK if result.status == "PASSED" else EXIT_DEPENDENCY


def _release_artifact_input(args: argparse.Namespace) -> Mapping[str, Any]:
    if args.artifacts:
        value = _read_json_any(Path(args.artifacts).expanduser().resolve())
        if not isinstance(value, Mapping):
            raise InputError("RELEASE_ARTIFACTS_OBJECT_REQUIRED")
        return dict(value)
    return {
        "workflow_sha256": args.workflow_sha256,
        "workflow_names": args.workflow_name or [],
        "certification_sha256": args.certification_sha256 or [],
        "real_certification": bool(args.real_certification),
    }


def _release_prepare(args: argparse.Namespace) -> int:
    artifacts = _release_artifact_input(args)
    manifest = build_release_manifest(args.subject_commit, artifacts, args.settings)
    value = manifest.to_dict()
    if args.output:
        _write_json(Path(args.output), value)
        value["manifest"] = str(Path(args.output).expanduser().resolve())
    _emit(value, True)
    return EXIT_OK


def _release_receipts(args: argparse.Namespace) -> list[Mapping[str, Any]] | None:
    paths = list(args.certification_artifact or [])
    if not paths:
        return None
    return [_read_json_any(Path(path).expanduser().resolve()) for path in paths]


def _release_verify(args: argparse.Namespace) -> int:
    manifest_value = _read_json_any(Path(args.manifest).expanduser().resolve())
    manifest = ReleaseManifest.from_mapping(manifest_value)
    attestation = _read_json_any(Path(args.attestation).expanduser().resolve())
    if not isinstance(attestation, Mapping):
        raise InputError("RELEASE_ATTESTATION_OBJECT_REQUIRED")
    status = verify_release_attestation(
        manifest,
        attestation,
        args.evidence_commit,
        certification_receipts=_release_receipts(args),
    )
    value = status.to_dict()
    if args.output:
        _write_json(Path(args.output), value)
        value["report"] = str(Path(args.output).expanduser().resolve())
    _emit(value, True)
    return EXIT_OK if status.software_complete else EXIT_DEPENDENCY


def _release_report(args: argparse.Namespace) -> int:
    return _release_verify(args)


def _public_release(args: argparse.Namespace) -> int:
    if args.public_release_command == "policy" and args.policy_command == "verify":
        try:
            value = verify_publication_policy(Path(args.policy))
        except PublicationPolicyError as exc:
            _emit({"valid": False, "error_code": exc.code}, True)
            return EXIT_INPUT
        _emit(value, True)
        return EXIT_OK
    if args.public_release_command == "workflows" and args.workflow_command == "verify":
        try:
            value = audit_workflows(Path(args.workflow_dir))
        except (OSError, UnicodeError, WorkflowSecurityError, ValueError) as exc:
            _emit({"status": "failed", "error_code": str(exc).split(":", 1)[0]}, True)
            return EXIT_INPUT
        _emit(value, True)
        return EXIT_OK if value["status"] == "passed" else EXIT_DEPENDENCY
    raise InputError("PUBLIC_RELEASE_COMMAND_INVALID")


def _knowledge(args: argparse.Namespace) -> int:
    command = getattr(args, "knowledge_command", None)
    try:
        if command == "init":
            status = bootstrap_knowledge_repository(
                args.knowledge_root,
                engine_root=args.engine_root,
                runtime_root=args.runtime_root,
                initialize_git=not bool(args.no_git),
            )
        elif command == "inspect":
            status = inspect_knowledge_repository(
                args.knowledge_root,
                engine_root=args.engine_root,
                runtime_root=args.runtime_root,
            )
        else:
            raise InputError("KNOWLEDGE_COMMAND_INVALID")
    except KnowledgeRepositoryError as exc:
        _emit({"ok": False, "error_code": exc.code}, True)
        return EXIT_INPUT
    value = status.to_dict()
    _emit(value, True)
    return EXIT_OK if status.initialized and status.manifest_valid and status.required_paths_present else EXIT_DEPENDENCY


def _migration(args: argparse.Namespace) -> int:
    command = getattr(args, "migration_command", None)
    if command == "inspect":
        plan = build_root_migration_plan(
            args.repo,
            args.knowledge_root,
            args.runtime_root,
            policy_version=args.policy_version,
        )
        if args.plan_output:
            output = Path(args.plan_output).expanduser().resolve()
            runtime = Path(args.runtime_root).expanduser().resolve()
            if output != runtime and not output.is_relative_to(runtime):
                raise InputError("MIGRATION_PLAN_OUTPUT_MUST_BE_RUNTIME")
            write_root_migration_plan(plan, output)
        value = {**plan.to_dict(), "mode": "inspect", "mutations": bool(args.plan_output)}
        if args.plan_output:
            value["plan"] = str(Path(args.plan_output).expanduser().resolve())
    elif command == "apply":
        plan = load_root_migration_plan(args.plan)
        if args.confirm_plan_hash != plan.plan_hash:
            raise InputError("MIGRATION_PLAN_HASH_MISMATCH")
        result = apply_root_migration(plan)
        value = {**result.to_dict(), "mode": "apply", "mutations": True}
    elif command == "rollback":
        result = rollback_root_migration(args.receipt, confirm_plan_hash=args.confirm_plan_hash)
        value = {**result.to_dict(), "mode": "rollback", "mutations": True}
    elif command == "cleanup":
        plan = load_root_migration_plan(args.plan)
        if args.confirm_plan_hash != plan.plan_hash:
            raise InputError("MIGRATION_CLEANUP_APPROVAL_REQUIRED")
        removed = cleanup_legacy_root(
            plan,
            confirm_plan_hash=args.confirm_plan_hash,
            verified_backup=args.verified_backup,
        )
        value = {
            "mode": "cleanup",
            "mutations": True,
            "status": "complete",
            "plan_hash": plan.plan_hash,
            "removed_files": removed,
        }
    elif command == "inspect-recovery":
        status = inspect_root_migration_recovery(args.knowledge_root, args.runtime_root)
        value = {**status.to_dict(), "mode": "inspect-recovery", "mutations": False}
    elif command == "recover-staging":
        status = recover_root_migration_staging(
            args.knowledge_root,
            args.runtime_root,
            args.plan_hash,
            confirm=bool(args.confirm),
        )
        value = {**status.to_dict(), "mode": "recover-staging", "mutations": True}
    else:
        raise InputError("MIGRATION_COMMAND_INVALID")
    if getattr(args, "output", None):
        output = Path(args.output).expanduser().resolve()
        runtime_value = getattr(args, "runtime_root", None)
        if runtime_value is None and command in {"apply", "cleanup"}:
            runtime_value = plan.runtime_root if "plan" in locals() else None
        if runtime_value is not None:
            runtime = Path(runtime_value).expanduser().resolve()
            if output != runtime and not output.is_relative_to(runtime):
                raise InputError("MIGRATION_REPORT_OUTPUT_MUST_BE_RUNTIME")
        _write_json(output, value)
        value["report"] = str(output)
    _emit(value, True)
    return EXIT_OK


def _sync_plan(args: argparse.Namespace) -> int:
    root = Path(args.settings.paths.knowledge_root if not args.settings.paths.legacy_layout else args.settings.paths.engine_root)
    runner = GitRunner(root)
    status = runner.run(["git", "status", "--porcelain", "--untracked-files=all"])
    if status.returncode != 0:
        _emit({"ok": False, "error_code": "KNOWLEDGE_REPOSITORY_REQUIRED", "root": str(root)}, True)
        return EXIT_INPUT
    plan = build_sync_plan(status.stdout.splitlines(), args.settings)
    value = {
        "ok": plan.allowed or plan.reason_code == "NO_ENGINE_CHANGES",
        "reason_code": plan.reason_code,
        "root": str(root),
        "stage_paths": list(plan.stage_paths),
        "unrelated_paths": list(plan.unrelated_paths),
        "review_paths": list(plan.review_paths),
        "sync_enabled": bool(getattr(args.settings, "sync_enabled", False)),
        "mutations": False,
    }
    _emit(value, True)
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ei",
        description="Portable external intelligence engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(name: str, *, source: bool = False) -> argparse.ArgumentParser:
        child = sub.add_parser(name)
        child.add_argument("--repo", "--repo-root", dest="repo", default=".")
        child.add_argument("--engine-root")
        child.add_argument("--knowledge-root")
        child.add_argument("--codex-home")
        child.add_argument("--runtime-root")
        child.add_argument("--json", action="store_true", dest="json_mode")
        child.add_argument("--dry-run", action="store_true")
        if source:
            child.add_argument("--source", action="append", default=[])
        return child

    setup = common("setup")
    setup.add_argument("--check-only", action="store_true")
    setup.add_argument("--work-host", dest="work_hosts", action="append", default=[])
    setup.add_argument("--hosts", action="append", default=[], help="deprecated alias of --work-host")
    setup.add_argument("--host", dest="hosts", action="append", help="deprecated alias of --work-host")
    setup.add_argument("--host-home", action="append", default=[])
    setup.add_argument("--host-profile", action="append", default=[])
    setup.add_argument("--include-codex-app", action="store_true")
    setup.add_argument("--python-exe")
    setup.add_argument("--providers", action="append", default=[])
    setup.add_argument("--organizer-provider")
    setup.add_argument("--organizer-host")
    setup.add_argument("--privacy-profile", default="private-reusable")
    setup.add_argument("--knowledge-mode", choices=("local", "github-new", "github-existing"))
    setup.add_argument("--github-repository")
    setup.add_argument("--github-executable", default="gh")
    setup.add_argument("--remote-name", default="origin")
    setup.add_argument("--branch", default="main")
    setup.add_argument("--accept-plan", action="store_true")
    setup.add_argument("--confirm-github-create")
    sync_group = setup.add_mutually_exclusive_group()
    sync_group.add_argument("--sync", dest="sync", action="store_true")
    sync_group.add_argument("--no-sync", dest="sync", action="store_false")
    setup.set_defaults(sync=None)
    setup.add_argument("--experiment", action="store_true")
    setup.add_argument("--scheduler", action="store_true")
    setup.add_argument("--skill-mode", choices=("copy", "link"), default="copy")
    setup.add_argument("--skip-venv", action="store_true")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--personal-knowledge-root")
    team_group = setup.add_mutually_exclusive_group()
    team_group.add_argument("--team-knowledge-root")
    team_group.add_argument("--no-team-knowledge", dest="team_knowledge", action="store_false")
    setup.add_argument("--team-member-id")
    setup.set_defaults(team_knowledge=None)

    update = common("update")
    update.add_argument("--check-only", action="store_true")
    update.add_argument("--target-ref")

    uninstall = common("uninstall")
    uninstall.add_argument("--check-only", action="store_true")
    uninstall.add_argument("--manifest")
    uninstall.add_argument("--confirm-manifest-sha256")
    uninstall.add_argument("--restore-config-backup", action="store_true")
    uninstall.add_argument("--remove-runtime", action="store_true")
    uninstall.add_argument("--remove-queue", action="store_true")
    uninstall.add_argument("--remove-spool", action="store_true")
    uninstall.add_argument("--remove-runtime-cache", action="store_true")
    uninstall.add_argument("--remove-venv", action="store_true")
    uninstall.add_argument("--keep-skills", action="store_true")
    uninstall.add_argument("--force", action="store_true")

    doctor = common("doctor")
    doctor.add_argument("--strict", action="store_true")
    doctor.add_argument("--repair-plan", nargs="?", const="-")

    status = common("status")
    status.add_argument("--host", action="append", default=[])

    queue = sub.add_parser("queue")
    queue_sub = queue.add_subparsers(dest="queue_command", required=True)
    drain = queue_sub.add_parser("drain")
    drain.add_argument("--repo", "--repo-root", dest="repo", default=".")
    drain.add_argument("--engine-root")
    drain.add_argument("--knowledge-root")
    drain.add_argument("--codex-home")
    drain.add_argument("--runtime-root")
    drain.add_argument("--json", action="store_true", dest="json_mode")
    drain.add_argument("--dry-run", action="store_true")
    drain.add_argument("--max-items", type=int, default=100)
    drain.add_argument("--time-budget-ms", type=int, default=5000)
    drain.add_argument("--now")

    recall = common("recall")
    recall.add_argument("--query", required=True)
    recall.add_argument("--host", default="")
    recall.add_argument("--domain", default="")
    recall.add_argument("--scope", action="append", default=[])
    recall.add_argument("--version", default="")
    recall.add_argument("--cwd")
    recall.add_argument("--max-chars", type=int)
    recall.add_argument("--session-id")

    closeout = common("closeout")
    closeout.add_argument("--input-json")

    maintain = common("maintain", source=True)
    maintain.add_argument("--max-items", type=int, default=100)
    maintain.add_argument("--time-budget-ms", type=int, default=30000)
    maintain.add_argument("--sync-policy", choices=("disabled", "manual", "auto"))
    maintain.add_argument("--sync", action="store_true")
    maintain.add_argument("--log-file")
    maintain.add_argument("--quiet", action="store_true")
    maintain.add_argument("--now")

    sync = common("sync")
    sync.add_argument("--retry-now", action="store_true")
    sync_sub = sync.add_subparsers(dest="sync_command", required=False)
    sync_plan = sync_sub.add_parser("plan")
    sync_plan.add_argument("--repo", "--repo-root", dest="repo", default=None)
    sync_plan.add_argument("--engine-root", required=True)
    sync_plan.add_argument("--knowledge-root", required=True)
    sync_plan.add_argument("--codex-home")
    sync_plan.add_argument("--runtime-root", required=True)
    sync_plan.add_argument("--json", action="store_true", dest="json_mode")

    inventory = common("inventory-existing", source=True)
    inventory.add_argument("--memory-root")
    inventory.add_argument("--inventory")
    inventory.add_argument("--allow-global-source", action="store_true")
    inventory.add_argument("--approval-path")

    migrate = common("migrate-existing")
    migrate.add_argument("--source", action="append", required=True, default=[])
    migrate.add_argument("--report")
    migrate.add_argument("--inventory")
    migrate.add_argument("--apply", action="store_true")
    migrate.add_argument("--apply-plan-hash", "--expected-plan-hash", dest="apply_plan_hash")
    migrate.add_argument("--allow-global-source", action="store_true")

    migration = sub.add_parser("migration")
    migration_sub = migration.add_subparsers(dest="migration_command", required=True)
    migration_inspect = migration_sub.add_parser("inspect")
    migration_inspect.add_argument("--repo", "--repo-root", dest="repo", default=".")
    migration_inspect.add_argument("--knowledge-root", required=True)
    migration_inspect.add_argument("--runtime-root", required=True)
    migration_inspect.add_argument("--policy-version", default="1")
    migration_inspect.add_argument("--plan-output")
    migration_inspect.add_argument("--output")
    migration_inspect.add_argument("--json", action="store_true", dest="json_mode")
    migration_apply = migration_sub.add_parser("apply")
    migration_apply.add_argument("--plan", required=True)
    migration_apply.add_argument("--confirm-plan-hash", required=True)
    migration_apply.add_argument("--output")
    migration_apply.add_argument("--json", action="store_true", dest="json_mode")
    migration_rollback = migration_sub.add_parser("rollback")
    migration_rollback.add_argument("--receipt", required=True)
    migration_rollback.add_argument("--confirm-plan-hash", required=True)
    migration_rollback.add_argument("--output")
    migration_rollback.add_argument("--json", action="store_true", dest="json_mode")
    migration_cleanup = migration_sub.add_parser("cleanup")
    migration_cleanup.add_argument("--plan", required=True)
    migration_cleanup.add_argument("--confirm-plan-hash", required=True)
    migration_cleanup.add_argument("--verified-backup", required=True)
    migration_cleanup.add_argument("--output")
    migration_cleanup.add_argument("--json", action="store_true", dest="json_mode")
    migration_inspect_recovery = migration_sub.add_parser("inspect-recovery")
    migration_inspect_recovery.add_argument("--knowledge-root", required=True)
    migration_inspect_recovery.add_argument("--runtime-root", required=True)
    migration_inspect_recovery.add_argument("--output")
    migration_inspect_recovery.add_argument("--json", action="store_true", dest="json_mode")
    migration_recover = migration_sub.add_parser("recover-staging")
    migration_recover.add_argument("--knowledge-root", required=True)
    migration_recover.add_argument("--runtime-root", required=True)
    migration_recover.add_argument("--plan-hash", required=True)
    migration_recover.add_argument("--confirm", action="store_true")
    migration_recover.add_argument("--output")
    migration_recover.add_argument("--json", action="store_true", dest="json_mode")

    metrics = common("metrics")
    metrics.add_argument("--sqlite")
    metrics.add_argument("--from", dest="from_value")
    metrics.add_argument("--to", dest="to_value")

    experiment = common("experiment-report")
    experiment.add_argument("--experiment-id")
    experiment.add_argument("--exposures")
    experiment.add_argument("--outcomes")
    experiment.add_argument("--output")

    certify = common("certify-host")
    certify.add_argument("--host", required=True)
    certify.add_argument("--instance", required=True)
    certify.add_argument("--mode", choices=("fixture", "real"), required=True)
    certify.add_argument("--os-profile")
    certify.add_argument("--host-home", dest="certify_host_home")
    certify.add_argument("--output")

    release = sub.add_parser("release")
    release_sub = release.add_subparsers(dest="release_command", required=True)

    prepare = release_sub.add_parser("prepare")
    prepare.add_argument("--repo", "--repo-root", dest="repo", default=".")
    prepare.add_argument("--engine-root")
    prepare.add_argument("--knowledge-root")
    prepare.add_argument("--codex-home")
    prepare.add_argument("--runtime-root")
    prepare.add_argument("--json", action="store_true", dest="json_mode")
    prepare.add_argument("--artifacts")
    prepare.add_argument("--subject-commit", required=True)
    prepare.add_argument("--workflow-sha256")
    prepare.add_argument("--workflow-name", action="append", default=[])
    prepare.add_argument("--certification-sha256", action="append", default=[])
    prepare.add_argument("--real-certification", action="store_true")
    prepare.add_argument("--output")

    for release_name in ("verify-ci", "verify", "report"):
        verifier = release_sub.add_parser(release_name)
        verifier.add_argument("--repo", "--repo-root", dest="repo", default=".")
        verifier.add_argument("--engine-root")
        verifier.add_argument("--knowledge-root")
        verifier.add_argument("--codex-home")
        verifier.add_argument("--runtime-root")
        verifier.add_argument("--json", action="store_true", dest="json_mode")
        verifier.add_argument("--manifest", required=True)
        verifier.add_argument("--attestation", required=True)
        verifier.add_argument("--evidence-commit", required=True)
        verifier.add_argument("--certification-artifact", action="append", default=[])
        verifier.add_argument("--output")
    observe = common("observe")
    observe.add_argument("--json-input")
    observe.add_argument("--stdin-json", action="store_true")
    common("ingest", source=True)
    common("reconcile")
    query = common("query")
    query.add_argument("--prompt", required=True)
    common("project")

    knowledge = sub.add_parser("knowledge")
    knowledge_sub = knowledge.add_subparsers(dest="knowledge_command", required=True)
    knowledge_init = knowledge_sub.add_parser("init")
    knowledge_init.add_argument("--engine-root", required=True)
    knowledge_init.add_argument("--knowledge-root", required=True)
    knowledge_init.add_argument("--runtime-root")
    knowledge_init.add_argument("--no-git", action="store_true")
    knowledge_init.add_argument("--json", action="store_true", dest="json_mode")
    knowledge_inspect = knowledge_sub.add_parser("inspect")
    knowledge_inspect.add_argument("--engine-root", required=True)
    knowledge_inspect.add_argument("--knowledge-root", required=True)
    knowledge_inspect.add_argument("--runtime-root")
    knowledge_inspect.add_argument("--json", action="store_true", dest="json_mode")

    public_release = sub.add_parser("public-release")
    public_release_sub = public_release.add_subparsers(dest="public_release_command", required=True)
    policy = public_release_sub.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_verify = policy_sub.add_parser("verify")
    policy_verify.add_argument("--policy", required=True)
    policy_verify.add_argument("--json", action="store_true", dest="json_mode")
    workflows = public_release_sub.add_parser("workflows")
    workflow_sub = workflows.add_subparsers(dest="workflow_command", required=True)
    workflow_verify = workflow_sub.add_parser("verify")
    workflow_verify.add_argument("--workflow-dir", default=".github/workflows")
    workflow_verify.add_argument("--json", action="store_true", dest="json_mode")
    return parser
def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args: argparse.Namespace | None = None
    try:
        try:
            args = parser.parse_args(raw_argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else EXIT_INPUT
            if code != 0 and "--json" in raw_argv:
                _emit({"ok": False, "error_code": "ARGUMENTS_INVALID"}, True)
            return code
        if args.command == "setup":
            return _setup(args)
        if args.command == "public-release":
            return _public_release(args)
        if args.command == "knowledge":
            return _knowledge(args)
        if args.command == "migration":
            return _migration(args)
        args.settings = _settings(args)
        if args.command == "update":
            return _update(args)
        if args.command == "uninstall":
            return _uninstall(args)
        if args.command == "certify-host":
            return _certify_host(args)
        if args.command == "release":
            if args.release_command == "prepare":
                return _release_prepare(args)
            if args.release_command in {"verify-ci", "verify"}:
                return _release_verify(args)
            if args.release_command == "report":
                return _release_report(args)
            raise InputError("RELEASE_COMMAND_INVALID")
        if args.command == "doctor":
            report = run_doctor(
                args.settings,
                strict=bool(args.strict),
                repair_plan=args.repair_plan,
            )
            _emit(report.to_dict(), True)
            return EXIT_OK if report.ok or args.repair_plan is not None else EXIT_DEPENDENCY
        if args.command == "status":
            return _status(args)
        if args.command == "queue":
            if args.queue_command != "drain":
                raise InputError("QUEUE_COMMAND_INVALID")
            return _drain(args)
        if args.command == "recall":
            return _recall(args)
        if args.command == "closeout":
            return _closeout(args)
        if args.command == "maintain":
            return _maintain(args)
        if args.command == "sync":
            if getattr(args, "sync_command", None) == "plan":
                return _sync_plan(args)
            return _sync(args)
        if args.command == "inventory-existing":
            return _inventory(args)
        if args.command == "migrate-existing":
            return _migrate(args)
        if args.command == "metrics":
            return _metrics(args)
        if args.command == "experiment-report":
            return _experiment_report(args)
        if args.command == "observe":
            if args.stdin_json and args.json_input is not None:
                raise InputError("OBSERVATION_INPUT_MODE_CONFLICT")
            if args.dry_run:
                _emit({"status": "dry-run"}, args.json_mode)
                return EXIT_OK
            _emit(
                _direct_observe(args) if args.stdin_json else _observe(args),
                args.json_mode,
            )
            return EXIT_OK
        if args.command == "ingest":
            return _legacy_ingest(args)
        if args.command == "reconcile":
            return _legacy_reconcile(args)
        if args.command == "project":
            return _legacy_project(args)
        if args.command == "query":
            return _legacy_query(args)
        raise InputError("COMMAND_INVALID")
    except PrivacyRejected as exc:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": _error_code(exc, "PRIVACY_REJECTED")}, True)
        return EXIT_PRIVACY
    except ProviderSelectionError as exc:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": _error_code(exc, "NO_PROVIDER_AVAILABLE")}, True)
        return EXIT_DEPENDENCY
    except SourceAuthorizationError as exc:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": _error_code(exc, "SOURCE_NOT_AUTHORIZED")}, True)
        return EXIT_INPUT
    except InputError as exc:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": _error_code(exc, "INPUT_INVALID")}, True)
        return EXIT_INPUT
    except FileNotFoundError:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": "DEPENDENCY_NOT_FOUND"}, True)
        return EXIT_DEPENDENCY
    except ValueError as exc:
        code = _error_code(exc, "INPUT_INVALID")
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": code}, True)
        if code.startswith("PRIVACY_") or code in {"SECRET_PATTERN_MATCH", "RAW_FIELD_DETECTED"}:
            return EXIT_PRIVACY
        return EXIT_INPUT
    except RuntimeError as exc:
        code = _error_code(exc, "INTERNAL_ERROR")
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": code}, True)
        if code.startswith(("SYNC_", "GIT_", "REBASE_")):
            return EXIT_GIT
        return EXIT_INTERNAL
    except OSError as exc:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": _error_code(exc, "IO_ERROR")}, True)
        return EXIT_INTERNAL
    except Exception:
        if args is None or not getattr(args, "quiet", False):
            _emit({"ok": False, "error_code": "INTERNAL_ERROR"}, True)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
