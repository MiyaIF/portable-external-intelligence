from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .adapters.base import SourceCursor
from .ids import machine_id
from .journal import append_event, iter_events
from .models import Event
from .privacy import inspect_text
from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_no_reparse_components,
    assert_safe_target,
    canonical_path,
    safe_atomic_write,
    safe_ensure_directory,
    safe_remove_tree,
)


@dataclass(frozen=True)
class RecoveryResult:
    recovered: int
    parse_deferred: int
    policy_excluded: int
    capture_coverage_unknown: bool
    duplicate: int = 0
    reason_codes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recovered": self.recovered,
            "parse_deferred": self.parse_deferred,
            "policy_excluded": self.policy_excluded,
            "capture_coverage_unknown": self.capture_coverage_unknown,
            "duplicate": self.duplicate,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class RootMigrationRecovery:
    status: str
    destination_root: Path
    runtime_root: Path
    staging_names: tuple[str, ...] = ()
    receipt_names: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "destination_root": str(self.destination_root),
            "runtime_root": str(self.runtime_root),
            "staging_names": list(self.staging_names),
            "receipt_names": list(self.receipt_names),
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class SetupOperationRecovery:
    status: str
    operation_id: str | None
    operation_status: str | None
    stage: str | None
    resume_stage: str | None
    retryable: bool
    external_repository_retained: bool
    mode: str | None
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "operation_id": self.operation_id,
            "operation_status": self.operation_status,
            "stage": self.stage,
            "resume_stage": self.resume_stage,
            "retryable": self.retryable,
            "external_repository_retained": self.external_repository_retained,
            "mode": self.mode,
            "reason_codes": list(self.reason_codes),
        }


def inspect_setup_operation_recovery(runtime_value: Path | str) -> SetupOperationRecovery:
    """Return the newest validated knowledge-setup resume point without mutation."""

    from .knowledge_setup import KnowledgeSetupError, load_operation_receipt

    if isinstance(runtime_value, bool) or not isinstance(runtime_value, (Path, str)) or not str(runtime_value):
        raise ValueError("RUNTIME_ROOT_INVALID")
    try:
        runtime_raw = assert_no_reparse_components(absolute_path(runtime_value))
        runtime = canonical_path(runtime_raw)
        if runtime.exists():
            assert_safe_target(runtime, runtime, allow_root=True, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("RUNTIME_ROOT_INVALID") from exc
    if not runtime.is_absolute() or runtime == Path(runtime.anchor):
        raise ValueError("RUNTIME_ROOT_INVALID")
    directory = runtime / "setup-operations"
    if not directory.is_dir():
        return SetupOperationRecovery("clean", None, None, None, None, False, False, None)
    try:
        assert_safe_target(runtime, directory, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise ValueError("RUNTIME_ROOT_INVALID") from exc
    receipts: list[tuple[str, Path, Mapping[str, Any]]] = []
    invalid = 0
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        if path.name.endswith(".staging-ownership.json"):
            continue
        try:
            receipt = load_operation_receipt(path, runtime_root=runtime)
        except (KnowledgeSetupError, SafeFilesystemError, OSError, ValueError):
            invalid += 1
            continue
        receipts.append((str(receipt.get("updated_at", "")), path, receipt))
    if not receipts:
        reasons = ("SETUP_OPERATION_RECEIPT_INVALID",) if invalid else ()
        return SetupOperationRecovery("clean", None, None, None, None, False, False, None, reasons)
    _, path, receipt = max(receipts, key=lambda item: (item[0], item[1].name))
    recovery = receipt.get("recovery") if isinstance(receipt.get("recovery"), Mapping) else {}
    retryable = recovery.get("retryable") is True
    operation_status = str(receipt.get("status"))
    if operation_status == "COMPLETE":
        status = "complete"
    elif retryable:
        status = "retry_available"
    elif operation_status == "BLOCKED":
        status = "blocked"
    else:
        status = "incomplete"
    errors = receipt.get("errors") if isinstance(receipt.get("errors"), list) else []
    reason_codes = sorted(
        {
            str(item.get("code"))
            for item in errors
            if isinstance(item, Mapping) and isinstance(item.get("code"), str) and item.get("code")
        }
    )
    if invalid:
        reason_codes.append("SETUP_OPERATION_RECEIPT_INVALID")
    return SetupOperationRecovery(
        status=status,
        operation_id=path.stem,
        operation_status=operation_status,
        stage=str(receipt.get("stage")),
        resume_stage=str(recovery.get("resume_stage")) if retryable and recovery.get("resume_stage") is not None else None,
        retryable=retryable,
        external_repository_retained=recovery.get("external_repository_retained") is True,
        mode=str(receipt.get("mode")),
        reason_codes=tuple(dict.fromkeys(reason_codes)),
    )


def _migration_recovery_roots(destination_value: Path | str, runtime_value: Path | str) -> tuple[Path, Path]:
    from .migrate import _canonical_migration_root, _has_reparse_component

    destination = _canonical_migration_root(destination_value)
    runtime = _canonical_migration_root(runtime_value)
    if destination == runtime or destination.is_relative_to(runtime) or runtime.is_relative_to(destination):
        raise ValueError("MIGRATION_ROOTS_OVERLAP")
    if _has_reparse_component(destination.parent) or _has_reparse_component(runtime):
        raise ValueError("UNSAFE_REPARSE_POINT")
    return destination, runtime


def inspect_root_migration_recovery(destination_value: Path | str, runtime_value: Path | str) -> RootMigrationRecovery:
    """Inspect abandoned root-migration staging without deleting anything."""
    from .migrate import _is_reparse

    destination, runtime = _migration_recovery_roots(destination_value, runtime_value)
    parent = destination.parent
    prefix = f".{destination.name}.migration-"
    staging: list[str] = []
    if parent.is_dir():
        for entry in sorted(parent.iterdir(), key=lambda item: item.name):
            if not entry.name.startswith(prefix):
                continue
            suffix = entry.name[len(prefix):]
            if not re.fullmatch(r"[0-9a-f]{64}-[0-9a-f]{32}", suffix):
                continue
            if _is_reparse(entry):
                raise ValueError("UNSAFE_REPARSE_POINT")
            if not entry.is_dir():
                raise ValueError("MIGRATION_STAGING_INVALID")
            for child in entry.rglob("*"):
                if _is_reparse(child):
                    raise ValueError("UNSAFE_REPARSE_POINT")
            staging.append(entry.name)
    migration_dir = runtime / "migration"
    receipts: list[str] = []
    if migration_dir.is_dir():
        for entry in sorted(migration_dir.glob("*.json"), key=lambda item: item.name):
            if _is_reparse(entry):
                raise ValueError("UNSAFE_REPARSE_POINT")
            receipts.append(entry.name)
    status = "staging_recovery_required" if staging else "clean"
    reasons = ("ABANDONED_MIGRATION_STAGING",) if staging else ()
    return RootMigrationRecovery(status, destination, runtime, tuple(staging), tuple(receipts), reasons)


def recover_root_migration_staging(
    destination_value: Path | str,
    runtime_value: Path | str,
    plan_hash: str,
    *,
    confirm: bool = False,
) -> RootMigrationRecovery:
    """Remove only staging owned by the exact plan after explicit confirmation."""
    from .migrate import _is_reparse

    if not isinstance(plan_hash, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", plan_hash):
        raise ValueError("MIGRATION_PLAN_HASH_INVALID")
    if confirm is not True:
        raise ValueError("MIGRATION_RECOVERY_CONFIRMATION_REQUIRED")
    before = inspect_root_migration_recovery(destination_value, runtime_value)
    prefix = f".{before.destination_root.name}.migration-{plan_hash.removeprefix('sha256:')}-"
    for name in before.staging_names:
        if not name.startswith(prefix):
            continue
        target = before.destination_root.parent / name
        if _is_reparse(target) or not target.is_dir():
            raise ValueError("MIGRATION_STAGING_INVALID")
        for child in target.rglob("*"):
            if _is_reparse(child):
                raise ValueError("UNSAFE_REPARSE_POINT")
        try:
            safe_remove_tree(before.destination_root.parent, target, allow_missing=False)
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
    return inspect_root_migration_recovery(before.destination_root, before.runtime_root)


def _cursor_value(cursor: SourceCursor | Mapping[str, Any] | None) -> SourceCursor | None:
    if cursor is None:
        return None
    if isinstance(cursor, SourceCursor):
        return cursor
    if isinstance(cursor, Mapping):
        try:
            return SourceCursor.from_mapping(cursor)
        except ValueError:
            return None
    return None


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _read_jsonl(path: Path) -> tuple[list[Mapping[str, Any]], int]:
    if not path.exists():
        return [], 0
    rows: list[Mapping[str, Any]] = []
    invalid = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return [], 1
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeError):
            invalid += 1
            continue
        if isinstance(value, Mapping):
            rows.append(value)
        else:
            invalid += 1
    return rows, invalid


def _known_recovery_fingerprints(settings: Any) -> set[str]:
    root = Path(settings.paths.event_dir)
    if not root.exists():
        return set()
    known: set[str] = set()
    for event in iter_events(root):
        if event.event_type != "capture.fallback_recovered":
            continue
        value = event.payload.get("observation_fingerprint") or event.payload.get("source_hash")
        if isinstance(value, str) and value:
            known.add(value)
    return known


def _write_result(settings: Any, result: RecoveryResult) -> None:
    path = Path(settings.paths.runtime_dir) / "recovery-health.json"
    try:
        safe_ensure_directory(path.parent)
        safe_atomic_write(path.parent, path, (json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc


def reconcile_orphans(host_id: str, cursor: SourceCursor | Mapping[str, Any] | None, settings: Any) -> RecoveryResult:
    if not isinstance(host_id, str) or not host_id:
        result = RecoveryResult(0, 1, 0, True, reason_codes=("HOST_ID_INVALID",))
        _write_result(settings, result)
        return result
    source_cursor = _cursor_value(cursor)
    rows, invalid = _read_jsonl(Path(settings.paths.local_state_dir) / "orphan-sources.jsonl")
    receipts, receipt_invalid = _read_jsonl(Path(settings.paths.runtime_dir) / "hook-receipts.jsonl")
    known = _known_recovery_fingerprints(settings)
    recovered = 0
    parse_deferred = invalid + receipt_invalid
    policy_excluded = 0
    duplicate = 0
    reasons: set[str] = set()
    for row in rows:
        row_host = row.get("host_id")
        if row_host not in {None, host_id}:
            continue
        source_hash = row.get("source_hash")
        source_ref_hash = row.get("source_ref_hash")
        if not isinstance(source_hash, str) or not source_hash:
            parse_deferred += 1
            reasons.add("parse_deferred")
            continue
        if source_cursor is not None and source_hash == source_cursor.content_hash:
            duplicate += 1
            continue
        classification = row.get("classification", "private-reusable")
        source_kind = row.get("source_kind", classification)
        if not isinstance(classification, str) or not isinstance(source_kind, str):
            parse_deferred += 1
            reasons.add("parse_deferred")
            continue
        decision = inspect_text("", source_kind, str(source_ref_hash or "recovery-source"))
        if decision.classification.value in {"secret", "machine-local", "client-confidential", "external-reference"} or not decision.allow_private_sync:
            policy_excluded += 1
            reasons.add("policy_excluded")
            continue
        fingerprint = source_hash
        if fingerprint in known:
            duplicate += 1
            continue
        occurred_at = row.get("observed_at")
        parsed_occurred_at = datetime.now(timezone.utc)
        if not isinstance(occurred_at, str):
            occurred_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        else:
            try:
                parsed_occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError):
                parse_deferred += 1
                reasons.add("parse_deferred")
                continue
            if parsed_occurred_at.tzinfo is None or parsed_occurred_at.utcoffset() is None:
                parse_deferred += 1
                reasons.add("parse_deferred")
                continue
        event = Event.create_v2(
            event_type="capture.fallback_recovered",
            actor=f"recovery:{host_id}",
            machine_id=machine_id(),
            payload={
                "observation_fingerprint": fingerprint,
                "source_hash": fingerprint,
                "source_ref_hash": str(source_ref_hash or _hash(str(row.get("source_ref", "")))),
                "classification": decision.classification.value,
                "capture_path": "fallback",
                "host_id": host_id,
            },
            occurred_at=parsed_occurred_at,
        )
        try:
            append_event(event, settings.paths.event_dir)
        except (OSError, ValueError, RuntimeError):
            parse_deferred += 1
            reasons.add("append_deferred")
            continue
        known.add(fingerprint)
        recovered += 1
    unclosed_sessions: set[str] = set()
    closed_sessions: set[str] = set()
    for receipt in receipts:
        if receipt.get("host_id") != host_id:
            continue
        session = receipt.get("session_id_hash")
        if not isinstance(session, str) or not session:
            continue
        if receipt.get("normalized_event_name") == "session.end":
            closed_sessions.add(session)
        else:
            unclosed_sessions.add(session)
    unclosed_sessions.difference_update(closed_sessions)
    coverage_unknown = bool(unclosed_sessions) and not rows
    if coverage_unknown:
        reasons.add("capture_coverage_unknown")
    if parse_deferred:
        reasons.add("parse_deferred")
    if policy_excluded:
        reasons.add("policy_excluded")
    result = RecoveryResult(recovered, parse_deferred, policy_excluded, coverage_unknown, duplicate, tuple(sorted(reasons)))
    _write_result(settings, result)
    return result


__all__ = [
    "RecoveryResult",
    "RootMigrationRecovery",
    "SetupOperationRecovery",
    "inspect_setup_operation_recovery",
    "inspect_root_migration_recovery",
    "recover_root_migration_staging",
    "reconcile_orphans",
]
