from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .adapters.base import SourceRecord
from .adapters.codex_memory import CodexMemoryAdapter
from .adapters.rollout_summary import RolloutSummaryAdapter
from .cluster import assign_cluster
from .config import Settings
from .dedup import content_fingerprint
from .ids import fingerprint, machine_id, stable_hash
from .inventory import SourceInventory, authorized_migration_files, inventory_existing_state
from .journal import append_event, iter_events
from .models import Event, ObservationInput, ObservationState, validate_host_applicability_mapping
from .privacy import inspect_observation, inspect_text
from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_safe_target,
    canonical_path,
    create_ownership_record,
    read_ownership_record,
    safe_atomic_write,
    safe_copy_file,
    safe_ensure_directory,
    safe_move,
    safe_remove_tree,
    safe_unlink,
    tree_digest,
    validate_ownership_record,
    write_ownership_record,
)


_IMPORTABLE_DISPOSITIONS = frozenset({"imported", "referenced_only"})
_EXTERNAL_KINDS = frozenset({"external_article_copy", "skill_instruction"})
_POLICY_KINDS = frozenset({"policy_provenance"})
_SOURCE_SUFFIXES = frozenset({".md", ".jsonl"})
_FULL_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def _persisted_hash(value: str) -> str:
    if not value:
        return ""
    return value if _FULL_HASH.fullmatch(value) else fingerprint(value)


@dataclass(frozen=True)
class MigrationItem:
    source_path: Path
    source_hash: str
    record: SourceRecord
    record_fingerprint: str
    terminal_disposition: str = "imported"


@dataclass(frozen=True)
class MigrationPlan:
    source_root: Path
    settings: Settings
    items: tuple[MigrationItem, ...]
    source_hashes: Mapping[str, str]
    plan_hash: str
    inventory: SourceInventory | None = None
    source_roots: tuple[Path, ...] = ()


@dataclass(frozen=True)
class MigrationResult:
    plan_hash: str
    imported: int
    skipped: int
    duplicates: int
    external_references: int
    secret_rejected: int
    cluster_provenances: dict[str, tuple[str, ...]] = field(default_factory=dict)
    inventory_hash: str | None = None
    policy_provenance: int = 0
    resumed: bool = False
    checkpoint_path: Path | None = None
    rollback_manifest_path: Path | None = None
    status: str = "complete"


@dataclass(frozen=True)
class RootMigrationFile:
    relative_path: str
    sha256: str
    size: int
    mode: int
    category: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "category": self.category,
        }


@dataclass(frozen=True)
class RootMigrationPlan:
    source_root: Path
    destination_root: Path
    runtime_root: Path
    files: tuple[RootMigrationFile, ...]
    event_ids: tuple[str, ...]
    policy_version: str
    source_tree_digest: str
    plan_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "source_root": str(self.source_root),
            "destination_root": str(self.destination_root),
            "runtime_root": str(self.runtime_root),
            "files": [item.to_dict() for item in self.files],
            "event_ids": list(self.event_ids),
            "policy_version": self.policy_version,
            "source_tree_digest": self.source_tree_digest,
            "plan_hash": self.plan_hash,
        }


@dataclass(frozen=True)
class RootMigrationResult:
    plan_hash: str
    status: str
    destination_root: Path
    receipt_path: Path | None = None
    copied_files: int = 0
    destination_tree_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_hash": self.plan_hash,
            "status": self.status,
            "destination_root": str(self.destination_root),
            "receipt_path": str(self.receipt_path) if self.receipt_path else None,
            "copied_files": self.copied_files,
            "destination_tree_digest": self.destination_tree_digest,
        }


_BULLET = re.compile(r"^\s*[-*+]\s+(?P<text>\S.*)$")
_HEADING = re.compile(r"^\s*#{1,6}\s+(?P<text>\S.*)$")


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_fp(record: SourceRecord) -> str:
    return "sha256:" + stable_hash(
        "\x1e".join(
            (
                record.source_kind,
                record.title,
                record.claim,
                record.cwd,
                record.domain,
                record.benefit,
                record.classification,
                "\x1f".join(record.applicability),
                record.source_host_id,
                record.source_host_family,
            )
        )
    )


def _classify_record(record: SourceRecord, source: Path) -> SourceRecord:
    claim = record.claim.replace("[external_article_copy]", "").strip()
    source_name = source.name.casefold()
    external = (
        record.classification.casefold() in {"external-reference", "external_reference"}
        or record.source_kind == "external_article_copy"
        or "article" in source_name
        or "[external_article_copy]" in record.claim.casefold()
    )
    if external:
        return SourceRecord(
            **{
                **record.__dict__,
                "source_kind": "external_article_copy",
                "classification": "external-reference",
                "claim": claim,
            }
        )
    return SourceRecord(**{**record.__dict__, "claim": claim})


def _pattern_records(source: Path) -> Iterable[SourceRecord]:
    content = source.read_bytes()
    source_hash = hashlib.sha256(content).hexdigest()
    observed_at = datetime.fromtimestamp(source.stat().st_mtime, timezone.utc).isoformat()
    policy_file = source.name.casefold() in {
        "promotion-criteria.md",
        "retention-policy.md",
        "privacy-policy.md",
        "retrieval-policy.md",
    }
    domain = "policy" if policy_file else source.parent.name or "patterns"
    source_kind = "policy_provenance" if policy_file else "pattern_evidence"
    for line_number, line in enumerate(content.decode("utf-8", errors="strict").splitlines(), start=1):
        heading = _HEADING.match(line)
        if heading:
            continue
        bullet = _BULLET.match(line)
        if not bullet:
            continue
        claim = bullet.group("text").strip()
        if not claim:
            continue
        yield SourceRecord(
            source_kind=source_kind,
            source_ref=str(source.resolve()),
            source_hash=source_hash,
            observed_at=observed_at,
            title=f"{source.stem}:{line_number}",
            claim=claim,
            cwd="",
            domain=domain,
            outcome_status="success",
            benefit="discovered_structure" if not policy_file else "",
            classification="private-reusable",
            applicability=(domain,),
            provenance_key=f"pattern:{source_hash}",
        )


def _iter_source_records(source: Path) -> Iterable[SourceRecord]:
    if source.suffix.casefold() == ".jsonl":
        yield from RolloutSummaryAdapter([source]).iter_records({})
        return
    if "patterns" in {part.casefold() for part in source.parts}:
        yield from _pattern_records(source)
        return
    yield from CodexMemoryAdapter([source]).iter_records({})


def _record_scope(record: SourceRecord) -> dict[str, Any] | None:
    if not record.source_host_id or not record.source_host_family:
        return None
    try:
        scope = validate_host_applicability_mapping(
            {
                "source_host_id": record.source_host_id,
                "source_host_family": record.source_host_family,
                "applicability_scope": "host",
                "applicable_host_ids": [record.source_host_id],
                "applicable_host_families": [],
            },
            require_source_pair=True,
        )
    except ValueError:
        return None
    return {
        "source_host_id": record.source_host_id,
        "source_host_family": record.source_host_family,
        "applicability_scope": scope.scope,
        "applicable_host_ids": list(scope.host_ids),
        "applicable_host_families": list(scope.host_families),
    }


def _source_key(root_index: int, root_count: int, source: Path, root: Path) -> str:
    relative = source.relative_to(root).as_posix()
    return relative if root_count == 1 else f"{root_index}:{relative}"


def _source_root_for_path(path: Path, roots: tuple[Path, ...]) -> tuple[int, Path] | None:
    for index, root in enumerate(roots):
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return index, root
    return None


def _source_files(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and ".git" not in {part.casefold() for part in path.relative_to(root).parts}
    ]


def _plan_from_inventory(inventory: SourceInventory, settings: Settings) -> MigrationPlan:
    if not isinstance(inventory, SourceInventory):
        raise ValueError("MIGRATION_INVENTORY_INVALID")
    roots = tuple(Path(root).resolve() for root in inventory.source_roots)
    if not roots:
        raise ValueError("MIGRATION_SOURCE_ROOT_UNAVAILABLE")
    source_hashes: dict[str, str] = {}
    row_by_path: dict[Path, Any] = {}
    root_hash_to_index = {value: index for index, value in enumerate(inventory.source_root_hashes)}
    for row in inventory.rows:
        path = row.source_path
        if path is None:
            continue
        source_root_info = _source_root_for_path(path, roots)
        if source_root_info is None:
            continue
        root_index, root = source_root_info
        key = _source_key(root_index, len(roots), path, root)
        if path.is_file():
            source_hashes[key] = row.content_hash
        row_by_path[path.resolve()] = row

    items: list[MigrationItem] = []
    visited: set[Path] = set()
    for path in sorted(row_by_path):
        row = row_by_path[path]
        if path in visited or row.disposition not in _IMPORTABLE_DISPOSITIONS:
            continue
        if row.source_kind in {"skill_instruction", "sqlite_schema_metadata"}:
            continue
        if path.suffix.casefold() not in _SOURCE_SUFFIXES:
            continue
        source_root_info = _source_root_for_path(path, roots)
        if source_root_info is None:
            continue
        root_index, root = source_root_info
        source_key = _source_key(root_index, len(roots), path, root)
        try:
            records = list(_iter_source_records(path))
        except (OSError, UnicodeError, ValueError):
            records = []
        if not records and row.source_kind == "external_article_copy":
            records = [
                SourceRecord(
                    source_kind="external_article_copy",
                    source_ref=source_key,
                    source_hash=row.content_hash,
                    observed_at=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                    title=path.stem,
                    claim="External reference retained outside the user baseline.",
                    cwd=path.parent.relative_to(root).as_posix() if path.parent != root else "global",
                    domain="external-reference",
                    outcome_status="unknown",
                    benefit="reference_only",
                    classification="external-reference",
                    applicability=("external-reference",),
                    provenance_key=f"external:{row.content_hash}",
                )
            ]
        for record in records:
            scoped = SourceRecord(
                **{
                    **record.__dict__,
                    "source_ref": source_key,
                    "cwd": path.parent.relative_to(root).as_posix() if path.parent != root else "global",
                    "domain": path.parent.name or record.domain,
                    "provenance_key": record.provenance_key or f"migration:{row.content_hash}",
                }
            )
            classified = _classify_record(scoped, path)
            items.append(
                MigrationItem(
                    path,
                    row.content_hash,
                    classified,
                    _record_fp(classified),
                    row.disposition,
                )
            )
        visited.add(path)

    plan_material = {
        "schema_version": 2,
        "source_root_hashes": list(inventory.source_root_hashes),
        "source_hashes": dict(sorted(source_hashes.items())),
        "items": [item.record_fingerprint for item in items],
        "inventory_hash": inventory.inventory_hash,
    }
    plan_hash = hashlib.sha256(
        json.dumps(plan_material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return MigrationPlan(roots[0], settings, tuple(items), dict(sorted(source_hashes.items())), plan_hash, inventory, roots)


def plan_migration(
    inventory_or_source: SourceInventory | Path | str,
    settings: Settings,
    *,
    allow_global_source: bool = False,
) -> MigrationPlan:
    if isinstance(inventory_or_source, SourceInventory):
        return _plan_from_inventory(inventory_or_source, settings)
    root = Path(inventory_or_source).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("MIGRATION_SOURCE_ROOT_INVALID")
    inventory = inventory_existing_state(
        (root,),
        settings,
        allow_global_source=allow_global_source,
    )
    return _plan_from_inventory(inventory, settings)


def _verify_sources(plan: MigrationPlan) -> None:
    roots = tuple(plan.source_roots) or (plan.source_root,)
    for key, expected in plan.source_hashes.items():
        if len(roots) == 1 or ":" not in key:
            root_index = 0
            relative = key
        else:
            prefix, relative = key.split(":", 1)
            try:
                root_index = int(prefix)
            except ValueError as exc:
                raise ValueError("MIGRATION_PLAN_SOURCE_KEY_INVALID") from exc
        if root_index < 0 or root_index >= len(roots) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("MIGRATION_PLAN_SOURCE_KEY_INVALID")
        source = roots[root_index] / relative
        if not source.is_file() or source.is_symlink() or _file_hash(source) != expected:
            raise ValueError("MIGRATION_SOURCE_CHANGED")


def _existing_record_fingerprints(settings: Settings, event_type: str = "observation.recorded") -> set[str]:
    event_dir = settings.paths.event_dir
    if not event_dir.exists():
        return set()
    return {
        str(event.payload["record_fingerprint"])
        for event in iter_events(event_dir)
        if event.event_type == event_type and event.payload.get("record_fingerprint")
    }


def _event(record: SourceRecord, record_fp: str) -> Event:
    observation_id = "obs_" + record_fp.removeprefix("sha256:")[:24]
    payload = {
        "observation_id": observation_id,
        "title": record.title,
        "claim": record.claim,
        "source_kind": record.source_kind,
        "source_ref_hash": fingerprint(record.source_ref),
        "source_hash": _persisted_hash(record.source_hash),
        "cwd_fingerprint": fingerprint(record.cwd),
        "domain": record.domain,
        "outcome_status": record.outcome_status,
        "benefit": record.benefit,
        "classification": record.classification,
        "applicability": list(record.applicability),
        "provenance_key": record.provenance_key,
        "record_fingerprint": record_fp,
        "migration": True,
    }
    scope = _record_scope(record)
    if scope is not None:
        payload.update(scope)
    return Event.create("observation.recorded", record.observed_at, "migration", machine_id(), payload)


def _reference_event(record: SourceRecord, record_fp: str) -> Event:
    payload = {
        "title": record.title,
        "source_kind": "external_article_copy",
        "source_ref_hash": fingerprint(record.source_ref),
        "source_hash": _persisted_hash(record.source_hash),
        "classification": "external-reference",
        "provenance_key": record.provenance_key,
        "record_fingerprint": record_fp,
        "migration": True,
    }
    scope = _record_scope(record)
    if scope is not None:
        payload.update(scope)
    return Event.create("source.reference.recorded", record.observed_at, "migration", machine_id(), payload)


def _policy_event(record: SourceRecord, record_fp: str) -> Event:
    payload = {
        "title": record.title,
        "claim": record.claim,
        "source_kind": "policy_provenance",
        "source_ref_hash": fingerprint(record.source_ref),
        "source_hash": _persisted_hash(record.source_hash),
        "provenance_key": record.provenance_key,
        "record_fingerprint": record_fp,
        "migration": True,
        "status_is_not_evidence": True,
    }
    scope = _record_scope(record)
    if scope is not None:
        payload.update(scope)
    return Event.create("policy.provenance.recorded", record.observed_at, "migration", machine_id(), payload)


def _migration_dir(settings: Settings) -> Path:
    directory = settings.paths.local_state_dir / "migration"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> Path:
    path = absolute_path(path)
    try:
        safe_ensure_directory(path.parent)
        safe_atomic_write(path.parent, path, (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    return path


def _checkpoint_paths(plan: MigrationPlan) -> tuple[Path, Path]:
    directory = _migration_dir(plan.settings)
    return directory / f"{plan.plan_hash}.json", directory / f"{plan.plan_hash}.rollback.json"


def _load_checkpoint(path: Path, plan: MigrationPlan) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": 1,
            "plan_hash": plan.plan_hash,
            "status": "in_progress",
            "next_index": 0,
            "completed_fingerprints": [],
            "event_ids": [],
            "source_hash_digest": stable_hash(dict(sorted(plan.source_hashes.items()))),
        }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("MIGRATION_CHECKPOINT_INVALID") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("plan_hash") != plan.plan_hash
        or not isinstance(value.get("completed_fingerprints"), list)
        or not isinstance(value.get("event_ids"), list)
    ):
        raise ValueError("MIGRATION_CHECKPOINT_INVALID")
    return value


def _write_rollback(path: Path, plan: MigrationPlan, event_ids: Iterable[str], status: str) -> None:
    _write_json_atomic(
        path,
        {
            "schema_version": 1,
            "plan_hash": plan.plan_hash,
            "status": status,
            "event_count": len(tuple(event_ids)),
            "event_ids": list(event_ids),
            "source_hash_digest": stable_hash(dict(sorted(plan.source_hashes.items()))),
        },
    )


def _validate_inventory_for_apply(inventory: SourceInventory) -> None:
    if not inventory.balance_holds or inventory.unclassified != 0:
        raise ValueError("MIGRATION_INVENTORY_INCOMPLETE")
    if not inventory.privacy_scan_complete:
        raise ValueError("MIGRATION_PRIVACY_SCAN_INCOMPLETE")
    if inventory.historical_pending_review:
        raise ValueError("MIGRATION_HISTORICAL_REVIEW_REQUIRED")


def _duplicate_observation_count(observations: list[ObservationState]) -> int:
    count = 0
    for index, observation in enumerate(observations):
        decision = assign_cluster(observation, observations[:index])
        if decision.kind in {"duplicate", "join"}:
            count += 1
    return count

def _cluster_provenances(observations: list[ObservationState]) -> dict[str, tuple[str, ...]]:
    clusters: dict[str, set[str]] = {}
    for index, observation in enumerate(observations):
        decision = assign_cluster(observation, observations[:index])
        cluster_id = "cluster_" + content_fingerprint(observation.claim)[:20]
        if decision.kind in {"duplicate", "join"}:
            clusters.setdefault(cluster_id, set()).add(observation.provenance_key)
        else:
            clusters.setdefault(cluster_id, set()).add(observation.provenance_key)
    return {key: tuple(sorted(values)) for key, values in sorted(clusters.items())}


def execute_migration(
    plan: MigrationPlan,
    inventory: SourceInventory | None = None,
    settings: Settings | None = None,
) -> MigrationResult:
    active_settings = settings or plan.settings
    active_inventory = inventory or plan.inventory
    if active_inventory is None:
        raise ValueError("MIGRATION_INVENTORY_REQUIRED")
    if plan.inventory is not None and active_inventory.inventory_hash != plan.inventory.inventory_hash:
        raise ValueError("MIGRATION_INVENTORY_HASH_MISMATCH")
    _validate_inventory_for_apply(active_inventory)
    _verify_sources(plan)

    checkpoint_path, rollback_path = _checkpoint_paths(
        MigrationPlan(
            plan.source_root,
            active_settings,
            plan.items,
            plan.source_hashes,
            plan.plan_hash,
            plan.inventory,
            plan.source_roots,
        )
    )
    checkpoint = _load_checkpoint(checkpoint_path, plan)
    resumed = bool(checkpoint.get("completed_fingerprints")) or checkpoint.get("status") != "in_progress"
    completed = {str(value) for value in checkpoint.get("completed_fingerprints", []) if isinstance(value, str)}
    event_ids = [str(value) for value in checkpoint.get("event_ids", []) if isinstance(value, str)]
    _write_rollback(rollback_path, plan, event_ids, "in_progress")
    checkpoint["status"] = "in_progress"
    checkpoint["source_hash_digest"] = stable_hash(dict(sorted(plan.source_hashes.items())))
    _write_json_atomic(checkpoint_path, checkpoint)

    existing_observations = _existing_record_fingerprints(active_settings)
    existing_references = _existing_record_fingerprints(active_settings, "source.reference.recorded")
    existing_policies = _existing_record_fingerprints(active_settings, "policy.provenance.recorded")
    imported = 0
    skipped = 0
    duplicates = sum(1 for row in active_inventory.rows if row.disposition == "duplicate" or row.reason_code == "DUPLICATE_CONTENT")
    external_references = 0
    secret_rejected = sum(1 for row in active_inventory.rows if row.disposition == "rejected_secret")
    policy_provenance = 0
    observations: list[ObservationState] = []

    for index, item in enumerate(plan.items):
        checkpoint["next_index"] = index
        _write_json_atomic(checkpoint_path, checkpoint)
        if item.record_fingerprint in completed:
            continue
        record = item.record
        scope = _record_scope(record)
        # Legacy migration inputs do not carry a trusted source identity.  Do
        # not invent the current work host (or silently universalize the
        # record); mark the item complete without appending an event.
        if scope is None and not (
            record.source_kind in _EXTERNAL_KINDS
            or record.classification.casefold() in {"external-reference", "external_reference"}
        ):
            skipped += 1
            completed.add(item.record_fingerprint)
            checkpoint["completed_fingerprints"] = sorted(completed)
            checkpoint["next_index"] = index + 1
            _write_json_atomic(checkpoint_path, checkpoint)
            _write_rollback(rollback_path, plan, event_ids, "in_progress")
            continue
        if record.source_kind in _EXTERNAL_KINDS or record.classification.casefold() in {"external-reference", "external_reference"}:
            secret_check = inspect_text(record.claim, "private-reusable", record.source_ref)
            if secret_check.reason_code == "SECRET_PATTERN_MATCH":
                secret_rejected += 1
                skipped += 1
            elif item.record_fingerprint in existing_references:
                skipped += 1
            else:
                event = _reference_event(record, item.record_fingerprint)
                append_event(event, active_settings.paths.event_dir)
                existing_references.add(item.record_fingerprint)
                event_ids.append(event.event_id)
                external_references += 1
        elif record.source_kind in _POLICY_KINDS:
            observation = ObservationInput(
                record.title,
                record.claim,
                record.source_kind,
                record.source_ref,
                record.cwd,
                record.domain,
                record.outcome_status,
                record.benefit,
                record.classification,
                record.applicability,
                scope["source_host_id"],
                scope["source_host_family"],
                scope["applicability_scope"],
                tuple(scope["applicable_host_ids"]),
                tuple(scope["applicable_host_families"]),
            )
            decision = inspect_observation(observation)
            if not decision.allow_private_sync:
                skipped += 1
                if decision.reason_code == "SECRET_PATTERN_MATCH":
                    secret_rejected += 1
            elif item.record_fingerprint in existing_policies:
                skipped += 1
            else:
                event = _policy_event(record, item.record_fingerprint)
                append_event(event, active_settings.paths.event_dir)
                existing_policies.add(item.record_fingerprint)
                event_ids.append(event.event_id)
                policy_provenance += 1
        else:
            observation_input = ObservationInput(
                record.title,
                record.claim,
                record.source_kind,
                record.source_ref,
                record.cwd,
                record.domain,
                record.outcome_status,
                record.benefit,
                record.classification,
                record.applicability,
                scope["source_host_id"],
                scope["source_host_family"],
                scope["applicability_scope"],
                tuple(scope["applicable_host_ids"]),
                tuple(scope["applicable_host_families"]),
            )
            decision = inspect_observation(observation_input)
            if not decision.allow_private_sync:
                skipped += 1
                if decision.reason_code == "SECRET_PATTERN_MATCH":
                    secret_rejected += 1
            elif item.record_fingerprint in existing_observations:
                skipped += 1
                duplicates += 1
            else:
                event = _event(record, item.record_fingerprint)
                append_event(event, active_settings.paths.event_dir)
                existing_observations.add(item.record_fingerprint)
                event_ids.append(event.event_id)
                imported += 1
            observations.append(
                ObservationState(
                    "obs_" + item.record_fingerprint.removeprefix("sha256:")[:24],
                    record.title,
                    record.claim,
                    record.domain,
                    fingerprint(record.cwd),
                    record.provenance_key,
                    record.outcome_status,
                    record.benefit,
                    record.classification,
                    _persisted_hash(record.source_hash),
                    record.applicability,
                    applicability_scope=scope["applicability_scope"],
                    applicable_host_ids=tuple(scope["applicable_host_ids"]),
                    applicable_host_families=tuple(scope["applicable_host_families"]),
                    source_host_id=scope["source_host_id"],
                    source_host_family=scope["source_host_family"],
                )
            )
        completed.add(item.record_fingerprint)
        checkpoint["completed_fingerprints"] = sorted(completed)
        checkpoint["event_ids"] = list(event_ids)
        checkpoint["next_index"] = index + 1
        _write_json_atomic(checkpoint_path, checkpoint)
        _write_rollback(rollback_path, plan, event_ids, "in_progress")

    checkpoint["status"] = "complete"
    checkpoint["next_index"] = len(plan.items)
    checkpoint["completed_fingerprints"] = sorted(completed)
    checkpoint["event_ids"] = list(event_ids)
    _write_json_atomic(checkpoint_path, checkpoint)
    _write_rollback(rollback_path, plan, event_ids, "complete")
    duplicates += _duplicate_observation_count(observations)
    return MigrationResult(
        plan.plan_hash,
        imported,
        skipped,
        duplicates,
        external_references,
        secret_rejected,
        _cluster_provenances(observations),
        active_inventory.inventory_hash,
        policy_provenance,
        resumed,
        checkpoint_path,
        rollback_path,
        "complete",
    )


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name == "nt":
        try:
            return bool(path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        except (AttributeError, OSError):
            return False
    return False


def _has_reparse_component(path: Path) -> bool:
    """Detect links/junctions in the lexical path, including missing tails."""
    candidate = Path(path).expanduser()
    current = candidate.anchor and Path(candidate.anchor) or Path()
    for part in candidate.parts[1:] if candidate.anchor else candidate.parts:
        current = current / part
        if _is_reparse(current):
            return True
    return _is_reparse(candidate) if not candidate.parts else False


def _canonical_migration_root(value: Path | str, *, require_directory: bool = False) -> Path:
    try:
        lexical = Path(value).expanduser().absolute()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("MIGRATION_ROOT_INVALID") from exc
    if _has_reparse_component(lexical):
        raise ValueError("UNSAFE_REPARSE_POINT")
    try:
        canonical = lexical.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("MIGRATION_ROOT_INVALID") from exc
    if _has_reparse_component(canonical):
        raise ValueError("UNSAFE_REPARSE_POINT")
    if require_directory and (not canonical.is_dir() or _is_reparse(canonical)):
        raise ValueError("MIGRATION_SOURCE_ROOT_INVALID")
    return canonical


def _root_migration_category(relative: str) -> str | None:
    parts = PurePosixPath(relative).parts
    if not parts:
        return None
    if relative == "knowledge-repository.json":
        return "manifest"
    if relative == ".gitignore":
        return "repository_metadata"
    if parts[0] == "events" and len(parts) >= 2 and relative.casefold().endswith(".json"):
        return "event"
    if parts[0] == "knowledge" and len(parts) >= 2 and Path(parts[-1]).suffix.casefold() in {".md", ".json"}:
        return "knowledge_projection"
    if len(parts) >= 3 and parts[0] == "policies" and parts[1] == "user-overrides":
        return "user_policy"
    if parts[0] == "experiments" and len(parts) >= 2 and Path(parts[-1]).suffix.casefold() in {".json", ".jsonl", ".md"}:
        return "experiment"
    return None


def _root_migration_files(source_root: Path) -> tuple[RootMigrationFile, ...]:
    files: list[RootMigrationFile] = []
    for relative, path, category in authorized_migration_files(source_root):
        raw = path.read_bytes()
        mode = stat.S_IMODE(path.stat().st_mode)
        files.append(RootMigrationFile(relative, hashlib.sha256(raw).hexdigest(), len(raw), mode, category))
    files.sort(key=lambda item: item.relative_path)
    return tuple(files)


def _root_migration_digest(files: Iterable[RootMigrationFile]) -> str:
    material = [item.to_dict() for item in files]
    return "sha256:" + hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _root_migration_destination_safe(source: Path, destination: Path, runtime: Path) -> None:
    roots = (("SOURCE", source), ("DESTINATION", destination), ("RUNTIME", runtime))
    for index, (name, root) in enumerate(roots):
        if _has_reparse_component(root):
            raise ValueError("UNSAFE_REPARSE_POINT")
        for other_name, other in roots[index + 1 :]:
            if root == other or root.is_relative_to(other) or other.is_relative_to(root):
                if name == "DESTINATION" or other_name == "DESTINATION":
                    raise ValueError(f"MIGRATION_DESTINATION_OVERLAPS_{other_name if name == 'DESTINATION' else name}_ROOT")
                raise ValueError("MIGRATION_ROOTS_OVERLAP")
    if destination.exists():
        raise ValueError("MIGRATION_DESTINATION_COLLISION")
    if _has_reparse_component(destination.parent):
        raise ValueError("UNSAFE_REPARSE_POINT")


def build_root_migration_plan(
    source_root_value: Path | str,
    destination_root_value: Path | str,
    runtime_root_value: Path | str,
    *,
    policy_version: str = "1",
) -> RootMigrationPlan:
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise ValueError("MIGRATION_POLICY_VERSION_INVALID")
    source_root = _canonical_migration_root(source_root_value, require_directory=True)
    destination_root = _canonical_migration_root(destination_root_value)
    runtime_root = _canonical_migration_root(runtime_root_value)
    _root_migration_destination_safe(source_root, destination_root, runtime_root)
    files = _root_migration_files(source_root)
    event_ids: list[str] = []
    event_root = source_root / "events"
    if event_root.exists():
        try:
            event_ids = [event.event_id for event in iter_events(event_root)]
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            raise ValueError("MIGRATION_EVENT_ORDER_INVALID") from exc
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("MIGRATION_DUPLICATE_EVENT_ID")
    source_tree_digest = _root_migration_digest(files)
    material = {
        "schema_version": 1,
        "source_root": str(source_root),
        "destination_root": str(destination_root),
        "runtime_root": str(runtime_root),
        "files": [item.to_dict() for item in files],
        "event_ids": event_ids,
        "policy_version": str(policy_version),
        "source_tree_digest": source_tree_digest,
    }
    plan_hash = "sha256:" + hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return RootMigrationPlan(source_root, destination_root, runtime_root, files, tuple(event_ids), str(policy_version), source_tree_digest, plan_hash)


def plan_root_migration(
    source_root_value: Path | str,
    destination_root_value: Path | str,
    runtime_root_value: Path | str,
    *,
    policy_version: str = "1",
) -> RootMigrationPlan:
    return build_root_migration_plan(source_root_value, destination_root_value, runtime_root_value, policy_version=policy_version)


def write_root_migration_plan(plan: RootMigrationPlan, path_value: Path | str) -> Path:
    if not isinstance(plan, RootMigrationPlan):
        raise ValueError("MIGRATION_PLAN_INVALID")
    return _write_json_atomic(Path(path_value).expanduser().resolve(), plan.to_dict())


def _load_root_migration_plan(path_value: Path | str) -> RootMigrationPlan:
    path = Path(path_value).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("MIGRATION_PLAN_INVALID") from exc
    required = {
        "schema_version", "source_root", "destination_root", "runtime_root", "files",
        "event_ids", "policy_version", "source_tree_digest", "plan_hash",
    }
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema_version") != 1:
        raise ValueError("MIGRATION_PLAN_INVALID")
    try:
        raw_files = value["files"]
        if not isinstance(raw_files, list) or any(not isinstance(item, Mapping) for item in raw_files):
            raise ValueError("files")
        files = tuple(
            RootMigrationFile(str(item["relative_path"]), str(item["sha256"]), int(item["size"]), int(item["mode"]), str(item["category"]))
            for item in raw_files
        )
        if tuple(sorted(files, key=lambda item: item.relative_path)) != files or len({item.relative_path for item in files}) != len(files):
            raise ValueError("file_order")
        if any(
            not item.relative_path
            or PurePosixPath(item.relative_path).is_absolute()
            or ".." in PurePosixPath(item.relative_path).parts
            or not re.fullmatch(r"[0-9a-f]{64}", item.sha256)
            or item.size < 0
            or item.mode < 0
            or item.category not in {"manifest", "repository_metadata", "event", "knowledge_projection", "user_policy", "experiment"}
            for item in files
        ):
            raise ValueError("file_record")
        raw_event_ids = value["event_ids"]
        if not isinstance(raw_event_ids, list) or any(not isinstance(item, str) or not item for item in raw_event_ids) or len(set(raw_event_ids)) != len(raw_event_ids):
            raise ValueError("event_ids")
        source_tree_digest = str(value["source_tree_digest"])
        plan_hash = str(value["plan_hash"])
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_tree_digest) or not re.fullmatch(r"sha256:[0-9a-f]{64}", plan_hash):
            raise ValueError("digest")
        plan = RootMigrationPlan(
            _canonical_migration_root(str(value["source_root"]), require_directory=True),
            _canonical_migration_root(str(value["destination_root"])),
            _canonical_migration_root(str(value["runtime_root"])),
            files,
            tuple(raw_event_ids),
            str(value["policy_version"]),
            source_tree_digest,
            plan_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("MIGRATION_PLAN_INVALID") from exc
    expected = build_root_migration_plan(plan.source_root, plan.destination_root, plan.runtime_root, policy_version=plan.policy_version)
    if expected.plan_hash != plan.plan_hash:
        raise ValueError("MIGRATION_PLAN_HASH_INVALID")
    return plan


def load_root_migration_plan(path_value: Path | str) -> RootMigrationPlan:
    return _load_root_migration_plan(path_value)


def _verify_root_migration_source(plan: RootMigrationPlan) -> None:
    current_files = _root_migration_files(plan.source_root)
    if current_files != plan.files:
        raise ValueError("MIGRATION_SOURCE_CHANGED")
    event_root = plan.source_root / "events"
    current_events = tuple(event.event_id for event in iter_events(event_root)) if event_root.exists() else ()
    if current_events != plan.event_ids:
        raise ValueError("MIGRATION_SOURCE_CHANGED")


def _directory_digest(root: Path) -> str:
    files: list[RootMigrationFile] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if _is_reparse(path):
            raise ValueError("UNSAFE_REPARSE_POINT")
        if ".git" in Path(relative).parts or path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("MIGRATION_DESTINATION_ENTRY_INVALID")
        raw = path.read_bytes()
        files.append(RootMigrationFile(relative, hashlib.sha256(raw).hexdigest(), len(raw), stat.S_IMODE(path.stat().st_mode), "destination"))
    return _root_migration_digest(files)


def _migration_receipt_path(runtime_root: Path, plan_hash: str) -> Path:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", plan_hash):
        raise ValueError("MIGRATION_PLAN_HASH_INVALID")
    return runtime_root / "migration" / (plan_hash.removeprefix("sha256:") + ".json")


def _verify_projection(root: Path) -> None:
    projection = root / "knowledge"
    manifest_path = projection / "manifest.json"
    index_path = projection / "index.json"
    if not manifest_path.is_file() or not index_path.is_file():
        raise ValueError("MIGRATION_PROJECTION_MISMATCH")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("MIGRATION_PROJECTION_MISMATCH") from exc
    files = manifest.get("files") if isinstance(manifest, Mapping) else None
    if not isinstance(files, Mapping) or not isinstance(index, Mapping) or index.get("schema_version") != 2:
        raise ValueError("MIGRATION_PROJECTION_MISMATCH")
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise ValueError("MIGRATION_PROJECTION_MISMATCH")
        target = projection / Path(*PurePosixPath(relative).parts)
        if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts or not target.is_file():
            raise ValueError("MIGRATION_PROJECTION_MISMATCH")
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash:
            raise ValueError("MIGRATION_PROJECTION_MISMATCH")


def apply_root_migration(plan: RootMigrationPlan | Path | str, *, interrupt_after_files: int | None = None) -> RootMigrationResult:
    if not isinstance(plan, RootMigrationPlan):
        plan = _load_root_migration_plan(plan)
    _verify_root_migration_source(plan)
    _root_migration_destination_safe(plan.source_root, plan.destination_root, plan.runtime_root)
    if interrupt_after_files is not None and (isinstance(interrupt_after_files, bool) or not isinstance(interrupt_after_files, int) or interrupt_after_files < 1):
        raise ValueError("MIGRATION_INTERRUPT_INVALID")
    if _has_reparse_component(plan.destination_root.parent):
        raise ValueError("UNSAFE_REPARSE_POINT")
    try:
        safe_ensure_directory(plan.destination_root.parent)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    stage = plan.destination_root.parent / (
        f".{plan.destination_root.name}.migration-"
        f"{plan.plan_hash.removeprefix('sha256:')}-{uuid.uuid4().hex}"
    )
    if stage.exists() or stage.is_symlink():
        raise ValueError("MIGRATION_STAGING_COLLISION")
    owner_path = stage.with_name(stage.name + ".ownership.json")
    if owner_path.exists() or owner_path.is_symlink():
        raise ValueError("MIGRATION_STAGING_COLLISION")
    copied = 0
    owner = create_ownership_record(plan.destination_root.parent, stage, kind="root-migration-staging")
    token = str(owner["token"])
    moved = False
    try:
        safe_ensure_directory(stage.parent)
        stage.mkdir()
        write_ownership_record(owner_path, owner, root=plan.destination_root.parent)
        for item in plan.files:
            source = plan.source_root / Path(*PurePosixPath(item.relative_path).parts)
            target = stage / Path(*PurePosixPath(item.relative_path).parts)
            if _is_reparse(source) or not source.is_file():
                raise ValueError("MIGRATION_SOURCE_CHANGED")
            safe_ensure_directory(target.parent)
            safe_copy_file(plan.source_root, source, stage, target, expected_digest="sha256:" + item.sha256, mode=item.mode)
            raw = target.read_bytes()
            if len(raw) != item.size or hashlib.sha256(raw).hexdigest() != item.sha256:
                raise ValueError("MIGRATION_COPY_VERIFY_FAILED")
            copied += 1
            if interrupt_after_files is not None and copied >= interrupt_after_files:
                raise RuntimeError("MIGRATION_INTERRUPTED")
        from .project import project_events

        event_root = stage / "events"
        project_events(iter_events(event_root), stage / "knowledge")
        _verify_projection(stage)
        destination_digest = _directory_digest(stage)
        if plan.destination_root.exists():
            raise ValueError("MIGRATION_DESTINATION_COLLISION")
        safe_move(plan.destination_root.parent, stage, plan.destination_root.parent, plan.destination_root)
        moved = True
        safe_unlink(plan.destination_root.parent, owner_path, allow_missing=False)
        receipt_path = _migration_receipt_path(plan.runtime_root, plan.plan_hash)
        receipt = {
            "schema_version": 1,
            "status": "complete",
            "plan_hash": plan.plan_hash,
            "ownership_token_hash": "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "source_root": str(plan.source_root),
            "destination_root": str(plan.destination_root),
            "runtime_root": str(plan.runtime_root),
            "source_tree_digest": plan.source_tree_digest,
            "destination_tree_digest": destination_digest,
            "copied_files": copied,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        _write_json_atomic(receipt_path, receipt)
        return RootMigrationResult(plan.plan_hash, "complete", plan.destination_root, receipt_path, copied, destination_digest)
    except Exception as exc:
        cleanup_errors: list[BaseException] = []
        try:
            validate_ownership_record(owner, plan.destination_root.parent, stage, kind="root-migration-staging")
            safe_remove_tree(plan.destination_root.parent, stage, owner=owner, kind="root-migration-staging", allow_missing=True)
        except (OSError, ValueError) as cleanup_error:
            cleanup_errors.append(cleanup_error)
        try:
            safe_unlink(plan.destination_root.parent, owner_path, allow_missing=True)
        except (OSError, ValueError) as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if moved:
            try:
                if plan.destination_root.exists():
                    safe_remove_tree(plan.destination_root.parent, plan.destination_root, expected_digest=tree_digest(plan.destination_root))
            except (OSError, ValueError) as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            raise ValueError("MIGRATION_STAGING_CLEANUP_FAILED") from cleanup_errors[0]
        raise exc


def _read_root_migration_receipt(value: RootMigrationResult | Mapping[str, Any] | Path | str) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, RootMigrationResult):
        if value.receipt_path is None:
            raise ValueError("MIGRATION_RECEIPT_REQUIRED")
        path = value.receipt_path
    elif isinstance(value, (Path, str)):
        path = absolute_path(value)
    else:
        path = None
    if path is not None:
        try:
            safe_path = assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
            path = canonical_path(safe_path, require_exists=True)
        except SafeFilesystemError as exc:
            raise ValueError("MIGRATION_RECEIPT_INVALID") from exc
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("MIGRATION_RECEIPT_INVALID") from exc
    else:
        document = dict(value)
    required = {
        "schema_version", "status", "plan_hash", "ownership_token_hash", "source_root", "destination_root",
        "runtime_root", "source_tree_digest", "destination_tree_digest", "copied_files", "created_at",
    }
    if not isinstance(document, dict) or set(document) != required or document.get("schema_version") != 1 or document.get("status") != "complete":
        raise ValueError("MIGRATION_RECEIPT_INVALID")
    for key in ("plan_hash", "ownership_token_hash", "source_tree_digest", "destination_tree_digest"):
        if not isinstance(document.get(key), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", document[key]):
            raise ValueError("MIGRATION_RECEIPT_INVALID")
    if type(document.get("copied_files")) is not int or document["copied_files"] < 0:
        raise ValueError("MIGRATION_RECEIPT_INVALID")
    collision_allowed = False
    try:
        source = _canonical_migration_root(str(document["source_root"]), require_directory=True)
        destination = _canonical_migration_root(str(document["destination_root"]))
        runtime = _canonical_migration_root(str(document["runtime_root"]))
        _root_migration_destination_safe(source, destination, runtime)
    except ValueError as exc:
        if str(exc) == "MIGRATION_DESTINATION_COLLISION":
            # A completed receipt is allowed to name an existing destination.
            collision_allowed = True
        else:
            raise ValueError("MIGRATION_RECEIPT_INVALID") from exc
    if not collision_allowed:
        destination = _canonical_migration_root(str(document["destination_root"]))
    if path is not None:
        expected_directory = runtime / "migration"
        if path.parent != expected_directory or path.name != document["plan_hash"].removeprefix("sha256:") + ".json":
            raise ValueError("MIGRATION_RECEIPT_INVALID")
    return document, path


def rollback_root_migration(
    value: RootMigrationResult | Mapping[str, Any] | Path | str,
    *,
    confirm_plan_hash: str | None = None,
) -> RootMigrationResult:
    receipt, receipt_path = _read_root_migration_receipt(value)
    if confirm_plan_hash != receipt.get("plan_hash"):
        raise ValueError("MIGRATION_ROLLBACK_CONFIRMATION_REQUIRED")
    destination = Path(str(receipt.get("destination_root", ""))).expanduser().resolve()
    source = _canonical_migration_root(str(receipt["source_root"]), require_directory=True)
    runtime = _canonical_migration_root(str(receipt["runtime_root"]))
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination) or destination == runtime or destination.is_relative_to(runtime) or runtime.is_relative_to(destination):
        raise ValueError("MIGRATION_ROLLBACK_TARGET_INVALID")
    if not destination.is_dir() or _is_reparse(destination):
        raise ValueError("MIGRATION_ROLLBACK_TARGET_INVALID")
    if _directory_digest(destination) != receipt.get("destination_tree_digest"):
        raise ValueError("MIGRATION_ROLLBACK_TARGET_CHANGED")
    try:
        expected_safe_digest = tree_digest(destination)
        safe_remove_tree(destination.parent, destination, expected_digest=expected_safe_digest)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    updated = dict(receipt)
    updated["status"] = "rolled_back"
    updated["rolled_back_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if receipt_path is not None:
        _write_json_atomic(receipt_path, updated)
    return RootMigrationResult(str(receipt.get("plan_hash")), "rolled_back", destination, receipt_path, int(receipt.get("copied_files", 0) or 0), None)


def _verify_legacy_backup(active: RootMigrationPlan, value: Path | str) -> None:
    if isinstance(value, bool):
        raise ValueError("MIGRATION_VERIFIED_BACKUP_REQUIRED")
    backup = _canonical_migration_root(value)
    if not backup.exists() or _is_reparse(backup):
        raise ValueError("MIGRATION_VERIFIED_BACKUP_REQUIRED")
    if backup.is_dir():
        if backup == active.source_root or backup.is_relative_to(active.source_root) or active.source_root.is_relative_to(backup):
            raise ValueError("MIGRATION_VERIFIED_BACKUP_INVALID")
        if _root_migration_files(backup) != active.files:
            raise ValueError("MIGRATION_VERIFIED_BACKUP_INVALID")
        return
    try:
        document = json.loads(backup.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("MIGRATION_VERIFIED_BACKUP_INVALID") from exc
    if not isinstance(document, Mapping) or document.get("verified") is not True or document.get("plan_hash") != active.plan_hash or document.get("source_tree_digest") != active.source_tree_digest:
        raise ValueError("MIGRATION_VERIFIED_BACKUP_INVALID")


def _require_completed_migration(active: RootMigrationPlan) -> None:
    receipt_path = _migration_receipt_path(active.runtime_root, active.plan_hash)
    receipt, _ = _read_root_migration_receipt(receipt_path)
    if receipt.get("plan_hash") != active.plan_hash or receipt.get("source_tree_digest") != active.source_tree_digest:
        raise ValueError("MIGRATION_RECEIPT_INVALID")
    destination = _canonical_migration_root(active.destination_root)
    if not destination.is_dir() or _directory_digest(destination) != receipt.get("destination_tree_digest"):
        raise ValueError("MIGRATION_DESTINATION_CHANGED")


def cleanup_legacy_root(plan: RootMigrationPlan | Path | str, *, confirm_plan_hash: str, verified_backup: Path | str) -> int:
    if not isinstance(confirm_plan_hash, str) or not confirm_plan_hash or confirm_plan_hash != (plan.plan_hash if isinstance(plan, RootMigrationPlan) else _load_root_migration_plan(plan).plan_hash):
        raise ValueError("MIGRATION_CLEANUP_APPROVAL_REQUIRED")
    active = plan if isinstance(plan, RootMigrationPlan) else _load_root_migration_plan(plan)
    _verify_legacy_backup(active, verified_backup)
    _require_completed_migration(active)
    _verify_root_migration_source(active)
    removed = 0
    for item in active.files:
        target = active.source_root / Path(*PurePosixPath(item.relative_path).parts)
        if not target.is_file() or _is_reparse(target):
            raise ValueError("MIGRATION_SOURCE_CHANGED")
        try:
            safe_unlink(active.source_root, target, expected_digest="sha256:" + item.sha256)
        except SafeFilesystemError as exc:
            raise ValueError(exc.code) from exc
        removed += 1
    return removed
