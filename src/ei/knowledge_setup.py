"""Deterministic planning for local and private-GitHub knowledge storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .knowledge_repository import (
    KnowledgeRepositoryError,
    bootstrap_knowledge_repository,
    inspect_knowledge_repository,
)
from .remote_assurance import remote_fingerprint
from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_no_reparse_components,
    assert_safe_target,
    canonical_path,
    create_ownership_record,
    read_ownership_record,
    safe_atomic_write,
    safe_ensure_directory,
    safe_mkdir,
    safe_move,
    safe_remove_tree,
    safe_unlink,
    validate_ownership_record,
    write_ownership_record,
)


KNOWLEDGE_MODES = frozenset({"local", "github-new", "github-existing"})
SETUP_STAGES = (
    "PLANNED",
    "KNOWLEDGE_LOCAL_READY",
    "REMOTE_CREATED_OR_VERIFIED",
    "REMOTE_CONNECTED",
    "INITIAL_PUSH_VERIFIED",
    "HOSTS_INSTALLED",
    "MANIFEST_COMMITTED",
    "DIAGNOSTICS_COMPLETE",
)

_GITHUB_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9._])?$")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INVALID_BRANCH_CHARACTERS = frozenset(" ~^:?*[\\")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_OPERATION_STATUSES = frozenset({"IN_PROGRESS", "COMPLETE", "BLOCKED", "FAILED"})
_REPOSITORY_STATUSES = frozenset({"NOT_READY", "CREATED", "RESTORED", "ALREADY_CURRENT"})
_REMOTE_CLASSIFICATIONS = frozenset({"private_verified", "private_attested", "local_path"})
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "plan_digest",
        "status",
        "stage",
        "mode",
        "completed_actions",
        "started_at",
        "updated_at",
        "completed_at",
        "repository",
        "remote",
        "recovery",
        "errors",
    }
)


class KnowledgeSetupError(ValueError):
    """Raised when a knowledge setup selection or live state is unsafe."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class KnowledgeSetupSelection:
    mode: str
    engine_root: Path
    knowledge_root: Path
    runtime_root: Path
    github_repository: str | None = None
    github_executable: str = "gh"
    remote_name: str = "origin"
    branch: str = "main"
    sync_enabled: bool = False
    confirm_github_create: str | None = None


@dataclass(frozen=True)
class KnowledgeSetupAction:
    kind: str
    target: str
    mutates: bool
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
        if not isinstance(self.target, str) or not self.target:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
        if type(self.mutates) is not bool or not isinstance(self.details, Mapping):
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
        object.__setattr__(self, "details", MappingProxyType(dict(sorted(self.details.items()))))

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "target": self.target,
            "mutates": self.mutates,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class KnowledgeSetupPlan:
    selection: KnowledgeSetupSelection
    actions: tuple[KnowledgeSetupAction, ...]
    remote_fingerprint: str | None
    plan_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "selection": _selection_document(self.selection),
            "actions": [action.to_dict() for action in self.actions],
            "remote_fingerprint": self.remote_fingerprint,
            "plan_digest": self.plan_digest,
        }


@dataclass(frozen=True)
class KnowledgeSetupResult:
    ok: bool
    status: str
    stage: str
    repository: Mapping[str, object]
    remote: Mapping[str, object]
    actions: tuple[Mapping[str, object], ...] = ()
    recovery: Mapping[str, object] = field(default_factory=dict)
    errors: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if type(self.ok) is not bool or self.stage not in SETUP_STAGES:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_RESULT_INVALID")
        if not isinstance(self.status, str) or not self.status:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_RESULT_INVALID")
        object.__setattr__(self, "repository", MappingProxyType(dict(self.repository)))
        object.__setattr__(self, "remote", MappingProxyType(dict(self.remote)))
        object.__setattr__(self, "actions", tuple(MappingProxyType(dict(item)) for item in self.actions))
        object.__setattr__(self, "recovery", MappingProxyType(dict(self.recovery)))
        object.__setattr__(self, "errors", tuple(MappingProxyType(dict(item)) for item in self.errors))

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "status": self.status,
            "stage": self.stage,
            "repository": dict(self.repository),
            "remote": dict(self.remote),
            "actions": [dict(item) for item in self.actions],
            "recovery": dict(self.recovery),
            "errors": [dict(item) for item in self.errors],
        }


def normalize_github_repository(value: str) -> str:
    if not isinstance(value, str):
        raise KnowledgeSetupError("GITHUB_REPOSITORY_INVALID")
    normalized = value.strip()
    if normalized != value or normalized.count("/") != 1:
        raise KnowledgeSetupError("GITHUB_REPOSITORY_INVALID")
    owner, repository = normalized.split("/", 1)
    if (
        not _GITHUB_OWNER.fullmatch(owner)
        or "--" in owner
        or not _GITHUB_REPOSITORY.fullmatch(repository)
        or repository in {".", ".."}
        or ".." in repository
    ):
        raise KnowledgeSetupError("GITHUB_REPOSITORY_INVALID")
    return normalized


def _validated_text(value: str, code: str, *, reject_option: bool = True) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise KnowledgeSetupError(code)
    if "\x00" in value or "\r" in value or "\n" in value or (reject_option and value.startswith("-")):
        raise KnowledgeSetupError(code)
    return value


def _validated_branch(value: str) -> str:
    branch = _validated_text(value, "GIT_BRANCH_INVALID")
    segments = branch.split("/")
    if (
        branch in {"@", "HEAD"}
        or branch.startswith("/")
        or branch.endswith(("/", ".", ".lock"))
        or "//" in branch
        or ".." in branch
        or "@{" in branch
        or any(not segment or segment.startswith(".") or segment.endswith(".lock") for segment in segments)
        or any(character in _INVALID_BRANCH_CHARACTERS or ord(character) < 32 or ord(character) == 127 for character in branch)
    ):
        raise KnowledgeSetupError("GIT_BRANCH_INVALID")
    return branch


def _canonical_root(value: Path | str, code: str) -> Path:
    if isinstance(value, bool) or not isinstance(value, (Path, str)) or not os.fspath(value):
        raise KnowledgeSetupError(code)
    try:
        raw = assert_no_reparse_components(absolute_path(value))
        return canonical_path(raw)
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError) as exc:
        raise KnowledgeSetupError(code) from exc


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_root_separation(engine_root: Path, knowledge_root: Path, runtime_root: Path) -> None:
    if _contains(engine_root, knowledge_root) or _contains(knowledge_root, engine_root):
        raise KnowledgeSetupError("KNOWLEDGE_ROOT_OVERLAPS_ENGINE_ROOT")
    if _contains(runtime_root, knowledge_root) or _contains(knowledge_root, runtime_root):
        raise KnowledgeSetupError("KNOWLEDGE_ROOT_OVERLAPS_RUNTIME_ROOT")
    if _contains(engine_root, runtime_root) or _contains(runtime_root, engine_root):
        raise KnowledgeSetupError("ENGINE_ROOT_OVERLAPS_RUNTIME_ROOT")


def _normalize_selection(selection: KnowledgeSetupSelection) -> KnowledgeSetupSelection:
    if not isinstance(selection, KnowledgeSetupSelection):
        raise TypeError("KNOWLEDGE_SETUP_SELECTION_REQUIRED")
    if selection.mode not in KNOWLEDGE_MODES:
        raise KnowledgeSetupError("KNOWLEDGE_MODE_INVALID")
    engine_root = _canonical_root(selection.engine_root, "ENGINE_ROOT_INVALID")
    knowledge_root = _canonical_root(selection.knowledge_root, "KNOWLEDGE_ROOT_INVALID")
    runtime_root = _canonical_root(selection.runtime_root, "RUNTIME_ROOT_INVALID")
    _validate_root_separation(engine_root, knowledge_root, runtime_root)
    executable = _validated_text(selection.github_executable, "GITHUB_EXECUTABLE_INVALID")
    remote_name = _validated_text(selection.remote_name, "GIT_REMOTE_NAME_INVALID")
    if not _REMOTE_NAME.fullmatch(remote_name):
        raise KnowledgeSetupError("GIT_REMOTE_NAME_INVALID")
    branch = _validated_branch(selection.branch)
    if type(selection.sync_enabled) is not bool:
        raise KnowledgeSetupError("KNOWLEDGE_SYNC_SELECTION_INVALID")

    repository: str | None = None
    confirmation: str | None = selection.confirm_github_create
    if selection.mode == "local":
        if selection.github_repository is not None:
            raise KnowledgeSetupError("LOCAL_GITHUB_REPOSITORY_FORBIDDEN")
        if confirmation is not None:
            raise KnowledgeSetupError("LOCAL_GITHUB_CONFIRMATION_FORBIDDEN")
        if selection.sync_enabled:
            raise KnowledgeSetupError("LOCAL_SYNC_FORBIDDEN")
    else:
        if selection.github_repository is None:
            raise KnowledgeSetupError("GITHUB_REPOSITORY_REQUIRED")
        repository = normalize_github_repository(selection.github_repository)
        if confirmation is not None:
            confirmation = normalize_github_repository(confirmation)
        if selection.mode == "github-existing" and confirmation is not None:
            raise KnowledgeSetupError("GITHUB_EXISTING_CONFIRMATION_FORBIDDEN")

    return KnowledgeSetupSelection(
        mode=selection.mode,
        engine_root=engine_root,
        knowledge_root=knowledge_root,
        runtime_root=runtime_root,
        github_repository=repository,
        github_executable=executable,
        remote_name=remote_name,
        branch=branch,
        sync_enabled=selection.sync_enabled,
        confirm_github_create=confirmation,
    )


def _selection_document(selection: KnowledgeSetupSelection) -> dict[str, object]:
    return {
        "mode": selection.mode,
        "engine_root": str(selection.engine_root),
        "knowledge_root": str(selection.knowledge_root),
        "runtime_root": str(selection.runtime_root),
        "github_repository": selection.github_repository,
        "github_executable": selection.github_executable,
        "remote_name": selection.remote_name,
        "branch": selection.branch,
        "sync_enabled": selection.sync_enabled,
    }


def _local_action(selection: KnowledgeSetupSelection) -> KnowledgeSetupAction:
    status = inspect_knowledge_repository(
        selection.knowledge_root,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
    )
    if not status.initialized:
        return KnowledgeSetupAction("initialize-local", str(selection.knowledge_root), True)
    try:
        empty = next(selection.knowledge_root.iterdir(), None) is None
    except OSError as exc:
        raise KnowledgeSetupError("KNOWLEDGE_ROOT_INSPECTION_FAILED") from exc
    if empty:
        return KnowledgeSetupAction("initialize-local", str(selection.knowledge_root), True)
    if not (status.git_initialized and status.manifest_valid and status.required_paths_present):
        raise KnowledgeSetupError("KNOWLEDGE_ROOT_CONTRACT_INVALID")
    return KnowledgeSetupAction(
        "reuse-local",
        str(selection.knowledge_root),
        False,
        {"root_digest": status.root_digest or ""},
    )


def _github_remote(repository: str) -> str:
    return f"https://github.com/{repository}.git"


def _canonical_digest(selection: KnowledgeSetupSelection, actions: tuple[KnowledgeSetupAction, ...], fingerprint: str | None) -> str:
    document: dict[str, Any] = {
        "selection": _selection_document(selection),
        "actions": [action.to_dict() for action in actions],
        "remote_fingerprint": fingerprint,
    }
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def plan_knowledge_setup(selection: KnowledgeSetupSelection) -> KnowledgeSetupPlan:
    normalized = _normalize_selection(selection)
    local_action = _local_action(normalized)
    actions: list[KnowledgeSetupAction] = [local_action]
    fingerprint: str | None = None
    if normalized.github_repository is not None:
        remote = _github_remote(normalized.github_repository)
        fingerprint = remote_fingerprint(remote)
        if normalized.mode == "github-new":
            actions.extend(
                (
                    KnowledgeSetupAction("create-private-github", normalized.github_repository, True),
                    KnowledgeSetupAction("verify-private-remote", fingerprint, False),
                    KnowledgeSetupAction("connect-remote", normalized.remote_name, True, {"remote_fingerprint": fingerprint}),
                    KnowledgeSetupAction("push-and-verify", normalized.branch, True, {"remote_name": normalized.remote_name}),
                )
            )
        else:
            actions.extend(
                (
                    KnowledgeSetupAction("inspect-private-github", normalized.github_repository, False),
                    KnowledgeSetupAction("restore-or-connect-existing", normalized.remote_name, True, {"remote_fingerprint": fingerprint}),
                    KnowledgeSetupAction("verify-private-remote", fingerprint, False),
                )
            )
    action_tuple = tuple(actions)
    return KnowledgeSetupPlan(
        selection=normalized,
        actions=action_tuple,
        remote_fingerprint=fingerprint,
        plan_digest=_canonical_digest(normalized, action_tuple, fingerprint),
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def operation_receipt_path(plan: KnowledgeSetupPlan) -> Path:
    if not isinstance(plan, KnowledgeSetupPlan) or not _SHA256.fullmatch(plan.plan_digest):
        raise TypeError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
    return plan.selection.runtime_root / "setup-operations" / f"{plan.plan_digest.removeprefix('sha256:')}.json"


def _closed(value: object, keys: frozenset[str], required: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) - keys or not required.issubset(value):
        raise KnowledgeSetupError(code)
    return value


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_operation_receipt(value: object) -> dict[str, Any]:
    code = "KNOWLEDGE_OPERATION_RECEIPT_INVALID"
    receipt = _closed(value, _RECEIPT_KEYS, _RECEIPT_KEYS, code)
    if (
        receipt.get("schema_version") != 1
        or not isinstance(receipt.get("plan_digest"), str)
        or not _SHA256.fullmatch(str(receipt["plan_digest"]))
        or receipt.get("status") not in _OPERATION_STATUSES
        or receipt.get("stage") not in SETUP_STAGES
        or receipt.get("mode") not in KNOWLEDGE_MODES
        or not _valid_timestamp(receipt.get("started_at"))
        or not _valid_timestamp(receipt.get("updated_at"))
        or (receipt.get("completed_at") is not None and not _valid_timestamp(receipt.get("completed_at")))
    ):
        raise KnowledgeSetupError(code)

    completed = receipt.get("completed_actions")
    if not isinstance(completed, list):
        raise KnowledgeSetupError(code)
    for item in completed:
        action = _closed(
            item,
            frozenset({"kind", "target", "status", "completed_at"}),
            frozenset({"kind", "target", "status", "completed_at"}),
            code,
        )
        if (
            not isinstance(action.get("kind"), str)
            or not action["kind"]
            or not isinstance(action.get("target"), str)
            or not action["target"]
            or action.get("status") not in {"COMPLETED", "SKIPPED"}
            or not _valid_timestamp(action.get("completed_at"))
        ):
            raise KnowledgeSetupError(code)

    repository = _closed(
        receipt.get("repository"),
        frozenset({"root", "status", "git_initialized", "root_digest"}),
        frozenset({"root", "status", "git_initialized", "root_digest"}),
        code,
    )
    root_digest = repository.get("root_digest")
    if (
        not isinstance(repository.get("root"), str)
        or not repository["root"]
        or repository.get("status") not in _REPOSITORY_STATUSES
        or type(repository.get("git_initialized")) is not bool
        or (root_digest is not None and (not isinstance(root_digest, str) or not _SHA256.fullmatch(root_digest)))
    ):
        raise KnowledgeSetupError(code)

    remote = _closed(
        receipt.get("remote"),
        frozenset({"repository", "remote_name", "fingerprint", "classification", "branch", "connected", "initial_push_complete"}),
        frozenset({"repository", "remote_name", "fingerprint", "classification", "branch", "connected", "initial_push_complete"}),
        code,
    )
    if (
        any(value is not None and not isinstance(value, str) for value in (remote.get("repository"), remote.get("remote_name"), remote.get("branch")))
        or (remote.get("fingerprint") is not None and (not isinstance(remote.get("fingerprint"), str) or not _SHA256.fullmatch(str(remote["fingerprint"]))))
        or (remote.get("classification") is not None and remote.get("classification") not in _REMOTE_CLASSIFICATIONS)
        or type(remote.get("connected")) is not bool
        or type(remote.get("initial_push_complete")) is not bool
    ):
        raise KnowledgeSetupError(code)

    recovery = _closed(
        receipt.get("recovery"),
        frozenset({"retryable", "resume_stage", "external_repository_retained", "command"}),
        frozenset({"retryable", "resume_stage", "external_repository_retained", "command"}),
        code,
    )
    if (
        type(recovery.get("retryable")) is not bool
        or (recovery.get("resume_stage") is not None and recovery.get("resume_stage") not in SETUP_STAGES)
        or type(recovery.get("external_repository_retained")) is not bool
        or (recovery.get("command") is not None and (not isinstance(recovery.get("command"), str) or len(str(recovery["command"])) > 4096))
    ):
        raise KnowledgeSetupError(code)

    errors = receipt.get("errors")
    if not isinstance(errors, list):
        raise KnowledgeSetupError(code)
    for item in errors:
        error = _closed(
            item,
            frozenset({"code", "stage", "retryable"}),
            frozenset({"code", "stage", "retryable"}),
            code,
        )
        if (
            not isinstance(error.get("code"), str)
            or not _ERROR_CODE.fullmatch(str(error["code"]))
            or error.get("stage") not in SETUP_STAGES
            or type(error.get("retryable")) is not bool
        ):
            raise KnowledgeSetupError(code)
    return json.loads(json.dumps(dict(receipt), ensure_ascii=False))


def load_operation_receipt(path: Path | str, *, runtime_root: Path | str) -> dict[str, Any]:
    try:
        runtime_raw = assert_no_reparse_components(absolute_path(runtime_root))
        runtime = canonical_path(runtime_raw, require_exists=True)
        assert_safe_target(runtime, runtime, allow_root=True, allow_missing=False, expected_type="dir")
    except SafeFilesystemError as exc:
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_OUTSIDE_RUNTIME") from exc
    try:
        target_raw = assert_no_reparse_components(absolute_path(path))
        target = canonical_path(target_raw, require_exists=True)
    except SafeFilesystemError as exc:
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_INVALID") from exc
    try:
        target.relative_to(runtime)
    except ValueError as exc:
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_OUTSIDE_RUNTIME") from exc
    try:
        assert_safe_target(runtime, target, allow_missing=False, expected_type="file")
    except SafeFilesystemError as exc:
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_INVALID") from exc
    if not target.is_file():
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_INVALID")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KnowledgeSetupError("KNOWLEDGE_OPERATION_RECEIPT_INVALID") from exc
    return _validate_operation_receipt(value)


def _write_operation_receipt(plan: KnowledgeSetupPlan, value: Mapping[str, Any]) -> Path:
    receipt = _validate_operation_receipt(value)
    runtime = safe_ensure_directory(plan.selection.runtime_root, mode=0o700)
    directory = safe_mkdir(runtime, runtime / "setup-operations", mode=0o700)
    target = operation_receipt_path(plan)
    raw = (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    safe_atomic_write(directory, target, raw, mode=0o600)
    return target


def _operation_started_at(plan: KnowledgeSetupPlan) -> str:
    path = operation_receipt_path(plan)
    if path.is_file() and not path.is_symlink():
        try:
            existing = load_operation_receipt(path, runtime_root=plan.selection.runtime_root)
        except (KnowledgeSetupError, SafeFilesystemError):
            return _timestamp()
        if existing.get("plan_digest") == plan.plan_digest:
            return str(existing["started_at"])
    return _timestamp()


def _remote_document(plan: KnowledgeSetupPlan) -> dict[str, object]:
    return {
        "repository": plan.selection.github_repository,
        "remote_name": plan.selection.remote_name if plan.selection.github_repository is not None else None,
        "fingerprint": plan.remote_fingerprint,
        "classification": None,
        "branch": plan.selection.branch if plan.selection.github_repository is not None else None,
        "connected": False,
        "initial_push_complete": False,
    }


def _recovery_document(*, retryable: bool, stage: str | None, external_repository_retained: bool = False) -> dict[str, object]:
    return {
        "retryable": retryable,
        "resume_stage": stage,
        "external_repository_retained": external_repository_retained,
        "command": None,
    }


def _receipt_document(
    plan: KnowledgeSetupPlan,
    *,
    status: str,
    stage: str,
    repository: Mapping[str, object],
    remote: Mapping[str, object],
    actions: tuple[Mapping[str, object], ...],
    recovery: Mapping[str, object],
    errors: tuple[Mapping[str, object], ...],
) -> dict[str, object]:
    now = _timestamp()
    return {
        "schema_version": 1,
        "plan_digest": plan.plan_digest,
        "status": status,
        "stage": stage,
        "mode": plan.selection.mode,
        "completed_actions": [dict(item) for item in actions],
        "started_at": _operation_started_at(plan),
        "updated_at": now,
        "completed_at": now if status == "COMPLETE" else None,
        "repository": dict(repository),
        "remote": dict(remote),
        "recovery": dict(recovery),
        "errors": [dict(item) for item in errors],
    }


def _result_from_receipt(receipt: Mapping[str, Any]) -> KnowledgeSetupResult:
    return KnowledgeSetupResult(
        ok=receipt["status"] == "COMPLETE",
        status=str(receipt["status"]),
        stage=str(receipt["stage"]),
        repository=dict(receipt["repository"]),
        remote=dict(receipt["remote"]),
        actions=tuple(dict(item) for item in receipt["completed_actions"]),
        recovery=dict(receipt["recovery"]),
        errors=tuple(dict(item) for item in receipt["errors"]),
    )


def _staging_paths(plan: KnowledgeSetupPlan) -> tuple[Path, Path]:
    suffix = plan.plan_digest.removeprefix("sha256:")[:20]
    staging = plan.selection.knowledge_root.parent / f".{plan.selection.knowledge_root.name}.ei-setup-{suffix}"
    ownership = plan.selection.runtime_root / "setup-operations" / f"{suffix}.staging-ownership.json"
    return staging, ownership


def _recover_owned_staging(plan: KnowledgeSetupPlan, staging: Path, ownership_path: Path) -> None:
    if not (staging.exists() or staging.is_symlink()):
        if ownership_path.exists() and not ownership_path.is_symlink():
            safe_unlink(plan.selection.runtime_root, ownership_path)
        return
    if staging.is_symlink() or not staging.is_dir() or not ownership_path.is_file() or ownership_path.is_symlink():
        raise KnowledgeSetupError("KNOWLEDGE_STAGING_OWNERSHIP_REQUIRED")
    owner = read_ownership_record(ownership_path, root=plan.selection.runtime_root)
    validate_ownership_record(owner, staging.parent, staging, kind="knowledge-setup-staging")
    safe_remove_tree(staging.parent, staging, owner=owner, kind="knowledge-setup-staging")
    safe_unlink(plan.selection.runtime_root, ownership_path)


def _initialize_local_repository(plan: KnowledgeSetupPlan) -> Mapping[str, object]:
    selection = plan.selection
    runtime = safe_ensure_directory(selection.runtime_root, mode=0o700)
    safe_mkdir(runtime, runtime / "setup-operations", mode=0o700)
    parent = safe_ensure_directory(selection.knowledge_root.parent)
    if selection.knowledge_root.exists() or selection.knowledge_root.is_symlink():
        if selection.knowledge_root.is_symlink() or not selection.knowledge_root.is_dir():
            raise KnowledgeSetupError("KNOWLEDGE_ROOT_CONTRACT_INVALID")
        try:
            empty = next(selection.knowledge_root.iterdir(), None) is None
        except OSError as exc:
            raise KnowledgeSetupError("KNOWLEDGE_ROOT_INSPECTION_FAILED") from exc
        if not empty:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_PLAN_STALE")
        status = bootstrap_knowledge_repository(
            selection.knowledge_root,
            engine_root=selection.engine_root,
            runtime_root=selection.runtime_root,
            initialize_git=True,
        )
        return {
            "root": str(status.root),
            "status": "CREATED",
            "git_initialized": status.git_initialized,
            "root_digest": status.root_digest,
        }
    staging, ownership_path = _staging_paths(plan)
    _recover_owned_staging(plan, staging, ownership_path)
    owner = create_ownership_record(parent, staging, kind="knowledge-setup-staging")
    write_ownership_record(ownership_path, owner, root=runtime)
    safe_mkdir(parent, staging)
    bootstrap_knowledge_repository(
        staging,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
        initialize_git=True,
    )
    staged_status = inspect_knowledge_repository(
        staging,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
    )
    if not (staged_status.git_initialized and staged_status.manifest_valid and staged_status.required_paths_present):
        raise KnowledgeSetupError("KNOWLEDGE_STAGING_LAYOUT_INVALID")
    if selection.knowledge_root.exists() or selection.knowledge_root.is_symlink():
        raise KnowledgeSetupError("KNOWLEDGE_SETUP_PLAN_STALE")
    safe_move(parent, staging, parent, selection.knowledge_root)
    safe_unlink(runtime, ownership_path)
    status = inspect_knowledge_repository(
        selection.knowledge_root,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
    )
    return {
        "root": str(status.root),
        "status": "CREATED",
        "git_initialized": status.git_initialized,
        "root_digest": status.root_digest,
    }


def _apply_local(plan: KnowledgeSetupPlan) -> KnowledgeSetupResult:
    action = plan.actions[0]
    remote = _remote_document(plan)
    try:
        if action.kind == "initialize-local":
            repository = _initialize_local_repository(plan)
        elif action.kind == "reuse-local":
            status = inspect_knowledge_repository(
                plan.selection.knowledge_root,
                engine_root=plan.selection.engine_root,
                runtime_root=plan.selection.runtime_root,
            )
            if not (status.git_initialized and status.manifest_valid and status.required_paths_present):
                raise KnowledgeSetupError("KNOWLEDGE_SETUP_PLAN_STALE")
            repository = {
                "root": str(status.root),
                "status": "ALREADY_CURRENT",
                "git_initialized": status.git_initialized,
                "root_digest": status.root_digest,
            }
        else:
            raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
        completed = (
            {
                "kind": action.kind,
                "target": action.target,
                "status": "COMPLETED" if action.mutates else "SKIPPED",
                "completed_at": _timestamp(),
            },
        )
        receipt = _receipt_document(
            plan,
            status="COMPLETE",
            stage="KNOWLEDGE_LOCAL_READY",
            repository=repository,
            remote=remote,
            actions=completed,
            recovery=_recovery_document(retryable=False, stage=None),
            errors=(),
        )
    except (KnowledgeSetupError, KnowledgeRepositoryError, SafeFilesystemError, OSError) as exc:
        error_code = getattr(exc, "code", None)
        if not isinstance(error_code, str) or not _ERROR_CODE.fullmatch(error_code):
            error_code = "KNOWLEDGE_SETUP_FAILED"
        receipt = _receipt_document(
            plan,
            status="FAILED",
            stage="PLANNED",
            repository={
                "root": str(plan.selection.knowledge_root),
                "status": "NOT_READY",
                "git_initialized": False,
                "root_digest": None,
            },
            remote=remote,
            actions=(),
            recovery=_recovery_document(retryable=True, stage="PLANNED"),
            errors=({"code": error_code, "stage": "PLANNED", "retryable": True},),
        )
    _write_operation_receipt(plan, receipt)
    return _result_from_receipt(receipt)


def apply_knowledge_setup(plan: KnowledgeSetupPlan) -> KnowledgeSetupResult:
    if not isinstance(plan, KnowledgeSetupPlan):
        raise TypeError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
    current = plan_knowledge_setup(plan.selection)
    if current.plan_digest != plan.plan_digest:
        raise KnowledgeSetupError("KNOWLEDGE_SETUP_PLAN_STALE")
    if plan.selection.mode == "local":
        return _apply_local(plan)
    from .github_knowledge import apply_github_knowledge_setup

    return apply_github_knowledge_setup(plan)


__all__ = [
    "KNOWLEDGE_MODES",
    "SETUP_STAGES",
    "KnowledgeSetupAction",
    "KnowledgeSetupError",
    "KnowledgeSetupPlan",
    "KnowledgeSetupResult",
    "KnowledgeSetupSelection",
    "apply_knowledge_setup",
    "load_operation_receipt",
    "normalize_github_repository",
    "operation_receipt_path",
    "plan_knowledge_setup",
]
