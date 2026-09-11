"""Bounded GitHub CLI operations for private knowledge repositories."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .knowledge_repository import (
    KnowledgeRepositoryError,
    KnowledgeRepositoryStatus,
    inspect_knowledge_repository,
)
from .knowledge_setup import (
    KnowledgeSetupError,
    KnowledgeSetupPlan,
    KnowledgeSetupResult,
    _initialize_local_repository,
    _receipt_document,
    _recovery_document,
    _result_from_receipt,
    _timestamp,
    _write_operation_receipt,
    load_operation_receipt,
    normalize_github_repository,
)
from .remote_assurance import (
    RemoteAssuranceError,
    RemoteDescriptor,
    assure_remote,
    build_remote_assurance_receipt,
    normalize_remote,
    remote_fingerprint,
    write_remote_assurance_receipt,
)
from .safe_fs import (
    SafeFilesystemError,
    create_ownership_record,
    read_ownership_record,
    safe_ensure_directory,
    safe_move,
    safe_remove_tree,
    safe_unlink,
    validate_ownership_record,
    write_ownership_record,
)


_SECRET_ASSIGNMENT = re.compile(
    r'(?i)("(?:token|access_token|refresh_token|password|secret|authorization)"\s*:\s*)"(?:\\.|[^"\\])*"'
)
_TOKEN_SHAPE = re.compile(r"(?i)\b(?:ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_OPERATION_RECEIPT_NAME = re.compile(r"^[0-9a-f]{64}\.json$")


class GitHubKnowledgeError(ValueError):
    """Raised when a GitHub knowledge operation fails closed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class GitHubCommandResult:
    returncode: int
    stdout: str
    error_code: str


@dataclass(frozen=True)
class GitHubRepositoryState:
    repository: str
    exists: bool
    visibility: str | None
    default_branch: str | None
    empty: bool


def _sanitize_text(value: object, *, maximum: int = 1_048_576) -> str:
    text = value if isinstance(value, str) else ""
    text = _SECRET_ASSIGNMENT.sub(r'\1"<redacted>"', text)
    text = _TOKEN_SHAPE.sub("<redacted>", text)
    text = _BEARER.sub("Bearer <redacted>", text)
    if len(text) > maximum:
        return text[:maximum]
    return text


def _error_code(returncode: int, stdout: str, stderr: str) -> str:
    if returncode == 0:
        return ""
    combined = f"{stdout}\n{stderr}".casefold()
    if "rate limit" in combined or "too many requests" in combined or "http 429" in combined:
        return "GITHUB_RATE_LIMITED"
    if "already exists" in combined or "name already exists" in combined:
        return "GITHUB_REPOSITORY_ALREADY_EXISTS"
    if "http 404" in combined or "not found" in combined or "could not resolve to a repository" in combined:
        return "GITHUB_REPOSITORY_NOT_FOUND"
    if (
        "http 401" in combined
        or "bad credentials" in combined
        or "authentication" in combined
        or "gh auth login" in combined
        or "not logged" in combined
    ):
        return "GITHUB_AUTH_REQUIRED"
    if "http 403" in combined or "forbidden" in combined or "permission" in combined:
        return "GITHUB_PERMISSION_DENIED"
    if (
        "could not resolve host" in combined
        or "network is unreachable" in combined
        or "connection refused" in combined
        or "connection timed out" in combined
    ):
        return "GITHUB_NETWORK_UNAVAILABLE"
    return "GITHUB_COMMAND_FAILED"


def _executable(value: str | Path) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, Path)):
        raise GitHubKnowledgeError("GITHUB_EXECUTABLE_INVALID")
    text = os.fspath(value)
    if not isinstance(text, str) or not text or text != text.strip() or text.startswith("-"):
        raise GitHubKnowledgeError("GITHUB_EXECUTABLE_INVALID")
    if "\x00" in text or "\r" in text or "\n" in text:
        raise GitHubKnowledgeError("GITHUB_EXECUTABLE_INVALID")
    return text


def _arguments(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise GitHubKnowledgeError("GITHUB_ARGUMENTS_INVALID")
    result = tuple(values)
    if any(not isinstance(value, str) or not value or "\x00" in value or "\r" in value or "\n" in value for value in result):
        raise GitHubKnowledgeError("GITHUB_ARGUMENTS_INVALID")
    return result


class GitHubKnowledgeClient:
    def __init__(self, executable: str | Path = "gh", *, timeout_seconds: int = 30) -> None:
        self.executable = _executable(executable)
        if type(timeout_seconds) is not int or timeout_seconds < 1 or timeout_seconds > 300:
            raise GitHubKnowledgeError("GITHUB_TIMEOUT_INVALID")
        self.timeout_seconds = timeout_seconds

    def _run(self, arguments: Sequence[str]) -> GitHubCommandResult:
        argv = [self.executable, *_arguments(arguments)]
        try:
            process = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitHubKnowledgeError("GITHUB_COMMAND_TIMEOUT") from exc
        except OSError as exc:
            raise GitHubKnowledgeError("GITHUB_EXECUTABLE_UNAVAILABLE") from exc
        stdout = _sanitize_text(process.stdout)
        stderr = _sanitize_text(process.stderr)
        return GitHubCommandResult(process.returncode, stdout, _error_code(process.returncode, stdout, stderr))

    def run_read_only(self, arguments: Sequence[str]) -> GitHubCommandResult:
        values = _arguments(arguments)
        if values[0] not in {"api", "auth", "repo"}:
            raise GitHubKnowledgeError("GITHUB_READ_ONLY_COMMAND_FORBIDDEN")
        if values[0] == "repo" and (len(values) < 2 or values[1] != "view"):
            raise GitHubKnowledgeError("GITHUB_READ_ONLY_COMMAND_FORBIDDEN")
        return self._run(values)

    def verify_authentication(self) -> None:
        result = self._run(("auth", "status", "--hostname", "github.com"))
        if result.returncode != 0:
            raise GitHubKnowledgeError(result.error_code)

    def inspect_repository(self, repository: str) -> GitHubRepositoryState:
        slug = normalize_github_repository(repository)
        result = self._run(("api", f"repos/{slug}"))
        if result.returncode == 1 and result.error_code == "GITHUB_REPOSITORY_NOT_FOUND":
            return GitHubRepositoryState(slug, False, None, None, False)
        if result.returncode != 0:
            raise GitHubKnowledgeError(result.error_code)
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise GitHubKnowledgeError("GITHUB_RESPONSE_INVALID") from exc
        if not isinstance(document, dict):
            raise GitHubKnowledgeError("GITHUB_RESPONSE_INVALID")
        visibility = document.get("visibility")
        size = document.get("size")
        branch = document.get("default_branch")
        if visibility not in {"public", "private", "internal"} or type(size) is not int:
            raise GitHubKnowledgeError("GITHUB_RESPONSE_INVALID")
        if branch is not None and (not isinstance(branch, str) or not branch):
            raise GitHubKnowledgeError("GITHUB_RESPONSE_INVALID")
        return GitHubRepositoryState(slug, True, visibility, branch, size == 0)

    def create_private_repository(self, repository: str) -> None:
        slug = normalize_github_repository(repository)
        result = self._run(("repo", "create", slug, "--private"))
        if result.returncode != 0:
            raise GitHubKnowledgeError(result.error_code)

    def remote_url(self, repository: str) -> str:
        slug = normalize_github_repository(repository)
        return f"https://github.com/{slug}.git"


def _git(root: Path, *arguments: str, timeout: int = 90) -> GitHubCommandResult:
    if not root.is_dir() or root.is_symlink():
        raise GitHubKnowledgeError("GIT_WORKING_DIRECTORY_INVALID")
    values = _arguments(arguments)
    try:
        process = subprocess.run(
            ["git", *values],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitHubKnowledgeError("GIT_COMMAND_TIMEOUT") from exc
    except OSError as exc:
        raise GitHubKnowledgeError("GIT_EXECUTABLE_UNAVAILABLE") from exc
    stdout = _sanitize_text(process.stdout)
    stderr = _sanitize_text(process.stderr)
    combined = f"{stdout}\n{stderr}".casefold()
    if process.returncode == 0:
        code = ""
    elif "authentication" in combined or "permission denied" in combined or "could not read username" in combined:
        code = "GIT_AUTH_FAILED"
    elif "could not resolve host" in combined or "network is unreachable" in combined or "connection timed out" in combined:
        code = "GIT_NETWORK_UNAVAILABLE"
    else:
        code = "GIT_COMMAND_FAILED"
    return GitHubCommandResult(process.returncode, stdout, code)


def _validated_remote_name(value: str) -> str:
    if not isinstance(value, str) or not _REMOTE_NAME.fullmatch(value):
        raise GitHubKnowledgeError("GIT_REMOTE_NAME_INVALID")
    return value


def _validated_branch(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or value.startswith("/")
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
        or "@{" in value
        or any(character in " ~^:?*[\\" or ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GitHubKnowledgeError("GIT_BRANCH_INVALID")
    return value


def engine_remote_url(engine_root: Path, remote_name: str) -> str | None:
    name = _validated_remote_name(remote_name)
    root = Path(engine_root).expanduser().resolve()
    if not root.is_dir() or root.is_symlink() or not (root / ".git").exists():
        return None
    result = _git(root, "remote", "get-url", name)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.strip().splitlines()[0]


def connect_exact_remote(root: Path, remote_name: str, remote_url: str) -> None:
    name = _validated_remote_name(remote_name)
    try:
        normalize_remote(remote_url)
        expected_fingerprint = remote_fingerprint(remote_url)
    except RemoteAssuranceError as exc:
        raise GitHubKnowledgeError(exc.code) from exc
    repository = Path(root).expanduser().resolve()
    current = _git(repository, "remote", "get-url", name)
    if current.returncode == 0 and current.stdout.strip():
        current_url = current.stdout.strip().splitlines()[0]
        try:
            current_fingerprint = remote_fingerprint(current_url)
        except RemoteAssuranceError as exc:
            raise GitHubKnowledgeError("KNOWLEDGE_REMOTE_URL_CONFLICT") from exc
        if current_fingerprint != expected_fingerprint:
            raise GitHubKnowledgeError("KNOWLEDGE_REMOTE_URL_CONFLICT")
        return
    remotes = _git(repository, "remote")
    if remotes.returncode != 0:
        raise GitHubKnowledgeError("GIT_REMOTE_INSPECTION_FAILED")
    if name in {line.strip() for line in remotes.stdout.splitlines() if line.strip()}:
        raise GitHubKnowledgeError("KNOWLEDGE_REMOTE_URL_CONFLICT")
    added = _git(repository, "remote", "add", name, remote_url)
    if added.returncode != 0:
        raise GitHubKnowledgeError("GIT_REMOTE_ADD_FAILED")


def _revision(root: Path, reference: str) -> str:
    result = _git(root, "rev-parse", "--verify", reference)
    value = result.stdout.strip().splitlines()[0].casefold() if result.returncode == 0 and result.stdout.strip() else ""
    if not _SHA.fullmatch(value):
        raise GitHubKnowledgeError("GIT_REVISION_INVALID")
    return value


def push_and_verify(root: Path, remote_name: str, branch: str) -> str:
    repository = Path(root).expanduser().resolve()
    name = _validated_remote_name(remote_name)
    selected_branch = _validated_branch(branch)
    local = _revision(repository, "HEAD")
    pushed = _git(repository, "push", name, f"HEAD:refs/heads/{selected_branch}", timeout=180)
    if pushed.returncode != 0:
        raise GitHubKnowledgeError(pushed.error_code or "GIT_PUSH_FAILED")
    fetched = _git(
        repository,
        "fetch",
        name,
        f"refs/heads/{selected_branch}:refs/remotes/{name}/{selected_branch}",
        timeout=180,
    )
    if fetched.returncode != 0:
        raise GitHubKnowledgeError(fetched.error_code or "GIT_FETCH_FAILED")
    remote = _revision(repository, f"refs/remotes/{name}/{selected_branch}")
    if local != remote:
        raise GitHubKnowledgeError("GIT_PUSH_VERIFICATION_FAILED")
    return local


def ensure_local_knowledge(plan: KnowledgeSetupPlan) -> KnowledgeRepositoryStatus:
    if not isinstance(plan, KnowledgeSetupPlan):
        raise TypeError("KNOWLEDGE_SETUP_PLAN_REQUIRED")
    action = plan.actions[0]
    if action.kind == "initialize-local":
        _initialize_local_repository(plan)
    elif action.kind != "reuse-local":
        raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
    status = inspect_knowledge_repository(
        plan.selection.knowledge_root,
        engine_root=plan.selection.engine_root,
        runtime_root=plan.selection.runtime_root,
    )
    if not (status.git_initialized and status.manifest_valid and status.required_paths_present):
        raise KnowledgeSetupError("KNOWLEDGE_ROOT_CONTRACT_INVALID")
    return status


def _repository_document(plan: KnowledgeSetupPlan, status: KnowledgeRepositoryStatus, *, restored: bool = False) -> dict[str, object]:
    if restored:
        state = "RESTORED"
    elif plan.actions[0].kind == "reuse-local":
        state = "ALREADY_CURRENT"
    else:
        state = "CREATED"
    return {
        "root": str(status.root),
        "status": state,
        "git_initialized": status.git_initialized,
        "root_digest": status.root_digest,
    }


def _remote_document(plan: KnowledgeSetupPlan, *, classification: str | None = None, connected: bool = False, pushed: bool = False) -> dict[str, object]:
    return {
        "repository": plan.selection.github_repository,
        "remote_name": plan.selection.remote_name,
        "fingerprint": plan.remote_fingerprint,
        "classification": classification,
        "branch": plan.selection.branch,
        "connected": connected,
        "initial_push_complete": pushed,
    }


def _completed_action(plan: KnowledgeSetupPlan, kind: str, *, skipped: bool = False) -> dict[str, object]:
    action = next((item for item in plan.actions if item.kind == kind), None)
    if action is None:
        raise KnowledgeSetupError("KNOWLEDGE_SETUP_ACTION_INVALID")
    return {
        "kind": action.kind,
        "target": action.target,
        "status": "SKIPPED" if skipped else "COMPLETED",
        "completed_at": _timestamp(),
    }


def _persist_progress(
    plan: KnowledgeSetupPlan,
    *,
    status: str,
    stage: str,
    repository: Mapping[str, object],
    remote: Mapping[str, object],
    actions: Sequence[Mapping[str, object]],
    retryable: bool,
    retained: bool,
    error_code: str | None = None,
) -> dict[str, object]:
    errors: tuple[Mapping[str, object], ...] = ()
    if error_code is not None:
        errors = ({"code": error_code, "stage": stage, "retryable": retryable},)
    receipt = _receipt_document(
        plan,
        status=status,
        stage=stage,
        repository=repository,
        remote=remote,
        actions=tuple(actions),
        recovery=_recovery_document(
            retryable=retryable,
            stage=stage if status != "COMPLETE" else None,
            external_repository_retained=retained,
        ),
        errors=errors,
    )
    _write_operation_receipt(plan, receipt)
    return receipt


def _retained_remote_receipt(plan: KnowledgeSetupPlan) -> bool:
    directory = plan.selection.runtime_root / "setup-operations"
    if not directory.is_dir() or directory.is_symlink():
        return False
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file() or not _OPERATION_RECEIPT_NAME.fullmatch(path.name):
            continue
        try:
            receipt = load_operation_receipt(path, runtime_root=plan.selection.runtime_root)
        except (KnowledgeSetupError, SafeFilesystemError):
            continue
        remote = receipt.get("remote")
        repository = receipt.get("repository")
        recovery = receipt.get("recovery")
        if (
            receipt.get("mode") == "github-new"
            and isinstance(remote, Mapping)
            and remote.get("repository") == plan.selection.github_repository
            and remote.get("fingerprint") == plan.remote_fingerprint
            and isinstance(repository, Mapping)
            and repository.get("root") == str(plan.selection.knowledge_root)
            and isinstance(recovery, Mapping)
            and recovery.get("external_repository_retained") is True
        ):
            return True
    return False


def _assure_github_remote(plan: KnowledgeSetupPlan, client: GitHubKnowledgeClient, state: GitHubRepositoryState) -> RemoteDescriptor:
    if state.visibility not in {"private", "internal"}:
        raise KnowledgeSetupError("PRIVATE_REMOTE_REQUIRED")
    remote_url = client.remote_url(str(plan.selection.github_repository))
    descriptor = assure_remote(
        remote_url,
        engine_remote=engine_remote_url(plan.selection.engine_root, plan.selection.remote_name),
        visibility=state.visibility,
    )
    if descriptor.fingerprint != plan.remote_fingerprint:
        raise KnowledgeSetupError("KNOWLEDGE_REMOTE_FINGERPRINT_MISMATCH")
    return descriptor


def _owned_clone_paths(plan: KnowledgeSetupPlan) -> tuple[Path, Path]:
    suffix = str(plan.remote_fingerprint).removeprefix("sha256:")[:20]
    staging = plan.selection.knowledge_root.parent / f".{plan.selection.knowledge_root.name}.ei-restore-{suffix}"
    ownership = plan.selection.runtime_root / "setup-operations" / f"{suffix}.clone-ownership.json"
    return staging, ownership


def _clear_owned_clone(plan: KnowledgeSetupPlan, staging: Path, ownership_path: Path) -> None:
    if not (staging.exists() or staging.is_symlink()):
        if ownership_path.is_file() and not ownership_path.is_symlink():
            safe_unlink(plan.selection.runtime_root, ownership_path)
        return
    if staging.is_symlink() or not staging.is_dir() or not ownership_path.is_file() or ownership_path.is_symlink():
        raise KnowledgeSetupError("KNOWLEDGE_CLONE_OWNERSHIP_REQUIRED")
    owner = read_ownership_record(ownership_path, root=plan.selection.runtime_root)
    validate_ownership_record(owner, staging.parent, staging, kind="knowledge-clone-staging")
    safe_remove_tree(staging.parent, staging, owner=owner, kind="knowledge-clone-staging")
    safe_unlink(plan.selection.runtime_root, ownership_path)


def _clone_existing_repository(plan: KnowledgeSetupPlan, remote_url: str) -> KnowledgeRepositoryStatus:
    selection = plan.selection
    if selection.knowledge_root.exists() or selection.knowledge_root.is_symlink():
        raise KnowledgeSetupError("KNOWLEDGE_RESTORE_DESTINATION_NOT_ABSENT")
    runtime = safe_ensure_directory(selection.runtime_root, mode=0o700)
    operations = safe_ensure_directory(runtime / "setup-operations", mode=0o700)
    parent = safe_ensure_directory(selection.knowledge_root.parent)
    staging, ownership_path = _owned_clone_paths(plan)
    _clear_owned_clone(plan, staging, ownership_path)
    owner = create_ownership_record(parent, staging, kind="knowledge-clone-staging")
    write_ownership_record(ownership_path, owner, root=operations.parent)
    cloned = _git(
        parent,
        "clone",
        "--origin",
        selection.remote_name,
        "--branch",
        selection.branch,
        "--single-branch",
        remote_url,
        str(staging),
        timeout=300,
    )
    if cloned.returncode != 0:
        raise GitHubKnowledgeError(cloned.error_code or "GIT_CLONE_FAILED")
    status = inspect_knowledge_repository(
        staging,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
    )
    if not (status.git_initialized and status.manifest_valid and status.required_paths_present):
        raise KnowledgeSetupError("KNOWLEDGE_REMOTE_LAYOUT_INVALID")
    if status.dirty:
        raise KnowledgeSetupError("KNOWLEDGE_REMOTE_WORKTREE_DIRTY")
    connect_exact_remote(staging, selection.remote_name, remote_url)
    branch = _git(staging, "branch", "--show-current")
    if branch.returncode != 0 or branch.stdout.strip() != selection.branch:
        raise KnowledgeSetupError("KNOWLEDGE_REMOTE_BRANCH_MISMATCH")
    safe_move(parent, staging, parent, selection.knowledge_root)
    safe_unlink(runtime, ownership_path)
    return inspect_knowledge_repository(
        selection.knowledge_root,
        engine_root=selection.engine_root,
        runtime_root=selection.runtime_root,
    )


def _verify_existing_alignment(root: Path, remote_name: str, branch: str) -> None:
    name = _validated_remote_name(remote_name)
    selected_branch = _validated_branch(branch)
    fetched = _git(root, "fetch", name, f"refs/heads/{selected_branch}:refs/remotes/{name}/{selected_branch}", timeout=180)
    if fetched.returncode != 0:
        raise GitHubKnowledgeError(fetched.error_code or "GIT_FETCH_FAILED")
    local = _revision(root, "HEAD")
    remote = _revision(root, f"refs/remotes/{name}/{selected_branch}")
    if local == remote:
        return
    local_ancestor = _git(root, "merge-base", "--is-ancestor", local, remote).returncode == 0
    remote_ancestor = _git(root, "merge-base", "--is-ancestor", remote, local).returncode == 0
    if not local_ancestor and not remote_ancestor:
        raise KnowledgeSetupError("KNOWLEDGE_HISTORY_DIVERGED")
    raise KnowledgeSetupError("KNOWLEDGE_HISTORY_ALIGNMENT_REQUIRED")


def _github_new(plan: KnowledgeSetupPlan, client: GitHubKnowledgeClient) -> KnowledgeSetupResult:
    selection = plan.selection
    repository: Mapping[str, object] = {
        "root": str(selection.knowledge_root),
        "status": "NOT_READY",
        "git_initialized": False,
        "root_digest": None,
    }
    remote = _remote_document(plan)
    completed: list[Mapping[str, object]] = []
    stage = "PLANNED"
    retained = _retained_remote_receipt(plan)
    try:
        if selection.confirm_github_create != selection.github_repository:
            raise KnowledgeSetupError("GITHUB_CREATE_CONFIRMATION_REQUIRED")
        local = ensure_local_knowledge(plan)
        repository = _repository_document(plan, local)
        completed.append(_completed_action(plan, plan.actions[0].kind, skipped=not plan.actions[0].mutates))
        stage = "KNOWLEDGE_LOCAL_READY"
        _persist_progress(plan, status="IN_PROGRESS", stage=stage, repository=repository, remote=remote, actions=completed, retryable=True, retained=retained)
        client.verify_authentication()
        if retained:
            state = client.inspect_repository(str(selection.github_repository))
            completed.append(_completed_action(plan, "create-private-github", skipped=True))
        else:
            client.create_private_repository(str(selection.github_repository))
            retained = True
            completed.append(_completed_action(plan, "create-private-github"))
            stage = "REMOTE_CREATED_OR_VERIFIED"
            _persist_progress(plan, status="IN_PROGRESS", stage=stage, repository=repository, remote=remote, actions=completed, retryable=True, retained=True)
            state = client.inspect_repository(str(selection.github_repository))
        if not state.exists:
            raise KnowledgeSetupError("GITHUB_REPOSITORY_NOT_FOUND")
        if not state.empty:
            raise KnowledgeSetupError("GITHUB_NEW_REPOSITORY_NOT_EMPTY")
        descriptor = _assure_github_remote(plan, client, state)
        completed.append(_completed_action(plan, "verify-private-remote"))
        remote = _remote_document(plan, classification=descriptor.classification)
        stage = "REMOTE_CREATED_OR_VERIFIED"
        _persist_progress(plan, status="IN_PROGRESS", stage=stage, repository=repository, remote=remote, actions=completed, retryable=True, retained=True)
        connect_exact_remote(local.root, selection.remote_name, descriptor.remote)
        write_remote_assurance_receipt(selection.runtime_root, build_remote_assurance_receipt(descriptor))
        completed.append(_completed_action(plan, "connect-remote"))
        remote = _remote_document(plan, classification=descriptor.classification, connected=True)
        stage = "REMOTE_CONNECTED"
        _persist_progress(plan, status="IN_PROGRESS", stage=stage, repository=repository, remote=remote, actions=completed, retryable=True, retained=True)
        push_and_verify(local.root, selection.remote_name, selection.branch)
        completed.append(_completed_action(plan, "push-and-verify"))
        remote = _remote_document(plan, classification=descriptor.classification, connected=True, pushed=True)
        stage = "INITIAL_PUSH_VERIFIED"
        receipt = _persist_progress(plan, status="COMPLETE", stage=stage, repository=repository, remote=remote, actions=completed, retryable=False, retained=True)
        return _result_from_receipt(receipt)
    except (KnowledgeSetupError, KnowledgeRepositoryError, GitHubKnowledgeError, RemoteAssuranceError, SafeFilesystemError, OSError) as exc:
        code = getattr(exc, "code", "KNOWLEDGE_GITHUB_SETUP_FAILED")
        blocked = code in {
            "GITHUB_CREATE_CONFIRMATION_REQUIRED",
            "GITHUB_REPOSITORY_ALREADY_EXISTS",
            "GITHUB_NEW_REPOSITORY_NOT_EMPTY",
            "PRIVATE_REMOTE_REQUIRED",
            "ENGINE_REMOTE_REUSE",
            "KNOWLEDGE_REMOTE_FINGERPRINT_MISMATCH",
            "KNOWLEDGE_REMOTE_URL_CONFLICT",
        }
        receipt = _persist_progress(
            plan,
            status="BLOCKED" if blocked else "FAILED",
            stage=stage,
            repository=repository,
            remote=remote,
            actions=completed,
            retryable=not blocked,
            retained=retained,
            error_code=code if isinstance(code, str) and code else "KNOWLEDGE_GITHUB_SETUP_FAILED",
        )
        return _result_from_receipt(receipt)


def _github_existing(plan: KnowledgeSetupPlan, client: GitHubKnowledgeClient) -> KnowledgeSetupResult:
    selection = plan.selection
    repository: Mapping[str, object] = {
        "root": str(selection.knowledge_root),
        "status": "NOT_READY",
        "git_initialized": False,
        "root_digest": None,
    }
    remote = _remote_document(plan)
    completed: list[Mapping[str, object]] = []
    stage = "PLANNED"
    try:
        client.verify_authentication()
        state = client.inspect_repository(str(selection.github_repository))
        completed.append(_completed_action(plan, "inspect-private-github"))
        if not state.exists:
            raise KnowledgeSetupError("GITHUB_REPOSITORY_NOT_FOUND")
        if not state.empty and state.default_branch != selection.branch:
            raise KnowledgeSetupError("KNOWLEDGE_REMOTE_BRANCH_MISMATCH")
        descriptor = _assure_github_remote(plan, client, state)
        write_remote_assurance_receipt(selection.runtime_root, build_remote_assurance_receipt(descriptor))
        stage = "REMOTE_CREATED_OR_VERIFIED"
        remote = _remote_document(plan, classification=descriptor.classification)
        _persist_progress(plan, status="IN_PROGRESS", stage=stage, repository=repository, remote=remote, actions=completed, retryable=True, retained=True)

        existing = inspect_knowledge_repository(
            selection.knowledge_root,
            engine_root=selection.engine_root,
            runtime_root=selection.runtime_root,
        )
        restored = False
        pushed = False
        if not existing.initialized and not state.empty:
            local = _clone_existing_repository(plan, descriptor.remote)
            restored = True
        else:
            local = ensure_local_knowledge(plan)
            if local.dirty:
                raise KnowledgeSetupError("KNOWLEDGE_LOCAL_WORKTREE_DIRTY")
            if selection.remote_name in local.remote_names:
                connect_exact_remote(local.root, selection.remote_name, descriptor.remote)
                if state.empty:
                    push_and_verify(local.root, selection.remote_name, selection.branch)
                    pushed = True
                else:
                    _verify_existing_alignment(local.root, selection.remote_name, selection.branch)
            elif state.empty:
                connect_exact_remote(local.root, selection.remote_name, descriptor.remote)
                push_and_verify(local.root, selection.remote_name, selection.branch)
                pushed = True
            else:
                raise KnowledgeSetupError("KNOWLEDGE_HISTORY_ALIGNMENT_REQUIRED")
        repository = _repository_document(plan, local, restored=restored)
        completed.append(_completed_action(plan, "restore-or-connect-existing"))
        remote = _remote_document(plan, classification=descriptor.classification, connected=True, pushed=True)
        stage = "INITIAL_PUSH_VERIFIED"
        completed.append(_completed_action(plan, "verify-private-remote"))
        receipt = _persist_progress(plan, status="COMPLETE", stage=stage, repository=repository, remote=remote, actions=completed, retryable=False, retained=True)
        return _result_from_receipt(receipt)
    except (KnowledgeSetupError, KnowledgeRepositoryError, GitHubKnowledgeError, RemoteAssuranceError, SafeFilesystemError, OSError) as exc:
        code = getattr(exc, "code", "KNOWLEDGE_GITHUB_SETUP_FAILED")
        retryable = code in {
            "GITHUB_AUTH_REQUIRED",
            "GITHUB_RATE_LIMITED",
            "GITHUB_NETWORK_UNAVAILABLE",
            "GITHUB_COMMAND_TIMEOUT",
            "GIT_NETWORK_UNAVAILABLE",
            "GIT_COMMAND_TIMEOUT",
        }
        receipt = _persist_progress(
            plan,
            status="FAILED" if retryable else "BLOCKED",
            stage=stage,
            repository=repository,
            remote=remote,
            actions=completed,
            retryable=retryable,
            retained=True,
            error_code=code if isinstance(code, str) and code else "KNOWLEDGE_GITHUB_SETUP_FAILED",
        )
        return _result_from_receipt(receipt)


def apply_github_knowledge_setup(plan: KnowledgeSetupPlan) -> KnowledgeSetupResult:
    if not isinstance(plan, KnowledgeSetupPlan) or plan.selection.mode not in {"github-new", "github-existing"}:
        raise TypeError("GITHUB_KNOWLEDGE_SETUP_PLAN_REQUIRED")
    client = GitHubKnowledgeClient(plan.selection.github_executable)
    if plan.selection.mode == "github-new":
        return _github_new(plan, client)
    return _github_existing(plan, client)


__all__ = [
    "GitHubCommandResult",
    "GitHubKnowledgeClient",
    "GitHubKnowledgeError",
    "GitHubRepositoryState",
    "apply_github_knowledge_setup",
    "connect_exact_remote",
    "engine_remote_url",
    "ensure_local_knowledge",
    "push_and_verify",
]
