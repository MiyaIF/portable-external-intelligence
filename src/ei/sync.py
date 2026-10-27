from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .config import Settings
from .ids import machine_id
from .journal import JournalIntegrityError, iter_events, read_event
from .privacy import PrivacyError, assert_syncable, inspect_text
from .project import project_events, valid_projection_attributes
from .operation_runtime import _read_json
from .remote_assurance import RemoteAssuranceError, assure_remote, load_attestation, normalize_remote
from .safe_fs import (
    SafeFilesystemError,
    assert_safe_target,
    create_ownership_record,
    read_ownership_record,
    safe_atomic_write,
    safe_chmod,
    safe_copy_file,
    safe_ensure_directory,
    safe_mkdir,
    safe_remove_tree,
    safe_replace,
    safe_unlink,
    tree_digest,
    validate_ownership_record,
    write_ownership_record,
)
from .sync_policy import (
    DEFAULT_MANAGED_PATHS,
    MANAGED_ROOTS,
    configured_managed_paths,
    is_managed_path,
    managed_path_reason,
    normalize_repo_path,
    path_root,
    validate_managed_path_config,
)


ENGINE_PREFIXES = ("events/", "knowledge/")
RETRY_SECONDS = (300, 900, 3600, 21600)
_MAX_SYNC_FILE_BYTES = 2_000_000
_DEFAULT_REMOTE_RACE_RETRIES = 2


@dataclass
class _SyncAttempt:
    budget: object | None
    push_started: bool = False
    push_returncode: int | None = None
    worktree: Path | None = None


# Lexically scoped to sync_once; nested calls and other threads do not share a
# deadline. All internal runners, filesystem loops and finally blocks consult
# this same original object. No helper constructs a replacement allowance.
_ATTEMPT = ContextVar("ei_sync_attempt", default=None)


def _budget():
    attempt = _ATTEMPT.get()
    return attempt.budget if attempt is not None else None


def _check(budget=None):
    active = _budget() if budget is None else budget
    if active is not None:
        active.check()


def _can_continue():
    return _budget() is None or _budget().remaining_ms() > 0


def _checked(items):
    _check()
    for item in items:
        _check()
        yield item
    _check()


def _json_file(path, maximum=262144):
    _check()
    if _budget() is None:
        return json.loads(path.read_text(encoding="utf-8"))
    return _read_json(path, max_bytes=maximum, budget=_budget())


def _budget_args():
    return {"budget": _budget()} if _budget() is not None else {}


def _sync_file_bytes(path):
    _check()
    if _budget() is None:
        return path.read_bytes()
    from .index import _read_projection_bytes
    return _read_projection_bytes(path, budget=_budget(), maximum=_MAX_SYNC_FILE_BYTES)


def _sync_root(settings: Settings) -> Path:
    """Return the Git root whose data is allowed to be synchronized."""

    # Synchronization is deliberately personal-only.  Team events live in an
    # externally managed shared folder and must never become a Git target of
    # the personal sync operation.  Keep the legacy layout fallback for v1/v6
    # settings objects that do not expose the detached store view.
    stores = getattr(settings, "knowledge_stores", None)
    personal = getattr(stores, "personal", None)
    personal_root = getattr(personal, "root", None)
    if personal_root is not None and not settings.paths.legacy_layout:
        return Path(personal_root).expanduser().resolve()
    return Path(settings.paths.engine_root if settings.paths.legacy_layout else settings.paths.knowledge_root).expanduser().resolve()


@dataclass(frozen=True)
class _StatusEntry:
    path: str
    xy: str
    original_path: str | None = None


@dataclass(frozen=True)
class SyncPlan:
    allowed: bool
    reason_code: str
    stage_paths: list[str]
    unrelated_paths: tuple[str, ...] = ()
    review_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SyncResult:
    ok: bool
    reason_code: str
    retry_seconds: int | None = None
    staged_paths: tuple[str, ...] = ()
    commit_sha: str | None = None
    output: str = ""
    retry_at: str | None = None
    remote_attempt: int = 0
    recovery_command: str | None = None
    worktree_path: str | None = None
    preflight: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "reason_code": self.reason_code,
            "retry_seconds": self.retry_seconds,
            "staged_paths": list(self.staged_paths),
            "commit_sha": self.commit_sha,
            "output": self.output,
            "retry_at": self.retry_at,
            "remote_attempt": self.remote_attempt,
            "recovery_command": self.recovery_command,
            "worktree_path": self.worktree_path,
            "preflight": dict(self.preflight) if self.preflight else None,
        }


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _normalize_status_path(value: str) -> str:
    value = value.replace("\\", "/").strip()
    if " -> " in value:
        value = value.split(" -> ", 1)[1]
    return value.strip().strip('"')


def _status_entries(lines: Iterable[str]) -> list[_StatusEntry]:
    entries: list[_StatusEntry] = []
    for line in _checked(lines):
        if not isinstance(line, str) or not line.strip():
            continue
        if len(line) >= 3 and line[2] == " ":
            xy = line[:2]
            raw = line[3:]
        else:
            xy = "??"
            raw = line
        original: str | None = None
        if " -> " in raw:
            old, new = raw.split(" -> ", 1)
            original = _normalize_status_path(old)
            raw = new
        path = _normalize_status_path(raw)
        if path:
            entries.append(_StatusEntry(path, xy, original))
    return entries


def _status_path(line: str) -> str:
    entries = _status_entries((line,))
    return entries[0].path if entries else ""


def _safe_engine_path(value: str) -> bool:
    return is_managed_path(value)


def managed_paths(settings: Settings) -> Sequence[str]:
    """Return the locked repository-relative automatic-sync allowlist."""

    try:
        return configured_managed_paths(Path(settings.paths.engine_root))
    except (OSError, UnicodeError, ValueError):
        return DEFAULT_MANAGED_PATHS


def build_sync_plan(status_lines: Sequence[str], settings: Settings | None = None) -> SyncPlan:
    """Build a non-mutating plan from porcelain status output."""

    _check()
    if settings is not None:
        defaults_path = Path(settings.paths.engine_root) / "config" / "defaults.json"
        if defaults_path.exists():
            try:
                if _budget() is None:
                    configured_managed_paths(Path(settings.paths.engine_root))
                else:
                    document = _json_file(defaults_path)
                    sync = document.get("sync", {}) if isinstance(document, Mapping) else None
                    if not isinstance(sync, Mapping):
                        raise ValueError("SYNC_DEFAULTS_INVALID")
                    validate_managed_path_config(sync.get("managed_paths", list(DEFAULT_MANAGED_PATHS)))
            except TimeoutError:
                raise
            except (OSError, UnicodeError, ValueError):
                return SyncPlan(False, "SYNC_POLICY_INVALID", [])
    entries = _status_entries(status_lines)
    if not entries:
        return SyncPlan(False, "NO_ENGINE_CHANGES", [])

    managed: list[str] = []
    unrelated: list[str] = []
    review: list[str] = []
    unsafe: list[str] = []
    journal_mutations: list[str] = []
    for entry in _checked(entries):
        root = path_root(entry.path)
        if root in MANAGED_ROOTS and not is_managed_path(entry.path):
            unsafe.append(entry.path)
            continue
        reason = managed_path_reason(entry.path)
        if reason == "MANAGED_ENGINE_PATH":
            if entry.original_path is not None:
                journal_mutations.append(entry.path)
                continue
            flags = {flag for flag in entry.xy if flag != " "}
            if root == "events" and flags and flags.isdisjoint({"?", "A"}):
                journal_mutations.append(entry.path)
                continue
            managed.append(entry.path)
        elif reason == "REVIEW_REQUIRED_SOURCE_CHANGE":
            review.append(entry.path)
        elif reason == "MACHINE_LOCAL_PATH":
            unrelated.append(entry.path)
        else:
            unrelated.append(entry.path)

    if journal_mutations:
        return SyncPlan(False, "EVENT_JOURNAL_MODIFICATION_FORBIDDEN", [], tuple(sorted(journal_mutations)))
    if unsafe:
        return SyncPlan(False, "UNSAFE_ENGINE_PATH", [], tuple(sorted(unsafe)))
    if review:
        return SyncPlan(False, "REVIEW_REQUIRED_SOURCE_CHANGE", [], tuple(sorted(review)), tuple(sorted(review)))
    if unrelated:
        return SyncPlan(False, "UNRELATED_WORKTREE_CHANGES", [], tuple(sorted(unrelated)))
    if not managed:
        return SyncPlan(False, "NO_ENGINE_CHANGES", [])
    return SyncPlan(True, "ENGINE_PATHS_READY", sorted(set(managed)))


class FileLock:
    """Cross-platform exclusive lock with conservative stale-owner recovery."""

    def __init__(self, path: Path, stale_after_seconds: int = 6 * 60 * 60, *, budget=None):
        self.path = Path(path)
        self.stale_after_seconds = max(60, int(stale_after_seconds))
        self._fd: int | None = None
        self._token = uuid.uuid4().hex
        self.operation_budget = budget if budget is not None else _budget()
        self._identity = None
        self._stale_identity = None

    def _check(self):
        if self.operation_budget is not None:
            self.operation_budget.check()

    def _record(self, *, release=False):
        from .index import _read_projection_bytes
        raw = _read_projection_bytes(self.path, maximum=4096, budget=None if release else self.operation_budget)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("SYNC_LOCK_INVALID")
        return value

    @staticmethod
    def _pid_alive(pid: object) -> bool | None:
        from .spool import _pid_state
        return _pid_state(pid)

    def _stale(self) -> bool:
        self._check()
        try:
            raw = self._record()
            info = self.path.stat(follow_symlinks=False)
            self._stale_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except TimeoutError:
            raise
        except (OSError, UnicodeError, ValueError):
            return False
        pid = raw.get("pid") if isinstance(raw, Mapping) else None
        return self._pid_alive(pid) is False

    def __enter__(self) -> "FileLock":
        self._check()
        safe_ensure_directory(self.path.parent)
        self._check()
        assert_safe_target(self.path.parent, self.path, allow_missing=True, expected_type="file")
        payload = {
            "pid": os.getpid(),
            "machine_id": machine_id(),
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "token": self._token,
        }
        staging = self.path.with_name(self.path.name + "." + self._token + ".tmp")
        staging_identity = None
        try:
            self._check()
            self._fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            info = os.fstat(self._fd)
            self._identity = (info.st_dev, info.st_ino)
            staging_identity = self._identity
            self._check()
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if os.write(self._fd, encoded) != len(encoded):
                raise OSError("SYNC_LOCK_SHORT_WRITE")
            self._check()
            info = staging.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or staging_identity != (info.st_dev, info.st_ino) or info.st_nlink != 1:
                raise OSError("SYNC_LOCK_STAGING_REPLACED")
            self._check()
            try:
                os.link(staging, self.path)
            except FileExistsError as exc:
                if not self._stale():
                    raise RuntimeError("SYNC_LOCK_BUSY") from exc
                try:
                    self._check()
                    info = self.path.stat(follow_symlinks=False)
                    if self._stale_identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                        raise RuntimeError("SYNC_LOCK_BUSY")
                    safe_unlink(self.path.parent, self.path, allow_missing=True)
                except SafeFilesystemError as cleanup_error:
                    if cleanup_error.code != "SAFE_PATH_MISSING":
                        raise RuntimeError(cleanup_error.code) from cleanup_error
                self._check()
                try:
                    os.link(staging, self.path)
                except FileExistsError as retry_exc:
                    raise RuntimeError("SYNC_LOCK_BUSY") from retry_exc
            self._check()
        except BaseException:
            acquired = os.fstat(self._fd) if self._fd is not None else None
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            self._release_owned()
            self._release_staging(staging, acquired, expected_links=1)
            raise
        acquired = os.fstat(self._fd)
        os.close(self._fd)
        self._fd = None
        self._release_staging(staging, acquired, expected_links=2)
        return self

    def _release_staging(self, staging: Path, acquired, *, expected_links: int) -> None:
        # The private unpublished name is owned by its acquired descriptor.
        if acquired is None:
            return
        try:
            assert_safe_target(self.path.parent, staging, allow_missing=False, expected_type="file")
            info = staging.stat(follow_symlinks=False)
            if (stat.S_ISREG(info.st_mode) and stat.S_ISREG(acquired.st_mode)
                    and (info.st_dev, info.st_ino) == (acquired.st_dev, acquired.st_ino)
                    and info.st_nlink == expected_links):
                safe_unlink(self.path.parent, staging, allow_missing=True)
        except (OSError, ValueError):
            return

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._release_owned()

    def _release_owned(self):
        # Fixed 4KiB resource-release exception, even after the deadline. Only
        # this acquired token AND file identity authorize removal; no retries.
        try:
            raw = self._record(release=True)
            assert_safe_target(self.path.parent, self.path, allow_missing=False, expected_type="file")
            info = self.path.stat(follow_symlinks=False)
            if self._identity != (info.st_dev, info.st_ino) or raw.get("token") != self._token:
                return
            safe_unlink(self.path.parent, self.path, allow_missing=True)
        except (OSError, UnicodeError, ValueError):
            return


class GitRunner:
    def __init__(self, repo_root: Path, *, budget=None):
        self.operation_budget = budget if budget is not None else _budget()
        _check(self.operation_budget)
        self.repo_root = Path(repo_root).resolve()

    def run(self, args: Sequence[str]) -> CommandResult:
        _check(self.operation_budget)
        values = list(args)
        if not values or any(not isinstance(value, str) for value in values):
            raise ValueError("GIT_ARGUMENTS_INVALID")
        options = {}
        if self.operation_budget is not None:
            options = {"timeout": self.operation_budget.remaining_ms() / 1000,
                       "stdin": subprocess.DEVNULL,
                       "env": {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never",
                               "GH_PROMPT_DISABLED": "1", "GIT_ASKPASS": "", "SSH_ASKPASS": "",
                               "SSH_ASKPASS_REQUIRE": "never"}}
        try:
            completed = subprocess.run(values, cwd=self.repo_root, capture_output=True,
                                       text=True, check=False, shell=False, **options)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("OPERATION_BUDGET_EXHAUSTED") from exc
        _check(self.operation_budget)
        return CommandResult(completed.returncode, completed.stdout or "", completed.stderr or "")


def _run(runner: GitRunner | object, args: Sequence[str]) -> CommandResult:
    _check()
    attempt = _ATTEMPT.get()
    push = len(args) > 1 and args[0] == "git" and args[1] == "push"
    if push and attempt is not None:
        attempt.push_started = True
        attempt.push_returncode = None
    result = runner.run(args)
    if push and attempt is not None:
        attempt.push_returncode = int(getattr(result, "returncode", 1))
    _check()
    if isinstance(result, CommandResult):
        return result
    return CommandResult(
        int(getattr(result, "returncode", 1)),
        str(getattr(result, "stdout", "") or ""),
        str(getattr(result, "stderr", "") or ""),
    )


def classify_git_conflict(output: str) -> str:
    """Classify Git output without returning its potentially sensitive body."""

    text = str(output or "").casefold()
    semantic_markers = (
        "policies/",
        "policy/",
        "schemas/",
        "config/",
        "skills/",
        "hooks/",
        "src/",
        "templates/",
        "pyproject.toml",
        "requirements-",
    )
    if any(marker in text for marker in semantic_markers):
        return "SEMANTIC_POLICY_CONFLICT"
    if "events/" in text or ("event" in text and "conflict" in text):
        return "EVENT_FILE_CONFLICT"
    if "knowledge/" in text or "projection" in text:
        return "KNOWLEDGE_PROJECTION_CONFLICT"
    if any(marker in text for marker in ("non-fast-forward", "non fast forward", "fetch first", "rejected")):
        return "REMOTE_RACE"
    if any(marker in text for marker in ("could not resolve host", "network", "timed out", "timeout", "connection")):
        return "REMOTE_UNAVAILABLE"
    if any(marker in text for marker in ("authentication failed", "permission denied", "access denied", "403", "401")):
        return "REMOTE_AUTH_FAILED"
    if "conflict" in text or "merge conflict" in text:
        return "GIT_CONFLICT"
    return "GIT_ERROR"


def schedule_retry(reason_code: str, attempt: int, now: datetime) -> datetime:
    if not isinstance(reason_code, str) or not reason_code:
        raise ValueError("RETRY_REASON_INVALID")
    if type(attempt) is not int or attempt < 0:
        raise ValueError("RETRY_ATTEMPT_INVALID")
    return _utc_now(now) + timedelta(seconds=RETRY_SECONDS[min(attempt, len(RETRY_SECONDS) - 1)])


def _state_path(settings: Settings) -> Path:
    return Path(settings.paths.local_state_dir) / "sync-state.json"


def _load_state(settings: Settings) -> dict[str, object]:
    _check()
    try:
        value = _json_file(_state_path(settings))
    except TimeoutError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): value[key] for key in value if isinstance(key, str)}


def _save_state(settings: Settings, values: Mapping[str, object]) -> None:
    _check()
    path = _state_path(settings)
    safe_ensure_directory(path.parent)
    safe_values = {
        key: values[key]
        for key in (
            "offline_attempt",
            "remote_race_attempt",
            "last_reason_code",
            "last_status",
            "last_attempt_at",
            "next_retry_at",
            "last_commit_sha",
        )
        if key in values
    }
    _check()
    safe_atomic_write(
        Path(settings.paths.runtime_root),
        path,
        (json.dumps(safe_values, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )


def _record_state(settings: Settings, result: SyncResult, now: datetime) -> None:
    state = _load_state(settings)
    state.update(
        {
            "last_reason_code": result.reason_code,
            "last_status": "success" if result.ok else "blocked",
            "last_attempt_at": _utc_now(now).isoformat(),
            "remote_race_attempt": result.remote_attempt,
        }
    )
    if result.commit_sha:
        state["last_commit_sha"] = result.commit_sha
    if result.retry_at:
        state["next_retry_at"] = result.retry_at
    else:
        state.pop("next_retry_at", None)
    if result.ok:
        state["offline_attempt"] = 0
    _save_state(settings, state)


def _offline_result(
    settings: Settings,
    staged: tuple[str, ...],
    reason_code: str,
    now: datetime,
    *,
    commit_sha: str | None = None,
    remote_attempt: int = 0,
    output: str = "",
    worktree_path: str | None = None,
) -> SyncResult:
    state = _load_state(settings)
    attempt = state.get("offline_attempt", 0)
    if type(attempt) is not int or attempt < 0:
        attempt = 0
    retry_at = schedule_retry(reason_code, attempt, now)
    state.update(
        {
            "offline_attempt": attempt + 1,
            "remote_race_attempt": remote_attempt,
            "last_reason_code": reason_code,
            "last_status": "retryable",
            "last_attempt_at": _utc_now(now).isoformat(),
            "next_retry_at": retry_at.isoformat(),
        }
    )
    if commit_sha:
        state["last_commit_sha"] = commit_sha
    _save_state(settings, state)
    return SyncResult(
        False,
        "OFFLINE_RETRY_SCHEDULED",
        retry_seconds=int((retry_at - _utc_now(now)).total_seconds()),
        staged_paths=staged,
        commit_sha=commit_sha,
        output=output or reason_code,
        retry_at=retry_at.isoformat(),
        remote_attempt=remote_attempt,
        worktree_path=worktree_path,
    )


def _blocked_result(
    settings: Settings,
    reason_code: str,
    now: datetime,
    *,
    output: str = "",
    staged: tuple[str, ...] = (),
    commit_sha: str | None = None,
    remote_attempt: int = 0,
    worktree_path: str | None = None,
) -> SyncResult:
    result = SyncResult(
        False,
        reason_code,
        staged_paths=staged,
        commit_sha=commit_sha,
        output=output or reason_code,
        remote_attempt=remote_attempt,
        recovery_command="git status --porcelain; git diff --check",
        worktree_path=worktree_path,
    )
    _record_state(settings, result, now)
    return result


def _safe_repo_target(repo_root: Path, relative: str) -> Path:
    _check()
    normalized = normalize_repo_path(relative)
    root = Path(repo_root).resolve()
    try:
        return assert_safe_target(root, root / Path(*normalized.split("/")), allow_missing=True)
    except SafeFilesystemError as exc:
        raise PrivacyError(exc.code) from exc


def _validate_sync_file(repo_root: Path, relative: str, *, allow_missing: bool = False) -> None:
    target = _safe_repo_target(repo_root, relative)
    if not target.exists():
        if allow_missing:
            return
        raise PrivacyError("SYNC_FILE_MISSING")
    if target.is_symlink() or not target.is_file():
        raise PrivacyError("SYNC_FILE_NOT_REGULAR")
    try:
        if target.stat().st_size > _MAX_SYNC_FILE_BYTES:
            raise PrivacyError("PAYLOAD_TOO_LARGE")
        raw = _sync_file_bytes(target)
        if relative == "knowledge/.gitattributes" and not valid_projection_attributes(raw):
            raise PrivacyError("PROJECTION_ATTRIBUTES_CONFLICT")
        content = raw.decode("utf-8", errors="strict")
    except TimeoutError:
        raise
    except UnicodeError as exc:
        raise PrivacyError("SYNC_FILE_ENCODING_INVALID") from exc
    except OSError as exc:
        raise PrivacyError("SYNC_FILE_READ_FAILED") from exc
    try:
        assert_syncable(inspect_text(content, "private-reusable", relative))
    except PrivacyError:
        raise
    if path_root(relative) == "events":
        try:
            read_event(target, **_budget_args())
        except TimeoutError:
            raise
        except (JournalIntegrityError, OSError, UnicodeError, ValueError) as exc:
            raise PrivacyError("EVENT_SCHEMA_INVALID") from exc
    elif target.suffix.casefold() == ".json":
        try:
            value = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PrivacyError("PROJECTION_JSON_INVALID") from exc
        if not isinstance(value, (dict, list)):
            raise PrivacyError("PROJECTION_JSON_INVALID")


def _validate_plan_files(repo_root: Path, entries: Sequence[_StatusEntry], plan: SyncPlan) -> None:
    by_path = {entry.path: entry for entry in _checked(entries)}
    for relative in _checked(plan.stage_paths):
        entry = by_path.get(relative)
        allow_missing = path_root(relative) == "knowledge"
        target = _safe_repo_target(repo_root, relative)
        if not target.exists() and path_root(relative) == "events":
            raise PrivacyError("EVENT_FILE_MISSING")
        if target.exists():
            _validate_sync_file(repo_root, relative)
        elif allow_missing:
            _validate_sync_file(repo_root, relative, allow_missing=True)
        if entry is not None and path_root(relative) == "events":
            flags = {flag for flag in entry.xy if flag != " "}
            if flags and flags.isdisjoint({"?", "A"}):
                raise PrivacyError("EVENT_JOURNAL_MODIFICATION_FORBIDDEN")


def _validated_status(runner: GitRunner | object, settings: Settings) -> tuple[SyncPlan, list[_StatusEntry], CommandResult]:
    status_result = _run(runner, ["git", "status", "--porcelain", "--untracked-files=all"])
    if status_result.returncode != 0:
        return SyncPlan(False, "GIT_STATUS_FAILED", []), [], status_result
    entries = _status_entries(status_result.stdout.splitlines())
    plan = build_sync_plan(status_result.stdout.splitlines(), settings)
    if plan.allowed:
        by_path = {entry.path: entry for entry in entries}
        material_paths = [
            path
            for path in plan.stage_paths
            if _status_entry_has_material_change(runner, by_path[path])
        ]
        if not material_paths:
            plan = SyncPlan(False, "NO_ENGINE_CHANGES", [])
        elif material_paths != plan.stage_paths:
            plan = SyncPlan(
                True,
                plan.reason_code,
                material_paths,
                plan.unrelated_paths,
                plan.review_paths,
            )
    return plan, entries, status_result


def _status_entry_has_material_change(runner: GitRunner | object, entry: _StatusEntry) -> bool:
    """Reject stat/line-ending-only porcelain entries without mutating the index."""

    if entry.xy == "??":
        return True
    index_flag, worktree_flag = (entry.xy + "  ")[:2]
    if index_flag not in {" ", "?", "!"}:
        cached = _run(runner, ["git", "diff", "--cached", "--quiet", "--", entry.path])
        if cached.returncode != 0:
            return True
    if worktree_flag not in {" ", "?", "!"}:
        working = _run(runner, ["git", "diff", "--quiet", "--", entry.path])
        if working.returncode != 0:
            return True
    return False


def _preflight_git(runner: GitRunner | object, settings: Settings) -> str | None:
    root_result = _run(runner, ["git", "rev-parse", "--show-toplevel"])
    if root_result.returncode != 0:
        return "GIT_REPOSITORY_INVALID"
    cached_result = _run(runner, ["git", "diff", "--cached", "--name-only"])
    if cached_result.returncode != 0:
        return "GIT_INDEX_READ_FAILED"
    for raw in _checked(cached_result.stdout.splitlines()):
        path = _normalize_status_path(raw)
        if path and not is_managed_path(path):
            return "PREEXISTING_STAGED_UNRELATED_CHANGE"
    check_result = _run(runner, ["git", "diff", "--check"])
    if check_result.returncode != 0:
        return "GIT_WHITESPACE_CHECK_FAILED"
    return None


def _valid_git_ref(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not value.startswith("-") and "\x00" not in value


def _remote_settings_valid(settings: Settings) -> bool:
    return _valid_git_ref(getattr(settings, "sync_remote", "")) and _valid_git_ref(getattr(settings, "sync_branch", ""))


def _remote_url(runner: GitRunner, remote_name: str = "origin") -> str | None:
    if not _valid_git_ref(remote_name):
        return None
    result = _run(runner, ["git", "remote", "get-url", remote_name])
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.strip().splitlines()[0]


def _attestation_for(settings: Settings, fingerprint: str) -> Mapping[str, object] | None:
    _check()
    directory = Path(settings.paths.runtime_root) / "remote-assurance"
    target = directory / (fingerprint.removeprefix("sha256:") + ".json")
    if not target.is_file():
        return None
    try:
        if _budget() is None:
            return load_attestation(target)
        from .remote_assurance import _validate_assurance_receipt
        return _validate_assurance_receipt(_json_file(target))
    except RemoteAssuranceError:
        return None


def _remote_assurance_reason(settings: Settings) -> str | None:
    root_runner = GitRunner(_sync_root(settings))
    remote = _remote_url(root_runner, str(settings.sync_remote))
    if remote is None:
        if settings.paths.legacy_layout:
            return None
        return "KNOWLEDGE_REMOTE_REQUIRED"
    if settings.paths.legacy_layout:
        try:
            if normalize_remote(remote).startswith("file:"):
                return None
        except RemoteAssuranceError:
            return "REMOTE_INVALID"
    from .remote_assurance import remote_fingerprint

    fingerprint = remote_fingerprint(remote)
    expected_fingerprint = getattr(settings, "sync_remote_fingerprint", None)
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        return "REMOTE_FINGERPRINT_MISMATCH"
    assurance = _attestation_for(settings, fingerprint)
    if assurance is None:
        return "REMOTE_ASSURANCE_MISSING"
    if assurance.get("remote_fingerprint") != fingerprint:
        return "REMOTE_FINGERPRINT_MISMATCH"
    expected_classification = getattr(settings, "sync_remote_classification", None)
    if expected_classification is not None and assurance.get("classification") != expected_classification:
        return "REMOTE_CLASSIFICATION_MISMATCH"
    engine_remote = _remote_url(GitRunner(Path(settings.paths.engine_root)), str(settings.sync_remote))
    try:
        assure_remote(
            remote,
            engine_remote=engine_remote,
            attestation=assurance,
            data_classification="private-reusable",
            **_budget_args(),
        )
    except RemoteAssuranceError as exc:
        return exc.code
    return None


def _commit_message(now: datetime) -> str:
    return f"data: sync external intelligence {_utc_now(now).date().isoformat()}"


def _commit_sha(runner: GitRunner | object) -> str | None:
    result = _run(runner, ["git", "rev-parse", "HEAD"])
    if result.returncode != 0:
        return None
    value = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    return value if value and all(character in "0123456789abcdefABCDEF" for character in value) else None


def _cached_paths(runner: GitRunner | object) -> tuple[str, ...] | None:
    result = _run(runner, ["git", "diff", "--cached", "--name-only"])
    if result.returncode != 0:
        return None
    paths = tuple(sorted({_normalize_status_path(line) for line in result.stdout.splitlines() if _normalize_status_path(line)}))
    return paths


def _stage_and_commit(runner: GitRunner | object, paths: Sequence[str], now: datetime) -> tuple[bool, str, tuple[str, ...], str | None]:
    for relative in _checked(sorted(set(paths))):
        stage_result = _run(runner, ["git", "add", "--", relative])
        if stage_result.returncode != 0:
            return False, "GIT_STAGE_FAILED", tuple(sorted(set(paths))), None
    cached = _cached_paths(runner)
    if cached is None:
        return False, "GIT_INDEX_READ_FAILED", tuple(sorted(set(paths))), None
    if any(not is_managed_path(path) for path in cached):
        return False, "STAGED_PATH_OUTSIDE_ALLOWLIST", tuple(sorted(set(paths))), None
    diff_result = _run(runner, ["git", "diff", "--cached", "--check"])
    if diff_result.returncode != 0:
        whitespace_lines = (diff_result.stdout + "\n" + diff_result.stderr).splitlines()
        if any(line.startswith("events/") for line in whitespace_lines):
            return False, "GIT_STAGED_WHITESPACE_FAILED", tuple(sorted(set(paths))), None
    quiet_result = _run(runner, ["git", "diff", "--cached", "--quiet"])
    if quiet_result.returncode == 0:
        return True, "NO_STAGED_CHANGES", tuple(sorted(set(paths))), _commit_sha(runner)
    commit_result = _run(runner, ["git", "commit", "-m", _commit_message(now)])
    if commit_result.returncode != 0:
        return False, "GIT_COMMIT_FAILED", tuple(sorted(set(paths))), None
    return True, "COMMITTED", tuple(sorted(set(paths))), _commit_sha(runner)


def _local_commit_for_retry(settings: Settings, plan: SyncPlan, now: datetime) -> tuple[str | None, str | None]:
    runner = GitRunner(_sync_root(settings))
    ok, reason, _, sha = _stage_and_commit(runner, plan.stage_paths, now)
    if not ok:
        return None, reason
    return sha, None


def _sync_in_place(settings: Settings, runner: GitRunner | object, now: datetime) -> SyncResult:
    if bool(getattr(settings, "sync_enabled", False)):
        assurance_reason = _remote_assurance_reason(settings)
        if assurance_reason:
            return _blocked_result(settings, assurance_reason, now)
    plan, entries, _ = _validated_status(runner, settings)
    if not plan.allowed:
        result = SyncResult(
            plan.reason_code == "NO_ENGINE_CHANGES",
            plan.reason_code,
            output="" if plan.reason_code == "NO_ENGINE_CHANGES" else plan.reason_code,
        )
        _record_state(settings, result, now)
        return result
    preflight_reason = _preflight_git(runner, settings)
    if preflight_reason:
        return _blocked_result(settings, preflight_reason, now)
    try:
        _validate_plan_files(_sync_root(settings), entries, plan)
    except PrivacyError as exc:
        return _blocked_result(settings, "PRIVACY_REJECTED", now, output=exc.reason_code, staged=tuple(plan.stage_paths))
    committed, reason, staged, sha = _stage_and_commit(runner, plan.stage_paths, now)
    if not committed:
        return _blocked_result(settings, reason, now, staged=staged)
    if reason == "NO_STAGED_CHANGES":
        result = SyncResult(True, reason, staged_paths=staged, commit_sha=sha)
        _record_state(settings, result, now)
        return result
    if not bool(getattr(settings, "sync_enabled", False)):
        result = SyncResult(True, "LOCAL_COMMIT_ONLY", staged_paths=staged, commit_sha=sha)
        _record_state(settings, result, now)
        return result
    if not _remote_settings_valid(settings):
        return _blocked_result(settings, "GIT_REMOTE_INVALID", now, staged=staged, commit_sha=sha)
    assurance_reason = _remote_assurance_reason(settings)
    if assurance_reason:
        return _blocked_result(settings, assurance_reason, now, staged=staged, commit_sha=sha)
    fetch_result = _run(runner, ["git", "fetch", str(settings.sync_remote)])
    if fetch_result.returncode != 0:
        return _offline_result(settings, staged, "GIT_FETCH_FAILED", now, commit_sha=sha)
    remote_ref = f"refs/remotes/{settings.sync_remote}/{settings.sync_branch}"
    verify_remote = _run(runner, ["git", "rev-parse", "--verify", remote_ref])
    if verify_remote.returncode == 0:
        rebase_result = _run(runner, ["git", "rebase", f"{settings.sync_remote}/{settings.sync_branch}"])
        if rebase_result.returncode != 0:
            _run(runner, ["git", "rebase", "--abort"])
            conflict = classify_git_conflict(rebase_result.stdout + "\n" + rebase_result.stderr)
            return _blocked_result(settings, "SYNC_BLOCKED", now, output=conflict, staged=staged, commit_sha=sha)
        sha = _commit_sha(runner) or sha
    assurance_reason = _remote_assurance_reason(settings)
    if assurance_reason:
        return _blocked_result(settings, assurance_reason, now, staged=staged, commit_sha=sha)
    push_result = _run(runner, ["git", "push", str(settings.sync_remote), f"HEAD:refs/heads/{settings.sync_branch}"])
    if push_result.returncode != 0:
        conflict = classify_git_conflict(push_result.stdout + "\n" + push_result.stderr)
        if conflict == "REMOTE_RACE":
            return _offline_result(settings, staged, "GIT_PUSH_RACE", now, commit_sha=sha, output=conflict)
        if conflict == "REMOTE_AUTH_FAILED":
            return _blocked_result(settings, "GIT_AUTH_FAILED", now, output=conflict, staged=staged, commit_sha=sha)
        return _offline_result(settings, staged, "GIT_PUSH_FAILED", now, commit_sha=sha, output=conflict)
    result = SyncResult(True, "SYNCED", staged_paths=staged, commit_sha=sha)
    _record_state(settings, result, now)
    return result


def _worktree_paths(settings: Settings, source_root: Path) -> tuple[Path, Path]:
    _check()
    runtime = Path(settings.paths.runtime_root).resolve()
    name = "sync-worktree"
    try:
        config_root = Path(settings.paths.engine_root)
        defaults = _json_file(Path(config_root) / "config" / "defaults.json")
        sync = defaults.get("sync", {}) if isinstance(defaults, Mapping) else {}
        configured = sync.get("worktree_name") if isinstance(sync, Mapping) else None
        if isinstance(configured, str) and configured and configured not in {".", ".."} and "/" not in configured and "\\" not in configured:
            name = configured
    except TimeoutError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        name = "sync-worktree"
    target = runtime / name
    ownership = runtime / f"{name}.ownership.json"
    try:
        target.relative_to(source_root.resolve())
    except ValueError:
        return target, ownership
    raise ValueError("SYNC_WORKTREE_INSIDE_REPOSITORY")


def _create_worktree(source_runner: GitRunner, settings: Settings) -> tuple[Path, Path]:
    _check()
    source_root = source_runner.repo_root
    target, ownership = _worktree_paths(settings, source_root)
    runtime = Path(settings.paths.runtime_root).resolve()
    safe_ensure_directory(runtime)
    assert_safe_target(runtime, target.parent, allow_root=True, allow_missing=False, expected_type="dir")
    if target.exists():
        try:
            record = _json_file(ownership) if _budget() is not None else read_ownership_record(ownership, root=runtime)
            validate_ownership_record(record, runtime, target, kind="sync-worktree")
        except TimeoutError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise RuntimeError("SYNC_WORKTREE_OWNERSHIP_UNKNOWN") from exc
        authorities = record.get("authority_roots") if isinstance(record, Mapping) else None
        if not isinstance(authorities, Mapping) or authorities.get("source_root") != str(source_root):
            raise RuntimeError("SYNC_WORKTREE_OWNERSHIP_UNKNOWN")
        try:
            safe_remove_tree(runtime, target, owner=record, kind="sync-worktree", **_budget_args())
            _check()
            safe_unlink(runtime, ownership, allow_missing=True)
        except SafeFilesystemError as exc:
            raise RuntimeError(exc.code) from exc
        _run(source_runner, ["git", "worktree", "prune"])
    elif ownership.exists() or ownership.is_symlink():
        raise RuntimeError("SYNC_WORKTREE_OWNERSHIP_UNKNOWN")
    record = create_ownership_record(
        runtime,
        target,
        kind="sync-worktree",
        authority_roots={"source_root": source_root},
    )
    _check()
    write_ownership_record(ownership, record, root=runtime)
    attempt = _ATTEMPT.get()
    if attempt is not None:
        attempt.worktree = target
    add_result = _run(source_runner, ["git", "worktree", "add", "--detach", str(target), "HEAD"])
    if add_result.returncode != 0:
        try:
            if target.exists():
                safe_remove_tree(runtime, target, owner=record, kind="sync-worktree", allow_missing=True, **_budget_args())
            _check()
            safe_unlink(runtime, ownership, allow_missing=True)
        except SafeFilesystemError as cleanup_error:
            raise RuntimeError("SYNC_WORKTREE_CREATE_CLEANUP_FAILED") from cleanup_error
        raise RuntimeError("SYNC_WORKTREE_CREATE_FAILED")
    record = dict(record)
    record["expected_digest"] = tree_digest(target, **_budget_args())
    _check()
    write_ownership_record(ownership, record, root=runtime)
    return target, ownership


def _cleanup_worktree(source_runner: GitRunner, worktree: Path, ownership: Path) -> str | None:
    try:
        _check()
        runtime = ownership.parent
        record = _json_file(ownership) if _budget() is not None else read_ownership_record(ownership, root=runtime)
        validate_ownership_record(record, runtime, worktree, kind="sync-worktree")
        authorities = record.get("authority_roots") if isinstance(record, Mapping) else None
        if not isinstance(authorities, Mapping) or authorities.get("source_root") != str(source_runner.repo_root):
            return "SYNC_WORKTREE_OWNERSHIP_UNKNOWN"
        remove_result = _run(
            source_runner,
            ["git", "worktree", "remove", "--force", str(worktree)],
        )
        if remove_result.returncode != 0 and worktree.exists():
            safe_remove_tree(runtime, worktree, owner=record, kind="sync-worktree", **_budget_args())
        elif worktree.exists():
            safe_remove_tree(runtime, worktree, owner=record, kind="sync-worktree", **_budget_args())
        prune_result = _run(source_runner, ["git", "worktree", "prune"])
        if prune_result.returncode != 0 or worktree.exists():
            return "SYNC_WORKTREE_CLEANUP_FAILED"
        _check()
        safe_unlink(runtime, ownership, allow_missing=True)
        return None
    except TimeoutError:
        raise
    except (OSError, ValueError):
        return "SYNC_WORKTREE_CLEANUP_FAILED"


def _recover_owned_worktree(source_runner: GitRunner, settings: Settings) -> str | None:
    _check()
    worktree, ownership = _worktree_paths(settings, source_runner.repo_root)
    worktree_present = worktree.exists() or worktree.is_symlink()
    ownership_present = ownership.exists() or ownership.is_symlink()
    if not worktree_present and not ownership_present:
        return None
    if not ownership_present:
        return "SYNC_WORKTREE_OWNERSHIP_UNKNOWN"
    return _cleanup_worktree(source_runner, worktree, ownership)


def _copy_engine_changes(source_root: Path, worktree_root: Path, paths: Sequence[str]) -> None:
    for relative in _checked(paths):
        source = _safe_repo_target(source_root, relative)
        target = _safe_repo_target(worktree_root, relative)
        if source.exists():
            if source.is_symlink() or not source.is_file():
                raise PrivacyError("SYNC_FILE_NOT_REGULAR")
            if path_root(relative) == "events" and target.exists():
                # A normal text checkout can have CRLF while the immutable
                # source event was serialized with LF. Never rewrite an
                # existing journal record merely to change that encoding.
                if read_event(source, **_budget_args()).to_dict() != read_event(target, **_budget_args()).to_dict():
                    raise PrivacyError("EVENT_JOURNAL_MODIFICATION_FORBIDDEN")
                continue
            _check()
            if _budget() is not None:
                raw = _sync_file_bytes(source)
                _check()
                safe_mkdir(worktree_root, target.parent, parents=True)
                _check()
                safe_atomic_write(worktree_root, target, raw)
                continue
            safe_mkdir(worktree_root, target.parent, parents=True)
            temporary = target.with_name(target.name + f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
            safe_copy_file(source_root, source, worktree_root, temporary)
            safe_replace(worktree_root, temporary, worktree_root, target, source_type="file")
        elif path_root(relative) == "knowledge" and target.exists():
            if target.is_symlink() or not target.is_file():
                raise PrivacyError("SYNC_FILE_NOT_REGULAR")
            _check()
            safe_unlink(worktree_root, target)
        elif path_root(relative) == "events":
            raise PrivacyError("EVENT_FILE_MISSING")


def _fetch_and_rebase(worktree_runner: GitRunner, settings: Settings) -> tuple[str, str | None]:
    fetch_result = _run(worktree_runner, ["git", "fetch", str(settings.sync_remote)])
    if fetch_result.returncode != 0:
        return "GIT_FETCH_FAILED", fetch_result.stdout + "\n" + fetch_result.stderr
    remote_ref = f"refs/remotes/{settings.sync_remote}/{settings.sync_branch}"
    verify_remote = _run(worktree_runner, ["git", "rev-parse", "--verify", remote_ref])
    if verify_remote.returncode != 0:
        return "REMOTE_BRANCH_ABSENT", None
    rebase_result = _run(worktree_runner, ["git", "rebase", f"{settings.sync_remote}/{settings.sync_branch}"])
    if rebase_result.returncode != 0:
        _run(worktree_runner, ["git", "rebase", "--abort"])
        return "SYNC_BLOCKED", classify_git_conflict(rebase_result.stdout + "\n" + rebase_result.stderr)
    return "READY", None


def _project_and_commit(worktree_root: Path, worktree_runner: GitRunner, settings: Settings, now: datetime) -> tuple[str, tuple[str, ...], str | None]:
    try:
        _check()
        project_events(iter_events(worktree_root / "events", **_budget_args()), worktree_root / "knowledge", **_budget_args())
    except TimeoutError:
        raise
    except (OSError, UnicodeError, ValueError, JournalIntegrityError) as exc:
        return "PROJECTION_FAILED", (), type(exc).__name__
    plan, entries, _ = _validated_status(worktree_runner, settings)
    if not plan.allowed:
        if plan.reason_code == "NO_ENGINE_CHANGES":
            return "NO_ENGINE_CHANGES", (), None
        return plan.reason_code, tuple(plan.stage_paths), None
    try:
        _validate_plan_files(worktree_root, entries, plan)
    except PrivacyError as exc:
        return "PRIVACY_REJECTED", tuple(plan.stage_paths), exc.reason_code
    ok, reason, staged, sha = _stage_and_commit(worktree_runner, plan.stage_paths, now)
    if not ok:
        return reason, staged, None
    return reason, staged, sha


def _reconcile_source_after_push(source_runner: GitRunner, settings: Settings, commit_sha: str | None, paths: Sequence[str]) -> bool:
    """Keep source bytes until an exact, already-remote commit can fast-forward.

    Staging identical managed blobs is recoverable across interruption. Never
    delete an untracked body to make Git accept an otherwise unsafe merge.
    """
    if not isinstance(commit_sha, str) or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_sha) is None:
        return False
    allowed = set(paths)
    if any(not is_managed_path(path) for path in _checked(allowed)):
        return False
    if _preflight_git(source_runner, settings) or _remote_assurance_reason(settings):
        return False
    if _run(source_runner, ["git", "fetch", str(settings.sync_remote)]).returncode != 0:
        return False
    remote_ref = f"refs/remotes/{settings.sync_remote}/{settings.sync_branch}"
    for args in (["cat-file", "-e", f"{commit_sha}^{{commit}}"],
                 ["merge-base", "--is-ancestor", commit_sha, remote_ref],
                 ["merge-base", "--is-ancestor", "HEAD", commit_sha]):
        if _run(source_runner, ["git", *args]).returncode != 0:
            return False

    def checked_entries():
        plan, entries, status = _validated_status(source_runner, settings)
        if status.returncode != 0 or (not plan.allowed and plan.reason_code != "NO_ENGINE_CHANGES"):
            return None
        if any(entry.path not in allowed or entry.original_path is not None for entry in _checked(entries)):
            return None
        return entries

    def matches(entry):
        relative = entry.path
        target = _safe_repo_target(source_runner.repo_root, relative)
        expected = _run(source_runner, ["git", "rev-parse", "--verify", f"{commit_sha}:{relative}"])
        if not target.exists():
            return path_root(relative) == "knowledge" and expected.returncode != 0 and "D" in entry.xy
        _validate_sync_file(source_runner.repo_root, relative)
        if expected.returncode != 0:
            return False
        raw = _run(source_runner, ["git", "hash-object", "--no-filters", "--", relative])
        if raw.returncode != 0 or raw.stdout.strip() != expected.stdout.strip():
            return False
        if entry.xy[0] not in {" ", "?"}:
            cached = _run(source_runner, ["git", "rev-parse", "--verify", f":{relative}"])
            if cached.returncode != 0 or cached.stdout.strip() != expected.stdout.strip():
                return False
        return True

    entries = checked_entries()
    if entries is None or any(not matches(entry) for entry in _checked(entries)):
        return False
    for entry in _checked(entries):
        if not matches(entry) or _run(source_runner, ["git", "add", "--", entry.path]).returncode != 0:
            return False
    # Recheck the complete status and staged blobs after staging, so a newly
    # introduced unrelated or different staged change is never carried along.
    final = checked_entries()
    if final is None or any(not matches(entry) for entry in _checked(final)):
        return False
    merged = _run(source_runner, ["git", "merge", "--ff-only", commit_sha])
    return merged.returncode == 0 and _commit_sha(source_runner) == commit_sha


def _sync_dedicated_worktree(settings: Settings, now: datetime) -> SyncResult:
    source_runner = GitRunner(_sync_root(settings))
    recovery_reason = _recover_owned_worktree(source_runner, settings)
    if recovery_reason:
        return _blocked_result(settings, recovery_reason, now)
    assurance_reason = _remote_assurance_reason(settings)
    if assurance_reason:
        return _blocked_result(settings, assurance_reason, now)
    plan, entries, _ = _validated_status(source_runner, settings)
    if not plan.allowed:
        result = SyncResult(
            plan.reason_code == "NO_ENGINE_CHANGES",
            plan.reason_code,
            output="" if plan.reason_code == "NO_ENGINE_CHANGES" else plan.reason_code,
        )
        _record_state(settings, result, now)
        return result
    preflight_reason = _preflight_git(source_runner, settings)
    if preflight_reason:
        return _blocked_result(settings, preflight_reason, now)
    if not _remote_settings_valid(settings):
        return _blocked_result(settings, "GIT_REMOTE_INVALID", now, staged=tuple(plan.stage_paths))
    try:
        _validate_plan_files(_sync_root(settings), entries, plan)
    except PrivacyError as exc:
        return _blocked_result(settings, "PRIVACY_REJECTED", now, output=exc.reason_code, staged=tuple(plan.stage_paths))

    worktree: Path | None = None
    ownership: Path | None = None
    result: SyncResult | None = None
    try:
        worktree, ownership = _create_worktree(source_runner, settings)
        worktree_runner = GitRunner(worktree)
        assurance_reason = _remote_assurance_reason(settings)
        if assurance_reason:
            result = _blocked_result(settings, assurance_reason, now, staged=tuple(plan.stage_paths), worktree_path=str(worktree))
            return result
        fetch_reason, fetch_detail = _fetch_and_rebase(worktree_runner, settings)
        if fetch_reason == "GIT_FETCH_FAILED":
            sha, local_error = _local_commit_for_retry(settings, plan, now)
            if local_error:
                result = _blocked_result(settings, local_error, now, staged=tuple(plan.stage_paths), worktree_path=str(worktree))
            else:
                result = _offline_result(settings, tuple(plan.stage_paths), fetch_reason, now, commit_sha=sha, worktree_path=str(worktree), output="GIT_FETCH_FAILED")
            return result
        if fetch_reason == "SYNC_BLOCKED":
            result = _blocked_result(settings, "SYNC_BLOCKED", now, output=fetch_detail or "GIT_CONFLICT", staged=tuple(plan.stage_paths), worktree_path=str(worktree))
            return result
        _copy_engine_changes(source_runner.repo_root, worktree, plan.stage_paths)
        reason, staged, sha = _project_and_commit(worktree, worktree_runner, settings, now)
        if reason in {"PRIVACY_REJECTED", "EVENT_JOURNAL_MODIFICATION_FORBIDDEN", "UNSAFE_ENGINE_PATH", "REVIEW_REQUIRED_SOURCE_CHANGE", "UNRELATED_WORKTREE_CHANGES", "PROJECTION_FAILED", "STAGED_PATH_OUTSIDE_ALLOWLIST"}:
            result = _blocked_result(settings, reason, now, output=sha or reason, staged=staged, worktree_path=str(worktree))
            return result
        if reason in {"NO_ENGINE_CHANGES", "NO_STAGED_CHANGES"}:
            sha = sha or _commit_sha(worktree_runner)
            reconciled = _reconcile_source_after_push(source_runner, settings, sha, plan.stage_paths)
            result = SyncResult(reconciled, "NO_ENGINE_CHANGES" if reconciled else "SYNC_SOURCE_RECONCILIATION_PENDING", staged_paths=staged, commit_sha=sha, worktree_path=str(worktree))
            _record_state(settings, result, now)
            return result
        if reason != "COMMITTED":
            result = _blocked_result(settings, reason, now, staged=staged, worktree_path=str(worktree))
            return result

        max_races = _DEFAULT_REMOTE_RACE_RETRIES
        try:
            defaults = _json_file(Path(settings.paths.engine_root) / "config" / "defaults.json")
            sync = defaults.get("sync", {}) if isinstance(defaults, Mapping) else {}
            configured = sync.get("remote_race_retries") if isinstance(sync, Mapping) else None
            if type(configured) is int and 0 <= configured <= 5:
                max_races = configured
        except TimeoutError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            max_races = _DEFAULT_REMOTE_RACE_RETRIES
        for remote_attempt in _checked(range(max_races + 1)):
            assurance_reason = _remote_assurance_reason(settings)
            if assurance_reason:
                result = _blocked_result(settings, assurance_reason, now, staged=staged, commit_sha=sha, remote_attempt=remote_attempt, worktree_path=str(worktree))
                return result
            push_result = _run(worktree_runner, ["git", "push", str(settings.sync_remote), f"HEAD:refs/heads/{settings.sync_branch}"])
            if push_result.returncode == 0:
                pushed_sha = _commit_sha(worktree_runner) or sha
                reconciled = _reconcile_source_after_push(source_runner, settings, pushed_sha, plan.stage_paths)
                result = SyncResult(reconciled, "SYNCED" if reconciled else "SYNC_SOURCE_RECONCILIATION_PENDING", staged_paths=staged, commit_sha=pushed_sha, remote_attempt=remote_attempt, worktree_path=str(worktree), preflight={"push_started": True, "push_returncode": 0, "source_reconciled": reconciled})
                _record_state(settings, result, now)
                return result
            conflict = classify_git_conflict(push_result.stdout + "\n" + push_result.stderr)
            if conflict == "REMOTE_RACE" and remote_attempt < max_races:
                assurance_reason = _remote_assurance_reason(settings)
                if assurance_reason:
                    result = _blocked_result(settings, assurance_reason, now, staged=staged, commit_sha=sha, remote_attempt=remote_attempt + 1, worktree_path=str(worktree))
                    return result
                retry_reason, detail = _fetch_and_rebase(worktree_runner, settings)
                if retry_reason == "GIT_FETCH_FAILED":
                    result = _offline_result(settings, staged, retry_reason, now, commit_sha=sha, remote_attempt=remote_attempt + 1, worktree_path=str(worktree), output="GIT_FETCH_FAILED")
                    return result
                if retry_reason == "SYNC_BLOCKED":
                    result = _blocked_result(settings, "SYNC_BLOCKED", now, output=detail or "GIT_CONFLICT", staged=staged, commit_sha=sha, remote_attempt=remote_attempt + 1, worktree_path=str(worktree))
                    return result
                reproj_reason, reproj_staged, reproj_sha = _project_and_commit(worktree, worktree_runner, settings, now)
                if reproj_reason in {"PRIVACY_REJECTED", "PROJECTION_FAILED", "STAGED_PATH_OUTSIDE_ALLOWLIST", "UNRELATED_WORKTREE_CHANGES", "REVIEW_REQUIRED_SOURCE_CHANGE", "EVENT_JOURNAL_MODIFICATION_FORBIDDEN"}:
                    result = _blocked_result(settings, reproj_reason, now, output=reproj_sha or reproj_reason, staged=reproj_staged, commit_sha=sha, remote_attempt=remote_attempt + 1, worktree_path=str(worktree))
                    return result
                staged = reproj_staged or staged
                sha = reproj_sha or _commit_sha(worktree_runner) or sha
                continue
            if conflict == "SEMANTIC_POLICY_CONFLICT":
                result = _blocked_result(settings, "SYNC_BLOCKED", now, output=conflict, staged=staged, commit_sha=sha, remote_attempt=remote_attempt, worktree_path=str(worktree))
                return result
            if conflict == "REMOTE_AUTH_FAILED":
                result = _blocked_result(settings, "GIT_AUTH_FAILED", now, output=conflict, staged=staged, commit_sha=sha, remote_attempt=remote_attempt, worktree_path=str(worktree))
                return result
            result = _offline_result(settings, staged, "GIT_PUSH_FAILED", now, commit_sha=sha, remote_attempt=remote_attempt, worktree_path=str(worktree), output=conflict)
            return result
        result = _offline_result(settings, staged, "GIT_PUSH_RACE", now, commit_sha=sha, remote_attempt=max_races, worktree_path=str(worktree), output="REMOTE_RACE_RETRY_EXHAUSTED")
        return result
    except TimeoutError:
        raise
    except (OSError, RuntimeError, ValueError, PrivacyError) as exc:
        result = _blocked_result(settings, "SYNC_IO_FAILED", now, output=type(exc).__name__, worktree_path=str(worktree) if worktree else None)
        return result
    finally:
        if worktree is not None and ownership is not None and _can_continue():
            cleanup_error = _cleanup_worktree(source_runner, worktree, ownership)
            if cleanup_error and (result is None or result.ok):
                raise RuntimeError(cleanup_error)


def _sync_once(settings: Settings, now: datetime | object | None = None, runner: GitRunner | object | None = None) -> SyncResult:
    """Perform one bounded, privacy-checked synchronization attempt."""

    if runner is None and now is not None and not isinstance(now, datetime) and hasattr(now, "run"):
        runner = now
        now = None
    moment = _utc_now(now if isinstance(now, datetime) else None)
    try:
        _check()
        with FileLock(settings.paths.locks_dir / "sync.lock"):
            if runner is not None:
                return _sync_in_place(settings, runner, moment)
            if not bool(getattr(settings, "sync_enabled", False)):
                return _sync_in_place(settings, GitRunner(_sync_root(settings)), moment)
            return _sync_dedicated_worktree(settings, moment)
    except TimeoutError:
        raise
    except RuntimeError as exc:
        result = SyncResult(False, str(exc), output=str(exc))
        if str(exc) != "SYNC_LOCK_BUSY":
            _record_state(settings, result, moment)
        return result
    except (OSError, ValueError) as exc:
        result = SyncResult(False, "SYNC_IO_FAILED", output=type(exc).__name__)
        _record_state(settings, result, moment)
        return result


def sync_once(settings: Settings, now: datetime | object | None = None, runner: GitRunner | object | None = None, *, budget=None) -> SyncResult:
    attempt = _SyncAttempt(budget)
    token = _ATTEMPT.set(attempt)
    try:
        return _sync_once(settings, now, runner)
    except TimeoutError:
        reason = "SYNC_SOURCE_RECONCILIATION_PENDING" if attempt.push_returncode == 0 else "SYNC_REMOTE_OUTCOME_UNKNOWN" if attempt.push_started else "SYNC_BUDGET_EXHAUSTED"
        return SyncResult(False, reason,
                          worktree_path=str(attempt.worktree) if attempt.worktree else None,
                          preflight={"push_started": attempt.push_started, "push_returncode": attempt.push_returncode,
                                     "recovery_pending": attempt.worktree is not None})
    finally:
        _ATTEMPT.reset(token)


__all__ = [
    "CommandResult",
    "FileLock",
    "GitRunner",
    "RETRY_SECONDS",
    "SyncPlan",
    "SyncResult",
    "build_sync_plan",
    "classify_git_conflict",
    "managed_paths",
    "schedule_retry",
    "sync_once",
]
