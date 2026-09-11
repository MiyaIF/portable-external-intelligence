"""Plan, publish, and verify the guarded GitHub public release boundary.

The module deliberately separates a read-only publication plan from the
external mutation that creates a repository, changes its settings, and pushes
the already-sanitized fresh root.  No function in this module rewrites the
private development repository or accepts a private repository as a
publication source.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .ids import canonical_json
from .publication_audit import audit_repository
from .publication_policy import validate_publication_policy
from .safe_fs import SafeFilesystemError, assert_no_reparse_components, assert_safe_target


PUBLICATION_SCHEMA_VERSION = 1
PUBLICATION_TOOL_VERSION = "ei-github-publication/1"
PUBLICATION_RECORD_TYPE = "github_publication"
PUBLICATION_APPROVAL_SCHEMA_VERSION = 1
PUBLICATION_APPROVAL_TYPE = "github_publication_approval"
PUBLICATION_STATUSES = frozenset({"ready_for_confirmation", "blocked", "published", "verified"})
TARGET_STATUSES = frozenset({"not_found", "exists", "unknown"})
REQUIRED_WORKFLOW_NAMES = ("ci", "compatibility", "security", "package")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GITHUB_RUN_URL = re.compile(r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/actions/runs/[0-9]+$")
_RECORD_KEYS = frozenset(
    {
        "receipt_type",
        "schema_version",
        "tool_version",
        "status",
        "owner",
        "repository",
        "repository_url",
        "default_branch",
        "source_commit_sha",
        "source_tree_id",
        "source_tree_sha256",
        "root_commit_count",
        "source_audit_sha256",
        "plan_sha256",
        "settings",
        "settings_sha256",
        "ruleset",
        "ruleset_sha256",
        "feature_states",
        "target_observation",
        "ci_run_urls",
        "post_public_clone",
        "mutations_performed",
        "external_mutations",
        "generated_at",
        "receipt_sha256",
    }
)
_POST_CLONE_KEYS = frozenset(
    {"root_commit_sha", "tree_id", "tree_sha256", "root_commit_count", "audit_sha256", "package_sha256", "readme_quick_start"}
)
_FEATURE_KEYS = frozenset(
    {
        "visibility",
        "issues",
        "pull_requests",
        "wiki",
        "projects",
        "discussions",
        "secret_scanning",
        "secret_scanning_push_protection",
        "dependabot_alerts",
        "dependabot_security_updates",
        "private_vulnerability_reporting",
        "code_scanning",
        "actions_hosted_runners_only",
        "self_hosted_runner_registered",
    }
)
_APPROVAL_KEYS = frozenset({"approval_type", "schema_version", "plan_sha256", "approved_at", "approval_sha256"})


class GithubPublicationError(ValueError):
    """Raised when a public publication step cannot be proven safe."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


@dataclass(frozen=True)
class SourceSnapshot:
    commit_sha: str
    tree_id: str
    tree_sha256: str
    root_commit_count: int
    audit_sha256: str


def _fail(code: str, detail: str = "") -> None:
    raise GithubPublicationError(code, detail)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Mapping[str, Any]) -> str:
    return _sha256(canonical_json(value))


def _time(value: object) -> str:
    if value is None:
        moment = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GithubPublicationError("GITHUB_PUBLICATION_TIME_INVALID") from exc
    else:
        _fail("GITHUB_PUBLICATION_TIME_INVALID")
    if moment.tzinfo is None or moment.utcoffset() is None:
        _fail("GITHUB_PUBLICATION_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _absolute(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or isinstance(value, bool):
        _fail("GITHUB_PUBLICATION_PATH_INVALID")
    try:
        result = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GithubPublicationError("GITHUB_PUBLICATION_PATH_INVALID") from exc
    if not str(result) or "\x00" in str(result):
        _fail("GITHUB_PUBLICATION_PATH_INVALID")
    return result


def _safe_existing_path(value: Path | str, *, expected_type: str, invalid_code: str) -> Path:
    try:
        target = assert_no_reparse_components(_absolute(value))
        return assert_safe_target(
            target.parent,
            target,
            allow_missing=False,
            expected_type=expected_type,
        )
    except SafeFilesystemError as exc:
        if exc.code == "UNSAFE_REPARSE_POINT":
            raise GithubPublicationError(exc.code) from exc
        raise GithubPublicationError(invalid_code) from exc


def _safe_destination_path(value: Path | str) -> Path:
    try:
        return assert_no_reparse_components(_absolute(value))
    except SafeFilesystemError as exc:
        raise GithubPublicationError(exc.code) from exc


def _run(
    argv: Sequence[Path | str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    timeout: float = 120.0,
    code: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            [str(item) for item in argv],
            cwd=str(cwd) if cwd else None,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GithubPublicationError(code) from exc
    if result.returncode != 0:
        raise GithubPublicationError(code)
    return result


def _git(repo: Path, *arguments: str, timeout: float = 120.0, code: str = "GITHUB_PUBLICATION_GIT_FAILED") -> bytes:
    return _run(["git", "-C", repo, *arguments], cwd=repo, timeout=timeout, code=code).stdout


def _git_text(repo: Path, *arguments: str, timeout: float = 120.0, code: str = "GITHUB_PUBLICATION_GIT_FAILED") -> str:
    try:
        return _git(repo, *arguments, timeout=timeout, code=code).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise GithubPublicationError(code) from exc


def _validate_sha(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _fail(code)
    return value


def _tree_digest(repo: Path, revision: str = "HEAD") -> str:
    return _sha256(_git(repo, "ls-tree", "-r", "-z", "--full-tree", revision, code="GITHUB_PUBLICATION_TREE_READ_FAILED"))


def _source_snapshot(source_value: Path | str, policy: Mapping[str, Any]) -> SourceSnapshot:
    source = _safe_existing_path(
        source_value,
        expected_type="dir",
        invalid_code="GITHUB_PUBLICATION_SOURCE_DIRECTORY_INVALID",
    )
    try:
        top = _git_text(source, "rev-parse", "--show-toplevel", code="GITHUB_PUBLICATION_SOURCE_NOT_GIT")
        if Path(top).resolve() != source.resolve():
            _fail("GITHUB_PUBLICATION_SOURCE_NOT_REPOSITORY_ROOT")
        if _git(source, "status", "--porcelain=v1", "--untracked-files=all", code="GITHUB_PUBLICATION_SOURCE_STATUS_FAILED"):
            _fail("GITHUB_PUBLICATION_SOURCE_WORKTREE_DIRTY")
        commit = _validate_sha(_git_text(source, "rev-parse", "--verify", "HEAD", code="GITHUB_PUBLICATION_SOURCE_REVISION_INVALID"), _SHA40, "GITHUB_PUBLICATION_SOURCE_REVISION_INVALID").lower()
        tree = _validate_sha(_git_text(source, "rev-parse", "--verify", "HEAD^{tree}", code="GITHUB_PUBLICATION_SOURCE_REVISION_INVALID"), _SHA40, "GITHUB_PUBLICATION_SOURCE_REVISION_INVALID").lower()
        count_text = _git_text(source, "rev-list", "--max-parents=0", "--count", "HEAD", code="GITHUB_PUBLICATION_ROOT_COUNT_FAILED")
        if count_text != "1":
            _fail("GITHUB_PUBLICATION_FRESH_ROOT_REQUIRED")
        authors = _git_text(source, "log", "--format=%ae", "--all", code="GITHUB_PUBLICATION_AUTHOR_READ_FAILED").splitlines()
        expected_author = str(policy["public_author"]["email"]).casefold()
        if not authors or any(item.casefold() != expected_author for item in authors):
            _fail("GITHUB_PUBLICATION_AUTHOR_MISMATCH")
    except GithubPublicationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise GithubPublicationError("GITHUB_PUBLICATION_SOURCE_INVALID") from exc
    audit = audit_repository(source, policy, working_tree=True, reachable_history=True, require_scanner_receipts=False)
    audit_value = audit.to_dict()
    if audit_value.get("status") != "passed":
        _fail("GITHUB_PUBLICATION_SOURCE_AUDIT_FAILED")
    audit_hash = audit_value.get("report_digest")
    _validate_sha(audit_hash, _SHA256, "GITHUB_PUBLICATION_SOURCE_AUDIT_INVALID")
    return SourceSnapshot(commit, tree, _tree_digest(source), 1, audit_hash)


def _repository_url(owner: str, repository: str) -> str:
    return f"https://github.com/{owner}/{repository}"


def _settings(policy: Mapping[str, Any]) -> dict[str, Any]:
    contribution = policy["contribution_policy"]
    return {
        "visibility": "public",
        "has_issues": bool(contribution["issues"]),
        "has_projects": False,
        "has_wiki": False,
        "has_discussions": False,
        "security_and_analysis": {
            "secret_scanning": "enabled",  # pragma: allowlist secret
            "secret_scanning_push_protection": "enabled",  # pragma: allowlist secret
            "private_vulnerability_reporting": "enabled",
            "advanced_security": "enabled",
        },
    }


def _ruleset() -> dict[str, Any]:
    return {
        "name": "public-main-protection",
        "target": "branch",
        "enforcement": "active",
        "required_status_checks": list(REQUIRED_WORKFLOW_NAMES),
        "required_approving_review_count": 0,
        "require_code_owner_reviews": False,
        "dismiss_stale_reviews": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "workflow_security_review_required": True,
        "root_privacy_review_required": True,
        "signed_tags_required": False,
    }


def _features(policy: Mapping[str, Any]) -> dict[str, Any]:
    contribution = policy["contribution_policy"]
    return {
        "visibility": "public",
        "issues": bool(contribution["issues"]),
        "pull_requests": bool(contribution["pull_requests"]),
        "wiki": False,
        "projects": False,
        "discussions": False,
        "secret_scanning": True,
        "secret_scanning_push_protection": True,
        "dependabot_alerts": True,
        "dependabot_security_updates": True,
        "private_vulnerability_reporting": True,
        "code_scanning": True,
        "actions_hosted_runners_only": True,
        "self_hosted_runner_registered": False,
    }


def _target_observation(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        _fail("GITHUB_PUBLICATION_TARGET_OBSERVATION_INVALID")
    status = value.get("status")
    method = value.get("method", "github_api")
    if status not in TARGET_STATUSES or not isinstance(method, str) or not method or "\n" in method:
        _fail("GITHUB_PUBLICATION_TARGET_OBSERVATION_INVALID")
    return {"status": str(status), "method": method}


def _probe_target(policy: Mapping[str, Any], *, timeout: float = 15.0) -> dict[str, str]:
    owner = str(policy["github"]["owner"])
    repository = str(policy["github"]["repository"])
    request = Request(
        f"https://api.github.com/repos/{owner}/{repository}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "portable-external-intelligence-publication-plan/1",
        },
    )
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                return {"status": "exists", "method": "github_api"}
            return {"status": "unknown", "method": "github_api_status_" + str(response.status)}
    except HTTPError as exc:
        if exc.code == 404 and token:
            return {"status": "not_found", "method": "github_api"}
        return {"status": "unknown", "method": "github_api_status_" + str(exc.code)}
    except (URLError, TimeoutError, OSError, ValueError):
        return {"status": "unknown", "method": "github_api_unavailable"}


def _plan_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    mutable = {
        "status",
        "plan_sha256",
        "receipt_sha256",
        "ci_run_urls",
        "post_public_clone",
        "mutations_performed",
        "external_mutations",
        "generated_at",
    }
    return {key: value[key] for key in sorted(set(value) - mutable)}


def _receipt_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(set(value) - {"receipt_sha256"})}


def _finalize(value: dict[str, Any]) -> dict[str, Any]:
    value["plan_sha256"] = _digest(_plan_basis(value))
    value["receipt_sha256"] = _digest(_receipt_basis(value))
    validate_publication_record(value)
    return value


def validate_publication_approval(value: Mapping[str, Any], expected_plan_sha256: str | None = None) -> bool:
    if not isinstance(value, Mapping) or set(value) != _APPROVAL_KEYS:
        _fail("GITHUB_PUBLICATION_APPROVAL_SCHEMA_INVALID")
    if value.get("approval_type") != PUBLICATION_APPROVAL_TYPE or type(value.get("schema_version")) is not int or value.get("schema_version") != PUBLICATION_APPROVAL_SCHEMA_VERSION:
        _fail("GITHUB_PUBLICATION_APPROVAL_TYPE_INVALID")
    plan_sha256 = _validate_sha(value.get("plan_sha256"), _SHA256, "GITHUB_PUBLICATION_APPROVAL_PLAN_INVALID")
    if expected_plan_sha256 is not None:
        _validate_sha(expected_plan_sha256, _SHA256, "GITHUB_PUBLICATION_APPROVAL_PLAN_INVALID")
        if plan_sha256 != expected_plan_sha256:
            _fail("GITHUB_PUBLICATION_APPROVAL_PLAN_MISMATCH")
    approved_at = value.get("approved_at")
    if not isinstance(approved_at, str) or not approved_at.endswith("Z"):
        _fail("GITHUB_PUBLICATION_APPROVAL_TIME_INVALID")
    _time(approved_at)
    approval_sha256 = _validate_sha(value.get("approval_sha256"), _SHA256, "GITHUB_PUBLICATION_APPROVAL_HASH_INVALID")
    basis = {key: value[key] for key in sorted(_APPROVAL_KEYS - {"approval_sha256"})}
    if approval_sha256 != _digest(basis):
        _fail("GITHUB_PUBLICATION_APPROVAL_HASH_MISMATCH")
    return True


def confirm_plan_approval(record: Mapping[str, Any], approval: Mapping[str, Any]) -> bool:
    validate_publication_record(record)
    if record.get("status") != "ready_for_confirmation":
        _fail("GITHUB_PUBLICATION_PLAN_NOT_READY")
    validate_publication_approval(approval, str(record["plan_sha256"]))
    if record["target_observation"]["status"] != "not_found":
        _fail("GITHUB_PUBLICATION_TARGET_CONFLICT")
    return True


def validate_publication_record(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        _fail("GITHUB_PUBLICATION_RECEIPT_SCHEMA_INVALID")
    if value.get("receipt_type") != PUBLICATION_RECORD_TYPE or value.get("schema_version") != PUBLICATION_SCHEMA_VERSION:
        _fail("GITHUB_PUBLICATION_RECEIPT_TYPE_INVALID")
    if value.get("status") not in PUBLICATION_STATUSES:
        _fail("GITHUB_PUBLICATION_STATUS_INVALID")
    for key in ("source_commit_sha", "source_tree_id"):
        _validate_sha(value.get(key), _SHA40, "GITHUB_PUBLICATION_SHA_INVALID")
    for key in ("source_tree_sha256", "source_audit_sha256", "plan_sha256", "settings_sha256", "ruleset_sha256"):
        _validate_sha(value.get(key), _SHA256, "GITHUB_PUBLICATION_HASH_INVALID")
    if value.get("root_commit_count") != 1:
        _fail("GITHUB_PUBLICATION_FRESH_ROOT_REQUIRED")
    for key in ("owner", "repository", "default_branch", "repository_url", "tool_version"):
        if not isinstance(value.get(key), str) or not value[key] or "\x00" in value[key] or "\n" in value[key]:
            _fail("GITHUB_PUBLICATION_TEXT_INVALID", key)
    if value["default_branch"] != "main" or value["repository_url"] != _repository_url(value["owner"], value["repository"]):
        _fail("GITHUB_PUBLICATION_TARGET_INVALID")
    settings = value.get("settings")
    ruleset = value.get("ruleset")
    if not isinstance(settings, Mapping) or not isinstance(ruleset, Mapping):
        _fail("GITHUB_PUBLICATION_CONFIGURATION_INVALID")
    if value["settings_sha256"] != _digest(dict(settings)) or value["ruleset_sha256"] != _digest(dict(ruleset)):
        _fail("GITHUB_PUBLICATION_CONFIGURATION_HASH_MISMATCH")
    features = value.get("feature_states")
    if not isinstance(features, Mapping) or set(features) != _FEATURE_KEYS:
        _fail("GITHUB_PUBLICATION_FEATURE_STATE_INVALID")
    if features.get("visibility") != "public" or features.get("self_hosted_runner_registered") is not False:
        _fail("GITHUB_PUBLICATION_FEATURE_STATE_INVALID")
    for key in _FEATURE_KEYS - {"visibility"}:
        if type(features.get(key)) is not bool:
            _fail("GITHUB_PUBLICATION_FEATURE_STATE_INVALID")
    observation = _target_observation(value.get("target_observation"))
    if observation["status"] not in TARGET_STATUSES:
        _fail("GITHUB_PUBLICATION_TARGET_OBSERVATION_INVALID")
    urls = value.get("ci_run_urls")
    if not isinstance(urls, list) or any(not isinstance(item, str) or not _GITHUB_RUN_URL.fullmatch(item) for item in urls):
        _fail("GITHUB_PUBLICATION_CI_URLS_INVALID")
    post = value.get("post_public_clone")
    if post is not None:
        if not isinstance(post, Mapping) or set(post) != _POST_CLONE_KEYS:
            _fail("GITHUB_PUBLICATION_CLONE_RECEIPT_INVALID")
        for key in ("root_commit_sha", "tree_id"):
            _validate_sha(post.get(key), _SHA40, "GITHUB_PUBLICATION_CLONE_RECEIPT_INVALID")
        for key in ("tree_sha256", "audit_sha256", "package_sha256"):
            _validate_sha(post.get(key), _SHA256, "GITHUB_PUBLICATION_CLONE_RECEIPT_INVALID")
        if post.get("root_commit_count") != 1 or post.get("readme_quick_start") is not True:
            _fail("GITHUB_PUBLICATION_CLONE_RECEIPT_INVALID")
    if type(value.get("mutations_performed")) is not bool:
        _fail("GITHUB_PUBLICATION_MUTATION_STATE_INVALID")
    mutations = value.get("external_mutations")
    if not isinstance(mutations, list) or any(not isinstance(item, str) or not item or "\n" in item for item in mutations):
        _fail("GITHUB_PUBLICATION_MUTATION_LOG_INVALID")
    if not isinstance(value.get("generated_at"), str) or not value["generated_at"].endswith("Z"):
        _fail("GITHUB_PUBLICATION_TIME_INVALID")
    _time(value["generated_at"])
    if value["receipt_sha256"] != _digest(_receipt_basis(value)):
        _fail("GITHUB_PUBLICATION_RECEIPT_HASH_MISMATCH")
    if value["plan_sha256"] != _digest(_plan_basis(value)):
        _fail("GITHUB_PUBLICATION_PLAN_HASH_MISMATCH")
    return True


def build_publication_plan(
    source: Path | str,
    policy: Mapping[str, Any],
    *,
    target_observation: Mapping[str, Any] | None = None,
    generated_at: datetime | str | None = None,
) -> dict[str, Any]:
    normalized_policy = validate_publication_policy(policy)
    snapshot = _source_snapshot(source, normalized_policy)
    observation = _target_observation(target_observation or _probe_target(normalized_policy))
    owner = str(normalized_policy["github"]["owner"])
    repository = str(normalized_policy["github"]["repository"])
    value: dict[str, Any] = {
        "receipt_type": PUBLICATION_RECORD_TYPE,
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "tool_version": PUBLICATION_TOOL_VERSION,
        "status": "ready_for_confirmation" if observation["status"] == "not_found" else "blocked",
        "owner": owner,
        "repository": repository,
        "repository_url": _repository_url(owner, repository),
        "default_branch": "main",
        "source_commit_sha": snapshot.commit_sha,
        "source_tree_id": snapshot.tree_id,
        "source_tree_sha256": snapshot.tree_sha256,
        "root_commit_count": snapshot.root_commit_count,
        "source_audit_sha256": snapshot.audit_sha256,
        "settings": _settings(normalized_policy),
        "settings_sha256": "",
        "ruleset": _ruleset(),
        "ruleset_sha256": "",
        "feature_states": _features(normalized_policy),
        "target_observation": observation,
        "ci_run_urls": [],
        "post_public_clone": None,
        "mutations_performed": False,
        "external_mutations": [],
        "generated_at": _time(generated_at),
        "plan_sha256": "",
        "receipt_sha256": "",
    }
    value["settings_sha256"] = _digest(value["settings"])
    value["ruleset_sha256"] = _digest(value["ruleset"])
    return _finalize(value)


def _load_record(path: Path | str) -> dict[str, Any]:
    target = _safe_existing_path(
        path,
        expected_type="file",
        invalid_code="GITHUB_PUBLICATION_RECEIPT_READ_FAILED",
    )
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GithubPublicationError("GITHUB_PUBLICATION_RECEIPT_READ_FAILED") from exc
    if not isinstance(value, Mapping):
        _fail("GITHUB_PUBLICATION_RECEIPT_SCHEMA_INVALID")
    validate_publication_record(value)
    return dict(value)


def confirm_plan(record: Mapping[str, Any], confirmed_plan_sha256: str) -> bool:
    validate_publication_record(record)
    if record.get("status") != "ready_for_confirmation":
        _fail("GITHUB_PUBLICATION_PLAN_NOT_READY")
    _validate_sha(confirmed_plan_sha256, _SHA256, "GITHUB_PUBLICATION_PLAN_CONFIRMATION_INVALID")
    if confirmed_plan_sha256 != record.get("plan_sha256"):
        _fail("GITHUB_PUBLICATION_PLAN_CONFIRMATION_MISMATCH")
    if record["target_observation"]["status"] != "not_found":
        _fail("GITHUB_PUBLICATION_TARGET_CONFLICT")
    return True


def _gh_executable() -> str:
    executable = shutil.which("gh")
    if not executable:
        _fail("GITHUB_CLI_REQUIRED")
    return executable


def _gh_api(endpoint: str, *, method: str = "GET", payload: Mapping[str, Any] | None = None, timeout: float = 120.0) -> Mapping[str, Any] | list[Any]:
    executable = _gh_executable()
    argv: list[Path | str] = [executable, "api", endpoint, "--hostname", "github.com"]
    if method != "GET":
        argv.extend(["--method", method])
    input_bytes = None
    if payload is not None:
        argv.extend(["--input", "-"])
        input_bytes = (json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    result = _run(argv, input_bytes=input_bytes, timeout=timeout, code="GITHUB_API_REQUEST_FAILED")
    if not result.stdout.strip():
        return {}
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubPublicationError("GITHUB_API_RESPONSE_INVALID") from exc
    if not isinstance(value, (Mapping, list)):
        _fail("GITHUB_API_RESPONSE_INVALID")
    return value


def _readback_api(endpoint: str, code: str) -> Mapping[str, Any] | list[Any]:
    try:
        return _gh_api(endpoint)
    except GithubPublicationError as exc:
        raise GithubPublicationError(code) from exc


def _exact_equal(expected: object, actual: object) -> bool:
    if type(expected) is not type(actual):
        return False
    if isinstance(expected, Mapping):
        return set(expected) == set(actual) and all(_exact_equal(expected[key], actual[key]) for key in expected)
    if isinstance(expected, list):
        return len(expected) == len(actual) and all(_exact_equal(left, right) for left, right in zip(expected, actual))
    return expected == actual


def _verify_repository_readback(record: Mapping[str, Any], *, require_default_branch: bool = False) -> Mapping[str, Any]:
    owner = str(record["owner"])
    repository = str(record["repository"])
    settings = dict(record["settings"])
    expected: dict[str, Any] = {
        "name": repository,
        "full_name": f"{owner}/{repository}",
        "private": False,
        "visibility": "public",
        "has_issues": settings["has_issues"],
        "has_projects": settings["has_projects"],
        "has_wiki": settings["has_wiki"],
        "has_discussions": settings["has_discussions"],
    }
    if require_default_branch:
        expected["default_branch"] = str(record["default_branch"])
    value = _readback_api(f"repos/{owner}/{repository}", "GITHUB_PUBLICATION_REPOSITORY_READBACK_MISMATCH")
    projection = {key: value.get(key) for key in expected} if isinstance(value, Mapping) else None
    if not _exact_equal(expected, projection):
        _fail("GITHUB_PUBLICATION_REPOSITORY_READBACK_MISMATCH")
    return value


def _verify_security_readback(record: Mapping[str, Any], repository_value: Mapping[str, Any]) -> None:
    owner = str(record["owner"])
    repository = str(record["repository"])
    settings = dict(record["settings"])
    security_settings = dict(settings["security_and_analysis"])
    repository_security_keys = ("secret_scanning", "secret_scanning_push_protection")
    expected_security = {key: {"status": security_settings[key]} for key in repository_security_keys}
    security = repository_value.get("security_and_analysis")
    security_projection = {key: security.get(key) for key in expected_security} if isinstance(security, Mapping) else None
    if not _exact_equal(expected_security, security_projection):
        _fail("GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH")
    private_reporting = _readback_api(
        f"repos/{owner}/{repository}/private-vulnerability-reporting",
        "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH",
    )
    if not _exact_equal({"enabled": True}, private_reporting):
        _fail("GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH")
    alerts = _readback_api(
        f"repos/{owner}/{repository}/vulnerability-alerts",
        "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH",
    )
    if not _exact_equal({}, alerts):
        _fail("GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH")
    fixes = _readback_api(
        f"repos/{owner}/{repository}/automated-security-fixes",
        "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH",
    )
    fixes_projection = {key: fixes.get(key) for key in ("enabled", "paused")} if isinstance(fixes, Mapping) else None
    if not _exact_equal({"enabled": True, "paused": False}, fixes_projection):
        _fail("GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH")
    code_scanning = _readback_api(
        f"repos/{owner}/{repository}/code-scanning/default-setup",
        "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH",
    )
    if not isinstance(code_scanning, Mapping) or code_scanning.get("state") != "configured":
        _fail("GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH")


def _ruleset_api_payload(rules: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": rules["name"],
        "target": "branch",
        "enforcement": rules["enforcement"],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": rules["required_approving_review_count"],
                    "dismiss_stale_reviews_on_push": rules["dismiss_stale_reviews"],
                    "require_code_owner_review": rules["require_code_owner_reviews"],
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False,
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": name} for name in rules["required_status_checks"]],
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": True,
                },
            },
        ],
        "bypass_actors": [],
    }


def _project_expected_shape(expected: object, actual: object) -> object:
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping):
            return None
        return {key: _project_expected_shape(value, actual.get(key)) for key, value in expected.items()}
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(expected) != len(actual):
            return None
        return [_project_expected_shape(left, right) for left, right in zip(expected, actual)]
    return actual


def _verify_ruleset_readback(record: Mapping[str, Any]) -> None:
    owner = str(record["owner"])
    repository = str(record["repository"])
    rules = dict(record["ruleset"])
    endpoint = f"repos/{owner}/{repository}/rulesets"
    summaries = _readback_api(endpoint, "GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH")
    if not isinstance(summaries, list):
        _fail("GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH")
    matches = [
        item
        for item in summaries
        if isinstance(item, Mapping)
        and item.get("name") == rules["name"]
        and item.get("target") == "branch"
        and item.get("enforcement") == rules["enforcement"]
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int) or isinstance(matches[0].get("id"), bool) or matches[0]["id"] < 1:
        _fail("GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH")
    detail = _readback_api(endpoint + "/" + str(matches[0]["id"]), "GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH")
    expected = _ruleset_api_payload(rules)
    detail_projection = _project_expected_shape(expected, detail)
    if not _exact_equal(expected, detail_projection):
        _fail("GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH")


def _create_repository(record: Mapping[str, Any]) -> list[str]:
    owner = str(record["owner"])
    repository = str(record["repository"])
    settings = dict(record["settings"])
    identity = _gh_api(f"users/{owner}")
    account_type = identity.get("type")
    endpoint = f"orgs/{owner}/repos" if account_type == "Organization" else "user/repos" if account_type == "User" else ""
    if not endpoint:
        _fail("GITHUB_OWNER_ACCOUNT_INVALID")
    payload = {
        "name": repository,
        "private": False,
        "has_issues": settings["has_issues"],
        "has_projects": settings["has_projects"],
        "has_wiki": settings["has_wiki"],
        "has_discussions": settings["has_discussions"],
        "auto_init": False,
    }
    created = _gh_api(endpoint, method="POST", payload=payload)
    if created.get("full_name") != f"{owner}/{repository}" or created.get("private") is True:
        _fail("GITHUB_REPOSITORY_CREATE_UNVERIFIED")
    mutations = ["repository_created_public"]
    _gh_api(
        f"repos/{owner}/{repository}",
        method="PATCH",
        payload={
            "visibility": "public",
            "has_issues": settings["has_issues"],
            "has_projects": settings["has_projects"],
            "has_wiki": settings["has_wiki"],
            "has_discussions": settings["has_discussions"],
            "security_and_analysis": {
                key: {"status": "enabled"}
                for key in ("secret_scanning", "secret_scanning_push_protection")
            },
        },
    )
    _gh_api(f"repos/{owner}/{repository}/private-vulnerability-reporting", method="PUT")
    _gh_api(f"repos/{owner}/{repository}/vulnerability-alerts", method="PUT")
    _gh_api(f"repos/{owner}/{repository}/automated-security-fixes", method="PUT")
    _gh_api(f"repos/{owner}/{repository}/code-scanning/default-setup", method="PATCH", payload={"state": "configured"})
    mutations.extend(["repository_security_settings_enabled", "dependabot_alerts_enabled", "dependabot_security_updates_enabled", "code_scanning_default_setup_enabled"])
    rules = dict(record["ruleset"])
    _gh_api(f"repos/{owner}/{repository}/rulesets", method="POST", payload=_ruleset_api_payload(rules))
    mutations.append("main_branch_ruleset_enabled")
    repository_readback = _verify_repository_readback(record)
    _verify_security_readback(record, repository_readback)
    _verify_ruleset_readback(record)
    return mutations


def _push_fresh_root(source: Path, repository_url: str) -> None:
    with tempfile.TemporaryDirectory(prefix="ei-public-push-") as temporary:
        staging = Path(temporary) / "source"
        _run(["git", "clone", "--no-local", "--no-tags", source, staging], cwd=source, code="GITHUB_PUBLICATION_STAGING_CLONE_FAILED")
        _run(["git", "remote", "add", "public", repository_url + ".git"], cwd=staging, code="GITHUB_PUBLICATION_REMOTE_ADD_FAILED")
        _run(["git", "push", "--set-upstream", "public", "main"], cwd=staging, timeout=300.0, code="GITHUB_PUBLICATION_PUSH_FAILED")


def publish_publication_plan(
    source: Path | str,
    plan: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    approval: Mapping[str, Any] | None = None,
    confirmed_plan_sha256: str | None = None,
) -> dict[str, Any]:
    source_path = _absolute(source)
    validate_publication_record(plan)
    if confirmed_plan_sha256 is not None:
        _fail("GITHUB_PUBLICATION_APPROVAL_ARTIFACT_REQUIRED")
    if approval is None:
        _fail("GITHUB_PUBLICATION_APPROVAL_REQUIRED")
    confirm_plan_approval(plan, approval)
    normalized_policy = validate_publication_policy(policy)
    if normalized_policy["github"]["owner"] != plan["owner"] or normalized_policy["github"]["repository"] != plan["repository"]:
        _fail("GITHUB_PUBLICATION_POLICY_TARGET_MISMATCH")
    snapshot = _source_snapshot(source_path, normalized_policy)
    if snapshot.commit_sha != plan["source_commit_sha"] or snapshot.tree_id != plan["source_tree_id"] or snapshot.tree_sha256 != plan["source_tree_sha256"]:
        _fail("GITHUB_PUBLICATION_SOURCE_CHANGED")
    mutations = _create_repository(plan)
    _push_fresh_root(source_path, str(plan["repository_url"]))
    _verify_repository_readback(plan, require_default_branch=True)
    mutations.append("sanitized_root_pushed")
    value = dict(plan)
    value.update(
        {
            "status": "published",
            "mutations_performed": True,
            "external_mutations": mutations,
            "generated_at": _time(None),
        }
    )
    return _finalize(value)


def _package_digest(root: Path) -> str:
    files = sorted(path for path in (root / "dist").glob("*") if path.is_file())
    if not files:
        _fail("GITHUB_PUBLICATION_PACKAGE_MISSING")
    payload = [(path.name, _sha256(path.read_bytes())) for path in files]
    return _digest({"packages": payload})


def _readme_quick_start(root: Path, repository_url: str) -> bool:
    try:
        text = (root / "README.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GithubPublicationError("GITHUB_PUBLICATION_README_INVALID") from exc
    required = (
        "git clone " + repository_url + ".git",
        r".\scripts\setup.ps1",
        "sh scripts/setup.sh",
        "local",
        "github-new",
        "github-existing",
        "No second initialization command is part of the normal journey.",
    )
    normalized_text = " ".join(text.split())
    if not all(" ".join(item.split()) in normalized_text for item in required):
        _fail("GITHUB_PUBLICATION_README_QUICK_START_INVALID")
    return True


def verify_publication(
    receipt: Mapping[str, Any],
    policy: Mapping[str, Any],
    fresh_clone: Path | str,
    *,
    python_executable: Path | str | None = None,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    validate_publication_record(receipt)
    normalized_policy = validate_publication_policy(policy)
    if receipt["status"] not in {"published", "verified"} or receipt["mutations_performed"] is not True:
        _fail("GITHUB_PUBLICATION_NOT_PUBLISHED")
    if receipt["owner"] != normalized_policy["github"]["owner"] or receipt["repository"] != normalized_policy["github"]["repository"]:
        _fail("GITHUB_PUBLICATION_POLICY_TARGET_MISMATCH")
    clone = _safe_destination_path(fresh_clone)
    if clone.exists():
        try:
            assert_safe_target(
                clone.parent,
                clone,
                allow_missing=False,
                expected_type="dir",
            )
        except SafeFilesystemError as exc:
            if exc.code == "UNSAFE_REPARSE_POINT":
                raise GithubPublicationError(exc.code) from exc
            _fail("GITHUB_PUBLICATION_CLONE_DESTINATION_NOT_EMPTY")
        if any(clone.iterdir()):
            _fail("GITHUB_PUBLICATION_CLONE_DESTINATION_NOT_EMPTY")
    _run(["git", "clone", "--no-local", "--no-tags", str(receipt["repository_url"]) + ".git", clone], timeout=timeout_seconds, code="GITHUB_PUBLICATION_CLONE_FAILED")
    snapshot = _source_snapshot(clone, normalized_policy)
    if snapshot.commit_sha != receipt["source_commit_sha"] or snapshot.tree_id != receipt["source_tree_id"] or snapshot.tree_sha256 != receipt["source_tree_sha256"]:
        _fail("GITHUB_PUBLICATION_CLONE_TREE_MISMATCH")
    readme = _readme_quick_start(clone, str(receipt["repository_url"]))
    executable = _safe_existing_path(
        python_executable or shutil.which("python") or os.sys.executable,
        expected_type="file",
        invalid_code="GITHUB_PUBLICATION_PYTHON_MISSING",
    )
    _run([executable, "-B", "-m", "build", "--wheel", "--sdist", "--no-isolation"], cwd=clone, timeout=timeout_seconds, code="GITHUB_PUBLICATION_PACKAGE_BUILD_FAILED")
    post = {
        "root_commit_sha": snapshot.commit_sha,
        "tree_id": snapshot.tree_id,
        "tree_sha256": snapshot.tree_sha256,
        "root_commit_count": snapshot.root_commit_count,
        "audit_sha256": snapshot.audit_sha256,
        "package_sha256": _package_digest(clone),
        "readme_quick_start": readme,
    }
    value = dict(receipt)
    value.update({"status": "verified", "post_public_clone": post, "generated_at": _time(None)})
    return _finalize(value)


__all__ = [
    "GithubPublicationError",
    "PUBLICATION_APPROVAL_SCHEMA_VERSION",
    "PUBLICATION_APPROVAL_TYPE",
    "PUBLICATION_RECORD_TYPE",
    "PUBLICATION_SCHEMA_VERSION",
    "PUBLICATION_STATUSES",
    "build_publication_plan",
    "confirm_plan",
    "confirm_plan_approval",
    "publish_publication_plan",
    "validate_publication_approval",
    "validate_publication_record",
    "verify_publication",
]
