"""Certify an isolated, clean clone of the public engine.

The command is deliberately offline with respect to agent providers.  It uses
sanitized host contracts and never reads the operator's home, credentials,
agent cache, or Git configuration.  A successful receipt is suitable for
hosted CI evidence; it is not a real-host activation receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from ei.certification import REQUIRED_HOST_IDS, validate_receipt_artifact  # noqa: E402
from ei.config import PUBLIC_CLI_HOST_IDS  # noqa: E402
from ei.ids import canonical_json  # noqa: E402
from ei.models import Event  # noqa: E402
from ei.project import project_events  # noqa: E402
from ei.safe_fs import safe_atomic_write, safe_ensure_directory  # noqa: E402
from ei.test_runner import TestRunnerError, discover_test_modules, run_complete_suite  # noqa: E402


RECEIPT_TYPE = "public_clone_certification"
RECEIPT_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,120}$")
_SAFE_TEST_MODULE_RE = re.compile(r"^tests(?:\.[A-Za-z_][A-Za-z0-9_]*){2,20}$")
_FAILURE_STATUSES = frozenset({"failed", "crashed", "timed_out", "missing", "zero_test"})
_LOCK_FAILURE_CODES = {
    "requirements-build.lock": "BUILD_LOCK_INSTALL_FAILED",
    "requirements-runtime.lock": "RUNTIME_LOCK_INSTALL_FAILED",
    "requirements-ci.lock": "CI_LOCK_INSTALL_FAILED",
}
_RECEIPT_KEYS = frozenset(
    {
        "receipt_type",
        "schema_version",
        "status",
        "source_commit_sha",
        "clone_commit_sha",
        "source_tree_id",
        "clone_tree_id",
        "os",
        "python_version",
        "package_hashes",
        "runner_inventory_sha256",
        "workflow_sha256",
        "dependency_lock_sha256",
        "source_audit_sha256",
        "public_audit_sha256",
        "host_contracts",
        "test_module_count",
        "test_count",
        "test_skipped_count",
        "duration_seconds",
        "steps",
        "offline_fixtures",
        "isolated_environment",
        "absolute_path_findings",
        "generated_at",
        "receipt_sha256",
    }
)


def _sanitize_suite_diagnostics(value: Mapping[str, Any]) -> dict[str, Any]:
    raw_counts = value.get("counts", {})
    counts: dict[str, int] = {}
    if isinstance(raw_counts, Mapping):
        for key in ("modules", "passed", "failed", "crashed", "timed_out", "missing", "zero_test"):
            raw = raw_counts.get(key, 0)
            if type(raw) is int and 0 <= raw <= 1_000_000:
                counts[key] = raw
    modules: list[dict[str, str]] = []
    raw_modules = value.get("modules", [])
    if isinstance(raw_modules, list):
        for item in raw_modules:
            if not isinstance(item, Mapping) or item.get("status") not in _FAILURE_STATUSES:
                continue
            module = item.get("module")
            status = item.get("status")
            error_code = item.get("error_code")
            if not isinstance(module, str) or not _SAFE_TEST_MODULE_RE.fullmatch(module):
                continue
            if not isinstance(status, str) or not _SAFE_CODE_RE.fullmatch(status):
                continue
            safe_error = error_code if isinstance(error_code, str) and _SAFE_CODE_RE.fullmatch(error_code) else "unknown"
            modules.append({"module": module, "status": status, "error_code": safe_error})
            if len(modules) >= 50:
                break
    result: dict[str, Any] = {}
    if "counts" in value or "modules" in value:
        result.update({"counts": counts, "modules": modules})
    process_reason = value.get("process_reason")
    if isinstance(process_reason, str) and _SAFE_CODE_RE.fullmatch(process_reason):
        result["process_reason"] = process_reason
    return result


class CertificationError(RuntimeError):
    """Raised when the clean-clone contract cannot be certified."""

    def __init__(self, code: str, *, diagnostics: Mapping[str, Any] | None = None) -> None:
        self.code = code if _SAFE_CODE_RE.fullmatch(code) else "CERTIFICATION_FAILED"
        self.diagnostics = _sanitize_suite_diagnostics(diagnostics) if isinstance(diagnostics, Mapping) else None
        super().__init__(self.code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: Mapping[str, Any]) -> str:
    return _sha256(canonical_json(dict(value)))


def _safe_text(value: object, *, pattern: re.Pattern[str] = _SAFE_CODE_RE) -> str:
    text = str(value or "")
    return text if pattern.fullmatch(text) else "unknown"


def _lock_failure_code(lock_name: str) -> str:
    return _LOCK_FAILURE_CODES.get(lock_name, "LOCK_INSTALL_FAILED")


def _process_failure_reason(stdout: str, stderr: str) -> str:
    text = (stdout + "\n" + stderr).casefold()
    categories = (
        (("no matching distribution found", "could not find a version that satisfies"), "NO_MATCHING_DISTRIBUTION"),
        (("do not match the hashes", "hashes are required"), "HASH_VALIDATION_FAILED"),
        (("read timed out", "readtimeouterror", "connectionerror", "temporary failure in name resolution"), "NETWORK_FAILURE"),
        (("no space left on device",), "DISK_FULL"),
        (("permission denied", "access is denied"), "PERMISSION_DENIED"),
        (("winerror 206", "filename or extension is too long"), "PATH_TOO_LONG"),
        (("unicodeencodeerror", "unicodedecodeerror"), "TEXT_ENCODING_FAILED"),
        (("resolutionimpossible",), "DEPENDENCY_RESOLUTION_FAILED"),
    )
    for markers, reason in categories:
        if any(marker in text for marker in markers):
            return reason
    return "PROCESS_EXIT_NONZERO"


def _suite_failure_diagnostics(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"counts": {}, "modules": []}
    if not isinstance(value, Mapping):
        return {"counts": {}, "modules": []}
    return _sanitize_suite_diagnostics(value)


def _bounded_complete_suite(
    clone: Path,
    *,
    output: Path,
    log_dir: Path,
    python_executable: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    try:
        suite = run_complete_suite(
            clone,
            output=output,
            jobs=1,
            timeout_seconds=timeout_seconds,
            python_executable=python_executable,
            log_dir=log_dir,
            progress_stream=sys.stdout,
            environment=environment,
        )
    except TestRunnerError as exc:
        raise CertificationError("COMPLETE_SUITE_FAILED") from exc
    except (OSError, UnicodeError) as exc:
        raise CertificationError("COMPLETE_SUITE_RECEIPT_INVALID") from exc
    value = suite.to_dict(repo_root=clone)
    if not suite.successful:
        raise CertificationError("COMPLETE_SUITE_FAILED", diagnostics=_sanitize_suite_diagnostics(value))
    return value


def _git(repo: Path, *args: str, env: Mapping[str, str] | None = None, timeout: float = 60.0) -> str:
    process_env = dict(env or os.environ)
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            env=process_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificationError("GIT_COMMAND_FAILED") from exc
    if completed.returncode != 0:
        raise CertificationError("GIT_COMMAND_FAILED")
    return completed.stdout.strip()


def _source_revision(source: Path) -> tuple[str, str]:
    if not source.is_dir():
        raise CertificationError("SOURCE_DIRECTORY_MISSING")
    status = _git(source, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise CertificationError("SOURCE_WORKTREE_DIRTY")
    commit = _git(source, "rev-parse", "--verify", "HEAD").lower()
    tree = _git(source, "rev-parse", "--verify", "HEAD^{tree}").lower()
    if not _SHA40_RE.fullmatch(commit) or not _SHA40_RE.fullmatch(tree):
        raise CertificationError("SOURCE_REVISION_INVALID")
    return commit, tree


def _isolated_environment(workspace: Path, homes: Mapping[str, Path]) -> dict[str, str]:
    """Return an environment which cannot consult the developer profile."""

    workspace = Path(workspace).expanduser().resolve()
    home = workspace / "process-home"
    home.mkdir(parents=True, exist_ok=True)
    process_temp = workspace / "process-temp"
    process_temp.mkdir(parents=True, exist_ok=True)
    git_config = workspace / "empty-git-config"
    git_config.write_text("", encoding="utf-8", newline="\n")
    environment = dict(os.environ)
    for key in tuple(environment):
        if any(marker in key.casefold() for marker in ("token", "secret", "password", "api_key", "private_key")):
            environment.pop(key, None)
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "HOMEDRIVE": home.drive,
            "HOMEPATH": str(home)[len(home.drive) :] if home.drive else str(home),
            "APPDATA": str(home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "PIP_CACHE_DIR": str(workspace / "pip-cache"),
            "TMPDIR": str(process_temp),
            "TMP": str(process_temp),
            "TEMP": str(process_temp),
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "GIT_CONFIG_GLOBAL": str(git_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "EI_CERTIFICATION_ENV": "isolated",
            "CODEX_HOME": str(Path(homes["codex-cli"]).expanduser().resolve()),
            "CLAUDE_CONFIG_DIR": str(Path(homes["claude-code"]).expanduser().resolve()),
            "GEMINI_HOME": str(Path(homes["gemini-cli"]).expanduser().resolve()),
            "QWEN_HOME": str(Path(homes["qwen-code"]).expanduser().resolve()),
        }
    )
    return environment


def _run(
    argv: Sequence[str | Path],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    code: str,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            [str(item) for item in argv],
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificationError(code) from exc
    if completed.returncode != 0:
        raise CertificationError(
            code,
            diagnostics={"process_reason": _process_failure_reason(completed.stdout, completed.stderr)},
        )
    return completed


def _step(
    steps: list[dict[str, Any]],
    name: str,
    action: Any,
) -> Any:
    started = time.monotonic()
    try:
        value = action()
    except CertificationError as exc:
        steps.append(
            {
                "name": name,
                "status": "failed",
                "duration_seconds": round(time.monotonic() - started, 6),
                "error_code": exc.code,
            }
        )
        raise
    steps.append(
        {
            "name": name,
            "status": "passed",
            "duration_seconds": round(time.monotonic() - started, 6),
        }
    )
    return value


def _json_command(
    python_executable: Path,
    clone: Path,
    env: Mapping[str, str],
    arguments: Sequence[str],
    *,
    timeout: float,
    code: str,
) -> dict[str, Any]:
    completed = _run(
        [python_executable, "-B", "-m", "ei.cli", *arguments],
        cwd=clone,
        env=env,
        timeout=timeout,
        code=code,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CertificationError(code + "_JSON") from exc
    if not isinstance(value, dict):
        raise CertificationError(code + "_OBJECT")
    return value


def _inventory_digest(clone: Path) -> tuple[str, int, list[str]]:
    try:
        raw = _git(clone, "ls-files", "-z", "--", "tests")
    except CertificationError:
        raise
    # ``git -z`` output is decoded by the subprocess wrapper, so a NUL is
    # retained even when a path contains non-ASCII characters.
    tracked = [item for item in raw.split("\0") if item]
    modules = discover_test_modules(clone, tracked_files=tracked)
    names = [item.module_name for item in modules]
    digest = _sha256(canonical_json({"modules": names, "paths": [item.relative_path for item in modules]}))
    return digest, len(modules), names


def _package_hashes(directory: Path) -> dict[str, str]:
    if not directory.is_dir():
        raise CertificationError("PACKAGE_OUTPUT_MISSING")
    files = sorted(path for path in directory.iterdir() if path.is_file())
    if not files:
        raise CertificationError("PACKAGE_OUTPUT_EMPTY")
    return {path.name: _sha256(path.read_bytes()) for path in files}


def _built_wheel(directory: Path) -> Path:
    wheels = sorted(path for path in directory.glob("*.whl") if path.is_file()) if directory.is_dir() else []
    if not wheels:
        raise CertificationError("PACKAGE_WHEEL_MISSING")
    if len(wheels) != 1:
        raise CertificationError("PACKAGE_WHEEL_AMBIGUOUS")
    return wheels[0]


def _package_install_arguments(python_executable: Path, wheel: Path) -> list[str | Path]:
    return [
        python_executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-deps",
        wheel,
    ]


def _audit_json(
    python_executable: Path,
    clone: Path,
    env: Mapping[str, str],
    script: str,
    arguments: Sequence[str],
    *,
    timeout: float,
    code: str,
) -> dict[str, Any]:
    completed = _run(
        [python_executable, "-B", script, *arguments],
        cwd=clone,
        env=env,
        timeout=timeout,
        code=code,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CertificationError(code + "_JSON") from exc
    if not isinstance(value, dict):
        raise CertificationError(code + "_OBJECT")
    if value.get("status") != "passed":
        raise CertificationError(code + "_FAILED")
    return value


def _completed_json(completed: subprocess.CompletedProcess[str], code: str) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CertificationError(code + "_JSON") from exc
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise CertificationError(code)
    return value


def _local_lifecycle_commands(
    clone: Path,
    roots: Mapping[str, Path],
    python_executable: Path,
    homes: Mapping[str, Path],
) -> dict[str, list[str]]:
    knowledge = Path(roots["knowledge"])
    runtime = Path(roots["runtime"])
    manifest = runtime / "install-manifest.json"
    setup = [
        "-B",
        "-m",
        "ei.installer",
        "--setup",
        "--engine-root",
        str(clone),
        "--knowledge-mode",
        "local",
        "--personal-knowledge-root",
        str(knowledge),
        "--runtime-root",
        str(runtime),
        "--python-exe",
        str(python_executable),
        "--skip-venv",
        "--non-interactive",
        "--accept-plan",
        "--no-sync",
        "--organizer-provider",
        "subscription-cli",
        "--organizer-host",
        "codex-cli",
        "--json",
    ]
    for host_id in PUBLIC_CLI_HOST_IDS:
        setup.extend(("--hosts", host_id, "--host-home", f"{host_id}={homes[host_id]}"))
    return {
        "setup": setup,
        "doctor_from_manifest": [
            "-B",
            "-m",
            "ei.cli",
            "doctor",
            "--engine-root",
            str(clone),
            "--runtime-root",
            str(runtime),
            "--json",
        ],
        "update_check": [
            "-B",
            "-m",
            "ei.installer",
            "--update",
            "--manifest",
            str(manifest),
            "--check-only",
            "--json",
        ],
        "uninstall_check": [
            "-B",
            "-m",
            "ei.installer",
            "--uninstall",
            "--manifest",
            str(manifest),
            "--check-only",
            "--json",
        ],
        "uninstall_apply": [
            "-B",
            "-m",
            "ei.installer",
            "--uninstall",
            "--manifest",
            str(manifest),
            "--json",
        ],
    }


def _confirmed_uninstall_command(
    command: Sequence[str],
    check_result: Mapping[str, Any],
) -> list[str]:
    manifest_sha256 = check_result.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or not _SHA256_RE.fullmatch(manifest_sha256):
        raise CertificationError("UNINSTALL_CHECK_FAILED")
    return [*command, "--confirm-manifest-sha256", manifest_sha256]


def _fixture_receipts(clone: Path, workspace: Path, env: Mapping[str, str], python_executable: Path, roots: Mapping[str, Path]) -> None:
    from ei.certification import certify_host
    from ei.config import load_settings

    settings = load_settings(
        engine_root=clone,
        knowledge_root=roots["knowledge"],
        runtime_root=roots["runtime"],
        host_homes={host: roots["homes"] / host for host in PUBLIC_CLI_HOST_IDS},
    )
    receipt_root = workspace / "fixture-receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    for host_id in REQUIRED_HOST_IDS:
        result = certify_host(host_id, "clean-clone-" + host_id, "fixture", settings)
        if result.status != "PASSED" or not result.receipt:
            raise CertificationError("HOST_FIXTURE_CONTRACT_FAILED")
        validate_receipt_artifact(result.receipt)
        (receipt_root / f"{host_id}.json").write_text(
            json.dumps(dict(result.receipt), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def _seed_recall_projection(roots: Mapping[str, Path]) -> None:
    event = Event.create(
        "pattern.promoted",
        "2026-01-01T00:00:00Z",
        "offline-certification",
        "offline-machine",
        {
            "pattern_id": "pat_clean_clone",
            "cluster_id": "cluster_clean_clone",
            "rule": "After a spreadsheet write, reload the target range and verify the persisted value.",
            "provenances": ["fixture:clean-clone"],
            "scopes": ["spreadsheet"],
            "applicability": ["spreadsheet"],
            "benefit_count": 1,
            "evidence_count": 2,
            "classification": "private-reusable",
        },
        event_id="evt_clean_clone_pattern",
    )
    project_events([event], roots["knowledge"] / "knowledge")


def _closeout_fixture_payload() -> dict[str, Any]:
    return {
        "decision": "NO",
        "candidate_id": "offline-clean-clone",
        "candidate_title": "Offline fixture",
        "candidate_claim": "This fixture is intentionally not persisted as reusable knowledge.",
        "reason_code": "one_off_fact",
        "classification": "private-reusable",
        "source_ref": "fixture:clean-clone",
    }


def _prepare_legacy_migration(workspace: Path, runtime: Path) -> tuple[Path, Path]:
    source = workspace / "legacy-combined-root"
    destination = workspace / "migrated-root"
    source.mkdir(parents=True, exist_ok=True)
    (source / "knowledge-repository.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository_kind": "private-knowledge",
                "sync_enabled": False,
                "storage": {"events_are_append_only": True, "projections_are_rebuildable": True},
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (source / ".gitignore").write_text("runtime/\n", encoding="utf-8", newline="\n")
    runtime.mkdir(parents=True, exist_ok=True)
    return source, destination


def _validate_receipt(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_KEYS:
        raise ValueError("PUBLIC_CLONE_RECEIPT_SCHEMA_INVALID")
    if value.get("receipt_type") != RECEIPT_TYPE or value.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise ValueError("PUBLIC_CLONE_RECEIPT_TYPE_INVALID")
    if value.get("status") not in {"PASSED", "FAILED", "BLOCKED"}:
        raise ValueError("PUBLIC_CLONE_RECEIPT_STATUS_INVALID")
    for key in ("source_commit_sha", "clone_commit_sha", "source_tree_id", "clone_tree_id"):
        if not isinstance(value.get(key), str) or not _SHA40_RE.fullmatch(value[key]):
            raise ValueError("PUBLIC_CLONE_RECEIPT_SHA_INVALID")
    for key in ("runner_inventory_sha256", "workflow_sha256", "dependency_lock_sha256", "source_audit_sha256", "public_audit_sha256"):
        if not isinstance(value.get(key), str) or not _SHA256_RE.fullmatch(value[key]):
            raise ValueError("PUBLIC_CLONE_RECEIPT_HASH_INVALID")
    if not isinstance(value.get("package_hashes"), Mapping) or not value["package_hashes"]:
        raise ValueError("PUBLIC_CLONE_RECEIPT_PACKAGES_INVALID")
    if any(not isinstance(key, str) or not key or not _SHA256_RE.fullmatch(str(hash_value)) for key, hash_value in value["package_hashes"].items()):
        raise ValueError("PUBLIC_CLONE_RECEIPT_PACKAGES_INVALID")
    os_value = value.get("os")
    if not isinstance(os_value, Mapping) or set(os_value) != {"system", "release", "image"}:
        raise ValueError("PUBLIC_CLONE_RECEIPT_OS_INVALID")
    if any(not isinstance(os_value[key], str) or not _SAFE_IMAGE_RE.fullmatch(os_value[key]) for key in os_value):
        raise ValueError("PUBLIC_CLONE_RECEIPT_OS_INVALID")
    if not isinstance(value.get("python_version"), str) or not re.fullmatch(r"\d+\.\d+\.\d+", value["python_version"]):
        raise ValueError("PUBLIC_CLONE_RECEIPT_PYTHON_INVALID")
    contracts = value.get("host_contracts")
    if contracts != list(PUBLIC_CLI_HOST_IDS):
        raise ValueError("PUBLIC_CLONE_RECEIPT_HOSTS_INVALID")
    for key in ("test_module_count", "test_count", "test_skipped_count"):
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError("PUBLIC_CLONE_RECEIPT_COUNTS_INVALID")
    if type(value.get("duration_seconds")) not in {int, float} or value["duration_seconds"] < 0:
        raise ValueError("PUBLIC_CLONE_RECEIPT_DURATION_INVALID")
    steps = value.get("steps")
    if not isinstance(steps, list) or not steps or any(
        not isinstance(item, Mapping)
        or set(item) - {"name", "status", "duration_seconds", "error_code"}
        or not isinstance(item.get("name"), str)
        or item.get("status") not in {"passed", "failed"}
        for item in steps
    ):
        raise ValueError("PUBLIC_CLONE_RECEIPT_STEPS_INVALID")
    if type(value.get("offline_fixtures")) is not bool or value["offline_fixtures"] is not True:
        raise ValueError("PUBLIC_CLONE_RECEIPT_OFFLINE_FLAG_INVALID")
    isolated = value.get("isolated_environment")
    if isolated != {"venv": True, "developer_home": False, "credentials": False, "git_config": False}:
        raise ValueError("PUBLIC_CLONE_RECEIPT_ISOLATION_INVALID")
    if value.get("absolute_path_findings") != 0:
        raise ValueError("PUBLIC_CLONE_RECEIPT_PATH_LEAK")
    if not isinstance(value.get("generated_at"), str) or not value["generated_at"].endswith("Z"):
        raise ValueError("PUBLIC_CLONE_RECEIPT_TIME_INVALID")
    digest_basis = {key: value[key] for key in sorted(_RECEIPT_KEYS - {"receipt_sha256"})}
    if value.get("receipt_sha256") != _digest(digest_basis):
        raise ValueError("PUBLIC_CLONE_RECEIPT_HASH_MISMATCH")
    return True


def _base_receipt(*, source_commit: str, clone_commit: str, source_tree: str, clone_tree: str, inventory_hash: str, workflow_hash: str, lock_hash: str, source_audit_hash: str, public_audit_hash: str, packages: Mapping[str, str], steps: Sequence[Mapping[str, Any]], counts: Mapping[str, int], started: float, status: str) -> dict[str, Any]:
    image = os.environ.get("ImageOS") or os.environ.get("RUNNER_OS") or platform.system()
    value: dict[str, Any] = {
        "receipt_type": RECEIPT_TYPE,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": status,
        "source_commit_sha": source_commit,
        "clone_commit_sha": clone_commit,
        "source_tree_id": source_tree,
        "clone_tree_id": clone_tree,
        "os": {"system": _safe_text(platform.system(), pattern=_SAFE_IMAGE_RE), "release": _safe_text(platform.release(), pattern=_SAFE_IMAGE_RE), "image": _safe_text(image, pattern=_SAFE_IMAGE_RE)},
        "python_version": platform.python_version(),
        "package_hashes": dict(sorted(packages.items())),
        "runner_inventory_sha256": inventory_hash,
        "workflow_sha256": workflow_hash,
        "dependency_lock_sha256": lock_hash,
        "source_audit_sha256": source_audit_hash,
        "public_audit_sha256": public_audit_hash,
        "host_contracts": list(PUBLIC_CLI_HOST_IDS),
        "test_module_count": int(counts.get("modules", 0)),
        "test_count": int(counts.get("tests", 0)),
        "test_skipped_count": int(counts.get("tests_skipped", 0)),
        "duration_seconds": round(time.monotonic() - started, 6),
        "steps": [dict(item) for item in steps],
        "offline_fixtures": True,
        "isolated_environment": {"venv": True, "developer_home": False, "credentials": False, "git_config": False},
        "absolute_path_findings": 0,
        "generated_at": _now(),
    }
    value["receipt_sha256"] = _digest({key: value[key] for key in sorted(_RECEIPT_KEYS - {"receipt_sha256"})})
    _validate_receipt(value)
    return value


def certify(source_value: Path | str, *, offline_fixtures: bool, timeout_seconds: float = 300.0) -> dict[str, Any]:
    if not offline_fixtures:
        raise CertificationError("OFFLINE_FIXTURES_REQUIRED")
    source = Path(source_value).expanduser().resolve()
    source_commit, source_tree = _source_revision(source)
    started = time.monotonic()
    steps: list[dict[str, Any]] = []
    empty_values: dict[str, Any] = {
        "source_commit": source_commit,
        "clone_commit": source_commit,
        "source_tree": source_tree,
        "clone_tree": source_tree,
        "inventory_hash": _sha256(b""),
        "workflow_hash": _sha256(b""),
        "lock_hash": _sha256(b""),
        "source_audit_hash": _sha256(b""),
        "public_audit_hash": _sha256(b""),
        "packages": {"certification-not-produced": _sha256(b"certification-not-produced")},
        "counts": {"modules": 0, "tests": 0, "tests_skipped": 0},
    }
    try:
        with tempfile.TemporaryDirectory(prefix="ei-public-clone-") as tmp:
            workspace = Path(tmp).resolve()
            if workspace == source or workspace.is_relative_to(source):
                raise CertificationError("CERTIFICATION_TEMP_ROOT_INVALID")
            clone = workspace / "clone with spaces 日本語"
            homes = {host: workspace / "host homes 日本語" / host for host in PUBLIC_CLI_HOST_IDS}
            for home in homes.values():
                home.mkdir(parents=True, exist_ok=True)
            environment = _isolated_environment(workspace, {host: homes[host] for host in PUBLIC_CLI_HOST_IDS})
            _step(steps, "clone", lambda: _run(["git", "clone", "--no-local", "--quiet", str(source), str(clone)], cwd=workspace, env=environment, timeout=timeout_seconds, code="CLONE_FAILED"))
            clone_commit = _git(clone, "rev-parse", "--verify", "HEAD").lower()
            clone_tree = _git(clone, "rev-parse", "--verify", "HEAD^{tree}").lower()
            if clone_commit != source_commit:
                raise CertificationError("CLONE_COMMIT_MISMATCH")
            if clone_tree != source_tree:
                raise CertificationError("CLONE_TREE_MISMATCH")
            venv_root = workspace / "venv"
            _step(steps, "isolated_venv", lambda: venv.EnvBuilder(with_pip=True, clear=True).create(venv_root))
            python_executable = venv_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if not python_executable.is_file():
                raise CertificationError("VENV_PYTHON_MISSING")
            environment = {**environment, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(clone / "src")}
            lock_hash = _sha256(b"".join((clone / name).read_bytes() for name in ("requirements-build.lock", "requirements-runtime.lock", "requirements-ci.lock")))
            for lock_name in ("requirements-build.lock", "requirements-runtime.lock", "requirements-ci.lock"):
                _step(steps, "install_" + lock_name.removesuffix(".lock"), lambda lock_name=lock_name: _run([python_executable, "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "-r", clone / lock_name], cwd=clone, env=environment, timeout=timeout_seconds, code=_lock_failure_code(lock_name)))
            package_dir = workspace / "dist"
            _step(steps, "build_packages", lambda: _run([python_executable, "-m", "build", "--wheel", "--sdist", "--no-isolation", "--outdir", package_dir], cwd=clone, env=environment, timeout=timeout_seconds, code="PACKAGE_BUILD_FAILED"))
            packages = _package_hashes(package_dir)
            wheel = _built_wheel(package_dir)
            _step(steps, "install_package", lambda: _run(_package_install_arguments(python_executable, wheel), cwd=clone, env=environment, timeout=timeout_seconds, code="PACKAGE_INSTALL_FAILED"))
            dependency_output = _step(steps, "dependency_lock_audit", lambda: _run([python_executable, "scripts/verify-dependency-lock.py", "--pyproject", "pyproject.toml", "--build-lock", "requirements-build.lock", "--runtime-lock", "requirements-runtime.lock", "--ci-lock", "requirements-ci.lock", "--workflow-dir", ".github/workflows"], cwd=clone, env=environment, timeout=timeout_seconds, code="DEPENDENCY_AUDIT_FAILED"))
            workflow_output = _step(steps, "workflow_security_audit", lambda: _json_command(python_executable, clone, environment, ["public-release", "workflows", "verify", "--workflow-dir", ".github/workflows", "--json"], timeout=timeout_seconds, code="WORKFLOW_AUDIT_FAILED"))
            source_output = _step(steps, "production_source_audit", lambda: _audit_json(python_executable, clone, environment, "scripts/audit-production-source.py", ["--repo", ".", "--json"], timeout=timeout_seconds, code="SOURCE_AUDIT_FAILED"))
            public_output = _step(steps, "public_tree_audit", lambda: _audit_json(python_executable, clone, environment, "scripts/audit-public-release.py", ["--repo", ".", "--policy", "release/publication-policy.json", "--working-tree", "--json"], timeout=timeout_seconds, code="PUBLIC_AUDIT_FAILED"))
            inventory_hash, module_count, module_names = _inventory_digest(clone)
            suite_summary_path = workspace / "unittest-summary.json"
            summary = _step(
                steps,
                "bounded_complete_suite",
                lambda: _bounded_complete_suite(
                    clone,
                    output=suite_summary_path,
                    log_dir=workspace / "test-logs",
                    python_executable=python_executable,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                ),
            )
            del module_names, dependency_output
            counts = summary.get("counts", {})
            if not isinstance(counts, Mapping) or int(counts.get("modules", 0)) != module_count:
                raise CertificationError("TEST_INVENTORY_INCOMPLETE")
            roots = {
                "knowledge": workspace / "private knowledge 日本語",
                "runtime": workspace / "machine runtime 日本語",
                "homes": workspace / "host homes 日本語",
            }
            commands = _local_lifecycle_commands(clone, roots, python_executable, homes)
            setup = _step(steps, "setup_apply", lambda: _run([python_executable, *commands["setup"]], cwd=clone, env=environment, timeout=timeout_seconds, code="SETUP_FAILED"))
            setup_result = _completed_json(setup, "SETUP_FAILED")
            if setup_result.get("status") != "SETUP_COMPLETE":
                raise CertificationError("SETUP_FAILED")
            _step(steps, "fixture_host_contracts", lambda: _fixture_receipts(clone, workspace, environment, python_executable, roots))
            _seed_recall_projection(roots)
            _step(steps, "recall", lambda: _json_command(python_executable, clone, environment, ["recall", "--engine-root", clone, "--knowledge-root", roots["knowledge"], "--runtime-root", roots["runtime"], "--query", "spreadsheet reload verify", "--json"], timeout=timeout_seconds, code="RECALL_FAILED"))
            closeout_path = workspace / "closeout.json"
            closeout_path.write_text(json.dumps(_closeout_fixture_payload(), sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            _step(steps, "closeout", lambda: _json_command(python_executable, clone, environment, ["closeout", "--engine-root", clone, "--knowledge-root", roots["knowledge"], "--runtime-root", roots["runtime"], "--input-json", closeout_path, "--json"], timeout=timeout_seconds, code="CLOSEOUT_FAILED"))
            _step(steps, "maintenance", lambda: _json_command(python_executable, clone, environment, ["maintain", "--engine-root", clone, "--knowledge-root", roots["knowledge"], "--runtime-root", roots["runtime"], "--sync-policy", "disabled", "--max-items", "10", "--time-budget-ms", "5000", "--json"], timeout=timeout_seconds, code="MAINTENANCE_FAILED"))
            _step(steps, "doctor_manifest_restore", lambda: _run([python_executable, *commands["doctor_from_manifest"]], cwd=clone, env=environment, timeout=timeout_seconds, code="DOCTOR_FAILED"))
            update_check = _step(steps, "update_check_only", lambda: _run([python_executable, *commands["update_check"]], cwd=clone, env=environment, timeout=timeout_seconds, code="UPDATE_CHECK_FAILED"))
            if _completed_json(update_check, "UPDATE_CHECK_FAILED").get("status") != "CHECK_ONLY":
                raise CertificationError("UPDATE_CHECK_FAILED")
            manifest = roots["runtime"] / "install-manifest.json"
            uninstall_check = _step(steps, "uninstall_check_only", lambda: _run([python_executable, *commands["uninstall_check"]], cwd=clone, env=environment, timeout=timeout_seconds, code="UNINSTALL_CHECK_FAILED"))
            uninstall_check_result = _completed_json(uninstall_check, "UNINSTALL_CHECK_FAILED")
            if not isinstance(uninstall_check_result.get("result"), Mapping) or uninstall_check_result["result"].get("status") != "CHECK_ONLY":
                raise CertificationError("UNINSTALL_CHECK_FAILED")
            uninstall_apply_command = _confirmed_uninstall_command(commands["uninstall_apply"], uninstall_check_result)
            uninstall_apply = _step(steps, "uninstall_apply", lambda: _run([python_executable, *uninstall_apply_command], cwd=clone, env=environment, timeout=timeout_seconds, code="UNINSTALL_FAILED"))
            uninstall_result = _completed_json(uninstall_apply, "UNINSTALL_FAILED")
            nested_uninstall = uninstall_result.get("result")
            if not isinstance(nested_uninstall, Mapping) or nested_uninstall.get("status") != "UNINSTALLED":
                raise CertificationError("UNINSTALL_FAILED")
            if not (roots["knowledge"] / "knowledge-repository.json").is_file() or not manifest.is_file():
                raise CertificationError("UNINSTALL_RETENTION_FAILED")
            restored = _step(steps, "one_shot_restore", lambda: _run([python_executable, *commands["setup"]], cwd=clone, env=environment, timeout=timeout_seconds, code="RESTORE_FAILED"))
            if _completed_json(restored, "RESTORE_FAILED").get("status") != "SETUP_COMPLETE":
                raise CertificationError("RESTORE_FAILED")
            legacy, migrated = _prepare_legacy_migration(workspace, roots["runtime"])
            from ei.migrate import apply_root_migration, build_root_migration_plan, rollback_root_migration
            migration_plan = _step(steps, "migration_plan", lambda: build_root_migration_plan(legacy, migrated, roots["runtime"]))
            migration_result = _step(steps, "migration_apply", lambda: apply_root_migration(migration_plan))
            _step(
                steps,
                "migration_rollback",
                lambda: rollback_root_migration(
                    migration_result,
                    confirm_plan_hash=migration_plan.plan_hash,
                ),
            )
            _step(steps, "sync_plan", lambda: _json_command(python_executable, clone, environment, ["sync", "plan", "--engine-root", clone, "--knowledge-root", roots["knowledge"], "--runtime-root", roots["runtime"], "--json"], timeout=timeout_seconds, code="SYNC_PLAN_FAILED"))
            return _base_receipt(source_commit=source_commit, clone_commit=clone_commit, source_tree=source_tree, clone_tree=clone_tree, inventory_hash=inventory_hash, workflow_hash=str(workflow_output["workflow_sha256"]), lock_hash=lock_hash, source_audit_hash=str(source_output["report_digest"] if source_output.get("report_digest") else _digest(source_output)), public_audit_hash=str(public_output["report_digest"]), packages=packages, steps=steps, counts={"modules": int(counts.get("modules", 0)), "tests": int(counts.get("tests", 0)), "tests_skipped": int(counts.get("tests_skipped", 0))}, started=started, status="PASSED")
    except CertificationError:
        raise


def _write_receipt(path: Path, value: Mapping[str, Any]) -> None:
    directory = safe_ensure_directory(path.expanduser().absolute().parent, mode=0o700)
    raw = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    safe_atomic_write(directory, directory / path.name, raw, mode=0o600)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline-fixtures", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.timeout_seconds <= 0:
            raise CertificationError("CERTIFICATION_TIMEOUT_INVALID")
        receipt = certify(args.source, offline_fixtures=bool(args.offline_fixtures), timeout_seconds=float(args.timeout_seconds))
    except CertificationError as exc:
        failure: dict[str, Any] = {"status": "failed", "error_code": exc.code}
        if exc.diagnostics is not None:
            failure["diagnostics"] = exc.diagnostics
        print(json.dumps(failure, ensure_ascii=False, sort_keys=True))
        return 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "failed", "error_code": _safe_text(type(exc).__name__)}, ensure_ascii=False, sort_keys=True))
        return 1
    _write_receipt(args.output, receipt)
    print(json.dumps({"status": receipt["status"], "receipt_sha256": receipt["receipt_sha256"], "output": args.output.name}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
