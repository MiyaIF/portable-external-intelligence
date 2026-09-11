from __future__ import annotations

import ast
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, TextIO


_TEST_FILE_RE = re.compile(r"^test_[^/]+\.py$")
_TEST_COUNT_RE = re.compile(r"Ran\s+(\d+)\s+test")
_SKIPPED_COUNT_RE = re.compile(r"skipped=(\d+)")
_FAILED_TEST_CASE_RE = re.compile(r"(?m)^(?:ERROR|FAIL):\s+(test_[A-Za-z0-9_]{1,88})\s+\(")
_STABLE_FAILURE_CODE_RE = re.compile(
    r"(?m)^(?:AssertionError|ValueError|RuntimeError|SafeFilesystemError|PublicExportError|InputError):\s*"
    r"([A-Z][A-Z0-9_]{2,95})(?:\s|$)"
)
_PLATFORM_SKIP_NAMES = frozenset({"PLATFORM_SKIP", "APPROVED_PLATFORM_SKIP", "__ei_platform_skip__"})
_MAX_JOBS = 32


class TestRunnerError(ValueError):
    """Raised when the complete-suite inventory or runner contract is invalid."""


@dataclass(frozen=True)
class TestModule:
    module_name: str
    relative_path: str


@dataclass(frozen=True)
class TestModuleResult:
    module_name: str
    relative_path: str
    status: str
    returncode: int | None
    tests_run: int
    tests_skipped: int
    duration_seconds: float
    log_path: str
    error_code: str | None = None

    def to_dict(self, *, repo_root: Path | None = None) -> dict[str, object]:
        log_path = Path(self.log_path)
        if repo_root is not None:
            try:
                log_value = log_path.resolve().relative_to(repo_root.resolve()).as_posix()
            except ValueError:
                log_value = log_path.name
        else:
            log_value = str(log_path)
        return {
            "module": self.module_name,
            "relative_path": self.relative_path,
            "status": self.status,
            "returncode": self.returncode,
            "tests_run": self.tests_run,
            "tests_skipped": self.tests_skipped,
            "duration_seconds": round(self.duration_seconds, 6),
            "log_path": log_value,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class CompleteSuiteSummary:
    successful: bool
    results: tuple[TestModuleResult, ...]
    counts: dict[str, int]
    duplicate_modules: tuple[str, ...] = ()

    def to_dict(self, *, repo_root: Path | None = None) -> dict[str, object]:
        return {
            "schema_version": 1,
            "successful": self.successful,
            "counts": dict(self.counts),
            "duplicate_modules": list(self.duplicate_modules),
            "modules": [result.to_dict(repo_root=repo_root) for result in self.results],
        }


def _normalise_relative_path(value: str) -> str:
    text = str(value).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not text.startswith("tests/"):
        raise TestRunnerError("TEST_PATH_INVALID")
    return path.as_posix()


def _git_tracked_files(repo_root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--", "tests"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise TestRunnerError("TEST_INVENTORY_GIT_UNAVAILABLE") from exc
    if completed.returncode != 0:
        raise TestRunnerError("TEST_INVENTORY_GIT_FAILED")
    try:
        decoded = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TestRunnerError("TEST_INVENTORY_PATH_ENCODING_INVALID") from exc
    return [item for item in decoded.split("\0") if item]


def discover_test_modules(repo_root: Path | str, *, tracked_files: Iterable[str] | None = None) -> list[TestModule]:
    root = Path(repo_root).expanduser().resolve()
    paths = list(tracked_files) if tracked_files is not None else _git_tracked_files(root)
    modules: list[TestModule] = []
    seen_paths: set[str] = set()
    seen_modules: set[str] = set()
    for raw_path in paths:
        relative_path = _normalise_relative_path(raw_path)
        if relative_path in seen_paths:
            raise TestRunnerError("DUPLICATE_TEST_MODULE:" + relative_path)
        seen_paths.add(relative_path)
        path = PurePosixPath(relative_path)
        if not _TEST_FILE_RE.fullmatch(path.name):
            continue
        module_name = ".".join(path.with_suffix("").parts)
        if module_name in seen_modules:
            raise TestRunnerError("DUPLICATE_TEST_MODULE:" + module_name)
        seen_modules.add(module_name)
        modules.append(TestModule(module_name=module_name, relative_path=relative_path))
    return sorted(modules, key=lambda item: item.module_name)


def _module_path(repo_root: Path, module: TestModule) -> Path:
    relative = Path(*PurePosixPath(module.relative_path).parts)
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise TestRunnerError("TEST_PATH_OUTSIDE_REPOSITORY") from exc
    return path


def _declares_platform_skip(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id in _PLATFORM_SKIP_NAMES for target in targets):
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                return True
    return False


def _log_file(log_dir: Path, module_name: str) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", module_name)
    return log_dir / f"{safe_name}.log"


def _bounded_log(log_path: Path, stdout: bytes, stderr: bytes, max_log_bytes: int) -> None:
    combined = b"[stdout]\n" + stdout + b"\n[stderr]\n" + stderr
    if len(combined) > max_log_bytes:
        marker = b"\n[output truncated]\n"
        if max_log_bytes <= len(marker):
            combined = marker[:max_log_bytes]
        else:
            combined = combined[: max_log_bytes - len(marker)] + marker
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(combined)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            process.kill()
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        deadline = time.monotonic() + 1.0
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            process.kill()


def _test_counts(output: bytes) -> tuple[int, int]:
    text = output.decode("utf-8", "replace")
    match = _TEST_COUNT_RE.search(text)
    tests_run = int(match.group(1)) if match else 0
    skipped_match = _SKIPPED_COUNT_RE.search(text)
    tests_skipped = int(skipped_match.group(1)) if skipped_match else 0
    return tests_run, tests_skipped


def _stable_failure_code(output: bytes) -> str | None:
    text = output.decode("utf-8", "replace")
    matches = _STABLE_FAILURE_CODE_RE.findall(text)
    if matches:
        return matches[-1]
    case_match = _FAILED_TEST_CASE_RE.search(text)
    case_suffix = "_" + case_match.group(1).upper() if case_match else ""
    lowered = text.casefold()
    if "filenotfounderror" in lowered or "no such file or directory" in lowered:
        return "TEST_DEPENDENCY_MISSING" + case_suffix
    if "unicodeencodeerror" in lowered or "unicodedecodeerror" in lowered:
        return "TEST_TEXT_ENCODING_FAILED" + case_suffix
    return None


def _environment(repo_root: Path, base_environment: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(base_environment) if base_environment is not None else os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    source_entries = [str(repo_root), str(repo_root / "src")]
    existing = env.get("PYTHONPATH")
    if existing:
        source_entries.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(source_entries)
    return env


def _child_creation_flags(platform_name: str = os.name) -> int:
    if platform_name != "nt":
        return 0
    return getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run_test_module(
    module: TestModule,
    repo_root: Path | str,
    *,
    timeout_seconds: float = 300.0,
    python_executable: Path | str | None = None,
    log_dir: Path | str | None = None,
    max_log_bytes: int = 256 * 1024,
    environment: Mapping[str, str] | None = None,
) -> TestModuleResult:
    root = Path(repo_root).expanduser().resolve()
    if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
        raise TestRunnerError("TEST_TIMEOUT_INVALID")
    if type(max_log_bytes) is not int or max_log_bytes <= 0:
        raise TestRunnerError("TEST_LOG_LIMIT_INVALID")
    executable = Path(python_executable or sys.executable).expanduser().resolve()
    destination = Path(log_dir or root / "artifacts" / "test-logs").expanduser().resolve()
    log_path = _log_file(destination, module.module_name)
    source_path = _module_path(root, module)
    started = time.monotonic()
    if not source_path.is_file():
        _bounded_log(log_path, b"", b"missing tracked test module", max_log_bytes)
        return TestModuleResult(module.module_name, module.relative_path, "missing", None, 0, 0, time.monotonic() - started, str(log_path), "TEST_MODULE_MISSING")
    if _declares_platform_skip(source_path):
        _bounded_log(log_path, b"approved platform skip", b"", max_log_bytes)
        return TestModuleResult(module.module_name, module.relative_path, "skipped", 0, 0, time.monotonic() - started, str(log_path), "APPROVED_PLATFORM_SKIP")

    creationflags = _child_creation_flags()
    try:
        process = subprocess.Popen(
            [str(executable), "-B", "-m", "unittest", module.module_name],
            cwd=str(root),
            env=_environment(root, environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        _bounded_log(log_path, b"", str(exc).encode("utf-8", "replace"), max_log_bytes)
        return TestModuleResult(module.module_name, module.relative_path, "crashed", None, 0, 0, time.monotonic() - started, str(log_path), "TEST_CHILD_START_FAILED")

    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=float(timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        _terminate_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        stdout = stdout or exc.output or b""
        stderr = stderr or exc.stderr or b""
    duration = time.monotonic() - started
    stdout = stdout or b""
    stderr = stderr or b""
    _bounded_log(log_path, stdout, stderr, max_log_bytes)
    tests_run, tests_skipped = _test_counts(stdout + b"\n" + stderr)
    returncode = process.returncode
    if timed_out:
        status, error_code = "timed_out", "TEST_CHILD_TIMEOUT"
    elif tests_run == 0 and returncode in (0, 5):
        status, error_code = "zero_test", "TEST_MODULE_ZERO_TESTS"
    elif returncode == 0:
        status, error_code = "passed", None
    elif any(marker in stdout + stderr for marker in (b"FAILED", b"ERROR", b"errors=")):
        status = "failed"
        error_code = _stable_failure_code(stdout + b"\n" + stderr) or "TEST_ASSERTION_FAILED"
    else:
        status, error_code = "crashed", "TEST_CHILD_CRASHED"
    return TestModuleResult(module.module_name, module.relative_path, status, returncode, tests_run, tests_skipped, duration, str(log_path), error_code)


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_complete_suite(
    repo_root: Path | str,
    *,
    output: Path | str,
    jobs: int = 1,
    timeout_seconds: float = 300.0,
    python_executable: Path | str | None = None,
    log_dir: Path | str | None = None,
    max_log_bytes: int = 256 * 1024,
    tracked_files: Iterable[str] | None = None,
    progress_stream: TextIO | None = None,
    environment: Mapping[str, str] | None = None,
) -> CompleteSuiteSummary:
    if type(jobs) is not int or not 1 <= jobs <= _MAX_JOBS:
        raise TestRunnerError("TEST_JOBS_INVALID")
    root = Path(repo_root).expanduser().resolve()
    modules = discover_test_modules(root, tracked_files=tracked_files)
    runner_args = {
        "repo_root": root,
        "timeout_seconds": timeout_seconds,
        "python_executable": python_executable,
        "log_dir": log_dir,
        "max_log_bytes": max_log_bytes,
        "environment": environment,
    }
    if jobs == 1:
        results: list[TestModuleResult] = []
        for index, module in enumerate(modules, start=1):
            result = run_test_module(module, **runner_args)
            results.append(result)
            if progress_stream is not None:
                progress_stream.write(f"[{index}/{len(modules)}] {module.module_name}: {result.status} ({result.tests_run} tests)\n")
                progress_stream.flush()
    else:
        with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="ei-test") as executor:
            futures = [executor.submit(run_test_module, module, **runner_args) for module in modules]
            results = []
            for index, (module, future) in enumerate(zip(modules, futures, strict=True), start=1):
                result = future.result()
                results.append(result)
                if progress_stream is not None:
                    progress_stream.write(f"[{index}/{len(modules)}] {module.module_name}: {result.status} ({result.tests_run} tests)\n")
                    progress_stream.flush()
    counter = Counter(result.status for result in results)
    counts = {
        "modules": len(results),
        "tests": sum(result.tests_run for result in results),
        "tests_skipped": sum(result.tests_skipped for result in results),
        "passed": counter.get("passed", 0),
        "failed": counter.get("failed", 0),
        "crashed": counter.get("crashed", 0),
        "timed_out": counter.get("timed_out", 0),
        "missing": counter.get("missing", 0),
        "zero_test": counter.get("zero_test", 0),
        "skipped": counter.get("skipped", 0),
    }
    successful = all(result.status in {"passed", "skipped"} for result in results)
    summary = CompleteSuiteSummary(successful=successful, results=tuple(results), counts=counts)
    _atomic_write_json(Path(output).expanduser().resolve(), summary.to_dict(repo_root=root))
    return summary
