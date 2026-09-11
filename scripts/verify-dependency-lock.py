from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9][A-Za-z0-9._-]*)$")
LOCK_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_. ,+-]+\])?=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)$"
)
RUNTIME_TRANSITIVES = {
    "cryptography": {"cffi", "pycparser"},
}
ACTION_REF_RE = re.compile(r"^\s*uses:\s*(?P<action>[^\s#]+)@(?P<ref>[^\s#]+)")
IMMUTABLE_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class LockEntry:
    name: str
    version: str
    hashes: tuple[str, ...]


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _read_pyproject(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    build_requires = data.get("build-system", {}).get("requires", [])
    runtime_requires = data.get("project", {}).get("dependencies", [])
    return _parse_exact_requirements(build_requires, "build-system.requires"), _parse_exact_requirements(
        runtime_requires,
        "project.dependencies",
    )


def _read_ci_tool_contract(pyproject_path: Path) -> dict[str, str]:
    defaults_path = pyproject_path.parent / "config" / "defaults.json"
    try:
        data = json.loads(defaults_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"CI_TOOL_CONTRACT_INVALID: {defaults_path.name}") from exc
    contract = data.get("dependency_locks", {})
    tools = contract.get("ci_tools") if isinstance(contract, dict) else None
    if not isinstance(tools, dict) or not tools:
        raise ValueError("CI_TOOL_CONTRACT_INVALID")
    normalized: dict[str, str] = {}
    for raw_name, raw_version in tools.items():
        if not isinstance(raw_name, str) or not raw_name or not isinstance(raw_version, str) or not raw_version:
            raise ValueError("CI_TOOL_CONTRACT_INVALID")
        name = _canonical_name(raw_name)
        previous = normalized.get(name)
        if previous is not None and previous != raw_version:
            raise ValueError("CI_TOOL_CONTRACT_INVALID")
        normalized[name] = raw_version
    if len(normalized) != len(tools):
        raise ValueError("CI_TOOL_CONTRACT_INVALID")
    return normalized


def _parse_exact_requirements(values: object, label: str) -> dict[str, str]:
    if not isinstance(values, list):
        raise ValueError(f"{label} must be a list")
    result: dict[str, str] = {}
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError(f"{label} must contain strings")
        match = PIN_RE.fullmatch(raw.strip())
        if not match:
            raise ValueError(f"{label} must use exact pins only: {raw}")
        name = _canonical_name(match.group("name"))
        version = match.group("version")
        previous = result.get(name)
        if previous is not None and previous != version:
            raise ValueError(f"{label} has conflicting pins for {name}")
        result[name] = version
    return result


def _parse_lock(path: Path) -> dict[str, LockEntry]:
    entries: dict[str, LockEntry] = {}
    logical_lines: list[tuple[int, str]] = []
    continuation = ""
    continuation_line = 0
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if continuation:
            continuation += " " + line.rstrip("\\").strip()
            if not line.endswith("\\"):
                logical_lines.append((continuation_line, continuation))
                continuation = ""
            continue
        if line.endswith("\\"):
            continuation = line[:-1].strip()
            continuation_line = line_number
            continue
        logical_lines.append((line_number, line))
    if continuation:
        raise ValueError(f"{path.name}:{continuation_line} has an unterminated continuation")
    for line_number, line in logical_lines:
        if line.startswith(("-e", "--editable")) or " @ " in line or line.count("@") > 1:
            raise ValueError(f"{path.name}:{line_number} must not use editable installs or direct URLs")
        match = LOCK_RE.fullmatch(line)
        if not match:
            raise ValueError(f"{path.name}:{line_number} must be exact name==version with sha256 hashes")
        name = _canonical_name(match.group("name"))
        version = match.group("version")
        hashes = tuple(token.removeprefix("--hash=sha256:") for token in match.group("hashes").split())
        if not hashes:
            raise ValueError(f"{path.name}:{line_number} is missing hashes")
        if len(set(hashes)) != len(hashes):
            raise ValueError(f"{path.name}:{line_number} has duplicate hashes")
        existing = entries.get(name)
        if existing is not None:
            if existing.version != version or existing.hashes != hashes:
                raise ValueError(f"{path.name} has duplicate or conflicting entries for {name}")
            raise ValueError(f"{path.name} has duplicate entries for {name}")
        entries[name] = LockEntry(name=name, version=version, hashes=hashes)
    return entries


def _require_expected_versions(expected: dict[str, str], actual: dict[str, LockEntry], label: str) -> None:
    for name, version in expected.items():
        entry = actual.get(name)
        if entry is None:
            raise ValueError(f"{label} is missing {name}=={version}")
        if entry.version != version:
            raise ValueError(f"{label} has version mismatch for {name}: {entry.version} != {version}")


def _require_exact_package_set(expected_names: set[str], actual: dict[str, LockEntry], label: str) -> None:
    actual_names = set(actual)
    missing = sorted(expected_names - actual_names)
    extras = sorted(actual_names - expected_names)
    if missing or extras:
        parts: list[str] = []
        if missing:
            parts.append("missing=" + ",".join(missing))
        if extras:
            parts.append("extra=" + ",".join(extras))
        raise ValueError(f"{label} package set mismatch: {'; '.join(parts)}")


def _require_direct_requirements(expected: dict[str, str], actual: dict[str, LockEntry], label: str) -> None:
    """Ensure every direct input is present while allowing resolved transitives."""

    for name, version in expected.items():
        entry = actual.get(name)
        if entry is None:
            raise ValueError(f"{label} is missing direct requirement {name}=={version}")
        if entry.version != version:
            raise ValueError(f"{label} direct requirement mismatch for {name}: {entry.version} != {version}")


def _expected_runtime_names(runtime_expected: dict[str, str]) -> set[str]:
    names = set(runtime_expected)
    for name in runtime_expected:
        names.update(RUNTIME_TRANSITIVES.get(name, set()))
    return names


def _read_input_requirements(path: Path) -> dict[str, str]:
    values: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            values.append(line)
    return _parse_exact_requirements(values, path.name)


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_workflow_actions(workflow_dir: Path) -> list[str]:
    if not workflow_dir.exists():
        return []
    failures: list[str] = []
    for path in sorted(workflow_dir.glob("*.y*ml")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            failures.append(f"{path.name}:WORKFLOW_READ_FAILED:{type(exc).__name__}")
            continue
        for line_number, line in enumerate(lines, start=1):
            candidate = line.split("#", 1)[0]
            match = ACTION_REF_RE.match(candidate)
            if not match:
                continue
            action, ref = match.group("action"), match.group("ref")
            if action.startswith("./"):
                continue
            if not IMMUTABLE_SHA_RE.fullmatch(ref):
                failures.append(f"{path.name}:{line_number}:ACTION_NOT_IMMUTABLE:{action}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pyproject", required=True, type=Path)
    parser.add_argument("--build-lock", required=True, type=Path)
    parser.add_argument("--runtime-lock", required=True, type=Path)
    parser.add_argument("--ci-lock", required=True, type=Path)
    parser.add_argument("--workflow-dir", type=Path)
    args = parser.parse_args(argv)

    try:
        build_expected, runtime_expected = _read_pyproject(args.pyproject)
        ci_expected = _read_ci_tool_contract(args.pyproject)
        root = args.pyproject.parent
        build_input = _read_input_requirements(root / "requirements-build.in")
        runtime_input = _read_input_requirements(root / "requirements-runtime.in")
        ci_input = _read_input_requirements(root / "requirements-ci.in")
        build_lock = _parse_lock(args.build_lock)
        runtime_lock = _parse_lock(args.runtime_lock)
        ci_lock = _parse_lock(args.ci_lock)
        _require_expected_versions(build_expected, build_lock, args.build_lock.name)
        _require_direct_requirements(build_input, build_lock, args.build_lock.name)
        _require_expected_versions(runtime_expected, runtime_lock, args.runtime_lock.name)
        _require_direct_requirements(runtime_input, runtime_lock, args.runtime_lock.name)
        _require_exact_package_set(_expected_runtime_names(runtime_expected), runtime_lock, args.runtime_lock.name)
        _require_expected_versions(ci_expected, ci_lock, args.ci_lock.name)
        _require_direct_requirements(ci_input, ci_lock, args.ci_lock.name)
        workflow_dir = args.workflow_dir or args.pyproject.parent / ".github" / "workflows"
        workflow_failures = _audit_workflow_actions(workflow_dir)
        if workflow_failures:
            raise ValueError("immutable workflow action audit failed: " + "; ".join(workflow_failures))
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        return _fail(str(exc))

    print(f"{args.build_lock.name} sha256={_hash_file(args.build_lock)}")
    print(f"{args.runtime_lock.name} sha256={_hash_file(args.runtime_lock)}")
    print(f"{args.ci_lock.name} sha256={_hash_file(args.ci_lock)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
