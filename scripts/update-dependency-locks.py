"""Verify pinned upstream releases and regenerate all hash-locked inputs.

The script intentionally has no version resolver of its own.  Versions come
from the checked-in ``requirements-*.in`` files and are passed unchanged to
the pinned pip-tools release.  ``--verify-upstream`` fails closed when an
input release cannot be verified through the Python Package Index JSON API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PIP_TOOLS_VERSION = "7.6.1"
INPUTS = ("build", "runtime", "ci")


def _parse_input(path: Path) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line or any(token in line for token in (" @ ", " ", "<", ">", "~", "*", ";")):
            raise ValueError(f"{path.name}:{line_number}: exact name==version pin required")
        name, version = line.split("==", 1)
        if not name or not version or any(character in name + version for character in "[]()\\/"):
            raise ValueError(f"{path.name}:{line_number}: invalid exact pin")
        values.append((name.strip().lower().replace("_", "-"), version.strip()))
    if not values:
        raise ValueError(f"{path.name}: no requirements")
    return values


def _all_inputs(root: Path) -> dict[str, list[tuple[str, str]]]:
    return {name: _parse_input(root / f"requirements-{name}.in") for name in INPUTS}


def _verify_pyproject(root: Path, inputs: dict[str, list[tuple[str, str]]]) -> None:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    build_requires = data.get("build-system", {}).get("requires", [])
    runtime_requires = data.get("project", {}).get("dependencies", [])
    build_names = {str(value).split("==", 1)[0].casefold().replace("_", "-") for value in build_requires if isinstance(value, str) and "==" in value}
    runtime_names = {str(value).split("==", 1)[0].casefold().replace("_", "-") for value in runtime_requires if isinstance(value, str) and "==" in value}
    build_input_names = {name for name, _ in inputs["build"]}
    runtime_input_names = {name for name, _ in inputs["runtime"]}
    if not build_names.issubset(build_input_names):
        raise ValueError("requirements-build.in is missing a pyproject build requirement")
    if runtime_names != runtime_input_names:
        raise ValueError("requirements-runtime.in must match pyproject project.dependencies")


def _verify_upstream(inputs: dict[str, list[tuple[str, str]]], timeout: float) -> dict[str, dict[str, object]]:
    checked: dict[str, dict[str, object]] = {}
    for environment, requirements in inputs.items():
        for name, version in requirements:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
            request = Request(url, headers={"Accept": "application/json", "User-Agent": "portable-external-intelligence-lock-check/1"})
            try:
                with urlopen(request, timeout=timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"UPSTREAM_RELEASE_UNVERIFIED:{name}=={version}:{type(exc).__name__}") from exc
            info = payload.get("info") if isinstance(payload, dict) else None
            if not isinstance(info, dict) or info.get("version") != version:
                raise RuntimeError(f"UPSTREAM_RELEASE_MISMATCH:{name}=={version}")
            checked[f"{name}=={version}"] = {
                "environment": environment,
                "url": url,
                "version": version,
            }
    return checked


def _run_pip_compile(root: Path, environment: str, python_exe: str) -> None:
    input_path = root / f"requirements-{environment}.in"
    output_path = root / f"requirements-{environment}.lock"
    command = [
        python_exe,
        "-m",
        "piptools",
        "compile",
        f"--output-file={output_path}",
        "--resolver=backtracking",
        "--generate-hashes",
        "--allow-unsafe",
        "--no-annotate",
        "--no-emit-index-url",
        str(input_path),
    ]
    completed = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"LOCK_GENERATION_FAILED:{environment}:{completed.stderr.strip()[-500:]}")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--python", default=sys.executable, help="Python executable that owns the pinned pip-tools installation")
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)
    root = args.root.expanduser().resolve()
    try:
        inputs = _all_inputs(root)
        _verify_pyproject(root, inputs)
        upstream = _verify_upstream(inputs, args.timeout) if args.verify_upstream else {}
        if args.generate:
            version_check = subprocess.run(
                [args.python, "-c", "import importlib.metadata; print(importlib.metadata.version('pip-tools'))"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            installed_version = version_check.stdout.strip() if version_check.returncode == 0 else ""
            if installed_version != PIP_TOOLS_VERSION:
                raise RuntimeError(f"PIP_TOOLS_VERSION_REQUIRED:{PIP_TOOLS_VERSION}")
            for environment in INPUTS:
                _run_pip_compile(root, environment, args.python)
        result = {
            "schema_version": 1,
            "pip_tools_version": PIP_TOOLS_VERSION,
            "upstream_verified": bool(args.verify_upstream),
            "upstream": upstream,
            "inputs": {
                environment: [f"{name}=={version}" for name, version in requirements]
                for environment, requirements in inputs.items()
            },
            "locks": {
                environment: {
                    "path": f"requirements-{environment}.lock",
                    "sha256": _sha256(root / f"requirements-{environment}.lock"),
                }
                for environment in INPUTS
                if (root / f"requirements-{environment}.lock").is_file()
            },
        }
    except (OSError, UnicodeError, ValueError, RuntimeError, tomllib.TOMLDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
