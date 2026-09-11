from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Sequence

_TEXT_EXTENSIONS = {".py", ".ps1", ".psm1", ".sh", ".bash", ".md", ".json", ".toml", ".yml", ".yaml"}
_CODE_EXTENSIONS = {".py"}
_ABSOLUTE_PERSONAL_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:[a-z]:[\\/]+(?:users|home)[\\/]+[^\\/\s\"']+|[a-z]:[\\/]+[^\\/\s\"']+)")
_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)"
    r"\s*[:=]\s*['\"][A-Za-z0-9_./+=-]{20,}['\"]"
)
_HEX_SECRET_RE = re.compile(r"(?i)\b(?:sk|ghp|github_pat)_[A-Za-z0-9_]{20,}\b")
_FORBIDDEN_IMPORTS = {"unittest.mock", "mock", "pytest_mock"}
_MARKERS = tuple(
    re.compile(r"\b" + marker + r"\b", re.IGNORECASE)
    for marker in ("TO" + "DO", "FIX" + "ME", "ST" + "UB", "PLACE" + "HOLDER")
)


def _files(repo: Path, requested: Sequence[str]) -> list[Path]:
    if requested:
        values = [(repo / item).resolve() if not Path(item).is_absolute() else Path(item).resolve() for item in requested]
    else:
        values = []
        for root_name in ("src", "scripts", "hooks", "skills"):
            root = repo / root_name
            if root.is_dir():
                values.extend(path for path in root.rglob("*") if path.is_file())
    return sorted(
        {
            path
            for path in values
            if path.is_file()
            and path.suffix.casefold() in _TEXT_EXTENSIONS
            and "__pycache__" not in path.parts
        }
    )


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.name


def _ast_violations(path: Path, source: str, relative: str) -> list[str]:
    if path.suffix.casefold() not in _CODE_EXTENSIONS:
        return []
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError as exc:
        return [f"{relative}:{exc.lineno or 0}:PYTHON_SYNTAX_INVALID"]
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Pass):
            violations.append(f"{relative}:{node.lineno}:EMPTY_PASS")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Constant) and body[0].value.value is True:
                violations.append(f"{relative}:{node.lineno}:CONSTANT_SUCCESS_ROUTE")
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            target = node.exc.func
            if isinstance(target, ast.Name) and target.id == "NotImplementedError":
                violations.append(f"{relative}:{node.lineno}:UNHANDLED_NOT_IMPLEMENTED")
        if isinstance(node, ast.Import):
            for imported in node.names:
                module = imported.name
                if module in _FORBIDDEN_IMPORTS or module.startswith("unittest.mock"):
                    violations.append(f"{relative}:{node.lineno}:TEST_ONLY_IMPORT")
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in _FORBIDDEN_IMPORTS or module.startswith("unittest.mock"):
                violations.append(f"{relative}:{node.lineno}:TEST_ONLY_IMPORT")
    return violations


def audit_paths(repo: Path, paths: Sequence[str] = ()) -> list[str]:
    violations: list[str] = []
    for path in _files(repo, paths):
        relative = _relative(path, repo)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            violations.append(f"{relative}:SOURCE_READ_FAILED:{type(exc).__name__}")
            continue
        if _ABSOLUTE_PERSONAL_PATH_RE.search(source):
            violations.append(f"{relative}:FORBIDDEN_WORKSPACE_PATH")
        private_parts = {part.casefold() for part in Path(relative).parts}
        if private_parts.intersection({"transcripts", "raw-transcript", "raw_prompt", "raw_response", "raw_tool_output", "credentials", "secret-data"}) and Path(relative).suffix.casefold() in _TEXT_EXTENSIONS:
            violations.append(f"{relative}:PRIVATE_DATA_PATH")
        if Path(relative).suffix.casefold() in {".sqlite", ".sqlite3", ".db"}:
            violations.append(f"{relative}:SQLITE_RUNTIME_ARTIFACT")
        if _SECRET_RE.search(source) or _HEX_SECRET_RE.search(source):
            violations.append(f"{relative}:POSSIBLE_CREDENTIAL_LITERAL")
        for marker in _MARKERS:
            if marker.search(source):
                violations.append(f"{relative}:UNRESOLVED_MARKER")
        violations.extend(_ast_violations(path, source, relative))
    return sorted(dict.fromkeys(violations))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit production source for unfinished or unsafe routes")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = args.repo.expanduser().resolve()
    violations = audit_paths(repo, args.path)
    result = {
        "status": "passed" if not violations else "failed",
        "repo": repo.name,
        "scanned_paths": len(_files(repo, args.path)),
        "violations": violations,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    elif violations:
        print("\n".join(violations))
    else:
        print("production source audit passed")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
