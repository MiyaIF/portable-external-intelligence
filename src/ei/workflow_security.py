"""Static security contract for workflows that may be published publicly."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<value>[^\s#]+)")
_SHELL_BRIDGE = re.compile(r"(?i)(?:^|[\s])(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-command|pwsh(?:\.exe)?\s+-command|(?:sh|bash|zsh)\s+-c)(?:[\s]|$)")


@dataclass(frozen=True)
class WorkflowFinding:
    workflow: str
    code: str
    detail: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"workflow": self.workflow, "code": self.code, "detail": self.detail}
        if self.line is not None:
            value["line"] = self.line
        return value


class WorkflowSecurityError(ValueError):
    """Raised when a public workflow cannot satisfy the security contract."""


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise WorkflowSecurityError("YAML_PARSER_UNAVAILABLE") from exc
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise WorkflowSecurityError(f"WORKFLOW_READ_INVALID:{path.name}") from exc
    if not isinstance(value, Mapping):
        raise WorkflowSecurityError(f"WORKFLOW_OBJECT_REQUIRED:{path.name}")
    return value


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}/{index}")


def _permissions_findings(workflow: str, document: Mapping[str, Any]) -> list[WorkflowFinding]:
    findings: list[WorkflowFinding] = []
    permissions = document.get("permissions")
    if permissions is None:
        findings.append(WorkflowFinding(workflow, "PERMISSIONS_MISSING", "top-level permissions must be explicit"))
    elif isinstance(permissions, str):
        if permissions.casefold() != "read-all":
            findings.append(WorkflowFinding(workflow, "PERMISSIONS_TOO_BROAD", str(permissions)))
    elif isinstance(permissions, Mapping):
        for key, value in permissions.items():
            if str(value).casefold() not in {"read", "none"}:
                findings.append(WorkflowFinding(workflow, "PERMISSIONS_TOO_BROAD", f"{key}={value}"))
    else:
        findings.append(WorkflowFinding(workflow, "PERMISSIONS_INVALID", "permissions must be a mapping"))
    return findings


def _matrix_values(document: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        return values
    for job in jobs.values():
        if not isinstance(job, Mapping):
            continue
        matrix = job.get("strategy", {}).get("matrix") if isinstance(job.get("strategy"), Mapping) else None
        if not isinstance(matrix, Mapping):
            continue
        for key, value in matrix.items():
            if key in {"os", "runner", "python-version"} and isinstance(value, list):
                values.update(str(item) for item in value)
    return values


def _public_trigger(document: Mapping[str, Any], raw: str) -> bool:
    # PyYAML 1.1 may decode the YAML 1.2 `on` key as True. Raw text is the
    # authoritative trigger check for the security rule.
    return bool(re.search(r"(?m)^\s*pull_request\s*:", raw))


def audit_workflow(path: Path) -> list[WorkflowFinding]:
    raw = path.read_text(encoding="utf-8")
    document = _load_yaml(path)
    workflow = path.name
    findings = _permissions_findings(workflow, document)
    matrix_values = _matrix_values(document)
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping) or not jobs:
        findings.append(WorkflowFinding(workflow, "JOBS_MISSING", "jobs must be a non-empty mapping"))
    else:
        for job_id, job in jobs.items():
            if not isinstance(job, Mapping):
                findings.append(WorkflowFinding(workflow, "JOB_INVALID", str(job_id)))
                continue
            if "timeout-minutes" not in job:
                findings.append(WorkflowFinding(workflow, "TIMEOUT_MISSING", str(job_id)))
            runner = job.get("runs-on")
            if isinstance(runner, str) and "self-hosted" in runner.casefold():
                findings.append(WorkflowFinding(workflow, "SELF_HOSTED_RUNNER", str(job_id)))
            if runner == "${{ matrix.os }}" and not matrix_values:
                findings.append(WorkflowFinding(workflow, "RUNNER_MATRIX_UNVALIDATED", str(job_id)))
            if isinstance(runner, str) and _EXPRESSION.search(runner) and runner != "${{ matrix.os }}":
                findings.append(WorkflowFinding(workflow, "RUNNER_INPUT_UNTRUSTED", str(job_id)))
    for path, value in _walk(document):
        if path.endswith("/run") and isinstance(value, str) and _EXPRESSION.search(value):
            findings.append(
                WorkflowFinding(
                    workflow,
                    "RUN_EXPRESSION_UNTRUSTED",
                    f"run contains an expression at {path}",
                )
            )
    for line_number, line in enumerate(raw.splitlines(), start=1):
        uses_match = _USES.match(line)
        if uses_match:
            reference = uses_match.group("value")
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                findings.append(WorkflowFinding(workflow, "ACTION_REFERENCE_INVALID", reference, line_number))
            else:
                action, ref = reference.rsplit("@", 1)
                if not action or not _SHA40.fullmatch(ref):
                    findings.append(WorkflowFinding(workflow, "ACTION_NOT_IMMUTABLE", reference, line_number))
        if _SHELL_BRIDGE.search(line):
            findings.append(WorkflowFinding(workflow, "SHELL_BRIDGE_FORBIDDEN", "shell bridge in workflow", line_number))
    if _public_trigger(document, raw) and re.search(r"\bsecrets\.", raw):
        findings.append(WorkflowFinding(workflow, "PULL_REQUEST_SECRET_USE", "pull_request workflow references secrets"))
    return sorted(findings, key=lambda item: (item.workflow, item.line or 0, item.code, item.detail))


def audit_workflows(directory: Path) -> dict[str, Any]:
    root = directory.expanduser().resolve()
    if not root.is_dir():
        raise WorkflowSecurityError("WORKFLOW_DIRECTORY_MISSING")
    paths = sorted(path for path in root.glob("*.y*ml") if path.is_file())
    if not paths:
        raise WorkflowSecurityError("WORKFLOW_DIRECTORY_EMPTY")
    findings: list[WorkflowFinding] = []
    hashes: dict[str, str] = {}
    for path in paths:
        findings.extend(audit_workflow(path))
        hashes[path.name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "status": "passed" if not findings else "failed",
        "workflow_count": len(paths),
        "workflow_hashes": hashes,
        "workflow_sha256": "sha256:" + hashlib.sha256(json.dumps(hashes, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        "findings": [finding.to_dict() for finding in findings],
    }


__all__ = ["WorkflowFinding", "WorkflowSecurityError", "audit_workflow", "audit_workflows"]
