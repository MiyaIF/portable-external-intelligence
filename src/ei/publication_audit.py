from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .ids import canonical_json
from .publication_policy import validate_publication_policy


_TEXT_EXTENSIONS = frozenset({".py", ".ps1", ".psm1", ".sh", ".bash", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".ini"})
_PRIVATE_DATA_PARTS = frozenset({"transcripts", "raw-transcript", "raw_prompt", "raw_response", "raw_tool_output"})
# `$HOME`/`$USERPROFILE` are portable shell variables used in documentation,
# not resolved personal paths.  Only scan literal absolute paths here.
_PERSONAL_PATH_RE = re.compile(
    r"(?i)(?<!\$)(?:[a-z]:[\\/]+(?:users|home)[\\/]+[^\\/\s\"']+|(?<![A-Za-z0-9._-])/(?:users|home)/[^/\s\"']+)"
)
_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)"
    r"\s*[:=]\s*['\"][A-Za-z0-9_./+=-]{20,}['\"]"
)
_PRIVATE_KEY_BEGIN = "-----" + "BEGIN"
_PRIVATE_KEY_RE = re.compile(
    _PRIVATE_KEY_BEGIN
    + r"(?: [A-Z0-9-]+)* PRIVATE KEY-----|"
    + _PRIVATE_KEY_BEGIN
    + r" PGP (?:PRIVATE|SECRET) KEY BLOCK-----|"
    + "open"
    + "ssh-key-v1",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_BEARER_RE = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+")
_UNSAFE_RUN_RE = re.compile(r"(?im)^\s*(?:-\s*)?run\s*:\s*[^\n]*\$\{\{")
_HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class AuditCheck:
    check_id: str
    status: str
    evidence_path: str | None = None
    evidence_commit: str | None = None
    remediation: str = ""
    tool_version: str = "ei-publication-audit/1"

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "status": self.status,
            "evidence_path": self.evidence_path,
            "evidence_commit": self.evidence_commit,
            "remediation": self.remediation,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True)
class PublicationAuditResult:
    checks: tuple[AuditCheck, ...]
    scanned_files: int
    scanned_commits: int

    @property
    def passed(self) -> bool:
        return all(item.status in {"passed", "skipped"} for item in self.checks)

    def to_dict(self) -> dict[str, object]:
        checks = [item.to_dict() for item in self.checks]
        value: dict[str, object] = {
            "status": "passed" if self.passed else "failed",
            "scanned_files": self.scanned_files,
            "scanned_commits": self.scanned_commits,
            "checks": checks,
        }
        value["report_digest"] = "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()
        return value


def contains_private_key_material(value: bytes | str) -> bool:
    if isinstance(value, bytes):
        text = value.decode("ascii", "ignore")
    elif isinstance(value, str):
        text = value
    else:
        return False
    return _PRIVATE_KEY_RE.search(text) is not None


def _git(repo: Path, *arguments: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_paths(repo: Path, *, cached_and_untracked: bool) -> list[str]:
    arguments = ["ls-files", "-z"]
    if cached_and_untracked:
        arguments.extend(["--cached", "--others", "--exclude-standard"])
    else:
        arguments.append("--cached")
    arguments.extend(["--", "."])
    raw = _git(repo, *arguments)
    if raw is None:
        return []
    try:
        return sorted({item for item in raw.decode("utf-8").split("\0") if item})
    except UnicodeDecodeError:
        return []


def _relative(value: str) -> str:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & 0x400)


def _content_issues(text: str) -> tuple[str, ...]:
    issues: list[str] = []
    if _PERSONAL_PATH_RE.search(text):
        issues.append("TREE_FORBIDDEN_PERSONAL_PATH")
    if contains_private_key_material(text):
        issues.append("TREE_PRIVATE_KEY_MATERIAL")
    if _SECRET_RE.search(text) or _TOKEN_RE.search(text) or _BEARER_RE.search(text):
        issues.append("TREE_SECRET_PATTERN")
    return tuple(issues)


def _append_content_checks(checks: list[AuditCheck], relative: str, text: str, commit: str | None = None) -> None:
    for check_id in _content_issues(text):
        checks.append(
            AuditCheck(
                check_id,
                "failed",
                evidence_path=relative,
                evidence_commit=commit,
                remediation="remove or generalize the sensitive content before publication",
            )
        )


def _working_tree_files(repo: Path) -> list[tuple[str, Path]]:
    paths = _git_paths(repo, cached_and_untracked=True)
    if not paths:
        paths = [path.relative_to(repo).as_posix() for path in repo.rglob("*") if path.is_file()]
    result: list[tuple[str, Path]] = []
    for relative in paths:
        path = repo / Path(*PurePathParts(relative))
        try:
            path.relative_to(repo)
        except ValueError:
            continue
        result.append((_relative(relative), path))
    return result


def PurePathParts(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.replace("\\", "/").split("/") if part not in {"", "."})


def _history_commits(repo: Path) -> list[str]:
    raw = _git(repo, "rev-list", "--all")
    if not raw:
        return []
    return [item for item in raw.decode("ascii", "ignore").splitlines() if _HEX_SHA_RE.fullmatch(item)]


def _history_files(repo: Path, commit: str) -> list[tuple[str, str, str, str]]:
    raw = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    if raw is None:
        return []
    result: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record or b"\t" not in record:
            continue
        header, encoded_path = record.split(b"\t", 1)
        fields = header.split()
        if len(fields) != 3:
            continue
        mode, object_type, object_id = (field.decode("ascii", "replace") for field in fields)
        path = encoded_path.decode("utf-8", "replace")
        result.append((mode, object_type, object_id, path))
    return result


def _history_blob_contents(repo: Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    selected = sorted({item for item in object_ids if _HEX_SHA_RE.fullmatch(item)})
    if not selected:
        return {}
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input=("\n".join(selected) + "\n").encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return {}
    if completed.returncode != 0:
        return {}
    output = completed.stdout
    offset = 0
    contents: dict[str, bytes] = {}
    for requested in selected:
        newline = output.find(b"\n", offset)
        if newline < 0:
            return {}
        header = output[offset:newline].split()
        offset = newline + 1
        if len(header) == 2 and header[1] == b"missing":
            continue
        if len(header) != 3:
            return {}
        try:
            actual = header[0].decode("ascii")
            object_type = header[1].decode("ascii")
            size = int(header[2])
        except (UnicodeDecodeError, ValueError):
            return {}
        if actual != requested or size < 0 or offset + size >= len(output):
            return {}
        content = output[offset : offset + size]
        offset += size
        if output[offset : offset + 1] != b"\n":
            return {}
        offset += 1
        if object_type == "blob":
            contents[requested] = content
    return contents


def _identity_checks(repo: Path, policy: Mapping[str, Any]) -> list[AuditCheck]:
    raw = _git(repo, "log", "--format=%H%x00%ae")
    if raw is None:
        return []
    allowed = str(policy["public_author"]["email"]).casefold()
    checks: list[AuditCheck] = []
    records = raw.decode("utf-8", "replace").splitlines()
    for record in records:
        if "\0" not in record:
            continue
        commit, email = record.split("\0", 1)
        if not _HEX_SHA_RE.fullmatch(commit) or email.casefold() == allowed:
            continue
        checks.append(
            AuditCheck(
                "HISTORY_AUTHOR_NOT_ALLOWLISTED",
                "failed",
                evidence_commit=commit,
                remediation="create a sanitized public root with the owner-approved author identity",
            )
        )
    return checks


def _workflow_checks(relative: str, text: str) -> list[AuditCheck]:
    checks: list[AuditCheck] = []
    if re.search(r"(?i)\bself-hosted\b", text):
        checks.append(AuditCheck("WORKFLOW_SELF_HOSTED", "failed", relative, remediation="use GitHub-hosted ephemeral runners"))
    if _UNSAFE_RUN_RE.search(text):
        checks.append(AuditCheck("WORKFLOW_INPUT_INJECTION", "failed", relative, remediation="validate inputs and pass them through an environment boundary"))
    return checks


def _license_check(repo: Path, relative_paths: Iterable[str]) -> AuditCheck:
    if any(Path(relative).name.casefold().startswith("license") for relative in relative_paths):
        return AuditCheck("LICENSE_PRESENT", "passed")
    return AuditCheck("LICENSE_MISSING", "failed", remediation="add the exact owner-selected license text")


def _evidence_check(repo: Path, head: str | None) -> AuditCheck | None:
    manifest_path = repo / "release" / "evidence-manifest.json"
    if not manifest_path.is_file():
        return None
    if not isinstance(head, str) or not _HEX_SHA_RE.fullmatch(head):
        return AuditCheck(
            "EVIDENCE_HEAD_INVALID",
            "failed",
            "release/evidence-manifest.json",
            remediation="publish evidence only from a repository with a canonical lowercase 40-hex HEAD SHA",
        )
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return AuditCheck("EVIDENCE_MANIFEST_INVALID", "failed", "release/evidence-manifest.json", remediation="regenerate release evidence from canonical data")
    if isinstance(value, Mapping) and value.get("status") == "awaiting_public_subject":
        expected_keys = {
            "ci_runs",
            "evidence_commit_sha",
            "evidence_type",
            "generated_at",
            "index_sha256",
            "package_sha256",
            "public_tree_audit_sha256",
            "publication_policy_sha256",
            "receipt_index",
            "sbom_sha256",
            "states",
            "status",
            "subject_commit_sha",
            "workflow_sha256",
        }
        empty_evidence = all(
            value.get(key) is None
            for key in (
                "evidence_commit_sha",
                "package_sha256",
                "public_tree_audit_sha256",
                "sbom_sha256",
                "subject_commit_sha",
                "workflow_sha256",
            )
        )
        strict_waiting = (
            set(value) == expected_keys
            and value.get("evidence_type") == "public_release_evidence"
            and value.get("ci_runs") == {}
            and value.get("receipt_index") == []
            and empty_evidence
            and isinstance(value.get("generated_at"), str)
            and value["generated_at"].endswith("Z")
            and isinstance(value.get("index_sha256"), str)
            and _SHA256_RE.fullmatch(value["index_sha256"])
            and isinstance(value.get("publication_policy_sha256"), str)
            and _SHA256_RE.fullmatch(value["publication_policy_sha256"])
            and value.get("states")
            == {
                "effect_validated": "awaiting_sample",
                "production_enabled": False,
                "software_complete": False,
            }
        )
        if strict_waiting:
            return AuditCheck(
                "EVIDENCE_AWAITING_PUBLIC_SUBJECT",
                "passed",
                "release/evidence-manifest.json",
                remediation="generate subject-bound evidence only after the sanitized public root exists",
            )
        return AuditCheck(
            "EVIDENCE_MANIFEST_INVALID",
            "failed",
            "release/evidence-manifest.json",
            remediation="keep every subject-bound field empty and every upper release state false while awaiting the public subject",
        )
    subject = value.get("subject_commit_sha") if isinstance(value, Mapping) else None
    if not isinstance(subject, str) or not _HEX_SHA_RE.fullmatch(subject):
        return AuditCheck(
            "EVIDENCE_SHA_INVALID",
            "failed",
            "release/evidence-manifest.json",
            remediation="record the canonical lowercase 40-hex HEAD SHA as subject_commit_sha",
        )
    if subject != head:
        return AuditCheck("EVIDENCE_SHA_STALE", "failed", "release/evidence-manifest.json", evidence_commit=subject, remediation="regenerate evidence for the exact public subject SHA")
    return AuditCheck("EVIDENCE_SHA_CURRENT", "passed", "release/evidence-manifest.json", evidence_commit=head)


def _scanner_checks(repo: Path, *, required: bool) -> list[AuditCheck]:
    if not required:
        return []
    root = repo / "release" / "scanner-receipts"
    candidates = {
        "SCANNER_DETECT_SECRETS_MISSING": root / "detect-secrets.json",
        "SCANNER_PIP_AUDIT_MISSING": root / "pip-audit.json",
    }
    checks: list[AuditCheck] = []
    for check_id, path in candidates.items():
        checks.append(AuditCheck(check_id.replace("_MISSING", "_PRESENT" if path.is_file() else "_MISSING"), "passed" if path.is_file() else "failed", _relative(str(path.relative_to(repo))) if path.is_file() else None, remediation="attach a sanitized maintained scanner receipt"))
    gitleaks = root / "gitleaks.json"
    if not gitleaks.is_file():
        checks.append(AuditCheck("SCANNER_GITLEAKS_OR_EQUIVALENT_MISSING", "failed", remediation="attach a Gitleaks or equivalent secret scanner receipt"))
    else:
        checks.append(AuditCheck("SCANNER_GITLEAKS_OR_EQUIVALENT_PRESENT", "passed", "release/scanner-receipts/gitleaks.json"))
    return checks


def audit_repository(
    repo_root: Path | str,
    policy: Mapping[str, Any],
    *,
    working_tree: bool = True,
    reachable_history: bool = False,
    require_scanner_receipts: bool = False,
) -> PublicationAuditResult:
    repo = Path(repo_root).expanduser().resolve()
    normalized_policy = validate_publication_policy(policy)
    checks: list[AuditCheck] = []
    scanned_files = 0
    scanned_commits = 0

    if working_tree:
        files = _working_tree_files(repo)
        scanned_files = len(files)
        relative_paths = [relative for relative, _ in files]
        checks.append(_license_check(repo, relative_paths))
        for relative, path in files:
            if _is_reparse(path):
                checks.append(AuditCheck("TREE_REPARSE_POINT", "failed", relative, remediation="remove symlink/junction/reparse entries from public source"))
                continue
            try:
                size = path.stat().st_size
            except OSError:
                checks.append(AuditCheck("TREE_FILE_UNREADABLE", "failed", relative, remediation="make the public file readable"))
                continue
            if size > 1024 * 1024:
                checks.append(AuditCheck("TREE_FILE_TOO_LARGE", "failed", relative, remediation="remove or split files larger than 1 MiB"))
            if Path(relative).suffix.casefold() not in _TEXT_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                checks.append(AuditCheck("TREE_TEXT_READ_FAILED", "failed", relative, remediation="use valid UTF-8 for public text files"))
                continue
            _append_content_checks(checks, relative, text)
            if relative.startswith(".github/workflows/"):
                checks.extend(_workflow_checks(relative, text))
            if Path(relative).name.casefold() in {"transcript.jsonl", "raw_prompt.jsonl", "raw_response.jsonl", "raw_tool_output.jsonl"} or any(part.casefold() in _PRIVATE_DATA_PARTS for part in Path(relative).parts):
                checks.append(AuditCheck("TREE_RAW_PRIVATE_DATA", "failed", relative, remediation="exclude raw transcript and private runtime data from public source"))
        for relative in relative_paths:
            if Path(relative).suffix.casefold() in {".sqlite", ".sqlite3", ".db"}:
                checks.append(AuditCheck("TREE_SQLITE_PRESENT", "failed", relative, remediation="exclude SQLite runtime data from public source"))

    head_raw = _git(repo, "rev-parse", "HEAD")
    head = head_raw.decode("ascii", "ignore").strip() if head_raw else None
    evidence = _evidence_check(repo, head)
    if evidence:
        checks.append(evidence)
    checks.extend(_scanner_checks(repo, required=require_scanner_receipts))

    if reachable_history:
        commits = _history_commits(repo)
        scanned_commits = len(commits)
        checks.extend(_identity_checks(repo, normalized_policy))
        history_entries: list[tuple[str, str, str, str, str]] = []
        for commit in commits:
            for mode, object_type, object_id, relative_path in _history_files(repo, commit):
                history_entries.append((commit, mode, object_type, object_id, _relative(relative_path)))
        blob_contents = _history_blob_contents(
            repo,
            (
                object_id
                for _, mode, object_type, object_id, _ in history_entries
                if mode not in {"120000", "160000"} and object_type == "blob"
            ),
        )
        for commit, mode, object_type, object_id, relative in history_entries:
            if mode == "160000" or object_type == "commit":
                checks.append(AuditCheck("HISTORY_SUBMODULE_PRESENT", "failed", relative, evidence_commit=commit, remediation="remove submodules from public history"))
                continue
            if mode == "120000":
                checks.append(AuditCheck("HISTORY_SYMLINK_PRESENT", "failed", relative, evidence_commit=commit, remediation="remove symlink entries from public history"))
                continue
            content = blob_contents.get(object_id)
            if content is None:
                continue
            if len(content) > 1024 * 1024:
                checks.append(AuditCheck("HISTORY_FILE_TOO_LARGE", "failed", relative, evidence_commit=commit, remediation="remove oversized files from public history"))
            if Path(relative).suffix.casefold() in _TEXT_EXTENSIONS:
                _append_content_checks(checks, relative, content.decode("utf-8", "replace"), commit)

    deduplicated: dict[tuple[str, str | None, str | None], AuditCheck] = {}
    for check in checks:
        key = (check.check_id, check.evidence_path, check.evidence_commit)
        deduplicated[key] = check
    return PublicationAuditResult(tuple(sorted(deduplicated.values(), key=lambda item: (item.check_id, item.evidence_path or "", item.evidence_commit or ""))), scanned_files, scanned_commits)
