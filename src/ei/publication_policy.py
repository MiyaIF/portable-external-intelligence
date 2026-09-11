from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from .ids import canonical_json


PUBLIC_OWNER_DECISION_REQUIRED = "PUBLIC_OWNER_DECISION_REQUIRED"
POLICY_SCHEMA_VERSION = 1

_TOP_LEVEL_FIELDS = {
    "schema_version",
    "license_spdx",
    "copyright_holder",
    "public_author",
    "github",
    "security_reporting",
    "contribution_policy",
    "initial_version",
}
_AUTHOR_FIELDS = {"name", "email"}
_GITHUB_FIELDS = {"owner", "repository", "default_branch"}
_SECURITY_FIELDS = {"type", "url", "acknowledgement_days", "triage_days"}
_CONTRIBUTION_FIELDS = {
    "issues",
    "pull_requests",
    "dco_required",
    "cla_required",
    "response_sla_days",
    "merge_guarantee",
    "bug_bounty",
}
_SPDX_IDS = frozenset(
    {
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "GPL-2.0-only",
        "GPL-3.0-only",
        "ISC",
        "LGPL-2.1-only",
        "MIT",
        "MPL-2.0",
        "Unlicense",
    }
)
_GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_PUBLIC_EMAIL_RE = re.compile(r"^[0-9]+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_LICENSE_EXPRESSION_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?: (?:AND|OR|WITH) [A-Za-z0-9][A-Za-z0-9.+-]*)*$"
)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:sk|rk|xox[baprs])-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class PublicationPolicyError(ValueError):
    """Raised when publication authority is absent or unsafe."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}:{detail}" if detail else code)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationPolicyError("PUBLIC_POLICY_DUPLICATE_FIELD")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PublicationPolicyError("PUBLIC_POLICY_INVALID_JSON")


def _require_mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicationPolicyError(code)
    return value


def _require_fields(value: Mapping[str, Any], allowed: set[str], required: set[str], code: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise PublicationPolicyError("PUBLIC_POLICY_UNKNOWN_FIELD", sorted(unknown)[0])
    missing = required - set(value)
    if missing:
        raise PublicationPolicyError(code, sorted(missing)[0])


def _require_text(value: Any, code: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or _CONTROL_RE.search(value):
        raise PublicationPolicyError(code)
    return value


def _walk_for_secret_like(value: Any) -> None:
    if isinstance(value, Mapping):
        for nested in value.values():
            _walk_for_secret_like(nested)
    elif isinstance(value, list):
        for nested in value:
            _walk_for_secret_like(nested)
    elif isinstance(value, str) and any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise PublicationPolicyError("PUBLIC_POLICY_SECRET_LIKE_VALUE")


def _validate_license(value: Any) -> str:
    text = _require_text(value, "PUBLIC_POLICY_INVALID_LICENSE", maximum=200)
    if not _LICENSE_EXPRESSION_RE.fullmatch(text):
        raise PublicationPolicyError("PUBLIC_POLICY_INVALID_LICENSE")
    identifiers = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", text)
    if any(identifier not in _SPDX_IDS for identifier in identifiers):
        raise PublicationPolicyError("PUBLIC_POLICY_INVALID_LICENSE")
    return text


def _validate_author(value: Any) -> dict[str, str]:
    author = _require_mapping(value, "PUBLIC_OWNER_DECISION_REQUIRED")
    _require_fields(author, _AUTHOR_FIELDS, _AUTHOR_FIELDS, PUBLIC_OWNER_DECISION_REQUIRED)
    name = _require_text(author["name"], PUBLIC_OWNER_DECISION_REQUIRED, maximum=100)
    email = _require_text(author["email"], PUBLIC_OWNER_DECISION_REQUIRED, maximum=254)
    if not _PUBLIC_EMAIL_RE.fullmatch(email):
        raise PublicationPolicyError("PUBLIC_POLICY_AUTHOR_EMAIL_NOT_PUBLIC")
    return {"name": name, "email": email}


def _validate_github(value: Any) -> dict[str, str]:
    github = _require_mapping(value, PUBLIC_OWNER_DECISION_REQUIRED)
    _require_fields(github, _GITHUB_FIELDS, _GITHUB_FIELDS, PUBLIC_OWNER_DECISION_REQUIRED)
    owner = _require_text(github["owner"], "PUBLIC_POLICY_GITHUB_SLUG_INVALID", maximum=39)
    repository = _require_text(github["repository"], "PUBLIC_POLICY_GITHUB_SLUG_INVALID", maximum=100)
    branch = _require_text(github["default_branch"], "PUBLIC_POLICY_GITHUB_BRANCH_INVALID", maximum=100)
    if not _GITHUB_OWNER_RE.fullmatch(owner) or not _GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise PublicationPolicyError("PUBLIC_POLICY_GITHUB_SLUG_INVALID")
    if repository.endswith(".git") or not _BRANCH_RE.fullmatch(branch):
        raise PublicationPolicyError("PUBLIC_POLICY_GITHUB_BRANCH_INVALID")
    return {"owner": owner, "repository": repository, "default_branch": branch}


def _validate_security(value: Any, github: Mapping[str, str]) -> dict[str, Any]:
    security = _require_mapping(value, "PUBLIC_POLICY_SECURITY_ROUTE_REQUIRED")
    _require_fields(security, _SECURITY_FIELDS, _SECURITY_FIELDS, "PUBLIC_POLICY_SECURITY_ROUTE_REQUIRED")
    if security["type"] != "github_private_vulnerability_reporting":
        raise PublicationPolicyError("PUBLIC_POLICY_SECURITY_ROUTE_INVALID")
    url = _require_text(security["url"], "PUBLIC_POLICY_SECURITY_ROUTE_INVALID", maximum=500)
    expected = f"https://github.com/{github['owner']}/{github['repository']}/security/advisories/new"
    if url != expected:
        raise PublicationPolicyError("PUBLIC_POLICY_SECURITY_ROUTE_INVALID")
    for field in ("acknowledgement_days", "triage_days"):
        days = security[field]
        if type(days) is not int or not 1 <= days <= 30:
            raise PublicationPolicyError("PUBLIC_POLICY_SECURITY_ROUTE_INVALID", field)
    return {
        "type": security["type"],
        "url": url,
        "acknowledgement_days": security["acknowledgement_days"],
        "triage_days": security["triage_days"],
    }


def _validate_contribution(value: Any) -> dict[str, Any]:
    contribution = _require_mapping(value, "PUBLIC_OWNER_DECISION_REQUIRED")
    _require_fields(contribution, _CONTRIBUTION_FIELDS, _CONTRIBUTION_FIELDS, PUBLIC_OWNER_DECISION_REQUIRED)
    for field in ("issues", "pull_requests", "dco_required", "cla_required", "merge_guarantee", "bug_bounty"):
        if type(contribution[field]) is not bool:
            raise PublicationPolicyError("PUBLIC_POLICY_CONTRIBUTION_INVALID", field)
    response_sla = contribution["response_sla_days"]
    if response_sla is not None and (type(response_sla) is not int or not 0 <= response_sla <= 365):
        raise PublicationPolicyError("PUBLIC_POLICY_CONTRIBUTION_INVALID", "response_sla_days")
    return {field: contribution[field] for field in sorted(_CONTRIBUTION_FIELDS)}


def validate_publication_policy(value: Any) -> dict[str, Any]:
    policy = _require_mapping(value, "PUBLIC_OWNER_DECISION_REQUIRED")
    unknown = set(policy) - _TOP_LEVEL_FIELDS
    if unknown:
        raise PublicationPolicyError("PUBLIC_POLICY_UNKNOWN_FIELD", sorted(unknown)[0])
    if "security_reporting" not in policy:
        raise PublicationPolicyError("PUBLIC_POLICY_SECURITY_ROUTE_REQUIRED")
    missing = _TOP_LEVEL_FIELDS - set(policy)
    if missing:
        raise PublicationPolicyError(PUBLIC_OWNER_DECISION_REQUIRED, sorted(missing)[0])
    _walk_for_secret_like(policy)
    if policy["schema_version"] != POLICY_SCHEMA_VERSION or type(policy["schema_version"]) is not int:
        raise PublicationPolicyError("PUBLIC_POLICY_SCHEMA_VERSION_INVALID")
    github = _validate_github(policy["github"])
    result: dict[str, Any] = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "license_spdx": _validate_license(policy["license_spdx"]),
        "copyright_holder": _require_text(policy["copyright_holder"], PUBLIC_OWNER_DECISION_REQUIRED, maximum=200),
        "public_author": _validate_author(policy["public_author"]),
        "github": github,
        "security_reporting": _validate_security(policy["security_reporting"], github),
        "contribution_policy": _validate_contribution(policy["contribution_policy"]),
        "initial_version": _require_text(policy["initial_version"], "PUBLIC_POLICY_VERSION_INVALID", maximum=64),
    }
    if not _SEMVER_RE.fullmatch(result["initial_version"]):
        raise PublicationPolicyError("PUBLIC_POLICY_VERSION_INVALID")
    return result


def load_publication_policy(path: Path | str) -> dict[str, Any]:
    policy_path = Path(path).expanduser()
    if not policy_path.is_file():
        raise PublicationPolicyError(PUBLIC_OWNER_DECISION_REQUIRED)
    try:
        raw = policy_path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
    except PublicationPolicyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationPolicyError("PUBLIC_POLICY_INVALID_JSON") from exc
    return validate_publication_policy(value)


def canonical_policy_bytes(policy: Mapping[str, Any]) -> bytes:
    return canonical_json(validate_publication_policy(policy))


def policy_digest(policy: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def verify_publication_policy(path: Path | str) -> dict[str, Any]:
    policy = load_publication_policy(path)
    return {
        "valid": True,
        "schema_version": policy["schema_version"],
        "policy_digest": policy_digest(policy),
        "license_spdx": policy["license_spdx"],
        "github": policy["github"],
        "security_reporting": {"type": policy["security_reporting"]["type"]},
    }
