from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .certification import (
    REQUIRED_HOST_IDS,
    REQUIRED_OS_PROFILES,
    RECEIPT_KEYS,
    _os_profile,
    validate_receipt_artifact,
)
from .hooks.registry import canonical_host_id

REQUIRED_WORKFLOW_NAMES = (
    "ci",
    "compatibility",
    "security",
    "package",
)
PUBLIC_EVIDENCE_STATUSES = frozenset(
    {"awaiting_public_subject", "awaiting_post_push_attestation", "verified"}
)
PUBLIC_RECEIPT_TYPES = frozenset(
    {"fixture", "hosted_contract", "real_host", "activation", "rollback", "ab"}
)
PUBLIC_REQUIRED_RELEASE_RECEIPTS = (
    "hosted_ci",
    "package",
    "sbom",
    "secret_scanner",
    "dependency_scanner",
    "workflow_security",
    "security_remediation",
    "clean_clone",
)
PUBLIC_RELEASE_RECEIPT_WORKFLOWS = {
    "hosted_ci": "ci",
    "package": "package",
    "sbom": "package",
    "secret_scanner": "security",  # pragma: allowlist secret
    "dependency_scanner": "security",
    "workflow_security": "security",
    "security_remediation": "security",
    "clean_clone": "compatibility",
}
PRODUCTION_LIFECYCLE_STEPS = (
    "setup",
    "hook_skill_activation",
    "recall",
    "closeout",
    "maintenance",
    "scheduler",
    "private_sync",
    "doctor",
    "migration",
    "restore",
    "rollback",
)
PUBLIC_COMPATIBILITY_PAIRS = tuple(
    (host_id, os_profile)
    for host_id in REQUIRED_HOST_IDS
    for os_profile in REQUIRED_OS_PROFILES
)
PUBLIC_EVIDENCE_INDEX_KEYS = frozenset(
    {
        "evidence_type",
        "status",
        "subject_commit_sha",
        "evidence_commit_sha",
        "public_tree_audit_sha256",
        "workflow_sha256",
        "ci_runs",
        "package_sha256",
        "sbom_sha256",
        "publication_policy_sha256",
        "receipt_index",
        "states",
        "generated_at",
        "index_sha256",
    }
)
PUBLIC_ATTESTATION_KEYS = frozenset(
    {
        "evidence_type",
        "subject_commit_sha",
        "evidence_commit_sha",
        "manifest_sha256",
        "public_tree_audit_sha256",
        "workflow_sha256",
        "ci_runs",
        "package_sha256",
        "sbom_sha256",
        "publication_policy_sha256",
        "receipt_index",
        "attested_at",
        "attestation_sha256",
    }
)
SUBJECT_MANIFEST_KEYS = frozenset(
    {
        "evidence_type",
        "subject_commit_sha",
        "manifest_sha256",
        "workflow_sha256",
        "certification_sha256",
    }
)
ATTESTATION_KEYS = frozenset(
    {
        "evidence_type",
        "subject_commit_sha",
        "evidence_commit_sha",
        "manifest_sha256",
        "workflow_sha256",
        "certification_sha256",
        "attested_at",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
PRIVATE_CERTIFICATION_IMPORT_KEYS = frozenset(
    {
        "receipt_type",
        "public_subject_commit_sha",
        "host_id",
        "os_profile",
        "mode",
        "status",
        "artifact_sha256",
        "event_sha256",
        "source_receipt_sha256",
        "certified_at",
        "import_sha256",
    }
)
PUBLIC_RELEASE_RECEIPT_KEYS = frozenset(
    {
        "receipt_type",
        "schema_version",
        "receipt_sha256",
        "subject_commit_sha",
        "status",
        "producer_workflow",
        "producer_run_id",
        "artifact_sha256",
    }
)
SECURITY_REMEDIATION_KEYS = frozenset(
    {
        "receipt_type",
        "schema_version",
        "scan_id",
        "subject_commit_sha",
        "status",
        "scanner_receipt_sha256",
        "scanner_snapshot_sha256",
        "reportable_finding_count",
        "finding_set_sha256",
        "findings",
        "report_sha256",
    }
)
SECURITY_FINDING_KEYS = frozenset(
    {"finding_id", "severity", "status", "subject_commit_sha", "regression_evidence_sha256"}
)
PRODUCTION_EVIDENCE_KEYS = frozenset(
    {
        "receipt_type",
        "schema_version",
        "status",
        "subject_commit_sha",
        "lifecycle",
        "compatibility_matrix",
        "real_host_receipts",
        "private_ops_attestation_sha256",
        "evidence_sha256",
    }
)
PRODUCTION_LIFECYCLE_RECORD_KEYS = frozenset({"status", "subject_commit_sha", "receipt_sha256"})
PRODUCTION_MATRIX_ROW_KEYS = frozenset({"host_id", "os_profile", "supported", "subject_commit_sha", "receipt_sha256"})


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _commit(value: object, code: str = "RELEASE_COMMIT_SHA_INVALID") -> str:
    if not isinstance(value, str) or not _HEX40_RE.fullmatch(value):
        raise ValueError(code)
    return value


def _hash(value: object, code: str = "RELEASE_HASH_INVALID") -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(code)
    return value


def _private_import_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in sorted(PRIVATE_CERTIFICATION_IMPORT_KEYS - {"import_sha256"})
    }


def validate_private_certification_import(value: Mapping[str, Any]) -> bool:
    """Validate the path-free receipt exchanged from a private certification host."""
    if not isinstance(value, Mapping) or set(value) != PRIVATE_CERTIFICATION_IMPORT_KEYS:
        raise ValueError("PRIVATE_CERTIFICATION_IMPORT_SCHEMA_INVALID")
    if value.get("receipt_type") != "private_certification_import":
        raise ValueError("PRIVATE_CERTIFICATION_IMPORT_TYPE_INVALID")
    subject = _commit(value.get("public_subject_commit_sha"), "PRIVATE_CERTIFICATION_SUBJECT_INVALID")
    if subject != subject.lower():
        raise ValueError("PRIVATE_CERTIFICATION_SUBJECT_NOT_CANONICAL")
    try:
        host = canonical_host_id(str(value.get("host_id")))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("PRIVATE_CERTIFICATION_HOST_INVALID") from exc
    if host not in REQUIRED_HOST_IDS or value.get("host_id") != host:
        raise ValueError("PRIVATE_CERTIFICATION_HOST_INVALID")
    if value.get("os_profile") not in REQUIRED_OS_PROFILES:
        raise ValueError("PRIVATE_CERTIFICATION_OS_PROFILE_INVALID")
    if value.get("mode") != "real" or value.get("status") != "PASSED":
        raise ValueError("PRIVATE_CERTIFICATION_REAL_PASS_REQUIRED")
    for key in ("artifact_sha256", "event_sha256", "source_receipt_sha256", "import_sha256"):
        _hash(value.get(key), "PRIVATE_CERTIFICATION_HASH_INVALID")
    _time(value.get("certified_at"))
    if value.get("import_sha256") != _digest(_private_import_basis(value)):
        raise ValueError("PRIVATE_CERTIFICATION_IMPORT_HASH_MISMATCH")
    return True


def build_private_certification_import(
    certification_result: Mapping[str, Any],
    public_subject_commit_sha: str,
) -> dict[str, Any]:
    """Convert a private host result into a minimal public-safe receipt."""
    if not isinstance(certification_result, Mapping):
        raise ValueError("PRIVATE_CERTIFICATION_RESULT_OBJECT_REQUIRED")
    receipt_value = certification_result.get("receipt", certification_result)
    if not isinstance(receipt_value, Mapping):
        raise ValueError("PRIVATE_CERTIFICATION_RECEIPT_REQUIRED")
    validate_receipt_artifact(receipt_value)
    if receipt_value.get("mode") != "real":
        raise ValueError("PRIVATE_CERTIFICATION_REAL_REQUIRED")
    if certification_result.get("status", "PASSED") != "PASSED":
        raise ValueError("PRIVATE_CERTIFICATION_PASS_REQUIRED")
    if "real_evidence" in certification_result and certification_result.get("real_evidence") is not True:
        raise ValueError("PRIVATE_CERTIFICATION_REAL_EVIDENCE_REQUIRED")
    try:
        host = canonical_host_id(str(receipt_value["host_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("PRIVATE_CERTIFICATION_HOST_INVALID") from exc
    profile = _os_profile(str(receipt_value["os_family"]), str(receipt_value["os_version"]))
    if host not in REQUIRED_HOST_IDS or not profile:
        raise ValueError("PRIVATE_CERTIFICATION_OS_PROFILE_INVALID")
    subject = _commit(public_subject_commit_sha, "PRIVATE_CERTIFICATION_SUBJECT_INVALID").lower()
    value: dict[str, Any] = {
        "receipt_type": "private_certification_import",
        "public_subject_commit_sha": subject,
        "host_id": host,
        "os_profile": profile,
        "mode": "real",
        "status": "PASSED",
        "artifact_sha256": str(receipt_value["artifact_sha256"]),
        "event_sha256": str(receipt_value["event_sha256"]),
        "source_receipt_sha256": _digest(dict(receipt_value)),
        "certified_at": str(receipt_value["certified_at"]),
    }
    value["import_sha256"] = _digest(_private_import_basis(value))
    validate_private_certification_import(value)
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("RELEASE_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("RELEASE_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("RELEASE_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime | str | None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = _time(value)
    else:
        raise ValueError("PUBLIC_EVIDENCE_TIME_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("PUBLIC_EVIDENCE_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_index_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in sorted(PUBLIC_EVIDENCE_INDEX_KEYS - {"index_sha256"})
    }


def _public_attestation_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in sorted(PUBLIC_ATTESTATION_KEYS - {"attestation_sha256"})
    }


def _validate_public_ci_runs(
    value: Any,
    *,
    require_all: bool = False,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise ValueError("PUBLIC_CI_RUNS_INVALID")
    result: dict[str, dict[str, Any]] = {}
    for name, row in value.items():
        workflow = str(name)
        if workflow not in REQUIRED_WORKFLOW_NAMES:
            raise ValueError("PUBLIC_CI_WORKFLOW_INVALID")
        if not isinstance(row, Mapping) or set(row) != {"run_id", "conclusion", "head_sha"}:
            raise ValueError("PUBLIC_CI_RUN_INVALID")
        run_id = row.get("run_id")
        if not (
            (type(run_id) is int and run_id > 0)
            or (isinstance(run_id, str) and run_id.isdigit() and int(run_id) > 0)
        ):
            raise ValueError("PUBLIC_CI_RUN_ID_INVALID")
        conclusion = row.get("conclusion")
        if not isinstance(conclusion, str) or conclusion not in {
            "success",
            "failure",
            "cancelled",
            "skipped",
            "neutral",
            "action_required",
        }:
            raise ValueError("PUBLIC_CI_CONCLUSION_INVALID")
        head_sha = _commit(row.get("head_sha"), "PUBLIC_CI_HEAD_SHA_INVALID")
        result[workflow] = {
            "run_id": int(run_id),
            "conclusion": conclusion,
            "head_sha": head_sha,
        }
    if require_all and set(result) != set(REQUIRED_WORKFLOW_NAMES):
        raise ValueError("PUBLIC_CI_RUNS_INCOMPLETE")
    return result


def _validate_public_receipt_index(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError("PUBLIC_RECEIPT_INDEX_INVALID")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"receipt_type", "receipt_sha256"}:
            raise ValueError("PUBLIC_RECEIPT_INDEX_INVALID")
        receipt_type = row.get("receipt_type")
        if receipt_type not in PUBLIC_RECEIPT_TYPES:
            raise ValueError("PUBLIC_RECEIPT_TYPE_INVALID")
        receipt_hash = _hash(row.get("receipt_sha256"), "PUBLIC_RECEIPT_HASH_INVALID")
        identity = (str(receipt_type), receipt_hash)
        if identity in seen:
            raise ValueError("PUBLIC_RECEIPT_DUPLICATE")
        seen.add(identity)
        result.append({"receipt_type": str(receipt_type), "receipt_sha256": receipt_hash})
    return result


def _validate_public_states(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "software_complete",
        "production_enabled",
        "effect_validated",
    }:
        raise ValueError("PUBLIC_EVIDENCE_STATES_INVALID")
    if type(value.get("software_complete")) is not bool or type(value.get("production_enabled")) is not bool:
        raise ValueError("PUBLIC_EVIDENCE_STATES_INVALID")
    effect = value.get("effect_validated")
    if type(effect) is not bool and effect != "awaiting_sample":
        raise ValueError("PUBLIC_EVIDENCE_EFFECT_STATE_INVALID")
    return {
        "software_complete": value["software_complete"],
        "production_enabled": value["production_enabled"],
        "effect_validated": effect,
    }


def validate_public_evidence_index(value: Mapping[str, Any]) -> bool:
    """Validate the canonical public-release evidence index and its digest."""
    if not isinstance(value, Mapping) or set(value) != PUBLIC_EVIDENCE_INDEX_KEYS:
        raise ValueError("PUBLIC_EVIDENCE_INDEX_SCHEMA_INVALID")
    if value.get("evidence_type") != "public_release_evidence":
        raise ValueError("PUBLIC_EVIDENCE_INDEX_TYPE_INVALID")
    status = value.get("status")
    if status not in PUBLIC_EVIDENCE_STATUSES:
        raise ValueError("PUBLIC_EVIDENCE_STATUS_INVALID")
    policy_hash = _hash(value.get("publication_policy_sha256"), "PUBLIC_POLICY_HASH_INVALID")
    _validate_public_receipt_index(value.get("receipt_index"))
    states = _validate_public_states(value.get("states"))
    if states["effect_validated"] != "awaiting_sample":
        raise ValueError("PUBLIC_EFFECT_STATE_EXTERNAL_REQUIRED")
    _time(value.get("generated_at"))
    subject = value.get("subject_commit_sha")
    evidence = value.get("evidence_commit_sha")
    hash_fields = (
        "public_tree_audit_sha256",
        "workflow_sha256",
        "package_sha256",
        "sbom_sha256",
    )
    if status == "awaiting_public_subject":
        if subject is not None or evidence is not None:
            raise ValueError("PUBLIC_SUBJECT_PENDING_FIELDS_INVALID")
        if any(value.get(key) is not None for key in hash_fields):
            raise ValueError("PUBLIC_SUBJECT_PENDING_FIELDS_INVALID")
        if value.get("ci_runs") != {} or value.get("receipt_index") != []:
            raise ValueError("PUBLIC_SUBJECT_PENDING_FIELDS_INVALID")
        if states != {
            "software_complete": False,
            "production_enabled": False,
            "effect_validated": "awaiting_sample",
        }:
            raise ValueError("PUBLIC_SUBJECT_PENDING_STATE_INVALID")
    else:
        subject_text = _commit(subject, "PUBLIC_SUBJECT_SHA_INVALID")
        if subject_text != subject_text.lower():
            raise ValueError("PUBLIC_SUBJECT_SHA_NOT_CANONICAL")
        for key in hash_fields:
            _hash(value.get(key), "PUBLIC_EVIDENCE_HASH_INVALID")
        runs = _validate_public_ci_runs(value.get("ci_runs"), require_all=status == "verified")
        if status == "awaiting_post_push_attestation":
            if evidence is not None:
                raise ValueError("PUBLIC_EVIDENCE_COMMIT_PENDING")
            if any(row["head_sha"] != subject_text for row in runs.values()):
                raise ValueError("PUBLIC_CI_SUBJECT_SHA_MISMATCH")
        else:
            evidence_text = _commit(evidence, "PUBLIC_EVIDENCE_SHA_INVALID")
            if evidence_text != evidence_text.lower():
                raise ValueError("PUBLIC_EVIDENCE_SHA_NOT_CANONICAL")
            if any(row["conclusion"] != "success" or row["head_sha"] != evidence_text for row in runs.values()):
                raise ValueError("PUBLIC_CI_EVIDENCE_INVALID")
    _hash(value.get("index_sha256"), "PUBLIC_EVIDENCE_INDEX_HASH_INVALID")
    if value.get("index_sha256") != _digest(_public_index_basis(value)):
        raise ValueError("PUBLIC_EVIDENCE_INDEX_HASH_MISMATCH")
    return True


def _normalise_ci_runs(value: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        rows = [{"workflow": str(key), **dict(row)} for key, row in value.items() if isinstance(row, Mapping)]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        rows = [dict(row) for row in value if isinstance(row, Mapping)]
    else:
        raise ValueError("PUBLIC_CI_RUNS_INVALID")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        workflow = str(row.get("workflow", row.get("name", "")))
        if not workflow or workflow in result:
            raise ValueError("PUBLIC_CI_WORKFLOW_INVALID")
        result[workflow] = {
            "run_id": row.get("run_id", row.get("databaseId")),
            "conclusion": row.get("conclusion"),
            "head_sha": row.get("head_sha", row.get("headSha")),
        }
    return _validate_public_ci_runs(result)


def _normalise_public_receipts(value: Sequence[Mapping[str, Any]] | None) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("PUBLIC_RECEIPT_INDEX_INVALID")
    rows = _validate_public_receipt_index([dict(row) for row in value if isinstance(row, Mapping)])
    return sorted(rows, key=lambda row: (row["receipt_type"], row["receipt_sha256"]))


def build_public_evidence_index(
    *,
    publication_policy_sha256: str,
    subject_commit_sha: str | None = None,
    evidence_commit_sha: str | None = None,
    public_tree_audit_sha256: str | None = None,
    workflow_sha256: str | None = None,
    ci_runs: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    package_sha256: str | None = None,
    sbom_sha256: str | None = None,
    receipt_index: Sequence[Mapping[str, Any]] | None = None,
    production_evidence: Mapping[str, Any] | None = None,
    effect_evidence: Mapping[str, Any] | None = None,
    generated_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build an immutable public evidence index; effect proof remains a bound sidecar."""
    if effect_evidence is not None:
        # Effect evidence includes this index digest.  Embedding it while the
        # digest is being constructed would create an unverifiable cycle.
        raise ValueError("PUBLIC_EFFECT_EVIDENCE_SEPARATE_REQUIRED")
    policy_hash = _hash(publication_policy_sha256, "PUBLIC_POLICY_HASH_INVALID")
    stamp = _timestamp(generated_at)
    if subject_commit_sha is None:
        if any(
            item is not None
            for item in (
                evidence_commit_sha,
                public_tree_audit_sha256,
                workflow_sha256,
                package_sha256,
                sbom_sha256,
            )
        ) or ci_runs or receipt_index:
            raise ValueError("PUBLIC_SUBJECT_REQUIRED")
        value: dict[str, Any] = {
            "evidence_type": "public_release_evidence",
            "status": "awaiting_public_subject",
            "subject_commit_sha": None,
            "evidence_commit_sha": None,
            "public_tree_audit_sha256": None,
            "workflow_sha256": None,
            "ci_runs": {},
            "package_sha256": None,
            "sbom_sha256": None,
            "publication_policy_sha256": policy_hash,
            "receipt_index": [],
            "states": {
                "software_complete": False,
                "production_enabled": False,
                "effect_validated": "awaiting_sample",
            },
            "generated_at": stamp,
        }
        value["index_sha256"] = _digest(_public_index_basis(value))
        validate_public_evidence_index(value)
        return value
    subject = _commit(subject_commit_sha, "PUBLIC_SUBJECT_SHA_INVALID").lower()
    required_hashes = {
        "public_tree_audit_sha256": public_tree_audit_sha256,
        "workflow_sha256": workflow_sha256,
        "package_sha256": package_sha256,
        "sbom_sha256": sbom_sha256,
    }
    if any(value is None for value in required_hashes.values()):
        raise ValueError("PUBLIC_EVIDENCE_FIELDS_REQUIRED")
    for key, value in required_hashes.items():
        required_hashes[key] = _hash(value, "PUBLIC_EVIDENCE_HASH_INVALID")
    runs = _normalise_ci_runs(ci_runs)
    receipts = _normalise_public_receipts(receipt_index)
    evidence = None
    status = "awaiting_post_push_attestation"
    if evidence_commit_sha is not None:
        evidence = _commit(evidence_commit_sha, "PUBLIC_EVIDENCE_SHA_INVALID").lower()
        valid, reasons = validate_prerequisite_runs(runs, evidence)
        if not valid:
            raise ValueError(reasons[0] if reasons else "PUBLIC_CI_RUNS_INCOMPLETE")
        status = "verified"
    elif any(row["head_sha"] != subject for row in runs.values()):
        raise ValueError("PUBLIC_CI_SUBJECT_SHA_MISMATCH")
    production = _production_evidence_valid(production_evidence, subject)[0]
    value = {
        "evidence_type": "public_release_evidence",
        "status": status,
        "subject_commit_sha": subject,
        "evidence_commit_sha": evidence,
        **required_hashes,
        "ci_runs": runs,
        "publication_policy_sha256": policy_hash,
        "receipt_index": receipts,
        "states": {
            "software_complete": status == "verified",
            "production_enabled": production,
            "effect_validated": "awaiting_sample",
        },
        "generated_at": stamp,
    }
    value["index_sha256"] = _digest(_public_index_basis(value))
    validate_public_evidence_index(value)
    return value


def validate_public_release_attestation(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping) or set(value) != PUBLIC_ATTESTATION_KEYS:
        raise ValueError("PUBLIC_ATTESTATION_SCHEMA_INVALID")
    if value.get("evidence_type") != "post_push_public_attestation":
        raise ValueError("PUBLIC_ATTESTATION_TYPE_INVALID")
    for key in ("subject_commit_sha", "evidence_commit_sha"):
        _commit(value.get(key), "PUBLIC_ATTESTATION_COMMIT_INVALID")
    for key in (
        "manifest_sha256",
        "public_tree_audit_sha256",
        "workflow_sha256",
        "package_sha256",
        "sbom_sha256",
        "publication_policy_sha256",
    ):
        _hash(value.get(key), "PUBLIC_ATTESTATION_HASH_INVALID")
    _validate_public_ci_runs(value.get("ci_runs"), require_all=True)
    _validate_public_receipt_index(value.get("receipt_index"))
    _time(value.get("attested_at"))
    _hash(value.get("attestation_sha256"), "PUBLIC_ATTESTATION_HASH_INVALID")
    if value.get("attestation_sha256") != _digest(_public_attestation_basis(value)):
        raise ValueError("PUBLIC_ATTESTATION_HASH_MISMATCH")
    return True


def build_public_release_attestation(
    index: Mapping[str, Any],
    evidence_commit_sha: str,
    prerequisite_runs: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    attested_at: datetime | None = None,
) -> dict[str, Any]:
    validate_public_evidence_index(index)
    if index.get("status") == "awaiting_public_subject":
        raise ValueError("PUBLIC_SUBJECT_PENDING")
    subject = _commit(index.get("subject_commit_sha"), "PUBLIC_SUBJECT_SHA_INVALID")
    evidence = _commit(evidence_commit_sha, "PUBLIC_EVIDENCE_SHA_INVALID")
    valid, reasons = validate_prerequisite_runs(prerequisite_runs, evidence)
    if not valid:
        raise ValueError(reasons[0] if reasons else "PUBLIC_CI_RUNS_INCOMPLETE")
    runs = _normalise_ci_runs(prerequisite_runs)
    value = {
        "evidence_type": "post_push_public_attestation",
        "subject_commit_sha": subject,
        "evidence_commit_sha": evidence,
        "manifest_sha256": index["index_sha256"],
        "public_tree_audit_sha256": index["public_tree_audit_sha256"],
        "workflow_sha256": index["workflow_sha256"],
        "ci_runs": runs,
        "package_sha256": index["package_sha256"],
        "sbom_sha256": index["sbom_sha256"],
        "publication_policy_sha256": index["publication_policy_sha256"],
        "receipt_index": list(index["receipt_index"]),
        "attested_at": _timestamp(attested_at),
    }
    value["attestation_sha256"] = _digest(_public_attestation_basis(value))
    validate_public_release_attestation(value)
    return value


def verify_public_release_attestation(
    index: Mapping[str, Any],
    attestation: Mapping[str, Any],
    expected_evidence_commit_sha: str,
    *,
    production_evidence: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> CompletionStatus:
    reasons: list[str] = []
    try:
        validate_public_evidence_index(index)
    except ValueError as exc:
        reasons.append(str(exc))
    try:
        validate_public_release_attestation(attestation)
    except (TypeError, ValueError) as exc:
        reasons.append(str(exc))
    if reasons:
        return CompletionStatus(False, False, "awaiting_sample", tuple(dict.fromkeys(reasons)), {})
    expected = _commit(expected_evidence_commit_sha, "PUBLIC_EVIDENCE_SHA_INVALID")
    checks: dict[str, bool] = {}
    for key in (
        "subject_commit_sha",
        "manifest_sha256",
        "public_tree_audit_sha256",
        "workflow_sha256",
        "package_sha256",
        "sbom_sha256",
        "publication_policy_sha256",
    ):
        if attestation[key] != (index["index_sha256"] if key == "manifest_sha256" else index[key]):
            reasons.append("PUBLIC_EVIDENCE_FIELD_MISMATCH:" + key)
    if attestation["evidence_commit_sha"] != expected:
        reasons.append("EVIDENCE_COMMIT_SHA_MISMATCH")
    if attestation["receipt_index"] != index["receipt_index"]:
        reasons.append("PUBLIC_RECEIPT_INDEX_MISMATCH")
    prerequisite_ok, prerequisite_reasons = validate_prerequisite_runs(
        attestation["ci_runs"], expected
    )
    checks["prerequisite_runs"] = prerequisite_ok
    reasons.extend(prerequisite_reasons)
    software_reasons = tuple(dict.fromkeys(reasons))
    software_complete = not software_reasons
    production = _production_evidence_valid(production_evidence, index["subject_commit_sha"])[0]
    if not production:
        reasons.append("PRODUCTION_REAL_ACTIVATION_PENDING")
    state = index["states"]["effect_validated"]
    effect_validated: bool | str = True if state is True else "awaiting_sample"
    if effect_validated != True:
        reasons.append("EFFECT_AWAITING_SAMPLE")
    return CompletionStatus(
        software_complete=software_complete,
        production_enabled=production,
        effect_validated=effect_validated,
        reason_codes=tuple(dict.fromkeys(reasons)),
        checks=checks,
    )


def _effect_valid(
    value: object,
    *,
    subject_commit_sha: str | None = None,
    evidence_index_sha256: str | None = None,
) -> bool:
    try:
        from .experiment import validate_effect_evidence

        return validate_effect_evidence(
            value,
            expected_subject_commit_sha=subject_commit_sha,
            expected_evidence_index_sha256=evidence_index_sha256,
        )
    except (TypeError, ValueError, ImportError):
        return False


def _validate_release_receipts(
    value: Mapping[str, Any] | None,
    evidence_index: Mapping[str, Any],
) -> tuple[bool, tuple[str, ...], dict[str, bool]]:
    checks = {name: False for name in PUBLIC_REQUIRED_RELEASE_RECEIPTS}
    reasons: list[str] = []
    if value is None:
        return False, tuple("REQUIRED_RECEIPT_MISSING:" + name for name in PUBLIC_REQUIRED_RELEASE_RECEIPTS), checks
    if not isinstance(value, Mapping) or set(value) != set(PUBLIC_REQUIRED_RELEASE_RECEIPTS):
        reasons.append("REQUIRED_RECEIPT_SET_INVALID")
    subject_commit_sha = str(evidence_index.get("subject_commit_sha", ""))
    ci_runs = evidence_index.get("ci_runs")
    if not isinstance(ci_runs, Mapping):
        ci_runs = {}
    for name in PUBLIC_REQUIRED_RELEASE_RECEIPTS:
        row = value.get(name) if isinstance(value, Mapping) else None
        if not isinstance(row, Mapping) or set(row) != PUBLIC_RELEASE_RECEIPT_KEYS:
            reasons.append("REQUIRED_RECEIPT_INVALID:" + name)
            continue
        if row.get("receipt_type") != name or row.get("schema_version") != 1 or type(row.get("schema_version")) is not int:
            reasons.append("REQUIRED_RECEIPT_IDENTITY_INVALID:" + name)
            continue
        expected_workflow = PUBLIC_RELEASE_RECEIPT_WORKFLOWS[name]
        producer = ci_runs.get(expected_workflow)
        if row.get("producer_workflow") != expected_workflow:
            reasons.append("REQUIRED_RECEIPT_PRODUCER_INVALID:" + name)
            continue
        if (
            not isinstance(producer, Mapping)
            or type(row.get("producer_run_id")) is not int
            or row.get("producer_run_id") != producer.get("run_id")
            or producer.get("head_sha") != subject_commit_sha
            or producer.get("conclusion") != "success"
        ):
            reasons.append("REQUIRED_RECEIPT_PRODUCER_RUN_MISMATCH:" + name)
            continue
        try:
            _hash(row.get("receipt_sha256"), "REQUIRED_RECEIPT_HASH_INVALID")
            _hash(row.get("artifact_sha256"), "REQUIRED_RECEIPT_ARTIFACT_HASH_INVALID")
            _commit(row.get("subject_commit_sha"), "REQUIRED_RECEIPT_SUBJECT_INVALID")
        except ValueError as exc:
            reasons.append(str(exc) + ":" + name)
            continue
        if row.get("status") != "PASSED":
            reasons.append("REQUIRED_RECEIPT_NOT_PASSED:" + name)
            continue
        if row.get("subject_commit_sha") != subject_commit_sha:
            reasons.append("REQUIRED_RECEIPT_SUBJECT_MISMATCH:" + name)
            continue
        basis = {key: row[key] for key in sorted(PUBLIC_RELEASE_RECEIPT_KEYS - {"receipt_sha256"})}
        if row.get("receipt_sha256") != _digest(basis):
            reasons.append("REQUIRED_RECEIPT_DIGEST_MISMATCH:" + name)
            continue
        checks[name] = True
    return not reasons, tuple(dict.fromkeys(reasons)), checks


def _security_remediation_valid(
    value: Mapping[str, Any] | None,
    subject_commit_sha: str,
    expected_artifact_sha256: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    if value is None:
        return False, ("SECURITY_REMEDIATION_MISSING",)
    if not isinstance(value, Mapping):
        return False, ("SECURITY_REMEDIATION_SCHEMA_INVALID",)
    reasons: list[str] = []
    if set(value) != SECURITY_REMEDIATION_KEYS:
        reasons.append("SECURITY_REMEDIATION_SCHEMA_INVALID")
    if value.get("receipt_type") != "security_remediation":
        reasons.append("SECURITY_REMEDIATION_TYPE_INVALID")
    if value.get("schema_version") != 1 or type(value.get("schema_version")) is not int:
        reasons.append("SECURITY_REMEDIATION_VERSION_INVALID")
    if value.get("status") != "resolved":
        reasons.append("SECURITY_REMEDIATION_NOT_RESOLVED")
    scan_id = value.get("scan_id")
    if not isinstance(scan_id, str) or not scan_id or len(scan_id) > 160:
        reasons.append("SECURITY_SCAN_ID_INVALID")
    try:
        _commit(value.get("subject_commit_sha"), "SECURITY_REMEDIATION_SUBJECT_INVALID")
        _hash(value.get("scanner_receipt_sha256"), "SECURITY_REMEDIATION_SCANNER_HASH_INVALID")
        _hash(value.get("scanner_snapshot_sha256"), "SECURITY_REMEDIATION_SNAPSHOT_HASH_INVALID")
        _hash(value.get("finding_set_sha256"), "SECURITY_FINDING_SET_HASH_INVALID")
        _hash(value.get("report_sha256"), "SECURITY_REMEDIATION_REPORT_HASH_INVALID")
    except ValueError as exc:
        reasons.append(str(exc))
    if value.get("subject_commit_sha") != subject_commit_sha:
        reasons.append("SECURITY_REMEDIATION_SUBJECT_MISMATCH")
    findings = value.get("findings")
    finding_count = value.get("reportable_finding_count")
    if type(finding_count) is not int or finding_count < 0:
        reasons.append("SECURITY_FINDING_COUNT_INVALID")
        finding_count = -1
    if not isinstance(findings, list):
        reasons.append("SECURITY_FINDING_LIST_INVALID")
        findings = []
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping) or set(finding) != SECURITY_FINDING_KEYS:
            reasons.append("SECURITY_FINDING_SCHEMA_INVALID")
            continue
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in seen:
            reasons.append("SECURITY_FINDING_ID_INVALID")
        seen.add(str(finding_id))
        if finding.get("severity") not in {"low", "medium", "high", "critical"}:
            reasons.append("SECURITY_FINDING_SEVERITY_INVALID")
        if finding.get("status") != "fixed":
            reasons.append("SECURITY_FINDING_NOT_FIXED")
        if finding.get("subject_commit_sha") != subject_commit_sha:
            reasons.append("SECURITY_FINDING_SUBJECT_MISMATCH")
        try:
            _hash(finding.get("regression_evidence_sha256"), "SECURITY_FINDING_REGRESSION_HASH_INVALID")
        except ValueError as exc:
            reasons.append(str(exc))
    if finding_count != len(findings):
        reasons.append("SECURITY_FINDING_COUNT_INVALID")
    expected_finding_set = _digest({"finding_ids": sorted(seen)})
    if value.get("finding_set_sha256") != expected_finding_set:
        reasons.append("SECURITY_FINDING_SET_MISMATCH")
    basis = {key: value[key] for key in sorted(SECURITY_REMEDIATION_KEYS - {"report_sha256"}) if key in value}
    if isinstance(value.get("report_sha256"), str) and value.get("report_sha256") != _digest(basis):
        reasons.append("SECURITY_REMEDIATION_REPORT_HASH_MISMATCH")
    if expected_artifact_sha256 is None or value.get("report_sha256") != expected_artifact_sha256:
        reasons.append("SECURITY_REMEDIATION_ARTIFACT_MISMATCH")
    return not reasons, tuple(dict.fromkeys(reasons))


def _publication_receipt_valid(value: Mapping[str, Any] | None, subject_commit_sha: str) -> tuple[bool, tuple[str, ...]]:
    if value is None:
        return False, ("PUBLICATION_RECEIPT_MISSING",)
    try:
        from .github_publication import validate_publication_record

        validate_publication_record(value)
    except (ImportError, TypeError, ValueError) as exc:
        return False, ("PUBLICATION_RECEIPT_INVALID:" + str(exc),)
    post = value.get("post_public_clone")
    if value.get("status") != "verified":
        return False, ("PUBLICATION_RECEIPT_NOT_VERIFIED",)
    if value.get("source_commit_sha") != subject_commit_sha:
        return False, ("PUBLICATION_RECEIPT_SUBJECT_MISMATCH",)
    if not isinstance(post, Mapping) or post.get("root_commit_sha") != subject_commit_sha:
        return False, ("PUBLICATION_RECEIPT_CLONE_SUBJECT_MISMATCH",)
    return True, ()


def _production_evidence_valid(value: Mapping[str, Any] | None, subject_commit_sha: str) -> tuple[bool, tuple[str, ...]]:
    if value is None:
        return False, ("PRODUCTION_EVIDENCE_MISSING",)
    if not isinstance(value, Mapping):
        return False, ("PRODUCTION_EVIDENCE_SCHEMA_INVALID",)
    reasons: list[str] = []
    if set(value) != PRODUCTION_EVIDENCE_KEYS:
        reasons.append("PRODUCTION_EVIDENCE_SCHEMA_INVALID")
    if value.get("receipt_type") != "production_evidence":
        reasons.append("PRODUCTION_EVIDENCE_TYPE_INVALID")
    if value.get("schema_version") != 1 or type(value.get("schema_version")) is not int:
        reasons.append("PRODUCTION_EVIDENCE_VERSION_INVALID")
    if value.get("status") != "PASSED":
        reasons.append("PRODUCTION_EVIDENCE_NOT_PASSED")
    if value.get("subject_commit_sha") != subject_commit_sha:
        reasons.append("PRODUCTION_EVIDENCE_SUBJECT_MISMATCH")
    try:
        _commit(value.get("subject_commit_sha"), "PRODUCTION_EVIDENCE_SUBJECT_INVALID")
        _hash(value.get("private_ops_attestation_sha256"), "PRODUCTION_OPS_ATTESTATION_HASH_INVALID")
        _hash(value.get("evidence_sha256"), "PRODUCTION_EVIDENCE_HASH_INVALID")
    except ValueError as exc:
        reasons.append(str(exc))

    lifecycle = value.get("lifecycle")
    if not isinstance(lifecycle, Mapping) or set(lifecycle) != set(PRODUCTION_LIFECYCLE_STEPS):
        reasons.append("PRODUCTION_LIFECYCLE_SET_INVALID")
        lifecycle = {}
    for step in PRODUCTION_LIFECYCLE_STEPS:
        row = lifecycle.get(step)
        if not isinstance(row, Mapping) or set(row) != PRODUCTION_LIFECYCLE_RECORD_KEYS:
            reasons.append("PRODUCTION_LIFECYCLE_INVALID:" + step)
            continue
        if row.get("status") != "PASSED":
            reasons.append("PRODUCTION_LIFECYCLE_NOT_PASSED:" + step)
        if row.get("subject_commit_sha") != subject_commit_sha:
            reasons.append("PRODUCTION_LIFECYCLE_SUBJECT_MISMATCH:" + step)
        try:
            _hash(row.get("receipt_sha256"), "PRODUCTION_LIFECYCLE_HASH_INVALID")
        except ValueError as exc:
            reasons.append(str(exc) + ":" + step)

    receipt_pairs: set[tuple[str, str]] = set()
    host_receipts = value.get("real_host_receipts")
    if not isinstance(host_receipts, list) or len(host_receipts) != len(PUBLIC_COMPATIBILITY_PAIRS):
        reasons.append("REAL_HOST_RECEIPT_SET_INVALID")
        host_receipts = []
    for receipt in host_receipts:
        try:
            validate_private_certification_import(receipt)
        except (TypeError, ValueError) as exc:
            reasons.append("REAL_HOST_RECEIPT_INVALID:" + str(exc))
            continue
        if receipt.get("public_subject_commit_sha") != subject_commit_sha:
            reasons.append("REAL_HOST_RECEIPT_SUBJECT_MISMATCH")
        pair = (str(receipt.get("host_id")), str(receipt.get("os_profile")))
        receipt_pairs.add(pair)
    if receipt_pairs != set(PUBLIC_COMPATIBILITY_PAIRS):
        reasons.append("REAL_HOST_COMPATIBILITY_MATRIX_INCOMPLETE")

    matrix = value.get("compatibility_matrix")
    matrix_pairs: set[tuple[str, str]] = set()
    if not isinstance(matrix, list) or len(matrix) != len(PUBLIC_COMPATIBILITY_PAIRS):
        reasons.append("COMPATIBILITY_MATRIX_SET_INVALID")
        matrix = []
    receipt_hashes = {
        str(row.get("import_sha256"))
        for row in host_receipts
        if isinstance(row, Mapping) and isinstance(row.get("import_sha256"), str)
    }
    for row in matrix:
        if not isinstance(row, Mapping) or set(row) != PRODUCTION_MATRIX_ROW_KEYS:
            reasons.append("COMPATIBILITY_MATRIX_ROW_INVALID")
            continue
        pair = (str(row.get("host_id")), str(row.get("os_profile")))
        matrix_pairs.add(pair)
        if row.get("supported") is not True:
            reasons.append("COMPATIBILITY_MATRIX_PAIR_NOT_SUPPORTED:" + ":".join(pair))
        if row.get("subject_commit_sha") != subject_commit_sha:
            reasons.append("COMPATIBILITY_MATRIX_SUBJECT_MISMATCH:" + ":".join(pair))
        try:
            _hash(row.get("receipt_sha256"), "COMPATIBILITY_MATRIX_HASH_INVALID")
        except ValueError as exc:
            reasons.append(str(exc))
        if row.get("receipt_sha256") not in receipt_hashes:
            reasons.append("COMPATIBILITY_MATRIX_RECEIPT_MISMATCH:" + ":".join(pair))
    if matrix_pairs != set(PUBLIC_COMPATIBILITY_PAIRS):
        reasons.append("COMPATIBILITY_MATRIX_INCOMPLETE")

    basis = {key: value[key] for key in sorted(PRODUCTION_EVIDENCE_KEYS - {"evidence_sha256"}) if key in value}
    if isinstance(value.get("evidence_sha256"), str) and value.get("evidence_sha256") != _digest(basis):
        reasons.append("PRODUCTION_EVIDENCE_HASH_MISMATCH")
    return not reasons, tuple(dict.fromkeys(reasons))


def evaluate_public_completion(
    *,
    evidence_index: Mapping[str, Any],
    export_receipt: Mapping[str, Any] | None = None,
    publication_receipt: Mapping[str, Any] | None = None,
    release_receipts: Mapping[str, Any] | None = None,
    security_evidence: Mapping[str, Any] | None = None,
    production_evidence: Mapping[str, Any] | None = None,
    effect_evidence: Mapping[str, Any] | None = None,
) -> PublicCompletionStatus:
    """Evaluate independent release gates from hash-bound evidence only.

    The function never upgrades a state from a boolean supplied by a caller.
    Every affirmative state requires a validated receipt bound to the same
    public subject commit.
    """

    reasons: list[str] = []
    checks: dict[str, bool] = {}
    index_value: Mapping[str, Any] = evidence_index if isinstance(evidence_index, Mapping) else {}
    index_valid = True
    try:
        validate_public_evidence_index(index_value)
    except (TypeError, ValueError) as exc:
        index_valid = False
        reasons.append("PUBLIC_EVIDENCE_INDEX_INVALID:" + str(exc))
    checks["evidence_index"] = index_valid
    subject = index_value.get("subject_commit_sha") if index_valid else None
    subject_valid = isinstance(subject, str) and _HEX40_RE.fullmatch(subject) is not None

    source_ready = False
    if export_receipt is None:
        reasons.append("PUBLIC_EXPORT_RECEIPT_MISSING")
    else:
        try:
            from .public_export import validate_public_export_receipt

            validate_public_export_receipt(export_receipt)
            export_valid = export_receipt.get("status") == "validated"
            checks["public_export"] = export_valid
            if not export_valid:
                reasons.append("PUBLIC_EXPORT_NOT_VALIDATED")
            if not subject_valid or export_receipt.get("public_root_sha") != subject:
                reasons.append("PUBLIC_EXPORT_SUBJECT_MISMATCH")
            if index_valid and export_receipt.get("publication_policy_sha256") != index_value.get("publication_policy_sha256"):
                reasons.append("PUBLIC_EXPORT_POLICY_MISMATCH")
            source_ready = bool(export_valid and subject_valid and export_receipt.get("public_root_sha") == subject)
        except (ImportError, TypeError, ValueError) as exc:
            checks["public_export"] = False
            reasons.append("PUBLIC_EXPORT_RECEIPT_INVALID:" + str(exc))
    if "public_export" not in checks:
        checks["public_export"] = False
    checks["public_subject_binding"] = source_ready

    release_receipts_ready, receipt_reasons, receipt_checks = _validate_release_receipts(
        release_receipts,
        index_value if index_valid else {},
    )
    checks.update(receipt_checks)
    reasons.extend(receipt_reasons)

    security_artifact_sha256: str | None = None
    if receipt_checks.get("security_remediation") and isinstance(release_receipts, Mapping):
        security_receipt = release_receipts.get("security_remediation")
        if isinstance(security_receipt, Mapping) and isinstance(security_receipt.get("artifact_sha256"), str):
            security_artifact_sha256 = security_receipt["artifact_sha256"]
    security_ready, security_reasons = _security_remediation_valid(
        security_evidence,
        str(subject) if subject_valid else "",
        security_artifact_sha256,
    )
    checks["security_remediation"] = security_ready
    reasons.extend(security_reasons)

    publication_ready, publication_reasons = _publication_receipt_valid(
        publication_receipt,
        str(subject) if subject_valid else "",
    )
    checks["publication"] = publication_ready
    reasons.extend(publication_reasons)

    hosted_ci_ready = bool(
        index_valid
        and index_value.get("status") == "verified"
        and isinstance(index_value.get("ci_runs"), Mapping)
        and set(index_value["ci_runs"]) == set(REQUIRED_WORKFLOW_NAMES)
        and all(
            isinstance(row, Mapping)
            and row.get("conclusion") == "success"
            and row.get("head_sha") == subject
            for row in index_value["ci_runs"].values()
        )
    )
    checks["hosted_ci"] = hosted_ci_ready
    checks["package"] = bool(index_valid and index_value.get("package_sha256")) and bool(receipt_checks.get("package", False))
    checks["sbom"] = bool(index_valid and index_value.get("sbom_sha256")) and bool(receipt_checks.get("sbom", False))
    if not hosted_ci_ready:
        reasons.append("HOSTED_CI_EVIDENCE_PENDING")
    if not (index_valid and index_value.get("package_sha256")):
        reasons.append("PACKAGE_EVIDENCE_MISSING")
    if not (index_valid and index_value.get("sbom_sha256")):
        reasons.append("SBOM_EVIDENCE_MISSING")

    public_release_ready = bool(
        source_ready
        and index_valid
        and index_value.get("status") == "verified"
        and hosted_ci_ready
        and release_receipts_ready
        and security_ready
        and publication_ready
        and bool(index_value.get("package_sha256"))
        and bool(index_value.get("sbom_sha256"))
    )
    checks["public_release"] = public_release_ready
    if not public_release_ready:
        reasons.append("PUBLIC_RELEASE_GATE_PENDING")

    production_ready, production_reasons = _production_evidence_valid(
        production_evidence,
        str(subject) if subject_valid else "",
    )
    checks["production_evidence"] = production_ready
    reasons.extend(production_reasons)
    production_complete = bool(public_release_ready and production_ready)
    checks["production"] = production_complete
    if public_release_ready and not production_complete:
        reasons.append("PRODUCTION_COMPLETE_PENDING")

    effect_validated: bool | str = "awaiting_sample"
    if effect_evidence is None:
        reasons.append("EFFECT_AWAITING_SAMPLE")
    else:
        try:
            from .experiment import validate_effect_evidence

            validate_effect_evidence(
                effect_evidence,
                expected_subject_commit_sha=str(subject) if subject_valid else None,
                expected_evidence_index_sha256=(
                    str(index_value.get("index_sha256"))
                    if index_valid and isinstance(index_value.get("index_sha256"), str)
                    else None
                ),
            )
            effect_validated = True
            checks["ab_effect"] = True
        except (ImportError, TypeError, ValueError) as exc:
            checks["ab_effect"] = False
            reasons.append("EFFECT_EVIDENCE_PENDING:" + str(exc))
    if "ab_effect" not in checks:
        checks["ab_effect"] = False
    return PublicCompletionStatus(
        public_source_ready=source_ready,
        public_release_ready=public_release_ready,
        production_complete=production_complete,
        effect_validated=effect_validated,
        reason_codes=tuple(dict.fromkeys(reasons)),
        checks=checks,
    )


def _manifest_basis(
    subject_commit_sha: str,
    workflow_sha256: str,
    certification_sha256: Sequence[str],
) -> dict[str, Any]:
    return {
        "evidence_type": "subject_manifest",
        "subject_commit_sha": subject_commit_sha,
        "workflow_sha256": workflow_sha256,
        "certification_sha256": list(certification_sha256),
    }


def _validate_subject_mapping(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != SUBJECT_MANIFEST_KEYS:
        raise ValueError("RELEASE_SUBJECT_SCHEMA_INVALID")
    if value.get("evidence_type") != "subject_manifest":
        raise ValueError("RELEASE_SUBJECT_TYPE_INVALID")
    subject = _commit(value.get("subject_commit_sha"))
    workflow = _hash(value.get("workflow_sha256"))
    certifications = value.get("certification_sha256")
    if (
        not isinstance(certifications, list)
        or not certifications
        or any(not isinstance(item, str) for item in certifications)
        or len(set(certifications)) != len(certifications)
    ):
        raise ValueError("CERTIFICATION_EVIDENCE_MISSING")
    for item in certifications:
        _hash(item)
    if value.get("manifest_sha256") != _digest(_manifest_basis(subject, workflow, certifications)):
        raise ValueError("MANIFEST_HASH_MISMATCH")


def _validate_attestation_mapping(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != ATTESTATION_KEYS:
        raise ValueError("RELEASE_ATTESTATION_SCHEMA_INVALID")
    if value.get("evidence_type") != "post_push_attestation":
        raise ValueError("RELEASE_ATTESTATION_TYPE_INVALID")
    _commit(value.get("subject_commit_sha"))
    _commit(value.get("evidence_commit_sha"))
    _hash(value.get("manifest_sha256"))
    _hash(value.get("workflow_sha256"))
    certifications = value.get("certification_sha256")
    if (
        not isinstance(certifications, list)
        or not certifications
        or any(not isinstance(item, str) for item in certifications)
        or len(set(certifications)) != len(certifications)
    ):
        raise ValueError("CERTIFICATION_EVIDENCE_MISSING")
    for item in certifications:
        _hash(item)
    _time(value.get("attested_at"))


@dataclass(frozen=True)
class ReleaseManifest:
    evidence_type: str
    subject_commit_sha: str
    manifest_sha256: str
    workflow_sha256: str
    certification_sha256: tuple[str, ...]
    workflow_names: tuple[str, ...] = field(default_factory=tuple, repr=False, compare=False)
    real_certification: bool | None = field(default=None, repr=False, compare=False)
    production_enabled: bool = field(default=False, repr=False, compare=False)
    effect_validated: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        value = {
            "evidence_type": self.evidence_type,
            "subject_commit_sha": self.subject_commit_sha,
            "manifest_sha256": self.manifest_sha256,
            "workflow_sha256": self.workflow_sha256,
            "certification_sha256": list(self.certification_sha256),
        }
        _validate_subject_mapping(value)
        if self.workflow_names and not set(REQUIRED_WORKFLOW_NAMES).issubset(self.workflow_names):
            raise ValueError("RELEASE_WORKFLOW_EVIDENCE_MISSING")
        if self.real_certification is not None and not isinstance(self.real_certification, bool):
            raise ValueError("RELEASE_CERTIFICATION_STATE_INVALID")
        object.__setattr__(self, "certification_sha256", tuple(self.certification_sha256))
        object.__setattr__(self, "workflow_names", tuple(self.workflow_names))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "subject_commit_sha": self.subject_commit_sha,
            "manifest_sha256": self.manifest_sha256,
            "workflow_sha256": self.workflow_sha256,
            "certification_sha256": list(self.certification_sha256),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReleaseManifest":
        _validate_subject_mapping(value)
        return cls(
            evidence_type="subject_manifest",
            subject_commit_sha=str(value["subject_commit_sha"]),
            manifest_sha256=str(value["manifest_sha256"]),
            workflow_sha256=str(value["workflow_sha256"]),
            certification_sha256=tuple(str(item) for item in value["certification_sha256"]),
        )


@dataclass(frozen=True)
class CompletionStatus:
    software_complete: bool
    production_enabled: bool
    effect_validated: bool | str
    reason_codes: tuple[str, ...]
    checks: Mapping[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "software_complete": self.software_complete,
            "production_enabled": self.production_enabled,
            "effect_validated": self.effect_validated,
            "reason_codes": list(self.reason_codes),
            "checks": dict(self.checks),
        }


@dataclass(frozen=True)
class PublicCompletionStatus:
    """Independent public-source, release, production, and effect gates."""

    public_source_ready: bool
    public_release_ready: bool
    production_complete: bool
    effect_validated: bool | str
    reason_codes: tuple[str, ...]
    checks: Mapping[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_source_ready": self.public_source_ready,
            "public_release_ready": self.public_release_ready,
            "production_complete": self.production_complete,
            "effect_validated": self.effect_validated,
            "reason_codes": list(self.reason_codes),
            "checks": dict(self.checks),
        }


def build_release_manifest(
    subject_commit_sha: str,
    artifact_hashes: Mapping[str, Any],
    settings: Any,
) -> ReleaseManifest:
    if not isinstance(artifact_hashes, Mapping):
        raise ValueError("RELEASE_ARTIFACTS_OBJECT_REQUIRED")
    subject = _commit(subject_commit_sha)
    workflow = artifact_hashes.get("workflow_sha256")
    if workflow is None:
        workflow_parts = artifact_hashes.get("workflow_hashes")
        if isinstance(workflow_parts, Mapping) and workflow_parts:
            workflow = _digest({str(key): str(value) for key, value in sorted(workflow_parts.items())})
    workflow_hash = _hash(workflow, "RELEASE_WORKFLOW_HASH_INVALID")
    workflow_names_value = artifact_hashes.get("workflow_names", ())
    if not isinstance(workflow_names_value, (list, tuple, set, frozenset)):
        raise ValueError("RELEASE_WORKFLOW_EVIDENCE_MISSING")
    workflow_names = tuple(sorted({str(item) for item in workflow_names_value if str(item)}))
    if not set(REQUIRED_WORKFLOW_NAMES).issubset(workflow_names):
        raise ValueError("RELEASE_WORKFLOW_EVIDENCE_MISSING")
    certifications = artifact_hashes.get("certification_sha256")
    if not isinstance(certifications, (list, tuple)):
        raise ValueError("CERTIFICATION_EVIDENCE_MISSING")
    cert_hashes = tuple(str(item) for item in certifications)
    for item in cert_hashes:
        _hash(item, "CERTIFICATION_HASH_INVALID")
    if not cert_hashes or len(set(cert_hashes)) != len(cert_hashes):
        raise ValueError("CERTIFICATION_EVIDENCE_MISSING")
    basis = _manifest_basis(subject, workflow_hash, cert_hashes)
    return ReleaseManifest(
        evidence_type="subject_manifest",
        subject_commit_sha=subject,
        manifest_sha256=_digest(basis),
        workflow_sha256=workflow_hash,
        certification_sha256=cert_hashes,
        workflow_names=workflow_names,
        real_certification=(
            bool(artifact_hashes["real_certification"])
            if "real_certification" in artifact_hashes
            else None
        ),
        production_enabled=bool(artifact_hashes.get("production_enabled", False)),
        effect_validated=_effect_valid(
            artifact_hashes.get("effect_evidence"),
            subject_commit_sha=subject,
        ),
    )


def _validate_certification_receipts(
    receipts: Iterable[Mapping[str, Any]],
    expected_hashes: Sequence[str],
) -> tuple[bool, tuple[str, ...]]:
    rows = list(receipts)
    reasons: list[str] = []
    if not rows:
        return False, ("REAL_CERTIFICATION_UNVERIFIED",)
    hosts: set[str] = set()
    profiles: set[str] = set()
    hashes: set[str] = set()
    for row in rows:
        try:
            validate_receipt_artifact(row)
        except ValueError:
            reasons.append("CERTIFICATION_ARTIFACT_INVALID")
            continue
        if row["mode"] != "real":
            reasons.append("REAL_CERTIFICATION_MISSING")
            continue
        hosts.add(str(row["host_id"]))
        hashes.add(str(row["artifact_sha256"]))
        profile = _os_profile(str(row["os_family"]), str(row["os_version"]))
        if profile:
            profiles.add(profile)
    if hosts != set(REQUIRED_HOST_IDS):
        reasons.append("HOST_CERTIFICATION_MISSING")
    if not set(REQUIRED_OS_PROFILES).issubset(profiles):
        reasons.append("OS_CERTIFICATION_MISSING")
    if set(expected_hashes) != hashes:
        reasons.append("CERTIFICATION_HASH_MISMATCH")
    return not reasons, tuple(dict.fromkeys(reasons))


def validate_prerequisite_runs(
    prerequisite_runs: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    evidence_commit_sha: str,
) -> tuple[bool, tuple[str, ...]]:
    _commit(evidence_commit_sha)
    if isinstance(prerequisite_runs, Mapping):
        rows = [
            {"workflow": str(name), **dict(value)}
            for name, value in prerequisite_runs.items()
            if isinstance(value, Mapping)
        ]
    elif isinstance(prerequisite_runs, Sequence) and not isinstance(prerequisite_runs, (str, bytes)):
        rows = [dict(value) for value in prerequisite_runs if isinstance(value, Mapping)]
    else:
        rows = []
    by_name = {str(row.get("workflow", row.get("name", ""))): row for row in rows}
    reasons: list[str] = []
    for workflow in REQUIRED_WORKFLOW_NAMES:
        row = by_name.get(workflow)
        if row is None:
            reasons.append("PREREQUISITE_RUN_MISSING:" + workflow)
            continue
        run_id = row.get("run_id")
        if not isinstance(run_id, (str, int)) or not str(run_id):
            reasons.append("PREREQUISITE_RUN_ID_INVALID:" + workflow)
        if row.get("conclusion") != "success":
            reasons.append("PREREQUISITE_RUN_NOT_SUCCESS:" + workflow)
        if row.get("head_sha") != evidence_commit_sha:
            reasons.append("PREREQUISITE_RUN_SHA_MISMATCH:" + workflow)
    return not reasons, tuple(reasons)


def build_release_attestation(
    manifest: ReleaseManifest | Mapping[str, Any],
    evidence_commit_sha: str,
    prerequisite_runs: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    attested_at: datetime | None = None,
) -> dict[str, Any]:
    selected = manifest if isinstance(manifest, ReleaseManifest) else ReleaseManifest.from_mapping(manifest)
    valid, reasons = validate_prerequisite_runs(prerequisite_runs, evidence_commit_sha)
    if not valid:
        raise ValueError(reasons[0] if reasons else "PREREQUISITE_RUN_INVALID")
    timestamp = (attested_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    value = {
        "evidence_type": "post_push_attestation",
        "subject_commit_sha": selected.subject_commit_sha,
        "evidence_commit_sha": _commit(evidence_commit_sha),
        "manifest_sha256": selected.manifest_sha256,
        "workflow_sha256": selected.workflow_sha256,
        "certification_sha256": list(selected.certification_sha256),
        "attested_at": timestamp.isoformat().replace("+00:00", "Z"),
    }
    _validate_attestation_mapping(value)
    return value

def verify_release_attestation(
    manifest: ReleaseManifest | Mapping[str, Any],
    attestation: Mapping[str, Any],
    expected_evidence_commit_sha: str,
    *,
    certification_receipts: Iterable[Mapping[str, Any]] | None = None,
    production_evidence: Mapping[str, Any] | None = None,
    prerequisite_runs: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    now: datetime | None = None,
) -> CompletionStatus:
    reasons: list[str] = []
    checks: dict[str, bool] = {}
    if isinstance(manifest, ReleaseManifest):
        selected_manifest = manifest
        try:
            _validate_subject_mapping(selected_manifest.to_dict())
        except ValueError as exc:
            reasons.append(str(exc))
    else:
        try:
            selected_manifest = ReleaseManifest.from_mapping(manifest)
        except ValueError as exc:
            selected_manifest = None
            reasons.append(str(exc))
    if selected_manifest is None:
        return CompletionStatus(False, False, "awaiting_sample", tuple(dict.fromkeys(reasons)), checks)
    checks["subject_manifest_valid"] = not reasons
    try:
        _validate_attestation_mapping(attestation)
    except ValueError as exc:
        schema_reason = str(exc)
        if schema_reason == "CERTIFICATION_EVIDENCE_MISSING":
            reasons.append(schema_reason)
        else:
            reasons.append(schema_reason)
    if attestation.get("subject_commit_sha") != selected_manifest.subject_commit_sha:
        reasons.append("SUBJECT_SHA_MISMATCH")
    if attestation.get("evidence_commit_sha") != expected_evidence_commit_sha:
        reasons.append("EVIDENCE_COMMIT_SHA_MISMATCH")
    if attestation.get("manifest_sha256") != selected_manifest.manifest_sha256:
        reasons.append("MANIFEST_HASH_MISMATCH")
    if attestation.get("workflow_sha256") != selected_manifest.workflow_sha256:
        reasons.append("WORKFLOW_HASH_MISMATCH")
    if attestation.get("certification_sha256") != list(selected_manifest.certification_sha256):
        reasons.append("CERTIFICATION_HASH_MISMATCH")
    if prerequisite_runs is not None:
        prerequisite_ok, prerequisite_reasons = validate_prerequisite_runs(
            prerequisite_runs,
            str(attestation.get("evidence_commit_sha", "")),
        )
        checks["prerequisite_runs"] = prerequisite_ok
        reasons.extend(prerequisite_reasons)
    certification_hashes = attestation.get("certification_sha256")
    if not isinstance(certification_hashes, list) or len(certification_hashes) < len(REQUIRED_HOST_IDS):
        reasons.append("CERTIFICATION_EVIDENCE_MISSING")
    if attestation.get("fixture_only") is True:
        reasons.append("REAL_CERTIFICATION_MISSING")
    if certification_receipts is not None:
        valid_real, receipt_reasons = _validate_certification_receipts(
            certification_receipts,
            selected_manifest.certification_sha256,
        )
        checks["real_certification_receipts"] = valid_real
        reasons.extend(receipt_reasons)
    elif selected_manifest.real_certification is False:
        checks["real_certification_receipts"] = False
        reasons.append("REAL_CERTIFICATION_MISSING")
    elif selected_manifest.real_certification is True:
        checks["real_certification_receipts"] = True
    else:
        checks["real_certification_receipts"] = False
        reasons.append("REAL_CERTIFICATION_UNVERIFIED")
    attested_at = attestation.get("attested_at")
    if isinstance(attested_at, str):
        try:
            stamp = _time(attested_at)
            reference = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)
            if stamp > reference + timedelta(minutes=5):
                reasons.append("ATTESTATION_TIME_INVALID")
            elif reference - stamp > timedelta(days=30):
                reasons.append("ATTESTATION_STALE")
        except ValueError as exc:
            reasons.append(str(exc))
    software_reasons = tuple(dict.fromkeys(reasons))
    software_complete = not software_reasons
    production_enabled = False
    if production_evidence is not None:
        required = (
            "setup",
            "hook_canary",
            "recall",
            "closeout",
            "migration",
            "sync",
            "rollback",
        )
        production_enabled = all(production_evidence.get(key) is True for key in required)
        checks["production_evidence"] = production_enabled
    if not production_enabled:
        reasons.append("PRODUCTION_REAL_ACTIVATION_PENDING")
    effect_validated: bool | str = "awaiting_sample"
    if selected_manifest.effect_validated:
        effect_validated = True
    else:
        reasons.append("EFFECT_AWAITING_SAMPLE")
    return CompletionStatus(
        software_complete=software_complete,
        production_enabled=production_enabled,
        effect_validated=effect_validated,
        reason_codes=tuple(dict.fromkeys(reasons)),
        checks=checks,
    )


__all__ = [
    "ATTESTATION_KEYS",
    "CompletionStatus",
    "PRODUCTION_LIFECYCLE_STEPS",
    "PUBLIC_COMPATIBILITY_PAIRS",
    "PUBLIC_REQUIRED_RELEASE_RECEIPTS",
    "PublicCompletionStatus",
    "PRIVATE_CERTIFICATION_IMPORT_KEYS",
    "REQUIRED_WORKFLOW_NAMES",
    "ReleaseManifest",
    "SUBJECT_MANIFEST_KEYS",
    "build_private_certification_import",
    "build_release_attestation",
    "build_release_manifest",
    "evaluate_public_completion",
    "validate_private_certification_import",
    "validate_prerequisite_runs",
    "verify_release_attestation",
]
