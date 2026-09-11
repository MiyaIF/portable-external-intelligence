from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse
from typing import Any, Mapping

from .safe_fs import (
    SafeFilesystemError,
    absolute_path,
    assert_no_reparse_components,
    assert_safe_target,
    canonical_path,
    safe_atomic_write,
    safe_ensure_directory,
    safe_mkdir,
)


REMOTE_CLASSES = frozenset({"local_path", "private_verified", "private_attested", "public", "unknown"})
PRIVATE_ALLOWED_CLASSES = frozenset({"local_path", "private_verified", "private_attested"})
_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_V1_KEYS = frozenset({"schema_version", "classification", "remote_fingerprint", "fingerprint_digest", "approved_at", "approved_by_hash"})
_V2_KEYS = frozenset({"schema_version", "classification", "provider", "verification_source", "remote_fingerprint", "fingerprint_digest", "verified_at", "approved_by_hash"})
_RECEIPT_CLASSIFICATIONS = frozenset({"local_path", "private_verified", "private_attested"})


class RemoteAssuranceError(ValueError):
    """Raised when a knowledge remote is not safe for the requested data."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}:{detail}")


@dataclass(frozen=True)
class RemoteDescriptor:
    remote: str
    normalized: str
    fingerprint: str
    classification: str
    provider: str
    owner: str | None = None
    repository: str | None = None
    visibility_source: str | None = None

    def to_dict(self, *, include_normalized: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "classification": self.classification,
            "provider": self.provider,
            "owner": self.owner,
            "repository": self.repository,
            "visibility_source": self.visibility_source,
        }
        if include_normalized:
            value["normalized"] = self.normalized
        return value


def normalize_remote(remote: str | Path) -> str:
    if not isinstance(remote, (str, Path)) or not str(remote).strip():
        raise RemoteAssuranceError("REMOTE_INVALID")
    value = str(remote).strip()
    if "\x00" in value or "\r" in value or "\n" in value:
        raise RemoteAssuranceError("REMOTE_INVALID")
    if value.startswith("file://"):
        parsed = urlparse(value)
        path = unquote(parsed.path)
        if parsed.netloc and parsed.netloc not in {"", "localhost"}:
            path = "//" + parsed.netloc + path
        return "file:" + str(Path(path).expanduser().resolve()).replace("\\", "/")
    if "://" not in value and not ("@" in value and ":" in value.split("@", 1)[-1]):
        return "file:" + str(Path(value).expanduser().resolve()).replace("\\", "/")
    scp_match = re.fullmatch(r"(?P<user>[A-Za-z0-9_.-]+)@(?P<host>[A-Za-z0-9_.-]+):(?P<path>[^\s]+)", value)
    if scp_match:
        host = scp_match.group("host").casefold()
        path = scp_match.group("path").strip("/")
        return f"ssh://{host}/{path.removesuffix('.git')}"
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        raise RemoteAssuranceError("REMOTE_INVALID")
    if parsed.username or parsed.password:
        raise RemoteAssuranceError("REMOTE_CREDENTIALS_FORBIDDEN")
    host = parsed.hostname.casefold()
    path = unquote(parsed.path).strip("/").removesuffix(".git")
    if not path:
        raise RemoteAssuranceError("REMOTE_REPOSITORY_REQUIRED")
    return f"{parsed.scheme.casefold()}://{host}/{path}"


def remote_fingerprint(remote: str | Path) -> str:
    normalized = normalize_remote(remote)
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _github_parts(normalized: str) -> tuple[str, str] | None:
    parsed = urlparse(normalized)
    if parsed.hostname not in _GITHUB_HOSTS:
        return None
    parts = [item for item in parsed.path.split("/") if item]
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def _probe_github_visibility(owner: str, repository: str, executable: str = "gh") -> tuple[str | None, str]:
    try:
        result = subprocess.run(
            [executable, "api", f"repos/{owner}/{repository}", "--jq", ".visibility"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None, "gh_unavailable"
    if result.returncode != 0:
        return None, "github_api_unverified"
    visibility = result.stdout.strip().casefold()
    if visibility not in {"public", "private", "internal"}:
        return None, "github_visibility_unverified"
    return visibility, "github_api"


def _attestation_matches(attestation: Mapping[str, Any] | None, fingerprint: str) -> bool:
    if not isinstance(attestation, Mapping):
        return False
    value = str(attestation.get("remote_fingerprint", ""))
    return value == fingerprint and attestation.get("classification") == "private_attested"


def classify_remote(
    remote: str | Path,
    *,
    visibility: str | None = None,
    attestation: Mapping[str, Any] | None = None,
    github_executable: str = "gh",
) -> RemoteDescriptor:
    normalized = normalize_remote(remote)
    fingerprint = "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if normalized.startswith("file:"):
        return RemoteDescriptor(str(remote), normalized, fingerprint, "local_path", "local")
    github = _github_parts(normalized)
    if github is not None:
        owner, repository = github
        source = "explicit"
        resolved_visibility = visibility.casefold() if isinstance(visibility, str) else None
        if resolved_visibility is None:
            resolved_visibility, source = _probe_github_visibility(owner, repository, github_executable)
        if resolved_visibility == "public":
            classification = "public"
        elif resolved_visibility in {"private", "internal"}:
            classification = "private_verified"
        elif _attestation_matches(attestation, fingerprint):
            classification = "private_attested"
            source = "operator_attestation"
        else:
            classification = "unknown"
        return RemoteDescriptor(str(remote), normalized, fingerprint, classification, "github", owner, repository, source)
    if _attestation_matches(attestation, fingerprint):
        return RemoteDescriptor(str(remote), normalized, fingerprint, "private_attested", urlparse(normalized).hostname or "generic", visibility_source="operator_attestation")
    return RemoteDescriptor(str(remote), normalized, fingerprint, "unknown", urlparse(normalized).hostname or "generic", visibility_source="unverified")


def _validate_assurance_receipt(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    schema_version = value.get("schema_version")
    keys = set(value)
    fingerprint = value.get("remote_fingerprint")
    digest = value.get("fingerprint_digest")
    if (
        not isinstance(fingerprint, str)
        or not _SHA256.fullmatch(fingerprint)
        or not isinstance(digest, str)
        or not _HEX.fullmatch(digest)
        or digest != fingerprint.removeprefix("sha256:")
    ):
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    if schema_version == 1:
        required = {"schema_version", "classification", "remote_fingerprint", "fingerprint_digest", "approved_at"}
        if keys - _V1_KEYS or not required.issubset(keys) or value.get("classification") != "private_attested":
            raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
        if not isinstance(value.get("approved_at"), str) or not value["approved_at"]:
            raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
        approved_by = value.get("approved_by_hash")
        if approved_by is not None and (not isinstance(approved_by, str) or not _SHA256.fullmatch(approved_by)):
            raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
        return dict(value)
    if schema_version != 2:
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    required = {
        "schema_version",
        "classification",
        "provider",
        "verification_source",
        "remote_fingerprint",
        "fingerprint_digest",
        "verified_at",
    }
    classification = value.get("classification")
    if keys - _V2_KEYS or not required.issubset(keys) or classification not in _RECEIPT_CLASSIFICATIONS:
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    for key in ("provider", "verification_source", "verified_at"):
        field = value.get(key)
        if not isinstance(field, str) or not field or "\x00" in field or "\r" in field or "\n" in field:
            raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    approved_by = value.get("approved_by_hash")
    if classification == "private_attested":
        if not isinstance(approved_by, str) or not _SHA256.fullmatch(approved_by):
            raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    elif approved_by is not None:
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    return dict(value)


def load_remote_assurance_receipt(path: Path | str) -> dict[str, Any]:
    try:
        raw = assert_no_reparse_components(absolute_path(path))
        target = canonical_path(raw, require_exists=True)
        assert_safe_target(target.parent, target, allow_missing=False, expected_type="file")
    except SafeFilesystemError as exc:
        raise RemoteAssuranceError("REMOTE_ASSURANCE_PATH_UNSAFE", exc.code) from exc
    if not target.is_file():
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID") from exc
    return _validate_assurance_receipt(value)


def load_attestation(path: Path | str) -> dict[str, Any]:
    return load_remote_assurance_receipt(path)


def build_attestation(remote: str | Path, *, approved_by_hash: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    normalized = normalize_remote(remote)
    fingerprint = "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "classification": "private_attested",
        "remote_fingerprint": fingerprint,
        "fingerprint_digest": fingerprint[7:],
        "approved_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if approved_by_hash is not None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", approved_by_hash):
            raise RemoteAssuranceError("REMOTE_APPROVER_HASH_INVALID")
        receipt["approved_by_hash"] = approved_by_hash
    return receipt


def build_remote_assurance_receipt(
    descriptor: RemoteDescriptor,
    *,
    approved_by_hash: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(descriptor, RemoteDescriptor):
        raise TypeError("REMOTE_DESCRIPTOR_REQUIRED")
    if descriptor.classification not in _RECEIPT_CLASSIFICATIONS:
        raise RemoteAssuranceError("REMOTE_ASSURANCE_CLASSIFICATION_FORBIDDEN")
    if not _SHA256.fullmatch(descriptor.fingerprint):
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    if descriptor.classification == "private_attested":
        if not isinstance(approved_by_hash, str) or not _SHA256.fullmatch(approved_by_hash):
            raise RemoteAssuranceError("REMOTE_APPROVER_HASH_INVALID")
    elif approved_by_hash is not None:
        raise RemoteAssuranceError("REMOTE_APPROVER_HASH_FORBIDDEN")
    receipt: dict[str, Any] = {
        "schema_version": 2,
        "classification": descriptor.classification,
        "provider": descriptor.provider,
        "verification_source": descriptor.visibility_source or ("local_path" if descriptor.classification == "local_path" else "operator_attestation"),
        "remote_fingerprint": descriptor.fingerprint,
        "fingerprint_digest": descriptor.fingerprint.removeprefix("sha256:"),
        "verified_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if approved_by_hash is not None:
        receipt["approved_by_hash"] = approved_by_hash
    return _validate_assurance_receipt(receipt)


def _write_assurance_receipt(runtime_root: Path | str, receipt: Mapping[str, Any]) -> Path:
    value = _validate_assurance_receipt(dict(receipt))
    try:
        raw_root = assert_no_reparse_components(absolute_path(runtime_root))
        if raw_root == Path(raw_root.anchor):
            raise RemoteAssuranceError("RUNTIME_ROOT_INVALID")
        root = safe_ensure_directory(raw_root, mode=0o700)
        directory = safe_mkdir(root, root / "remote-assurance", mode=0o700)
    except RemoteAssuranceError:
        raise
    except SafeFilesystemError as exc:
        raise RemoteAssuranceError("REMOTE_ASSURANCE_PATH_UNSAFE", exc.code) from exc
    fingerprint = str(value["remote_fingerprint"])
    target = directory / (fingerprint.removeprefix("sha256:") + ".json")
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    try:
        return safe_atomic_write(directory, target, raw, mode=0o600)
    except SafeFilesystemError as exc:
        raise RemoteAssuranceError("REMOTE_ASSURANCE_PATH_UNSAFE", exc.code) from exc


def write_remote_assurance_receipt(runtime_root: Path | str, receipt: Mapping[str, Any]) -> Path:
    return _write_assurance_receipt(runtime_root, receipt)


def write_attestation(runtime_root: Path | str, attestation: Mapping[str, Any]) -> Path:
    value = _validate_assurance_receipt(dict(attestation))
    if value.get("schema_version") != 1 or value.get("classification") != "private_attested":
        raise RemoteAssuranceError("REMOTE_ATTESTATION_INVALID")
    return _write_assurance_receipt(runtime_root, value)


def assert_remote_allowed(classification: str, *, data_classification: str = "private-reusable") -> None:
    if classification not in REMOTE_CLASSES:
        raise RemoteAssuranceError("REMOTE_CLASSIFICATION_INVALID")
    if data_classification == "public-sanitized":
        if classification in {"unknown", "public"}:
            return
        return
    if data_classification not in {"private-reusable", "client-confidential", "machine-local"}:
        raise RemoteAssuranceError("DATA_CLASSIFICATION_INVALID")
    if classification not in PRIVATE_ALLOWED_CLASSES:
        raise RemoteAssuranceError("PRIVATE_REMOTE_REQUIRED" if classification == "public" else "REMOTE_VISIBILITY_UNKNOWN")


def assure_remote(
    remote: str | Path,
    *,
    engine_remote: str | Path | None = None,
    attestation: Mapping[str, Any] | None = None,
    visibility: str | None = None,
    data_classification: str = "private-reusable",
    github_executable: str = "gh",
) -> RemoteDescriptor:
    descriptor = classify_remote(remote, visibility=visibility, attestation=attestation, github_executable=github_executable)
    if engine_remote is not None and descriptor.fingerprint == remote_fingerprint(engine_remote):
        raise RemoteAssuranceError("ENGINE_REMOTE_REUSE")
    assert_remote_allowed(descriptor.classification, data_classification=data_classification)
    if descriptor.classification == "private_attested" and not _attestation_matches(attestation, descriptor.fingerprint):
        raise RemoteAssuranceError("REMOTE_APPROVAL_FINGERPRINT_MISMATCH")
    return descriptor


__all__ = [
    "PRIVATE_ALLOWED_CLASSES",
    "REMOTE_CLASSES",
    "RemoteAssuranceError",
    "RemoteDescriptor",
    "assure_remote",
    "assert_remote_allowed",
    "build_attestation",
    "build_remote_assurance_receipt",
    "classify_remote",
    "load_attestation",
    "load_remote_assurance_receipt",
    "normalize_remote",
    "remote_fingerprint",
    "write_attestation",
    "write_remote_assurance_receipt",
]
