from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from .models import ObservationInput, ObservationState
from .redaction import redact_reusable


class Classification(str, Enum):
    PUBLIC = "public"
    PRIVATE_REUSABLE = "private-reusable"
    CLIENT_CONFIDENTIAL = "client-confidential"
    MACHINE_LOCAL = "machine-local"
    SECRET = "secret"  # pragma: allowlist secret
    EXTERNAL_REFERENCE = "external-reference"


PrivacyClassification = Classification


class PrivacyError(ValueError):
    """Raised when data cannot cross the private repository boundary."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code if isinstance(reason_code, str) else "PRIVACY_REJECTED")
        self.reason_code = reason_code if isinstance(reason_code, str) else "PRIVACY_REJECTED"


@dataclass(frozen=True)
class PrivacyDecision:
    classification: Classification
    allow_private_sync: bool
    allow_user_baseline: bool
    reason_code: str
    matched_rule_id: str | None = None
    irreversible_generalization: bool = False


_MAX_INSPECT_CHARS = 2_000_000
_PRIVATE_KEY_BEGIN = "-----" + "BEGIN"
_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key_block",
        re.compile(
            _PRIVATE_KEY_BEGIN
            + r"(?: [A-Z0-9]+)* PRIVATE KEY-----|"
            + _PRIVATE_KEY_BEGIN
            + r" OPENSSH PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    (
        "authorization_header",
        re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*\S+"),
    ),
    (
        "cookie_header",
        re.compile(r"(?i)\b(?:cookie|set-cookie)\s*:\s*\S+"),
    ),
    (
        "password_assignment",
        re.compile(
            r"""(?ix)\b(?:password|passwd|pwd)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
        ),
    ),
    (
        "provider_token",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9][A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,})\b"
        ),
    ),
    (
        "connection_string",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://[^/\s:@]+:[^@\s]+@"
        ),
    ),
)

_FORBIDDEN_FILE_NAMES = frozenset(
    {
        "auth",
        "auth.json",
        "auth.yaml",
        "auth.yml",
        "auth.toml",
        "credentials",
        "credentials.json",
        "cookies",
        "cookies.json",
        "session.sqlite",
        "state.sqlite",
    }
)
_FORBIDDEN_DIRECTORY_NAMES = frozenset(
    {
        "auth",
        "authentication",
        "browser",
        "browser-state",
        "cookies",
        "cookie",
        "transcript",
        "transcripts",
        "raw-transcript",
        "raw_transcript",
        "sqlite",
        "spool",
        "quarantine",
        "local-runtime",
        ".ei-local",
    }
)


def _normal_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def _safe_rejection(reason: str, rule_id: str | None = None) -> PrivacyDecision:
    return PrivacyDecision(Classification.SECRET, False, False, reason, rule_id)


def _path_parts(value: str) -> tuple[str, ...]:
    normalized = _normal_text(value).replace("\\", "/")
    return tuple(part for part in normalized.split("/") if part not in {"", "."})


def _forbidden_path_reason(value: str) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parts = _path_parts(value)
    lowered = tuple(part.casefold() for part in parts)
    for index, part in enumerate(lowered):
        if part.startswith(".env") or part.endswith((".sqlite", ".sqlite3", ".db")):
            return "MACHINE_LOCAL_PATH"
        if part in _FORBIDDEN_FILE_NAMES:
            return "MACHINE_LOCAL_PATH"
        if part in _FORBIDDEN_DIRECTORY_NAMES:
            return "MACHINE_LOCAL_PATH"
        if "transcript" in part or "browser" in part:
            return "MACHINE_LOCAL_PATH"
        if part in {"key", "keys"} and index > 0 and lowered[index - 1] in {"spool", "queue", "runtime"}:
            return "MACHINE_LOCAL_PATH"
    return None


def _secret_match(value: str) -> tuple[str, re.Pattern[str]] | None:
    normalized = _normal_text(value)
    normalized = re.sub(r"\[REDACTED_[A-Z0-9_]+\]", "", normalized)
    for rule_id, pattern in _SECRET_RULES:
        if pattern.search(normalized):
            return rule_id, pattern
    return None


def classify_source(source_kind: str) -> Classification:
    if not isinstance(source_kind, str):
        return Classification.MACHINE_LOCAL
    mapping = {
        "public": Classification.PUBLIC,
        "private": Classification.PRIVATE_REUSABLE,
        "private-reusable": Classification.PRIVATE_REUSABLE,
        "private_reusable": Classification.PRIVATE_REUSABLE,
        "client-confidential": Classification.CLIENT_CONFIDENTIAL,
        "client_confidential": Classification.CLIENT_CONFIDENTIAL,
        "client-confidential-generalized": Classification.PRIVATE_REUSABLE,
        "machine-local": Classification.MACHINE_LOCAL,
        "machine_local": Classification.MACHINE_LOCAL,
        "secret": Classification.SECRET,
        "external-reference": Classification.EXTERNAL_REFERENCE,
        "external_reference": Classification.EXTERNAL_REFERENCE,
        "external_article_copy": Classification.EXTERNAL_REFERENCE,
    }
    return mapping.get(source_kind.casefold(), Classification.PRIVATE_REUSABLE)


def inspect_text(text: str, source_kind: str, source_ref: str) -> PrivacyDecision:
    """Classify text without returning any source content in rejection metadata."""
    if not isinstance(text, str) or not isinstance(source_kind, str) or not isinstance(source_ref, str):
        return _safe_rejection("PRIVACY_INPUT_INVALID")
    normalized = _normal_text(text)
    if len(normalized) > _MAX_INSPECT_CHARS:
        return PrivacyDecision(Classification.MACHINE_LOCAL, False, False, "PAYLOAD_TOO_LARGE", "size_limit")
    match = _secret_match(normalized)
    if match is not None:
        return _safe_rejection("SECRET_PATTERN_MATCH", match[0])
    path_reason = _forbidden_path_reason(source_ref)
    if path_reason is not None:
        return PrivacyDecision(Classification.MACHINE_LOCAL, False, False, path_reason, "path_policy")
    classification = classify_source(source_kind)
    if classification is Classification.SECRET:
        return _safe_rejection("SECRET_CLASSIFICATION", "source_class")
    if classification is Classification.CLIENT_CONFIDENTIAL:
        return PrivacyDecision(classification, False, False, "CLIENT_CONFIDENTIAL_LOCAL_ONLY", "classification")
    if classification is Classification.MACHINE_LOCAL:
        return PrivacyDecision(classification, False, False, "MACHINE_LOCAL_SOURCE", "classification")
    allow_sync = classification in {
        Classification.PUBLIC,
        Classification.PRIVATE_REUSABLE,
    }
    return PrivacyDecision(classification, allow_sync, False, "CLASSIFIED", "classification")


def _observation_values(observation: ObservationInput | ObservationState) -> tuple[str, ...] | None:
    names = (
        "title",
        "claim",
        "source_kind",
        "source_ref",
        "cwd",
        "domain",
        "outcome_status",
        "benefit",
        "classification",
        "observation_id",
        "provenance_key",
        "cwd_fingerprint",
        "source_hash",
    )
    values: list[str] = []
    for name in names:
        value = getattr(observation, name, "")
        if value is None:
            continue
        if not isinstance(value, str):
            return None
        values.append(value)
    applicability = getattr(observation, "applicability", ())
    if not isinstance(applicability, (tuple, list)) or any(not isinstance(item, str) for item in applicability):
        return None
    values.extend(applicability)
    return tuple(values)


def inspect_observation(observation: ObservationInput | ObservationState) -> PrivacyDecision:
    if not isinstance(observation, (ObservationInput, ObservationState)):
        return _safe_rejection("PRIVACY_INPUT_INVALID")
    values = _observation_values(observation)
    if values is None:
        return _safe_rejection("PRIVACY_INPUT_INVALID")
    text = "\n".join(values)
    source_kind = getattr(observation, "source_kind", "")
    source_ref = getattr(observation, "source_ref", "")
    if not source_kind:
        source_kind = getattr(observation, "classification", "")
    if not source_ref:
        source_ref = getattr(observation, "provenance_key", "")
    decision = inspect_text(text, source_kind, source_ref)
    if not decision.allow_private_sync and decision.reason_code != "CLASSIFIED":
        return decision
    cwd = getattr(observation, "cwd", "") or getattr(observation, "cwd_fingerprint", "")
    for value in (cwd, getattr(observation, "source_ref", "")):
        reason = _forbidden_path_reason(value)
        if reason is not None:
            return PrivacyDecision(Classification.MACHINE_LOCAL, False, False, reason, "path_policy")
    explicit = getattr(observation, "classification", "")
    if not isinstance(explicit, str):
        return _safe_rejection("PRIVACY_INPUT_INVALID")
    explicit_class = classify_source(explicit)
    if explicit.casefold() in {"client-confidential-generalized", "client_confidential_generalized"}:
        return PrivacyDecision(
            Classification.PRIVATE_REUSABLE,
            True,
            False,
            "GENERALIZATION_VERIFIED",
            "generalization",
            True,
        )
    if explicit_class is Classification.SECRET:
        return _safe_rejection("SECRET_CLASSIFICATION", "classification")
    if explicit_class is Classification.CLIENT_CONFIDENTIAL:
        return PrivacyDecision(explicit_class, False, False, "CLIENT_CONFIDENTIAL_LOCAL_ONLY", "classification")
    if explicit_class is Classification.MACHINE_LOCAL:
        return PrivacyDecision(explicit_class, False, False, "MACHINE_LOCAL_SOURCE", "classification")
    if explicit_class is Classification.EXTERNAL_REFERENCE or source_kind in {
        "external_article_copy",
        "external-reference",
        "external_reference",
    }:
        return PrivacyDecision(Classification.EXTERNAL_REFERENCE, False, False, "EXTERNAL_REFERENCE_LOCAL_ONLY", "classification")
    return PrivacyDecision(
        explicit_class,
        explicit_class in {Classification.PUBLIC, Classification.PRIVATE_REUSABLE},
        False,
        decision.reason_code,
        decision.matched_rule_id,
    )


def inspect_persisted_text(text: str, source_kind: str, source_ref: str) -> PrivacyDecision:
    """Apply the common text policy before a value is persisted or synchronized."""
    if not isinstance(text, str):
        return _safe_rejection("PRIVACY_INPUT_INVALID")
    normalized = _normal_text(text)
    if any(unicodedata.category(char) in {"Cc", "Cf"} and char not in "\t\n\r" for char in normalized):
        return _safe_rejection("UNICODE_CONTROL_FORBIDDEN", "unicode_control")
    return inspect_text(normalized, source_kind, source_ref)


def assert_syncable(decision: PrivacyDecision) -> None:
    if not isinstance(decision, PrivacyDecision):
        raise PrivacyError("PRIVACY_DECISION_INVALID")
    allowed_classification = decision.classification in {Classification.PUBLIC, Classification.PRIVATE_REUSABLE} or (decision.classification is Classification.CLIENT_CONFIDENTIAL and decision.irreversible_generalization)
    if not allowed_classification or not decision.allow_private_sync:
        raise PrivacyError(decision.reason_code or "PRIVACY_REJECTED")
    if decision.classification is Classification.CLIENT_CONFIDENTIAL and not decision.irreversible_generalization:
        raise PrivacyError("CLIENT_CONFIDENTIAL_LOCAL_ONLY")


def _canonical_path(path: Path) -> Path:
    try:
        return Path(path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise PrivacyError("SOURCE_PATH_INVALID") from exc


def _path_key(path: Path) -> str:
    value = os.path.normpath(os.path.abspath(str(path)))
    if os.name == "nt":
        value = unicodedata.normalize("NFKC", value).casefold()
    return value.rstrip("\\/") or value


def _within(candidate: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_path_key(candidate), _path_key(root))) == _path_key(root)
    except (OSError, ValueError):
        return False


def _has_reparse_component(candidate: Path, root: Path) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
            is_junction = getattr(current, "is_junction", None)
            if callable(is_junction) and is_junction():
                return True
        except OSError:
            return True
    return False


def safe_source_path(path: Path, allowed_roots: Sequence[Path]) -> Path:
    """Return a canonical file path only when it is within an explicit root."""
    if not isinstance(path, Path) or not isinstance(allowed_roots, Sequence) or not allowed_roots:
        raise PrivacyError("SOURCE_ROOT_REQUIRED")
    if _forbidden_path_reason(str(path)) is not None:
        raise PrivacyError("SOURCE_PATH_DENIED")
    candidate = _canonical_path(path)
    for raw_root in allowed_roots:
        if not isinstance(raw_root, Path):
            raise PrivacyError("SOURCE_ROOT_INVALID")
        root = _canonical_path(raw_root)
        if not _within(candidate, root) or candidate == root:
            continue
        if _has_reparse_component(candidate, root):
            raise PrivacyError("SOURCE_PATH_REPARSE")
        return candidate
    raise PrivacyError("SOURCE_PATH_OUTSIDE_ROOT")
