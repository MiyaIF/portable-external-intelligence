from __future__ import annotations

import re
import hashlib
import unicodedata


_MAX_REDACT_CHARS = 2_000_000
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_HEADER = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization)\s*:\s*)\S+.*$")
_COOKIE_HEADER = re.compile(r"(?im)^(\s*(?:cookie|set-cookie)\s*:\s*)\S+.*$")
_ASSIGNMENT = re.compile(
    r"""(?ix)(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
)
_PROVIDER_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9][A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,})\b"
)
_CONNECTION_CREDENTIAL = re.compile(
    r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://)[^/\s:@]+:[^@\s]+@"
)
_WINDOWS_PATH = re.compile(r"(?i)(?<![\w])(?:[a-z]:[\\/])(?:[^\\/\r\n]+[\\/])+[^\\/\r\n,; ]+")
_UNIX_USER_PATH = re.compile(r"(?<![\w])/(?:Users|home|private/var|tmp)/[^\s,;]+")


def _replace_assignment(match: re.Match[str]) -> str:
    return match.group(1) + "[REDACTED_SECRET]"


def redact_reusable(text: str) -> str:
    """Remove credentials and machine/client identifiers deterministically."""
    if not isinstance(text, str):
        raise ValueError("REDACTION_INPUT_INVALID")
    normalized = unicodedata.normalize("NFKC", text)
    if len(normalized) > _MAX_REDACT_CHARS:
        raise ValueError("PAYLOAD_TOO_LARGE")
    result = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", normalized)
    result = _AUTH_HEADER.sub(r"\1[REDACTED_AUTHORIZATION]", result)
    result = _COOKIE_HEADER.sub(r"\1[REDACTED_COOKIE]", result)
    result = _ASSIGNMENT.sub(_replace_assignment, result)
    result = _PROVIDER_TOKEN.sub("[REDACTED_PROVIDER_TOKEN]", result)
    result = _CONNECTION_CREDENTIAL.sub(r"\1[REDACTED_CREDENTIAL]@", result)
    result = _WINDOWS_PATH.sub("[REDACTED_LOCAL_PATH]", result)
    result = _UNIX_USER_PATH.sub("[REDACTED_LOCAL_PATH]", result)
    if contains_secret_like(result):
        raise ValueError("REDACTION_FAILED")
    return result


def domain_hash(value: str, domain: str) -> str:
    """Hash an identifier with a stable namespace so domains cannot collide."""
    if not isinstance(value, str) or not isinstance(domain, str) or not domain:
        raise ValueError("DOMAIN_HASH_INPUT_INVALID")
    normalized_domain = unicodedata.normalize("NFKC", domain).strip()
    normalized_value = unicodedata.normalize("NFKC", value)
    if not normalized_domain or "\x00" in normalized_domain or "\x00" in normalized_value:
        raise ValueError("DOMAIN_HASH_INPUT_INVALID")
    material = f"ei:{normalized_domain}:v1\0{normalized_value}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def contains_secret_like(text: str) -> bool:
    if not isinstance(text, str):
        return True
    scan_text = re.sub(r"\[REDACTED_[A-Z0-9_]+\]", "", unicodedata.normalize("NFKC", text))
    scan_text = re.sub(r"(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*$", "", scan_text)
    scan_text = re.sub(r"(?im)\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*(?=\s*(?:$|\r?$))", "", scan_text)
    return any(
        pattern.search(scan_text) is not None
        for pattern in (
            _PRIVATE_KEY,
            _AUTH_HEADER,
            _COOKIE_HEADER,
            _ASSIGNMENT,
            _PROVIDER_TOKEN,
            _CONNECTION_CREDENTIAL,
        )
    )
