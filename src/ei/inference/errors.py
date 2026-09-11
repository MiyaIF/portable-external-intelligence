from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .base import ProviderResult, require_aware


BACKOFF_SECONDS = (300, 900, 3600, 21600)
QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
RATE_LIMITED = "RATE_LIMITED"
AUTH_FAILED = "AUTH_FAILED"
PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"


def next_eligible_at(now: datetime, retry_after_seconds: int | None, attempt: int) -> datetime:
    moment = require_aware(now)
    if type(attempt) is not int or attempt < 0:
        raise ValueError("RETRY_ATTEMPT_INVALID")
    if retry_after_seconds is not None:
        if type(retry_after_seconds) is not int or retry_after_seconds < 0:
            raise ValueError("RETRY_AFTER_INVALID")
        delay = retry_after_seconds
    else:
        delay = BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)]
    return moment + timedelta(seconds=delay)


def _text(stderr: str) -> str:
    return stderr.casefold() if isinstance(stderr, str) else ""


def classify_provider_error(
    exit_code: int,
    stderr: str,
    retry_after_seconds: int | None = None,
    *,
    provider_id: str = "unknown",
    now: datetime | None = None,
    attempt: int = 0,
    schema_name: str = "",
) -> ProviderResult:
    if type(exit_code) is not int:
        raise ValueError("PROVIDER_EXIT_CODE_INVALID")
    text = _text(stderr)
    if exit_code in {401, 403} or any(marker in text for marker in ("unauthorized", "authentication", "invalid api key", "permission denied", "forbidden")):
        return ProviderResult(provider_id, "disabled", error_code=AUTH_FAILED, schema_name=schema_name, attempt=max(1, attempt + 1))
    if exit_code in {429, 430} or any(marker in text for marker in ("quota", "resource exhausted", "credits exhausted", "usage limit", "monthly limit", "daily limit")):
        moment = now or datetime.now(timezone.utc)
        return ProviderResult(
            provider_id,
            "deferred",
            error_code=QUOTA_EXHAUSTED,
            retry_after_seconds=retry_after_seconds,
            next_eligible_at=next_eligible_at(moment, retry_after_seconds, attempt),
            schema_name=schema_name,
            attempt=max(1, attempt + 1),
        )
    if any(marker in text for marker in ("rate limit", "too many requests", "retry-after", "temporarily throttled")):
        moment = now or datetime.now(timezone.utc)
        return ProviderResult(
            provider_id,
            "deferred",
            error_code=RATE_LIMITED,
            retry_after_seconds=retry_after_seconds,
            next_eligible_at=next_eligible_at(moment, retry_after_seconds, attempt),
            schema_name=schema_name,
            attempt=max(1, attempt + 1),
        )
    if exit_code in {124, 408} or any(marker in text for marker in ("timed out", "timeout", "deadline exceeded")):
        return ProviderResult(provider_id, "failed", error_code=PROVIDER_TIMEOUT, schema_name=schema_name, attempt=max(1, attempt + 1))
    if any(marker in text for marker in ("json", "malformed", "parse error", "invalid response", "unexpected token")):
        return ProviderResult(provider_id, "failed", error_code=MALFORMED_RESPONSE, schema_name=schema_name, attempt=max(1, attempt + 1))
    return ProviderResult(provider_id, "failed", error_code=PROVIDER_UNAVAILABLE, schema_name=schema_name, attempt=max(1, attempt + 1))


__all__ = [
    "AUTH_FAILED",
    "BACKOFF_SECONDS",
    "MALFORMED_RESPONSE",
    "PROVIDER_TIMEOUT",
    "PROVIDER_UNAVAILABLE",
    "QUOTA_EXHAUSTED",
    "RATE_LIMITED",
    "classify_provider_error",
    "next_eligible_at",
]