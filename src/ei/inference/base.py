from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable


_PROVIDER_STATUSES = frozenset({"success", "deferred", "failed", "disabled"})
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "prompt",
        "query",
        "message",
        "response",
        "transcript",
        "tool_output",
        "stderr",
        "stdout",
        "raw",
        "body",
        "api_key",
        "token",
        "secret",
    }
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def require_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("DATETIME_TIMEZONE_REQUIRED")
    return moment.astimezone(timezone.utc)


def estimate_tokens(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        return max(1, (len(value.encode("utf-8")) + 3) // 4) if value else 0
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        encoded = str(value).encode("utf-8", "replace")
    return (len(encoded) + 3) // 4


def decimal_cost(value: Decimal | int | float | str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("COST_INVALID") from exc
    if not result.is_finite() or result < 0:
        raise ValueError("COST_INVALID")
    return result.quantize(Decimal("0.00000001"))


def sanitize_metadata(value: Any, key: str = "") -> Any:
    lowered = key.casefold()
    if lowered in _FORBIDDEN_METADATA_KEYS or any(marker in lowered for marker in ("prompt", "transcript", "secret", "token", "password", "cookie")):
        return None
    if isinstance(value, Mapping):
        return {
            str(child_key): sanitized
            for child_key, child in value.items()
            if (sanitized := sanitize_metadata(child, str(child_key))) is not None
        }
    if isinstance(value, (list, tuple)):
        return [sanitized for child in value if (sanitized := sanitize_metadata(child, lowered)) is not None]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass(frozen=True)
class InferenceBudget:
    max_input_tokens: int = 20_000
    max_output_tokens: int = 4_000
    max_cost: Decimal = Decimal("0")
    deadline_ms: int = 120_000
    max_response_bytes: int = 256 * 1024
    candidate_id: str = ""
    purpose: str = "inheritance-gate"
    retry_attempt: int = 0

    def __post_init__(self) -> None:
        for name in ("max_input_tokens", "max_output_tokens", "deadline_ms", "max_response_bytes", "retry_attempt"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"INFERENCE_BUDGET_INVALID:{name}")
        object.__setattr__(self, "max_cost", decimal_cost(self.max_cost))
        if not self.purpose or len(self.purpose) > 80:
            raise ValueError("INFERENCE_BUDGET_INVALID:purpose")
        if len(self.candidate_id) > 160:
            raise ValueError("INFERENCE_BUDGET_INVALID:candidate_id")

    @classmethod
    def from_value(cls, value: InferenceBudget | Mapping[str, Any] | None) -> "InferenceBudget":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("INFERENCE_BUDGET_OBJECT_REQUIRED")
        fields = {
            "max_input_tokens": value.get("max_input_tokens", value.get("input_token_cap", cls.max_input_tokens)),
            "max_output_tokens": value.get("max_output_tokens", value.get("output_token_cap", cls.max_output_tokens)),
            "max_cost": value.get("max_cost", value.get("cost_cap", cls.max_cost)),
            "deadline_ms": value.get("deadline_ms", cls.deadline_ms),
            "max_response_bytes": value.get("max_response_bytes", cls.max_response_bytes),
            "candidate_id": value.get("candidate_id", ""),
            "purpose": value.get("purpose", cls.purpose),
            "retry_attempt": value.get("retry_attempt", 0),
        }
        return cls(**fields)


@dataclass(frozen=True)
class ProviderResult:
    provider_id: str
    status: str = "success"
    output: Mapping[str, Any] | None = None
    error_code: str | None = None
    retry_after_seconds: int | None = None
    next_eligible_at: datetime | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost: Decimal = Decimal("0")
    repaired: bool = False
    attempt: int = 1
    schema_name: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.provider_id or len(self.provider_id) > 100:
            raise ValueError("PROVIDER_RESULT_PROVIDER_ID_INVALID")
        if self.status not in _PROVIDER_STATUSES:
            raise ValueError("PROVIDER_RESULT_STATUS_INVALID")
        for name in ("input_tokens", "output_tokens", "attempt"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"PROVIDER_RESULT_{name.upper()}_INVALID")
        if self.retry_after_seconds is not None and (type(self.retry_after_seconds) is not int or self.retry_after_seconds < 0):
            raise ValueError("PROVIDER_RESULT_RETRY_AFTER_INVALID")
        if self.next_eligible_at is not None:
            require_aware(self.next_eligible_at)
        object.__setattr__(self, "cost", decimal_cost(self.cost))
        if self.output is not None and not isinstance(self.output, Mapping):
            raise ValueError("PROVIDER_RESULT_OUTPUT_OBJECT_REQUIRED")
        if self.metadata is None or not isinstance(self.metadata, Mapping):
            raise ValueError("PROVIDER_RESULT_METADATA_INVALID")
        sanitized = sanitize_metadata(self.metadata)
        object.__setattr__(self, "metadata", sanitized if isinstance(sanitized, Mapping) else {})

    @property
    def ok(self) -> bool:
        return self.status == "success"

    @property
    def deferred(self) -> bool:
        return self.status == "deferred"

    @property
    def reason_code(self) -> str:
        return self.error_code or ("OK" if self.ok else "PROVIDER_FAILED")

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "provider_id": self.provider_id,
            "status": self.status,
            "error_code": self.error_code,
            "retry_after_seconds": self.retry_after_seconds,
            "next_eligible_at": self.next_eligible_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if self.next_eligible_at else None,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost": str(self.cost),
            "repaired": self.repaired,
            "attempt": self.attempt,
            "schema_name": self.schema_name,
            "metadata": dict(self.metadata),
        }
        if include_output:
            result["output"] = dict(self.output) if self.output is not None else None
        return result


@runtime_checkable
class InferenceProvider(Protocol):
    provider_id: str
    locality: str

    def available(self) -> bool:
        ...

    def generate(self, schema_name: str, input_json: Mapping[str, Any], budget: InferenceBudget | Mapping[str, Any] | None) -> ProviderResult:
        ...


class ProviderProtocolError(ValueError):
    """Raised internally when a provider response violates the structured contract."""


def validate_input(schema_name: str, input_json: Mapping[str, Any]) -> None:
    if not isinstance(schema_name, str) or not schema_name or len(schema_name) > 120:
        raise ValueError("SCHEMA_NAME_INVALID")
    if not isinstance(input_json, Mapping):
        raise ValueError("INFERENCE_INPUT_OBJECT_REQUIRED")
    try:
        encoded = json.dumps(dict(input_json), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("INFERENCE_INPUT_INVALID") from exc
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("INFERENCE_INPUT_TOO_LARGE")


def validate_output(schema_name: str, output: Mapping[str, Any]) -> dict[str, Any]:
    validate_input(schema_name, output)
    result = dict(output)
    if "decision" in result and result["decision"] not in {"YES", "NO"}:
        raise ProviderProtocolError("OUTPUT_DECISION_INVALID")
    if "confidence" in result:
        confidence = result["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ProviderProtocolError("OUTPUT_CONFIDENCE_INVALID")
    return result


def extract_structured_output(payload: Any) -> Mapping[str, Any] | None:
    """Extract a JSON object from common local/CLI response envelopes without retaining raw text."""
    if isinstance(payload, Mapping):
        if isinstance(payload.get("choices"), list) and payload["choices"]:
            first = payload["choices"][0]
            if isinstance(first, Mapping):
                message = first.get("message")
                content = message.get("content") if isinstance(message, Mapping) else first.get("content")
                extracted = extract_structured_output(content)
                if extracted is not None:
                    return extracted
        for key in ("structured_output", "structured_result", "output", "result", "data"):
            if key in payload:
                extracted = extract_structured_output(payload[key])
                if extracted is not None:
                    return extracted
        if "response" in payload and isinstance(payload["response"], str):
            return extract_structured_output(payload["response"])
        return payload
    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return decoded if isinstance(decoded, Mapping) else None
    return None


def unavailable_result(provider_id: str, reason_code: str = "PROVIDER_UNAVAILABLE", *, schema_name: str = "") -> ProviderResult:
    return ProviderResult(provider_id=provider_id, status="failed", error_code=reason_code, schema_name=schema_name)


__all__ = [
    "InferenceBudget",
    "InferenceProvider",
    "ProviderProtocolError",
    "ProviderResult",
    "decimal_cost",
    "extract_structured_output",
    "estimate_tokens",
    "require_aware",
    "sanitize_metadata",
    "unavailable_result",
    "utc_now",
    "validate_input",
    "validate_output",
]
