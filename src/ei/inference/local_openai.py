from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .base import (
    InferenceBudget,
    ProviderProtocolError,
    ProviderResult,
    estimate_tokens,
    extract_structured_output,
    unavailable_result,
    validate_input,
    validate_output,
)
from .errors import MALFORMED_RESPONSE, PROVIDER_TIMEOUT, classify_provider_error


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _validate_loopback_endpoint(endpoint: object) -> str:
    if not isinstance(endpoint, str):
        raise ValueError("LOCAL_ENDPOINT_INVALID")
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        _ = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("LOCAL_ENDPOINT_INVALID") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("LOCAL_ENDPOINT_INVALID")
    try:
        address = ipaddress.ip_address(host) if host is not None else None
    except ValueError as exc:
        raise ValueError("LOCAL_ENDPOINT_NOT_LOOPBACK") from exc
    if address is None or not address.is_loopback:
        raise ValueError("LOCAL_ENDPOINT_NOT_LOOPBACK")
    return endpoint


class LocalOpenAICompatibleProvider:
    provider_id = "local-openai-compatible"
    locality = "local"

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8000/v1/chat/completions",
        *,
        model: str = "local-model",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 262_144,
        enabled: bool = True,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        endpoint = _validate_loopback_endpoint(endpoint)
        if not model or len(model) > 200:
            raise ValueError("LOCAL_MODEL_INVALID")
        if timeout_seconds <= 0 or max_response_bytes <= 0:
            raise ValueError("LOCAL_LIMIT_INVALID")
        self.endpoint = endpoint
        self.model = model
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = int(max_response_bytes)
        self.enabled = bool(enabled)
        self._opener = opener or build_opener(_NoRedirectHandler()).open

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None = None) -> "LocalOpenAICompatibleProvider":
        value = config if isinstance(config, Mapping) else {}
        return cls(
            endpoint=str(value.get("endpoint", "http://127.0.0.1:8000/v1/chat/completions")),
            model=str(value.get("model", "local-model")),
            timeout_seconds=float(value.get("timeout_seconds", 30)),
            max_response_bytes=int(value.get("max_response_bytes", 262_144)),
            enabled=bool(value.get("enabled", True)),
        )

    def available(self) -> bool:
        return self.enabled

    def _payload(self, schema_name: str, input_json: Mapping[str, Any], repair: bool = False, previous_response: str = "") -> dict[str, Any]:
        instruction = (
            "Return exactly one JSON object satisfying the requested schema. Do not include prose."
            if not repair
            else "Repair the previous local response and return exactly one JSON object satisfying the requested schema."
        )
        user_value = json.dumps({"schema_name": schema_name, "input": dict(input_json)}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        message: dict[str, Any] = {"role": "user", "content": user_value}
        if repair:
            message["repair_instruction"] = instruction
            message["previous_response"] = previous_response
        return {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": instruction}, message],
            "response_format": {"type": "json_object"},
        }

    def _read_limited(self, response: Any, limit: int) -> bytes:
        body = response.read(limit + 1)
        if not isinstance(body, (bytes, bytearray)):
            raise ProviderProtocolError("PROVIDER_RESPONSE_BYTES_REQUIRED")
        if len(body) > limit:
            raise ProviderProtocolError("PROVIDER_RESPONSE_TOO_LARGE")
        return bytes(body)

    def _post(self, payload: Mapping[str, Any], budget: InferenceBudget, attempt: int) -> tuple[ProviderResult | None, bytes]:
        data = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = Request(self.endpoint, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
        timeout = min(self.timeout_seconds, max(0.001, budget.deadline_ms / 1000))
        response = None
        try:
            response = self._opener(request, timeout=timeout)
            body = self._read_limited(response, min(self.max_response_bytes, budget.max_response_bytes))
            return None, body
        except HTTPError as exc:
            retry_after = None
            try:
                header = exc.headers.get("Retry-After") if exc.headers else None
                retry_after = int(header) if header is not None else None
            except (TypeError, ValueError):
                retry_after = None
            return classify_provider_error(exc.code, "http provider error", retry_after, provider_id=self.provider_id, now=datetime.now(timezone.utc), attempt=attempt), b""
        except TimeoutError as exc:
            del exc
            return ProviderResult(self.provider_id, "failed", error_code=PROVIDER_TIMEOUT, attempt=attempt, schema_name=""), b""
        except (URLError, OSError, ConnectionError) as exc:
            del exc
            return unavailable_result(self.provider_id), b""
        except ProviderProtocolError:
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, attempt=attempt), b""
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if callable(close):
                    close()

    def generate(
        self,
        schema_name: str,
        input_json: Mapping[str, Any],
        budget: InferenceBudget | Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        current_budget = InferenceBudget.from_value(budget)
        validate_input(schema_name, input_json)
        estimated_input = estimate_tokens(input_json)
        if estimated_input > current_budget.max_input_tokens:
            return ProviderResult(self.provider_id, "failed", error_code="TOKEN_CAP_EXCEEDED", input_tokens=estimated_input, schema_name=schema_name)
        if current_budget.deadline_ms <= 0:
            return ProviderResult(self.provider_id, "failed", error_code="DEADLINE_EXCEEDED", schema_name=schema_name)
        first_payload = self._payload(schema_name, input_json)
        transport_error, body = self._post(first_payload, current_budget, 1)
        if transport_error is not None:
            return ProviderResult(**{**transport_error.__dict__, "schema_name": schema_name})
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        output = extract_structured_output(decoded)
        repaired = False
        if output is None:
            repair_payload = self._payload(schema_name, input_json, True, body.decode("utf-8", "replace"))
            transport_error, repaired_body = self._post(repair_payload, current_budget, 2)
            if transport_error is not None:
                return ProviderResult(**{**transport_error.__dict__, "schema_name": schema_name})
            try:
                repaired_decoded = json.loads(repaired_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                repaired_decoded = None
            output = extract_structured_output(repaired_decoded)
            repaired = True
        if output is None:
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=estimated_input, schema_name=schema_name, repaired=repaired, attempt=2 if repaired else 1)
        try:
            validated = validate_output(schema_name, output)
        except (ValueError, ProviderProtocolError) as exc:
            del exc
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=estimated_input, schema_name=schema_name, repaired=repaired, attempt=2 if repaired else 1)
        output_tokens = estimate_tokens(validated)
        if output_tokens > current_budget.max_output_tokens:
            return ProviderResult(self.provider_id, "failed", error_code="TOKEN_CAP_EXCEEDED", input_tokens=estimated_input, output_tokens=output_tokens, schema_name=schema_name, repaired=repaired, attempt=2 if repaired else 1)
        return ProviderResult(
            self.provider_id,
            "success",
            output=validated,
            input_tokens=estimated_input,
            output_tokens=output_tokens,
            cost="0",
            repaired=repaired,
            attempt=2 if repaired else 1,
            schema_name=schema_name,
            metadata={"transport": "openai-compatible-local"},
        )


__all__ = ["LocalOpenAICompatibleProvider"]
