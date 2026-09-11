from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

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


class OllamaProvider:
    provider_id = "ollama"
    locality = "local"

    def __init__(
        self,
        command: Sequence[str] = ("ollama", "run"),
        *,
        model: str = "llama3.2",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 262_144,
        enabled: bool = True,
        runner: Any = subprocess.run,
    ) -> None:
        if isinstance(command, (str, bytes)) or not command or any(not isinstance(item, str) or not item for item in command):
            raise ValueError("OLLAMA_COMMAND_INVALID")
        if not model or len(model) > 200:
            raise ValueError("OLLAMA_MODEL_INVALID")
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("OLLAMA_LIMIT_INVALID")
        self.command = tuple(command)
        self.model = model
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = int(max_output_bytes)
        self.enabled = bool(enabled)
        self._runner = runner

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None = None) -> "OllamaProvider":
        value = config if isinstance(config, Mapping) else {}
        command = value.get("argv", ["ollama", "run"])
        if isinstance(command, str):
            command = [command]
        return cls(
            command=command,
            model=str(value.get("model", "llama3.2")),
            timeout_seconds=float(value.get("timeout_seconds", 60)),
            max_output_bytes=int(value.get("max_output_bytes", 262_144)),
            enabled=bool(value.get("enabled", True)),
        )

    def build_argv(self) -> tuple[str, ...]:
        if self.command and self.command[-1] == self.model:
            return self.command
        return (*self.command, self.model)

    def available(self) -> bool:
        if not self.enabled:
            return False
        executable = self.build_argv()[0]
        return bool(shutil.which(executable) or os.path.isabs(executable) and os.path.exists(executable))

    def generate(
        self,
        schema_name: str,
        input_json: Mapping[str, Any],
        budget: InferenceBudget | Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        current_budget = InferenceBudget.from_value(budget)
        validate_input(schema_name, input_json)
        input_tokens = estimate_tokens(input_json)
        if input_tokens > current_budget.max_input_tokens:
            return ProviderResult(self.provider_id, "failed", error_code="TOKEN_CAP_EXCEEDED", input_tokens=input_tokens, schema_name=schema_name)
        if current_budget.deadline_ms <= 0:
            return ProviderResult(self.provider_id, "failed", error_code="DEADLINE_EXCEEDED", schema_name=schema_name)
        request = json.dumps({"schema_name": schema_name, "input": dict(input_json)}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        timeout = min(self.timeout_seconds, max(0.001, current_budget.deadline_ms / 1000))
        try:
            completed = self._runner(
                self.build_argv(),
                input=request,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                shell=False,
                env={**os.environ, "EI_INTERNAL": "1"},
            )
        except subprocess.TimeoutExpired:
            return ProviderResult(self.provider_id, "failed", error_code=PROVIDER_TIMEOUT, input_tokens=input_tokens, schema_name=schema_name)
        except (OSError, ValueError) as exc:
            del exc
            return unavailable_result(self.provider_id, schema_name=schema_name)
        stdout = getattr(completed, "stdout", "")
        stderr = getattr(completed, "stderr", "")
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=input_tokens, schema_name=schema_name)
        output_bytes = stdout.encode("utf-8", "replace")
        if len(output_bytes) > min(self.max_output_bytes, current_budget.max_response_bytes):
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=input_tokens, schema_name=schema_name)
        return_code = getattr(completed, "returncode", 1)
        if type(return_code) is not int or return_code != 0:
            result = classify_provider_error(
                return_code if type(return_code) is int else 1,
                "ollama provider failure " + ("timeout" if "timeout" in stderr.casefold() else "process failure"),
                provider_id=self.provider_id,
                now=datetime.now(timezone.utc),
                attempt=1,
                schema_name=schema_name,
            )
            return ProviderResult(**{**result.__dict__, "input_tokens": input_tokens})
        try:
            decoded = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        output = extract_structured_output(decoded if decoded is not None else stdout)
        if output is None:
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=input_tokens, schema_name=schema_name)
        try:
            validated = validate_output(schema_name, output)
        except (ValueError, ProviderProtocolError) as exc:
            del exc
            return ProviderResult(self.provider_id, "failed", error_code=MALFORMED_RESPONSE, input_tokens=input_tokens, schema_name=schema_name)
        output_tokens = estimate_tokens(validated)
        if output_tokens > current_budget.max_output_tokens:
            return ProviderResult(self.provider_id, "failed", error_code="TOKEN_CAP_EXCEEDED", input_tokens=input_tokens, output_tokens=output_tokens, schema_name=schema_name)
        return ProviderResult(
            self.provider_id,
            "success",
            output=validated,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            schema_name=schema_name,
            metadata={"transport": "ollama-subprocess"},
        )


__all__ = ["OllamaProvider"]