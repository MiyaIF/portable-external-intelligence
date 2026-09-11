from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from threading import get_ident
from typing import Any, Mapping

from .base import decimal_cost, require_aware


DEFAULT_BACKOFF_SECONDS = (300, 900, 3600, 21600)
BACKOFF_SECONDS = DEFAULT_BACKOFF_SECONDS


def _positive_int(value: Any, name: str, default: int) -> int:
    if type(value) is not int or value < 0:
        if value is None:
            return default
        raise ValueError(f"BUDGET_POLICY_INVALID:{name}")
    return value


def _utc_day(now: datetime) -> str:
    return require_aware(now).date().isoformat()


def _new_counter() -> dict[str, Any]:
    return {"input_tokens": 0, "output_tokens": 0, "cost": "0.00000000", "day": ""}


def _add(counter: dict[str, Any], input_tokens: int, output_tokens: int, cost: Decimal, day: str) -> None:
    counter["input_tokens"] = int(counter.get("input_tokens", 0)) + input_tokens
    counter["output_tokens"] = int(counter.get("output_tokens", 0)) + output_tokens
    counter["cost"] = str(decimal_cost(Decimal(str(counter.get("cost", "0"))) + cost))
    counter["day"] = day


@dataclass(frozen=True)
class BudgetPolicy:
    schema_version: int = 1
    mode: str = "local_first_subscription_only"
    per_run_input_tokens: int = 20_000
    per_run_output_tokens: int = 4_000
    per_run_cost: Decimal = Decimal("0")
    per_day_input_tokens: int = 100_000
    per_day_output_tokens: int = 20_000
    per_day_cost: Decimal = Decimal("0")
    per_candidate_input_tokens: int = 12_000
    per_candidate_output_tokens: int = 3_000
    per_candidate_cost: Decimal = Decimal("0")
    retry_limit: int = 4
    deadline_ms: int = 120_000
    max_response_bytes: int = 262_144
    backoff_seconds: tuple[int, ...] = DEFAULT_BACKOFF_SECONDS
    cloud_api_enabled: bool = False
    cloud_spend_cap: Decimal = Decimal("0")
    subscription_on_quota: str = "DEFERRED_QUOTA"

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("BUDGET_POLICY_SCHEMA_UNSUPPORTED")
        if not self.mode:
            raise ValueError("BUDGET_POLICY_MODE_REQUIRED")
        for name in (
            "per_run_input_tokens",
            "per_run_output_tokens",
            "per_day_input_tokens",
            "per_day_output_tokens",
            "per_candidate_input_tokens",
            "per_candidate_output_tokens",
            "retry_limit",
            "deadline_ms",
            "max_response_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"BUDGET_POLICY_INVALID:{name}")
        for name in ("per_run_cost", "per_day_cost", "per_candidate_cost", "cloud_spend_cap"):
            object.__setattr__(self, name, decimal_cost(getattr(self, name)))
        if not self.backoff_seconds or any(type(value) is not int or value < 0 for value in self.backoff_seconds):
            raise ValueError("BUDGET_POLICY_INVALID:backoff_seconds")
        if self.subscription_on_quota != "DEFERRED_QUOTA":
            raise ValueError("BUDGET_POLICY_INVALID:subscription_on_quota")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BudgetPolicy":
        if not isinstance(value, Mapping):
            raise ValueError("BUDGET_POLICY_OBJECT_REQUIRED")
        limits = value.get("limits", {})
        if not isinstance(limits, Mapping):
            raise ValueError("BUDGET_POLICY_INVALID:limits")
        run = limits.get("per_run", {})
        day = limits.get("per_day", {})
        candidate = limits.get("per_candidate", {})
        retry = value.get("retry", {})
        deadline = value.get("deadline", {})
        cloud = value.get("cloud_api", {})
        subscription = value.get("subscription", {})
        if not all(isinstance(item, Mapping) for item in (run, day, candidate, retry, deadline, cloud, subscription)):
            raise ValueError("BUDGET_POLICY_INVALID:section")
        backoff = retry.get("backoff_seconds", DEFAULT_BACKOFF_SECONDS)
        if not isinstance(backoff, (list, tuple)):
            raise ValueError("BUDGET_POLICY_INVALID:backoff_seconds")
        return cls(
            schema_version=value.get("schema_version", 1),
            mode=str(value.get("mode", "local_first_subscription_only")),
            per_run_input_tokens=_positive_int(run.get("input_tokens", 20_000), "per_run_input_tokens", 20_000),
            per_run_output_tokens=_positive_int(run.get("output_tokens", 4_000), "per_run_output_tokens", 4_000),
            per_run_cost=run.get("cost", "0"),
            per_day_input_tokens=_positive_int(day.get("input_tokens", 100_000), "per_day_input_tokens", 100_000),
            per_day_output_tokens=_positive_int(day.get("output_tokens", 20_000), "per_day_output_tokens", 20_000),
            per_day_cost=day.get("cost", "0"),
            per_candidate_input_tokens=_positive_int(candidate.get("input_tokens", 12_000), "per_candidate_input_tokens", 12_000),
            per_candidate_output_tokens=_positive_int(candidate.get("output_tokens", 3_000), "per_candidate_output_tokens", 3_000),
            per_candidate_cost=candidate.get("cost", "0"),
            retry_limit=_positive_int(retry.get("max_attempts", 4), "retry_limit", 4),
            deadline_ms=_positive_int(deadline.get("max_ms", 120_000), "deadline_ms", 120_000),
            max_response_bytes=_positive_int(deadline.get("max_response_bytes", 262_144), "max_response_bytes", 262_144),
            backoff_seconds=tuple(backoff),
            cloud_api_enabled=bool(cloud.get("enabled", False)),
            cloud_spend_cap=cloud.get("spend_cap", value.get("cloud_spend_cap", "0")),
            subscription_on_quota=str(subscription.get("on_quota", "DEFERRED_QUOTA")),
        )

    @classmethod
    def from_path(cls, path: Path) -> "BudgetPolicy":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("BUDGET_POLICY_READ_FAILED") from exc
        return cls.from_mapping(raw)


@dataclass(frozen=True)
class BudgetResult:
    allowed: bool
    reason_code: str
    provider_id: str
    purpose: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost: Decimal = Decimal("0")
    run_input_tokens: int = 0
    day_input_tokens: int = 0
    candidate_input_tokens: int = 0
    run_cost: Decimal = Decimal("0")
    day_cost: Decimal = Decimal("0")
    candidate_cost: Decimal = Decimal("0")
    next_eligible_at: datetime | None = None
    remaining: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.provider_id or not self.purpose:
            raise ValueError("BUDGET_RESULT_ID_REQUIRED")
        if type(self.allowed) is not bool:
            raise ValueError("BUDGET_RESULT_ALLOWED_INVALID")
        for name in ("input_tokens", "output_tokens", "run_input_tokens", "day_input_tokens", "candidate_input_tokens"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"BUDGET_RESULT_INVALID:{name}")
        for name in ("cost", "run_cost", "day_cost", "candidate_cost"):
            object.__setattr__(self, name, decimal_cost(getattr(self, name)))
        if self.next_eligible_at is not None:
            require_aware(self.next_eligible_at)

    @property
    def ok(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "provider_id": self.provider_id,
            "purpose": self.purpose,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost": str(self.cost),
            "run_input_tokens": self.run_input_tokens,
            "day_input_tokens": self.day_input_tokens,
            "candidate_input_tokens": self.candidate_input_tokens,
            "run_cost": str(self.run_cost),
            "day_cost": str(self.day_cost),
            "candidate_cost": str(self.candidate_cost),
            "next_eligible_at": self.next_eligible_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if self.next_eligible_at else None,
            "remaining": dict(self.remaining),
        }


class BudgetLockError(RuntimeError):
    """Raised when the machine-local budget ledger lock cannot be acquired."""


class BudgetLedger:
    def __init__(
        self,
        path_or_settings: Path | str | Any | None = None,
        policy: BudgetPolicy | Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
        candidate_id: str | None = None,
        purpose: str = "inheritance-gate",
        disabled_providers: set[str] | frozenset[str] | None = None,
    ) -> None:
        settings = path_or_settings if hasattr(path_or_settings, "paths") else None
        if settings is not None:
            path = settings.paths.runtime_dir / "inference-budget.json"
            if policy is None and getattr(settings, "budget_policy_path", None):
                policy_path = Path(settings.budget_policy_path)
                policy = BudgetPolicy.from_path(policy_path) if policy_path.exists() else None
        elif path_or_settings is None:
            path = Path(".ei-local") / "inference-budget.json"
        else:
            path = Path(path_or_settings)
            if path.suffix.casefold() != ".json":
                path = path / "inference-budget.json"
        self.path = path.expanduser().resolve()
        if policy is None:
            self.policy = BudgetPolicy()
        elif isinstance(policy, BudgetPolicy):
            self.policy = policy
        else:
            self.policy = BudgetPolicy.from_mapping(policy)
        self.run_id = self._safe_id(run_id or f"process-{os.getpid()}-{get_ident()}")
        self.candidate_id = candidate_id or ""
        self.purpose = self._safe_id(purpose)
        self.disabled_providers = frozenset(disabled_providers or ())
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    @staticmethod
    def _safe_id(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 200:
            raise ValueError("BUDGET_ID_INVALID")
        return value

    def _acquire(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        while True:
            try:
                descriptor = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(descriptor, f"pid={os.getpid()}".encode("ascii"))
                return descriptor
            except (FileExistsError, PermissionError):
                if not self.lock_path.exists():
                    time.sleep(0.001)
                    continue
                try:
                    age = time.time() - self.lock_path.stat().st_mtime
                    if age > 120:
                        self.lock_path.unlink()
                        continue
                except OSError:
                    age = 0
                if time.monotonic() - started >= 5:
                    raise BudgetLockError("BUDGET_LOCK_TIMEOUT")
                time.sleep(0.01)

    def _release(self, descriptor: int) -> None:
        os.close(descriptor)
        try:
            self.lock_path.unlink()
        except FileNotFoundError:
            return

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "entries": {}, "runs": {}, "candidates": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            quarantine = self.path.with_name(self.path.name + ".corrupt")
            try:
                os.replace(self.path, quarantine)
            except OSError:
                return {"schema_version": 1, "entries": {}, "runs": {}, "candidates": {}}
            return {"schema_version": 1, "entries": {}, "runs": {}, "candidates": {}}
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("BUDGET_LEDGER_SCHEMA_INVALID")
        for key in ("entries", "runs", "candidates"):
            if not isinstance(value.get(key), dict):
                raise ValueError("BUDGET_LEDGER_SCHEMA_INVALID")
        return value

    def _write(self, value: Mapping[str, Any]) -> None:
        temporary = self.path.with_name(self.path.name + f".{os.getpid()}.{get_ident()}.tmp")
        temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
        try:
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _counter(value: Any, day: str) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("day") != day:
            return _new_counter()
        result = _new_counter()
        result["input_tokens"] = int(value.get("input_tokens", 0))
        result["output_tokens"] = int(value.get("output_tokens", 0))
        result["cost"] = str(decimal_cost(value.get("cost", "0")))
        result["day"] = day
        return result

    def _result(
        self,
        allowed: bool,
        reason: str,
        provider_id: str,
        purpose: str,
        input_tokens: int,
        output_tokens: int,
        cost: Decimal,
        run: Mapping[str, Any],
        day: Mapping[str, Any],
        candidate: Mapping[str, Any],
        remaining: Mapping[str, Any] | None = None,
    ) -> BudgetResult:
        return BudgetResult(
            allowed,
            reason,
            provider_id,
            purpose,
            input_tokens,
            output_tokens,
            cost,
            int(run.get("input_tokens", 0)),
            int(day.get("input_tokens", 0)),
            int(candidate.get("input_tokens", 0)),
            Decimal(str(run.get("cost", "0"))),
            Decimal(str(day.get("cost", "0"))),
            Decimal(str(candidate.get("cost", "0"))),
            remaining=remaining or {},
        )

    def consume(
        self,
        provider_id: str,
        input_tokens: int,
        output_tokens: int,
        cost: Decimal,
        now: datetime,
        *,
        purpose: str | None = None,
        candidate_id: str | None = None,
        run_id: str | None = None,
        deadline_ms: int | None = None,
    ) -> BudgetResult:
        if not isinstance(provider_id, str) or not provider_id or len(provider_id) > 100:
            raise ValueError("PROVIDER_ID_INVALID")
        if type(input_tokens) is not int or input_tokens < 0 or type(output_tokens) is not int or output_tokens < 0:
            raise ValueError("TOKEN_COUNT_INVALID")
        moment = require_aware(now)
        amount = decimal_cost(cost)
        selected_purpose = self._safe_id(purpose or self.purpose)
        selected_run = self._safe_id(run_id or self.run_id)
        selected_candidate = candidate_id if candidate_id is not None else self.candidate_id
        if not isinstance(selected_candidate, str) or len(selected_candidate) > 200:
            raise ValueError("BUDGET_CANDIDATE_INVALID")
        day_key = _utc_day(moment)
        if provider_id in self.disabled_providers:
            empty = _new_counter()
            return self._result(False, "PROVIDER_DISABLED", provider_id, selected_purpose, input_tokens, output_tokens, amount, empty, empty, empty)
        if deadline_ms is not None and (type(deadline_ms) is not int or deadline_ms <= 0):
            empty = _new_counter()
            return self._result(False, "DEADLINE_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, empty, empty, empty)

        descriptor = self._acquire()
        try:
            data = self._read()
            entry_key = f"{provider_id}|{day_key}|{selected_purpose}"
            entry = self._counter(data["entries"].get(entry_key), day_key)
            run_key = f"{selected_run}|{provider_id}|{selected_purpose}"
            run = self._counter(data["runs"].get(run_key), day_key)
            candidate_key = hashlib.sha256((selected_candidate or "<none>").encode("utf-8", "replace")).hexdigest()
            candidate = self._counter(data["candidates"].get(candidate_key), day_key)
            next_run = dict(run)
            next_day = dict(entry)
            next_candidate = dict(candidate)
            _add(next_run, input_tokens, output_tokens, amount, day_key)
            _add(next_day, input_tokens, output_tokens, amount, day_key)
            _add(next_candidate, input_tokens, output_tokens, amount, day_key)
            policy = self.policy
            if next_run["input_tokens"] > policy.per_run_input_tokens or next_run["output_tokens"] > policy.per_run_output_tokens:
                return self._result(False, "TOKEN_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_run"})
            if next_day["input_tokens"] > policy.per_day_input_tokens or next_day["output_tokens"] > policy.per_day_output_tokens:
                return self._result(False, "TOKEN_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_day"})
            if next_candidate["input_tokens"] > policy.per_candidate_input_tokens or next_candidate["output_tokens"] > policy.per_candidate_output_tokens:
                return self._result(False, "TOKEN_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_candidate"})
            if Decimal(next_run["cost"]) > policy.per_run_cost:
                return self._result(False, "COST_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_run"})
            if Decimal(next_day["cost"]) > policy.per_day_cost:
                return self._result(False, "COST_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_day"})
            if Decimal(next_candidate["cost"]) > policy.per_candidate_cost:
                return self._result(False, "COST_CAP_EXCEEDED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "per_candidate"})
            if provider_id == "cloud-api" and (not policy.cloud_api_enabled or amount > policy.cloud_spend_cap or Decimal(next_day["cost"]) > policy.cloud_spend_cap):
                return self._result(False, "PROVIDER_DISABLED", provider_id, selected_purpose, input_tokens, output_tokens, amount, run, entry, candidate, {"scope": "cloud_api"})
            data["entries"][entry_key] = next_day
            data["runs"][run_key] = next_run
            data["candidates"][candidate_key] = next_candidate
            self._write(data)
            remaining = {
                "per_run_input_tokens": max(0, policy.per_run_input_tokens - int(next_run["input_tokens"])),
                "per_day_input_tokens": max(0, policy.per_day_input_tokens - int(next_day["input_tokens"])),
                "per_candidate_input_tokens": max(0, policy.per_candidate_input_tokens - int(next_candidate["input_tokens"])),
            }
            return self._result(True, "ALLOW", provider_id, selected_purpose, input_tokens, output_tokens, amount, next_run, next_day, next_candidate, remaining)
        finally:
            self._release(descriptor)

    def snapshot(self) -> Mapping[str, Any]:
        descriptor = self._acquire()
        try:
            return self._read()
        finally:
            self._release(descriptor)


__all__ = ["BACKOFF_SECONDS", "BudgetLedger", "BudgetLockError", "BudgetPolicy", "BudgetResult", "DEFAULT_BACKOFF_SECONDS"]