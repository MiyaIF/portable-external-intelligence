from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from pathlib import Path
from typing import Callable, Any

from .inference.base import require_aware
from .inference.budget import BudgetLedger
from .gate import GateDecision
from .changeset import ChangeSet
from .ids import stable_hash
from .spool import read_spool, write_spool


def _capture_binding(item: Any) -> str:
    return item.capture_id or "sha256:" + stable_hash({"queue_id": item.queue_id})


def save_validated_result(item: Any, candidate: dict, provider_id: str, decision: GateDecision,
                          changeset: ChangeSet | None, settings: Any, now: datetime, *, budget=None):
    if budget is not None:
        budget.check()
    expiry = datetime.fromisoformat(item.payload_ref.expires_at if item.payload_ref else item.created_at)
    if item.payload_ref is None:
        expiry += timedelta(days=30)
    ttl = int((require_aware(expiry) - require_aware(now)).total_seconds())
    if ttl <= 0:
        raise ValueError("VALIDATED_RESULT_EXPIRED")
    content = {"schema_version": 1, "schema_name": "organizer-validated-result", "provider_id": provider_id,
        "capture_id": _capture_binding(item), "source_hash": item.source_hash,
        "candidate_hash": stable_hash(candidate), "gate": decision.to_dict(),
        "changeset": changeset.to_dict() if changeset else None}
    return write_spool(content, item.privacy_classification, settings, now=now, ttl_seconds=ttl,
        purpose="validated-result", capture_id=_capture_binding(item), spool_id="result_" + stable_hash(content), budget=budget)


def load_validated_result(item: Any, candidate: dict, provider_id: str, settings: Any, now: datetime, *, budget=None):
    if budget is not None:
        budget.check()
    ref = item.validated_result_ref
    if ref is None:
        return None
    if ref.purpose != "validated-result" or item.payload_ref and datetime.fromisoformat(ref.expires_at) > datetime.fromisoformat(item.payload_ref.expires_at):
        raise ValueError("VALIDATED_RESULT_BINDING_INVALID")
    content = json.loads(read_spool(ref, settings, now=now, expected_capture_id=_capture_binding(item), budget=budget))
    if budget is not None:
        budget.check()
    expected = {"schema_version": 1, "schema_name": "organizer-validated-result", "provider_id": provider_id,
        "capture_id": _capture_binding(item), "source_hash": item.source_hash, "candidate_hash": stable_hash(candidate)}
    if any(content.get(key) != value for key, value in expected.items()):
        raise ValueError("VALIDATED_RESULT_BINDING_INVALID")
    gate = GateDecision.from_mapping(content["gate"], source_host_id=item.source_host_id, source_host_family=item.source_host_family)
    changeset = ChangeSet.from_mapping(content["changeset"]) if content["changeset"] is not None else None
    if gate.decision == "YES" and (changeset is None or changeset.provider_id != gate.provider_id):
        raise ValueError("VALIDATED_RESULT_BINDING_INVALID")
    return gate, changeset


def next_retry(now: datetime, attempt: int, provider_deadline: datetime | None = None) -> datetime:
    now = require_aware(now)
    if type(attempt) is not int or attempt < 1:
        raise ValueError("RETRY_ATTEMPT_INVALID")
    due = now + timedelta(seconds=(300, 900, 3600, 21600)[min(attempt - 1, 3)])
    return max(due, require_aware(provider_deadline)) if provider_deadline else due


class OrganizerRecovery:
    """Durable, sanitized hold state for one organizer, shared by its queue."""

    def __init__(self, path: Path, provider_id: str, *, malformed_limit: int = 3, config_fingerprint: str = "", operation_budget=None) -> None:
        self.storage = BudgetLedger(path, operation_budget=operation_budget)
        self.provider_id = provider_id
        self.malformed_limit = malformed_limit
        self.config_fingerprint = config_fingerprint

    def _read(self) -> dict[str, Any]:
        self.storage._check_operation_budget()
        if not self.storage.path.exists():
            return {"schema_version": 1, "provider_id": self.provider_id, "attempts": 0,
                "malformed_attempts": 0, "needs_action": False, "reason_code": "READY",
                "next_eligible_at": None, "config_fingerprint": self.config_fingerprint,
                "retry_request": None, "retry_consumed": False}
        try:
            with self.storage.path.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError()
            self.storage._check_operation_budget()
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError()
            if value["schema_version"] != 1 or value["provider_id"] != self.provider_id:
                raise ValueError()
            value.setdefault("retry_request", None)
            value.setdefault("retry_consumed", False)
            value.setdefault("config_fingerprint", "")
            if type(value["needs_action"]) is not bool or any(type(value[key]) is not int or value[key] < 0 for key in ("attempts", "malformed_attempts")):
                raise ValueError()
            if type(value["retry_consumed"]) is not bool:
                raise ValueError()
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", value["reason_code"]):
                raise ValueError()
            if value["config_fingerprint"] != "" and not re.fullmatch(r"sha256:[a-f0-9]{64}", value["config_fingerprint"]):
                raise ValueError()
            if value["next_eligible_at"] is not None:
                require_aware(datetime.fromisoformat(value["next_eligible_at"]))
            request = value["retry_request"]
            if request is not None:
                if (not isinstance(request, dict) or set(request) != {"provider_id", "requested_at", "config_fingerprint"}
                        or request["provider_id"] != self.provider_id
                        or not isinstance(request["requested_at"], str)
                        or type(request["config_fingerprint"]) is not str
                        or (request["config_fingerprint"] != "" and not re.fullmatch(r"sha256:[a-f0-9]{64}", request["config_fingerprint"]))
                        or request["config_fingerprint"] != value["config_fingerprint"]):
                    raise ValueError()
                require_aware(datetime.fromisoformat(request["requested_at"]))
            return value
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("ORGANIZER_STATE_INVALID") from exc

    def _retry_result(self, status: str, reason_code: str, state: dict[str, Any]) -> dict[str, Any]:
        return {"status": status, "reason_code": reason_code, "provider_id": self.provider_id,
            "next_eligible_at": state.get("next_eligible_at")}

    def _retry_request_result(self, state: dict[str, Any], provider: Any, now: datetime,
                              config_fingerprint: str | None, *, persist: bool) -> dict[str, Any]:
        if getattr(provider, "provider_id", None) != self.provider_id:
            return self._retry_result("UNAVAILABLE", "ORGANIZER_PROVIDER_MISMATCH", state)
        if getattr(provider, "enabled", None) is False:
            return self._retry_result("DISABLED", "PROVIDER_DISABLED", state)
        if config_fingerprint is not None and (type(config_fingerprint) is not str or
                not re.fullmatch(r"sha256:[a-f0-9]{64}", config_fingerprint)):
            return self._retry_result("UNAVAILABLE", "ORGANIZER_BINDING_INVALID", state)
        saved_fingerprint = state["config_fingerprint"]
        if saved_fingerprint and config_fingerprint is None:
            return self._retry_result("UNAVAILABLE", "ORGANIZER_BINDING_UNAVAILABLE", state)
        if config_fingerprint is not None and saved_fingerprint and config_fingerprint != saved_fingerprint:
            return self._retry_result("UNAVAILABLE", "ORGANIZER_BINDING_MISMATCH", state)
        binding = config_fingerprint if config_fingerprint is not None else saved_fingerprint
        if state["retry_request"] is not None:
            if config_fingerprint is not None and state["retry_request"]["config_fingerprint"] != config_fingerprint:
                return self._retry_result("UNAVAILABLE", "ORGANIZER_BINDING_MISMATCH", state)
            return self._retry_result("ALREADY_REQUESTED", "AUTH_RETRY_ALREADY_REQUESTED", state)
        eligible = state["needs_action"] and (state["reason_code"] == "AUTH_FAILED" or state["retry_consumed"])
        if not eligible:
            reason = "ORGANIZER_READY" if not state["needs_action"] else "AUTH_RETRY_NOT_APPLICABLE"
            return self._retry_result("NO_ACTION", reason, state)
        request = {"provider_id": self.provider_id,
            "requested_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "config_fingerprint": binding}
        if persist:
            state["retry_request"] = request
            if binding and not saved_fingerprint:
                # Learning the first binding is not recovery: needs_action and
                # the original deadline/counters remain unchanged.
                state["config_fingerprint"] = binding
                self.config_fingerprint = binding
            self.storage._write(state)
        return self._retry_result("RETRY_REQUESTED", "AUTH_RETRY_REQUESTED", state)

    def request_auth_retry(self, provider: Any, *, now: datetime,
                           config_fingerprint: str | None = None) -> dict[str, Any]:
        moment = require_aware(now)
        try:
            lock = self.storage._acquire()
        except (OSError, RuntimeError, ValueError):
            return {"status": "UNAVAILABLE", "reason_code": "ORGANIZER_STATE_UNAVAILABLE",
                "provider_id": self.provider_id, "next_eligible_at": None}
        try:
            state = self._read()
            return self._retry_request_result(state, provider, moment, config_fingerprint, persist=True)
        except (OSError, RuntimeError):
            return {"status": "UNAVAILABLE", "reason_code": "ORGANIZER_STATE_UNAVAILABLE",
                "provider_id": self.provider_id, "next_eligible_at": None}
        except ValueError as exc:
            reason = "ORGANIZER_STATE_INVALID" if str(exc) == "ORGANIZER_STATE_INVALID" else "ORGANIZER_BINDING_INVALID"
            return {"status": "UNAVAILABLE", "reason_code": reason,
                "provider_id": self.provider_id, "next_eligible_at": None}
        finally:
            self.storage._release(lock)

    def preview_auth_retry(self, provider: Any, *, now: datetime,
                           config_fingerprint: str | None = None) -> dict[str, Any]:
        """Read-only dry-run view; it never creates a lock or writes state."""
        moment = require_aware(now)
        try:
            state = self._read()
            return self._retry_request_result(state, provider, moment, config_fingerprint, persist=False)
        except (OSError, RuntimeError, ValueError):
            return {"status": "UNAVAILABLE", "reason_code": "ORGANIZER_STATE_UNAVAILABLE",
                "provider_id": self.provider_id, "next_eligible_at": None}

    def snapshot(self) -> dict[str, Any]:
        lock = self.storage._acquire()
        try:
            return self._read()
        finally:
            self.storage._release(lock)

    def run(self, operation: Callable[[], GateDecision], now: datetime, *,
            admission_refused: Callable[[], bool] | None = None,
            retry_provider: Any | None = None) -> GateDecision:
        moment = require_aware(now)
        lock = self.storage._acquire()
        try:
            state = self._read()
            due = datetime.fromisoformat(state["next_eligible_at"]) if state["next_eligible_at"] else None
            retry_attempt = False
            if state["needs_action"]:
                request = state["retry_request"]
                same_provider = retry_provider is not None and getattr(retry_provider, "provider_id", None) == self.provider_id
                enabled = same_provider and getattr(retry_provider, "enabled", None) is not False
                same_binding = (not state["config_fingerprint"] and not self.config_fingerprint) or (
                    bool(state["config_fingerprint"]) and self.config_fingerprint == state["config_fingerprint"])
                eligible = state["reason_code"] == "AUTH_FAILED" or state["retry_consumed"]
                if request is None or not enabled or not same_binding or not eligible:
                    return GateDecision("DEFERRED", state["reason_code"], provider_id=self.provider_id,
                        next_eligible_at=due if request is not None else max(due or moment, next_retry(moment, 4)))
                if due is not None and due > moment:
                    return GateDecision("DEFERRED", state["reason_code"], provider_id=self.provider_id,
                        next_eligible_at=due)
                retry_attempt = True
            elif due is not None and due > moment:
                return GateDecision("DEFERRED", state["reason_code"], provider_id=self.provider_id,
                    next_eligible_at=due)
            previous = dict(state)
            state["attempts"] += 1
            if retry_attempt:
                state["retry_request"] = None
                state["retry_consumed"] = True
            # Persist the cooldown before invoking the provider. A terminated
            # process cannot leave a free, immediately repeatable probe.
            state.update(reason_code="PROVIDER_INTERRUPTED", next_eligible_at=next_retry(moment, state["attempts"]).isoformat())
            self.storage._write(state)
            self.storage._check_operation_budget()
            if retry_attempt and self.provider_id == "subscription-cli":
                repair = getattr(retry_provider, "repair_auth", None)
                if callable(repair):
                    repair()
            result = operation()
            if not result.semantic and admission_refused is not None and admission_refused() is True:
                # A completed, router-proven refusal is not a provider fault.
                # Restore prior history, never clear it. A crash, exception or
                # failed restoration retains the durable interruption hold.
                self.storage._write(previous)
                return result
            if result.semantic:
                state.update(attempts=0, malformed_attempts=0, needs_action=False, reason_code="READY", next_eligible_at=None,
                    retry_request=None, retry_consumed=False)
            else:
                reason = result.reason_code
                if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", reason):
                    reason = "PROVIDER_FAILED"
                state["reason_code"] = reason
                state["malformed_attempts"] += reason == "MALFORMED_RESPONSE"
                state["needs_action"] = (retry_attempt or reason == "AUTH_FAILED" or state["malformed_attempts"] >= self.malformed_limit)
                if not state["needs_action"]:
                    state["retry_consumed"] = False
                deadline = result.next_eligible_at
                if result.retry_after_seconds is not None:
                    deadline = max(deadline or moment, moment + timedelta(seconds=result.retry_after_seconds))
                state["next_eligible_at"] = next_retry(moment, state["attempts"], deadline).isoformat()
            self.storage._write(state)
            if result.semantic:
                return result
            from dataclasses import replace
            return replace(result, next_eligible_at=datetime.fromisoformat(state["next_eligible_at"]))
        finally:
            self.storage._release(lock)

    def recover(self, provider: Any, *, verified_auth: bool = False, config_fingerprint: str | None = None) -> bool:
        """Trusted caller supplies verified same-provider evidence, never a candidate."""
        if getattr(provider, "provider_id", None) != self.provider_id:
            raise ValueError("ORGANIZER_RECOVERY_PROVIDER_MISMATCH")
        if type(verified_auth) is not bool:
            raise ValueError("ORGANIZER_RECOVERY_EVIDENCE_INVALID")
        if config_fingerprint is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", config_fingerprint):
            raise ValueError("ORGANIZER_RECOVERY_EVIDENCE_INVALID")
        lock = self.storage._acquire()
        try:
            state = self._read()
            # Learning a first trusted value is a baseline, not evidence of a
            # change or repair. In particular it must not release an old hold.
            changed = bool(state["config_fingerprint"]) and config_fingerprint is not None and config_fingerprint != state["config_fingerprint"]
            if not verified_auth and not changed:
                if config_fingerprint is not None and not state["config_fingerprint"]:
                    state["config_fingerprint"] = config_fingerprint
                    self.storage._write(state)
                    self.config_fingerprint = config_fingerprint
                return False
            # repair_auth only clears this adapter's local latch; it never
            # logs in, changes credentials, or overrides its enabled setting.
            repair = getattr(provider, "repair_auth", None)
            if self.provider_id == "subscription-cli" and callable(repair):
                self.storage._check_operation_budget()
                repair()
            state.update(needs_action=False, next_eligible_at=None, attempts=0, malformed_attempts=0,
                reason_code="AUTH_VERIFIED" if verified_auth else "CONFIG_CHANGED_RETRY",
                retry_request=None, retry_consumed=False)
            if config_fingerprint is not None:
                state["config_fingerprint"] = config_fingerprint
                self.config_fingerprint = config_fingerprint
            self.storage._write(state)
            return True
        finally:
            self.storage._release(lock)
