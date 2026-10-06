"""Shared legacy and adapter-trusted closeout processing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping
from uuid import uuid4

from .changeset import apply_changeset, validate_changeset
from .ids import fingerprint, machine_id, stable_hash
from .index import build_index
from .inference.router import ProviderSelectionError
from .journal import append_event
from .models import Event, ObservationInput, validate_host_label
from .privacy import inspect_observation


EXIT_OK = 0
EXIT_INPUT = 2
EXIT_PRIVACY = 3
EXIT_DEPENDENCY = 5
EXIT_INTERNAL = 6

if TYPE_CHECKING:
    from .closeout_context import ContextValidation
    from .operation_runtime import OperationBudget


@dataclass(frozen=True)
class CloseoutResult:
    payload: dict[str, Any]
    exit_code: int


class InputError(ValueError):
    """Raised for invalid closeout input or schema."""


class PrivacyRejected(ValueError):
    """Raised when closeout input cannot cross the privacy boundary."""


def _error_code(exc: BaseException, fallback: str = "INTERNAL_ERROR") -> str:
    text = str(exc or "")
    candidate = text.split(":", 1)[0].strip()
    return candidate if re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", candidate) else fallback


def _event_audit(
    settings: Any,
    decision: Any,
    candidate: Mapping[str, Any],
    *,
    trusted_record_hash: str | None = None,
    semantic_content_hash: str | None = None,
    unique_attempt: bool = False,
) -> None:
    payload = {
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "provider_id": decision.provider_id or "unknown",
        "classification": decision.classification,
        "evidence_count": len(decision.evidence_refs),
        "candidate_id_hash": fingerprint(
            str(candidate.get("candidate_id", candidate.get("title", "candidate")))
        ),
    }
    if decision.source_host_id and decision.source_host_family:
        payload.update(
            {
                "source_host_id": decision.source_host_id,
                "source_host_family": decision.source_host_family,
                "applicability_scope": decision.applicability_scope,
                "applicable_host_ids": list(decision.applicable_host_ids),
                "applicable_host_families": list(decision.applicable_host_families),
            }
        )
    if unique_attempt:
        event_id = "evt_gate_" + uuid4().hex
    elif trusted_record_hash is not None and semantic_content_hash is not None:
        event_id = "evt_gate_" + stable_hash({
            "domain": "ei-trusted-closeout-audit-v1",
            "audit": payload,
            "record_hash": trusted_record_hash,
            "content_hash": semantic_content_hash,
        })[:32]
    else:
        event_id = "evt_gate_" + stable_hash(payload)[:32]
    event = Event.create(
        "gate.decision",
        datetime.now(timezone.utc).isoformat(),
        "external-intelligence",
        machine_id(),
        payload,
        event_id=event_id,
    )
    append_event(event, settings.paths.event_dir)


def _closeout_source_pair(candidate: Mapping[str, Any], *, required: bool) -> tuple[str, str]:
    source_host_id = candidate.get("source_host_id", "")
    source_host_family = candidate.get("source_host_family", "")
    if not isinstance(source_host_id, str) or not isinstance(source_host_family, str):
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID")
    if bool(source_host_id) != bool(source_host_family):
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID")
    if not source_host_id and not source_host_family:
        if required:
            raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_REQUIRED")
        return "", ""
    try:
        validate_host_label(source_host_id, field="source_host_id")
        validate_host_label(source_host_family, field="source_host_family")
    except ValueError as exc:
        raise InputError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID") from exc
    return source_host_id, source_host_family


def _association(status: str, reason_code: str, acknowledged: bool = False) -> dict[str, Any]:
    return {"status": status, "reason_code": reason_code, "acknowledged": acknowledged}


def _context_association(validation: Any | None) -> dict[str, Any]:
    reason = getattr(validation, "reason_code", "CLOSEOUT_CONTEXT_UNVERIFIED")
    if not isinstance(reason, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason):
        reason = "CLOSEOUT_CONTEXT_UNVERIFIED"
    return _association("UNKNOWN", reason)


def _index(settings: Any, *, budget=None):
    knowledge = Path(settings.paths.knowledge_dir)
    index_path = knowledge / "index.json"
    if not index_path.is_file():
        return None
    return build_index(knowledge, index_path, budget=budget)


_CANDIDATE_SEMANTIC_FIELDS = (
    "candidate_id", "title", "claim", "rule", "precondition", "failure_mode",
    "benefit", "classification", "evidence_refs", "evidence_ids", "provenances",
    "provenance_refs", "scopes", "scope", "applicability", "scope_tags", "domain",
    "source_ref", "source_kind", "cwd", "cwd_fingerprint", "outcome_status",
    "version_constraint", "exception", "exceptions", "source_host_id",
    "source_host_family", "applicability_scope", "applicable_host_ids",
    "applicable_host_families",
)
_GATE_SEMANTIC_FIELDS = (
    "decision", "reason_code", "candidate_title", "candidate_claim", "evidence_refs",
    "benefit", "classification", "confidence", "provider_id", "source_host_id",
    "source_host_family", "applicability_scope", "applicable_host_ids",
    "applicable_host_families",
)


def _content_hash(candidate: Mapping[str, Any], decision: Any) -> str:
    candidate_values = {name: candidate[name] for name in _CANDIDATE_SEMANTIC_FIELDS if name in candidate}
    gate = decision.to_dict()
    gate_values = {name: gate[name] for name in _GATE_SEMANTIC_FIELDS if name in gate}
    return fingerprint({
        "domain": "ei-trusted-closeout-content-v1",
        "candidate": candidate_values,
        "gate": gate_values,
    })


def _candidate_id(candidate: Mapping[str, Any], content_hash: str) -> str:
    value = candidate.get("candidate_id")
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        return value
    return "cand_" + stable_hash({"content_hash": content_hash})[:20]


def _curator_input(candidate: Mapping[str, Any], decision: Any) -> dict[str, Any]:
    return {
        **candidate,
        "decision": "YES",
        "title": decision.candidate_title,
        "claim": decision.candidate_claim,
        "candidate_title": decision.candidate_title,
        "candidate_claim": decision.candidate_claim,
        "benefit": decision.benefit,
        "classification": decision.classification,
        "evidence_refs": list(decision.evidence_refs),
        "source_host_id": decision.source_host_id,
        "source_host_family": decision.source_host_family,
        "applicability_scope": decision.applicability_scope,
        "applicable_host_ids": list(decision.applicable_host_ids),
        "applicable_host_families": list(decision.applicable_host_families),
    }


def _team_result(settings: Any, *, applied: bool, changeset: Any, event_ids: tuple[str, ...], candidate: Mapping[str, Any]) -> dict[str, Any]:
    team_store = getattr(getattr(settings, "knowledge_stores", None), "team", None)
    if team_store is None:
        return {"status": "DISABLED", "reason_code": "TEAM_DISABLED"}
    if not applied:
        return {"status": "SKIPPED", "reason_code": "PERSONAL_APPLY_NOT_SUCCESS"}
    from .team_routing import route_applied_personal_knowledge

    change_hash = getattr(changeset, "fingerprint", None)
    routed = route_applied_personal_knowledge(
        {
            "applied": True,
            "changeset_hash": change_hash,
            "event_ids": list(event_ids),
            "candidate": candidate,
            **({"changeset": changeset.to_dict()} if changeset is not None else {}),
        },
        settings,
    )
    return routed.to_dict()


def _legacy_payload(decision: Any, candidate: Mapping[str, Any], settings: Any, *, validation: Any | None) -> CloseoutResult:
    if decision.decision == "NO":
        team = _team_result(settings, applied=False, changeset=None, event_ids=(), candidate=candidate)
        return CloseoutResult({
            "status": "discarded",
            "gate": decision.to_dict(),
            "curation": {"status": "not_run"},
            "personal": {"status": "DISCARDED"},
            "team": team,
            "knowledge_stores": {"personal": {"status": "DISCARDED"}, "team": team},
            "knowledge": "DISCARDED",
            "association": _context_association(validation),
        }, EXIT_OK)
    if decision.decision == "DEFERRED":
        team = {"status": "DISABLED", "reason_code": "TEAM_DISABLED"} if getattr(getattr(settings, "knowledge_stores", None), "team", None) is None else {"status": "DEFERRED", "reason_code": "DEFERRED_TEAM_STORE"}
        return CloseoutResult({
            "status": "deferred", "gate": decision.to_dict(),
            "personal": {"status": "DEFERRED"}, "team": team,
            "knowledge_stores": {"personal": {"status": "DEFERRED"}, "team": team},
            "knowledge": "DEFERRED",
            "association": _association("PENDING", "CLOSEOUT_EVALUATION_DEFERRED") if validation is not None and getattr(validation, "valid", False) else _context_association(validation),
        }, EXIT_DEPENDENCY)
    if decision.decision == "FAILED":
        team = _team_result(settings, applied=False, changeset=None, event_ids=(), candidate=candidate)
        retryable = {"NO_PROVIDER_AVAILABLE", "PROVIDER_UNAVAILABLE", "QUOTA_EXHAUSTED"}
        exit_code = EXIT_DEPENDENCY if decision.reason_code in retryable else EXIT_INTERNAL
        return CloseoutResult({
            "status": "failed", "gate": decision.to_dict(),
            "personal": {"status": "FAILED"}, "team": team,
            "knowledge_stores": {"personal": {"status": "FAILED"}, "team": team},
            "knowledge": "FAILED",
            "association": _association("PENDING", "CLOSEOUT_EVALUATION_FAILED") if validation is not None and getattr(validation, "valid", False) else _context_association(validation),
        }, exit_code)
    raise ValueError("CLOSEOUT_DECISION_INVALID")


def _prepare_yes(candidate: Mapping[str, Any], decision: Any, settings: Any, *, budget=None):
    from .curator import curate_candidate

    curator_input = _curator_input(candidate, decision)
    changeset = curate_candidate(
        curator_input,
        _index(settings, budget=budget),
        {"provider_id": decision.provider_id or "manual-structured"},
        None,
        operation_budget=budget,
    )
    result = validate_changeset(changeset, settings, budget=budget)
    if not result.valid:
        code = result.reason_codes[0] if result.reason_codes else "CHANGESET_INVALID"
        if code in {"RAW_CONTENT_FORBIDDEN", "PRIVACY_REJECTED"}:
            raise PrivacyRejected(code)
        raise InputError(code)
    return changeset, curator_input


def _associated_payload(decision: Any, candidate: Mapping[str, Any], settings: Any, validation: Any,
                        content_hash: str, *, now: datetime, budget, changeset=None) -> CloseoutResult:
    from .closeout_association import PreparedCloseout, apply_associated_closeout

    context = getattr(validation, "context", None)
    identity = getattr(context, "identity", None)
    record_hash = getattr(identity, "record_hash", None)
    if not isinstance(record_hash, str):
        return CloseoutResult({
            "ok": False,
            "error_code": "CLOSEOUT_CONTEXT_UNVERIFIED",
            "knowledge": "UNKNOWN",
            "association": _association("UNKNOWN", "CLOSEOUT_CONTEXT_UNVERIFIED"),
        }, EXIT_DEPENDENCY)

    def audit_initial_prepare(holder: dict[str, Any]) -> None:
        try:
            _event_audit(
                settings,
                decision,
                candidate,
                trusted_record_hash=record_hash,
                semantic_content_hash=content_hash,
            )
        except TimeoutError:
            raise
        except Exception:
            holder["prepare_error"] = "CLOSEOUT_AUDIT_FAILED"
            raise

    if decision.decision == "NO":
        prepared_candidate_id = _candidate_id(candidate, content_hash)

        def prepare():
            audit_initial_prepare(holder)
            from .team_routing import noneligible_team_routing
            team_prepared = noneligible_team_routing("PERSONAL_APPLY_NOT_SUCCESS", settings, now=now)
            return PreparedCloseout(prepared_candidate_id, content_hash, "NO", None, team_prepared)

        holder: dict[str, Any] = {}
    else:
        holder = {}

        def prepare():
            audit_initial_prepare(holder)
            try:
                selected, curated = _prepare_yes(candidate, decision, settings, budget=budget)
            except (InputError, PrivacyRejected) as exc:
                holder["prepare_error"] = _error_code(exc, "CLOSEOUT_PREPARE_REJECTED")
                raise
            from .team_routing import prepare_team_routing
            team_prepared = prepare_team_routing(
                curated,
                settings,
                now=now,
                operation_budget=budget,
            )
            holder["changeset"] = selected
            holder["curator_input"] = curated
            holder["team_prepared"] = team_prepared
            return PreparedCloseout(selected.candidate_id, content_hash, "YES", selected, team_prepared)

    result = apply_associated_closeout(
        settings,
        validation,
        content_hash=content_hash,
        prepare=prepare,
        now=now,
        budget=budget,
    )
    reason = holder.get("prepare_error", result.reason_code)
    association = _association(result.association, reason, result.acknowledged)
    selected_changeset = holder.get("changeset") or changeset
    applied = result.knowledge == "APPLIED"
    if decision.decision == "NO":
        team = dict(result.team_result) if isinstance(result.team_result, Mapping) else {
            "status": "UNKNOWN", "reason_code": "TEAM_RESULT_UNKNOWN"
        }
        payload = {
            "status": "discarded",
            "gate": decision.to_dict(),
            "curation": {"status": "not_run"},
            "personal": {"status": "DISCARDED"},
            "team": team,
            "knowledge_stores": {"personal": {"status": "DISCARDED"}, "team": team},
            "knowledge": result.knowledge,
            "association": association,
        }
        return CloseoutResult(payload, EXIT_OK if result.acknowledged else EXIT_INTERNAL)

    curated = holder.get("curator_input") or _curator_input(candidate, decision)
    team = dict(result.team_result) if isinstance(result.team_result, Mapping) else {
        "status": "PENDING" if applied else "UNKNOWN",
        "reason_code": "TEAM_RESULT_UNKNOWN",
    }
    curation: dict[str, Any] = {
        "applied": applied,
        "reason_code": reason,
        "event_ids": list(result.event_ids),
        "already_applied": result.knowledge == "APPLIED" and not bool(holder.get("changeset")),
    }
    if selected_changeset is not None:
        curation["changeset"] = selected_changeset.to_dict()
    payload = {
        "status": "applied" if applied else "failed",
        "gate": decision.to_dict(),
        "curation": curation,
        "personal": {"status": "READY" if applied else "FAILED", "reason_code": reason},
        "team": team,
        "knowledge_stores": {"personal": {"status": "READY" if applied else "FAILED"}, "team": team},
        "knowledge": result.knowledge,
        "association": association,
    }
    return CloseoutResult(
        payload,
        EXIT_OK if result.acknowledged else EXIT_DEPENDENCY if applied else EXIT_INTERNAL,
    )


def process_closeout(payload: Mapping[str, Any], settings: Any, *, validation: ContextValidation | None = None,
                     now: datetime | None = None, budget: OperationBudget | None = None) -> CloseoutResult:
    """Evaluate and apply one closeout, optionally binding it to adapter targets."""
    if budget is not None:
        budget.check()
    if not isinstance(payload, Mapping):
        raise InputError("CLOSEOUT_OBJECT_REQUIRED")
    nested_candidate = payload.get("candidate")
    if nested_candidate is not None and not isinstance(nested_candidate, Mapping):
        raise InputError("CLOSEOUT_CANDIDATE_OBJECT_REQUIRED")
    candidate = {
        str(key): value
        for key, value in (nested_candidate if isinstance(nested_candidate, Mapping) else payload).items()
        if isinstance(key, str)
    }
    gate_input = payload.get("gate_decision") if isinstance(payload.get("gate_decision"), Mapping) else candidate
    trusted_entry = validation is not None
    try:
        if isinstance(gate_input, Mapping) and isinstance(payload.get("gate_decision"), Mapping):
            from .gate import GateDecision
            source_host_id, source_host_family = _closeout_source_pair(
                candidate, required=gate_input.get("decision") == "YES"
            )
            decision = GateDecision.from_mapping(
                gate_input,
                source_host_id=source_host_id,
                source_host_family=source_host_family,
            )
        elif candidate.get("decision") in {"YES", "NO"}:
            from .gate import GateDecision
            source_host_id, source_host_family = _closeout_source_pair(
                candidate, required=candidate.get("decision") == "YES"
            )
            decision = GateDecision.from_mapping(
                candidate,
                source_host_id=source_host_id,
                source_host_family=source_host_family,
            )
        elif trusted_entry:
            return CloseoutResult({
                "ok": False,
                "error_code": "CLOSEOUT_EVALUATION_REQUIRED",
                "knowledge": "UNKNOWN",
                "association": _association(
                    "UNKNOWN" if not getattr(validation, "valid", False) else "PENDING",
                    "CLOSEOUT_EVALUATION_REQUIRED" if getattr(validation, "valid", False) else _context_association(validation)["reason_code"],
                ),
            }, EXIT_DEPENDENCY)
        else:
            from .gate import decide_inheritance
            from .inference.base import InferenceBudget
            from .inference.router import ProviderRouter
            from .maintainer import _RouterAdapter

            inference_budget = InferenceBudget(
                candidate_id=str(candidate.get("candidate_id", "closeout")),
                purpose="inheritance-gate",
                deadline_ms=int(getattr(settings, "prompt_budget_ms", 1000)),
            )
            decision = decide_inheritance(
                candidate,
                _RouterAdapter(ProviderRouter(settings=settings)),
                inference_budget,
            )
    except ProviderSelectionError:
        raise
    except (ValueError, TypeError) as exc:
        raise InputError(_error_code(exc, "GATE_INPUT_INVALID")) from exc

    privacy_rejected_no = False
    if decision.decision in {"YES", "NO"}:
        privacy = inspect_observation(ObservationInput(
            decision.candidate_title,
            decision.candidate_claim,
            "agent_direct",
            str(candidate.get("source_ref", "closeout")),
            "",
            str(candidate.get("domain", "general")),
            "observed",
            decision.benefit,
            decision.classification,
        ))
        if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
            if decision.decision == "YES":
                raise PrivacyRejected(privacy.reason_code)
            from .gate import GateDecision
            decision = GateDecision(
                "NO", "secret_or_confidential", "", "", (), "", "private-reusable", 1.0,
                decision.provider_id,
                source_host_id=decision.source_host_id,
                source_host_family=decision.source_host_family,
                applicability_scope=decision.applicability_scope,
                applicable_host_ids=decision.applicable_host_ids,
                applicable_host_families=decision.applicable_host_families,
            )
            privacy_rejected_no = trusted_entry
        if trusted_entry and getattr(validation, "valid", False) and privacy_rejected_no:
            _event_audit(settings, decision, candidate, unique_attempt=True)
        elif not (trusted_entry and getattr(validation, "valid", False)):
            _event_audit(settings, decision, candidate)

    if decision.decision in {"NO", "DEFERRED", "FAILED"}:
        if decision.decision == "NO" and trusted_entry and getattr(validation, "valid", False) and not privacy_rejected_no:
            content_hash = _content_hash(candidate, decision)
            return _associated_payload(
                decision, candidate, settings, validation, content_hash,
                now=now or datetime.now(timezone.utc), budget=budget,
            )
        result = _legacy_payload(decision, candidate, settings, validation=validation)
        if privacy_rejected_no:
            value = dict(result.payload)
            value["association"] = _association("REJECTED", "CLOSEOUT_PRIVACY_REJECTED")
            return CloseoutResult(value, result.exit_code)
        return result

    if decision.decision != "YES":
        raise InputError("GATE_DECISION_INVALID")

    curator_input = _curator_input(candidate, decision)
    if trusted_entry and getattr(validation, "valid", False):
        content_hash = _content_hash(candidate, decision)
        return _associated_payload(
            decision, candidate, settings, validation, content_hash,
            now=now or datetime.now(timezone.utc), budget=budget,
        )

    from .curator import curate_candidate
    changeset = curate_candidate(
        curator_input,
        _index(settings, budget=budget),
        {"provider_id": decision.provider_id or "manual-structured"},
        None,
        operation_budget=budget,
    )
    change_validation = validate_changeset(changeset, settings, budget=budget)
    if not change_validation.valid:
        code = change_validation.reason_codes[0] if change_validation.reason_codes else "CHANGESET_INVALID"
        if code in {"RAW_CONTENT_FORBIDDEN", "PRIVACY_REJECTED"}:
            raise PrivacyRejected(code)
        raise InputError(code)
    applied = apply_changeset(changeset, settings, budget=budget)
    team = _team_result(settings, applied=applied.applied, changeset=changeset,
                        event_ids=tuple(applied.event_ids), candidate=curator_input)
    value = {
        "status": "applied" if applied.applied else "failed",
        "gate": decision.to_dict(),
        "curation": {
            "changeset": changeset.to_dict(),
            "applied": applied.applied,
            "reason_code": applied.reason_code,
            "event_ids": list(applied.event_ids),
            "already_applied": applied.already_applied,
        },
        "personal": {"status": "READY" if applied.applied else "FAILED", "reason_code": applied.reason_code},
        "team": team,
        "knowledge_stores": {"personal": {"status": "READY" if applied.applied else "FAILED"}, "team": team},
        "knowledge": "APPLIED" if applied.applied else "FAILED",
        "association": _context_association(validation),
    }
    return CloseoutResult(value, EXIT_OK if applied.applied else EXIT_INTERNAL)


__all__ = [
    "CloseoutResult", "InputError", "PrivacyRejected", "process_closeout",
]
