"""Independent routing of an applied personal knowledge record to team storage.

The personal journal remains the source of truth.  This module only receives
an already-applied result, runs a second bounded eligibility/privacy decision,
and either appends a sanitized event or hands the same sanitized event to the
encrypted machine-local outbox.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .inference.base import InferenceBudget, ProviderResult
from .inference.router import ProviderSelectionError
from .ids import machine_id
from .journal import event_integrity, read_event
from .models import Event
from .persistable_fields import inspect_persistable
from .privacy import inspect_text
from .redaction import domain_hash
from .spool import SpoolError
from .team_store import append_team_event, inspect_team_store


_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_CLASSIFICATIONS = frozenset({"public", "private-reusable"})
_FIELDS = (
    "title",
    "claim",
    "scope",
    "preconditions",
    "failure_modes",
    "benefit",
    "classification",
)


@dataclass(frozen=True)
class TeamRoutingDecision:
    status: Literal["ELIGIBLE", "NOT_ELIGIBLE", "DEFERRED", "FAILED"]
    reason_code: str
    personal_event_hash: str
    team_store_id: str
    normalized_payload: Mapping[str, object] | None
    delivery_event_id: str | None = None
    delivery_event_hash: str | None = None
    receipt_id: str | None = None
    receipt_status: str | None = None
    team_root_hash: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"ELIGIBLE", "NOT_ELIGIBLE", "DEFERRED", "FAILED"}:
            raise ValueError("TEAM_ROUTING_STATUS_INVALID")
        for name in ("reason_code", "personal_event_hash", "team_store_id"):
            if not isinstance(getattr(self, name), str):
                raise ValueError("TEAM_ROUTING_RESULT_INVALID")
        if self.normalized_payload is not None and not isinstance(self.normalized_payload, Mapping):
            raise ValueError("TEAM_ROUTING_PAYLOAD_INVALID")

    def to_dict(self) -> dict[str, object]:
        value = {
            "status": self.status,
            "reason_code": self.reason_code,
            "personal_event_hash": self.personal_event_hash,
            "team_store_id": self.team_store_id,
            "normalized_payload": dict(self.normalized_payload) if self.normalized_payload is not None else None,
        }
        for name in ("delivery_event_id", "delivery_event_hash", "receipt_id", "receipt_status", "team_root_hash"):
            selected = getattr(self, name)
            if selected is not None:
                value[name] = selected
        return value


def _value(source: object, name: str, default: object = None) -> object:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _text(source: object, *names: str, default: str = "") -> str:
    for name in names:
        value = _value(source, name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _list(source: object, *names: str) -> list[str]:
    for name in names:
        value = _value(source, name)
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return list(dict.fromkeys(item.strip() for item in value if isinstance(item, str) and item.strip()))
    return []


def _team_value(team_store: object, name: str, default: object = None) -> object:
    value = _value(team_store, name, default)
    return default if value is None else value


def _store_id(team_store: object) -> str:
    value = _team_value(team_store, "store_id", "")
    return value if isinstance(value, str) else ""


def _normalise_candidate(candidate: object) -> dict[str, object]:
    return {
        "title": _text(candidate, "title", "candidate_title")[:160],
        "claim": _text(candidate, "claim", "candidate_claim"),
        "scope": _list(candidate, "scope", "scopes") or [_text(candidate, "domain", default="general")],
        "preconditions": _list(candidate, "preconditions", "precondition") or ["同じ問題構造が再発している"],
        "failure_modes": _list(candidate, "failure_modes", "failure_mode") or ["検証を省略して再作業になる"],
        "benefit": _text(candidate, "benefit", default="reduced_rework"),
        "classification": _text(candidate, "classification", default="private-reusable"),
    }


def _candidate_hashes(candidate: object) -> tuple[str, ...]:
    values: list[str] = []
    for name in ("evidence_refs", "evidence_hashes", "source_hashes", "source_hash"):
        value = _value(candidate, name)
        if isinstance(value, str):
            value = (value,)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            values.extend(item for item in value if isinstance(item, str) and _HASH.fullmatch(item))
    return tuple(dict.fromkeys(values))


def _provider_output(provider: object, input_json: Mapping[str, object], budget: InferenceBudget) -> tuple[str, Mapping[str, object] | None, str | None]:
    if provider is None:
        return "FAILED", None, "PROVIDER_UNAVAILABLE"
    available = getattr(provider, "available", None)
    if callable(available):
        try:
            if not available():
                return "FAILED", None, "PROVIDER_UNAVAILABLE"
        except Exception:
            return "FAILED", None, "PROVIDER_UNAVAILABLE"
    elif available is False:
        return "FAILED", None, "PROVIDER_UNAVAILABLE"
    try:
        generated = provider.generate("team-routing-decision", input_json, budget)
    except ProviderSelectionError as exc:
        return "FAILED", None, getattr(exc, "reason_code", "PROVIDER_UNAVAILABLE")
    except Exception as exc:
        return "FAILED", None, type(exc).__name__
    if isinstance(generated, ProviderResult):
        if generated.deferred:
            return "DEFERRED", None, generated.error_code or "PROVIDER_DEFERRED"
        if not generated.ok:
            return "FAILED", None, generated.error_code or "PROVIDER_FAILED"
        generated = generated.output
    if not isinstance(generated, Mapping):
        return "FAILED", None, "MALFORMED_RESPONSE"
    return "ELIGIBLE", generated, None


def _validate_payload(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
    if set(value) != set(_FIELDS):
        raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
    result: dict[str, object] = {}
    title = value.get("title")
    claim = value.get("claim")
    if not isinstance(title, str) or not title or len(title) > 160:
        raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
    if not isinstance(claim, str) or len(claim) < 20 or len(claim) > 1200:
        raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
    for name in ("scope", "preconditions", "failure_modes"):
        items = value.get(name)
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)) or not items or any(not isinstance(item, str) or not item.strip() for item in items):
            raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
        result[name] = list(dict.fromkeys(item.strip() for item in items))
    benefit = value.get("benefit")
    classification = value.get("classification")
    if not isinstance(benefit, str) or not benefit or not isinstance(classification, str) or classification not in _CLASSIFICATIONS:
        raise ValueError("TEAM_ROUTING_RESPONSE_INVALID")
    result.update({"title": title.strip(), "claim": claim.strip(), "benefit": benefit.strip(), "classification": classification})
    inspection = inspect_persistable(result, classification=classification)
    if not inspection.valid:
        raise ValueError(inspection.reason_codes[0] if inspection.reason_codes else "TEAM_ROUTING_PRIVACY_REJECTED")
    privacy = inspect_text("\n".join([str(result["title"]), str(result["claim"]), str(result["benefit"])]), classification, "team-routing")
    if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
        raise ValueError("TEAM_ROUTING_PRIVACY_REJECTED")
    return result


def decide_team_routing(
    candidate: object,
    team_store: object,
    provider: object,
    budget: InferenceBudget | Mapping[str, object] | None = None,
) -> TeamRoutingDecision:
    """Run the independent team eligibility and normalized-payload decision."""

    store_id = _store_id(team_store)
    personal_hash = _text(candidate, "personal_event_hash", "source_hash", default="")
    if not _HASH.fullmatch(personal_hash):
        personal_hash = "sha256:" + hashlib.sha256(json.dumps(_normalise_candidate(candidate), ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    if _team_value(team_store, "enabled", False) is not True:
        return TeamRoutingDecision("NOT_ELIGIBLE", "TEAM_DISABLED", personal_hash, store_id, None)
    normalized = _normalise_candidate(candidate)
    classification = str(normalized["classification"])
    if classification not in _CLASSIFICATIONS:
        return TeamRoutingDecision("NOT_ELIGIBLE", "TEAM_CLASSIFICATION_NOT_ELIGIBLE", personal_hash, store_id, None)
    privacy = inspect_text("\n".join(str(normalized[name]) for name in ("title", "claim", "benefit")), classification, "team-routing")
    if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
        return TeamRoutingDecision("NOT_ELIGIBLE", "TEAM_PRIVACY_REJECTED", personal_hash, store_id, None)
    evidence_hashes = _candidate_hashes(candidate)
    input_json = {
        **normalized,
        "evidence_kinds": _list(candidate, "evidence_kinds", "source_kind"),
        "evidence_hashes": list(evidence_hashes),
        "team_store_id_hash": domain_hash(store_id, "team-store") if store_id else "",
    }
    selected_budget = InferenceBudget.from_value(budget)
    status, output, reason = _provider_output(provider, input_json, selected_budget)
    if status != "ELIGIBLE" or output is None:
        return TeamRoutingDecision(status, reason or "PROVIDER_FAILED", personal_hash, store_id, None)
    try:
        payload = _validate_payload(output)
    except (TypeError, ValueError) as exc:
        return TeamRoutingDecision("FAILED", str(exc), personal_hash, store_id, None)
    return TeamRoutingDecision("ELIGIBLE", "TEAM_ELIGIBLE", personal_hash, store_id, payload)


_TEAM_PREPARED_KEYS = frozenset({
    "schema_version", "status", "reason_code", "normalized_payload", "team_store_id",
    "team_member_id", "writer_id", "team_root_hash", "actor_hash", "machine_hash", "prepared_at",
})
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_TEAM_STORE = re.compile(r"^team_[0-9a-f]{16,64}$")
_TEAM_MEMBER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_TEAM_WRITER = re.compile(r"^writer_[0-9a-f]{16,64}$")
_EVENT_IDS = re.compile(r"^evt_changeset_[0-9a-f]{32}$")


def _utc_stamp(value: datetime | None) -> tuple[datetime, str]:
    moment = value or datetime.now(timezone.utc)
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("TEAM_ROUTING_TIME_INVALID")
    selected = moment.astimezone(timezone.utc)
    return selected, selected.isoformat().replace("+00:00", "Z")


def _budget_check(budget: object | None) -> None:
    check = getattr(budget, "check", None)
    if callable(check):
        check()


def _routing_budget(candidate: Mapping[str, object], value: object | None) -> InferenceBudget:
    if isinstance(value, InferenceBudget):
        return replace(value, purpose="team-routing")
    if isinstance(value, Mapping):
        return InferenceBudget.from_value({**dict(value), "purpose": "team-routing"})
    remaining = getattr(value, "remaining_ms", None)
    deadline = max(0, remaining()) if callable(remaining) else InferenceBudget.deadline_ms
    candidate_id = _text(candidate, "candidate_id", default="team-routing")[:160]
    return InferenceBudget(candidate_id=candidate_id, purpose="team-routing", deadline_ms=deadline)


def _binding_fields(settings: object, descriptor: Mapping[str, object] | None) -> dict[str, object]:
    if descriptor is None:
        return {
            "team_store_id": "", "team_member_id": "", "writer_id": "",
            "team_root_hash": None, "actor_hash": None, "machine_hash": None,
        }
    root_value = descriptor.get("root")
    try:
        root = Path(str(root_value)).expanduser().resolve(strict=False) if root_value is not None else None
        root_hash = domain_hash(str(root), "team-root") if root is not None else None
    except (OSError, RuntimeError, TypeError, ValueError):
        root_hash = None
    store_id = _store_id(descriptor)
    member_id = _text(descriptor, "team_member_id")
    writer_id = _text(descriptor, "writer_id")
    valid_identity = bool(
        _TEAM_STORE.fullmatch(store_id)
        and _TEAM_MEMBER.fullmatch(member_id)
        and _TEAM_WRITER.fullmatch(writer_id)
        and root_hash
    )
    machine = getattr(settings, "machine_id_hash", None) or machine_id()
    return {
        "team_store_id": store_id if valid_identity else "",
        "team_member_id": member_id if valid_identity else "",
        "writer_id": writer_id if valid_identity else "",
        "team_root_hash": root_hash if valid_identity else None,
        "actor_hash": domain_hash(member_id, "team-member-actor") if valid_identity else None,
        "machine_hash": domain_hash(str(machine), "team-machine") if valid_identity else None,
    }


def validate_prepared_team_routing(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != _TEAM_PREPARED_KEYS:
        return False
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        return False
    status, reason = value.get("status"), value.get("reason_code")
    if status not in {"ELIGIBLE", "NOT_ELIGIBLE", "DEFERRED", "FAILED"}:
        return False
    if not isinstance(reason, str) or not _REASON.fullmatch(reason):
        return False
    for name in ("team_store_id", "team_member_id", "writer_id", "prepared_at"):
        if not isinstance(value.get(name), str):
            return False
    for name in ("team_root_hash", "actor_hash", "machine_hash"):
        raw = value.get(name)
        if raw is not None and (not isinstance(raw, str) or not _HASH.fullmatch(raw)):
            return False
    store_id = value["team_store_id"]
    member_id = value["team_member_id"]
    writer_id = value["writer_id"]
    identity = bool(store_id and member_id and writer_id)
    if identity != all(value.get(name) is not None for name in ("team_root_hash", "actor_hash", "machine_hash")):
        return False
    if identity and not (
        _TEAM_STORE.fullmatch(store_id)
        and _TEAM_MEMBER.fullmatch(member_id)
        and _TEAM_WRITER.fullmatch(writer_id)
    ):
        return False
    try:
        stamp = value["prepared_at"]
        if len(stamp) > 40 or not stamp.endswith("Z"):
            return False
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return False
    if moment.tzinfo is None or moment.utcoffset() != timezone.utc.utcoffset(moment):
        return False
    if moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") != stamp:
        return False
    normalized = value.get("normalized_payload")
    if status == "ELIGIBLE":
        try:
            return identity and _validate_payload(normalized) == dict(normalized)
        except (TypeError, ValueError):
            return False
    return normalized is None


def prepare_team_routing(
    candidate: Mapping[str, object],
    settings: object,
    *,
    now: datetime,
    operation_budget: object | None,
) -> dict[str, object]:
    """Freeze one sanitized team eligibility decision before personal apply."""

    _budget_check(operation_budget)
    moment, stamp = _utc_stamp(now)
    descriptor = _team_descriptor(settings)
    binding = _binding_fields(settings, descriptor)
    if descriptor is None or descriptor.get("enabled") is not True:
        prepared = {
            "schema_version": 1,
            "status": "NOT_ELIGIBLE",
            "reason_code": "TEAM_DISABLED",
            "normalized_payload": None,
            **binding,
            "prepared_at": stamp,
        }
        if not validate_prepared_team_routing(prepared):
            raise ValueError("TEAM_PREPARE_INVALID")
        return prepared
    if not binding["team_store_id"]:
        prepared = {
            "schema_version": 1,
            "status": "FAILED",
            "reason_code": "TEAM_IDENTITY_REQUIRED",
            "normalized_payload": None,
            **binding,
            "prepared_at": stamp,
        }
        return prepared
    try:
        from .inference.router import ProviderRouter
        provider = ProviderRouter(settings=settings)
    except Exception:
        provider = None
    decision = decide_team_routing(
        candidate,
        descriptor,
        provider,
        _routing_budget(candidate, operation_budget),
    )
    _budget_check(operation_budget)
    reason = decision.reason_code if _REASON.fullmatch(decision.reason_code) else "TEAM_ROUTING_FAILED"
    prepared = {
        "schema_version": 1,
        "status": decision.status,
        "reason_code": reason,
        "normalized_payload": dict(decision.normalized_payload) if decision.normalized_payload is not None else None,
        **binding,
        "prepared_at": stamp,
    }
    if not validate_prepared_team_routing(prepared):
        raise ValueError("TEAM_PREPARE_INVALID")
    return prepared


def noneligible_team_routing(reason_code: str, settings: object, *, now: datetime) -> dict[str, object]:
    """Create a bounded explicit no-delivery decision without invoking a provider."""

    moment, stamp = _utc_stamp(now)
    del moment
    reason = reason_code if _REASON.fullmatch(reason_code) else "TEAM_NOT_ELIGIBLE"
    prepared = {
        "schema_version": 1,
        "status": "NOT_ELIGIBLE",
        "reason_code": reason,
        "normalized_payload": None,
        **_binding_fields(settings, _team_descriptor(settings)),
        "prepared_at": stamp,
    }
    if not validate_prepared_team_routing(prepared):
        raise ValueError("TEAM_PREPARE_INVALID")
    return prepared


def _current_binding_matches(prepared: Mapping[str, object], settings: object) -> tuple[Mapping[str, object] | None, bool]:
    descriptor = _team_descriptor(settings)
    current = _binding_fields(settings, descriptor)
    same = bool(
        descriptor is not None
        and descriptor.get("enabled") is True
        and all(current.get(name) == prepared.get(name) for name in (
            "team_store_id", "team_member_id", "writer_id", "team_root_hash", "actor_hash", "machine_hash",
        ))
    )
    return descriptor, same


def _prepared_event(
    prepared: Mapping[str, object],
    personal_event_hash: str,
    *,
    deterministic: bool,
) -> Event:
    normalized = prepared.get("normalized_payload")
    if not isinstance(normalized, Mapping):
        raise ValueError("TEAM_PREPARE_INVALID")
    store_id = str(prepared["team_store_id"])
    payload = dict(normalized)
    payload["knowledge_scope"] = "team"
    payload["origin_event_hash"] = domain_hash(personal_event_hash, "personal-event-origin")
    idempotency_key = domain_hash(personal_event_hash + store_id, "team-event-idempotency")
    payload["idempotency_key"] = idempotency_key
    moment = datetime.fromisoformat(str(prepared["prepared_at"]).replace("Z", "+00:00"))
    event = Event.create_v2(
        "team.knowledge.recorded",
        actor=str(prepared["actor_hash"]),
        machine_id=str(prepared["machine_hash"]),
        payload=payload,
        occurred_at=moment if deterministic else None,
        idempotency_key=idempotency_key,
    )
    if deterministic:
        timestamp = moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        event_id = f"evt_{timestamp}_{idempotency_key.removeprefix('sha256:')[:12]}"
        event = replace(event, event_id=event_id)
    return event


def deliver_prepared_team_routing(
    prepared: Mapping[str, object],
    settings: object,
    *,
    personal_event_hash: str,
    event_ids: Sequence[str],
    operation_budget: object | None,
) -> TeamRoutingDecision:
    """Deliver the frozen team decision after verified personal application."""

    _budget_check(operation_budget)
    store_id = str(prepared.get("team_store_id", "")) if isinstance(prepared, Mapping) else ""
    if not validate_prepared_team_routing(prepared) or not _HASH.fullmatch(personal_event_hash):
        return TeamRoutingDecision("FAILED", "TEAM_PREPARE_INVALID", personal_event_hash, store_id, None)
    if (
        not isinstance(event_ids, Sequence)
        or isinstance(event_ids, (str, bytes, bytearray))
        or not 2 <= len(event_ids) <= 65
        or len(set(event_ids)) != len(event_ids)
        or any(not isinstance(item, str) or not _EVENT_IDS.fullmatch(item) for item in event_ids)
    ):
        return TeamRoutingDecision("FAILED", "TEAM_PERSONAL_EVENTS_INVALID", personal_event_hash, store_id, None)
    status = str(prepared["status"])
    reason = str(prepared["reason_code"])
    if status != "ELIGIBLE":
        return TeamRoutingDecision(status, reason, personal_event_hash, store_id, None)
    descriptor, binding_matches = _current_binding_matches(prepared, settings)
    if not binding_matches or descriptor is None:
        return TeamRoutingDecision("FAILED", "TEAM_BINDING_CHANGED", personal_event_hash, store_id, None)
    event = _prepared_event(prepared, personal_event_hash, deterministic=True)
    expected_hash = event_integrity(event)
    root = Path(str(descriptor.get("root", ""))).expanduser().resolve(strict=False)
    append_error_code = "TEAM_ROOT_UNAVAILABLE"
    _budget_check(operation_budget)
    if root.is_dir():
        try:
            inspected = inspect_team_store(root, expected_store_id=store_id, budget=operation_budget)
            if inspected.store_id != store_id:
                return TeamRoutingDecision("FAILED", "TEAM_BINDING_CHANGED", personal_event_hash, store_id, None)
            target = append_team_event(
                root, str(prepared["team_member_id"]), str(prepared["writer_id"]), event,
                budget=operation_budget,
            )
            stored = read_event(target, budget=operation_budget)
            if (
                stored.event_id != event.event_id
                or stored.idempotency_key != event.idempotency_key
                or event_integrity(stored) != expected_hash
            ):
                return TeamRoutingDecision("FAILED", "TEAM_EVENT_READBACK_FAILED", personal_event_hash, store_id, None)
            return TeamRoutingDecision(
                "ELIGIBLE", "TEAM_EVENT_RECORDED", personal_event_hash, store_id,
                dict(prepared["normalized_payload"]), event.event_id, expected_hash,
                team_root_hash=str(prepared["team_root_hash"]),
            )
        except TimeoutError:
            raise
        except ValueError as exc:
            if str(exc) == "TEAM_STORE_ID_MISMATCH":
                return TeamRoutingDecision("FAILED", "TEAM_BINDING_CHANGED", personal_event_hash, store_id, None)
            if str(exc) in {"TEAM_EVENT_ID_CONFLICT", "TEAM_IDEMPOTENCY_CONFLICT"}:
                return TeamRoutingDecision("FAILED", "TEAM_EVENT_CONFLICT", personal_event_hash, store_id, None)
            append_error_code = "TEAM_ROOT_UNAVAILABLE"
        except OSError:
            append_error_code = "TEAM_ROOT_UNAVAILABLE"
    try:
        from .team_outbox import enqueue_team_event, read_team_outbox_receipt
        outbox_payload = {
            "event": event.to_dict(),
            "member_id": str(prepared["team_member_id"]),
            "writer_id": str(prepared["writer_id"]),
            "append_error_code": append_error_code,
            "team_root_hash": str(prepared["team_root_hash"]),
        }
        accepted = enqueue_team_event(
            settings,
            outbox_payload,
            personal_event_hash=personal_event_hash,
            store_id=store_id,
            member_id=str(prepared["team_member_id"]),
            writer_id=str(prepared["writer_id"]),
            budget=operation_budget,
        )
        receipt_id = accepted.get("receipt_id")
        if not isinstance(receipt_id, str):
            return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_READBACK_FAILED", personal_event_hash, store_id, None)
        receipt = read_team_outbox_receipt(settings, receipt_id, budget=operation_budget)
        if not isinstance(receipt, Mapping):
            return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_READBACK_FAILED", personal_event_hash, store_id, None)
        if (
            receipt.get("store_id_hash") != domain_hash(store_id, "team-store-id")
            or receipt.get("member_id_hash") != domain_hash(str(prepared["team_member_id"]), "team-member-id")
            or receipt.get("writer_id_hash") != domain_hash(str(prepared["writer_id"]), "team-writer-id")
            or receipt.get("personal_event_hash") != personal_event_hash
            or receipt.get("idempotency_key") != event.idempotency_key
            or receipt.get("team_root_hash") != prepared.get("team_root_hash")
        ):
            return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_READBACK_FAILED", personal_event_hash, store_id, None)
        receipt_status = receipt.get("status")
        if receipt_status in {"PENDING", "DEFERRED"} and isinstance(receipt.get("spool_ref"), Mapping):
            from .spool import read_spool
            raw = read_spool(receipt["spool_ref"], settings, budget=operation_budget)
            cached = json.loads(raw.decode("utf-8", errors="strict"))
            if not isinstance(cached, Mapping) or dict(cached) != outbox_payload:
                return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_READBACK_FAILED", personal_event_hash, store_id, None)
            return TeamRoutingDecision(
                "DEFERRED", "TEAM_ROOT_UNAVAILABLE", personal_event_hash, store_id,
                dict(prepared["normalized_payload"]), event.event_id, expected_hash,
                receipt_id, str(receipt_status), str(prepared["team_root_hash"]),
            )
        if receipt_status == "DELIVERED" and receipt.get("final_event_hash") == expected_hash:
            return TeamRoutingDecision(
                "ELIGIBLE", "TEAM_EVENT_RECORDED", personal_event_hash, store_id,
                dict(prepared["normalized_payload"]), event.event_id, expected_hash,
                receipt_id, str(receipt_status), str(prepared["team_root_hash"]),
            )
        return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_READBACK_FAILED", personal_event_hash, store_id, None)
    except TimeoutError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError, SpoolError):
        return TeamRoutingDecision("FAILED", "TEAM_OUTBOX_PENDING", personal_event_hash, store_id, None)


def _applied_ok(value: object) -> bool:
    if isinstance(value, Mapping):
        return value.get("applied") is True or value.get("status") == "applied"
    return getattr(value, "applied", False) is True


def _settings_team(settings: object) -> object | None:
    stores = getattr(settings, "knowledge_stores", None)
    return getattr(stores, "team", None) if stores is not None else None


def _manifest_team(settings: object) -> dict[str, object] | None:
    try:
        path = Path(settings.paths.runtime_root) / "install-manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (AttributeError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    stores = value.get("knowledge_stores") if isinstance(value, Mapping) else None
    team = stores.get("team") if isinstance(stores, Mapping) else None
    return dict(team) if isinstance(team, Mapping) else None


def _team_descriptor(settings: object) -> dict[str, object] | None:
    team = _settings_team(settings)
    if team is None:
        return None
    result = dict(team) if isinstance(team, Mapping) else {"root": str(getattr(team, "root", ""))}
    manifest = _manifest_team(settings)
    if manifest:
        result = {**manifest, **result}
    result.setdefault("enabled", True)
    return result


def _candidate_from_applied(value: object, explicit: object | None = None) -> Mapping[str, object]:
    if isinstance(explicit, Mapping):
        return explicit
    if isinstance(value, Mapping):
        for key in ("candidate", "normalized_payload", "payload"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                return nested
        changeset = value.get("changeset")
        if isinstance(changeset, Mapping):
            operations = changeset.get("operations")
            if isinstance(operations, Sequence):
                for operation in operations:
                    if isinstance(operation, Mapping) and isinstance(operation.get("payload"), Mapping):
                        return operation["payload"]
    nested = getattr(value, "candidate", None)
    return nested if isinstance(nested, Mapping) else {}


def _personal_event_hash(value: object, candidate: Mapping[str, object]) -> str:
    if isinstance(value, Mapping):
        for key in ("changeset_hash", "personal_event_hash", "source_hash"):
            raw = value.get(key)
            if isinstance(raw, str) and _HASH.fullmatch(raw):
                return raw
    raw = _value(value, "changeset_hash", "")
    if isinstance(raw, str) and _HASH.fullmatch(raw):
        return raw
    return "sha256:" + hashlib.sha256(json.dumps(dict(candidate), ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def route_applied_personal_knowledge(
    applied_change: object,
    settings: object,
    provider: object | None = None,
    budget: InferenceBudget | Mapping[str, object] | None = None,
    *,
    candidate: Mapping[str, object] | None = None,
    writer_id: str | None = None,
    key_provider: object | None = None,
) -> TeamRoutingDecision:
    """Route only after personal apply; failures never undo that apply."""

    descriptor = _team_descriptor(settings)
    selected_candidate = _candidate_from_applied(applied_change, candidate)
    personal_hash = _personal_event_hash(applied_change, selected_candidate)
    if not _applied_ok(applied_change):
        return TeamRoutingDecision("FAILED", "PERSONAL_APPLY_REQUIRED", personal_hash, _store_id(descriptor or {}), None)
    if descriptor is None or descriptor.get("enabled") is not True:
        return TeamRoutingDecision("NOT_ELIGIBLE", "TEAM_DISABLED", personal_hash, _store_id(descriptor or {}), None)
    member_id = _text(descriptor, "team_member_id", default=_text(applied_change, "team_member_id"))
    selected_writer = writer_id or _text(descriptor, "writer_id", default=_text(applied_change, "writer_id"))
    if not member_id or not selected_writer:
        return TeamRoutingDecision("FAILED", "TEAM_IDENTITY_REQUIRED", personal_hash, _store_id(descriptor), None)
    if provider is None:
        try:
            from .inference.router import ProviderRouter
            provider = ProviderRouter(settings=settings)
        except Exception:
            provider = None
    decision = decide_team_routing({**dict(selected_candidate), "personal_event_hash": personal_hash}, descriptor, provider, budget)
    if decision.status != "ELIGIBLE" or decision.normalized_payload is None:
        return decision
    store_id = decision.team_store_id
    payload = dict(decision.normalized_payload)
    payload["knowledge_scope"] = "team"
    payload["origin_event_hash"] = domain_hash(personal_hash, "personal-event-origin")
    payload["idempotency_key"] = domain_hash(personal_hash + store_id, "team-event-idempotency")
    # Event actor/machine fields are domain-separated hashes, never raw IDs.
    event = Event.create_v2(
        "team.knowledge.recorded",
        actor=domain_hash(member_id, "team-member-actor"),
        machine_id=domain_hash(str(getattr(settings, "machine_id_hash", machine_id())), "team-machine"),
        payload=payload,
        idempotency_key=payload["idempotency_key"],
    )
    root = Path(str(descriptor.get("root", ""))).expanduser()
    append_error_code = None
    try:
        if root.is_dir():
            append_team_event(root, member_id, selected_writer, event)
            return TeamRoutingDecision("ELIGIBLE", "TEAM_EVENT_RECORDED", personal_hash, store_id, payload)
    except (OSError, TypeError, ValueError) as exc:
        append_error_code = type(exc).__name__
    from .team_outbox import enqueue_team_event
    try:
        enqueue_team_event(
            settings,
            {
                "event": event.to_dict(),
                "member_id": member_id,
                "writer_id": selected_writer,
                "append_error_code": append_error_code,
            },
            personal_event_hash=personal_hash,
            store_id=store_id,
            member_id=member_id,
            writer_id=selected_writer,
            key_provider=key_provider,
        )
    except Exception as exc:
        return TeamRoutingDecision("FAILED", str(exc), personal_hash, store_id, payload)
    return TeamRoutingDecision("DEFERRED", "TEAM_ROOT_UNAVAILABLE", personal_hash, store_id, payload)


__all__ = [
    "TeamRoutingDecision", "decide_team_routing", "prepare_team_routing",
    "deliver_prepared_team_routing", "validate_prepared_team_routing",
    "noneligible_team_routing", "route_applied_personal_knowledge",
]
