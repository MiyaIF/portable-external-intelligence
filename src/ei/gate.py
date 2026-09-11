from __future__ import annotations

import json
import os
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .inference.base import InferenceBudget, ProviderResult, validate_output
from .models import validate_host_applicability_mapping, validate_host_label
from .privacy import inspect_text
from .queue import QueueItem, QueueState, transition_queue_item


_REASON_CLASSES = frozenset({
    "project_specific",
    "one_off_fact",
    "no_evidence",
    "no_future_benefit",
    "duplicate_without_new_evidence",
    "secret_or_confidential",
    "transient_state",
    "already_encoded",
})
_ALLOWED_BENEFITS = frozenset({"avoided_failure", "reduced_rework", "faster_completion", "quality_improvement", "discovered_structure", ""})
_SEMANTIC_REASON_CLASSES = _REASON_CLASSES | frozenset({"evidence_verified", "evidence_repeated", "novel_structure"})
_SAFE_PROCESSING_REASON = re.compile(r"^[A-Z0-9_.:-]{1,80}$")
_SAFE_HOST_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}$")
_HOST_SCOPES = frozenset({"universal", "family", "host"})


@dataclass(frozen=True)
class GateDecision:
    decision: str
    reason_code: str
    candidate_title: str = ""
    candidate_claim: str = ""
    evidence_refs: tuple[str, ...] = ()
    benefit: str = ""
    classification: str = "private-reusable"
    confidence: float = 0.0
    provider_id: str = ""
    processing_state: str = "complete"
    retry_after_seconds: int | None = None
    next_eligible_at: datetime | None = None
    source_host_id: str = ""
    source_host_family: str = ""
    applicability_scope: Literal["universal", "family", "host"] = "universal"
    applicable_host_ids: tuple[str, ...] = ()
    applicable_host_families: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.decision not in {"YES", "NO", "DEFERRED", "FAILED"}:
            raise ValueError("GATE_DECISION_INVALID")
        for field_name in ("reason_code", "candidate_title", "candidate_claim", "benefit", "classification", "provider_id", "processing_state"):
            if not isinstance(getattr(self, field_name), str):
                raise ValueError("GATE_FIELD_INVALID")
        if not self.reason_code or len(self.reason_code) > 80:
            raise ValueError("GATE_REASON_INVALID")
        if self.decision in {"YES", "NO"} and self.reason_code not in _SEMANTIC_REASON_CLASSES:
            raise ValueError("GATE_REASON_CLASS_INVALID")
        if self.decision in {"DEFERRED", "FAILED"} and not _SAFE_PROCESSING_REASON.fullmatch(self.reason_code):
            raise ValueError("GATE_REASON_INVALID")
        if len(self.candidate_title) > 160 or len(self.candidate_claim) > 1200:
            raise ValueError("GATE_CANDIDATE_TOO_LARGE")
        if not isinstance(self.evidence_refs, tuple) or any(not isinstance(item, str) or not item.startswith("sha256:") for item in self.evidence_refs):
            raise ValueError("GATE_EVIDENCE_REF_INVALID")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool) or not 0 <= self.confidence <= 1:
            raise ValueError("GATE_CONFIDENCE_INVALID")
        if self.retry_after_seconds is not None and (type(self.retry_after_seconds) is not int or self.retry_after_seconds < 0):
            raise ValueError("GATE_RETRY_AFTER_INVALID")
        if self.next_eligible_at is not None and (self.next_eligible_at.tzinfo is None or self.next_eligible_at.utcoffset() is None):
            raise ValueError("GATE_TIMEZONE_REQUIRED")
        for field_name in ("source_host_id", "source_host_family"):
            value = getattr(self, field_name)
            try:
                validate_host_label(value, field=field_name, allow_empty=True)
            except ValueError:
                raise ValueError("GATE_HOST_LABEL_INVALID")
        if self.decision == "YES":
            try:
                validate_host_applicability_mapping(
                    {
                        "source_host_id": self.source_host_id,
                        "source_host_family": self.source_host_family,
                        "applicability_scope": self.applicability_scope,
                    "applicable_host_ids": list(self.applicable_host_ids),
                    "applicable_host_families": list(self.applicable_host_families),
                },
                    require_source_pair=True,
                )
            except ValueError as exc:
                raise ValueError("GATE_APPLICABILITY_INVALID") from exc
        for field_name in ("applicable_host_ids", "applicable_host_families"):
            values = getattr(self, field_name)
            if not isinstance(values, tuple) or len(values) > 16 or len(set(values)) != len(values):
                raise ValueError("GATE_HOST_LIST_INVALID")
            if any(not isinstance(value, str) or not _SAFE_HOST_LABEL.fullmatch(value) for value in values):
                raise ValueError("GATE_HOST_LABEL_INVALID")

    @property
    def semantic(self) -> bool:
        return self.decision in {"YES", "NO"}

    @property
    def is_deferred(self) -> bool:
        return self.decision == "DEFERRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "candidate_title": self.candidate_title,
            "candidate_claim": self.candidate_claim,
            "evidence_refs": list(self.evidence_refs),
            "benefit": self.benefit,
            "classification": self.classification,
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "processing_state": self.processing_state,
            "retry_after_seconds": self.retry_after_seconds,
            "next_eligible_at": self.next_eligible_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if self.next_eligible_at else None,
            "source_host_id": self.source_host_id,
            "source_host_family": self.source_host_family,
            "applicability_scope": self.applicability_scope,
            "applicable_host_ids": list(self.applicable_host_ids),
            "applicable_host_families": list(self.applicable_host_families),
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        provider_id: str = "",
        source_host_id: str = "",
        source_host_family: str = "",
    ) -> "GateDecision":
        if not isinstance(value, Mapping):
            raise ValueError("GATE_OUTPUT_OBJECT_REQUIRED")
        if not isinstance(provider_id, str):
            raise ValueError("GATE_PROVIDER_ID_INVALID")
        decision = value.get("decision")
        if decision not in {"YES", "NO"}:
            raise ValueError("GATE_DECISION_INVALID")
        refs = value.get("evidence_refs", ())
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes, bytearray)):
            raise ValueError("GATE_EVIDENCE_REFS_INVALID")
        if any(not isinstance(item, str) for item in refs):
            raise ValueError("GATE_EVIDENCE_REFS_INVALID")
        for field_name, default in (("reason_code", "no_evidence" if decision == "NO" else "evidence_verified"), ("candidate_title", ""), ("candidate_claim", ""), ("benefit", ""), ("classification", "private-reusable")):
            if field_name in value and not isinstance(value[field_name], str):
                raise ValueError("GATE_FIELD_INVALID")
        confidence = value.get("confidence", 0)
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("GATE_CONFIDENCE_INVALID")
        if decision == "YES":
            required_scope_fields = {"applicability_scope", "applicable_host_ids", "applicable_host_families"}
            if not required_scope_fields.issubset(value):
                raise ValueError("GATE_YES_APPLICABILITY_REQUIRED")
        raw_ids = value.get("applicable_host_ids", ()) if decision == "YES" else ()
        raw_families = value.get("applicable_host_families", ()) if decision == "YES" else ()
        if not isinstance(raw_ids, Sequence) or isinstance(raw_ids, (str, bytes, bytearray)):
            raise ValueError("GATE_HOST_LIST_INVALID")
        if not isinstance(raw_families, Sequence) or isinstance(raw_families, (str, bytes, bytearray)):
            raise ValueError("GATE_HOST_LIST_INVALID")
        if any(not isinstance(item, str) for item in raw_ids) or any(not isinstance(item, str) for item in raw_families):
            raise ValueError("GATE_HOST_LIST_INVALID")
        if len(set(raw_ids)) != len(raw_ids) or len(set(raw_families)) != len(raw_families):
            raise ValueError("GATE_HOST_LIST_INVALID")
        if not isinstance(source_host_id, str) or not isinstance(source_host_family, str):
            raise ValueError("GATE_HOST_LABEL_INVALID")
        if "provider_id" in value and not isinstance(value["provider_id"], str):
            raise ValueError("GATE_PROVIDER_ID_INVALID")
        raw_scope = value.get("applicability_scope", "universal") if decision == "YES" else "universal"
        if not isinstance(raw_scope, str):
            raise ValueError("GATE_APPLICABILITY_SCOPE_INVALID")
        result = cls(
            decision,
            value.get("reason_code", "no_evidence" if decision == "NO" else "evidence_verified"),
            value.get("candidate_title", ""),
            value.get("candidate_claim", ""),
            tuple(refs),
            value.get("benefit", ""),
            value.get("classification", "private-reusable"),
            confidence,
            provider_id or (value.get("provider_id", "") if isinstance(value.get("provider_id", ""), str) else ""),
            source_host_id=source_host_id,
            source_host_family=source_host_family,
            applicability_scope=raw_scope,
            applicable_host_ids=tuple(raw_ids),
            applicable_host_families=tuple(raw_families),
        )
        if result.decision == "YES" and (len(result.candidate_claim) < 20 or not result.evidence_refs or result.benefit not in _ALLOWED_BENEFITS):
            raise ValueError("GATE_YES_FIELDS_INVALID")
        return result


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    reason_code: str
    state: QueueState
    queue_item: QueueItem
    discarded_payload: bool = False


def _candidate_value(candidate: Any, field: str, default: str = "") -> str:
    if isinstance(candidate, Mapping):
        value = candidate.get(field, default)
    else:
        value = getattr(candidate, field, default)
    return value if isinstance(value, str) else default


def _candidate_input(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, Mapping):
        return {str(key): value for key, value in candidate.items() if isinstance(key, str) and key not in {"raw", "transcript", "response", "tool_output"}}
    result: dict[str, Any] = {}
    for field in (
        "title", "claim", "benefit", "classification", "domain", "scope", "evidence_refs", "applicability", "source_hash",
        "source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families",
    ):
        value = getattr(candidate, field, None)
        if value is not None:
            result[field] = value
    return result


def _processing_result(provider_id: str, result: ProviderResult, candidate: Any) -> GateDecision:
    status = result.error_code or "PROVIDER_FAILED"
    if not _SAFE_PROCESSING_REASON.fullmatch(status):
        status = "PROVIDER_FAILED"
    decision = "DEFERRED" if result.deferred else "FAILED"
    scope = _candidate_value(candidate, "applicability_scope", "universal")
    raw_ids = candidate.get("applicable_host_ids", ()) if isinstance(candidate, Mapping) else getattr(candidate, "applicable_host_ids", ())
    raw_families = candidate.get("applicable_host_families", ()) if isinstance(candidate, Mapping) else getattr(candidate, "applicable_host_families", ())
    host_ids = tuple(item for item in raw_ids if isinstance(item, str)) if isinstance(raw_ids, (list, tuple)) else ()
    host_families = tuple(item for item in raw_families if isinstance(item, str)) if isinstance(raw_families, (list, tuple)) else ()
    return GateDecision(
        decision,
        status,
        _candidate_value(candidate, "title"),
        "",
        (),
        "",
        _candidate_value(candidate, "classification", "private-reusable") or "private-reusable",
        0.0,
        provider_id or result.provider_id,
        processing_state=status,
        retry_after_seconds=result.retry_after_seconds,
        next_eligible_at=result.next_eligible_at,
        source_host_id=_candidate_value(candidate, "source_host_id"),
        source_host_family=_candidate_value(candidate, "source_host_family"),
        applicability_scope=scope if scope in {"universal", "family", "host"} else "universal",
        applicable_host_ids=host_ids,
        applicable_host_families=host_families,
    )


def decide_inheritance(
    candidate: Any,
    provider: Any,
    budget: InferenceBudget | Mapping[str, Any] | None = None,
) -> GateDecision:
    title = _candidate_value(candidate, "candidate_title", _candidate_value(candidate, "title"))
    claim = _candidate_value(candidate, "candidate_claim", _candidate_value(candidate, "claim"))
    classification = _candidate_value(candidate, "classification", "private-reusable") or "private-reusable"
    source_host_id = _candidate_value(candidate, "source_host_id")
    source_host_family = _candidate_value(candidate, "source_host_family")
    source_kind = _candidate_value(candidate, "source_kind", classification)
    source_ref = _candidate_value(candidate, "source_ref", "candidate")
    privacy = inspect_text("\n".join((title, claim)), source_kind, source_ref)
    if privacy.reason_code not in {"CLASSIFIED", "CLIENT_CONFIDENTIAL_LOCAL_ONLY", "GENERALIZATION_VERIFIED"}:
        return GateDecision("NO", "secret_or_confidential", "", "", (), "", "private-reusable", 1.0, "privacy-gate", source_host_id=source_host_id, source_host_family=source_host_family)
    if not claim:
        return GateDecision("NO", "no_evidence", "", "", (), "", classification, 0.0, "input-gate", source_host_id=source_host_id, source_host_family=source_host_family)
    if provider is None:
        return GateDecision("FAILED", "PROVIDER_UNAVAILABLE", title, "", (), "", classification, 0.0, "none", processing_state="PROVIDER_UNAVAILABLE", source_host_id=source_host_id, source_host_family=source_host_family)
    try:
        if isinstance(provider, ProviderResult):
            result = provider
        elif isinstance(provider, Mapping):
            result = ProviderResult("manual-structured", "success", output=provider, schema_name="gate-decision")
        else:
            generated = provider.generate("gate-decision", _candidate_input(candidate), InferenceBudget.from_value(budget))
            result = generated if isinstance(generated, ProviderResult) else ProviderResult("provider", "success", output=generated, schema_name="gate-decision")
    except Exception as exc:
        return GateDecision("FAILED", type(exc).__name__, title, "", (), "", classification, 0.0, getattr(provider, "provider_id", "provider"), processing_state="PROVIDER_EXCEPTION", source_host_id=source_host_id, source_host_family=source_host_family)
    if not result.ok:
        return _processing_result(getattr(provider, "provider_id", result.provider_id), result, candidate)
    try:
        output = validate_output("gate-decision", result.output or {})
        decision = GateDecision.from_mapping(
            output,
            provider_id=result.provider_id,
            source_host_id=source_host_id,
            source_host_family=source_host_family,
        )
    except (ValueError, TypeError) as exc:
        del exc
        return GateDecision("FAILED", "MALFORMED_RESPONSE", title, "", (), "", classification, 0.0, result.provider_id, processing_state="MALFORMED_RESPONSE", source_host_id=source_host_id, source_host_family=source_host_family)
    if decision.decision == "YES":
        privacy = inspect_text("\n".join((decision.candidate_title, decision.candidate_claim, decision.benefit)), decision.classification, source_ref)
        if privacy.reason_code not in {"CLASSIFIED", "GENERALIZATION_VERIFIED"}:
            return GateDecision("NO", "secret_or_confidential", "", "", (), "", "private-reusable", 1.0, result.provider_id, source_host_id=source_host_id, source_host_family=source_host_family)
    return decision


def _record_aggregate(item: QueueItem, decision: GateDecision, settings: Any) -> None:
    path = Path(settings.paths.runtime_dir) / "gate-aggregate.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"schema_version": 1, "rows": {}}
    except (OSError, UnicodeError, json.JSONDecodeError):
        value = {"schema_version": 1, "rows": {}}
    if not isinstance(value, dict) or not isinstance(value.get("rows"), dict):
        value = {"schema_version": 1, "rows": {}}
    day = datetime.now(timezone.utc).date().isoformat()
    provider_class = "local" if item.provider_preference and item.provider_preference[0] in {"local-openai-compatible", "ollama"} else "subscription"
    key = f"{item.host_id}|{day}|{decision.reason_code}|{provider_class}"
    row = value["rows"].setdefault(key, {"host_id": item.host_id, "day": day, "reason_class": decision.reason_code, "provider_class": provider_class, "yes_count": 0, "no_count": 0})
    row["yes_count" if decision.decision == "YES" else "no_count"] += 1
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply_gate_decision(decision: GateDecision, item: QueueItem, settings: Any) -> ApplyResult:
    if not isinstance(decision, GateDecision) or not isinstance(item, QueueItem):
        raise ValueError("GATE_APPLY_INPUT_INVALID")
    if decision.decision == "NO":
        _record_aggregate(item, decision, settings)
        updated = transition_queue_item(item, QueueState.NO_DISCARDED, settings, reason_code=decision.reason_code)
        return ApplyResult(True, decision.reason_code, updated.state, updated, item.payload_ref is not None)
    if decision.decision == "DEFERRED":
        updated = transition_queue_item(item, QueueState.DEFERRED_QUOTA, settings, reason_code=decision.reason_code, next_eligible_at=decision.next_eligible_at)
        return ApplyResult(False, decision.reason_code, updated.state, updated, False)
    if decision.decision == "FAILED":
        updated = transition_queue_item(item, QueueState.FAILED, settings, reason_code=decision.reason_code)
        return ApplyResult(False, decision.reason_code, updated.state, updated, False)
    _record_aggregate(item, decision, settings)
    updated = transition_queue_item(item, QueueState.YES_CURATING, settings, reason_code="GATE_YES")
    return ApplyResult(True, "GATE_YES", updated.state, updated, False)


__all__ = ["ApplyResult", "GateDecision", "apply_gate_decision", "decide_inheritance"]
