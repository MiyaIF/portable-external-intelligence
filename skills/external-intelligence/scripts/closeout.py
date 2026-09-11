from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Mapping

sys.dont_write_bytecode = True

from _trusted_runtime import (
    BindingError,
    activate_engine,
    add_binding_arguments,
    invocation_script_path,
    load_binding,
    require_trusted_child,
)


_MAX_INPUT = 2 * 1024 * 1024


def _emit(value: Mapping[str, Any], code: int = 0) -> int:
    sys.stdout.write(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return code


def _read_input() -> bytes:
    raw = sys.stdin.buffer.read(_MAX_INPUT + 1)
    if len(raw) > _MAX_INPUT:
        raise ValueError("CLOSEOUT_INPUT_TOO_LARGE")
    return raw


def _one_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("CLOSEOUT_UTF8_INVALID") from exc
    decoder = json.JSONDecoder()
    stripped = text.lstrip()
    try:
        value, end = decoder.raw_decode(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError("CLOSEOUT_JSON_INVALID") from exc
    if stripped[end:].strip():
        raise ValueError("CLOSEOUT_MULTIPLE_JSON")
    if not isinstance(value, dict):
        raise ValueError("CLOSEOUT_OBJECT_REQUIRED")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence-closeout")
    add_binding_arguments(parser)
    args = parser.parse_args(argv)
    try:
        script_path = invocation_script_path()
        binding = load_binding(args.runtime_root, args.engine_root, script_path=script_path)
        require_trusted_child(binding)
        raw_input = _read_input()
        if os.environ.get("EI_INTERNAL") == "1":
            return _emit({"status": "skipped", "reason_code": "RECURSION_GUARD"})
        os.environ["EI_INTERNAL"] = "1"
        activate_engine(binding)
        payload = _one_object(raw_input)
        gate = payload.get("gate_decision", payload)
        if not isinstance(gate, Mapping):
            raise ValueError("GATE_DECISION_OBJECT_REQUIRED")
        decision = str(gate.get("decision", ""))
        if decision != "YES":
            reason = str(gate.get("reason_code", "NO_CHANGE"))
            return _emit({"status": "not_inherited", "decision": "NO", "reason_code": reason[:80]})
        from ei.changeset import validate_changeset
        from ei.config import load_settings
        from ei.curator import curate_candidate
        from ei.gate import GateDecision
        from ei.index import build_index

        candidate = dict(payload.get("candidate", {})) if isinstance(payload.get("candidate"), Mapping) else {}
        trusted_source_host_id = candidate.get("source_host_id", "")
        trusted_source_host_family = candidate.get("source_host_family", "")
        if not isinstance(trusted_source_host_id, str) or not isinstance(trusted_source_host_family, str):
            raise ValueError("CLOSEOUT_SOURCE_HOST_PAIR_INVALID")
        required = {
            "decision": gate.get("decision"),
            "reason_code": gate.get("reason_code"),
            "candidate_title": gate.get("candidate_title", ""),
            "candidate_claim": gate.get("candidate_claim", ""),
            "evidence_refs": gate.get("evidence_refs", []),
            "benefit": gate.get("benefit", ""),
            "classification": gate.get("classification", "private-reusable"),
            "confidence": gate.get("confidence", 0),
            "applicability_scope": gate.get("applicability_scope"),
            "applicable_host_ids": gate.get("applicable_host_ids"),
            "applicable_host_families": gate.get("applicable_host_families"),
        }
        if any(required[field] is None for field in ("applicability_scope", "applicable_host_ids", "applicable_host_families")):
            raise ValueError("GATE_YES_APPLICABILITY_REQUIRED")
        provider_value = gate.get("provider_id", "manual")
        if not isinstance(provider_value, str):
            raise ValueError("GATE_PROVIDER_ID_INVALID")
        gate_decision = GateDecision.from_mapping(
            required,
            provider_id=provider_value,
            source_host_id=trusted_source_host_id,
            source_host_family=trusted_source_host_family,
        )
        candidate.update({
            "decision": "YES",
            "candidate_title": gate_decision.candidate_title,
            "candidate_claim": gate_decision.candidate_claim,
            "benefit": gate_decision.benefit,
            "classification": gate_decision.classification,
            "evidence_refs": list(gate_decision.evidence_refs),
            "source_host_id": gate_decision.source_host_id,
            "source_host_family": gate_decision.source_host_family,
            "applicability_scope": gate_decision.applicability_scope,
            "applicable_host_ids": list(gate_decision.applicable_host_ids),
            "applicable_host_families": list(gate_decision.applicable_host_families),
        })
        settings = load_settings(
            engine_root=binding.engine_root,
            personal_knowledge_root=binding.personal_knowledge_root,
            team_knowledge_root=binding.team_knowledge_root,
            runtime_root=binding.runtime_root,
        )
        knowledge = settings.paths.knowledge_dir
        index = build_index(knowledge, knowledge / "index.json") if (knowledge / "index.json").is_file() else None
        changeset = curate_candidate(candidate, index, {"provider_id": gate_decision.provider_id or "manual"}, None)
        validation = validate_changeset(changeset, settings)
        result: dict[str, Any] = {
            "status": "changeset_ready" if validation.valid else "changeset_rejected",
            "decision": "YES",
            "changeset": changeset.to_dict(),
        }
        result["validation"] = {"valid": validation.valid, "reason_codes": list(validation.reason_codes)}
        return _emit(result, 0 if result["status"] != "changeset_rejected" else 2)
    except BindingError as exc:
        return _emit({"status": "rejected", "error_code": exc.code}, 2)
    except (ValueError, OSError, TypeError, ImportError) as exc:
        code = str(exc)
        safe = code if code and len(code) <= 80 and all(char.isalnum() or char in "_.:-" for char in code) else "CLOSEOUT_REJECTED"
        return _emit({"status": "rejected", "error_code": safe}, 2)


if __name__ == "__main__":
    raise SystemExit(main())
