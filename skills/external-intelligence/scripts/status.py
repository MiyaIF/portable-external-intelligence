from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

sys.dont_write_bytecode = True

from _trusted_runtime import BindingError, RuntimeBinding, add_binding_arguments, load_binding, require_trusted_child, root_arguments, run_cli


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _cli_status(binding: RuntimeBinding) -> dict[str, Any]:
    command = ["doctor", *root_arguments(binding), "--json"]
    try:
        completed = run_cli(binding, command, timeout=120)
        value = json.loads(completed.stdout.strip() or "{}")
        return value if isinstance(value, dict) else {}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return {}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _summarize_queue(check: Mapping[str, Any] | None) -> dict[str, Any]:
    check = _mapping(check)
    health = _mapping(check.get("health"))
    names = ("corrupt", "needs_attention", "deferred", "retryable", "ready", "in_progress", "emergency_items")
    if any(type(health.get(name)) is not int or health[name] < 0 for name in names):
        return {"status": "UNKNOWN", "reason_code": "QUEUE_HEALTH_UNAVAILABLE"}
    stale = check.get("stale_leases")
    if type(stale) is not int or stale < 0:
        return {"status": "UNKNOWN", "reason_code": "QUEUE_HEALTH_UNAVAILABLE"}
    if health["corrupt"] or health["needs_attention"] or stale:
        status = "NEEDS_ATTENTION"
    elif health["deferred"] or health["retryable"]:
        status = "DEFERRED"
    elif health["in_progress"]:
        status = "PROCESSING"
    elif health["ready"] or health["emergency_items"]:
        status = "PENDING"
    else:
        status = "READY"
    return {"status": status, **{key: health[key] for key in names}, "stale_leases": stale}


def _summarize_doctor(doctor: Mapping[str, Any]) -> dict[str, Any]:
    check_rows = doctor.get("checks", ())
    checks = {row.get("name"): row for row in check_rows if isinstance(row, Mapping) and isinstance(row.get("name"), str)} if isinstance(check_rows, (list, tuple)) else {}
    host_rows = _mapping(checks.get("hosts")).get("hosts", ())
    hooks: dict[str, Any] = {}
    skills: dict[str, Any] = {}
    for row in host_rows if isinstance(host_rows, (list, tuple)) else ():
        if not isinstance(row, Mapping) or not isinstance(row.get("host_id"), str):
            continue
        hook = _mapping(row.get("hook"))
        live = _mapping(hook.get("live"))
        verified = (live.get("hook_status") == "HOOK_VERIFIED"
                    and _mapping(hook.get("static")).get("valid") is True
                    and hook.get("ok") is True)
        hooks[row["host_id"]] = {"status": "VERIFIED" if verified else "UNVERIFIED",
                                 "hook_status": live.get("hook_status", "HOOK_UNVERIFIED")}
        skill = _mapping(row.get("skill"))
        hashes = [skill.get(key) for key in ("source_hash", "installed_hash", "actual_hash")]
        matched = all(isinstance(value, str) and value for value in hashes) and hashes[0] == hashes[1] == hashes[2]
        available = matched and _mapping(skill.get("binding")).get("ok") is True and skill.get("ok") is True
        skills[row["host_id"]] = {"status": "AVAILABLE" if available else "UNVERIFIED" if skill else "UNKNOWN",
                                  "tree_hash": skill.get("actual_hash") or "",
                                  "hashes_match": matched}
    hook_status = "VERIFIED" if hooks and all(row["status"] == "VERIFIED" for row in hooks.values()) else "UNVERIFIED"
    skill_status = "AVAILABLE" if skills and all(row["status"] == "AVAILABLE" for row in skills.values()) else "UNVERIFIED" if any(row["status"] == "UNVERIFIED" for row in skills.values()) else "UNKNOWN"
    queue = _summarize_queue(checks.get("queue"))
    spool_check = _mapping(checks.get("spool"))
    spool = {"status": "UNKNOWN"}
    if isinstance(spool_check.get("health"), Mapping):
        invalid = spool_check.get("invalid_envelopes")
        expired = spool_check.get("expired_envelopes")
        if type(invalid) is int and type(expired) is int:
            spool = {"status": "NEEDS_ATTENTION" if invalid or spool_check.get("reason_code") else "PENDING" if expired else "READY",
                     "invalid_envelopes": invalid, "expired_envelopes": expired}
    provider_check = _mapping(checks.get("provider"))
    organizer = _mapping(provider_check.get("organizer"))
    provider = {"status": "UNKNOWN", "organizer": dict(organizer),
                "cloud_spend_cap": provider_check.get("cloud_spend_cap")}
    if organizer:
        provider["status"] = "CONFIGURED" if organizer.get("status") == "READY" and provider_check.get("eligible", 0) else "DEFERRED"
    projection = _mapping(checks.get("projection"))
    result = {
        "Hook": {"status": hook_status, "doctor_ok": doctor.get("ok") is True, "hosts": hooks},
        "Skill": {"status": skill_status, "hosts": skills,
                  "tree_hash": next(iter(skills.values()))["tree_hash"] if len(skills) == 1 else ""},
        "queue": queue, "spool": spool, "provider": provider,
        "maintenance": {key: checks.get("maintenance", {}).get(key) for key in ("status", "reason_code", "requested", "last_recorded_status", "continuous_execution_verified")},
        "projection": {key: projection[key] for key in ("freshness", "reason_code", "active_patterns", "candidate_patterns", "observation_count", "source_observation_count", "candidate_diagnostics") if key in projection},
    }
    states = [hook_status, skill_status, queue["status"], spool["status"], provider["status"]]
    other_failure = doctor.get("ok") is False or any(
        row.get("ok") is False or (row.get("reason_code") and name not in {"projection", "maintenance", "scheduler", "team"})
        for name, row in checks.items()
    )
    if other_failure or any(state in {"NEEDS_ATTENTION", "DEFERRED"} for state in states) or projection.get("freshness") == "STALE":
        result["health_status"] = "degraded"
    elif "UNKNOWN" in states or "UNVERIFIED" in states or projection.get("freshness") != "CURRENT":
        result["health_status"] = "unknown"
    else:
        result["health_status"] = "healthy"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence-status")
    add_binding_arguments(parser)
    args = parser.parse_args(argv)
    try:
        binding = load_binding(args.runtime_root, args.engine_root)
        require_trusted_child(binding)
    except BindingError as exc:
        sys.stdout.write(json.dumps({"status": "rejected", "error_code": exc.code}, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    runtime = binding.runtime_root
    manifest = _read_json(runtime / "install-manifest.json")
    doctor = _cli_status(binding)
    queue_dir = runtime / "queue"
    spool_dir = runtime / "spool"
    experiment_enabled = bool(manifest.get("experiment_enabled", False))
    sync_enabled = bool(manifest.get("sync_enabled", False))
    result = {
        "status": "success",
        **_summarize_doctor(doctor),
        "sync": {"status": "ENABLED" if sync_enabled else "DISABLED", "enabled": sync_enabled},
        "experiment": {"status": "ENABLED" if experiment_enabled else "DISABLED", "enabled": experiment_enabled, "experiment_id": str(manifest.get("experiment_id", "retrieval-v1"))},
    }
    result["queue"]["present"] = queue_dir.is_dir()
    result["spool"]["present"] = spool_dir.is_dir()
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
