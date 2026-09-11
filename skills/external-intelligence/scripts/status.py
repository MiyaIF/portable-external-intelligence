from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

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
    repo = binding.engine_root
    runtime = binding.runtime_root
    manifest = _read_json(runtime / "install-manifest.json")
    provider_configured = bool(manifest.get("providers")) or (repo / "config" / "inference-providers.json").is_file()
    skill_file = Path(__file__).resolve().parents[1] / "SKILL.md"
    doctor = _cli_status(binding)
    queue_dir = runtime / "queue"
    spool_dir = runtime / "spool"
    experiment_enabled = bool(manifest.get("experiment_enabled", False))
    sync_enabled = bool(manifest.get("sync_enabled", False))
    result = {
        "status": "success",
        "Hook": {"status": "VERIFIED" if doctor.get("ok") is True else "UNVERIFIED", "doctor_ok": doctor.get("ok") is True},
        "Skill": {"status": "AVAILABLE" if skill_file.is_file() else "MISSING", "tree_hash": hashlib.sha256(skill_file.read_bytes()).hexdigest() if skill_file.is_file() else ""},
        "queue": {"status": "READY" if queue_dir.is_dir() else "NOT_INITIALIZED", "present": queue_dir.is_dir()},
        "spool": {"status": "READY" if spool_dir.is_dir() else "NOT_INITIALIZED", "present": spool_dir.is_dir()},
        "provider": {"status": "CONFIGURED" if provider_configured else "DEFAULT_ORDER", "cloud_spend_cap": 0},
        "sync": {"status": "ENABLED" if sync_enabled else "DISABLED", "enabled": sync_enabled},
        "experiment": {"status": "ENABLED" if experiment_enabled else "DISABLED", "enabled": experiment_enabled, "experiment_id": str(manifest.get("experiment_id", "retrieval-v1"))},
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
