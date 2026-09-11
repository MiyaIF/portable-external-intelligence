from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

sys.dont_write_bytecode = True

from _trusted_runtime import BindingError, add_binding_arguments, load_binding, require_trusted_child, root_arguments, run_cli


def _result(stdout: str, returncode: int) -> dict[str, Any]:
    try:
        value = json.loads(stdout.strip() or "{}")
    except (TypeError, ValueError):
        value = {}
    if not isinstance(value, dict):
        value = {}
    allowed = ("ok", "reason_code", "status", "branch", "remote", "ahead", "behind")
    result = {key: value[key] for key in allowed if key in value}
    result.setdefault("status", "blocked" if returncode else "success")
    if returncode:
        result.setdefault("reason_code", "SYNC_BLOCKED")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence-sync")
    add_binding_arguments(parser)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 3600:
        sys.stdout.write('{"status":"rejected","error_code":"TIMEOUT_INVALID"}\n')
        return 2
    try:
        binding = load_binding(args.runtime_root, args.engine_root)
        require_trusted_child(binding)
    except BindingError as exc:
        sys.stdout.write(json.dumps({"status": "rejected", "reason_code": exc.code}, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    command = ["sync", *root_arguments(binding), "--json"]
    if args.dry_run:
        command.append("--dry-run")
    try:
        completed = run_cli(binding, command, timeout=args.timeout)
        value = _result(completed.stdout, completed.returncode)
        sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        return completed.returncode
    except (OSError, subprocess.SubprocessError):
        sys.stdout.write('{"status":"blocked","reason_code":"CLI_UNAVAILABLE"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
