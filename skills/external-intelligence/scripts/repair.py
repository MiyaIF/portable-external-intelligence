from __future__ import annotations

import argparse
import json
import subprocess
import sys

sys.dont_write_bytecode = True

from _trusted_runtime import BindingError, add_binding_arguments, load_binding, require_trusted_child, root_arguments, run_cli


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence-repair")
    add_binding_arguments(parser)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 3600:
        sys.stdout.write('{"status":"rejected","error_code":"TIMEOUT_INVALID"}\n')
        return 2
    try:
        binding = load_binding(args.runtime_root, args.engine_root)
        require_trusted_child(binding)
    except BindingError as exc:
        sys.stdout.write(json.dumps({"status": "rejected", "error_code": exc.code}, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    command = ["doctor", *root_arguments(binding), "--json", "--strict"]
    try:
        completed = run_cli(binding, command, timeout=args.timeout)
        try:
            value = json.loads(completed.stdout.strip() or "{}")
        except (TypeError, ValueError):
            value = {}
        if not isinstance(value, dict):
            value = {}
        result = {"status": "doctor_guided", "doctor_ok": bool(value.get("ok", False)), "findings": value.get("findings", []) if isinstance(value.get("findings", []), list) else []}
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        return completed.returncode
    except (OSError, subprocess.SubprocessError):
        sys.stdout.write('{"status":"blocked","error_code":"CLI_UNAVAILABLE"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
