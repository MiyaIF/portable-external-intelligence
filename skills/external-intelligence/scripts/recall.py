from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

sys.dont_write_bytecode = True

from _trusted_runtime import (
    BindingError,
    add_binding_arguments,
    invocation_script_path,
    load_binding,
    require_trusted_child,
    root_arguments,
    run_cli,
)


def _emit(value: dict[str, Any], code: int = 0) -> int:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return code


def _safe_result(stdout: str, returncode: int) -> dict[str, Any]:
    try:
        value = json.loads(stdout.strip() or "{}")
    except (TypeError, ValueError):
        value = {}
    if not isinstance(value, dict):
        value = {}
    if returncode:
        error_code = value.get("error_code")
        if not isinstance(error_code, str) or not error_code:
            error_code = "RECALL_FAILED"
        return {"status": "rejected", "error_code": error_code, "hits": [], "context": ""}
    allowed = (
        "status",
        "reason_code",
        "error_code",
        "arm",
        "hits",
        "context",
        "context_chars",
        "exposure_id",
        "query_fingerprint",
        "team_projection",
        "knowledge_stores",
    )
    result = {key: value[key] for key in allowed if key in value}
    if result.get("status") == "ok":
        result["status"] = "success"
    result.setdefault("status", "success")
    result.setdefault("hits", [])
    result.setdefault("context", "")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence-recall")
    add_binding_arguments(parser)
    parser.add_argument("--query", required=True)
    parser.add_argument("--host", default="")
    parser.add_argument("--domain", default="")
    parser.add_argument("--scope", action="append", default=[])
    parser.add_argument("--version", default="")
    parser.add_argument("--max-chars", type=int, default=5000)
    args = parser.parse_args(argv)
    if len(args.query) > 5000 or args.max_chars < 1:
        return _emit({"status": "rejected", "error_code": "RECALL_INPUT_INVALID"}, 2)
    try:
        script_path = invocation_script_path()
        binding = load_binding(args.runtime_root, args.engine_root, script_path=script_path)
        require_trusted_child(binding)
        command = [
            "recall",
            *root_arguments(binding),
            "--query",
            args.query,
            "--host",
            args.host,
            "--max-chars",
            str(args.max_chars),
            "--json",
        ]
        if args.domain:
            command.extend(("--domain", args.domain))
        for scope in args.scope:
            command.extend(("--scope", scope))
        if args.version:
            command.extend(("--version", args.version))
        completed = run_cli(binding, command, timeout=30)
        return _emit(_safe_result(completed.stdout, completed.returncode), completed.returncode)
    except BindingError as exc:
        return _emit({"status": "rejected", "error_code": exc.code, "hits": [], "context": ""}, 2)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        code = str(exc)
        safe = code if code and len(code) <= 80 and all(char.isalnum() or char in "_.:-" for char in code) else "RECALL_FAILED"
        return _emit({"status": "unavailable", "error_code": safe, "hits": [], "context": ""}, 0)


if __name__ == "__main__":
    raise SystemExit(main())
