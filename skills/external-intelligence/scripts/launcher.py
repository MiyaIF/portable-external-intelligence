from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import json
import os
import runpy
from pathlib import Path

from _trusted_runtime import (
    BindingError,
    invocation_script_path,
    is_isolated_python,
    isolated_environment,
    load_binding,
)


_MODES = frozenset({"recall", "closeout", "maintain", "sync", "repair", "status"})


def _emit(code: str) -> int:
    sys.stdout.write(json.dumps({"status": "rejected", "error_code": code}, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="external-intelligence")
    parser.add_argument("--engine-root", "--repo", dest="engine_root", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("mode", choices=sorted(_MODES))
    args, remainder = parser.parse_known_args(argv)
    try:
        launcher = invocation_script_path()
        binding = load_binding(args.runtime_root, args.engine_root, script_path=launcher)
        if not is_isolated_python(binding):
            raise BindingError("SKILL_LAUNCHER_ISOLATION_REQUIRED")
        environment = isolated_environment(binding)
        environment["EI_SKILL_TRUSTED_CHILD"] = "1"
        os.environ.clear()
        os.environ.update(environment)
        target = launcher.parent / f"{args.mode}.py"
        if target.is_symlink() or not target.is_file() or target.parent != launcher.parent:
            raise BindingError("SKILL_SCRIPT_MISSING")
        sys.argv = [
            str(target),
            "--engine-root",
            str(binding.engine_root),
            "--runtime-root",
            str(binding.runtime_root),
            *remainder,
        ]
        runpy.run_path(str(target), run_name="__main__")
        return 0
    except BindingError as exc:
        return _emit(exc.code)


if __name__ == "__main__":
    raise SystemExit(main())
