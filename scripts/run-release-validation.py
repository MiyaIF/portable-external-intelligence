from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ei.test_runner import TestRunnerError, run_complete_suite  # noqa: E402


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run every tracked unittest module in bounded child processes")
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--jobs", type=_positive_int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--output", default="artifacts/unittest-summary.json")
    parser.add_argument("--log-dir", default=None)
    parser.add_argument("--python", dest="python_executable", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_complete_suite(
            args.repo,
            output=args.output,
            jobs=args.jobs,
            timeout_seconds=args.timeout_seconds,
            python_executable=args.python_executable,
            log_dir=args.log_dir,
            progress_stream=sys.stdout,
        )
    except TestRunnerError as exc:
        print(json.dumps({"successful": False, "error_code": str(exc).split(":", 1)[0]}, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(summary.to_dict(repo_root=Path(args.repo).expanduser().resolve()), ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if summary.successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
