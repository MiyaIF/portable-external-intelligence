from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ei.publication_audit import audit_repository  # noqa: E402
from ei.publication_policy import PublicationPolicyError, load_publication_policy  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a repository for public release safety")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--working-tree", action="store_true")
    parser.add_argument("--reachable-history", action="store_true")
    parser.add_argument("--require-scanner-receipts", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_publication_policy(args.policy)
    except PublicationPolicyError as exc:
        value = {"status": "failed", "error_code": exc.code}
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
        return 2
    result = audit_repository(
        args.repo,
        policy,
        working_tree=args.working_tree or not args.reachable_history,
        reachable_history=args.reachable_history,
        require_scanner_receipts=args.require_scanner_receipts,
    )
    value = result.to_dict()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
