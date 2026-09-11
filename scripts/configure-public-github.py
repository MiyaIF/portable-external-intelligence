"""Plan, apply, or verify the guarded GitHub public-repository boundary.

``plan`` is read-only. ``apply`` is the only subcommand that can call GitHub
or push, and it requires an independent approval artifact bound to the plan.
``verify``
fetches the resulting public repository into a separate directory and checks
that it is the same sanitized fresh root.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ei.github_publication import (  # noqa: E402
    GithubPublicationError,
    build_publication_plan,
    confirm_plan_approval,
    publish_publication_plan,
    validate_publication_record,
    verify_publication,
)
from ei.publication_policy import load_publication_policy  # noqa: E402
from ei.safe_fs import (  # noqa: E402
    SafeFilesystemError,
    assert_no_reparse_components,
    assert_safe_target,
    safe_atomic_write,
    safe_ensure_directory,
)


def _safe_input(path: Path) -> Path:
    target = assert_no_reparse_components(path)
    return assert_safe_target(
        target.parent,
        target,
        allow_missing=False,
        expected_type="file",
    )


def _safe_output(path: Path) -> Path:
    return assert_no_reparse_components(path)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(_safe_input(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, SafeFilesystemError) as exc:
        if isinstance(exc, SafeFilesystemError):
            raise GithubPublicationError(exc.code) from exc
        raise ValueError("GITHUB_PUBLICATION_INPUT_READ_FAILED") from exc


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    try:
        target = _safe_output(path)
        safe_ensure_directory(target.parent)
        return safe_atomic_write(
            target.parent,
            target,
            (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
    except SafeFilesystemError as exc:
        raise GithubPublicationError(exc.code) from exc


def _policy_path(args: argparse.Namespace) -> Path:
    return _safe_input(args.policy or ROOT / "release" / "publication-policy.json")


def _print(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _plan(args: argparse.Namespace) -> int:
    output_target = _safe_output(args.output)
    policy = load_publication_policy(_policy_path(args))
    observation = {"status": "unknown", "method": "offline_no_network"} if args.offline else None
    plan = build_publication_plan(
        args.source,
        policy,
        target_observation=observation,
        generated_at=args.generated_at,
    )
    output = _write_json(output_target, plan)
    _print(
        {
            "status": plan["status"],
            "plan_sha256": plan["plan_sha256"],
            "source_commit_sha": plan["source_commit_sha"],
            "source_tree_id": plan["source_tree_id"],
            "owner": plan["owner"],
            "repository": plan["repository"],
            "target_observation": plan["target_observation"],
            "output": output.name,
        }
    )
    return 0 if plan["status"] == "ready_for_confirmation" else 2


def _apply(args: argparse.Namespace) -> int:
    output_target = _safe_output(args.output)
    policy = load_publication_policy(_policy_path(args))
    plan_path = _safe_input(args.plan)
    approval_path = _safe_input(args.approval)
    try:
        same_artifact = plan_path == approval_path or plan_path.samefile(approval_path)
    except OSError:
        same_artifact = plan_path == approval_path
    if same_artifact:
        raise ValueError("GITHUB_PUBLICATION_APPROVAL_MUST_BE_SEPARATE")
    plan = _read_json(plan_path)
    if not isinstance(plan, dict):
        raise ValueError("GITHUB_PUBLICATION_PLAN_OBJECT_REQUIRED")
    approval = _read_json(approval_path)
    if not isinstance(approval, dict):
        raise ValueError("GITHUB_PUBLICATION_APPROVAL_OBJECT_REQUIRED")
    confirm_plan_approval(plan, approval)
    receipt = publish_publication_plan(
        args.source,
        plan,
        policy=policy,
        approval=approval,
    )
    output = _write_json(output_target, receipt)
    _print(
        {
            "status": receipt["status"],
            "receipt_sha256": receipt["receipt_sha256"],
            "repository_url": receipt["repository_url"],
            "source_commit_sha": receipt["source_commit_sha"],
            "output": output.name,
        }
    )
    return 0


def _verify(args: argparse.Namespace) -> int:
    output_target = _safe_output(args.output)
    assert_no_reparse_components(args.fresh_clone)
    policy = load_publication_policy(_policy_path(args))
    receipt = _read_json(args.receipt)
    if not isinstance(receipt, dict):
        raise ValueError("GITHUB_PUBLICATION_RECEIPT_OBJECT_REQUIRED")
    validate_publication_record(receipt)
    verified = verify_publication(
        receipt,
        policy,
        args.fresh_clone,
        python_executable=args.python,
        timeout_seconds=args.timeout_seconds,
    )
    output = _write_json(output_target, verified)
    _print(
        {
            "status": verified["status"],
            "receipt_sha256": verified["receipt_sha256"],
            "repository_url": verified["repository_url"],
            "source_commit_sha": verified["source_commit_sha"],
            "post_public_clone": verified["post_public_clone"],
            "output": output.name,
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="create a read-only publication plan")
    plan.add_argument("--source", type=Path, required=True)
    plan.add_argument("--policy", type=Path)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--offline", action="store_true", help="skip target probing and record an unknown target")
    plan.add_argument("--generated-at")
    plan.set_defaults(handler=_plan)

    apply = commands.add_parser("apply", help="create/configure/push after independent approval")
    apply.add_argument("--source", type=Path, required=True)
    apply.add_argument("--policy", type=Path)
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--approval", type=Path, required=True, help="independent owner approval artifact")
    apply.add_argument("--output", type=Path, required=True)
    apply.set_defaults(handler=_apply)

    verify = commands.add_parser("verify", help="verify a published repository from a fresh clone")
    verify.add_argument("--policy", type=Path)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--fresh-clone", type=Path, required=True)
    verify.add_argument("--python", type=Path)
    verify.add_argument("--timeout-seconds", type=float, default=300.0)
    verify.add_argument("--output", type=Path, required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (GithubPublicationError, OSError, TypeError, ValueError) as exc:
        code = getattr(exc, "code", str(exc).split(":", 1)[0])
        _print({"status": "failed", "error_code": str(code)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
