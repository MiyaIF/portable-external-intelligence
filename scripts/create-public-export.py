"""Create a fresh, sanitized public repository root from a clean source SHA."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ei.public_export import (  # noqa: E402
    PublicExportError,
    create_public_export,
    resume_public_export_validation,
    validate_public_export_receipt,
)
from ei.safe_fs import (  # noqa: E402
    SafeFilesystemError,
    assert_no_reparse_components,
    assert_safe_target,
    safe_atomic_write,
    safe_ensure_directory,
)


def _safe_existing(path: Path, *, expected_type: str) -> Path:
    target = assert_no_reparse_components(path)
    return assert_safe_target(
        target.parent,
        target,
        allow_missing=False,
        expected_type=expected_type,
    )


def _safe_optional_root(path: Path | None) -> Path | None:
    return assert_no_reparse_components(path) if path is not None else None


def _write_receipt(path: Path, value: dict[str, object]) -> None:
    try:
        target = assert_no_reparse_components(path)
        safe_ensure_directory(target.parent)
        safe_atomic_write(
            target.parent,
            target,
            (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
    except SafeFilesystemError as exc:
        raise PublicExportError(exc.code) from exc


def _repeat_check(
    args: argparse.Namespace,
    first: object,
    *,
    source: Path,
    policy: Path,
    allowlist: Path,
    knowledge_root: Path | None,
    runtime_root: Path | None,
    python_executable: Path | None,
) -> None:
    if not args.verify_repeat:
        return
    destination = assert_no_reparse_components(getattr(first, "destination"))
    with tempfile.TemporaryDirectory(prefix=".ei-public-repeat-", dir=str(destination.parent)) as temporary:
        second = create_public_export(
            source,
            Path(temporary),
            policy_path=policy,
            allowlist_path=allowlist,
            expected_source_commit=args.expected_source_sha,
            knowledge_root=knowledge_root,
            runtime_root=runtime_root,
            validate=False,
            python_executable=python_executable,
            timeout_seconds=args.timeout_seconds,
        )
        first_receipt = getattr(first, "receipt")
        if second.receipt["public_tree_id"] != first_receipt["public_tree_id"] or second.receipt["public_tree_sha256"] != first_receipt["public_tree_sha256"]:
            raise PublicExportError("PUBLIC_EXPORT_DETERMINISM_MISMATCH")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=None)
    parser.add_argument("--allowlist", type=Path, default=None)
    parser.add_argument("--receipt", type=Path, default=None)
    parser.add_argument("--expected-source-sha", "--source-commit", dest="expected_source_sha")
    parser.add_argument("--knowledge-root", type=Path, default=None)
    parser.add_argument("--runtime-root", type=Path, default=None)
    parser.add_argument("--python", dest="python", default=None)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--skip-validation", action="store_true", help="Create an explicitly unvalidated export for local structural tests")
    parser.add_argument(
        "--resume-validation",
        action="store_true",
        help="Validate an existing export only after deterministic source/tree verification",
    )
    parser.add_argument("--no-repeat-check", dest="verify_repeat", action="store_false")
    parser.set_defaults(verify_repeat=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source = _safe_existing(args.source, expected_type="dir")
        policy = _safe_existing(
            args.policy or source / "release" / "publication-policy.json",
            expected_type="file",
        )
        allowlist = _safe_existing(
            args.allowlist or source / "config" / "public-export-allowlist.json",
            expected_type="file",
        )
        destination = assert_no_reparse_components(args.destination)
        receipt_path = assert_no_reparse_components(
            args.receipt
            or args.destination.with_name(args.destination.name + "-receipt.json")
        )
        knowledge_root = _safe_optional_root(args.knowledge_root)
        runtime_root = _safe_optional_root(args.runtime_root)
        python_executable = (
            _safe_existing(Path(args.python), expected_type="file")
            if args.python is not None
            else None
        )
        if args.resume_validation and args.skip_validation:
            raise PublicExportError("PUBLIC_EXPORT_RESUME_VALIDATION_REQUIRED")
        if args.resume_validation:
            result = resume_public_export_validation(
                source,
                destination,
                policy_path=policy,
                allowlist_path=allowlist,
                receipt_path=receipt_path,
                expected_source_commit=args.expected_source_sha,
                knowledge_root=knowledge_root,
                runtime_root=runtime_root,
                python_executable=python_executable,
                timeout_seconds=args.timeout_seconds,
            )
        else:
            result = create_public_export(
                source,
                destination,
                policy_path=policy,
                allowlist_path=allowlist,
                expected_source_commit=args.expected_source_sha,
                knowledge_root=knowledge_root,
                runtime_root=runtime_root,
                validate=not args.skip_validation,
                python_executable=python_executable,
                timeout_seconds=args.timeout_seconds,
            )
            _repeat_check(
                args,
                result,
                source=source,
                policy=policy,
                allowlist=allowlist,
                knowledge_root=knowledge_root,
                runtime_root=runtime_root,
                python_executable=python_executable,
            )
            _write_receipt(receipt_path, result.receipt)
        validate_public_export_receipt(result.receipt)
        value = {
            "status": result.receipt["status"],
            "public_root_sha": result.receipt["public_root_sha"],
            "public_tree_id": result.receipt["public_tree_id"],
            "selected_file_count": result.receipt["selected_file_count"],
            "receipt_sha256": result.receipt["receipt_sha256"],
            "receipt": receipt_path.name,
        }
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (PublicExportError, SafeFilesystemError) as exc:
        print(json.dumps({"status": "failed", "error_code": exc.code}, ensure_ascii=False, sort_keys=True))
        return 1
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error_code": type(exc).__name__}, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
