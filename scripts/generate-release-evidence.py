from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ei.publication_policy import load_publication_policy, policy_digest  # noqa: E402
from ei.release import build_public_evidence_index, evaluate_public_completion  # noqa: E402
from ei.safe_fs import absolute_path, assert_no_reparse_components, assert_safe_target, safe_atomic_write, safe_ensure_directory  # noqa: E402


def _read_json(path: Path) -> Any:
    try:
        target = assert_no_reparse_components(path)
        target = assert_safe_target(target.parent, target, allow_missing=False, expected_type="file")
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("RELEASE_EVIDENCE_INPUT_READ_FAILED") from exc


def _parse_ci_run(value: str) -> dict[str, Any]:
    parts = value.split(":", 3)
    if len(parts) != 4:
        raise ValueError("RELEASE_CI_RUN_FORMAT_INVALID")
    workflow, run_id, conclusion, head_sha = parts
    if not workflow or not run_id or not conclusion or not head_sha:
        raise ValueError("RELEASE_CI_RUN_FORMAT_INVALID")
    try:
        parsed_id = int(run_id)
    except ValueError as exc:
        raise ValueError("RELEASE_CI_RUN_ID_INVALID") from exc
    return {"workflow": workflow, "run_id": parsed_id, "conclusion": conclusion, "head_sha": head_sha}


def _parse_receipt(value: str) -> dict[str, str]:
    receipt_type, separator, receipt_hash = value.partition("=")
    if not separator or not receipt_type or not receipt_hash:
        raise ValueError("RELEASE_RECEIPT_FORMAT_INVALID")
    return {"receipt_type": receipt_type, "receipt_sha256": receipt_hash}


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    target = absolute_path(path)
    assert_no_reparse_components(target.parent)
    safe_ensure_directory(target.parent)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return safe_atomic_write(target.parent, target, data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate canonical public release evidence")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=ROOT / "release" / "publication-policy.json")
    parser.add_argument("--publication-policy-sha256")
    parser.add_argument("--subject-commit")
    parser.add_argument("--evidence-commit")
    parser.add_argument("--public-tree-audit-sha256")
    parser.add_argument("--workflow-sha256")
    parser.add_argument("--package-sha256")
    parser.add_argument("--sbom-sha256")
    parser.add_argument("--ci-runs", type=Path)
    parser.add_argument("--ci-run", action="append", default=[], metavar="WORKFLOW:RUN_ID:CONCLUSION:HEAD_SHA")
    parser.add_argument("--receipt", action="append", default=[], metavar="TYPE=SHA256")
    parser.add_argument("--production-evidence", type=Path)
    parser.add_argument("--effect-evidence", type=Path)
    parser.add_argument("--export-receipt", type=Path)
    parser.add_argument("--publication-receipt", type=Path)
    parser.add_argument("--release-receipts", type=Path)
    parser.add_argument("--security-evidence", type=Path)
    parser.add_argument("--completion-output", type=Path)
    parser.add_argument("--generated-at")
    args = parser.parse_args(argv)
    try:
        if args.publication_policy_sha256:
            policy_hash = args.publication_policy_sha256
        else:
            policy_hash = policy_digest(load_publication_policy(args.policy))
        ci_runs: Any = _read_json(args.ci_runs) if args.ci_runs else None
        if args.ci_run:
            if ci_runs is not None:
                raise ValueError("RELEASE_CI_INPUT_CONFLICT")
            ci_runs = [_parse_ci_run(value) for value in args.ci_run]
        receipts = [_parse_receipt(value) for value in args.receipt]
        production = _read_json(args.production_evidence) if args.production_evidence else None
        effect = _read_json(args.effect_evidence) if args.effect_evidence else None
        value = build_public_evidence_index(
            publication_policy_sha256=policy_hash,
            subject_commit_sha=args.subject_commit,
            evidence_commit_sha=args.evidence_commit,
            public_tree_audit_sha256=args.public_tree_audit_sha256,
            workflow_sha256=args.workflow_sha256,
            ci_runs=ci_runs,
            package_sha256=args.package_sha256,
            sbom_sha256=args.sbom_sha256,
            receipt_index=receipts,
            production_evidence=production,
            generated_at=args.generated_at,
        )
        output = _write_json(args.output, value)
        result: dict[str, Any] = {
            "status": value["status"],
            "index_sha256": value["index_sha256"],
            "output": output.name,
        }
        final_requested = any(
            item is not None
            for item in (
                args.export_receipt,
                args.publication_receipt,
                args.release_receipts,
                args.security_evidence,
                args.effect_evidence,
                args.completion_output,
            )
        )
        if final_requested:
            completion = evaluate_public_completion(
                evidence_index=value,
                export_receipt=_read_json(args.export_receipt) if args.export_receipt else None,
                publication_receipt=_read_json(args.publication_receipt) if args.publication_receipt else None,
                release_receipts=_read_json(args.release_receipts) if args.release_receipts else None,
                security_evidence=_read_json(args.security_evidence) if args.security_evidence else None,
                production_evidence=production,
                effect_evidence=effect,
            )
            completion_value = completion.to_dict()
            if args.completion_output:
                completion_path = _write_json(args.completion_output, completion_value)
                result["completion_output"] = completion_path.name
            result["gates"] = completion_value
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if final_requested:
            return 0 if all(
                (
                    completion.public_source_ready,
                    completion.public_release_ready,
                    completion.production_complete,
                    completion.effect_validated is True,
                )
            ) else 1
        return 0
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc).split(":", 1)[0]}, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
