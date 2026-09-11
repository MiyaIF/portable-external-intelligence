from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ei.release import (  # noqa: E402
    ReleaseManifest,
    build_release_attestation,
    build_public_release_attestation,
    evaluate_public_completion,
    verify_release_attestation,
    validate_public_evidence_index,
    verify_public_release_attestation,
)
from ei.safe_fs import absolute_path, assert_no_reparse_components, assert_safe_target, safe_atomic_write, safe_ensure_directory  # noqa: E402


def _read(path: Path) -> Any:
    try:
        target = assert_no_reparse_components(path)
        target = assert_safe_target(target.parent, target, allow_missing=False, expected_type="file")
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("RELEASE_INPUT_READ_FAILED") from exc


def _write(path: Path, value: Mapping[str, Any]) -> Path:
    target = absolute_path(path)
    assert_no_reparse_components(target.parent)
    safe_ensure_directory(target.parent)
    data = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return safe_atomic_write(target.parent, target, data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify or create a post-push release evidence attestation")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-commit")
    parser.add_argument("--prerequisites", type=Path)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--attestation-output", type=Path)
    parser.add_argument("--certification-artifact", action="append", default=[])
    parser.add_argument("--production-evidence", type=Path)
    parser.add_argument("--export-receipt", type=Path)
    parser.add_argument("--publication-receipt", type=Path)
    parser.add_argument("--release-receipts", type=Path)
    parser.add_argument("--security-evidence", type=Path)
    parser.add_argument("--effect-evidence", type=Path)
    parser.add_argument("--completion-output", type=Path)
    parser.add_argument("--completion-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        manifest_value = _read(args.manifest)
        if not isinstance(manifest_value, Mapping):
            raise ValueError("RELEASE_MANIFEST_OBJECT_REQUIRED")
        if manifest_value.get("evidence_type") == "public_release_evidence":
            validate_public_evidence_index(manifest_value)
            final_requested = args.completion_only or any(
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
                    evidence_index=manifest_value,
                    export_receipt=_read(args.export_receipt) if args.export_receipt else None,
                    publication_receipt=_read(args.publication_receipt) if args.publication_receipt else None,
                    release_receipts=_read(args.release_receipts) if args.release_receipts else None,
                    security_evidence=_read(args.security_evidence) if args.security_evidence else None,
                    production_evidence=_read(args.production_evidence) if args.production_evidence else None,
                    effect_evidence=_read(args.effect_evidence) if args.effect_evidence else None,
                )
                completion_value = completion.to_dict()
                if args.completion_output:
                    _write(args.completion_output, completion_value)
                print(json.dumps(completion_value, ensure_ascii=False, sort_keys=True))
                return 0 if all(
                    (
                        completion.public_source_ready,
                        completion.public_release_ready,
                        completion.production_complete,
                        completion.effect_validated is True,
                    )
                ) else 1
            if args.status_only:
                value = {
                    "status": manifest_value["status"],
                    "index_sha256": manifest_value["index_sha256"],
                    "states": manifest_value["states"],
                }
                print(json.dumps(value, ensure_ascii=False, sort_keys=True))
                return 0 if value["status"] == "verified" else 1
            if not args.evidence_commit:
                raise ValueError("PUBLIC_EVIDENCE_SHA_REQUIRED")
            if not args.prerequisites:
                raise ValueError("PREREQUISITES_REQUIRED")
            prerequisites = _read(args.prerequisites)
            if not isinstance(prerequisites, (Mapping, list)):
                raise ValueError("PREREQUISITE_DOCUMENT_INVALID")
            if args.attestation:
                attestation = _read(args.attestation)
                if not isinstance(attestation, Mapping):
                    raise ValueError("PUBLIC_ATTESTATION_OBJECT_REQUIRED")
            else:
                attestation = build_public_release_attestation(
                    manifest_value,
                    args.evidence_commit,
                    prerequisites,
                )
                if args.attestation_output:
                    _write(args.attestation_output, attestation)
            production = _read(args.production_evidence) if args.production_evidence else None
            if production is not None and not isinstance(production, Mapping):
                raise ValueError("PRODUCTION_EVIDENCE_OBJECT_REQUIRED")
            status = verify_public_release_attestation(
                manifest_value,
                attestation,
                args.evidence_commit,
                production_evidence=production,
            )
            report: dict[str, Any] = {
                "evidence_index": dict(manifest_value),
                "attestation": dict(attestation),
                "completion": status.to_dict(),
            }
        else:
            if args.completion_only or any(
                item is not None
                for item in (
                    args.export_receipt,
                    args.publication_receipt,
                    args.release_receipts,
                    args.security_evidence,
                    args.effect_evidence,
                    args.completion_output,
                )
            ):
                raise ValueError("COMPLETION_ONLY_PUBLIC_INDEX_REQUIRED")
            if args.status_only:
                print(json.dumps({"status": "private_development_candidate", "software_complete": False}, ensure_ascii=False, sort_keys=True))
                return 1
            if not args.evidence_commit or not args.prerequisites:
                raise ValueError("LEGACY_RELEASE_INPUTS_REQUIRED")
            manifest = ReleaseManifest.from_mapping(manifest_value)
            prerequisites = _read(args.prerequisites)
            if not isinstance(prerequisites, (Mapping, list)):
                raise ValueError("PREREQUISITE_DOCUMENT_INVALID")
            if args.attestation:
                attestation = _read(args.attestation)
                if not isinstance(attestation, Mapping):
                    raise ValueError("RELEASE_ATTESTATION_OBJECT_REQUIRED")
            else:
                attestation = build_release_attestation(
                    manifest,
                    args.evidence_commit,
                    prerequisites,
                )
                if args.attestation_output:
                    _write(args.attestation_output, attestation)
            receipts = [_read(Path(path)) for path in args.certification_artifact]
            production = _read(args.production_evidence) if args.production_evidence else None
            if production is not None and not isinstance(production, Mapping):
                raise ValueError("PRODUCTION_EVIDENCE_OBJECT_REQUIRED")
            status = verify_release_attestation(
                manifest,
                attestation,
                args.evidence_commit,
                certification_receipts=receipts or None,
                prerequisite_runs=prerequisites,
                production_evidence=production,
            )
            report = {"attestation": dict(attestation), "completion": status.to_dict()}
        if args.output:
            output = _write(args.output, report)
            report_path = str(output)
        else:
            report_path = None
        print(json.dumps({**status.to_dict(), "report": report_path}, ensure_ascii=False, sort_keys=True))
        return 0 if status.software_complete else 1
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"software_complete": False, "error_code": str(exc).split(":", 1)[0]}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
