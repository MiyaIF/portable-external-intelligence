from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

import ei.experiment as experiment
import ei.github_publication as publication
import ei.public_export as public_export
import ei.release as release


def digest(char: str) -> str:
    return "sha256:" + char * 64


def _export_receipt(subject: str, policy_hash: str, *, status: str = "validated") -> dict[str, object]:
    value: dict[str, object] = {
        "receipt_type": "public_export",
        "schema_version": 1,
        "tool_version": "ei-public-export/1",
        "status": status,
        "source_commit_sha": "1" * 40,
        "source_tree_id": "2" * 40,
        "source_tree_sha256": digest("a"),
        "public_root_sha": subject,
        "public_tree_id": "3" * 40,
        "public_tree_sha256": digest("b"),
        "selected_paths_sha256": digest("c"),
        "allowlist_sha256": digest("d"),
        "publication_policy_sha256": policy_hash,
        "selected_file_count": 10,
        "root_commit_count": 1,
        "author": {"name": "MiyaIF", "email": "103426917+MiyaIF@users.noreply.github.com"},
        "validation": {"status": "passed", "step_digests": {"public_audit": digest("e")}},
        "generated_at": "2026-08-28T00:00:00Z",
    }
    value["receipt_sha256"] = public_export._hash_basis({key: value[key] for key in sorted(value)})
    public_export.validate_public_export_receipt(value)
    return value


def _publication_receipt(subject: str) -> dict[str, object]:
    policy = {
        "schema_version": 1,
        "license_spdx": "Apache-2.0",
        "copyright_holder": "Fiso",
        "public_author": {"name": "MiyaIF", "email": "103426917+MiyaIF@users.noreply.github.com"},
        "github": {"owner": "MiyaIF", "repository": "portable-external-intelligence", "default_branch": "main"},
        "security_reporting": {
            "type": "github_private_vulnerability_reporting",
            "url": "https://github.com/MiyaIF/portable-external-intelligence/security/advisories/new",
            "acknowledgement_days": 7,
            "triage_days": 14,
        },
        "contribution_policy": {"issues": True, "pull_requests": True, "dco_required": True, "cla_required": False, "response_sla_days": None, "merge_guarantee": False, "bug_bounty": False},
        "initial_version": "1.0.0",
    }
    settings = publication._settings(policy)
    ruleset = publication._ruleset()
    value: dict[str, object] = {
        "receipt_type": "github_publication",
        "schema_version": 1,
        "tool_version": publication.PUBLICATION_TOOL_VERSION,
        "status": "verified",
        "owner": "MiyaIF",
        "repository": "portable-external-intelligence",
        "repository_url": "https://github.com/MiyaIF/portable-external-intelligence",
        "default_branch": "main",
        "source_commit_sha": subject,
        "source_tree_id": "4" * 40,
        "source_tree_sha256": digest("f"),
        "root_commit_count": 1,
        "source_audit_sha256": digest("0"),
        "plan_sha256": "",
        "settings": settings,
        "settings_sha256": publication._digest(settings),
        "ruleset": ruleset,
        "ruleset_sha256": publication._digest(ruleset),
        "feature_states": publication._features(policy),
        "target_observation": {"status": "not_found", "method": "github_api"},
        "ci_run_urls": [],
        "post_public_clone": {
            "root_commit_sha": subject,
            "tree_id": "5" * 40,
            "tree_sha256": digest("1"),
            "root_commit_count": 1,
            "audit_sha256": digest("2"),
            "package_sha256": digest("3"),
            "readme_quick_start": True,
        },
        "mutations_performed": True,
        "external_mutations": ["repository_created_public", "sanitized_root_pushed"],
        "generated_at": "2026-08-28T00:00:00Z",
        "receipt_sha256": "",
    }
    value["plan_sha256"] = publication._digest(publication._plan_basis(value))
    value["receipt_sha256"] = publication._digest(publication._receipt_basis(value))
    publication.validate_publication_record(value)
    return value


def _security(subject: str) -> dict[str, object]:
    findings = [
        {
            "finding_id": "SEC-" + str(index),
            "severity": "high" if index < 2 else "medium",
            "status": "fixed",
            "subject_commit_sha": subject,
            "regression_evidence_sha256": digest(format(index + 5, "x")[-1]),
        }
        for index in range(11)
    ]
    value: dict[str, object] = {
        "receipt_type": "security_remediation",
        "schema_version": 1,
        "scan_id": "scan-public-subject",
        "subject_commit_sha": subject,
        "status": "resolved",
        "scanner_receipt_sha256": digest("4"),
        "scanner_snapshot_sha256": digest("3"),
        "reportable_finding_count": len(findings),
        "finding_set_sha256": release._digest({"finding_ids": sorted(row["finding_id"] for row in findings)}),
        "findings": findings,
        "report_sha256": "",
    }
    value["report_sha256"] = release._digest({key: value[key] for key in sorted(release.SECURITY_REMEDIATION_KEYS - {"report_sha256"})})
    return value


def _release_receipts(index_value: dict[str, object], subject: str) -> dict[str, object]:
    receipts: dict[str, object] = {}
    for position, name in enumerate(release.PUBLIC_REQUIRED_RELEASE_RECEIPTS):
        workflow = release.PUBLIC_RELEASE_RECEIPT_WORKFLOWS[name]
        value: dict[str, object] = {
            "receipt_type": name,
            "schema_version": 1,
            "status": "PASSED",
            "subject_commit_sha": subject,
            "producer_workflow": workflow,
            "producer_run_id": index_value["ci_runs"][workflow]["run_id"],
            "artifact_sha256": (
                _security(subject)["report_sha256"]
                if name == "security_remediation"
                else digest(format(position, "x")[-1])
            ),
            "receipt_sha256": "",
        }
        value["receipt_sha256"] = release._digest(
            {key: value[key] for key in sorted(release.PUBLIC_RELEASE_RECEIPT_KEYS - {"receipt_sha256"})}
        )
        receipts[name] = value
    return receipts


def _production(subject: str) -> dict[str, object]:
    imported: list[dict[str, object]] = []
    for index, (host_id, os_profile) in enumerate(release.PUBLIC_COMPATIBILITY_PAIRS):
        row: dict[str, object] = {
            "receipt_type": "private_certification_import",
            "public_subject_commit_sha": subject,
            "host_id": host_id,
            "os_profile": os_profile,
            "mode": "real",
            "status": "PASSED",
            "artifact_sha256": digest(str(index % 10)),
            "event_sha256": digest(str((index + 1) % 10)),
            "source_receipt_sha256": digest(str((index + 2) % 10)),
            "certified_at": "2026-08-28T00:00:00Z",
            "import_sha256": "",
        }
        row["import_sha256"] = release._digest(release._private_import_basis(row))
        release.validate_private_certification_import(row)
        imported.append(row)
    lifecycle = {
        step: {"status": "PASSED", "subject_commit_sha": subject, "receipt_sha256": digest(format(index + 1, "x")[-1])}
        for index, step in enumerate(release.PRODUCTION_LIFECYCLE_STEPS)
    }
    value: dict[str, object] = {
        "receipt_type": "production_evidence",
        "schema_version": 1,
        "status": "PASSED",
        "subject_commit_sha": subject,
        "lifecycle": lifecycle,
        "compatibility_matrix": [
            {"host_id": host, "os_profile": os, "supported": True, "subject_commit_sha": subject, "receipt_sha256": imported[index]["import_sha256"]}
            for index, (host, os) in enumerate(release.PUBLIC_COMPATIBILITY_PAIRS)
        ],
        "real_host_receipts": imported,
        "private_ops_attestation_sha256": digest("a"),
        "evidence_sha256": "",
    }
    value["evidence_sha256"] = release._digest({key: value[key] for key in sorted(release.PRODUCTION_EVIDENCE_KEYS - {"evidence_sha256"})})
    return value


def _effect(subject: str, evidence_index_sha256: str) -> dict[str, object]:
    value: dict[str, object] = {
        "evidence_type": "ab_effect",
        "experiment_id": "retrieval-v1",
        "protocol_hash": digest("b"),
        "subject_commit_sha": subject,
        "evidence_index_sha256": evidence_index_sha256,
        "primary_metrics": ["repeated_search", "rework", "failure"],
        "eligible_units_per_arm": 50,
        "duration_days": 14,
        "power": 0.80,
        "alpha": 0.05,
        "metric_provenance": {
            metric: {"status": "verified", "evidence_sha256": digest(str(index))}
            for index, metric in enumerate(("repeated_search", "rework", "failure"))
        },
        "missingness": {"status": "complete", "missing_metric_count": 0, "missing_outcome_count": 0, "orphan_outcome_count": 0, "duplicate_outcome_count": 0, "invalid_outcome_count": 0},
        "contamination": {"status": "clean", "count": 0, "assignment_drift_count": 0, "protocol_mismatch_count": 0, "post_treatment_exclusion_count": 0},
        "causal_report": {"status": "CAUSAL_EFFECT_ESTIMATED", "evidence_sha256": digest("f")},
        "analysis_sha256": "",
    }
    value["analysis_sha256"] = experiment._effect_digest({key: value[key] for key in sorted(experiment.EFFECT_EVIDENCE_KEYS - {"analysis_sha256"})})
    experiment.validate_effect_evidence(value)
    return value


class PublicCompletionContractTests(unittest.TestCase):
    def _index(self) -> tuple[dict[str, object], str]:
        subject = "a" * 40
        policy_hash = digest("a")
        runs = {
            workflow: {"run_id": index + 1, "conclusion": "success", "head_sha": subject}
            for index, workflow in enumerate(release.REQUIRED_WORKFLOW_NAMES)
        }
        index = release.build_public_evidence_index(
            publication_policy_sha256=policy_hash,
            subject_commit_sha=subject,
            evidence_commit_sha=subject,
            public_tree_audit_sha256=digest("b"),
            workflow_sha256=digest("c"),
            package_sha256=digest("d"),
            sbom_sha256=digest("e"),
            ci_runs=runs,
            receipt_index=[{"receipt_type": "hosted_contract", "receipt_sha256": digest("f")}],
            generated_at="2026-08-28T00:00:00Z",
        )
        return index, subject

    def test_source_release_production_and_effect_are_independent_gates(self) -> None:
        index, subject = self._index()
        export = _export_receipt(subject, index["publication_policy_sha256"])
        effect = _effect(subject, index["index_sha256"])
        pending = release.evaluate_public_completion(evidence_index=index, export_receipt=export, effect_evidence=effect)
        self.assertTrue(pending.public_source_ready)
        self.assertFalse(pending.public_release_ready)
        self.assertFalse(pending.production_complete)
        self.assertTrue(pending.effect_validated)

        ready = release.evaluate_public_completion(
            evidence_index=index,
            export_receipt=export,
            publication_receipt=_publication_receipt(subject),
            release_receipts=_release_receipts(index, subject),
            security_evidence=_security(subject),
            production_evidence=_production(subject),
            effect_evidence=effect,
        )
        self.assertTrue(ready.public_source_ready)
        self.assertTrue(ready.public_release_ready)
        self.assertTrue(ready.production_complete)
        self.assertTrue(ready.effect_validated)

    def test_public_release_requires_all_receipts_and_resolved_security(self) -> None:
        index, subject = self._index()
        export = _export_receipt(subject, index["publication_policy_sha256"])
        kwargs = {
            "evidence_index": index,
            "export_receipt": export,
            "publication_receipt": _publication_receipt(subject),
            "release_receipts": _release_receipts(index, subject),
            "security_evidence": _security(subject),
        }
        del kwargs["release_receipts"]["sbom"]
        blocked = release.evaluate_public_completion(**kwargs)
        self.assertFalse(blocked.public_release_ready)
        self.assertIn("REQUIRED_RECEIPT_SET_INVALID", blocked.reason_codes)
        bad_security = _security(subject)
        bad_security["findings"][0]["status"] = "open"
        blocked_security = release.evaluate_public_completion(
            evidence_index=index,
            export_receipt=export,
            publication_receipt=_publication_receipt(subject),
            release_receipts=_release_receipts(index, subject),
            security_evidence=bad_security,
        )
        self.assertFalse(blocked_security.public_release_ready)
        self.assertIn("SECURITY_FINDING_NOT_FIXED", blocked_security.reason_codes)

    def test_security_manifest_count_and_ci_artifact_binding_are_required(self) -> None:
        index, subject = self._index()
        security = _security(subject)
        security["reportable_finding_count"] = 10
        security["report_sha256"] = release._digest(
            {key: security[key] for key in sorted(release.SECURITY_REMEDIATION_KEYS - {"report_sha256"})}
        )
        status = release.evaluate_public_completion(
            evidence_index=index,
            export_receipt=_export_receipt(subject, index["publication_policy_sha256"]),
            publication_receipt=_publication_receipt(subject),
            release_receipts=_release_receipts(index, subject),
            security_evidence=security,
        )
        self.assertFalse(status.public_release_ready)
        self.assertIn("SECURITY_FINDING_COUNT_INVALID", status.reason_codes)
        self.assertIn("SECURITY_REMEDIATION_ARTIFACT_MISMATCH", status.reason_codes)

    def test_production_requires_every_cli_os_pair_and_lifecycle_step(self) -> None:
        index, subject = self._index()
        production = _production(subject)
        production["real_host_receipts"] = production["real_host_receipts"][:-1]
        status = release.evaluate_public_completion(
            evidence_index=index,
            export_receipt=_export_receipt(subject, index["publication_policy_sha256"]),
            publication_receipt=_publication_receipt(subject),
            release_receipts=_release_receipts(index, subject),
            security_evidence=_security(subject),
            production_evidence=production,
        )
        self.assertTrue(status.public_release_ready)
        self.assertFalse(status.production_complete)
        self.assertIn("REAL_HOST_RECEIPT_SET_INVALID", status.reason_codes)

    def test_missing_public_subject_never_becomes_source_ready(self) -> None:
        index = release.build_public_evidence_index(publication_policy_sha256=digest("a"), generated_at="2026-08-28T00:00:00Z")
        status = release.evaluate_public_completion(
            evidence_index=index,
            effect_evidence=_effect("b" * 40, digest("c")),
        )
        self.assertFalse(status.public_source_ready)
        self.assertFalse(status.public_release_ready)
        self.assertEqual(status.effect_validated, "awaiting_sample")

    def test_effect_from_another_release_is_rejected(self) -> None:
        index, subject = self._index()
        wrong = _effect("b" * 40, index["index_sha256"])
        status = release.evaluate_public_completion(evidence_index=index, effect_evidence=wrong)
        self.assertEqual(status.effect_validated, "awaiting_sample")
        self.assertTrue(any("EFFECT_SUBJECT_MISMATCH" in code for code in status.reason_codes))

    def test_release_receipt_provenance_must_match_ci_run(self) -> None:
        index, subject = self._index()
        receipts = _release_receipts(index, subject)
        receipts["package"]["producer_run_id"] = 999999
        receipts["package"]["receipt_sha256"] = release._digest(
            {
                key: receipts["package"][key]
                for key in sorted(release.PUBLIC_RELEASE_RECEIPT_KEYS - {"receipt_sha256"})
            }
        )
        status = release.evaluate_public_completion(
            evidence_index=index,
            export_receipt=_export_receipt(subject, index["publication_policy_sha256"]),
            publication_receipt=_publication_receipt(subject),
            release_receipts=receipts,
            security_evidence=_security(subject),
        )
        self.assertFalse(status.public_release_ready)
        self.assertIn("REQUIRED_RECEIPT_PRODUCER_RUN_MISMATCH:package", status.reason_codes)

    def test_setup_complete_is_not_external_activation_or_effect_evidence(self) -> None:
        root = Path.cwd()
        text = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("README.md", "docs/setup.md", "docs/update.md", "docs/uninstall.md")
        ).casefold()
        self.assertIn("setup_complete", text)
        self.assertIn("not proof", text)
        for term in ("acl", "external sync", "member distribution", "live hook", "production completion", "measured effect"):
            self.assertIn(term, text)


if __name__ == "__main__":
    unittest.main()
