from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import ei.release as release_module
from ei.cli import main
from ei.release import (
    PRIVATE_CERTIFICATION_IMPORT_KEYS,
    REQUIRED_WORKFLOW_NAMES,
    build_private_certification_import,
    build_release_attestation,
    build_release_manifest,
    build_public_evidence_index,
    build_public_release_attestation,
    validate_private_certification_import,
    validate_public_evidence_index,
    validate_prerequisite_runs,
    verify_public_release_attestation,
    verify_release_attestation,
)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def real_receipt(host_id: str, instance_id: str, os_family: str, os_version: str) -> dict[str, object]:
    receipt = {
        "receipt_id": "receipt-" + host_id,
        "mode": "real",
        "host_id": host_id,
        "host_instance_id": instance_id,
        "host_version": "1.0.0",
        "os_family": os_family,
        "os_version": os_version,
        "python_version": "3.13.0",
        "event_sha256": digest("a"),
        "activation_state": "AUTO_ALLOWED" if host_id != "gemini-cli" else "CONSENT_REQUIRED",
        "certified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    basis = {key: receipt[key] for key in sorted(receipt)}
    receipt["artifact_sha256"] = "sha256:" + hashlib.sha256(
        json.dumps(basis, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return receipt


class ReleaseContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_release_evidence_writers_reject_junction_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            junction = root / "linked-output"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            repo = Path(__file__).resolve().parents[2]
            generate = subprocess.run(
                [
                    __import__("sys").executable,
                    "scripts/generate-release-evidence.py",
                    "--publication-policy-sha256",
                    digest("1"),
                    "--output",
                    str(junction / "generated.json"),
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            verify = subprocess.run(
                [
                    __import__("sys").executable,
                    "scripts/verify-release-evidence.py",
                    "--manifest",
                    "release/evidence-manifest.json",
                    "--completion-only",
                    "--completion-output",
                    str(junction / "verified.json"),
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(generate.returncode, 0, generate.stdout + generate.stderr)
            self.assertNotEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertFalse((outside / "generated.json").exists())
            self.assertFalse((outside / "verified.json").exists())

    def _artifacts(self) -> dict[str, object]:
        return {
            "workflow_sha256": digest("a"),
            "workflow_names": list(REQUIRED_WORKFLOW_NAMES),
            "certification_sha256": [digest(char) for char in "bcdef"],
            "real_certification": True,
            "effect_evidence": None,
        }

    def _attestation(self, manifest) -> dict[str, object]:
        return {
            "evidence_type": "post_push_attestation",
            "subject_commit_sha": manifest.subject_commit_sha,
            "evidence_commit_sha": "b" * 40,
            "manifest_sha256": manifest.manifest_sha256,
            "workflow_sha256": manifest.workflow_sha256,
            "certification_sha256": list(manifest.certification_sha256),
            "attested_at": "2026-08-27T00:00:00Z",
        }

    def test_subject_manifest_forbids_evidence_commit_self_reference(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        self.assertNotIn("evidence_commit_sha", manifest.to_dict())
        self.assertEqual(manifest.evidence_type, "subject_manifest")

    def test_valid_attestation_separates_software_production_and_effect(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        status = verify_release_attestation(manifest, self._attestation(manifest), "b" * 40)
        self.assertTrue(status.software_complete)
        self.assertFalse(status.production_enabled)
        self.assertEqual(status.effect_validated, "awaiting_sample")
        self.assertEqual(status.reason_codes, ("PRODUCTION_REAL_ACTIVATION_PENDING", "EFFECT_AWAITING_SAMPLE"))

    def test_mismatch_missing_and_stale_evidence_never_completes(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        cases = (
            ("missing", {**self._attestation(manifest), "certification_sha256": []}, "CERTIFICATION_EVIDENCE_MISSING"),
            ("subject", {**self._attestation(manifest), "subject_commit_sha": "c" * 40}, "SUBJECT_SHA_MISMATCH"),
            ("evidence", self._attestation(manifest), "EVIDENCE_COMMIT_SHA_MISMATCH"),
            ("fixture-only", {**self._attestation(manifest), "certification_sha256": [digest("f")] * 5, "fixture_only": True}, "REAL_CERTIFICATION_MISSING"),
        )
        for name, attestation, expected in cases:
            with self.subTest(name=name):
                expected_evidence = "b" * 40 if name != "evidence" else "c" * 40
                status = verify_release_attestation(manifest, attestation, expected_evidence)
                self.assertFalse(status.software_complete)
                self.assertIn(expected, status.reason_codes)

    def test_subject_manifest_rejects_extra_evidence_sha(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        invalid = {**manifest.to_dict(), "evidence_commit_sha": "b" * 40}
        status = verify_release_attestation(manifest, {**self._attestation(manifest), "manifest_sha256": digest("f")}, "b" * 40)
        self.assertFalse(status.software_complete)
        self.assertIn("MANIFEST_HASH_MISMATCH", status.reason_codes)
        with self.assertRaises(ValueError):
            type(manifest).from_mapping(invalid)

    def test_post_push_attestation_requires_exact_prerequisite_sha_and_workflow_set(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        prerequisites = {
            workflow: {
                "run_id": index + 1,
                "conclusion": "success",
                "head_sha": "b" * 40,
            }
            for index, workflow in enumerate(REQUIRED_WORKFLOW_NAMES)
        }
        valid, reasons = validate_prerequisite_runs(prerequisites, "b" * 40)
        self.assertTrue(valid)
        self.assertEqual(reasons, ())
        attestation = build_release_attestation(manifest, "b" * 40, prerequisites)
        self.assertEqual(attestation["evidence_commit_sha"], "b" * 40)
        self.assertNotIn("evidence_commit_sha", manifest.to_dict())
        status = verify_release_attestation(
            manifest,
            attestation,
            "b" * 40,
            prerequisite_runs=prerequisites,
        )
        self.assertTrue(status.software_complete)

    def test_prerequisite_run_with_different_head_sha_is_rejected(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        prerequisites = {
            workflow: {
                "run_id": index + 1,
                "conclusion": "success",
                "head_sha": "c" * 40,
            }
            for index, workflow in enumerate(REQUIRED_WORKFLOW_NAMES)
        }
        valid, reasons = validate_prerequisite_runs(prerequisites, "b" * 40)
        self.assertFalse(valid)
        self.assertTrue(any("PREREQUISITE_RUN_SHA_MISMATCH" in item for item in reasons))
        with self.assertRaises(ValueError):
            build_release_attestation(manifest, "b" * 40, prerequisites)
    def test_release_wrapper_generates_sanitized_attestation_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            receipts = [
                real_receipt("codex-cli", "codex-cli-windows-10", "Windows", "Windows 10"),
                real_receipt("claude-code", "claude-windows-11", "Windows", "Windows 11"),
                real_receipt("gemini-cli", "gemini-macos", "macOS", "14"),
                real_receipt("qwen-code", "qwen-ubuntu", "Linux", "Ubuntu 24.04"),
                real_receipt("codex-cli", "codex-cli-debian", "Linux", "Debian 12"),
            ]
            artifact_hashes = {
                **self._artifacts(),
                "certification_sha256": [row["artifact_sha256"] for row in receipts],
            }
            manifest = build_release_manifest("a" * 40, artifact_hashes, {})
            manifest_path = root / "manifest.json"
            prerequisites_path = root / "prerequisites.json"
            attestation_path = root / "attestation.json"
            report_path = root / "report.json"
            manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
            prerequisites_path.write_text(
                json.dumps(
                    {
                        workflow: {
                            "run_id": index + 1,
                            "conclusion": "success",
                            "head_sha": "b" * 40,
                        }
                        for index, workflow in enumerate(REQUIRED_WORKFLOW_NAMES)
                    }
                ),
                encoding="utf-8",
            )
            command = [
                __import__("sys").executable,
                "scripts/verify-release-evidence.py",
                "--manifest", str(manifest_path),
                "--evidence-commit", "b" * 40,
                "--prerequisites", str(prerequisites_path),
                "--attestation-output", str(attestation_path),
                "--output", str(report_path),
            ]
            for receipt in receipts:
                receipt_path = root / (str(receipt["host_instance_id"]) + ".json")
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                command.extend(["--certification-artifact", str(receipt_path)])
            result = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            self.assertEqual(attestation["evidence_commit_sha"], "b" * 40)
            self.assertNotIn("evidence_commit_sha", manifest.to_dict())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["completion"]["software_complete"])
    def test_stale_attestation_never_completes(self) -> None:
        manifest = build_release_manifest("a" * 40, self._artifacts(), {})
        status = verify_release_attestation(
            manifest,
            self._attestation(manifest),
            "b" * 40,
            now=datetime(2026, 10, 1, tzinfo=timezone.utc),
        )
        self.assertFalse(status.software_complete)
        self.assertIn("ATTESTATION_STALE", status.reason_codes)

    def test_underpowered_effect_is_not_validated(self) -> None:
        manifest = build_release_manifest("a" * 40, {**self._artifacts(), "effect_evidence": {"eligible_units_per_arm": 49}}, {})
        status = verify_release_attestation(manifest, self._attestation(manifest), "b" * 40)
        self.assertEqual(status.effect_validated, "awaiting_sample")
        self.assertIn("EFFECT_AWAITING_SAMPLE", status.reason_codes)

    def test_private_certification_import_is_subject_bound_and_path_free(self) -> None:
        source = real_receipt("codex-cli", "private-host", "Windows", "Windows 11")
        imported = build_private_certification_import(
            {"status": "PASSED", "real_evidence": True, "receipt": source},
            "a" * 40,
        )
        validate_private_certification_import(imported)
        self.assertEqual(set(imported), PRIVATE_CERTIFICATION_IMPORT_KEYS)
        self.assertEqual(imported["public_subject_commit_sha"], "a" * 40)
        self.assertNotIn("host_instance_id", imported)
        self.assertNotIn("prompt", json.dumps(imported).casefold())
        with self.assertRaisesRegex(ValueError, "PRIVATE_CERTIFICATION_REAL_EVIDENCE_REQUIRED"):
            build_private_certification_import(
                {"status": "PASSED", "real_evidence": False, "receipt": source},
                "a" * 40,
            )

    def test_public_evidence_index_is_pending_until_subject_and_exact_ci_evidence_exist(self) -> None:
        policy_hash = digest("1")
        pending = build_public_evidence_index(
            publication_policy_sha256=policy_hash,
            generated_at="2026-08-28T00:00:00Z",
        )
        validate_public_evidence_index(pending)
        self.assertEqual(pending["status"], "awaiting_public_subject")
        self.assertFalse(pending["states"]["software_complete"])
        with self.assertRaisesRegex(ValueError, "PUBLIC_EVIDENCE_FIELDS_REQUIRED"):
            build_public_evidence_index(
                publication_policy_sha256=policy_hash,
                subject_commit_sha="a" * 40,
                generated_at="2026-08-28T00:00:00Z",
            )

    def test_effect_evidence_is_external_to_the_immutable_public_index(self) -> None:
        with self.assertRaisesRegex(ValueError, "^PUBLIC_EFFECT_EVIDENCE_SEPARATE_REQUIRED$"):
            build_public_evidence_index(
                publication_policy_sha256=digest("1"),
                effect_evidence={},
                generated_at="2026-08-28T00:00:00Z",
            )

        index = build_public_evidence_index(
            publication_policy_sha256=digest("1"),
            generated_at="2026-08-28T00:00:00Z",
        )
        index["states"]["effect_validated"] = True
        index["index_sha256"] = release_module._digest(release_module._public_index_basis(index))
        with self.assertRaisesRegex(ValueError, "^PUBLIC_EFFECT_STATE_EXTERNAL_REQUIRED$"):
            validate_public_evidence_index(index)

    def test_public_attestation_binds_subject_manifest_hash_and_all_workflow_runs(self) -> None:
        prerequisites = {
            workflow: {"run_id": index + 1, "conclusion": "success", "head_sha": "b" * 40}
            for index, workflow in enumerate(REQUIRED_WORKFLOW_NAMES)
        }
        index = build_public_evidence_index(
            publication_policy_sha256=digest("1"),
            subject_commit_sha="a" * 40,
            evidence_commit_sha="b" * 40,
            public_tree_audit_sha256=digest("2"),
            workflow_sha256=digest("3"),
            package_sha256=digest("4"),
            sbom_sha256=digest("5"),
            ci_runs=prerequisites,
            receipt_index=[{"receipt_type": "hosted_contract", "receipt_sha256": digest("6")}],
            generated_at="2026-08-28T00:00:00Z",
        )
        self.assertEqual(index["status"], "verified")
        attestation = build_public_release_attestation(
            index,
            "b" * 40,
            prerequisites,
            attested_at=datetime(2026, 8, 28, tzinfo=timezone.utc),
        )
        status = verify_public_release_attestation(index, attestation, "b" * 40)
        self.assertTrue(status.software_complete)
        self.assertFalse(status.production_enabled)
        self.assertEqual(status.effect_validated, "awaiting_sample")
        broken = dict(index)
        broken["subject_commit_sha"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "PUBLIC_EVIDENCE_INDEX_HASH_MISMATCH"):
            validate_public_evidence_index(broken)

    def test_completion_only_cli_reports_pending_independent_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "completion.json"
            result = subprocess.run(
                [
                    __import__("sys").executable,
                    "scripts/verify-release-evidence.py",
                    "--manifest", "release/evidence-manifest.json",
                    "--completion-only",
                    "--completion-output", str(output),
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(value["public_source_ready"])
            self.assertFalse(value["public_release_ready"])
            self.assertFalse(value["production_complete"])
            self.assertEqual(value["effect_validated"], "awaiting_sample")


    def test_certify_host_cli_writes_sanitized_fixture_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}',
                encoding="utf-8",
            )
            runtime = root / "runtime"
            output = root / "receipt.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "certify-host",
                        "--repo", str(root),
                        "--codex-home", str(root / "codex"),
                        "--runtime-root", str(runtime),
                        "--host", "codex-cli",
                        "--instance", "fixture-cli",
                        "--mode", "fixture",
                        "--output", str(output),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["mode"], "fixture")
            self.assertEqual(json.loads(stdout.getvalue())["status"], "PASSED")

    def test_release_prepare_cli_emits_subject_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}',
                encoding="utf-8",
            )
            output = root / "manifest.json"
            argv = [
                "release", "prepare",
                "--repo", str(root),
                "--codex-home", str(root / "codex"),
                "--runtime-root", str(root / "runtime"),
                "--subject-commit", "a" * 40,
                "--workflow-sha256", digest("a"),
                "--certification-sha256", digest("b"),
                "--certification-sha256", digest("c"),
                "--certification-sha256", digest("d"),
                "--certification-sha256", digest("e"),
                "--certification-sha256", digest("f"),
                "--output", str(output),
                "--json",
            ]
            for workflow in REQUIRED_WORKFLOW_NAMES:
                argv.extend(["--workflow-name", workflow])
            self.assertEqual(main(argv), 0)
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertNotIn("evidence_commit_sha", manifest)
            self.assertEqual(manifest["subject_commit_sha"], "a" * 40)

if __name__ == "__main__":
    unittest.main()
