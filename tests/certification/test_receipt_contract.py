from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ei.certification import (
    REQUIRED_HOST_IDS,
    CertificationResult,
    certify_host,
    classify_certification_receipt,
    evaluate_certification_set,
    read_certification_artifact,
    validate_receipt_artifact,
    write_certification_artifact,
)
from tests.helpers import make_hook_settings


class ReceiptContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.settings = make_hook_settings(self.root)

    def test_fixture_receipt_has_exact_sanitized_schema(self) -> None:
        result = certify_host("codex-cli", "fixture-codex-cli", "fixture", self.settings)
        self.assertEqual(result.status, "PASSED")
        self.assertFalse(result.real_evidence)
        validate_receipt_artifact(result.receipt)
        self.assertEqual(
            set(result.receipt),
            {
                "receipt_id",
                "mode",
                "host_id",
                "host_instance_id",
                "host_version",
                "os_family",
                "os_version",
                "python_version",
                "artifact_sha256",
                "event_sha256",
                "activation_state",
                "certified_at",
            },
        )
        raw = json.dumps(result.receipt, ensure_ascii=False)
        self.assertNotIn(str(self.root), raw)
        self.assertNotIn("prompt", raw.casefold())
        self.assertNotIn("response", raw.casefold())
        self.assertNotIn("tool", raw.casefold())

    def test_real_host_without_receipts_is_missing_and_never_faked(self) -> None:
        result = certify_host("codex-cli", "real-codex-cli", "real", self.settings)
        self.assertEqual(result.status, "MISSING")
        self.assertIn("HOST_CERTIFICATION_MISSING", result.reason_codes)
        self.assertFalse(result.real_evidence)
        self.assertEqual(result.receipt["mode"], "real")
        self.assertEqual(result.receipt["activation_state"], "real-missing")
        validate_receipt_artifact(result.receipt)

    def test_artifact_round_trip_validates_content_hash(self) -> None:
        result = certify_host("claude-code", "fixture-claude", "fixture", self.settings)
        path = self.root.parent / (self.root.name + "-receipt.json")
        write_certification_artifact(path, result)
        loaded = read_certification_artifact(path)
        self.assertEqual(loaded, result.receipt)

    def test_fixture_receipts_do_not_satisfy_required_real_host_set(self) -> None:
        results = [
            certify_host(host_id, "fixture-" + host_id, "fixture", self.settings)
            for host_id in REQUIRED_HOST_IDS
        ]
        status = evaluate_certification_set(results)
        self.assertFalse(status.software_complete)
        self.assertIn("REAL_CERTIFICATION_REQUIRED", status.reason_codes)
        self.assertIn("HOST_CERTIFICATION_MISSING", status.reason_codes)

    def test_absolute_paths_are_not_allowed_in_sanitized_receipts(self) -> None:
        result = certify_host("codex-cli", "fixture-codex-cli", "fixture", self.settings)
        receipt = dict(result.receipt)
        receipt["host_instance_id"] = r"C:\client\receipt"
        basis = {key: receipt[key] for key in sorted(receipt) if key != "artifact_sha256"}
        receipt["artifact_sha256"] = "sha256:" + hashlib.sha256(
            json.dumps(basis, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "CERTIFICATION_ABSOLUTE_PATH_FORBIDDEN"):
            validate_receipt_artifact(receipt)

    def test_result_constructor_rejects_unsanitized_receipt(self) -> None:
        with self.assertRaises(ValueError):
            CertificationResult(
                host_id="codex-cli",
                host_instance_id="bad",
                mode="fixture",
                status="PASSED",
                reason_codes=(),
                receipt={"prompt": "secret"},
                real_evidence=False,
            )

    def test_unbound_real_receipt_is_private_development_evidence(self) -> None:
        fixture = certify_host("codex-cli", "fixture-codex-cli", "fixture", self.settings).receipt
        real = certify_host("codex-cli", "real-codex-cli", "real", self.settings).receipt
        self.assertEqual(classify_certification_receipt(fixture), "fixture")
        self.assertEqual(classify_certification_receipt(real), "private_development")
        self.assertEqual(classify_certification_receipt(real, public_subject_commit_sha="a" * 40), "private_development")
        with self.assertRaisesRegex(ValueError, "CERTIFICATION_PUBLIC_SUBJECT_INVALID"):
            classify_certification_receipt(real, public_subject_commit_sha="not-a-sha")


if __name__ == "__main__":
    unittest.main()
