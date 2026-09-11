from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ei.certification import REQUIRED_HOST_IDS, certify_host, evaluate_certification_set, validate_receipt_artifact
from tests.helpers import make_hook_settings


class AllHostRestoreTests(unittest.TestCase):
    def test_fixture_matrix_is_explicitly_non_production(self) -> None:
        self.assertEqual(
            REQUIRED_HOST_IDS,
            ("codex-cli", "claude-code", "gemini-cli", "qwen-code"),
        )

    def test_clean_room_restore_has_one_sanitized_fixture_contract_per_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            results = [
                certify_host(host_id, "clean-room-" + host_id, "fixture", settings)
                for host_id in REQUIRED_HOST_IDS
            ]
            self.assertEqual({result.host_id for result in results}, set(REQUIRED_HOST_IDS))
            for result in results:
                validate_receipt_artifact(result.receipt)
                self.assertEqual(result.receipt["mode"], "fixture")
            status = evaluate_certification_set(results)
            self.assertFalse(status.software_complete)
            self.assertIn("REAL_CERTIFICATION_REQUIRED", status.reason_codes)


if __name__ == "__main__":
    unittest.main()
