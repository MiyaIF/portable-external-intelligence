from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ei.certification import (
    REQUIRED_HOST_IDS,
    REQUIRED_OS_PROFILES,
    certify_host,
    evaluate_certification_set,
)
from ei.release import PUBLIC_COMPATIBILITY_PAIRS, PRODUCTION_LIFECYCLE_STEPS, evaluate_public_completion
from tests.helpers import make_hook_settings


class MissingHostBlocksCompletionTests(unittest.TestCase):
    def test_missing_host_and_os_are_explicit_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            results = [
                certify_host(host_id, "fixture-" + host_id, "fixture", settings)
                for host_id in REQUIRED_HOST_IDS[:-1]
            ]
            status = evaluate_certification_set(results)
            self.assertFalse(status.software_complete)
            self.assertIn("HOST_CERTIFICATION_MISSING", status.reason_codes)
            self.assertIn("OS_CERTIFICATION_MISSING", status.reason_codes)
            self.assertIn(REQUIRED_HOST_IDS[-1], status.missing_hosts)
            self.assertEqual(status.missing_os_profiles, REQUIRED_OS_PROFILES)

    def test_all_fixture_hosts_are_still_not_production_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            results = [
                certify_host(host_id, "fixture-" + host_id, "fixture", settings)
                for host_id in REQUIRED_HOST_IDS
            ]
            status = evaluate_certification_set(results)
            self.assertFalse(status.software_complete)
            self.assertFalse(status.production_enabled)
            self.assertIn("REAL_CERTIFICATION_REQUIRED", status.reason_codes)

    def test_public_production_contract_requires_the_declared_matrix_and_lifecycle(self) -> None:
        self.assertEqual(len(PUBLIC_COMPATIBILITY_PAIRS), len(REQUIRED_HOST_IDS) * len(REQUIRED_OS_PROFILES))
        self.assertIn("hook_skill_activation", PRODUCTION_LIFECYCLE_STEPS)
        self.assertIn("private_sync", PRODUCTION_LIFECYCLE_STEPS)
        pending = evaluate_public_completion(evidence_index={})
        self.assertFalse(pending.production_complete)
        self.assertFalse(pending.checks["production_evidence"])


if __name__ == "__main__":
    unittest.main()
