from __future__ import annotations

import unittest
from pathlib import Path

from ei.installer import SetupResult, already_current_setup_result, blocked_setup_result, check_only_setup_result
from ei.setup_reconciliation import SetupReconciliationPlan


def _plan(status: str = "ALREADY_CURRENT") -> SetupReconciliationPlan:
    return SetupReconciliationPlan(
        status,
        "sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        (),
        (),
        (),
        (),
    )


class InstallerReconciliationTests(unittest.TestCase):
    def test_result_exposes_reconciliation_and_knowledge_stores(self) -> None:
        result = SetupResult(True, "SETUP_COMPLETE", Path("C:/runtime/install-manifest.json"))
        payload = result.to_dict()
        self.assertIn("reconciliation", payload)
        self.assertIn("knowledge_stores", payload)

    def test_already_current_result_keeps_compatibility_status_and_no_changes(self) -> None:
        result = already_current_setup_result({}, _plan())
        self.assertEqual(result.status, "SETUP_COMPLETE")
        self.assertEqual(result.changed_paths, ())
        self.assertEqual(result.reconciliation["status"], "ALREADY_CURRENT")

    def test_check_only_result_is_non_mutating(self) -> None:
        result = check_only_setup_result(_plan("UPDATED"))
        self.assertEqual(result.status, "CHECK_ONLY")
        self.assertEqual(result.reconciliation["status"], "UPDATED")

    def test_blocked_result_reports_plan_errors_without_changes(self) -> None:
        plan = SetupReconciliationPlan(
            "BLOCKED",
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            (),
            (),
            (),
            ({"error_code": "PERSONAL_ROOT_CHANGE_REQUIRES_MIGRATION"},),
        )
        result = blocked_setup_result(plan)
        self.assertEqual(result.status, "SETUP_BLOCKED")
        self.assertEqual(result.changed_paths, ())
        self.assertEqual(result.errors[0]["error_code"], "PERSONAL_ROOT_CHANGE_REQUIRES_MIGRATION")


if __name__ == "__main__":
    unittest.main()
