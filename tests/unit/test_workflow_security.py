from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ei.workflow_security import WorkflowSecurityError, audit_workflow, audit_workflows


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"


class WorkflowSecurityTests(unittest.TestCase):
    def test_public_workflows_pass_static_security_contract(self) -> None:
        result = audit_workflows(WORKFLOW_ROOT)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["workflow_count"], 5)
        self.assertEqual(result["findings"], [])

    def test_bad_workflow_reports_each_high_risk_contract_violation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yml"
            path.write_text(
                "\n".join(
                    [
                        "name: bad",
                        "on:",
                        "  pull_request:",
                        "jobs:",
                        "  bad:",
                        "    runs-on: self-hosted",
                        "    steps:",
                        "      - uses: actions/checkout@v4",
                        "        run: echo '${{ github.event.pull_request.title }}'",
                        "        env:",
                        "          TOKEN: ${{ secrets.TOKEN }}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            findings = audit_workflow(path)
            codes = {item.code for item in findings}
            self.assertTrue(
                {
                    "PERMISSIONS_MISSING",
                    "TIMEOUT_MISSING",
                    "SELF_HOSTED_RUNNER",
                    "ACTION_NOT_IMMUTABLE",
                    "RUN_EXPRESSION_UNTRUSTED",
                    "PULL_REQUEST_SECRET_USE",
                }.issubset(codes),
                findings,
            )

    def test_block_run_expression_is_not_missed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "block.yml"
            path.write_text(
                "\n".join(
                    [
                        "name: block",
                        "permissions:",
                        "  contents: read",
                        "jobs:",
                        "  check:",
                        "    runs-on: ubuntu-latest",
                        "    timeout-minutes: 5",
                        "    steps:",
                        "      - name: unsafe",
                        "        run: |",
                        "          echo ${{ github.event.pull_request.title }}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertIn("RUN_EXPRESSION_UNTRUSTED", {item.code for item in audit_workflow(path)})

    def test_missing_and_empty_directories_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(WorkflowSecurityError, "WORKFLOW_DIRECTORY_EMPTY"):
                audit_workflows(root)
            with self.assertRaisesRegex(WorkflowSecurityError, "WORKFLOW_DIRECTORY_MISSING"):
                audit_workflows(root / "missing")

    def test_result_is_deterministic_and_json_safe(self) -> None:
        first = audit_workflows(WORKFLOW_ROOT)
        second = audit_workflows(WORKFLOW_ROOT)
        self.assertEqual(first, second)
        json.dumps(first, ensure_ascii=False, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
