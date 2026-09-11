import json
import tempfile
import unittest
from pathlib import Path

from ei.adapters.rollout_summary import RolloutSummaryAdapter


class RolloutAdapterTests(unittest.TestCase):
    def test_extracts_reusable_knowledge_failure_and_task_outcome(self):
        fixture = Path("tests/fixtures/memories/sample_rollout.jsonl")
        records = list(RolloutSummaryAdapter([fixture]).iter_records({}))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].domain, "spreadsheet-operations")
        self.assertEqual(records[0].outcome_status, "success")
        self.assertIn("数式", records[0].claim)
        self.assertEqual(records[1].benefit, "avoided_failure")

    def test_malformed_lines_are_skipped_without_fabricating_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rollout.jsonl"
            path.write_text(
                '{"type":"session_meta","payload":{"id":"s"}}\n'
                '{"type":"turn_context","cwd":"cwd:hash","domain":"engineering"}\n'
                '{"type":"response_item","kind":"reusable_knowledge","title":7,"claim":"invalid","benefit":"reduced_search"}\n'
                '{"type":"unknown","prompt":"must not be copied"}\n',
                encoding="utf-8",
            )
            adapter = RolloutSummaryAdapter([path])
            self.assertEqual(list(adapter.iter_records({})), [])
            self.assertGreaterEqual(adapter.parse_skipped, 2)
            self.assertNotIn("must not be copied", json.dumps(adapter.health))


if __name__ == "__main__":
    unittest.main()
