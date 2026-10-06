import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.adapters.rollout_summary import RolloutSummaryAdapter


class RolloutAdapterTests(unittest.TestCase):
    def test_verified_bytes_reuse_parser_without_reopening_source(self):
        path = Path("tests/fixtures/memories/sample_rollout.jsonl").resolve()
        raw, metadata = path.read_bytes(), path.stat()
        expected = list(RolloutSummaryAdapter([]).read(path))
        with patch.object(Path, "read_bytes", side_effect=AssertionError("reopened")), patch.object(Path, "stat", side_effect=AssertionError("restat")):
            actual = list(RolloutSummaryAdapter([]).read_verified(path, raw, metadata))
        self.assertEqual(actual, expected)
        self.assertNotEqual(actual[0].stable_record_id, actual[1].stable_record_id)

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
