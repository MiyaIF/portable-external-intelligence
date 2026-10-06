import unittest

from ei.experiment import Variant, assign_arm, assign_variant


class ExperimentTests(unittest.TestCase):
    def test_prepare_keeps_assignment_and_no_partial_duplicate_scan_append(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from ei.experiment import prepare_exposure
        from ei.operation_runtime import OperationBudget
        from tests.integration.test_unattended_operation import RemainingBudget
        from tests.unit.test_retrieve import RetrievalTests
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exposures.jsonl"
            patterns = [RetrievalTests._host_pattern()]
            first = prepare_exposure("one", "retrieval-v1", "reuse rule", patterns, record_path=path)
            before = path.read_bytes()
            self.assertEqual(prepare_exposure("one", "retrieval-v1", "reuse rule", patterns, record_path=path, budget=OperationBudget(5000)), first)
            self.assertEqual(path.read_bytes(), before)
            budget = RemainingBudget()
            loads = json.loads
            def expire(raw):
                value = loads(raw)
                budget.remaining = 0
                return value
            with patch("ei.experiment.json.loads", side_effect=expire), self.assertRaises(TimeoutError):
                prepare_exposure("two", "retrieval-v1", "reuse rule", patterns, record_path=path, budget=budget)
            self.assertEqual(path.read_bytes(), before)
            prepare_exposure("two", "retrieval-v1", "reuse rule", patterns, record_path=path, budget=OperationBudget(5000))
            self.assertEqual(len(path.read_text().splitlines()), 2)

    def test_assignment_is_stable_for_same_session(self):
        first = assign_variant("session-123", "retrieval-v1")
        second = assign_variant("session-123", "retrieval-v1")
        self.assertEqual(first, second)
        self.assertIn(first.value, {"control", "treatment"})

    def test_assign_arm_is_stable_for_already_hashed_session_id(self):
        session_hash = "sha256:" + "a" * 12
        first = assign_arm(session_hash, "retrieval-v1")
        second = assign_arm(session_hash, "retrieval-v1")
        self.assertEqual(first, second)
        self.assertIn(first, {"control", "treatment"})
    def test_different_experiment_changes_hash_namespace(self):
        assignments = {assign_variant(f"session-{i}", "retrieval-v1").value for i in range(50)}
        self.assertEqual(assignments, {"control", "treatment"})


if __name__ == "__main__":
    unittest.main()
