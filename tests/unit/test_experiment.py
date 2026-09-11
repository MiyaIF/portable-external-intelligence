import unittest

from ei.experiment import Variant, assign_arm, assign_variant


class ExperimentTests(unittest.TestCase):
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
