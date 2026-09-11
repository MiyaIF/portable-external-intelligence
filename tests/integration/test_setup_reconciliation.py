from __future__ import annotations

import copy
import unittest

from ei.setup_reconciliation import assert_plan_current, build_desired_state, plan_setup_reconciliation


class SetupReconciliationIntegrationTests(unittest.TestCase):
    def test_plan_is_pure_and_stale_check_does_not_mutate_inputs(self) -> None:
        current = {
            "engine_root": "C:/engine",
            "personal_knowledge_root": "C:/personal",
            "runtime_root": "C:/runtime",
            "personal": {"root": "C:/personal", "mode": "local", "remote_fingerprint": None},
            "team": None,
            "providers": ["ollama"],
            "privacy_profile": "private-reusable",
            "experiment_enabled": False,
            "hosts": {},
            "scheduler": {"enabled": False},
        }
        live = copy.deepcopy(current)
        before_current = copy.deepcopy(current)
        before_live = copy.deepcopy(live)
        desired = build_desired_state(current=current, explicit={"providers": ["ollama", "local-openai-compatible"]})
        plan = plan_setup_reconciliation(current, desired, live)
        self.assertEqual(current, before_current)
        self.assertEqual(live, before_live)
        self.assertEqual(plan.status, "UPDATED")
        assert_plan_current(plan, live)

    def test_error_payload_does_not_disclose_sensitive_identifiers(self) -> None:
        current = {
            "personal_knowledge_root": "C:/private/secret",
            "runtime_root": "C:/runtime",
            "personal": {"root": "C:/private/secret", "mode": "local", "remote_fingerprint": None},
            "team": {"enabled": True, "root": "Z:/shared/private", "store_id": "team_0123456789abcdef", "team_member_id": "member-secret", "writer_id": "writer_0123456789abcdef"},
        }
        desired = build_desired_state(current, {"runtime_root": "C:/new-runtime"})
        plan = plan_setup_reconciliation(current, desired, current)
        error = plan.errors[0]
        serialized = repr(error)
        self.assertNotIn("C:/private/secret", serialized)
        self.assertNotIn("Z:/shared/private", serialized)
        self.assertNotIn("member-secret", serialized)
        self.assertNotIn("writer_0123456789abcdef", serialized)


if __name__ == "__main__":
    unittest.main()
