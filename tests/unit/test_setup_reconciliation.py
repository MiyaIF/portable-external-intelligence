from __future__ import annotations

import copy
import unittest

from ei.setup_reconciliation import (
    ReconciliationAction,
    SetupReconciliationPlan,
    assert_plan_current,
    build_desired_state,
    plan_setup_reconciliation,
)


def current_state() -> dict[str, object]:
    return {
        "engine_root": "C:/engine",
        "personal_knowledge_root": "C:/personal",
        "runtime_root": "C:/runtime",
        "personal": {
            "enabled": True,
            "mode": "local",
            "root": "C:/personal",
            "remote_name": None,
            "remote_fingerprint": None,
            "remote_classification": None,
            "branch": None,
            "connected": False,
            "initial_push_complete": False,
            "sync_enabled": False,
        },
        "team": {
            "enabled": False,
            "root": "C:/team",
            "store_id": "team_0123456789abcdef",
            "layout": "member-writer-events-v1",
            "team_member_id": "member-a",
            "writer_id": "writer_0123456789abcdef",
            "transport": "external-shared-folder",
            "transport_managed": False,
            "status": "DISABLED",
        },
        "providers": ["ollama"],
        "privacy_profile": "private-reusable",
        "experiment_enabled": False,
        "hosts": {
            "codex-cli": {
                "runtime_root": "C:/runtime",
                "managed": {
                    "hook": "sha256:" + "1" * 64,
                    "context": "sha256:" + "2" * 64,
                    "skill": "sha256:" + "3" * 64,
                    "binding": "sha256:" + "4" * 64,
                },
            }
        },
        "scheduler": {"enabled": False, "identity": None, "managed": True},
        "managed_targets": {
            "C:/runtime/managed.json": {
                "hash": "sha256:" + "5" * 64,
                "ownership_hash": "sha256:" + "5" * 64,
                "owned": True,
            }
        },
        "retained_paths": ["C:/personal"],
    }


def live_matching(current: dict[str, object]) -> dict[str, object]:
    return copy.deepcopy(
        {
            "engine_root": current["engine_root"],
            "personal_knowledge_root": current["personal_knowledge_root"],
            "runtime_root": current["runtime_root"],
            "personal": current["personal"],
            "team": current["team"],
            "providers": current["providers"],
            "privacy_profile": current["privacy_profile"],
            "experiment_enabled": current["experiment_enabled"],
            "hosts": current["hosts"],
            "scheduler": current["scheduler"],
            "managed_targets": current["managed_targets"],
        }
    )


def identity_change(field: str) -> dict[str, object]:
    values: dict[str, object] = {
        "personal_root": {"personal_knowledge_root": "C:/other-personal"},
        "team_root": {
            "team": {
                "enabled": True,
                "root": "C:/other-team",
                "store_id": "team_0123456789abcdef",
                "layout": "member-writer-events-v1",
                "team_member_id": "member-a",
                "writer_id": "writer_0123456789abcdef",
                "transport": "external-shared-folder",
                "transport_managed": False,
                "status": "READY",
            }
        },
        "runtime_root": {"runtime_root": "C:/other-runtime"},
        "remote_fingerprint": {
            "personal": {
                "enabled": True,
                "mode": "github-existing",
                "root": "C:/personal",
                "remote_name": "origin",
                "remote_fingerprint": "sha256:" + "9" * 64,
                "remote_classification": "private_verified",
                "branch": "main",
                "connected": True,
                "initial_push_complete": True,
                "sync_enabled": True,
            }
        },
    }
    return values[field]


class SetupReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = current_state()

    def test_identical_state_is_already_current(self) -> None:
        desired = build_desired_state(current=self.current, explicit={})
        plan = plan_setup_reconciliation(
            current=self.current,
            desired=desired,
            live=live_matching(self.current),
        )
        self.assertEqual(plan.status, "ALREADY_CURRENT")
        self.assertEqual(plan.actions, ())
        self.assertEqual(plan.changed_paths, ())

    def test_identity_changes_are_blocked_without_writes(self) -> None:
        cases = (
            ("personal_root", "PERSONAL_ROOT_CHANGE_REQUIRES_MIGRATION"),
            ("team_root", "TEAM_ROOT_CHANGE_REQUIRES_MIGRATION"),
            ("runtime_root", "RUNTIME_ROOT_CHANGE_REQUIRES_MIGRATION"),
            ("remote_fingerprint", "PERSONAL_REMOTE_CHANGE_REQUIRES_MIGRATION"),
        )
        for field, code in cases:
            with self.subTest(field=field):
                explicit = identity_change(field)
                plan = plan_setup_reconciliation(
                    current=self.current,
                    desired=build_desired_state(current=self.current, explicit=explicit),
                    live=live_matching(self.current),
                )
                self.assertEqual(plan.status, "BLOCKED")
                self.assertEqual(plan.errors[0]["error_code"], code)
                self.assertEqual(plan.actions, ())
                self.assertEqual(set(plan.errors[0]), {"error_code", "retryable", "data_loss_risk", "user_action", "recovery_command", "target_kind"})

    def test_safe_managed_changes_have_stable_order(self) -> None:
        explicit = {
            "providers": ["local-openai-compatible", "ollama"],
            "privacy_profile": "public",
            "experiment_enabled": True,
            "hosts": {},
            "scheduler": {"enabled": True, "identity": "scheduler-v1", "managed": True},
            "team": {
                "enabled": True,
                "root": "C:/team",
                "store_id": "team_0123456789abcdef",
                "layout": "member-writer-events-v1",
                "team_member_id": "member-a",
                "writer_id": "writer_0123456789abcdef",
                "transport": "external-shared-folder",
                "transport_managed": False,
                "status": "READY",
            },
        }
        desired = build_desired_state(current=self.current, explicit=explicit)
        live = live_matching(self.current)
        first = plan_setup_reconciliation(current=self.current, desired=desired, live=live)
        second = plan_setup_reconciliation(current=self.current, desired=desired, live=live)
        self.assertEqual(first.status, "UPDATED")
        self.assertEqual(first, second)
        self.assertEqual([item.kind for item in first.actions], ["prepare-team", "remove-host", "write-managed", "scheduler-enable", "write-manifest"])
        self.assertIn("team", first.changed_paths)
        self.assertIn("providers", first.changed_paths)

    def test_live_managed_hash_conflict_is_blocked(self) -> None:
        live = live_matching(self.current)
        live["managed_targets"]["C:/runtime/managed.json"]["hash"] = "sha256:" + "f" * 64  # type: ignore[index]
        plan = plan_setup_reconciliation(self.current, build_desired_state(self.current, {}), live)
        self.assertEqual(plan.status, "BLOCKED")
        self.assertEqual(plan.errors[0]["error_code"], "MANAGED_TARGET_CONFLICT")
        self.assertEqual(plan.actions, ())

    def test_active_runtime_binding_mismatch_is_blocked(self) -> None:
        live = live_matching(self.current)
        live["hosts"]["codex-cli"]["runtime_root"] = "C:/different-runtime"  # type: ignore[index]
        plan = plan_setup_reconciliation(self.current, build_desired_state(self.current, {}), live)
        self.assertEqual(plan.status, "BLOCKED")
        self.assertEqual(plan.errors[0]["error_code"], "ACTIVE_RUNTIME_MISMATCH")
        self.assertEqual(plan.actions, ())

    def test_digest_excludes_volatile_values_but_live_change_is_stale(self) -> None:
        desired_a = build_desired_state(self.current, {"generated_at": "2026-01-01T00:00:00Z", "transaction_id": "one"})
        desired_b = build_desired_state(self.current, {"generated_at": "2027-01-01T00:00:00Z", "transaction_id": "two"})
        self.assertEqual(desired_a["desired_state_digest"], desired_b["desired_state_digest"])
        plan = plan_setup_reconciliation(self.current, desired_a, live_matching(self.current))
        changed_live = live_matching(self.current)
        changed_live["providers"] = ["changed"]
        with self.assertRaisesRegex(ValueError, "^SETUP_PLAN_STALE$"):
            assert_plan_current(plan, changed_live)

    def test_plan_and_action_are_immutable_value_types(self) -> None:
        action = ReconciliationAction("write-managed", "providers", None, "sha256:" + "a" * 64, True)
        self.assertEqual(action.target, "providers")
        self.assertIsInstance(SetupReconciliationPlan("ALREADY_CURRENT", "sha256:" + "a" * 64, "sha256:" + "b" * 64, (), (), (), ()), SetupReconciliationPlan)


if __name__ == "__main__":
    unittest.main()
