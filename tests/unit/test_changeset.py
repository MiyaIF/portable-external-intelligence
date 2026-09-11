from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ei.changeset import ChangeOperation, ChangeSet, apply_changeset, validate_changeset
from ei.config import RuntimePaths, Settings
from ei.ids import machine_id
from ei.journal import append_event, iter_events
from ei.models import Event


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def settings(root: Path) -> Settings:
    repo = root / "repo"
    runtime = root / "runtime"
    paths = RuntimePaths(repo_root=repo, codex_home=root / "home", runtime_dir=runtime, event_dir=repo / "events", knowledge_dir=repo / "knowledge", local_state_dir=runtime / "state", metrics_dir=runtime / "metrics", cache_dir=runtime / "cache", locks_dir=runtime / "locks", config_path=root / "home" / "config.toml", hooks_path=root / "home" / "hooks.json", agents_path=root / "home" / "AGENTS.md")
    return Settings(paths=paths)


def payload(source_hash: str = digest("a"), **extra):
    value = {
        "actor": "test-actor",
        "provider_id": "test-provider",
        "classification": "private-reusable",
        "source_hash": source_hash,
        "source_hashes": [source_hash],
        "evidence_refs": [source_hash],
        "provenances": [source_hash, digest("b")],
        "scopes": ["cli-agent", "general"],
        "applicability": ["cli-agent"],
        "benefit_count": 1,
    }
    value.update(extra)
    return value


def changeset(operation: ChangeOperation, source_hashes=(digest("a"),)) -> ChangeSet:
    return ChangeSet("cs_test", "cand_test", (operation,), tuple(source_hashes), "promotion-v1", NOW.isoformat(), "test-provider")


class ChangeSetTests(unittest.TestCase):
    def test_schema_round_trip_and_fixed_operation_allowlist(self):
        operation = ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE"))
        value = changeset(operation)
        self.assertEqual(ChangeSet.from_mapping(value.to_dict()), value)
        raw = value.to_dict()
        raw["operations"][0]["operation"] = "DELETE_FILE"
        with self.assertRaisesRegex(ValueError, "EVENT_SCHEMA_INVALID"):
            ChangeSet.from_mapping(raw)

    def test_host_metadata_round_trip_is_closed_and_source_safe(self):
        operation = ChangeOperation(
            "NO_CHANGE",
            None,
            payload(
                reason_code="NO_CHANGE",
                source_host_id="codex-cli",
                source_host_family="codex-compatible",
                applicability_scope="family",
                applicable_host_ids=[],
                applicable_host_families=["codex-compatible"],
            ),
        )
        value = ChangeSet(
            "cs_host",
            "cand_host",
            (operation,),
            (digest("a"),),
            "promotion-v1",
            NOW.isoformat(),
            "test-provider",
            "codex-cli",
            "codex-compatible",
            "family",
            (),
            ("codex-compatible",),
        )
        restored = ChangeSet.from_mapping(value.to_dict())
        self.assertEqual(restored, value)
        self.assertNotIn("C:\\", json.dumps(restored.to_dict()))

    def test_path_and_privacy_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            invalid_target = ChangeOperation("NO_CHANGE", "../outside", payload(reason_code="NO_CHANGE"))
            result = validate_changeset(changeset(invalid_target), configured)
            self.assertFalse(result.valid)
            self.assertIn("PATH_TRAVERSAL", result.reason_codes)
            secret = ChangeOperation("NO_CHANGE", None, payload(classification="secret", reason_code="NO_CHANGE"))
            result = validate_changeset(changeset(secret), configured)
            self.assertIn("CLASSIFICATION_NOT_SYNCABLE", result.reason_codes)

    def test_stale_policy_and_source_hash_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            stale_policy = ChangeSet("cs_policy", "cand_policy", (ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE")),), (digest("a"),), "promotion-v0", NOW.isoformat(), "test-provider")
            result = validate_changeset(stale_policy, configured)
            self.assertIn("STALE_POLICY", result.reason_codes)
            stale_source = ChangeSet("cs_source", "cand_source", (ChangeOperation("NO_CHANGE", None, payload(source_hash=digest("c"), source_hashes=[digest("c")], evidence_refs=[digest("c")], reason_code="NO_CHANGE")),), (digest("a"),), "promotion-v1", NOW.isoformat(), "test-provider")
            result = validate_changeset(stale_source, configured)
            self.assertIn("SOURCE_HASH_MISMATCH", result.reason_codes)

    def test_rule_hard_cap_and_lifecycle_transition_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            huge = ChangeOperation("CREATE_CANDIDATE", "pat_new", payload(rule="x" * 12001, precondition="known", failure_mode="known", applicability=["general"]))
            result = validate_changeset(changeset(huge), configured)
            self.assertIn("RULE_HARD_CAP_EXCEEDED", result.reason_codes)
            promote = ChangeOperation("PROMOTE_PATTERN", "pat_missing", payload(rule="A verified rule with enough detail to be reviewed and promoted safely.", precondition="known", failure_mode="known", applicability=["general"]))
            result = validate_changeset(changeset(promote), configured)
            self.assertIn("INVALID_LIFECYCLE_TRANSITION", result.reason_codes)

    def test_valid_create_apply_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            operation = ChangeOperation("CREATE_CANDIDATE", "pat_new", payload(
                title="Candidate",
                rule="A verified reusable rule records the condition, safe action, exception, and validation evidence.",
                precondition="When the same structure appears again",
                failure_mode="Repeated rework",
                applicability=["cli-agent"],
            ))
            value = changeset(operation, (digest("a"), digest("b")))
            self.assertTrue(validate_changeset(value, configured).valid)
            first = apply_changeset(value, configured)
            self.assertTrue(first.applied)
            self.assertGreaterEqual(len(first.event_ids), 2)
            second = apply_changeset(value, configured)
            self.assertTrue(second.applied)
            self.assertTrue(second.already_applied)
            self.assertEqual(len(list(iter_events(configured.paths.event_dir))), len(first.event_ids))

    def test_multi_operation_append_failure_leaves_no_new_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            first = ChangeOperation("CREATE_OBSERVATION", "obs_one", payload(title="Observed", claim="A verified observation is retained only when evidence and a reusable benefit are present.", domain="cli-agent"))
            value = ChangeSet("cs_multi", "cand_multi", (first, ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE", source_hash=digest("b"), source_hashes=[digest("b")]))), (digest("a"), digest("b")), "promotion-v1", NOW.isoformat(), "test-provider")
            with patch("ei.changeset.append_event", side_effect=RuntimeError("injected")):
                result = apply_changeset(value, configured)
            self.assertFalse(result.applied)
            self.assertEqual(list(configured.paths.event_dir.rglob("*.json")), [])

    def test_partial_changeset_is_append_only_hidden_and_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            first = ChangeOperation("CREATE_OBSERVATION", "obs_one", payload(title="Observed", claim="A verified observation is retained only when evidence and a reusable benefit are present.", domain="cli-agent"))
            second = ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE", source_hash=digest("b"), source_hashes=[digest("b")]))
            value = ChangeSet("cs_partial", "cand_partial", (first, second), (digest("a"), digest("b")), "promotion-v1", NOW.isoformat(), "test-provider")
            original = __import__("ei.changeset", fromlist=["append_event"]).append_event
            calls = 0

            def fail_on_second(event, event_dir):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("injected")
                return original(event, event_dir)

            with patch("ei.changeset.append_event", side_effect=fail_on_second):
                failed = apply_changeset(value, configured)

            self.assertFalse(failed.applied)
            self.assertEqual(len(list(configured.paths.event_dir.rglob("*.json"))), 1)
            self.assertEqual(list(iter_events(configured.paths.event_dir)), [])

            retried = apply_changeset(value, configured)
            self.assertTrue(retried.applied)
            self.assertEqual(retried.reason_code, "APPLIED")
            self.assertEqual(len(list(iter_events(configured.paths.event_dir))), 3)
            self.assertEqual(len(list(configured.paths.event_dir.rglob("*.json"))), 3)

    def test_redaction_requires_explicit_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            operation = ChangeOperation("REDACT_REFERENCE", "ref_1", payload(reference_hash=digest("a")))
            result = validate_changeset(changeset(operation), configured)
            self.assertIn("REDACTION_REQUIRES_APPROVAL", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
