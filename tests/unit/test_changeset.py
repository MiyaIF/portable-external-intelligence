from __future__ import annotations

import tempfile
import unittest
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import ei.changeset as changeset_module
from ei.changeset import ApplyResult, ChangeOperation, ChangeSet, apply_changeset, validate_changeset
from ei.config import RuntimePaths, Settings
from ei.ids import machine_id, stable_hash
from ei.journal import append_event, iter_events, read_event, JournalLimitError
from ei.models import Event, ValidationResult


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


def applied_observation(root: Path):
    configured = settings(root)
    value = changeset(ChangeOperation("CREATE_OBSERVATION", "obs_proof", payload(
        title="Observed",
        claim="A verified observation is retained only when evidence and a reusable benefit are present.",
        domain="cli-agent",
    )))
    return configured, value, apply_changeset(value, configured)


def journal_event_path(event_root: Path, event_id: str, occurred_at: str) -> Path:
    partition = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    return event_root / partition.strftime("%Y") / partition.strftime("%m") / f"{event_id}.json"


def tree_snapshot(root: Path):
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.is_dir(),
            path.read_bytes() if path.is_file() else None,
        )
        for path in sorted(root.rglob("*"))
    )


class ChangeSetTests(unittest.TestCase):
    def test_policy_read_deadline_is_not_misclassified_as_invalid_policy(self):
        from dataclasses import replace
        from ei.changeset import _policy
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            configured = replace(settings(root), promotion_policy_path=policy)
            with patch("ei.operation_runtime._read_json", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")):
                with self.assertRaisesRegex(TimeoutError, "OPERATION_BUDGET_EXHAUSTED"):
                    _policy(configured, budget=OperationBudget(5000))

    def test_shared_budget_stops_before_journal_or_failure_audit(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            value = changeset(ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE")))
            for action in (validate_changeset, apply_changeset):
                with self.subTest(action=action.__name__):
                    try:
                        with self.assertRaises(TimeoutError):
                            action(value, configured, budget=OperationBudget(0))
                    except TypeError as exc:
                        self.fail(str(exc))
            self.assertEqual(list(Path(tmp).rglob("*")), [])

    def test_fixed_journal_limit_is_not_reported_as_corruption(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            configured.paths.event_dir.mkdir(parents=True)
            (configured.paths.event_dir / "too-large.json").write_bytes(b" " * (8 * 1024 * 1024 + 1))
            value = changeset(ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE")))
            try:
                with self.assertRaisesRegex(ValueError, "JOURNAL_BOUNDED_LIMIT"):
                    apply_changeset(value, configured, budget=OperationBudget(5000))
            except TypeError as exc:
                self.fail(str(exc))

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

    def test_apply_returns_original_marker_reference_across_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            operation = ChangeOperation("CREATE_OBSERVATION", "obs_marker", payload(
                title="Observed",
                claim="A verified observation is retained only when evidence and a reusable benefit are present.",
                domain="cli-agent",
            ))
            original = changeset(operation)
            first = apply_changeset(original, configured)
            self.assertTrue(first.applied)
            self.assertEqual(first.reason_code, "APPLIED")

            marker = next(
                event for event in iter_events(configured.paths.event_dir)
                if event.event_type == "curation.changeset.applied"
            )
            first_ref = getattr(first, "application_ref", None)
            self.assertIsNotNone(first_ref)
            self.assertEqual(
                (first_ref.marker_id, first_ref.occurred_at, first_ref.changeset_hash),
                (marker.event_id, marker.occurred_at, original.fingerprint),
            )
            self.assertEqual(first_ref.changeset_hash, marker.payload["changeset_hash"])

            later = replace(original, generated_at="2026-09-01T00:00:00+00:00")
            self.assertNotEqual(original.fingerprint, later.fingerprint)
            event_reader = __import__("ei.changeset", fromlist=["_events"])._events
            with patch("ei.changeset._events", wraps=event_reader) as event_reads:
                second = apply_changeset(later, configured)
            self.assertEqual(event_reads.call_count, 1)
            self.assertTrue(second.already_applied)
            self.assertEqual(second.event_ids, ())
            self.assertEqual(second.application_ref, first_ref)
            self.assertEqual(second.application_ref.occurred_at, marker.occurred_at)
            self.assertTrue(second.application_ref.occurred_at.startswith("2026-08-"))

            same_time = apply_changeset(original, configured)
            self.assertTrue(same_time.already_applied)
            self.assertEqual(same_time.application_ref, first_ref)

            different_content = replace(original, candidate_id="cand_other")
            self.assertNotEqual(original.fingerprint, different_content.fingerprint)
            changed = apply_changeset(different_content, configured)
            self.assertTrue(changed.already_applied)
            self.assertEqual(changed.application_ref, first_ref)
            self.assertEqual(changed.application_ref.changeset_hash, original.fingerprint)

    def test_read_application_proof_verifies_original_apply_after_generated_at_moves_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configured, original, first = applied_observation(root)
            self.assertTrue(first.applied)
            self.assertIsNotNone(first.application_ref)

            requested = replace(original, generated_at="2026-09-01T00:00:00+00:00")
            self.assertNotEqual(requested.fingerprint, original.fingerprint)
            replay = apply_changeset(requested, configured)
            self.assertTrue(replay.already_applied)
            self.assertEqual(replay.application_ref, first.application_ref)

            getter = getattr(changeset_module, "read_application_proof", None)
            self.assertTrue(callable(getter), "read_application_proof must be implemented")
            requested_before = requested.to_dict()
            original_before = original.to_dict()
            files_before = tree_snapshot(root)
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                same_time_proof = getter(original, configured, application_ref=first.application_ref)
                proof = getter(requested, configured, application_ref=replay.application_ref)

            self.assertEqual(requested.to_dict(), requested_before)
            self.assertEqual(original.to_dict(), original_before)
            self.assertEqual(tree_snapshot(root), files_before)
            expected = ApplyResult(
                True,
                "APPLICATION_PROOF_VERIFIED",
                first.event_ids,
                original.changeset_id,
                True,
                ValidationResult(True, ("APPLICATION_PROOF_VERIFIED",)),
                first.application_ref,
            )
            self.assertEqual(same_time_proof, expected)
            self.assertEqual(proof, expected)

    def test_read_application_proof_rejects_changeset_identity_differences(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured, original, applied = applied_observation(Path(tmp))
            self.assertTrue(applied.applied)
            changed_operation = ChangeOperation("CREATE_OBSERVATION", "obs_proof", payload(
                title="Observed",
                claim="A different claim must not reuse an existing application proof.",
                domain="cli-agent",
            ))
            changed_host = replace(
                original,
                source_host_id="codex-cli",
                source_host_family="codex-compatible",
                applicability_scope="host",
                applicable_host_ids=("codex-cli",),
            )
            changed_values = (
                replace(original, operations=(changed_operation,)),
                changed_host,
                replace(original, policy_version="promotion-v2"),
                replace(original, provider_id="other-provider"),
                replace(original, source_hashes=(digest("c"),)),
            )
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                for changed in changed_values:
                    with self.subTest(changed=changed.to_dict()):
                        proof = changeset_module.read_application_proof(
                            changed, configured, application_ref=applied.application_ref
                        )
                        self.assertFalse(proof.applied)
                        self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
                        self.assertEqual(proof.event_ids, ())
                        self.assertEqual(proof.changeset_id, original.changeset_id)
                        self.assertIsNone(proof.application_ref)

    def test_read_application_proof_rejects_invalid_schema_and_untrusted_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured, original, applied = applied_observation(Path(tmp))
            self.assertTrue(applied.applied)
            ref = applied.application_ref
            invalid_refs = (
                replace(ref, occurred_at="2026-08-27T12:01:00+00:00"),
                replace(ref, occurred_at="2026-09-01T00:00:00+00:00"),
                replace(ref, changeset_hash=digest("f")),
                replace(ref, marker_id="evt_changeset_" + "f" * 32),
                replace(ref, marker_id="evt_changeset_../outside"),
            )
            invalid_changeset = original.to_dict()
            invalid_changeset["unexpected"] = "forbidden"
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                schema_result = changeset_module.read_application_proof(
                    invalid_changeset, configured, application_ref=ref
                )
                self.assertFalse(schema_result.applied)
                self.assertEqual(schema_result.reason_code, "APPLICATION_PROOF_INVALID")
                self.assertEqual(schema_result.changeset_id, original.changeset_id)
                for invalid_ref in invalid_refs:
                    with self.subTest(application_ref=invalid_ref):
                        proof = changeset_module.read_application_proof(
                            original, configured, application_ref=invalid_ref
                        )
                        self.assertFalse(proof.applied)
                        self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
                        self.assertEqual(proof.event_ids, ())
                        self.assertIsNone(proof.application_ref)

    def test_read_application_proof_rejects_missing_marker_or_operation(self):
        for missing_marker in (True, False):
            with self.subTest(missing_marker=missing_marker), tempfile.TemporaryDirectory() as tmp:
                configured, original, applied = applied_observation(Path(tmp))
                self.assertTrue(applied.applied)
                event_id = applied.application_ref.marker_id if missing_marker else applied.event_ids[0]
                path = journal_event_path(configured.paths.event_dir, event_id, applied.application_ref.occurred_at)
                path.unlink()
                with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                        patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                    proof = changeset_module.read_application_proof(
                        original, configured, application_ref=applied.application_ref
                    )
                self.assertFalse(proof.applied)
                self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
                self.assertEqual(proof.event_ids, ())
                self.assertIsNone(proof.application_ref)

    def test_read_application_proof_rejects_tampered_operation_and_event_id_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured, original, applied = applied_observation(Path(tmp))
            self.assertTrue(applied.applied)
            operation_path = journal_event_path(
                configured.paths.event_dir, applied.event_ids[0], applied.application_ref.occurred_at
            )
            tampered_operation = json.loads(operation_path.read_text(encoding="utf-8"))
            tampered_operation["payload"]["claim"] = "tampered after its stored integrity was computed"
            operation_path.write_text(json.dumps(tampered_operation), encoding="utf-8")
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                proof = changeset_module.read_application_proof(
                    original, configured, application_ref=applied.application_ref
                )
            self.assertFalse(proof.applied)
            self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
            self.assertIsNone(proof.application_ref)

        for event_ids in ([], ["evt_changeset_" + "f" * 32]):
            with self.subTest(event_ids=event_ids), tempfile.TemporaryDirectory() as tmp:
                configured, original, applied = applied_observation(Path(tmp))
                marker_path = journal_event_path(
                    configured.paths.event_dir,
                    applied.application_ref.marker_id,
                    applied.application_ref.occurred_at,
                )
                marker = read_event(marker_path)
                changed_payload = dict(marker.payload)
                changed_payload["event_ids"] = event_ids
                changed_id = "evt_changeset_" + stable_hash(
                    {"changeset_id": original.changeset_id, "marker": changed_payload}
                )[:32]
                changed_marker = Event.create(
                    marker.event_type,
                    marker.occurred_at,
                    marker.actor,
                    marker.machine_id,
                    changed_payload,
                    event_id=changed_id,
                )
                marker_path.unlink()
                changed_path = journal_event_path(
                    configured.paths.event_dir, changed_id, marker.occurred_at
                )
                changed_path.write_text(
                    json.dumps(changed_marker.to_dict(), ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                changed_ref = changeset_module.AppliedMarkerRef(
                    changed_id, marker.occurred_at, original.fingerprint
                )
                with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                        patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                    proof = changeset_module.read_application_proof(
                        original, configured, application_ref=changed_ref
                    )
                self.assertFalse(proof.applied)
                self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
                self.assertIsNone(proof.application_ref)

    def test_read_application_proof_checks_operation_metadata_even_with_valid_integrity(self):
        changed_fields = (
            ("changeset_id", "cs_other"),
            ("candidate_id", "cand_other"),
            ("change_operation", "NO_CHANGE"),
            ("policy_version", "promotion-v2"),
            ("provider_id", "other-provider"),
            ("source_hashes", [digest("b")]),
        )
        for field, changed_value in changed_fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                configured, original, applied = applied_observation(Path(tmp))
                operation_path = journal_event_path(
                    configured.paths.event_dir,
                    applied.event_ids[0],
                    applied.application_ref.occurred_at,
                )
                event = read_event(operation_path)
                changed_payload = dict(event.payload)
                changed_payload[field] = changed_value
                changed_event = Event.create(
                    event.event_type,
                    event.occurred_at,
                    event.actor,
                    event.machine_id,
                    changed_payload,
                    event_id=event.event_id,
                )
                operation_path.write_text(
                    json.dumps(changed_event.to_dict(), ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                        patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                    proof = changeset_module.read_application_proof(
                        original, configured, application_ref=applied.application_ref
                    )
                self.assertFalse(proof.applied)
                self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
                self.assertEqual(proof.event_ids, ())
                self.assertIsNone(proof.application_ref)

    def test_read_application_proof_rejects_non_integer_marker_operation_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured, original, applied = applied_observation(Path(tmp))
            marker_path = journal_event_path(
                configured.paths.event_dir,
                applied.application_ref.marker_id,
                applied.application_ref.occurred_at,
            )
            marker = read_event(marker_path)
            malformed_payload = dict(marker.payload)
            malformed_payload["operation_count"] = True
            malformed_id = "evt_changeset_" + stable_hash(
                {"changeset_id": original.changeset_id, "marker": malformed_payload}
            )[:32]
            malformed_marker = Event.create(
                marker.event_type,
                marker.occurred_at,
                marker.actor,
                marker.machine_id,
                malformed_payload,
                event_id=malformed_id,
            )
            marker_path.unlink()
            malformed_path = journal_event_path(
                configured.paths.event_dir, malformed_id, marker.occurred_at
            )
            malformed_path.write_text(
                json.dumps(malformed_marker.to_dict(), ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            malformed_ref = changeset_module.AppliedMarkerRef(
                malformed_id, marker.occurred_at, original.fingerprint
            )
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                proof = changeset_module.read_application_proof(
                    original, configured, application_ref=malformed_ref
                )
            self.assertFalse(proof.applied)
            self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
            self.assertIsNone(proof.application_ref)

    def test_read_application_proof_rejects_symlinked_partition(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured, original, applied = applied_observation(Path(tmp))
            year_dir = configured.paths.event_dir / "2026"
            month_dir = year_dir / "08"
            real_month_dir = year_dir / "08-real"
            month_dir.rename(real_month_dir)
            try:
                month_dir.symlink_to(real_month_dir, target_is_directory=True)
            except (OSError, NotImplementedError, AttributeError) as exc:
                self.skipTest(f"directory symlink support unavailable: {type(exc).__name__}")
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                proof = changeset_module.read_application_proof(
                    original, configured, application_ref=applied.application_ref
                )
            self.assertFalse(proof.applied)
            self.assertEqual(proof.reason_code, "APPLICATION_PROOF_INVALID")
            self.assertIsNone(proof.application_ref)

    def test_read_application_proof_is_read_only_and_preserves_deadline_and_journal_limit(self):
        from ei.operation_runtime import OperationBudget

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configured, original, applied = applied_observation(root)
            files_before = tree_snapshot(root)
            with patch("ei.changeset._events", side_effect=AssertionError("proof getter scanned the journal")), \
                    patch("ei.changeset.iter_events", side_effect=AssertionError("proof getter scanned the journal")):
                with self.assertRaisesRegex(TimeoutError, "OPERATION_BUDGET_EXHAUSTED"):
                    changeset_module.read_application_proof(
                        original,
                        configured,
                        application_ref=applied.application_ref,
                        budget=OperationBudget(0),
                    )
            self.assertEqual(tree_snapshot(root), files_before)

            marker_path = journal_event_path(
                configured.paths.event_dir,
                applied.application_ref.marker_id,
                applied.application_ref.occurred_at,
            )
            marker_path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(JournalLimitError, "JOURNAL_BOUNDED_LIMIT"):
                changeset_module.read_application_proof(
                    original, configured, application_ref=applied.application_ref
                )

    def test_invalid_existing_marker_fields_have_no_application_reference(self):
        value = changeset(ChangeOperation("CREATE_OBSERVATION", "obs_marker", payload(
            title="Observed",
            claim="A verified observation is retained only when evidence and a reusable benefit are present.",
            domain="cli-agent",
        )))
        cases = (
            ("invalid id", "evt_changeset_invalid", NOW.isoformat(), value.fingerprint),
            ("missing id", "", NOW.isoformat(), value.fingerprint),
            ("invalid time", "evt_changeset_" + "a" * 32, "2026-08-27T12:00:00", value.fingerprint),
            ("missing time", "evt_changeset_" + "a" * 32, "", value.fingerprint),
            ("invalid hash", "evt_changeset_" + "a" * 32, NOW.isoformat(), "sha256:bad"),
            ("missing hash", "evt_changeset_" + "a" * 32, NOW.isoformat(), None),
        )
        for label, marker_id, occurred_at, marker_hash in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                configured = settings(Path(tmp))
                marker_payload = {"changeset_id": value.changeset_id}
                if marker_hash is not None:
                    marker_payload["changeset_hash"] = marker_hash
                marker = Event.create(
                    "curation.changeset.applied",
                    NOW.isoformat(),
                    "external-intelligence",
                    machine_id(),
                    marker_payload,
                    event_id="evt_changeset_" + "a" * 32,
                )
                marker = replace(marker, event_id=marker_id, occurred_at=occurred_at)
                with patch("ei.changeset._events", return_value=[marker]) as event_reads:
                    result = apply_changeset(value, configured)
                self.assertEqual(event_reads.call_count, 1)
                self.assertTrue(result.already_applied)
                self.assertEqual(result.reason_code, "ALREADY_APPLIED")
                self.assertEqual(result.event_ids, ())
                self.assertIsNone(result.application_ref)

    def test_utc_conversion_overflow_preserves_existing_apply_result(self):
        value = changeset(ChangeOperation("CREATE_OBSERVATION", "obs_marker", payload(
            title="Observed",
            claim="A verified observation is retained only when evidence and a reusable benefit are present.",
            domain="cli-agent",
        )))
        cases = (
            ("utc underflow", "0001-01-01T00:00:00+01:00"),
            ("utc overflow", "9999-12-31T23:59:59-01:00"),
        )
        for label, occurred_at in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                configured = settings(Path(tmp))
                marker = Event.create(
                    "curation.changeset.applied",
                    NOW.isoformat(),
                    "external-intelligence",
                    machine_id(),
                    {"changeset_id": value.changeset_id, "changeset_hash": value.fingerprint},
                    event_id="evt_changeset_" + "a" * 32,
                )
                marker = replace(marker, occurred_at=occurred_at)
                with patch("ei.changeset._events", return_value=[marker]):
                    result = apply_changeset(value, configured)
                self.assertTrue(result.applied)
                self.assertTrue(result.already_applied)
                self.assertEqual(result.reason_code, "ALREADY_APPLIED")
                self.assertEqual(result.event_ids, ())
                self.assertEqual(result.changeset_id, value.changeset_id)
                self.assertIsNone(result.application_ref)
                self.assertEqual(result.validation, ValidationResult(True, ("ALREADY_APPLIED",)))

    def test_apply_result_keeps_legacy_positional_constructor(self):
        result = ApplyResult(
            True,
            "APPLIED",
            (),
            "cs_legacy",
            False,
            ValidationResult(True, ()),
        )
        self.assertIsNone(result.application_ref)

    def test_schema_validation_and_append_failures_have_no_application_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))

            schema_failure = apply_changeset({}, configured)
            self.assertFalse(schema_failure.applied)
            self.assertIsNone(schema_failure.application_ref)

            invalid = replace(
                changeset(ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE"))),
                policy_version="promotion-v0",
            )
            validation_failure = apply_changeset(invalid, configured)
            self.assertFalse(validation_failure.applied)
            self.assertIsNone(validation_failure.application_ref)

            operation = ChangeOperation("CREATE_OBSERVATION", "obs_failure", payload(
                title="Observed",
                claim="A verified observation is retained only when evidence and a reusable benefit are present.",
                domain="cli-agent",
            ))
            with patch("ei.changeset.append_event", side_effect=RuntimeError("injected")):
                append_failure = apply_changeset(changeset(operation), configured)
            self.assertFalse(append_failure.applied)
            self.assertIsNone(append_failure.application_ref)

    def test_multi_operation_append_failure_leaves_no_new_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured = settings(Path(tmp))
            first = ChangeOperation("CREATE_OBSERVATION", "obs_one", payload(title="Observed", claim="A verified observation is retained only when evidence and a reusable benefit are present.", domain="cli-agent"))
            value = ChangeSet("cs_multi", "cand_multi", (first, ChangeOperation("NO_CHANGE", None, payload(reason_code="NO_CHANGE", source_hash=digest("b"), source_hashes=[digest("b")]))), (digest("a"), digest("b")), "promotion-v1", NOW.isoformat(), "test-provider")
            with patch("ei.changeset.append_event", side_effect=RuntimeError("injected")):
                result = apply_changeset(value, configured)
            self.assertFalse(result.applied)
            self.assertIsNone(getattr(result, "application_ref", None))
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
            self.assertIsNone(getattr(failed, "application_ref", None))
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
