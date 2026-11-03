import json
import re
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from ei.capture_contract import CaptureReceipt, capture_key, pending_policy
from ei.hooks.base import NormalizedHookEvent
from ei.ids import new_event_id
from ei.journal import JournalIntegrityError, validate_schema
from ei.models import CaptureContext
from ei.queue import _new_queue_id
from tests.unattended_helpers import NOW, identity


class CaptureContractTests(unittest.TestCase):
    @staticmethod
    def _receipt(candidate_ids, candidate_hashes=()):
        return {
            "capture_id": "sha256:" + "8" * 64,
            "state": "SECURED",
            "candidate_ids": list(candidate_ids),
            "covered_target_ids": ["sha256:" + "a" * 64],
            "reason_code": "CAPTURE_SECURED",
            "updated_at": "2026-09-18T00:00:00Z",
            "candidate_hashes": [list(pair) for pair in candidate_hashes],
        }

    def test_missing_record_identity_is_not_a_shared_key(self):
        self.assertIsNone(capture_key(replace(identity(), record_hash=None)))
        self.assertEqual(capture_key(identity()), capture_key(identity()))
        self.assertNotEqual(capture_key(identity()), capture_key(identity("b")))

    def test_stable_record_key_allows_unknown_session_and_turn(self):
        uncorrelated = replace(identity(), session_hash=None, turn_hash=None)

        self.assertEqual(
            capture_key(uncorrelated),
            "sha256:ec18d47d79fab7e1823296cc5a54048701bece06fa17fcc8516446de2a76bb36",
        )

    def test_every_present_identity_field_is_validated_before_missing_record_returns_none(self):
        with self.assertRaisesRegex(ValueError, "^CAPTURE_HOST_INVALID$"):
            capture_key(replace(identity(), host_id="C:/host", record_hash=None))
        with self.assertRaisesRegex(ValueError, "^CAPTURE_ID_INVALID$"):
            capture_key(replace(identity(), turn_hash="<missing-turn>", record_hash=None))

    def test_capture_key_separates_host_instance_store_and_record(self):
        original = identity()
        variants = (
            replace(original, host_id="codex-app"),
            replace(original, instance_hash="sha256:" + "5" * 64),
            replace(original, store_id="sha256:" + "6" * 64),
            replace(original, record_hash="sha256:" + "7" * 64),
        )

        self.assertEqual(len({capture_key(original), *(capture_key(item) for item in variants)}), 5)

    def test_explicit_old_retention_survives(self):
        self.assertEqual(pending_policy({}).ttl_seconds, 2_592_000)
        self.assertEqual(pending_policy({"ttl_seconds": 600}).ttl_seconds, 600)
        self.assertEqual(pending_policy({"ttl_seconds": 600, "pending": {"ttl_seconds": 900}}).ttl_seconds, 900)
        with self.assertRaisesRegex(ValueError, "^PENDING_POLICY_INVALID$"):
            pending_policy({"max_items": True})

    def test_shipped_policy_uses_new_pending_limits_without_replacing_legacy_limits(self):
        policy = json.loads((Path(__file__).parents[2] / "policies" / "capture-policy.json").read_text(encoding="utf-8"))

        self.assertEqual(policy["ttl_seconds"], 604_800)
        self.assertEqual(policy["max_items"], 10_000)
        self.assertEqual(policy["max_bytes"], 536_870_912)
        self.assertEqual(pending_policy(policy).ttl_seconds, 2_592_000)
        self.assertEqual(pending_policy(policy).max_items, 1_000)
        self.assertEqual(pending_policy(policy).max_bytes, 67_108_864)

    def test_receipt_uses_utc_datetime_and_optional_candidate_hash_pairs(self):
        receipt = CaptureReceipt(
            capture_id="sha256:" + "8" * 64,
            state="SECURED",
            candidate_ids=("sha256:" + "9" * 64,),
            covered_target_ids=("sha256:" + "a" * 64,),
            reason_code="CAPTURE_SECURED",
            updated_at=NOW,
            candidate_hashes=(("sha256:" + "9" * 64, "sha256:" + "b" * 64),),
        )

        self.assertEqual(receipt.updated_at, NOW)
        self.assertEqual(receipt.candidate_hashes[0][0], receipt.candidate_ids[0])
        with self.assertRaisesRegex(ValueError, "^CAPTURE_TIME_INVALID$"):
            replace(receipt, updated_at=datetime(2026, 9, 18))

    def test_capture_identity_is_optional_on_legacy_contexts_and_hook_events(self):
        context = CaptureContext("session", "turn", 1)
        event = NormalizedHookEvent(
            event_id="evt_20260918T000000000000Z_aaaaaaaaaaaa",
            idempotency_key="sha256:" + "1" * 64,
            host_id="codex-cli",
            host_instance_id="instance-a",
            host_event_name="turn.stop",
            normalized_event_name="turn.stop",
            session_id_hash="sha256:" + "2" * 64,
            turn_id_hash="sha256:" + "3" * 64,
            cwd_hash="sha256:" + "4" * 64,
            source_ref=None,
            source_hash="sha256:" + "5" * 64,
            payload_hash="sha256:" + "6" * 64,
            received_at=NOW,
            privacy_classification="private-reusable",
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
        )

        self.assertIsNone(context.capture_identity)
        self.assertIsNone(event.capture_identity)
        self.assertNotIn("capture_identity", event.to_dict())

    def test_hook_event_serializes_trusted_capture_identity_only_when_supplied(self):
        event = NormalizedHookEvent(
            event_id="evt_20260918T000000000000Z_aaaaaaaaaaaa",
            idempotency_key="sha256:" + "1" * 64,
            host_id="codex-cli",
            host_instance_id="instance-a",
            host_event_name="turn.stop",
            normalized_event_name="turn.stop",
            session_id_hash="sha256:" + "2" * 64,
            turn_id_hash="sha256:" + "3" * 64,
            cwd_hash="sha256:" + "4" * 64,
            source_ref=None,
            source_hash="sha256:" + "5" * 64,
            payload_hash="sha256:" + "6" * 64,
            received_at=NOW,
            privacy_classification="private-reusable",
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
            capture_identity=identity(),
        )

        self.assertEqual(
            event.to_dict()["capture_identity"],
            {
                "host_id": "codex-cli",
                "instance_hash": "sha256:" + "1" * 64,
                "store_id": "sha256:" + "2" * 64,
                "session_hash": "sha256:" + "3" * 64,
                "turn_hash": "sha256:" + "4" * 64,
                "record_hash": "sha256:" + "a" * 64,
            },
        )

    def test_runtime_schema_accepts_capture_identity_and_rejects_untrusted_fields(self):
        event = NormalizedHookEvent(
            event_id="evt_20260918T000000000000Z_aaaaaaaaaaaa",
            idempotency_key="sha256:" + "1" * 64,
            host_id="codex-cli",
            host_instance_id="instance-a",
            host_event_name="turn.stop",
            normalized_event_name="turn.stop",
            session_id_hash="sha256:" + "2" * 64,
            turn_id_hash="sha256:" + "3" * 64,
            cwd_hash="sha256:" + "4" * 64,
            source_ref=None,
            source_hash="sha256:" + "5" * 64,
            payload_hash="sha256:" + "6" * 64,
            received_at=NOW,
            privacy_classification="private-reusable",
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
            capture_identity=identity(),
        ).to_dict()

        validate_schema("hook-event", event)
        invalid = dict(event)
        invalid["capture_identity"] = {**event["capture_identity"], "store_id": "C:/private/store"}
        with self.assertRaisesRegex(JournalIntegrityError, "hook-event.capture_identity.store_id"):
            validate_schema("hook-event", invalid)

    def test_runtime_receipt_schema_enforces_state_evidence_and_no_free_text(self):
        receipt = {
            "capture_id": "sha256:" + "8" * 64,
            "state": "SECURED",
            "candidate_ids": ["sha256:" + "9" * 64],
            "covered_target_ids": ["sha256:" + "a" * 64],
            "reason_code": "CAPTURE_SECURED",
            "updated_at": "2026-09-18T00:00:00Z",
            "candidate_hashes": [["sha256:" + "9" * 64, "sha256:" + "b" * 64]],
        }

        validate_schema("capture-receipt", receipt)
        with self.assertRaisesRegex(JournalIntegrityError, "capture-receipt.candidate_ids"):
            validate_schema("capture-receipt", {**receipt, "candidate_ids": []})
        with self.assertRaisesRegex(JournalIntegrityError, "capture-receipt.body"):
            validate_schema("capture-receipt", {**receipt, "body": "must not persist"})

    def test_runtime_receipt_schema_accepts_legacy_unknown_without_hash_pairs(self):
        receipt = {
            "capture_id": "sha256:" + "8" * 64,
            "state": "UNKNOWN",
            "candidate_ids": [],
            "covered_target_ids": ["sha256:" + "a" * 64],
            "reason_code": "LEGACY_EVIDENCE_UNKNOWN",
            "updated_at": "2026-09-18T00:00:00Z",
        }

        validate_schema("capture-receipt.schema.json", receipt)

    def test_schema_candidate_reference_patterns_accept_real_queue_event_and_hash_ids(self):
        event_id = new_event_id(NOW, "capture-contract-machine")
        queue_id = _new_queue_id(event_id, "sha256:" + "c" * 64, "codex-cli")
        hash_id = "sha256:" + "d" * 64
        schema = json.loads((Path(__file__).parents[2] / "schemas" / "capture-receipt.schema.json").read_text(encoding="utf-8"))
        candidate_pattern = schema["properties"]["candidate_ids"]["items"]["pattern"]
        pair_id_pattern = schema["properties"]["candidate_hashes"]["items"]["prefixItems"][0]["pattern"]

        for candidate_id in (queue_id, event_id, hash_id):
            with self.subTest(candidate_id=candidate_id):
                self.assertIsNotNone(re.fullmatch(candidate_pattern, candidate_id))
                self.assertIsNotNone(re.fullmatch(pair_id_pattern, candidate_id))

    def test_schema_declares_runtime_semantic_validation_boundary(self):
        schema = json.loads((Path(__file__).parents[2] / "schemas" / "capture-receipt.schema.json").read_text(encoding="utf-8"))

        self.assertEqual(schema["x-runtime-semantic-validator"], 'ei.journal.validate_schema("capture-receipt", value)')
        self.assertEqual(
            schema["x-candidate-hashes-semantics"],
            {"partial": True, "id_membership": "candidate_ids", "max_hashes_per_id": 1},
        )

    def test_runtime_receipt_accepts_real_queue_event_ids_and_partial_hash_mapping(self):
        event_id = new_event_id(NOW, "capture-contract-machine")
        queue_id = _new_queue_id(event_id, "sha256:" + "c" * 64, "codex-cli")
        receipt = self._receipt(
            (queue_id, event_id),
            ((queue_id, "sha256:" + "d" * 64),),
        )

        validate_schema("capture-receipt", receipt)

    def test_runtime_receipt_rejects_unknown_candidate_hash_mapping(self):
        listed_id = "sha256:" + "c" * 64
        unknown_id = "sha256:" + "d" * 64
        receipt = self._receipt(
            (listed_id,),
            ((unknown_id, "sha256:" + "e" * 64),),
        )

        with self.assertRaisesRegex(JournalIntegrityError, "capture-receipt.candidate_hashes"):
            validate_schema("capture-receipt", receipt)

    def test_runtime_receipt_rejects_multiple_hashes_for_one_candidate(self):
        candidate_id = "sha256:" + "c" * 64
        receipt = self._receipt(
            (candidate_id,),
            (
                (candidate_id, "sha256:" + "d" * 64),
                (candidate_id, "sha256:" + "e" * 64),
            ),
        )

        with self.assertRaisesRegex(JournalIntegrityError, "capture-receipt.candidate_hashes"):
            validate_schema("capture-receipt", receipt)

    def test_runtime_receipt_rejects_malformed_path_and_free_text_candidate_ids(self):
        for candidate_id in ("queue_abc", "C:/private/queue", "candidate from prompt"):
            with self.subTest(candidate_id=candidate_id):
                with self.assertRaisesRegex(JournalIntegrityError, "capture-receipt.candidate_ids"):
                    validate_schema("capture-receipt", self._receipt((candidate_id,)))


if __name__ == "__main__":
    unittest.main()
