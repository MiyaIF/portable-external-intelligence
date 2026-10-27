import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from ei.capture_contract import capture_key
from ei.capture_ledger import read_receipt
from ei.key_provider import InMemoryKeyProvider
from ei.models import ObservationInput
from ei.pending_capture import accept_candidate, reconcile_pending
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory
from ei.queue import list_queue_items, QueueState, claim_queue_item, transition_queue_item
from ei.spool import SpoolError, read_spool
from tests.unattended_helpers import NOW, identity, make_settings


def observation():
    return ObservationInput("検証", "書込後には対象範囲を再読込し結果を検証する", "agent_direct",
        "structured-test", "", "general", "success", "reduced_rework", "private-reusable",
        source_host_id="codex-cli", source_host_family="codex-compatible")


class PendingCaptureTests(unittest.TestCase):
    def test_unpublished_tagless_intent_is_preserved_without_replay_ack(self):
        from ei.runtime_catalog import RuntimeCatalog
        self.assertEqual(self.accept().state, "SECURED")
        root = self.settings.paths.runtime_dir / "state" / "capture" / "intents"
        path = next(root.rglob("pending_*.json"))
        value = json.loads(path.read_text(encoding="utf-8"))
        value.pop("admission")
        raw = json.dumps(value, sort_keys=True).encode("utf-8")
        RuntimeCatalog(root, prefix="pending_").write(path.stem, raw, purpose="intent",
            created_at=value["spool_ref"]["created_at"], expires_at=value["spool_ref"]["expires_at"])
        result = self.accept()
        self.assertEqual(result.state, "WAITING")
        self.assertEqual(result.reason_code, "SESSION_CAPTURE_HISTORY_UNKNOWN")
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        transition_queue_item(list_queue_items(self.settings)[0], QueueState.NO_DISCARDED, self.settings, now=NOW)
        recovered = self.reconcile()
        self.assertEqual(recovered["secured"], 0)
        self.assertEqual(recovered["waiting"], 1)
        self.assertEqual(path.read_bytes(), raw)

    def test_explicit_origin_metadata_does_not_infer_skill_from_body_source_kind(self):
        from ei.runtime_catalog import RuntimeCatalog
        self.assertEqual(self.accept().state, "SECURED")
        root = self.settings.paths.runtime_dir / "state" / "capture" / "intents"
        paths = tuple(root.rglob("pending_*.json"))
        value = json.loads(paths[0].read_text(encoding="utf-8"))
        self.assertEqual(value["admission"], {"origin": "UNKNOWN", "session_hash": identity().session_hash, "agent_key": None})
        self.assertEqual(RuntimeCatalog(root, prefix="pending_").tagged_paths("UNKNOWN:" + identity().session_hash, limit=1), paths)
        result = accept_candidate(self.settings, identity("b"), observation(), now=NOW, key_provider=self.key, origin="NATIVE_SOURCE")
        self.assertEqual(result.state, "SECURED")
        values = [json.loads(path.read_text(encoding="utf-8")) for path in root.rglob("pending_*.json")]
        self.assertEqual({value["admission"]["origin"] for value in values}, {"UNKNOWN", "NATIVE_SOURCE"})
        self.assertEqual(accept_candidate(self.settings, identity("c"), observation(), now=NOW, key_provider=self.key, origin="AGENT_SKILL").reason_code, "PENDING_INPUT_REJECTED")

    def test_legacy_safe_benefit_is_preserved_and_secrets_still_rejected(self):
        result = self.accept(replace(observation(), benefit="reduced_search"))
        self.assertEqual(result.state, "SECURED")
        item = list_queue_items(self.settings)[0]
        payload = json.loads(read_spool(item.payload_ref, self.settings, now=NOW, key_provider=self.key))
        self.assertEqual(payload["benefit"], "reduced_search")
        self.assertNotEqual(self.accept(replace(observation(), benefit="password=secret-value")).state, "SECURED")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_settings(Path(self.tmp.name))
        self.key = InMemoryKeyProvider("test-key", b"s" * 32)

    def accept(self, item=None, now=NOW):
        return accept_candidate(self.settings, identity(), item or observation(), now=now, key_provider=self.key)

    def policy(self, **values):
        path = self.settings.capture_policy_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"pending": values}), encoding="utf-8")

    def reconcile(self, now=NOW):
        with patch("ei.spool.default_key_provider", return_value=self.key):
            return reconcile_pending(self.settings, now=now)

    def test_repeated_delivery_has_one_durable_candidate(self):
        first, second = self.accept(), self.accept()
        self.assertEqual(first.state, "SECURED")
        self.assertEqual(first.candidate_ids, second.candidate_ids)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        item = list_queue_items(self.settings)[0]
        self.assertEqual(item.capture_id, capture_key(identity()))
        self.assertEqual(item.payload_ref.purpose, "pending")
        payload = json.loads(read_spool(item.payload_ref, self.settings, now=NOW, key_provider=self.key))
        self.assertEqual(payload["claim"], observation().claim)
        for path in self.settings.paths.runtime_dir.rglob("*.json"):
            self.assertNotIn(observation().claim, path.read_text(encoding="utf-8"))

    def test_privacy_and_schema_rejection_write_no_body_or_queue(self):
        for item in (replace(observation(), claim="password=secret-value"),
                     replace(observation(), title=""), replace(observation(), classification="client-confidential")):
            receipt = self.accept(item)
            self.assertNotEqual(receipt.state, "SECURED")
        self.assertEqual(list_queue_items(self.settings), ())
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_full_capacity_has_no_success_receipt(self):
        self.policy(max_bytes=1)
        result = self.accept()
        self.assertEqual(result.state, "WAITING")
        self.assertEqual(list_queue_items(self.settings), ())

    def test_retry_does_not_extend_original_retention_after_policy_change(self):
        self.policy(ttl_seconds=10)
        self.accept()
        expiry = list_queue_items(self.settings)[0].payload_ref.expires_at
        self.policy(ttl_seconds=1000)
        self.assertEqual(self.accept(now=NOW + timedelta(seconds=9)).state, "SECURED")
        self.assertEqual(list_queue_items(self.settings)[0].payload_ref.expires_at, expiry)
        self.assertEqual(self.accept(now=NOW + timedelta(seconds=10)).reason_code, "PENDING_EXPIRED")

    def test_expiry_receipt_write_failure_keeps_body(self):
        self.policy(ttl_seconds=10)
        self.accept()
        item = list_queue_items(self.settings)[0]
        with patch("ei.capture_ledger._record_receipt_locked", side_effect=OSError("disk full")):
            self.assertEqual(self.reconcile(NOW + timedelta(seconds=10))["waiting"], 1)
        self.assertTrue((runtime_lookup(self.settings.paths.spool_dir, item.payload_ref.spool_id)).exists())
        self.assertEqual(read_receipt(self.settings, capture_key(identity())).state, "SECURED")
        self.reconcile(NOW + timedelta(seconds=10))
        self.assertEqual(read_receipt(self.settings, capture_key(identity())).reason_code, "PENDING_EXPIRED")

    def test_key_unavailable_never_acknowledges_or_writes_body(self):
        from ei.key_provider import KeyProviderError
        with patch.object(self.key, "current", side_effect=KeyProviderError("UNAVAILABLE")):
            self.assertEqual(self.accept().state, "WAITING")
        self.assertEqual(list_queue_items(self.settings), ())
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))
        self.assertEqual(self.accept().state, "SECURED")

    def test_ttl_is_terminal_and_cleanup_failure_is_retried(self):
        self.policy(ttl_seconds=10)
        self.accept()
        item = list_queue_items(self.settings)[0]
        with patch("ei.pending_capture.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")):
            failed = self.reconcile(NOW + timedelta(seconds=10))
        capture_id = capture_key(identity())
        self.assertEqual(failed["cleanup_failed_capture_ids"], [capture_id])
        self.assertFalse(failed["processed"][0]["retained_verified"])
        receipt = read_receipt(self.settings, capture_key(identity()))
        self.assertEqual((receipt.state, receipt.reason_code), ("UNAVAILABLE", "PENDING_EXPIRED"))
        self.assertEqual(list_queue_items(self.settings)[0].state, QueueState.FAILED_NEEDS_ATTENTION)
        serialized = "\n".join(p.read_text(encoding="utf-8") for p in (self.settings.paths.runtime_dir / "state" / "capture" / "intents").rglob("*.json"))
        self.assertIn("EXPIRY_CLEANUP_FAILED", serialized)
        resolved = self.reconcile(NOW + timedelta(seconds=11))
        self.assertEqual(resolved["cleanup_confirmed_capture_ids"], [capture_id])
        self.assertEqual(resolved["expired_capture_ids"], [capture_id])
        self.assertFalse((runtime_lookup(self.settings.paths.spool_dir, item.payload_ref.spool_id)).exists())
        self.assertEqual(self.accept(now=NOW + timedelta(days=1)).state, "UNAVAILABLE")
        self.assertIsNone(claim_queue_item("worker", self.settings, now=NOW + timedelta(days=1)))

    def test_expired_candidate_cannot_be_claimed_before_reconcile(self):
        self.policy(ttl_seconds=10)
        self.accept()
        self.assertIsNone(claim_queue_item("worker", self.settings, now=NOW + timedelta(seconds=10)))
        self.reconcile(NOW + timedelta(seconds=10))
        self.assertEqual(read_receipt(self.settings, capture_key(identity())).reason_code, "PENDING_EXPIRED")

    def test_corrupt_ciphertext_does_not_ack_replay(self):
        self.accept()
        item = list_queue_items(self.settings)[0]
        path = runtime_lookup(self.settings.paths.spool_dir, item.payload_ref.spool_id)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["ciphertext"] = "AAAA"
        path.write_text(json.dumps(value), encoding="utf-8")
        self.assertNotEqual(self.accept().state, "SECURED")

    def test_quarantined_pending_queue_records_expiry_as_needs_attention(self):
        self.policy(ttl_seconds=10)
        self.accept()
        item = list_queue_items(self.settings)[0]
        transition_queue_item(item, QueueState.QUARANTINED, self.settings, now=NOW)
        self.reconcile(NOW + timedelta(seconds=10))
        item = list_queue_items(self.settings)[0]
        self.assertEqual((item.state, item.last_error_code), (QueueState.FAILED_NEEDS_ATTENTION, "PENDING_EXPIRED"))

    def test_terminal_queue_mismatch_never_acknowledges_replay(self):
        from ei.operation_runtime import OperationBudget
        for field, value in (("source_hash", "sha256:" + "f" * 64),
                             ("idempotency_key", "sha256:" + "e" * 64),
                             ("event_id", "evt_unrelated"),
                             ("session_id_hash", "sha256:" + "d" * 64),
                             ("turn_id_hash", "sha256:" + "c" * 64),
                             ("privacy_classification", "public"),
                             ("created_at", "2026-01-01T00:00:00Z")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                original = accept_candidate(self.settings, identity(), observation(), now=NOW,
                    key_provider=self.key, budget=OperationBudget(20000))
                self.assertEqual(original.state, "SECURED", repr(original))
                item = list_queue_items(self.settings)[0]
                transition_queue_item(item, QueueState.NO_DISCARDED, self.settings, now=NOW)
                path = runtime_lookup(self.settings.paths.queue_dir, item.queue_id)
                value_dict = json.loads(path.read_text(encoding="utf-8"))
                value_dict[field] = value
                path.write_text(json.dumps(value_dict), encoding="utf-8")
                self.assertEqual(self.accept().state, "WAITING")
                self.assertEqual(self.reconcile()["waiting"], 1)
                self.assertEqual(read_receipt(self.settings, capture_key(identity())), original)
                self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_terminal_recovery_cannot_revive_expired_receipt(self):
        from ei.capture_ledger import record_receipt
        first = self.accept()
        item = list_queue_items(self.settings)[0]
        with patch("ei.queue.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")), self.assertRaises(SpoolError):
            transition_queue_item(item, QueueState.NO_DISCARDED, self.settings, now=NOW)
        expired = record_receipt(self.settings, replace(first, state="UNAVAILABLE", reason_code="PENDING_EXPIRED"))
        self.assertEqual(self.accept(), expired)
        self.assertEqual(self.reconcile()["secured"], 0)
        self.assertEqual(read_receipt(self.settings, capture_key(identity())), expired)
        self.assertIsNone(list_queue_items(self.settings)[0].payload_ref)
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))


if __name__ == "__main__":
    unittest.main()
