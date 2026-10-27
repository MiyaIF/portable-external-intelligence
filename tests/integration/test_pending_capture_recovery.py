import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from ei import pending_capture, spool, queue, capture_ledger
from ei.capture_contract import capture_key
from ei.journal import iter_events
from ei.key_provider import InMemoryKeyProvider, KeyProviderError
from ei.maintainer import drain_queue, run_maintenance
from ei.queue import QueueState, list_queue_items, read_queue_item, transition_queue_item
from ei.runtime_catalog import RuntimeCatalog, inventory_paths as runtime_inventory, lookup as runtime_lookup
from ei.spool import SpoolError
from tests.unattended_helpers import NOW, identity, make_settings
from tests.unit import test_maintainer as maintenance_fixtures
from tests.unit.test_pending_capture import observation


class PowerLoss(BaseException):
    pass


class PendingRecoveryTests(unittest.TestCase):
    def test_interrupted_native_admission_keeps_origin_and_retry_does_not_reclassify(self):
        with patch.object(pending_capture, "write_spool", side_effect=SpoolError("failed")):
            result = pending_capture.accept_candidate(self.settings, identity(), observation(), now=NOW, key_provider=self.key, origin="NATIVE_SOURCE")
        self.assertEqual(result.state, "WAITING")
        root = self.settings.paths.runtime_dir / "state" / "capture" / "intents"
        path = next(root.rglob("pending_*.json"))
        before = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(before["phase"], "PREPARED")
        self.assertEqual(before["admission"]["origin"], "NATIVE_SOURCE")
        recovered = self.accept()
        self.assertEqual(recovered.state, "SECURED")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["admission"], before["admission"])
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_duplicate_intent_lookup_reads_receive_the_original_budget(self):
        import ei.runtime_catalog as runtime
        from ei.operation_runtime import OperationBudget
        self.assertEqual(self.accept().state, "SECURED")
        root = self.settings.paths.runtime_dir / "state" / "capture" / "intents"
        managed = next(root.rglob("pending_*.json"))
        (root / managed.name).write_bytes(managed.read_bytes())
        budget = OperationBudget(5000)
        original = runtime.read_entry
        def checked(root, path, passed=None):
            self.assertIs(passed, budget)
            return original(root, path, passed)
        with patch.object(runtime, "read_entry", side_effect=checked):
            actual = pending_capture.accept_candidate(self.settings, identity(), observation(), now=NOW, key_provider=self.key, budget=budget)
        self.assertEqual(actual.state, "SECURED")

    def test_secured_replay_does_not_rewrite_unchanged_intent(self):
        first = self.accept()
        original = capture_ledger._write_path
        def reject_unchanged_intent(root, path, encoded, **kwargs):
            if path.stem.startswith("pending_"):
                raise AssertionError("unchanged intent rewritten")
            return original(root, path, encoded, **kwargs)
        with patch("ei.capture_ledger._write_path", side_effect=reject_unchanged_intent):
            replay = self.accept(now=NOW + timedelta(seconds=1))
        self.assertEqual(replay.candidate_ids, first.candidate_ids)
        self.assertEqual(replay.state, "SECURED")

    def test_timeout_after_page_does_not_skip_its_unprocessed_suffix(self):
        for record in ("a", "b", "c"):
            with patch("ei.pending_capture.write_spool", side_effect=OSError("full")):
                pending_capture.accept_candidate(self.settings, identity(record), observation(), now=NOW, key_provider=self.key)
        original = pending_capture._load
        visited = []
        def limited(root, path, **kwargs):
            visited.append(path.stem)
            if len(visited) == 2:
                raise TimeoutError("deadline")
            return original(root, path, **kwargs)
        with patch("ei.pending_capture._load", side_effect=limited):
            partial = pending_capture.reconcile_pending(self.settings, now=NOW, max_records=3)
        self.assertFalse(partial["page_complete"])
        self.assertEqual(partial["reason_code"], "PENDING_TIME_LIMIT")
        self.assertEqual(len(partial["processed"]), 1)
        resumed = pending_capture.reconcile_pending(self.settings, now=NOW, max_records=1)
        self.assertEqual(resumed["processed"][0]["pending_id"], visited[1])

    def test_absent_intent_write_retries_original_ttl_after_later_call(self):
        original = capture_ledger._write_path
        def fail_intent(root, path, encoded, **kwargs):
            if path.stem.startswith("pending_"):
                raise OSError("full")
            return original(root, path, encoded, **kwargs)
        with patch("ei.capture_ledger._write_path", side_effect=fail_intent):
            self.assertEqual(self.accept().state, "WAITING")
        self.assertEqual(self.accept(now=NOW + timedelta(days=1)).state, "SECURED")
        item = list_queue_items(self.settings)[0]
        self.assertEqual(item.payload_ref.created_at, NOW.isoformat().replace("+00:00", "Z"))
        self.assertEqual(item.payload_ref.expires_at, (NOW + timedelta(days=30)).isoformat().replace("+00:00", "Z"))

    def test_short_suffix_never_becomes_complete_pending_aggregate(self):
        for record in ("a", "b", "c"):
            with patch("ei.pending_capture.write_spool", side_effect=OSError("full")):
                pending_capture.accept_candidate(self.settings, identity(record), observation(), now=NOW, key_provider=self.key)
        first = pending_capture.reconcile_pending(self.settings, now=NOW, max_records=2)
        second = pending_capture.reconcile_pending(self.settings, now=NOW, max_records=2)
        self.assertEqual((first["waiting"], second["waiting"]), (2, 1))
        self.assertFalse(second["aggregate_complete"])
        self.assertTrue(second["inventory_complete"])
        self.assertTrue(second["page_complete"])
        self.assertEqual(len(second["processed"]), 1)

    def test_bounded_reconciliation_rotates_past_waiting_prefix(self):
        from ei.operation_runtime import OperationBudget
        from ei.runtime_catalog import lookup
        identities = [replace(identity(), record_hash="sha256:" + str(number) * 64) for number in range(3)]
        for key in identities:
            with patch("ei.pending_capture.write_spool", side_effect=OSError("full")):
                self.assertEqual(pending_capture.accept_candidate(self.settings, key, observation(), now=NOW, key_provider=self.key).state, "WAITING")
        seen = set()
        original = pending_capture._load
        def load(root, path, **kwargs):
            seen.add(path.stem)
            return original(root, path, **kwargs)
        with patch("ei.pending_capture._load", side_effect=load):
            for _ in range(3):
                pending_capture.reconcile_pending(self.settings, now=NOW, budget=OperationBudget(5000), max_records=1)
        self.assertEqual(len(seen), 3)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_settings(Path(self.tmp.name))
        self.key = InMemoryKeyProvider("restart", b"r" * 32)

    def accept(self, now=NOW, item=None):
        return pending_capture.accept_candidate(self.settings, identity(), item or observation(), now=now, key_provider=self.key)

    def reconcile(self, now=NOW):
        with patch("ei.spool.default_key_provider", return_value=self.key):
            return pending_capture.reconcile_pending(self.settings, now=now)

    def test_process_death_at_each_persistence_boundary_converges(self):
        # Fail immediately AFTER each real durable write, keeping its effects.
        # Spool now has one payload writer; capacity sidecars were removed.
        # Exercise all four actual intent checkpoints and the catalog commit.
        boundaries = [("ei.pending_capture._save", i) for i in (1, 2, 3, 4)] + [("ei.spool._atomic_json", 1), ("ei.runtime_catalog.RuntimeCatalog._settle", 2)] + [
            ("ei.queue._atomic_json", 1),
            ("ei.capture_ledger._record_receipt_locked", 1)]
        for target, stop in boundaries:
            with self.subTest(target=target, stop=stop), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                module, name = target.rsplit(".", 1)
                import importlib
                original = getattr(queue.RuntimeCatalog, name) if module == "ei.runtime_catalog.RuntimeCatalog" else getattr(importlib.import_module(module), name)
                calls = 0
                def crash_after(*args, **kwargs):
                    nonlocal calls
                    result = original(*args, **kwargs)
                    calls += 1
                    if calls == stop:
                        raise PowerLoss()
                    return result
                with patch(target, autospec=True, side_effect=crash_after), self.assertRaises(PowerLoss):
                    self.accept()
                self.reconcile()
                result = self.accept()
                self.assertEqual(result.state, "SECURED")
                self.assertEqual(len(list_queue_items(self.settings)), 1)
                self.assertEqual(result.candidate_ids, (list_queue_items(self.settings)[0].queue_id,))

    def test_prepared_without_body_waits_without_synthesizing_content(self):
        with patch("ei.pending_capture.write_spool", side_effect=OSError("disk full")):
            result = self.accept()
        self.assertEqual(result.state, "WAITING")
        self.assertEqual(self.reconcile()["waiting"], 1)
        self.assertEqual(list_queue_items(self.settings), ())
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))
        self.assertEqual(self.accept().state, "SECURED")

    def interrupted_consumer_completion(self, state, waiting=False):
        if waiting:
            capture_ledger.register_target(self.settings, identity(), now=NOW)
        original = queue._atomic_json
        def crash_after_queue(*args, **kwargs):
            original(*args, **kwargs)
            raise PowerLoss()
        with patch("ei.queue._atomic_json", side_effect=crash_after_queue), self.assertRaises(PowerLoss):
            self.accept()
        item = queue.claim_queue_item("consumer", self.settings, now=NOW)
        self.assertIsNotNone(item)
        spool.read_spool(item.payload_ref, self.settings, now=NOW, key_provider=self.key)
        terminal = transition_queue_item(item, state, self.settings, now=NOW)
        self.assertFalse((runtime_lookup(self.settings.paths.spool_dir, item.payload_ref.spool_id)).exists())
        return terminal, item.payload_ref

    def test_done_cleanup_retries_after_each_interruption_at_day31_without_reinference(self):
        cases = ("after_done_store", "after_payload_delete", "after_result_delete",
                 "before_ref_detach_store", "delete_oserror", "delete_deadline")
        for boundary in cases:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                key = InMemoryKeyProvider("restart", b"r" * 32)
                settings = maintenance_fixtures.make_settings(tmp)
                self.settings, self.key = settings, key
                self.accept()
                accepted = list_queue_items(settings)[0]
                provider = maintenance_fixtures.YesProvider()
                original_store = queue._store
                original_delete = queue.delete_spool
                delete_calls = 0

                def store_after_done(root, item, budget=None):
                    nonlocal original_store
                    if boundary == "before_ref_detach_store" and item.state == QueueState.DONE and (item.payload_ref is None) != (item.validated_result_ref is None):
                        raise PowerLoss()
                    saved = original_store(root, item, budget=budget)
                    if boundary == "after_done_store" and item.state == QueueState.DONE and item.payload_ref is not None and item.validated_result_ref is not None:
                        raise PowerLoss()
                    return saved

                def delete_at_boundary(*args, **kwargs):
                    nonlocal delete_calls
                    delete_calls += 1
                    if boundary == "delete_oserror":
                        raise OSError("synthetic deletion failure")
                    removed = original_delete(*args, **kwargs)
                    if boundary == "delete_deadline":
                        raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")
                    if boundary == "after_payload_delete" and delete_calls == 1:
                        raise PowerLoss()
                    if boundary == "after_result_delete" and delete_calls == 2:
                        raise PowerLoss()
                    return removed

                with patch.object(provider, "generate", wraps=provider.generate) as generate:
                    with patch("ei.spool.default_key_provider", return_value=key):
                        if boundary in {"after_done_store", "before_ref_detach_store"}:
                            interruption = patch("ei.queue._store", side_effect=store_after_done)
                        else:
                            interruption = patch("ei.queue.delete_spool", side_effect=delete_at_boundary)
                        with interruption:
                            if boundary in {"after_done_store", "after_payload_delete", "after_result_delete", "before_ref_detach_store"}:
                                with self.assertRaises(PowerLoss):
                                    drain_queue(settings, provider=provider, now=NOW, time_budget_ms=10000)
                            else:
                                drain_queue(settings, provider=provider, now=NOW, time_budget_ms=10000)

                    terminal = read_queue_item(accepted.queue_id, settings)
                    self.assertEqual(terminal.state, QueueState.DONE)
                    intent_path = next((settings.paths.runtime_dir / "state" / "capture" / "intents").rglob("pending_*.json"))
                    original_expiry = accepted.payload_ref.expires_at
                    later = NOW + timedelta(days=31)
                    with patch("ei.spool.default_key_provider", return_value=key), patch("ei.operation_runtime.service_operation", return_value={"status": "DISABLED", "reason_code": "TEST"}):
                        run_maintenance(settings, provider=provider, source_paths=(), sync_policy="disabled", now=later)

                    recovered = read_queue_item(accepted.queue_id, settings)
                    self.assertEqual(recovered.state, QueueState.DONE)
                    self.assertIsNone(recovered.payload_ref)
                    self.assertIsNone(recovered.validated_result_ref)
                    self.assertEqual(capture_ledger.read_receipt(settings, capture_key(identity())).state, "SECURED")
                    intent = json.loads(intent_path.read_text(encoding="utf-8"))
                    self.assertEqual(intent["phase"], "COMMITTED")
                    self.assertEqual(intent["spool_ref"]["expires_at"], original_expiry)
                    self.assertEqual(list(runtime_inventory(settings.paths.spool_dir, prefix="pending_")), [])
                    self.assertEqual(list(runtime_inventory(settings.paths.spool_dir, prefix="result_")), [])
                    catalog = RuntimeCatalog(settings.paths.spool_dir)
                    self.assertEqual(catalog.capacity("pending"), (0, 0))
                    self.assertEqual(catalog.capacity("validated-result"), (0, 0))
                    events = iter_events(settings.paths.event_dir)
                    self.assertEqual(sum(event.event_type == "curation.changeset.applied" for event in events), 1)
                    self.assertEqual(generate.call_count, 1)

    def test_terminal_consumer_before_receipt_recovers_without_body(self):
        for state in (QueueState.NO_DISCARDED, QueueState.DONE):
            for waiting in (False, True):
                for route in ("replay", "reconcile"):
                    with self.subTest(state=state, waiting=waiting, route=route), tempfile.TemporaryDirectory() as tmp:
                        self.settings = make_settings(Path(tmp))
                        terminal, ref = self.interrupted_consumer_completion(state, waiting)
                        old = capture_ledger.read_receipt(self.settings, capture_key(identity()))
                        self.assertEqual(old.state if old else None, "WAITING" if waiting else None)
                        with patch("ei.pending_capture.write_spool", side_effect=AssertionError("must not recreate body")), patch("ei.pending_capture.read_spool", side_effect=AssertionError("body already consumed")):
                            if route == "reconcile":
                                self.assertEqual(self.reconcile()["secured"], 1)
                            result = self.accept()
                        self.assertEqual(result.state, "SECURED")
                        self.assertEqual(result.candidate_ids, (terminal.queue_id,))
                        self.assertEqual(result.candidate_hashes, ((terminal.queue_id, ref.content_hash),))
                        self.assertEqual(capture_ledger.read_receipt(self.settings, capture_key(identity())), result)
                        self.assertEqual(len(list_queue_items(self.settings)), 1)
                        self.assertEqual(list_queue_items(self.settings)[0].state, state)
                        intent_path = next((self.settings.paths.runtime_dir / "state" / "capture" / "intents").rglob("*.json"))
                        self.assertEqual(json.loads(intent_path.read_text(encoding="utf-8"))["phase"], "COMMITTED")
                        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_terminal_hash_mismatch_does_not_create_missing_receipt(self):
        terminal, _ = self.interrupted_consumer_completion(QueueState.NO_DISCARDED)
        path = runtime_lookup(self.settings.paths.queue_dir, terminal.queue_id)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["source_hash"] = "sha256:" + "f" * 64
        path.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self.reconcile()["waiting"], 1)
        self.assertEqual(self.accept().state, "WAITING")
        self.assertIsNone(capture_ledger.read_receipt(self.settings, capture_key(identity())))
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_consumed_terminal_candidate_is_not_lost_when_recovery_is_late(self):
        for state in (QueueState.NO_DISCARDED, QueueState.DONE):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                self.interrupted_consumer_completion(state)
                self.assertEqual(self.reconcile(NOW + timedelta(days=31))["secured"], 1)
                self.assertEqual(self.accept(now=NOW + timedelta(days=31)).state, "SECURED")
                self.assertEqual(list_queue_items(self.settings)[0].state, state)
                self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_terminal_receipt_repair_write_failures_never_ack_and_retry(self):
        for target in ("ei.capture_ledger._record_receipt_locked", "ei.pending_capture._save"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                terminal, ref = self.interrupted_consumer_completion(QueueState.NO_DISCARDED)
                with patch(target, side_effect=OSError("synthetic storage error")):
                    self.assertEqual(self.accept().state, "WAITING")
                self.assertEqual(self.reconcile()["secured"], 1)
                result = self.accept()
                self.assertEqual(result.candidate_hashes, ((terminal.queue_id, ref.content_hash),))
                self.assertEqual(result.state, "SECURED")
                self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_owned_temporary_cleanup_retries_after_expiry_receipt(self):
        self.assertEqual(self.accept().state, "SECURED")
        ref = list_queue_items(self.settings)[0].payload_ref
        body = spool.lookup(self.settings.paths.spool_dir, ref.spool_id)
        orphan = body.with_name(body.name + ".12345678.1234abcd.tmp")
        orphan.write_bytes(b"synthetic encrypted fragment")
        def denied(*args, **kwargs):
            receipt = capture_ledger.read_receipt(self.settings, capture_key(identity()))
            self.assertEqual((receipt.state, receipt.reason_code), ("UNAVAILABLE", "PENDING_EXPIRED"))
            raise OSError("denied")
        with patch("ei.spool._pid_state", return_value=False), patch("ei.spool.safe_unlink", side_effect=denied):
            failed = self.reconcile(NOW + timedelta(days=30))
        self.assertEqual(failed["cleanup_failed_capture_ids"], [capture_key(identity())])
        self.assertTrue(body.exists())
        self.assertTrue(orphan.exists())
        with patch("ei.spool._pid_state", return_value=False):
            recovered = self.reconcile(NOW + timedelta(days=30, seconds=1))
        self.assertEqual(recovered["cleanup_confirmed_capture_ids"], [capture_key(identity())])
        self.assertFalse(body.exists())
        self.assertFalse(orphan.exists())

    def test_unrelated_orphan_blocks_admission_but_is_not_capture_cleanup_failure(self):
        self.settings.paths.spool_dir.mkdir(parents=True)
        orphan = self.settings.paths.spool_dir / ("pending_" + "b" * 64 + ".json.12345678.1234abcd.tmp")
        orphan.write_bytes(b"synthetic encrypted fragment")
        with patch("ei.spool._pid_state", return_value=False, create=True), patch("ei.spool.safe_unlink", side_effect=OSError("denied"), create=True):
            self.assertEqual(self.accept().state, "WAITING")
        self.assertEqual(list_queue_items(self.settings), ())
        with patch("ei.spool._pid_state", return_value=False, create=True), patch("ei.spool.safe_unlink", side_effect=OSError("denied"), create=True):
            self.reconcile(NOW + timedelta(days=30))
        receipt = capture_ledger.read_receipt(self.settings, capture_key(identity()))
        self.assertEqual((receipt.state, receipt.reason_code), ("UNAVAILABLE", "PENDING_EXPIRED"))
        self.assertTrue(orphan.exists())
        intent_path = next((self.settings.paths.runtime_dir / "state" / "capture" / "intents").rglob("*.json"))
        self.assertEqual(json.loads(intent_path.read_text(encoding="utf-8"))["cleanup_code"], "EXPIRY_CLEANUP_CONFIRMED")
        with patch("ei.spool._pid_state", return_value=False, create=True):
            spool.gc_expired_spool(self.settings, now=NOW + timedelta(days=30, seconds=1), key_provider=self.key)
        self.assertFalse(orphan.exists())
        self.assertEqual(json.loads(intent_path.read_text(encoding="utf-8"))["cleanup_code"], "EXPIRY_CLEANUP_CONFIRMED")

    def test_owned_temporary_live_or_unknown_owner_is_never_deleted(self):
        for owner in (True, None):
            with self.subTest(owner=owner), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                self.assertEqual(self.accept().state, "SECURED")
                ref = list_queue_items(self.settings)[0].payload_ref
                body = spool.lookup(self.settings.paths.spool_dir, ref.spool_id)
                orphan = body.with_name(body.name + ".12345678.1234abcd.tmp")
                orphan.write_bytes(b"synthetic encrypted fragment")
                with patch("ei.spool._pid_state", return_value=owner), patch("ei.spool.safe_unlink", wraps=spool.safe_unlink) as unlink:
                    result = self.reconcile(NOW + timedelta(days=30))
                self.assertEqual(result["cleanup_failed_capture_ids"], [capture_key(identity())])
                self.assertTrue(body.exists())
                self.assertTrue(orphan.exists())
                self.assertEqual(unlink.call_count, 0)

    def test_key_unavailable_during_recovery_preserves_ciphertext(self):
        self.accept()
        path = next(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_"))
        before = path.read_bytes()
        with patch.object(self.key, "get", side_effect=KeyProviderError("UNAVAILABLE")):
            self.assertEqual(self.reconcile()["waiting"], 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.reconcile()["secured"], 1)

    def test_crash_after_queue_before_receipt_then_expiry_marks_queue_failed(self):
        original = queue._atomic_json
        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise PowerLoss()
        with patch("ei.queue._atomic_json", side_effect=crash), self.assertRaises(PowerLoss):
            self.accept()
        self.reconcile(NOW + timedelta(days=30))
        self.assertEqual(list_queue_items(self.settings)[0].state, QueueState.FAILED_NEEDS_ATTENTION)

    def test_terminal_no_replay_never_recreates_deleted_body(self):
        first = self.accept()
        item = list_queue_items(self.settings)[0]
        transition_queue_item(item, QueueState.NO_DISCARDED, self.settings, now=NOW)
        replay = self.accept()
        self.assertEqual(replay.state, "SECURED")
        self.assertEqual(replay.candidate_ids, first.candidate_ids)
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_no_cleanup_retries_outside_queue_lock_and_retains_ref_on_failure(self):
        self.accept()
        item = list_queue_items(self.settings)[0]
        def fail(*args, **kwargs):
            self.assertFalse((self.settings.paths.queue_dir / ".queue.lock").exists())
            raise SpoolError("SPOOL_DELETE_FAILED")
        with patch("ei.queue.delete_spool", side_effect=fail), self.assertRaises(SpoolError):
            transition_queue_item(item, QueueState.NO_DISCARDED, self.settings, now=NOW)
        failed = list_queue_items(self.settings)[0]
        self.assertEqual(failed.state, QueueState.NO_DISCARDED)
        self.assertEqual(failed.payload_ref, item.payload_ref)
        result = transition_queue_item(failed, QueueState.NO_DISCARDED, self.settings, now=NOW + timedelta(seconds=300))
        self.assertIsNone(result.payload_ref)

    def test_reconcile_retries_interrupted_no_cleanup(self):
        self.accept()
        item = list_queue_items(self.settings)[0]
        with patch("ei.queue.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")), self.assertRaises(SpoolError):
            transition_queue_item(item, QueueState.NO_DISCARDED, self.settings, now=NOW)
        self.reconcile()
        self.assertIsNone(list_queue_items(self.settings)[0].payload_ref)
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_reconcile_existing_queue_does_not_enqueue_again(self):
        self.accept()
        with patch("ei.pending_capture.enqueue_receipt", side_effect=AssertionError("existing queue must be reused")):
            self.assertEqual(self.reconcile()["secured"], 1)

    def test_reconcile_never_recreates_body_deleted_after_authenticated_read(self):
        self.accept()
        original = pending_capture.read_spool
        def remove_after_read(ref, *args, **kwargs):
            result = original(ref, *args, **kwargs)
            spool.delete_spool(ref, self.settings)
            return result
        with patch("ei.pending_capture.read_spool", side_effect=remove_after_read):
            self.assertEqual(self.reconcile()["waiting"], 1)
        self.assertFalse(list(runtime_inventory(self.settings.paths.spool_dir, prefix="pending_")))

    def test_stale_transition_cannot_delete_another_candidates_body(self):
        self.accept()
        first = list_queue_items(self.settings)[0]
        self.accept(item=replace(observation(), title="独立候補"))
        second = next(item for item in list_queue_items(self.settings) if item.queue_id != first.queue_id)
        # A stale caller-supplied ref must never be used as deletion authority.
        stale = replace(first, payload_ref=second.payload_ref)
        transition_queue_item(stale, QueueState.NO_DISCARDED, self.settings, now=NOW)
        self.assertTrue((runtime_lookup(self.settings.paths.spool_dir, second.payload_ref.spool_id)).exists())
        self.assertFalse((runtime_lookup(self.settings.paths.spool_dir, first.payload_ref.spool_id)).exists())

    def test_multiple_candidates_of_one_capture_count_separately(self):
        path = self.settings.capture_policy_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"pending": {"max_items": 1}}), encoding="utf-8")
        self.assertEqual(self.accept().state, "SECURED")
        self.assertEqual(self.accept(item=replace(observation(), title="別候補")).state, "WAITING")
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_disk_full_is_sanitized_and_never_acknowledged(self):
        for target in ("ei.spool._atomic_json", "ei.pending_capture._save", "ei.queue._atomic_json", "ei.capture_ledger._record_receipt_locked"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                self.settings = make_settings(Path(tmp))
                with patch(target, side_effect=OSError("body and paths must not escape")):
                    result = self.accept()
                self.assertEqual((result.state, result.reason_code), ("WAITING", "PENDING_STORAGE_UNAVAILABLE"))
                self.assertEqual(self.accept().state, "SECURED")


if __name__ == "__main__":
    unittest.main()
