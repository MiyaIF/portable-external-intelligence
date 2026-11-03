import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from ei import queue
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory


class QueueBoundedLockTests(unittest.TestCase):
    def test_atomic_write_and_fsync_errors_remove_their_own_temporary(self):
        for boundary in ("write", "fsync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "queue_failure.json"
                with patch("ei.queue.os." + boundary, side_effect=OSError("disk full")), self.assertRaises(OSError):
                    queue._atomic_json(path, {"queue_id": "synthetic"})
                self.assertEqual(list(Path(tmp).glob("*.tmp")), [])
                self.assertFalse(path.exists())

    def test_atomic_write_handles_short_os_writes(self):
        import os
        real_write = os.write
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.json"
            with patch("ei.queue.os.write", side_effect=lambda fd, data: real_write(fd, data[:7])):
                queue._atomic_json(path, {"marker": "complete durable metadata"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"marker": "complete durable metadata"})

    def test_permission_and_stat_lock_failures_are_bounded(self):
        for failure in (PermissionError(), FileExistsError()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch("ei.queue.os.open", side_effect=failure), patch.object(Path, "stat", side_effect=OSError()) as stat_probe, patch("ei.queue.time.monotonic", side_effect=[0, 0, 6]), patch("ei.queue.time.sleep") as retry_sleep:
                    with self.assertRaisesRegex(queue.QueueError, "QUEUE_LOCK_PERMISSION_DENIED|QUEUE_LOCK_TIMEOUT"):
                        queue._acquire(Path(tmp))
                    self.assertEqual(stat_probe.call_count, int(isinstance(failure, FileExistsError)))
                    self.assertEqual(retry_sleep.call_count, int(isinstance(failure, FileExistsError)))

from ei.hooks.registry import normalize_hook_event
from ei.key_provider import InMemoryKeyProvider
from ei.queue import (
    QueueError,
    QueueItem,
    QueueState,
    claim_queue_item,
    enqueue_receipt,
    queue_health,
    read_queue_item,
    recover_emergency_spool,
    write_emergency_envelope,
    transition_queue_item,
)
from ei.spool import SpoolError, read_spool, write_spool
from ei.config import RuntimePaths, Settings
from ei.setup_contract import OrganizerSelection


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)

def make_isolated_hook_settings(root: Path) -> Settings:
    root = Path(root).resolve()
    repo = root / "repo"
    runtime = root / "machine-runtime"
    codex_home = root / "codex-home"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=codex_home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=codex_home / "config.toml",
        hooks_path=codex_home / "hooks.json",
        agents_path=codex_home / "AGENTS.md",
    )
    return Settings(paths=paths, retrieval_max_chars=5000, retrieval_max_results=5)


def make_event(settings, event_name="Stop", turn_id="t1"):
    return normalize_hook_event(
        "codex-cli",
        {"hook_event_name": event_name, "session_id": "s1", "turn_id": turn_id, "cwd": "C:/work"},
        settings,
    )


class QueueTests(unittest.TestCase):
    def test_duplicate_lookup_reads_receive_the_original_budget(self):
        import ei.runtime_catalog as runtime
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            managed = runtime.lookup(settings.paths.queue_dir, item.queue_id)
            (settings.paths.queue_dir / managed.name).write_bytes(managed.read_bytes())
            budget = OperationBudget(5000)
            original = runtime.read_entry
            def checked(root, path, passed=None):
                self.assertIs(passed, budget)
                return original(root, path, passed)
            with patch.object(runtime, "read_entry", side_effect=checked):
                self.assertEqual(read_queue_item(item.queue_id, settings, budget=budget), item)

    def test_failed_claim_file_write_retries_later_with_one_attempt_and_original_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("candidate", "public", settings, key_provider=InMemoryKeyProvider(), now=NOW)
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            with patch("ei.queue._atomic_json", side_effect=OSError("interrupted before file")), self.assertRaises(OSError):
                claim_queue_item("worker", settings, now=NOW)
            actual = claim_queue_item("worker", settings, now=NOW + timedelta(seconds=1))
            self.assertEqual((actual.attempts, actual.created_at, actual.payload_ref), (1, item.created_at, ref))
            self.assertEqual(actual.lease_expires_at, (NOW + timedelta(seconds=301)).isoformat().replace("+00:00", "Z"))

    def test_emergency_managed_replay_is_bounded_and_preserves_unprocessed_suffix(self):
        from ei.runtime_catalog import lookup
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            items = [enqueue_receipt(make_event(settings, turn_id=str(index)), None, settings, now=NOW) for index in range(3)]
            for item in items:
                path = write_emergency_envelope(item, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
                self.assertIn("managed", path.parts)
            first = recover_emergency_spool(settings, now=NOW, max_records=1)
            self.assertEqual(len(first), 1)
            second = recover_emergency_spool(settings, now=NOW, max_records=1)
            self.assertEqual(len(second), 1)
            self.assertNotEqual(first[0].queue_id, second[0].queue_id)
            self.assertEqual(queue_health(settings).emergency_items, 1)

    def test_result_attachment_exhausted_budget_has_no_mutation(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("result", "public", settings, key_provider=InMemoryKeyProvider(), now=NOW, purpose="validated-result", capture_id="sha256:" + "a" * 64)
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            claimed = claim_queue_item("worker", settings, now=NOW)
            with self.assertRaises(TimeoutError):
                queue.attach_validated_result(claimed, ref, settings, budget=OperationBudget(0))
            self.assertIsNone(read_queue_item(item.queue_id, settings).validated_result_ref)

    def test_pre_file_queue_failure_replays_same_receipt_without_false_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            event = make_event(settings)
            original = queue._atomic_json
            def fail_payload(path, value, **kwargs):
                if path.is_relative_to(settings.paths.queue_dir):
                    raise OSError("full")
                return original(path, value, **kwargs)
            with patch("ei.queue._atomic_json", side_effect=fail_payload):
                failed = enqueue_receipt(event, None, settings, now=NOW)
            self.assertEqual(failed.state, QueueState.QUARANTINED)
            actual = enqueue_receipt(event, None, settings, now=NOW + timedelta(days=1))
            self.assertEqual(actual.state, QueueState.READY)
            self.assertEqual(actual.created_at, NOW.isoformat().replace("+00:00", "Z"))
            self.assertEqual(read_queue_item(actual.queue_id, settings), actual)

    def test_claim_timeout_does_not_advance_past_uncommitted_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            first = enqueue_receipt(make_event(settings, turn_id="first"), None, settings, now=NOW)
            second = enqueue_receipt(make_event(settings, turn_id="second"), None, settings, now=NOW)
            expected = min(first.queue_id, second.queue_id)
            with patch("ei.queue._store", side_effect=TimeoutError("deadline")), self.assertRaises(TimeoutError):
                claim_queue_item("worker", settings, now=NOW, max_records=1)
            self.assertEqual(claim_queue_item("worker", settings, now=NOW, max_records=1).queue_id, expected)

    def test_managed_queue_can_be_read_claimed_and_transitioned_by_legacy_api(self):
        from ei.runtime_catalog import lookup
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            self.assertIn("managed", lookup(settings.paths.queue_dir, item.queue_id).parts)
            self.assertEqual(read_queue_item(item.queue_id, settings), item)
            claimed = claim_queue_item("worker", settings, now=NOW)
            self.assertEqual(claimed.queue_id, item.queue_id)
            self.assertEqual(transition_queue_item(claimed, QueueState.DONE, settings).state, QueueState.DONE)

    def test_claim_retries_legacy_no_cleanup_without_claiming_it_for_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("legacy candidate", "public", settings, key_provider=key, now=NOW)
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            with patch("ei.queue.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")), self.assertRaises(SpoolError):
                transition_queue_item(item, QueueState.NO_DISCARDED, settings, now=NOW)
            before = read_queue_item(item.queue_id, settings)
            self.assertIsNone(before.capture_id)
            real_delete = queue.delete_spool
            def unlocked_delete(*args, **kwargs):
                self.assertFalse((settings.paths.queue_dir / ".queue.lock").exists())
                return real_delete(*args, **kwargs)
            with patch("ei.queue.delete_spool", side_effect=unlocked_delete):
                self.assertIsNone(claim_queue_item("worker", settings, now=NOW + timedelta(seconds=300)))
            after = read_queue_item(item.queue_id, settings)
            self.assertEqual((after.state, after.attempts), (QueueState.NO_DISCARDED, before.attempts))
            self.assertIsNone(after.payload_ref)
            self.assertFalse((runtime_lookup(settings.paths.spool_dir, ref.spool_id)).exists())

    def test_claim_cleanup_attempt_is_bounded_and_failure_does_not_starve_other_no(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            items = []
            for turn in ("cleanup-one", "cleanup-two"):
                ref = write_spool(turn, "public", settings, key_provider=key, now=NOW)
                item = enqueue_receipt(make_event(settings, turn_id=turn), ref, settings, now=NOW)
                with patch("ei.queue.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")), self.assertRaises(SpoolError):
                    transition_queue_item(item, QueueState.NO_DISCARDED, settings, now=NOW)
                items.append(item)
            first, second = sorted(items, key=lambda item: item.queue_id)
            for item in (first, second):
                self.assertEqual(read_queue_item(item.queue_id, settings).next_eligible_at, "2026-08-26T12:05:00Z")
            attempts = []
            real_delete = queue.delete_spool
            def fail_first_then_delete(ref, *args, **kwargs):
                attempts.append(ref.spool_id)
                if len(attempts) == 1:
                    raise SpoolError("SPOOL_DELETE_FAILED")
                return real_delete(ref, *args, **kwargs)
            with patch("ei.queue.delete_spool", side_effect=fail_first_then_delete):
                self.assertIsNone(claim_queue_item("worker", settings, now=NOW + timedelta(seconds=300)))
                self.assertEqual(len(attempts), 1)
                self.assertIsNone(claim_queue_item("worker", settings, now=NOW + timedelta(seconds=300)))
            self.assertEqual(len(attempts), 2)
            self.assertNotEqual(attempts[0], attempts[1])
            remaining = [read_queue_item(item.queue_id, settings) for item in (first, second)]
            failed_cleanup = next(item for item in remaining if item.payload_ref is not None)
            cleaned = next(item for item in remaining if item.payload_ref is None)
            self.assertEqual(failed_cleanup.payload_ref.spool_id, attempts[0])
            self.assertEqual(failed_cleanup.next_eligible_at, "2026-08-26T12:10:00Z")
            self.assertIsNone(cleaned.next_eligible_at)
            self.assertTrue(runtime_lookup(settings.paths.spool_dir, failed_cleanup.payload_ref.spool_id).exists())
            self.assertFalse(runtime_lookup(settings.paths.spool_dir, attempts[1]).exists())

    def test_claim_resumes_one_scan_after_cleanup_before_leasing_other_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            items = []
            for turn in ("mixed-one", "mixed-two"):
                ref = write_spool(turn, "public", settings, key_provider=key, now=NOW)
                items.append(enqueue_receipt(make_event(settings, turn_id=turn), ref, settings, now=NOW))
            discarded, ready = sorted(items, key=lambda item: item.queue_id)
            with patch("ei.queue.delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")), self.assertRaises(SpoolError):
                transition_queue_item(discarded, QueueState.NO_DISCARDED, settings, now=NOW)
            scans = 0
            real_page = queue.RuntimeCatalog.page
            real_advance = queue.RuntimeCatalog.advance
            real_delete = queue.delete_spool
            def counted_page(catalog, consumer, **kwargs):
                nonlocal scans
                if catalog.root == settings.paths.queue_dir and consumer == "claim":
                    scans += 1
                return real_page(catalog, consumer, **kwargs)
            def unlocked_delete(*args, **kwargs):
                self.assertFalse((settings.paths.queue_dir / ".queue.lock").exists())
                self.assertEqual(read_queue_item(ready.queue_id, settings).state, QueueState.READY)
                return real_delete(*args, **kwargs)
            def locked_advance(catalog, *args, **kwargs):
                self.assertTrue((catalog.root / ".queue.lock").exists())
                return real_advance(catalog, *args, **kwargs)
            with patch.object(queue.RuntimeCatalog, "page", counted_page), patch.object(queue.RuntimeCatalog, "advance", locked_advance), patch("ei.queue.delete_spool", side_effect=unlocked_delete):
                claimed = claim_queue_item("worker", settings, now=NOW + timedelta(seconds=300))
            self.assertEqual(claimed.queue_id, ready.queue_id)
            self.assertEqual(scans, 1)
            self.assertIsNone(read_queue_item(discarded.queue_id, settings).payload_ref)
            self.assertEqual(read_spool(ready.payload_ref, settings, now=NOW, key_provider=key), b"mixed-one" if ready == items[0] else b"mixed-two")

    def test_legacy_source_host_omission_is_read_without_rewriting_or_reprocessing(self):
        for state in ("NO_DISCARDED", "DONE"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
                raw = item.to_dict()
                raw.pop("source_host_id")
                raw.pop("source_host_family")
                raw["state"] = state
                path = runtime_lookup(settings.paths.queue_dir, item.queue_id)
                path.write_text(json.dumps(raw), encoding="utf-8")
                before = path.read_bytes(), path.stat().st_mtime_ns
                try:
                    loaded = read_queue_item(item.queue_id, settings)
                except QueueError as exc:
                    self.fail(f"valid legacy queue rejected: {exc}")
                self.assertEqual(loaded.source_host_id, "")
                self.assertNotIn("source_host_id", loaded.to_dict())
                self.assertEqual(queue_health(settings).corrupt, 0)
                self.assertIsNone(claim_queue_item("worker", settings, NOW))
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    def test_explicit_invalid_source_host_is_not_hidden_as_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            raw = enqueue_receipt(make_event(settings), None, settings, now=NOW).to_dict()
            for fields in ({"source_host_id": "", "source_host_family": ""},
                           {"source_host_id": None, "source_host_family": None},
                           {"source_host_id": "codex-cli"},
                           {"source_host_family": "codex-cli"}):
                with self.subTest(fields=fields):
                    value = {k: v for k, v in raw.items()
                             if k not in {"source_host_id", "source_host_family"}}
                    value.update(fields)
                    with self.assertRaises(QueueError):
                        QueueItem.from_dict(value)

    def test_payload_is_durable_before_queue_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("durable before queue", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-queue")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            self.assertTrue((runtime_lookup(settings.paths.spool_dir, "spool-queue")).exists())
            self.assertTrue((runtime_lookup(settings.paths.queue_dir, item.queue_id)).exists())
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1)), b"durable before queue")

    def test_idempotent_replay_reuses_same_queue_item_and_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            event = make_event(settings)
            first_ref = write_spool("first", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-first")
            first = enqueue_receipt(event, first_ref, settings, now=NOW)
            replay = enqueue_receipt(event, first_ref, settings, now=NOW + timedelta(seconds=1))
            self.assertEqual(replay.queue_id, first.queue_id)
            second_ref = write_spool("second", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-second")
            with self.assertRaisesRegex(QueueError, "IDEMPOTENCY_COLLISION"):
                enqueue_receipt(event, second_ref, settings, now=NOW + timedelta(seconds=2))

    def test_claim_lease_stale_reclaim_and_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            claimed = claim_queue_item("worker-a", settings, NOW, lease_seconds=1)
            self.assertEqual(claimed.state, QueueState.IN_PROGRESS)
            self.assertEqual(claimed.attempts, 1)
            reclaimed = claim_queue_item("worker-b", settings, NOW + timedelta(seconds=2), lease_seconds=10)
            self.assertEqual(reclaimed.state, QueueState.IN_PROGRESS)
            self.assertEqual(reclaimed.attempts, 2)
            done = transition_queue_item(reclaimed, QueueState.DONE, settings, now=NOW + timedelta(seconds=3), reason_code="APPLIED")
            self.assertEqual(done.state, QueueState.DONE)
            self.assertIsNone(claim_queue_item("worker-c", settings, NOW + timedelta(seconds=4)))

    def test_quota_transition_retains_spool_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("quota candidate", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-quota")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            updated = transition_queue_item(item, QueueState.DEFERRED_QUOTA, settings, now=NOW, reason_code="DEFERRED_QUOTA", next_eligible_at=NOW + timedelta(minutes=5))
            self.assertEqual(updated.state, QueueState.DEFERRED_QUOTA)
            self.assertIsNotNone(updated.payload_ref)
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(minutes=1)), b"quota candidate")

    def test_new_queue_item_records_only_the_selected_organizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = make_isolated_hook_settings(Path(tmp))
            settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "ollama", None),
                provider_order=("ollama", "subscription-cli"),
            )
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            self.assertEqual(item.provider_preference, ("ollama",))

    def test_claim_rewrites_legacy_multi_provider_preference_to_current_organizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = make_isolated_hook_settings(Path(tmp))
            old_settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "ollama", None),
                provider_order=("ollama", "subscription-cli"),
            )
            with patch("ei.queue._store"):
                item = enqueue_receipt(make_event(old_settings, turn_id="legacy-organizer"), None, old_settings, now=NOW)
            path = old_settings.paths.queue_dir / (item.queue_id + ".json")
            raw = item.to_dict()
            raw["provider_preference"] = ["ollama", "subscription-cli"]
            path.write_text(json.dumps(raw), encoding="utf-8")

            current_settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "subscription-cli", "codex-cli"),
                provider_order=("subscription-cli",),
            )
            claimed = claim_queue_item("current-organizer", current_settings, NOW, lease_seconds=30)

            self.assertEqual(claimed.provider_preference, ("subscription-cli",))
            persisted = json.loads(runtime_lookup(current_settings.paths.queue_dir, item.queue_id).read_text(encoding="utf-8"))
            self.assertEqual(persisted["provider_preference"], ["subscription-cli"])
            self.assertEqual(persisted["state"], QueueState.IN_PROGRESS.value)

    def test_retryable_failure_is_claimable_after_next_eligible_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            retryable = transition_queue_item(
                item,
                QueueState.FAILED_RETRYABLE,
                settings,
                now=NOW,
                reason_code="MALFORMED_RESPONSE",
                next_eligible_at=NOW + timedelta(minutes=5),
            )
            self.assertEqual(retryable.state, QueueState.FAILED_RETRYABLE)
            self.assertIsNone(claim_queue_item("too-early", settings, NOW + timedelta(minutes=4)))
            claimed = claim_queue_item("retry-worker", settings, NOW + timedelta(minutes=5))
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.state, QueueState.IN_PROGRESS)

    def test_legacy_queue_states_are_read_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            path = runtime_lookup(settings.paths.queue_dir, item.queue_id)
            raw = item.to_dict()
            raw["state"] = "DEFERRED_QUOTA"
            path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = __import__("ei.queue", fromlist=["read_queue_item"]).read_queue_item(item.queue_id, settings)
            self.assertEqual(loaded.state, QueueState.DEFERRED)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["state"], "DEFERRED_QUOTA")

    def test_no_discarded_deletes_payload_and_keeps_no_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("no body survives", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-no")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            updated = transition_queue_item(item, QueueState.NO_DISCARDED, settings, now=NOW, reason_code="project_specific")
            self.assertIsNone(updated.payload_ref)
            self.assertFalse((runtime_lookup(settings.paths.spool_dir, "spool-no")).exists())
            serialized = (runtime_lookup(settings.paths.queue_dir, item.queue_id)).read_text(encoding="utf-8")
            self.assertNotIn("no body survives", serialized)

    def test_queue_write_failure_creates_bounded_emergency_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            event = make_event(settings)
            original = __import__("ei.queue", fromlist=["_atomic_json"])._atomic_json

            def write(path, value, **kwargs):
                if path.is_relative_to(settings.paths.queue_dir):
                    raise OSError("simulated queue write failure")
                return original(path, value, **kwargs)

            with patch("ei.queue._atomic_json", side_effect=write):
                item = enqueue_receipt(event, None, settings, now=NOW)
            emergency = list(runtime_inventory(settings.paths.emergency_spool_dir, prefix="emergency_"))
            self.assertEqual(len(emergency), 1)
            data = json.loads(emergency[0].read_text(encoding="utf-8"))
            self.assertNotIn("body", data)
            self.assertEqual(item.state, QueueState.QUARANTINED)

    def test_emergency_recovery_deletes_only_after_normal_queue_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            original = queue._atomic_json
            def fail_queue(path, value, **kwargs):
                if path.is_relative_to(settings.paths.queue_dir):
                    raise OSError("simulated queue write failure")
                return original(path, value, **kwargs)
            with patch("ei.queue._atomic_json", side_effect=fail_queue):
                failed = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            emergency = next(runtime_inventory(settings.paths.emergency_spool_dir, prefix="emergency_"))
            item = QueueItem.from_dict(json.loads(emergency.read_text(encoding="utf-8"))["queue_item"])
            with patch("ei.queue._store", side_effect=OSError("still full")):
                self.assertEqual(recover_emergency_spool(settings, now=NOW), ())
            self.assertTrue(emergency.exists())
            from ei.queue import write_emergency_envelope
            recovered = recover_emergency_spool(settings, now=NOW + timedelta(seconds=1))
            self.assertEqual(len(recovered), 1)
            self.assertTrue((runtime_lookup(settings.paths.queue_dir, item.queue_id)).exists())
            self.assertEqual(list(runtime_inventory(settings.paths.emergency_spool_dir, prefix="emergency_")), [])

    def test_emergency_spool_full_reports_health_without_silent_eviction(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.capture_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.capture_policy_path.write_text(json.dumps({"emergency_spool": {"max_items": 1, "max_bytes": 65536, "ttl_seconds": 60}}), encoding="utf-8")
            first = enqueue_receipt(make_event(settings, turn_id="full-1"), None, settings, now=NOW)
            second = enqueue_receipt(make_event(settings, turn_id="full-2"), None, settings, now=NOW)
            write_emergency_envelope(first, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
            with self.assertRaisesRegex(QueueError, "EMERGENCY_SPOOL_FULL"):
                write_emergency_envelope(second, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
            emergency = list(runtime_inventory(settings.paths.emergency_spool_dir, prefix="emergency_"))
            self.assertEqual(len(emergency), 1)
            health = json.loads((settings.paths.emergency_spool_dir / "health.json").read_text(encoding="utf-8"))
            self.assertEqual(health["status"], "EMERGENCY_SPOOL_FULL")
            self.assertEqual(health["items"], 1)
    def test_capture_order_never_returns_semantic_no_for_unknown_coverage(self):
        class Host:
            capture_order = ("HOOK_DIRECT",)

        from ei.capture import select_capture_path
        self.assertEqual(select_capture_path(Host(), {}), "capture_coverage_unknown")
        self.assertEqual(select_capture_path(Host(), {"HOOK_DIRECT": True}), "HOOK_DIRECT")


if __name__ == "__main__":
    unittest.main()
