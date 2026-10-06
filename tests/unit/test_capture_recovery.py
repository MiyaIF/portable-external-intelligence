import tempfile
import unittest
import json
import os
import time
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from ei.capture_recovery import RecoverySource, recover_page, _read_verified
from tests.unattended_helpers import NOW, identity, make_settings
from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.key_provider import InMemoryKeyProvider
from ei.queue import list_queue_items
from ei.capture_ledger import list_receipts


class CaptureRecoveryTests(unittest.TestCase):
    def test_parser_deadline_prevents_initial_and_next_record_work(self):
        from ei.capture_recovery import _parsed_records
        chosen = self.write_memory("valid.md", ("Verify persisted results", "Retain independent source evidence"))
        for after_first in (False, True):
            with self.subTest(after_first=after_first):
                adapter = CodexMemoryAdapter([])
                records = _parsed_records(adapter, chosen, chosen.read_bytes(), chosen.stat(), 10.0)
                with patch("ei.capture_recovery.time.monotonic", return_value=0.0) as clock:
                    if after_first:
                        next(records)
                    clock.return_value = 11.0
                    with self.assertRaises(TimeoutError):
                        next(records)
                self.assertEqual(adapter.health["parsed"], int(after_first))

    def test_invalid_utf8_parser_is_partial_without_ack_or_cursor(self):
        from ei.journal import iter_events
        chosen = self.write_memory("valid.md")
        chosen.write_bytes(b"\xff\xfe")
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        result = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(result.reason_code, "SOURCE_PARTIAL")
        self.assertEqual((result.scanned, result.secured, result.created_events), (0, 0, 0))
        self.assertEqual((result.coverage, result.cursor_committed), ("UNKNOWN", False))
        self.assertEqual(source.adapter.parse_skipped, 1)
        self.assertEqual(list(iter_events(self.settings.paths.event_dir)), [])
        self.assertEqual(list_receipts(self.settings), ())
        self.assertEqual(list((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json")), [])

    def test_partial_parser_iterator_retains_only_durable_offset_and_resumes(self):
        from ei.journal import iter_events
        chosen = self.write_memory("valid.md", ("Verify persisted results", "Retain independent source evidence"))
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        original = source.adapter.read_verified
        def first_then_invalid(*args):
            yield next(iter(original(*args)))
            raise ValueError("malformed source record")
        with patch.object(source.adapter, "read_verified", side_effect=first_then_invalid):
            result = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(result.reason_code, "SOURCE_PARTIAL")
        self.assertEqual((result.scanned, result.secured, result.created_events), (1, 1, 1))
        self.assertEqual((result.coverage, result.cursor_committed), ("UNKNOWN", True))
        self.assertEqual(source.adapter.parse_skipped, 1)
        cursor = next((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        state = json.loads(cursor.read_text(encoding="utf-8"))
        self.assertEqual(state["frontier"], [[chosen.name, "file"]])
        self.assertEqual(state["record_offset"], 1)
        first_ids = {event.event_id for event in iter_events(self.settings.paths.event_dir)}
        self.assertEqual(len(first_ids), 1)
        replay = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual((replay.secured, replay.created_events), (1, 1))
        after_ids = {event.event_id for event in iter_events(self.settings.paths.event_dir)}
        self.assertEqual(len(after_ids), 2)
        self.assertTrue(first_ids <= after_ids)

    def test_only_parser_format_errors_are_soft_partial(self):
        chosen = self.write_memory("valid.md")
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        for target, error, expected in (
            ("parser", ValueError("malformed source record"), "SOURCE_PARTIAL"),
            ("parser", TimeoutError("SOURCE_TIME_LIMIT"), "SOURCE_TIME_LIMIT"),
            ("state", UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid state"), "SOURCE_READ_OR_STATE_UNAVAILABLE"),
            ("read", OSError("storage unavailable"), "SOURCE_READ_OR_STATE_UNAVAILABLE"),
            ("coordinator", ValueError("invalid durable binding"), "SOURCE_READ_OR_STATE_UNAVAILABLE"),
        ):
            with self.subTest(target=target, error=type(error).__name__):
                skipped_before = source.adapter.parse_skipped
                mocked = patch.object(source.adapter, "read_verified", side_effect=error) if target == "parser" else patch(
                    {"state": "ei.capture_recovery._load_state", "read": "ei.capture_recovery._read_verified",
                     "coordinator": "ei.capture_recovery.coordinate_record"}[target], side_effect=error)
                with mocked:
                    result = recover_page(self.settings, source, now=NOW, max_ms=10000)
                self.assertEqual(result.reason_code, expected)
                self.assertEqual((result.secured, result.created_events, result.cursor_committed), (0, 0, False))
                self.assertEqual(source.adapter.parse_skipped - skipped_before, int(expected == "SOURCE_PARTIAL"))

    def test_corrupt_frontier_is_not_mistaken_for_partial_source_content(self):
        chosen = self.write_memory("valid.md", ("Verify persisted results", "Retain independent source evidence"))
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        first = recover_page(self.settings, source, now=NOW, max_records=1, max_ms=10000)
        self.assertEqual((first.secured, first.created_events), (1, 1))
        cursor = next((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        cursor.write_bytes(b"\xff")
        with patch.object(source.adapter, "read_verified", side_effect=AssertionError("parser must not read corrupt state")):
            result = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(result.reason_code, "SOURCE_READ_OR_STATE_UNAVAILABLE")
        self.assertEqual((result.secured, result.created_events, result.cursor_committed), (0, 0, False))
        self.assertEqual(source.adapter.parse_skipped, 0)
        self.assertEqual(cursor.read_bytes(), b"\xff")

    def test_recovery_page_six_positional_arguments_keep_zero_created_default(self):
        from ei.capture_recovery import RecoveryPage
        page = RecoveryPage(1, 1, 0, "UNKNOWN", True, "SOURCE_CORRELATION_UNKNOWN")
        self.assertEqual(page.created_events, 0)

    def test_exact_legacy_file_never_enumerates_siblings_and_replays_event(self):
        from ei.journal import iter_events
        chosen = self.write_memory("valid.md")
        self.write_memory("memory.md", ("This sibling was never selected",))
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        with patch("ei.capture_recovery.os.scandir", side_effect=AssertionError("exact file enumerated parent")):
            first = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual((first.secured, first.coverage, first.cursor_committed), (1, "UNKNOWN", True))
        self.assertEqual(first.created_events, 1)
        events = list(iter_events(self.settings.paths.event_dir))
        self.assertEqual(len(events), 1)
        original = next(self.settings.paths.event_dir.rglob("*.json")).read_bytes()
        replay = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(replay.secured, 1)
        self.assertEqual(replay.created_events, 0)
        self.assertEqual(next(self.settings.paths.event_dir.rglob("*.json")).read_bytes(), original)
        self.assertEqual(list_receipts(self.settings), ())

    def test_legacy_namespace_validates_present_fields_privacy_and_exact_cursor(self):
        chosen = self.write_memory("valid.md")
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        for invalid in (replace(source, instance_hash="sha256:" + "a" * 64), replace(source, host_id="../host"), replace(source, instance_hash="bad", store_id="bad")):
            self.assertEqual(recover_page(self.settings, invalid, now=NOW, max_ms=10000).secured, 0)
        original_read = source.adapter.read_verified
        for classification in ("secret", "client-confidential", "machine-local"):
            def classified(*args):
                return (replace(record, classification=classification) for record in original_read(*args))
            with patch.object(source.adapter, "read_verified", side_effect=classified), patch("ei.capture_recovery.coordinate_record", side_effect=AssertionError("private body reached coordinator")):
                result = recover_page(self.settings, source, now=NOW, max_ms=10000)
            self.assertEqual((result.secured, result.rejected), (0, 1))
        self.assertFalse(self.settings.paths.event_dir.exists())
        cursor = next((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        value = json.loads(cursor.read_text())
        value["frontier"] = [["memory.md", "file"]]
        cursor.write_text(json.dumps(value))
        with patch("ei.capture_recovery._read_verified", side_effect=AssertionError("unselected cursor read")):
            result = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(result.secured, 0)
        self.assertFalse(result.cursor_committed)

    def test_legacy_event_deadline_does_not_ack_and_trusted_route_is_not_changed(self):
        from ei.operation_runtime import OperationBudget
        from ei import ingest
        chosen = self.write_memory("valid.md")
        source = replace(self.source, root=chosen, instance_hash=None, store_id=None)
        budget = OperationBudget(10000)
        original = ingest.append_event
        def append_then_expire(*args, **kwargs):
            path = original(*args, **kwargs)
            budget.deadline = 0
            # Descendant budget has the same deadline value, so exhaust it too.
            kwargs["budget"].deadline = 0
            return path
        with patch("ei.ingest.append_event", side_effect=append_then_expire):
            result = recover_page(self.settings, source, now=NOW, max_ms=10000, budget=budget)
        self.assertEqual((result.secured, result.cursor_committed), (0, False))
        self.assertEqual(result.created_events, 0)
        before = next(self.settings.paths.event_dir.rglob("*.json")).read_bytes()
        self.assertEqual(recover_page(self.settings, source, now=NOW, max_ms=10000).secured, 1)
        self.assertEqual(next(self.settings.paths.event_dir.rglob("*.json")).read_bytes(), before)
        trusted_file = self.write_memory("second.md")
        trusted = replace(self.source, root=trusted_file)
        secured = recover_page(self.settings, trusted, now=NOW, max_ms=10000)
        self.assertEqual((secured.secured, secured.created_events), (1, 0))
        plans = {p: p.read_bytes() for p in (self.settings.paths.local_state_dir / "source-records").glob("*.json")}
        self.assertEqual(recover_page(self.settings, replace(trusted, instance_hash=None, store_id=None), now=NOW, max_ms=10000).secured, 1)
        self.assertEqual({p: p.read_bytes() for p in plans}, plans)
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_default_budget_retries_acknowledge_both_candidates_without_prefix_starvation(self):
        self.write_memory(claims=("Verify persisted results", "Use bounded retrieval for every operation"))
        acknowledged = 0
        for _ in range(20):
            page = recover_page(self.settings, self.source, now=NOW)
            acknowledged += page.secured
            if page.secured:
                self.assertTrue(page.cursor_committed)
            if acknowledged == 2:
                break
        self.assertEqual(acknowledged, 2)
        items = list_queue_items(self.settings)
        self.assertEqual(len(items), 2)
        self.assertEqual(len({item.queue_id for item in items}), 2)

    def test_smaller_page_limit_bounds_descendant_spool_lock(self):
        from ei.operation_runtime import OperationBudget
        self.write_memory()
        lock_root = self.settings.paths.spool_dir
        lock_root.mkdir(parents=True)
        (lock_root / ".spool.lock").write_bytes(b"")
        started = time.monotonic()
        result = recover_page(self.settings, self.source, now=NOW, max_ms=150,
                              budget=OperationBudget(2000))
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual((result.secured, result.cursor_committed), (0, False))

    def test_exhausted_shared_budget_creates_no_runtime_or_cursor(self):
        from ei.operation_runtime import OperationBudget
        self.write_memory()
        result = recover_page(self.settings, self.source, now=NOW, budget=OperationBudget(0))
        self.assertEqual((result.secured, result.cursor_committed), (0, False))
        self.assertEqual(result.reason_code, "SOURCE_TIME_LIMIT")
        self.assertFalse(self.settings.paths.local_state_dir.exists())

    def test_intake_lock_obeys_shared_deadline_without_acknowledging_record(self):
        from ei.operation_runtime import OperationBudget
        self.write_memory()
        lock_root = self.settings.paths.spool_dir
        lock_root.mkdir(parents=True)
        (lock_root / ".spool.lock").write_bytes(b"")
        started = time.monotonic()
        result = recover_page(self.settings, self.source, now=NOW, budget=OperationBudget(150))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual((result.secured, result.cursor_committed), (0, False))
        (lock_root / ".spool.lock").unlink()
        self.assertEqual(self.recover().secured, 1)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.settings = make_settings(self.root)
        self.source_root = self.root / "sources"
        self.source_root.mkdir()
        key = identity()
        self.source = RecoverySource("memory", key.host_id, key.instance_hash, key.store_id,
                                     self.source_root, CodexMemoryAdapter([]), True)
        provider = InMemoryKeyProvider("test-key", b"s" * 32)
        key_patch = patch("ei.spool.default_key_provider", return_value=provider)
        key_patch.start()
        self.addCleanup(key_patch.stop)

    def write_memory(self, name="memory.md", claims=("Verify persisted results",)):
        path = self.source_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("## Reusable knowledge\n" + "".join("- " + value + "\n" for value in claims), encoding="utf-8")
        return path

    def recover(self, **kwargs):
        return recover_page(self.settings, self.source, now=NOW, max_ms=10000, **kwargs)

    def test_hookless_candidate_is_secured_without_claiming_turn_coverage(self):
        self.write_memory()
        result = self.recover()
        self.assertEqual((result.scanned, result.secured), (1, 1))
        self.assertEqual(result.coverage, "UNKNOWN")
        self.assertTrue(result.cursor_committed)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.recover()
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_no_source_does_not_imply_covered(self):
        self.assertEqual(self.recover().coverage, "UNKNOWN")
        self.assertEqual(len(list_queue_items(self.settings)), 0)

    def test_record_limit_and_full_capacity_resume_at_unacknowledged_record(self):
        self.write_memory(claims=("Verify persisted results", "Use bounded retrieval for every operation", "Preserve privacy for all persisted records"))
        policy = self.settings.capture_policy_path
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text(json.dumps({"pending": {"max_items": 1}}), encoding="utf-8")
        first = self.recover(max_records=2)
        self.assertEqual(first.secured, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        policy.write_text(json.dumps({"pending": {"max_items": 10}}), encoding="utf-8")
        second = self.recover(max_records=1)
        self.assertEqual(second.secured, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 2)
        self.recover(max_records=1)
        self.assertEqual(len(list_queue_items(self.settings)), 3)

    def test_full_before_first_candidate_has_no_acknowledged_cursor_commit(self):
        self.write_memory()
        policy = self.settings.capture_policy_path
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text(json.dumps({"pending": {"max_bytes": 1}}), encoding="utf-8")
        result = self.recover()
        self.assertEqual(result.secured, 0)
        self.assertFalse(result.cursor_committed)

    def test_more_files_than_record_limit_and_earlier_addition_next_cycle(self):
        self.write_memory("z/memory.md")
        self.write_memory("y/memory.md", ("Preserve privacy for all persisted records",))
        self.recover(max_records=1)
        self.write_memory("a/memory.md", ("Bound operation duration",))
        for _ in range(8):
            page = self.recover(max_records=1)
            self.assertLessEqual(page.scanned, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 3)

    def test_deleted_frontier_file_does_not_block_later_or_new_candidates(self):
        self.write_memory("memory.md")
        deleted = self.write_memory("memory_summary.md", ("This candidate will disappear before intake",))
        self.write_memory("raw_memories.md", ("Recover the remaining structured candidate",))
        self.assertEqual(self.recover(max_records=1).secured, 1)
        deleted.unlink()
        self.write_memory("added/memory.md", ("Recover candidates added after the previous page",))
        next_page = self.recover(max_records=1)
        self.assertEqual((next_page.secured, next_page.coverage), (1, "UNKNOWN"))
        for _ in range(5):
            self.recover(max_records=1)
        self.assertEqual(len(list_queue_items(self.settings)), 3)
        self.assertEqual(len(list_receipts(self.settings)), 3)

    def test_deleted_frontier_directory_does_not_block_later_or_new_candidates(self):
        self.write_memory("a/memory.md")
        deleted = self.write_memory("b/memory.md", ("This directory will disappear before intake",))
        self.write_memory("c/memory.md", ("Recover the remaining structured candidate",))
        initial = recover_page(self.settings, self.source, now=NOW, max_records=1, max_ms=20000)
        self.assertEqual(initial.secured, 1, repr(initial))
        deleted.unlink()
        deleted.parent.rmdir()
        self.write_memory("aa/memory.md", ("Recover additions before the old cursor position",))
        next_page = self.recover(max_records=1)
        self.assertEqual((next_page.secured, next_page.coverage), (1, "UNKNOWN"))
        for _ in range(5):
            self.recover(max_records=1)
        self.assertEqual(len(list_queue_items(self.settings)), 3)
        self.assertEqual(len(list_receipts(self.settings)), 3)

    def test_missing_only_frontier_entry_is_unknown_without_acknowledged_commit(self):
        self.write_memory("memory.md")
        deleted = self.write_memory("memory_summary.md", ("This candidate will disappear before intake",))
        self.recover(max_records=1)
        deleted.unlink()
        page = self.recover(max_records=1)
        self.assertEqual((page.scanned, page.secured, page.coverage, page.cursor_committed), (0, 0, "UNKNOWN", False))
        self.assertEqual(page.reason_code, "SOURCE_ENTRY_MISSING")
        self.write_memory("added/memory.md", ("Recover candidates after all old entries disappear",))
        for _ in range(3):
            self.recover(max_records=1)
        self.assertEqual(len(list_queue_items(self.settings)), 2)

    def test_frontier_stat_permission_error_does_not_discard_the_entry(self):
        self.write_memory("memory.md")
        blocked = self.write_memory("memory_summary.md", ("Keep a temporarily unreadable candidate pending",)).resolve(strict=True)
        self.recover(max_records=1)
        cursor = next((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        before = cursor.read_bytes()
        original_stat = Path.stat
        denied = False
        def deny_selected(path, *args, **kwargs):
            nonlocal denied
            if path == blocked:
                denied = True
                raise PermissionError("temporary denial")
            return original_stat(path, *args, **kwargs)
        with patch.object(Path, "stat", deny_selected):
            page = self.recover(max_records=1)
        self.assertTrue(denied, "frontier stat permission fault was not injected")
        self.assertEqual((page.secured, page.cursor_committed), (0, False))
        self.assertEqual(cursor.read_bytes(), before)
        self.assertEqual(self.recover(max_records=1).secured, 1)

    def test_frontier_directory_replaced_with_link_is_not_treated_as_deleted(self):
        self.write_memory("a/memory.md")
        replaced = self.write_memory("b/memory.md", ("Keep unsafe replacements outside the reader",))
        self.recover(max_records=1)
        cursor = next((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        before = cursor.read_bytes()
        replaced.unlink()
        replaced.parent.rmdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "memory.md").write_text("## Reusable knowledge\n- Never read the unauthorized replacement\n", encoding="utf-8")
        try:
            replaced.parent.symlink_to(outside, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(replaced.parent), str(outside)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, "test junction could not be created")
        with patch("ei.capture_recovery._read_verified", side_effect=AssertionError("unsafe replacement read")):
            page = self.recover(max_records=1)
        self.assertEqual((page.secured, page.cursor_committed), (0, False))
        self.assertNotEqual(page.reason_code, "SOURCE_ENTRY_MISSING")
        self.assertEqual(cursor.read_bytes(), before)

    def test_privacy_rejection_has_durable_body_free_receipt_then_progresses(self):
        self.write_memory(claims=("password=secret-value", "Verify persisted results"))
        result = self.recover()
        self.assertEqual((result.rejected, result.secured), (1, 1))
        self.assertTrue(any(item.reason_code == "SOURCE_PRIVACY_REJECTED" for item in list_receipts(self.settings)))
        for path in self.settings.paths.runtime_dir.rglob("*.json"):
            self.assertNotIn("password=secret-value", path.read_text(encoding="utf-8"))

    def test_large_file_is_rejected_before_open(self):
        path = self.write_memory(claims=("x" * 10000,))
        with patch("ei.capture_recovery._read_verified", side_effect=AssertionError("oversized file read")):
            page = self.recover(max_bytes=2000)
        self.assertEqual(page.secured, 0)
        self.assertEqual(page.coverage, "UNKNOWN")

    def test_replaced_file_gets_distinct_version(self):
        self.write_memory()
        self.recover()
        self.write_memory(claims=("Use bounded retrieval for every operation",))
        self.recover()
        self.assertEqual(len(list_queue_items(self.settings)), 2)

    def test_adapter_without_bytes_boundary_is_not_opened(self):
        self.write_memory()
        source = replace(self.source, adapter=object())
        page = recover_page(self.settings, source, now=NOW)
        self.assertEqual((page.coverage, page.cursor_committed), ("UNKNOWN", False))

    def test_frontier_limit_is_explicit_and_restart_with_larger_budget_succeeds(self):
        for index in range(20):
            self.write_memory(f"directory-{index:02}/memory.md")
        page = self.recover(max_bytes=100)
        self.assertEqual(page.reason_code, "SOURCE_FRONTIER_LIMIT")
        self.assertEqual(page.secured, 0)
        previous_count = 0
        queue_ids = set()
        for _ in range(20):
            page = self.recover(max_records=5)
            self.assertLessEqual(page.scanned, 5)
            self.assertLessEqual(page.secured, 5)
            queue_ids = {item.queue_id for item in list_queue_items(self.settings)}
            self.assertGreaterEqual(len(queue_ids), previous_count)
            previous_count = len(queue_ids)
            if len(queue_ids) == 20:
                break

        self.assertEqual(len(queue_ids), 20)
        self.assertEqual(len(set(queue_ids)), 20)
        receipts = list_receipts(self.settings)
        self.assertEqual(len(receipts), 20)
        self.assertEqual(len({receipt.capture_id for receipt in receipts}), 20)
        self.assertEqual({receipt.state for receipt in receipts}, {"SECURED"})

    def test_time_limit_does_not_skip_unlisted_entries(self):
        self.write_memory()
        with patch("ei.capture_recovery.time.monotonic", side_effect=[0, 0, 2]):
            result = recover_page(self.settings, self.source, now=NOW, max_ms=1)
        self.assertEqual(result.reason_code, "SOURCE_TIME_LIMIT")
        self.assertFalse(result.cursor_committed)
        self.assertEqual(self.recover().secured, 1)

    def test_denied_directory_and_arbitrary_filename_are_not_opened(self):
        self.write_memory("transcripts/memory.md")
        self.write_memory("hook-input.md")
        with patch("ei.capture_recovery._read_verified", side_effect=AssertionError("denied read")):
            self.assertEqual(self.recover().scanned, 0)

    def test_file_replacement_at_open_rejected_before_bytes_are_read(self):
        path = self.write_memory()
        replacement = self.write_memory("replacement.md", ("Other persisted content is not authorized",))
        before = path.stat()
        original_open = os.open
        def replace_at_open(target, flags, *args, **kwargs):
            os.replace(replacement, path)
            return original_open(target, flags, *args, **kwargs)
        with patch("ei.capture_recovery.os.open", side_effect=replace_at_open):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED_DURING_READ"):
                _read_verified(self.source_root, path, before, 1000, time.monotonic() + 10)

    def test_parent_link_is_rejected_before_content_read(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "memory.md").write_text("## Reusable knowledge\n- Never cross an authorized root boundary\n", encoding="utf-8")
        link = self.source_root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, "test junction could not be created")
        with patch("ei.capture_recovery._read_verified", side_effect=AssertionError("link read")):
            self.assertEqual(self.recover().secured, 0)

    def test_source_root_junction_swap_after_boundary_check_is_rejected(self):
        from ei.safe_fs import assert_safe_target as real_assert_safe_target

        outside = self.root / "outside-authorized-source"
        outside.mkdir()
        (outside / "memory.md").write_text(
            "## Reusable knowledge\n- Outside boundary sentinel\n", encoding="utf-8"
        )
        swapped = False

        def swap_after_source_check(root, target, **kwargs):
            nonlocal swapped
            validated = real_assert_safe_target(root, target, **kwargs)
            if not swapped and Path(target) == self.source_root and not kwargs.get("allow_root", False):
                self.source_root.rename(self.root / "source-before-swap")
                if os.name == "nt":
                    result = subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(self.source_root), str(outside)],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
                else:
                    self.source_root.symlink_to(outside, target_is_directory=True)
                swapped = True
            return validated

        with patch("ei.capture_recovery.assert_safe_target", side_effect=swap_after_source_check):
            result = self.recover()

        self.assertTrue(swapped)
        self.assertEqual((result.secured, result.cursor_committed), (0, False), repr(result))
        self.assertEqual(list_queue_items(self.settings), ())
        spool_root = self.settings.paths.spool_dir
        self.assertEqual(list(spool_root.rglob("*.json")) if spool_root.exists() else [], [])
        self.assertEqual(result.reason_code, "SOURCE_CHANGED_DURING_READ", repr(result))

    def test_growth_during_stream_read_is_not_accepted(self):
        path = self.write_memory()
        original_fstat = os.fstat
        calls = 0
        def mutate_after_read(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                with path.open("ab") as stream:
                    stream.write(b"changed")
            return original_fstat(descriptor)
        with patch("ei.capture_recovery.os.fstat", side_effect=mutate_after_read):
            self.assertEqual(self.recover().secured, 0)

    def test_missing_stable_record_id_never_invents_coverage(self):
        from ei.adapters.claude import ClaudeAdapter
        self.write_memory("memory.json", ())
        path = self.source_root / "memory.json"
        path.write_text(json.dumps({"schema_version": 1, "entries": [{"title": "Memory", "claim": "Verify persisted results before completion"}]}), encoding="utf-8")
        source = replace(self.source, host_id="claude-code", adapter=ClaudeAdapter([]))
        result = recover_page(self.settings, source, now=NOW, max_ms=10000)
        self.assertEqual(result.reason_code, "SOURCE_RECORD_ID_UNKNOWN")
        self.assertEqual(len(list_queue_items(self.settings)), 0)


    def test_unverified_source_is_not_claimed_as_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = identity()
            adapter = Mock()
            source = RecoverySource("test", key.host_id, key.instance_hash,
                                    key.store_id, root / "source", adapter)
            result = recover_page(make_settings(root), source, now=NOW)
            self.assertEqual(result.coverage, "UNKNOWN")
            self.assertFalse(result.cursor_committed)
            self.assertEqual(adapter.mock_calls, [])
