import tempfile
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.capture_recovery import RecoverySource, recover_page
from ei.ingest import ingest_sources
from ei.key_provider import InMemoryKeyProvider
from ei.queue import list_queue_items
from tests.unattended_helpers import NOW, identity, make_settings


class CaptureCatchupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.settings = make_settings(self.root)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.path = self.sources / "memory.md"
        self.path.write_text("## Reusable knowledge\n- Verify persisted results\n", encoding="utf-8")
        key = identity()
        self.source = RecoverySource("test", key.host_id, key.instance_hash, key.store_id, self.sources, CodexMemoryAdapter([]), True)
        key_patch = patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test-key", b"s" * 32))
        key_patch.start()
        self.addCleanup(key_patch.stop)

    def ingest(self):
        return ingest_sources(self.settings, [CodexMemoryAdapter([self.path])])

    def recover(self):
        return recover_page(self.settings, self.source, now=NOW, max_ms=10000)

    def test_ingest_then_recovery_reuses_actual_event(self):
        self.assertEqual(self.ingest().created_events, 1)
        self.assertEqual(self.recover().secured, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 0)
        self.assertEqual(len(list(self.settings.paths.event_dir.rglob("*.json"))), 1)

    def test_recovery_then_ingest_preserves_single_pending_candidate(self):
        self.assertEqual(self.recover().secured, 1)
        self.assertEqual(self.ingest().created_events, 0)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])

    def test_concurrent_paths_keep_one_persisted_candidate(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.ingest), pool.submit(self.recover)]
            for future in futures:
                future.result()
        self.recover()
        self.assertEqual(len(list_queue_items(self.settings)) + len(list(self.settings.paths.event_dir.rglob("*.json"))), 1)

    def test_capture_queue_before_receipt_cannot_fall_back_to_direct_event(self):
        with patch("ei.pending_capture.ledger._record_receipt_locked", side_effect=OSError("interrupted")):
            self.recover()
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.assertEqual(self.ingest().created_events, 0)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])

    def test_planned_event_before_append_resumes_same_route(self):
        with patch("ei.ingest.append_event", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                self.ingest()
        self.recover()
        self.ingest()
        self.assertEqual(len(list_queue_items(self.settings)) + len(list(self.settings.paths.event_dir.rglob("*.json"))), 1)

    def test_missing_capture_plan_cannot_create_second_storage_route(self):
        self.recover()
        for path in (self.settings.paths.local_state_dir / "source-records").glob("*.json"):
            path.unlink()
        self.assertEqual(self.ingest().created_events, 0)
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])

    def test_corrupt_plan_is_unknown_and_does_not_create_candidate(self):
        self.ingest()
        for path in (self.settings.paths.local_state_dir / "source-records").glob("*.json"):
            path.write_text("{}", encoding="utf-8")
        result = self.recover()
        self.assertEqual((result.coverage, result.secured), ("UNKNOWN", 0))
        self.assertEqual(len(list_queue_items(self.settings)), 0)

    def test_legacy_fingerprint_without_event_evidence_is_unknown(self):
        self.ingest()
        for directory in (self.settings.paths.local_state_dir / "source-records", self.settings.paths.event_dir):
            for path in directory.rglob("*.json"):
                path.unlink()
        result = self.recover()
        self.assertEqual(result.reason_code, "SOURCE_LEGACY_EVIDENCE_UNKNOWN")
        self.assertEqual(len(list_queue_items(self.settings)), 0)

    def test_lost_plan_after_queue_before_receipt_resumes_original_intake(self):
        with patch("ei.pending_capture.ledger._record_receipt_locked", side_effect=OSError("interrupted")):
            self.recover()
        for path in (self.settings.paths.local_state_dir / "source-records").glob("*.json"):
            path.unlink()
        self.assertEqual(self.ingest().created_events, 0)
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_changed_file_with_lost_plan_keeps_old_identity_and_adds_new_record(self):
        self.recover()
        first_id = list_queue_items(self.settings)[0].capture_id
        for path in (self.settings.paths.local_state_dir / "source-records").glob("*.json"):
            path.unlink()
        self.path.write_text("## Reusable knowledge\n- Verify persisted results\n- Bound all reads before parsing records\n", encoding="utf-8")
        self.recover()
        items = list_queue_items(self.settings)
        self.assertEqual(len(items), 2)
        self.assertIn(first_id, {item.capture_id for item in items})

    def test_missing_or_corrupt_binding_cannot_change_existing_capture_route(self):
        self.recover()
        binding = next((self.settings.paths.local_state_dir / "source-bindings").glob("*.json"))
        saved = binding.read_bytes()
        for content in (None, b"{}"):
            if content is None:
                binding.unlink()
            else:
                binding.write_bytes(content)
            self.assertEqual(self.recover().secured, 0)
            with self.assertRaises((ValueError, KeyError)):
                self.ingest()
            self.assertEqual(len(list_queue_items(self.settings)), 1)
            self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])
            binding.write_bytes(saved)

    def test_conflicting_source_identity_cannot_rebind_and_unbound_source_stays_direct(self):
        from dataclasses import replace
        self.recover()
        conflict = replace(self.source, instance_hash="sha256:" + "f" * 64)
        self.assertEqual(recover_page(self.settings, conflict, now=NOW, max_ms=10000).secured, 0)
        other = self.root / "other" / "memory.md"
        other.parent.mkdir()
        other.write_text("## Reusable knowledge\n- Keep each independent source scope separate\n", encoding="utf-8")
        self.assertEqual(ingest_sources(self.settings, [CodexMemoryAdapter([other])]).created_events, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_binding_budget_defers_without_evicting_existing_identity(self):
        self.recover()
        binding = next((self.settings.paths.local_state_dir / "source-bindings").glob("*.json"))
        original = binding.read_bytes()
        result = recover_page(self.settings, self.source, now=NOW, max_ms=10000, max_bytes=500)
        self.assertEqual(result.reason_code, "SOURCE_BINDING_LIMIT")
        self.assertEqual(binding.read_bytes(), original)
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_incomplete_capture_plan_is_reported_unknown_without_exception(self):
        self.recover()
        path = next((self.settings.paths.local_state_dir / "source-records").glob("*.json"))
        value = json.loads(path.read_bytes())
        del value["identity"]
        path.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self.recover().secured, 0)

    def test_process_exit_releases_source_lock_without_waiting_for_stale_timeout(self):
        script = (
            "import os,sys; from pathlib import Path; "
            "from tests.unattended_helpers import make_settings; "
            "from ei.ingest import source_coordination; "
            "lock=source_coordination(make_settings(Path(sys.argv[1]))); lock.__enter__(); os._exit(0)"
        )
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script, str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(self.recover().secured, 1)

    def test_live_other_process_excludes_recovery_until_its_handle_closes(self):
        script = (
            "import sys; from pathlib import Path; "
            "from tests.unattended_helpers import make_settings; "
            "from ei.ingest import source_coordination; "
            "lock=source_coordination(make_settings(Path(sys.argv[1]))); lock.__enter__(); "
            "print('locked',flush=True); sys.stdin.readline(); lock.__exit__(None,None,None)"
        )
        process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", "-c", script, str(self.root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            result = self.recover()
            self.assertEqual((result.secured, result.reason_code), (0, "SOURCE_COORDINATION_UNAVAILABLE"))
            process.communicate("release\n", timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(self.recover().secured, 1)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
