import tempfile
import json
import os
import re
import subprocess
import sys
import threading
import time as _time
import unittest
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from ei.adapters.codex_memory import CodexMemoryAdapter
from ei import capture_recovery as capture_recovery_module
from ei.capture_recovery import RecoverySource, recover_page
from ei.ingest import ingest_sources
from ei.key_provider import InMemoryKeyProvider
from ei.queue import list_queue_items
from tests.unattended_helpers import NOW, identity, make_settings

FUNCTIONAL_RECOVERY_BUDGET_MS = 20_000


class _ControlledMonotonicClock:
    """Finite logical time for recovery fixtures; every read advances it."""

    def __init__(self, *, step_ms=1):
        self._value = 0.0
        self._step_seconds = step_ms / 1000

    def __call__(self):
        self._value += self._step_seconds
        return self._value

    def advance_ms(self, milliseconds):
        self._value += milliseconds / 1000


class _ControlledTimeProxy:
    def __init__(self, clock):
        self._clock = clock
        self._controlled_thread = threading.get_ident()

    def monotonic(self):
        if threading.get_ident() == self._controlled_thread:
            return self._clock()
        return _time.monotonic()

    def __getattr__(self, name):
        return getattr(_time, name)


def _diagnostic_token(value):
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,95}", value, flags=re.ASCII):
        return value
    return "UNKNOWN"


def _diagnostic_count(value):
    if type(value) is int and 0 <= value <= 1_000_000:
        return str(value)
    return "UNKNOWN"


def _diagnostic_flag(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "UNKNOWN"


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

    def ingest(self, source_path=None):
        return ingest_sources(self.settings, [CodexMemoryAdapter([source_path or self.path])])

    def recover(self, *, max_ms=FUNCTIONAL_RECOVERY_BUDGET_MS, max_bytes=2_097_152, source=None):
        controlled_time = _ControlledTimeProxy(_ControlledMonotonicClock())
        with patch("ei.operation_runtime.time", new=controlled_time):
            with patch("ei.capture_recovery.time", new=controlled_time):
                return recover_page(
                    self.settings,
                    source if source is not None else self.source,
                    now=NOW,
                    max_ms=max_ms,
                    max_bytes=max_bytes,
                )

    @staticmethod
    def recovery_diagnostic(result):
        return (
            f"reason={_diagnostic_token(result.reason_code)}; coverage={_diagnostic_token(result.coverage)}; "
            f"secured={_diagnostic_count(result.secured)}; "
            f"cursor_committed={_diagnostic_flag(result.cursor_committed)}"
        )

    def test_ingest_then_recovery_reuses_actual_event(self):
        self.assertEqual(self.ingest(self.path.resolve(strict=True)).created_events, 1)
        result = self.recover()
        self.assertEqual(result.secured, 1, msg=self.recovery_diagnostic(result))
        self.assertEqual(len(list_queue_items(self.settings)), 0)
        self.assertEqual(len(list(self.settings.paths.event_dir.rglob("*.json"))), 1)

    def test_recovery_then_ingest_preserves_single_pending_candidate(self):
        result = self.recover()
        self.assertEqual(result.secured, 1, msg=self.recovery_diagnostic(result))
        self.assertEqual(self.ingest(self.path.resolve(strict=True)).created_events, 0)
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
        initial = self.recover()
        self.assertEqual(initial.secured, 1, msg=self.recovery_diagnostic(initial))
        binding = next((self.settings.paths.local_state_dir / "source-bindings").glob("*.json"))
        saved = binding.read_bytes()
        for content in (None, b"{}"):
            if content is None:
                binding.unlink()
            else:
                binding.write_bytes(content)
            result = self.recover()
            self.assertEqual(result.secured, 0, msg=self.recovery_diagnostic(result))
            with self.assertRaises((ValueError, KeyError)):
                self.ingest()
            self.assertEqual(len(list_queue_items(self.settings)), 1)
            self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])
            binding.write_bytes(saved)

    def test_conflicting_source_identity_cannot_rebind_and_unbound_source_stays_direct(self):
        from dataclasses import replace
        self.recover()
        conflict = replace(self.source, instance_hash="sha256:" + "f" * 64)
        conflict_result = self.recover(source=conflict)
        self.assertEqual(conflict_result.secured, 0, msg=self.recovery_diagnostic(conflict_result))
        other = self.root / "other" / "memory.md"
        other.parent.mkdir()
        other.write_text("## Reusable knowledge\n- Keep each independent source scope separate\n", encoding="utf-8")
        self.assertEqual(ingest_sources(self.settings, [CodexMemoryAdapter([other])]).created_events, 1)
        self.assertEqual(len(list_queue_items(self.settings)), 1)

    def test_binding_budget_defers_without_evicting_existing_identity(self):
        self.recover()
        binding = next((self.settings.paths.local_state_dir / "source-bindings").glob("*.json"))
        original = binding.read_bytes()
        result = self.recover(max_ms=10000, max_bytes=500)
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
        recovered = self.recover()
        self.assertEqual(recovered.secured, 1, msg=self.recovery_diagnostic(recovered))

    def test_functional_recovery_does_not_charge_host_clock_jump_during_real_read(self):
        host_clock = _ControlledMonotonicClock()
        host_time = _ControlledTimeProxy(host_clock)
        real_read = capture_recovery_module._read_verified

        def read_then_advance_host_clock(*args, **kwargs):
            result = real_read(*args, **kwargs)
            host_clock.advance_ms(FUNCTIONAL_RECOVERY_BUDGET_MS + 1)
            return result

        with patch("ei.operation_runtime.time", new=host_time):
            with patch("ei.capture_recovery.time", new=host_time):
                with patch("ei.capture_recovery._read_verified", side_effect=read_then_advance_host_clock):
                    result = self.recover()
        self.assertEqual(result.secured, 1, msg=self.recovery_diagnostic(result))
        self.assertEqual(len(list_queue_items(self.settings)), 1)
        self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])

    def test_deadline_after_real_source_read_does_not_advance_capture_or_cursor(self):
        clock = _ControlledMonotonicClock()
        controlled_time = _ControlledTimeProxy(clock)
        real_read = capture_recovery_module._read_verified

        def read_then_expire_budget(*args, **kwargs):
            result = real_read(*args, **kwargs)
            clock.advance_ms(FUNCTIONAL_RECOVERY_BUDGET_MS + 1)
            return result

        with patch("ei.operation_runtime.time", new=controlled_time):
            with patch("ei.capture_recovery.time", new=controlled_time):
                with patch("ei.capture_recovery._read_verified", side_effect=read_then_expire_budget):
                    result = recover_page(
                        self.settings,
                        self.source,
                        now=NOW,
                        max_ms=FUNCTIONAL_RECOVERY_BUDGET_MS,
                    )

        self.assertEqual(result.reason_code, "SOURCE_TIME_LIMIT", msg=self.recovery_diagnostic(result))
        self.assertEqual(result.scanned, 0)
        self.assertEqual(result.secured, 0)
        self.assertFalse(result.cursor_committed)
        cursor_files = list((self.settings.paths.local_state_dir / "capture-recovery").glob("*.json"))
        self.assertEqual(len(cursor_files), 1)
        cursor = json.loads(cursor_files[0].read_bytes())
        self.assertEqual(cursor["frontier"], [[self.path.name, "file"]])
        self.assertEqual(cursor["record_offset"], 0)
        self.assertEqual(cursor["file_version"], "")
        self.assertEqual(len(list_queue_items(self.settings)), 0)
        self.assertEqual(list(self.settings.paths.event_dir.rglob("*.json")), [])

    def test_live_other_process_excludes_recovery_until_its_handle_closes(self):
        script = (
            "import sys; from pathlib import Path; "
            "from tests.unattended_helpers import make_settings; "
            "from ei.ingest import source_coordination; "
            "lock=source_coordination(make_settings(Path(sys.argv[1]))); lock.__enter__(); "
            "print('locked',flush=True); sys.stdin.readline(); lock.__exit__(None,None,None)"
        )
        process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", "-c", script, str(self.root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        primary_failure = False
        try:
            if process.stdout.readline().strip() != "locked":
                self.fail("CAPTURE_LOCK_CHILD_READY_FAILED")
            result = recover_page(self.settings, self.source, now=NOW, max_ms=10000)
            if (result.secured, result.reason_code) != (0, "SOURCE_COORDINATION_UNAVAILABLE"):
                reason = result.reason_code
                reason = reason if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,47}", reason) else "UNKNOWN"
                secured = result.secured
                secured = str(secured) if type(secured) is int and 0 <= secured <= 999999 else "UNKNOWN"
                self.fail(f"CAPTURE_LOCK_RECOVERY_WHILE_HELD_FAILED_{reason}_{secured}")
            try:
                process.communicate("release\n", timeout=10)
            except subprocess.TimeoutExpired:
                self.fail("CAPTURE_LOCK_CHILD_RELEASE_TIMEOUT")
            if process.returncode != 0:
                self.fail("CAPTURE_LOCK_CHILD_EXIT_NONZERO")
            result = self.recover()
            if result.secured != 1:
                reason = result.reason_code
                reason = reason if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,47}", reason) else "UNKNOWN"
                secured = result.secured
                secured = str(secured) if type(secured) is int and 0 <= secured <= 999999 else "UNKNOWN"
                self.fail(f"CAPTURE_LOCK_RECOVERY_AFTER_RELEASE_FAILED_{reason}_{secured}")
        except BaseException:
            primary_failure = True
            raise
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
            except Exception:
                if not primary_failure:
                    self.fail("CAPTURE_LOCK_CHILD_CLEANUP_FAILED")
