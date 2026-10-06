import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.adapters.base import SourceRecord
from ei.capture import reconcile_fallback, record_agent_observation
from ei.capture_ledger import CaptureLedgerError, list_receipts, register_target
from ei.config import load_settings
from ei.hook_entry import handle_normalized_hook, normalize_hook_event
from ei.ids import fingerprint
from ei.journal import iter_events
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory
from ei.key_provider import InMemoryKeyProvider
from ei.models import CaptureContext, ObservationInput
from tests.unattended_helpers import NOW, identity, make_settings


class CaptureFallbackTests(unittest.TestCase):
    def test_lock_permission_failure_is_fail_open_without_success_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            event = replace(
                normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                    settings,
                ),
                capture_identity=identity(),
            )

            with patch(
                "ei.hook_entry.register_target",
                side_effect=CaptureLedgerError("CAPTURE_LOCK_PERMISSION_DENIED"),
            ):
                result = handle_normalized_hook(event, settings)

            self.assertTrue(result.continue_work)
            self.assertIsNone(result.receipt_id)
            self.assertEqual(result.status, "CAPTURE_LEDGER_FAILED")
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), ())

    def test_native_observation_missing_from_direct_capture_is_attributable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            settings = load_settings(root, codex_home=root / "codex")
            record = SourceRecord(
                "codex_memory", "memory.md", "hash-1", "2026-08-25T00:00:00+00:00", "native",
                "別経路から発見した再利用可能な判断知識", "project-a", "general", "success",
                "reduced_rework", "private-reusable", provenance_key="memory:hash-1",
                source_host_id="codex-cli", source_host_family="codex-compatible",
            )
            result = reconcile_fallback(settings, [], [record])
            self.assertEqual(result.recovered, 1)
            self.assertEqual(result.coverage_unknown, False)
            self.assertIn("capture.fallback_recovered", [event.event_type for event in iter_events(settings.paths.event_dir)])

    def test_trusted_metadata_hook_registers_waiting_target_without_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(make_settings(Path(tmp)), stop_budget_ms=5000)
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                settings,
            )
            event = replace(event, capture_identity=identity())

            result = handle_normalized_hook(event, settings)
            receipt = list_receipts(settings)[0]

            self.assertEqual(result.status, "ok")
            self.assertEqual(receipt.state, "WAITING")
            self.assertEqual(receipt.candidate_ids, ())
            self.assertEqual(receipt.candidate_hashes, ())
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), ())

    def test_late_metadata_hook_preserves_actual_secured_candidate_without_queue_attachment(self):
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("late-hook-test", b"l" * 32)):
            settings = replace(make_settings(Path(tmp)), stop_budget_ms=5000)
            capture_identity = replace(identity(), session_hash=fingerprint("s1"), turn_hash=fingerprint("t1"))
            observation = ObservationInput(
                "durable candidate",
                "本文を持つ直接観測だけを実候補として受付へ関連付ける検証済み判断です",
                "agent_direct",
                "source-a",
                "C:/work/a",
                "domain-a",
                "success",
                "reduced_rework",
                "private-reusable",
                source_host_id="codex-cli",
                source_host_family="codex-compatible",
            )
            context = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible", capture_identity)
            direct = record_agent_observation(observation, context, settings)
            self.assertTrue(direct.created, direct)
            before = list_receipts(settings)[0]
            queue_before = tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_"))
            self.assertEqual(len(queue_before), 1)
            event = replace(
                normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work/a"},
                    settings,
                ),
                capture_identity=capture_identity,
            )

            result = handle_normalized_hook(event, settings)
            after = list_receipts(settings)[0]

            self.assertTrue(direct.created)
            self.assertEqual(result.status, "ok")
            self.assertEqual(after.state, "SECURED")
            self.assertEqual(after.candidate_ids, (direct.event_id,))
            self.assertEqual(after.candidate_hashes, before.candidate_hashes)
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), queue_before)

    def test_legacy_hook_without_identity_records_unlinked_unknown_without_empty_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(make_settings(Path(tmp)), stop_budget_ms=5000)
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                settings,
            )

            result = handle_normalized_hook(event, settings)

            self.assertEqual(result.status, "ok")
            receipts = list_receipts(settings)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0].state, "UNKNOWN")
            self.assertEqual(receipts[0].covered_target_ids, ())
            self.assertEqual(receipts[0].candidate_ids, ())
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), ())

    def test_receipt_write_failure_returns_fail_open_without_success_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            capture_root = settings.paths.runtime_dir / "state" / "capture"
            capture_root.parent.mkdir(parents=True)
            capture_root.write_text("not-a-directory", encoding="utf-8")
            event = replace(
                normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                    settings,
                ),
                capture_identity=identity(),
            )

            result = handle_normalized_hook(event, settings)

            self.assertTrue(result.continue_work)
            self.assertIsNone(result.receipt_id)
            self.assertEqual(result.status, "CAPTURE_LEDGER_FAILED")
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), ())

    def test_corrupt_receipt_returns_fail_open_without_success_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            receipt = register_target(settings, identity(), now=NOW)
            path = settings.paths.runtime_dir / "state" / "capture" / f"{receipt.capture_id.removeprefix('sha256:')}.json"
            path.write_text("{}", encoding="utf-8")
            event = replace(
                normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                    settings,
                ),
                capture_identity=identity(),
            )

            result = handle_normalized_hook(event, settings)

            self.assertTrue(result.continue_work)
            self.assertIsNone(result.receipt_id)
            self.assertEqual(result.status, "CAPTURE_LEDGER_FAILED")
            self.assertEqual(tuple(runtime_inventory(settings.paths.queue_dir, prefix="queue_")), ())

    def test_untrusted_capture_identity_is_rejected_before_receipt_attachment(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            event = replace(
                normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
                    settings,
                ),
                capture_identity=replace(identity(), store_id="C:/untrusted"),
            )

            result = handle_normalized_hook(event, settings)

            self.assertTrue(result.continue_work)
            self.assertIsNone(result.receipt_id)
            self.assertEqual(result.status, "CAPTURE_ID_INVALID")
            self.assertEqual(list_receipts(settings), ())
            self.assertFalse((settings.paths.runtime_dir / "hook-receipts.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
