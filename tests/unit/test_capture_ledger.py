import json
import multiprocessing
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.capture_contract import CaptureReceipt
from ei.capture_ledger import (
    CaptureLedgerError,
    _acquire,
    list_receipts,
    record_receipt,
    read_receipt,
    register_target,
)
from ei.capture_contract import capture_key
from ei.closeout_context import register_adapter_target
from ei.hooks.registry import normalize_hook_event
from ei.operation_runtime import OperationBudget
from tests.unattended_helpers import NOW, identity, make_settings


def _record_candidate(root: str, candidate_id: str, content_hash: str) -> None:
    settings = make_settings(Path(root))
    waiting = register_target(settings, identity(), now=NOW)
    record_receipt(
        settings,
        replace(
            waiting,
            state="SECURED",
            reason_code="CAPTURE_SECURED",
            candidate_ids=(candidate_id,),
            candidate_hashes=((candidate_id, content_hash),),
        ),
    )


class CaptureLedgerTests(unittest.TestCase):
    def test_unsupported_adapter_keeps_existing_waiting_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            target_identity = identity()
            before = register_target(settings, target_identity, now=NOW)
            event = normalize_hook_event(
                "codex-cli",
                {
                    "hook_event_name": "Stop",
                    "session_id": "fixture-session",
                    "turn_id": "fixture-turn",
                    "cwd": "C:/fixture",
                },
                settings,
            )
            event = replace(event, capture_identity=target_identity)

            self.assertFalse(
                register_adapter_target(
                    settings,
                    event,
                    now=NOW,
                    budget=OperationBudget(5000),
                )
            )
            after = read_receipt(settings, capture_key(target_identity))
            self.assertEqual(after, before)

    def test_replace_retry_stops_when_original_budget_expires(self):
        from ei.capture_ledger import _write_path
        from ei.safe_fs import SafeFilesystemError
        class ExpiringBudget:
            expired = False
            def check(self):
                if self.expired:
                    raise TimeoutError()
            def remaining_ms(self):
                return 0 if self.expired else 5000
        budget = ExpiringBudget()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "receipt.json"
            path.write_bytes(b"original")
            def failed_replace(*args, **kwargs):
                budget.expired = True
                raise SafeFilesystemError("SAFE_REPLACE_FAILED")
            with patch("ei.capture_ledger.safe_atomic_write", side_effect=failed_replace):
                with self.assertRaises(TimeoutError):
                    _write_path(root, path, b"replacement", budget=budget)
            self.assertEqual(path.read_bytes(), b"original")

    def test_contended_capture_lock_obeys_remaining_budget(self):
        from ei.operation_runtime import OperationBudget
        from ei.capture_ledger import _release
        import time
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            descriptor = _acquire(root)
            try:
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    _acquire(root, budget=OperationBudget(30))
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue((root / ".capture.lock").exists())
            finally:
                _release(root, descriptor)

    def test_expired_caller_budget_does_not_create_lock(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(TimeoutError):
                _acquire(root, budget=OperationBudget(0))
            self.assertEqual(list(root.iterdir()), [])

    def test_lock_permission_error_fails_promptly_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / ".capture.lock"
            with (
                patch("ei.capture_ledger._lock_path", return_value=lock),
                patch("ei.capture_ledger.os.open", side_effect=PermissionError("denied")) as opened,
                patch.object(Path, "exists", return_value=False),
                patch("ei.capture_ledger.time.sleep", side_effect=AssertionError("permission retry")),
            ):
                with self.assertRaisesRegex(CaptureLedgerError, "^CAPTURE_LOCK_PERMISSION_DENIED$"):
                    _acquire(root)

            self.assertEqual(opened.call_count, 1)

    def test_lock_stat_retry_obeys_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / ".capture.lock"
            with (
                patch("ei.capture_ledger._lock_path", return_value=lock),
                patch("ei.capture_ledger.os.open", side_effect=FileExistsError("busy")),
                patch.object(Path, "exists", return_value=True),
                patch.object(Path, "stat", side_effect=[OSError("transient"), AssertionError("unbounded retry")]),
                patch("ei.capture_ledger.time.monotonic", side_effect=[0.0, 6.0]),
            ):
                with self.assertRaisesRegex(CaptureLedgerError, "^CAPTURE_LOCK_TIMEOUT$"):
                    _acquire(root)

    def test_late_hook_does_not_erase_secured_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            secured = replace(waiting, state="SECURED", candidate_ids=("queue_" + "1" * 32,))
            record_receipt(settings, secured)
            register_target(settings, identity(), now=NOW)
            self.assertEqual(read_receipt(settings, waiting.capture_id).state, "SECURED")

    def test_unknown_identity_gets_local_receipt_without_coverage_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            first = register_target(settings, replace(identity(), record_hash=None), now=NOW)
            second = register_target(settings, replace(identity(), record_hash=None), now=NOW)

            self.assertEqual(first.state, "UNKNOWN")
            self.assertEqual(first.reason_code, "LEGACY_EVIDENCE_UNKNOWN")
            self.assertEqual(first.covered_target_ids, ())
            self.assertNotEqual(first.capture_id, second.capture_id)
            self.assertEqual({item.capture_id for item in list_receipts(settings)}, {first.capture_id, second.capture_id})

    def test_missing_identity_object_gets_fresh_uncorrelated_unknown_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))

            first = register_target(settings, None, now=NOW)
            second = register_target(settings, None, now=NOW)

            self.assertEqual(first.state, "UNKNOWN")
            self.assertEqual(first.covered_target_ids, ())
            self.assertEqual(first.candidate_ids, ())
            self.assertNotEqual(first.capture_id, second.capture_id)

    def test_same_session_multiple_turns_are_distinct_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            first = register_target(settings, identity("a"), now=NOW)
            second_identity = replace(
                identity("b"),
                turn_hash="sha256:" + "7" * 64,
            )
            second = register_target(settings, second_identity, now=NOW)

            self.assertNotEqual(first.capture_id, second.capture_id)
            self.assertEqual(len(list_receipts(settings)), 2)

    def test_unknown_legacy_receipt_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            unknown = register_target(settings, replace(identity(), record_hash=None), now=NOW)

            result = record_receipt(
                settings,
                replace(
                    unknown,
                    state="EVALUATED_NONE",
                    reason_code="EXPLICITLY_EVALUATED_NONE",
                ),
            )

            self.assertEqual(result, unknown)
            self.assertEqual(read_receipt(settings, unknown.capture_id), unknown)

    def test_candidate_hash_conflict_is_rejected_without_changing_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            candidate_id = "queue_" + "2" * 32
            first = replace(
                waiting,
                state="SECURED",
                reason_code="CAPTURE_SECURED",
                candidate_ids=(candidate_id,),
                candidate_hashes=((candidate_id, "sha256:" + "a" * 64),),
            )
            record_receipt(settings, first)

            with self.assertRaisesRegex(ValueError, "^CAPTURE_CONTENT_CONFLICT$"):
                record_receipt(
                    settings,
                    replace(first, candidate_hashes=((candidate_id, "sha256:" + "b" * 64),)),
                )

            self.assertEqual(read_receipt(settings, waiting.capture_id).candidate_hashes, first.candidate_hashes)

    def test_partial_candidate_hashes_merge_with_real_candidate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            queue_id = "queue_" + "3" * 32
            event_id = "evt_20260918T000000000000Z_aaaaaaaaaaaa"

            record_receipt(
                settings,
                replace(
                    waiting,
                    state="SECURED",
                    reason_code="CAPTURE_SECURED",
                    candidate_ids=(queue_id,),
                    candidate_hashes=((queue_id, "sha256:" + "c" * 64),),
                ),
            )
            merged = record_receipt(
                settings,
                replace(
                    waiting,
                    state="SECURED",
                    reason_code="CAPTURE_SECURED",
                    candidate_ids=(event_id,),
                    candidate_hashes=(),
                ),
            )

            self.assertEqual(merged.candidate_ids, tuple(sorted((queue_id, event_id))))
            self.assertEqual(merged.candidate_hashes, ((queue_id, "sha256:" + "c" * 64),))

    def test_curator_candidate_ids_accept_only_stable_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            candidate_id = "cand_" + "a" * 20
            secured = record_receipt(
                settings,
                replace(
                    waiting,
                    state="SECURED",
                    reason_code="CAPTURE_SECURED",
                    candidate_ids=(candidate_id,),
                    candidate_hashes=((candidate_id, "sha256:" + "b" * 64),),
                ),
            )
            self.assertEqual(read_receipt(settings, waiting.capture_id).candidate_ids, (candidate_id,))
            self.assertIn(candidate_id, secured.candidate_ids)
            for malformed in ("cand_" + "a" * 19, "cand_" + "A" * 20):
                with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    ValueError, "^EVENT_SCHEMA_INVALID:capture-receipt.candidate_ids$"
                ):
                    record_receipt(
                        settings,
                        replace(
                            waiting,
                            state="SECURED",
                            reason_code="CAPTURE_SECURED",
                            candidate_ids=(malformed,),
                        ),
                    )

    def test_pending_expiry_wins_over_later_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            waiting = register_target(settings, identity(), now=NOW)
            expired = replace(waiting, state="UNAVAILABLE", reason_code="PENDING_EXPIRED")
            record_receipt(settings, expired)

            merged = record_receipt(
                settings,
                replace(
                    waiting,
                    state="SECURED",
                    reason_code="CAPTURE_SECURED",
                    candidate_ids=("queue_" + "4" * 32,),
                ),
            )

            self.assertEqual(merged.state, "UNAVAILABLE")
            self.assertEqual(merged.reason_code, "PENDING_EXPIRED")

    def test_two_processes_merge_candidates_without_lost_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            target = register_target(settings, identity(), now=NOW)
            ctx = multiprocessing.get_context("spawn")
            workers = (
                ctx.Process(target=_record_candidate, args=(tmp, "queue_" + "5" * 32, "sha256:" + "d" * 64)),
                ctx.Process(target=_record_candidate, args=(tmp, "queue_" + "6" * 32, "sha256:" + "e" * 64)),
            )
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
            for worker in workers:
                self.assertEqual(worker.exitcode, 0)

            receipt = read_receipt(settings, target.capture_id)
            self.assertEqual(receipt.candidate_ids, tuple(sorted(("queue_" + "5" * 32, "queue_" + "6" * 32))))
            self.assertEqual(len(receipt.candidate_hashes), 2)

    def test_semantically_invalid_receipt_file_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            receipt = register_target(settings, identity(), now=NOW)
            path = settings.paths.runtime_dir / "state" / "capture" / f"{receipt.capture_id.removeprefix('sha256:')}.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["state"] = "SECURED"
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(CaptureLedgerError, "^CAPTURE_RECEIPT_CORRUPT$"):
                read_receipt(settings, receipt.capture_id)


if __name__ == "__main__":
    unittest.main()
