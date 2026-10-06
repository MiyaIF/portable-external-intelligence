import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.capture import record_agent_observation, select_capture_path
from ei.capture_contract import capture_key
from ei.capture_ledger import read_receipt
from ei.dedup import normalize_claim
from ei.ids import fingerprint, stable_hash
from ei.journal import append_event, iter_events
from ei.models import CaptureContext, Event, ObservationInput
from tests.helpers import make_hook_settings
from tests.unattended_helpers import identity


class CaptureTests(unittest.TestCase):
    def _skill(self, settings, number, *, session="skill-session", trusted=True):
        item = ObservationInput(f"Skill {number}", "再利用する判断は保存後に対象の結果を読み直して検証する", "agent_direct",
            "structured-skill", "", "general", "success", "reduced_rework", "private-reusable",
            source_host_id="codex-cli", source_host_family="codex-compatible")
        target = replace(identity(format(number, "x")), session_hash=fingerprint(session), turn_hash=fingerprint(str(number)))
        context = CaptureContext(session, str(number), min(number, 3), "codex-cli", "codex-compatible", target if trusted else None)
        return item, context

    def test_trusted_skill_fourth_is_limited_but_full_session_replay_is_safe(self):
        from ei.key_provider import InMemoryKeyProvider
        from ei.queue import list_queue_items
        from tests.unattended_helpers import make_settings
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            results = [record_agent_observation(*self._skill(settings, n), settings) for n in range(1, 5)]
            self.assertEqual([result.created for result in results], [True, True, True, False])
            self.assertEqual(results[3].reason_code, "SESSION_CAPTURE_LIMIT")
            replay = record_agent_observation(*self._skill(settings, 1), settings)
            self.assertFalse(replay.created)
            self.assertEqual(replay.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(replay.event_id, results[0].event_id)
            self.assertEqual(len(list_queue_items(settings)), 3)

    def test_skill_legacy_and_pending_share_limit_and_concurrent_last_slot(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from ei.key_provider import InMemoryKeyProvider
        from ei.queue import list_queue_items
        from tests.unattended_helpers import make_settings
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            self.assertTrue(record_agent_observation(*self._skill(settings, 1, trusted=False), settings).created)
            self.assertTrue(record_agent_observation(*self._skill(settings, 2), settings).created)
            barrier = Barrier(2)
            def accept(number):
                barrier.wait(timeout=5)
                return record_agent_observation(*self._skill(settings, number), settings)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(accept, (3, 4)))
            self.assertEqual(sum(result.created for result in results), 1)
            self.assertEqual([result.reason_code for result in results].count("SESSION_CAPTURE_LIMIT"), 1)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)
            self.assertEqual(len(list_queue_items(settings)), 2)

    def test_unknown_pending_origin_blocks_only_its_session_and_native_is_independent(self):
        from ei.key_provider import InMemoryKeyProvider
        from ei.pending_capture import accept_candidate
        from ei.queue import list_queue_items
        from tests.unattended_helpers import NOW, make_settings
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            item, context = self._skill(settings, 1)
            self.assertEqual(accept_candidate(settings, context.capture_identity, item, now=NOW).state, "SECURED")
            blocked = record_agent_observation(*self._skill(settings, 2), settings)
            self.assertFalse(blocked.created)
            self.assertEqual(blocked.reason_code, "SESSION_CAPTURE_HISTORY_UNKNOWN")
            self.assertTrue(record_agent_observation(*self._skill(settings, 2, session="unrelated"), settings).created)
            for n in range(3, 7):
                item, context = self._skill(settings, n)
                self.assertEqual(accept_candidate(settings, context.capture_identity, item, now=NOW, origin="NATIVE_SOURCE").state, "SECURED")
            self.assertEqual(len(list_queue_items(settings)), 6)

    def test_skill_terminal_expired_and_prepared_reservations_keep_session_slots(self):
        from datetime import datetime, timedelta, timezone
        from ei.key_provider import InMemoryKeyProvider
        from ei.operation_runtime import OperationBudget
        from ei.pending_capture import reconcile_pending
        from ei.queue import QueueState, list_queue_items, transition_queue_item
        from ei.spool import SpoolError, delete_spool
        from tests.unattended_helpers import make_settings
        for mode in ("terminal", "expired", "prepared"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
                settings = make_settings(Path(tmp))
                for n in range(1, 4):
                    if mode == "prepared":
                        with patch("ei.pending_capture.write_spool", side_effect=SpoolError("failed")):
                            self.assertFalse(record_agent_observation(*self._skill(settings, n), settings).created)
                    else:
                        result = record_agent_observation(*self._skill(settings, n), settings, budget=OperationBudget(20000))
                        self.assertTrue(result.created, repr(result))
                if mode == "terminal":
                    for n, item in enumerate(list_queue_items(settings)):
                        if n % 2:
                            updating = transition_queue_item(item, QueueState.YES_CURATING, settings)
                            transition_queue_item(updating, QueueState.DONE, settings)
                        else:
                            transition_queue_item(item, QueueState.NO_DISCARDED, settings)
                        delete_spool(item.payload_ref, settings)
                elif mode == "expired":
                    result = reconcile_pending(settings, now=datetime.now(timezone.utc) + timedelta(days=31))
                    self.assertEqual(result["expired"], 3)
                else:
                    self.assertEqual(list_queue_items(settings), ())
                blocked = record_agent_observation(*self._skill(settings, 4), settings)
                self.assertEqual(blocked.reason_code, "SESSION_CAPTURE_LIMIT")
                replay = record_agent_observation(*self._skill(settings, 1), settings)
                self.assertEqual(replay.created, mode == "prepared")
                self.assertNotEqual(replay.reason_code, "SESSION_CAPTURE_LIMIT")

    def test_skill_legacy_event_and_same_pending_key_are_not_counted_twice(self):
        import json
        from ei.key_provider import InMemoryKeyProvider
        from tests.unattended_helpers import make_settings
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            item, context = self._skill(settings, 1)
            self.assertTrue(record_agent_observation(item, context, settings).created)
            path = next((settings.paths.runtime_dir / "state" / "capture" / "intents").rglob("pending_*.json"))
            agent_key = json.loads(path.read_text(encoding="utf-8"))["admission"]["agent_key"]
            self._append_legacy_direct_event(settings, item, context, key=agent_key)
            for n in (2, 3):
                self.assertTrue(record_agent_observation(*self._skill(settings, n), settings).created)
            self.assertEqual(record_agent_observation(*self._skill(settings, 4), settings).reason_code, "SESSION_CAPTURE_LIMIT")

    def test_duplicate_legacy_event_key_uses_one_session_slot(self):
        from ei.key_provider import InMemoryKeyProvider
        from ei.operation_runtime import OperationBudget
        from tests.unattended_helpers import make_settings

        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            item, context = self._skill(settings, 1)
            for _ in range(3):
                self._append_legacy_direct_event(settings, item, context)
            for number in (2, 3):
                result = record_agent_observation(*self._skill(settings, number), settings, budget=OperationBudget(20000))
                self.assertTrue(result.created, repr(result))
            self.assertEqual(record_agent_observation(*self._skill(settings, 4), settings).reason_code, "SESSION_CAPTURE_LIMIT")

    def test_same_skill_key_reuses_original_target_without_new_body_or_coverage(self):
        from ei.key_provider import InMemoryKeyProvider
        from ei.queue import QueueState, list_queue_items, transition_queue_item
        from ei.spool import SpoolError
        from tests.unattended_helpers import make_settings
        for state in ("ready", "terminal", "prepared"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
                settings = make_settings(Path(tmp))
                item, context = self._skill(settings, 1)
                if state == "prepared":
                    with patch("ei.pending_capture.write_spool", side_effect=SpoolError("failed")):
                        original = record_agent_observation(item, context, settings)
                else:
                    original = record_agent_observation(item, context, settings)
                    self.assertTrue(original.created)
                    if state == "terminal":
                        transition_queue_item(list_queue_items(settings)[0], QueueState.NO_DISCARDED, settings)
                changed_item = replace(item, title="changed title only", source_ref="other-source-ref")
                changed_context = replace(context, capture_identity=replace(context.capture_identity, record_hash=fingerprint("changed title")))
                intent_root = settings.paths.runtime_dir / "state" / "capture" / "intents"
                before = {path: path.read_bytes() for path in intent_root.rglob("pending_*.json")}
                spool_before = {path: path.read_bytes() for path in settings.paths.spool_dir.rglob("pending_*") if path.is_file()}
                replay = record_agent_observation(changed_item, changed_context, settings)
                self.assertFalse(replay.created)
                self.assertEqual(len(list_queue_items(settings)), 0 if state == "prepared" else 1)
                self.assertEqual({path: path.read_bytes() for path in intent_root.rglob("pending_*.json")}, before)
                self.assertEqual({path: path.read_bytes() for path in settings.paths.spool_dir.rglob("pending_*") if path.is_file()}, spool_before)
                self.assertIsNone(read_receipt(settings, capture_key(changed_context.capture_identity)))
                if state != "prepared":
                    self.assertEqual(replay.event_id, original.event_id)
                    self.assertEqual(replay.reason_code, "IDEMPOTENT_REPLAY")
                else:
                    self.assertTrue(record_agent_observation(item, context, settings).created)

    def test_skill_partial_or_mismatched_tag_does_not_ack_and_session_identity_is_checked(self):
        import sqlite3
        from contextlib import closing
        from ei.key_provider import InMemoryKeyProvider
        from ei.operation_runtime import OperationBudget
        from ei.runtime_catalog import RuntimeCatalog
        from tests.unattended_helpers import make_settings
        with tempfile.TemporaryDirectory() as tmp, patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"s" * 32)):
            settings = make_settings(Path(tmp))
            item, context = self._skill(settings, 1)
            mismatched = replace(context, capture_identity=replace(context.capture_identity, session_hash=fingerprint("different")))
            self.assertEqual(record_agent_observation(item, mismatched, settings).reason_code, "CAPTURE_INPUT_INVALID")
            self.assertEqual(list(Path(tmp).iterdir()), [])
            self.assertTrue(record_agent_observation(item, context, settings).created)
            budget = OperationBudget(5000)
            original = RuntimeCatalog.tagged_paths
            def timeout(catalog, *args, **kwargs):
                budget.deadline = 0
                return original(catalog, *args, **kwargs)
            with patch.object(RuntimeCatalog, "tagged_paths", timeout):
                denied = record_agent_observation(*self._skill(settings, 2), settings, budget=budget)
            self.assertEqual(denied.reason_code, "CAPTURE_BUDGET_EXHAUSTED")
            root = settings.paths.runtime_dir / "state" / "capture" / "intents"
            with closing(sqlite3.connect(root / ".runtime-catalog.sqlite")) as connection:
                connection.execute("UPDATE entries SET tag=?", ("AGENT_SKILL:" + fingerprint("different"),))
                connection.commit()
            # A returned index entry whose actual metadata is another session
            # cannot establish a count or grant admission.
            denied = record_agent_observation(*self._skill(settings, 2, session="different"), settings)
            self.assertFalse(denied.created)
            self.assertEqual(denied.reason_code, "SESSION_CAPTURE_HISTORY_UNKNOWN")
            with closing(sqlite3.connect(root / ".runtime-catalog.sqlite")) as connection:
                connection.execute("UPDATE entries SET tag=''")
                connection.commit()
            before = {path: path.read_bytes() for path in root.rglob("pending_*.json")}
            denied = record_agent_observation(*self._skill(settings, 2), settings)
            self.assertEqual(denied.reason_code, "SESSION_CAPTURE_HISTORY_UNKNOWN")
            self.assertEqual(before, {path: path.read_bytes() for path in root.rglob("pending_*.json")})

    def test_deferred_capture_diagnostic_uses_remaining_budget(self):
        from ei.capture import _record_deferred
        from ei.operation_runtime import OperationBudget
        from tests.unattended_helpers import make_settings
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            configured = make_settings(Path(tmp))
            budget = OperationBudget(0)
            with self.assertRaises(TimeoutError):
                _record_deferred(configured, "CAPTURE_DEFERRED", "OSError", budget=budget)
            self.assertEqual(list(Path(tmp).iterdir()), [])
            budget = OperationBudget(5000)
            with patch("ei.measurement_events._append_log_line") as append:
                _record_deferred(configured, "CAPTURE_DEFERRED", "OSError", budget=budget)
            self.assertIs(append.call_args.kwargs["budget"], budget)

    @staticmethod
    def _append_legacy_direct_event(settings, observation, context, *, include_scope=True, key=None):
        source_host_id = observation.source_host_id or context.source_host_id
        source_host_family = observation.source_host_family or context.source_host_family
        legacy_key = stable_hash("\0".join((
            context.session_id,
            context.turn_id,
            normalize_claim(observation.claim),
            source_host_id,
            source_host_family,
            "agent-direct-v1",
        )))
        payload = {
            "observation_id": "obs_legacy",
            "title": observation.title,
            "claim": observation.claim,
            "source_kind": "agent_direct",
            "source_ref_hash": fingerprint(observation.source_ref),
            "source_hash": "",
            "outcome_status": observation.outcome_status,
            "benefit": observation.benefit,
            "classification": observation.classification,
            "applicability": list(observation.applicability),
            "capture_path": "agent_direct",
            "capture_idempotency_key": key or legacy_key,
            "session_id_hash": fingerprint(context.session_id),
            "turn_id_hash": fingerprint(context.turn_id),
            "capture_index": context.capture_index,
            "source_host_id": source_host_id,
            "source_host_family": source_host_family,
            "applicability_scope": "host",
            "applicable_host_ids": [source_host_id],
            "applicable_host_families": [],
        }
        if include_scope:
            payload["cwd_fingerprint"] = fingerprint(observation.cwd)
            payload["domain"] = observation.domain
        event = Event.create(
            "observation.recorded",
            "2026-09-18T00:00:00+00:00",
            "agent_direct",
            "legacy-machine",
            payload,
        )
        return event, append_event(event, settings.paths.event_dir)

    def test_same_turn_and_claim_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            observation = ObservationInput("書込後の再読込", "外部書込後は対象範囲を再読込して数式と値を検証する", "agent_direct", "session-local", "C:/work/project-a", "spreadsheet-operations", "success", "avoided_failure", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            context = CaptureContext(session_id="s1", turn_id="t9", capture_index=1, source_host_id="codex-cli", source_host_family="codex-compatible")
            first = record_agent_observation(observation, context, settings)
            second = record_agent_observation(observation, context, settings)
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(second.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)

    def test_receipt_association_failure_is_incomplete_and_replay_repairs_without_duplicate_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            observation = ObservationInput("receipt retry", "永続eventの受付関連付けが失敗した場合は再試行で同じeventを修復する", "agent_direct", "source-a", "C:/work/a", "general", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            context = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible", replace(identity(), session_hash=fingerprint("s1")))
            legacy_event, legacy_path = self._append_legacy_direct_event(settings, observation, context)
            legacy_bytes = legacy_path.read_bytes()

            with patch("ei.capture.record_receipt", side_effect=OSError("disk unavailable")):
                first = record_agent_observation(observation, context, settings)
                retry_failed = record_agent_observation(observation, context, settings)

            self.assertFalse(first.created)
            self.assertEqual(first.reason_code, "CAPTURE_RECEIPT_DEFERRED")
            self.assertFalse(retry_failed.created)
            self.assertEqual(retry_failed.reason_code, "CAPTURE_RECEIPT_DEFERRED")
            self.assertEqual(retry_failed.event_id, first.event_id)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)
            waiting = read_receipt(settings, capture_key(context.capture_identity))
            self.assertEqual(waiting.state, "WAITING")
            self.assertEqual(waiting.candidate_ids, ())

            repaired = record_agent_observation(observation, context, settings)

            self.assertFalse(repaired.created)
            self.assertEqual(repaired.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(repaired.event_id, first.event_id)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)
            secured = read_receipt(settings, capture_key(context.capture_identity))
            self.assertEqual(secured.state, "SECURED")
            self.assertEqual(secured.candidate_ids, (first.event_id,))
            self.assertEqual(first.event_id, legacy_event.event_id)
            self.assertEqual(legacy_path.read_bytes(), legacy_bytes)

    def test_host_capture_order_is_respected_and_unknown_is_not_no(self):
        class Host:
            capture_order = ("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE")

        self.assertEqual(select_capture_path(Host(), {"NATIVE_SOURCE": True, "HOOK_DIRECT": True}), "HOOK_DIRECT")
        self.assertEqual(select_capture_path(Host(), {"AGENT_SKILL": True}), "AGENT_SKILL")
        self.assertEqual(select_capture_path(Host(), {}), "capture_coverage_unknown")
    def test_fourth_observation_hits_session_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            for index in range(1, 5):
                observation = ObservationInput(f"title-{index}", "これは20文字以上の再利用可能な検証済み判断知識です", "agent_direct", "session-local", "C:/work", "general", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
                result = record_agent_observation(observation, CaptureContext("s1", f"t{index}", min(index, 3), "codex-cli", "codex-compatible"), settings)
                if index == 4:
                    self.assertFalse(result.created)
                    self.assertEqual(result.reason_code, "SESSION_CAPTURE_LIMIT")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 3)

    def test_same_claim_in_different_scopes_creates_distinct_observations_and_receipts(self):
        from tests.unattended_helpers import make_settings
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            context_a = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible", replace(identity("a"), session_hash=fingerprint("s1")))
            context_b = CaptureContext("s1", "t1", 2, "codex-cli", "codex-compatible", replace(identity("b"), session_hash=fingerprint("s1"), store_id="sha256:" + "6" * 64))
            first = ObservationInput("scope a", "同じ本文でも適用範囲が異なれば別候補として安全に追跡する", "agent_direct", "source-a", "C:/work/a", "domain-a", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            second = replace(first, title="scope b", source_ref="source-b", cwd="C:/work/b", domain="domain-b")

            from ei.key_provider import InMemoryKeyProvider
            from ei.queue import list_queue_items
            from ei.spool import read_spool
            import json
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("test", b"t" * 32)):
                result_a = record_agent_observation(first, context_a, settings, budget=OperationBudget(20000))
                self.assertTrue(result_a.created, repr(result_a))
                result_b = record_agent_observation(second, context_b, settings, budget=OperationBudget(20000))
                self.assertTrue(result_b.created, repr(result_b))
                items = list_queue_items(settings)
                self.assertEqual(len(items), 2)
                self.assertEqual({item.capture_id for item in items}, {capture_key(context_a.capture_identity), capture_key(context_b.capture_identity)})
                self.assertEqual(len({item.payload_ref.spool_id for item in items}), 2)
                claims = [json.loads(read_spool(item.payload_ref, settings, expected_capture_id=item.capture_id)) for item in items]
                self.assertEqual({value["domain"] for value in claims}, {"domain-a", "domain-b"})
            self.assertFalse(settings.paths.event_dir.exists())

            self.assertTrue(result_a.created)
            self.assertTrue(result_b.created)
            self.assertNotEqual(result_a.event_id, result_b.event_id)
            self.assertEqual(read_receipt(settings, capture_key(context_a.capture_identity)).candidate_ids, (result_a.event_id,))
            self.assertEqual(read_receipt(settings, capture_key(context_b.capture_identity)).candidate_ids, (result_b.event_id,))

    def test_matching_scope_replays_legacy_key_without_rewriting_old_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            context = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible")
            observation = ObservationInput("legacy", "旧キーでも同じ適用範囲の証拠があれば安全に再利用できる判断です", "agent_direct", "source-a", "C:/work/a", "domain-a", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            event, path = self._append_legacy_direct_event(settings, observation, context)
            before = path.read_bytes()

            result = record_agent_observation(observation, context, settings)

            self.assertFalse(result.created)
            self.assertEqual(result.event_id, event.event_id)
            self.assertEqual(result.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)

    def test_different_scope_does_not_replay_legacy_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            context = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible")
            first = ObservationInput("legacy", "旧キーでも同じ適用範囲の証拠があれば安全に再利用できる判断です", "agent_direct", "source-a", "C:/work/a", "domain-a", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            self._append_legacy_direct_event(settings, first, context)
            second = replace(first, cwd="C:/work/b", domain="domain-b")

            result = record_agent_observation(second, context, settings)

            self.assertTrue(result.created)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 2)

    def test_missing_scope_evidence_does_not_replay_legacy_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            context = CaptureContext("s1", "t1", 1, "codex-cli", "codex-compatible")
            observation = ObservationInput("legacy", "旧キーでも同じ適用範囲の証拠があれば安全に再利用できる判断です", "agent_direct", "source-a", "C:/work/a", "domain-a", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            self._append_legacy_direct_event(settings, observation, context, include_scope=False)

            result = record_agent_observation(observation, context, settings)

            self.assertTrue(result.created)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 2)


if __name__ == "__main__":
    unittest.main()
