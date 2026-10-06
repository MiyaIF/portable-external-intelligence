from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ei import closeout_association as association
from ei.capture_ledger import read_receipt
from ei.closeout_store import CloseoutStore
from ei.operation_runtime import OperationBudget
from ei.spool import SpoolError, SpoolRef, delete_spool
from tests.unit import test_closeout_association as closeout_test_helpers


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
CONTENT_HASH = "sha256:" + "b" * 64


class SimulatedPowerLoss(BaseException):
    pass


class CloseoutRecoveryIntegrationTests(unittest.TestCase):
    def _fixture(self):
        fixture, validation = closeout_test_helpers.CloseoutAssociationTests._validated_fixture(self, turns=3)
        changeset = closeout_test_helpers.CloseoutAssociationTests._yes_changeset(self, validation)
        prepared = association.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=closeout_test_helpers._explicit_team_disabled(),
        )
        return fixture, validation, prepared

    def _active(self, settings):
        budget = OperationBudget(10000)
        with association._capture_lock(settings, budget):
            return CloseoutStore(settings, budget=budget).active_records()

    def test_recovery_reapplies_prepared_spool_without_preparing_again(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0
        applied_references = []

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        original_apply = association.apply_changeset

        def apply_then_crash(*args, **kwargs):
            result = original_apply(*args, **kwargs)
            applied_references.append(result.application_ref)
            raise SimulatedPowerLoss

        with patch.object(association, "apply_changeset", side_effect=apply_then_crash):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARED")
        self.assertIsNone(active[0]["application_ref"])
        self.assertEqual(active[0]["witness"], [])
        self.assertEqual(len(applied_references), 1)
        self.assertIsNotNone(applied_references[0])
        self.assertEqual(prepare_calls, 1)
        record_id = active[0]["record_id"]

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "COMMITTED")
        self.assertEqual(prepare_calls, 1)
        self.assertEqual(self._active(fixture.settings), [])
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(fixture.settings, target_id).state, "SECURED")
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            terminal = CloseoutStore(fixture.settings, budget=budget).read_record(record_id)
        self.assertEqual(terminal["application_ref"]["marker_id"], applied_references[0].marker_id)
        saved_event_ids = tuple(item["event_id"] for item in terminal["witness"])
        replay = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("committed recovery replay prepared again"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(15000),
        )
        self.assertTrue(replay.acknowledged)
        self.assertEqual(replay.event_ids, saved_event_ids)

    def test_ref_saved_before_witness_preserves_requested_cache_and_original_hash(self):
        from ei.changeset import apply_changeset

        fixture, validation, base_prepared = self._fixture()
        original = base_prepared.changeset
        applied = apply_changeset(original, fixture.settings, budget=OperationBudget(30000))
        self.assertTrue(applied.applied, applied.reason_code)
        self.assertIsNotNone(applied.application_ref)
        original_hash = applied.application_ref.changeset_hash
        requested_time = (
            datetime.fromisoformat(original.generated_at.replace("Z", "+00:00")) + timedelta(minutes=1)
        ).isoformat().replace("+00:00", "Z")
        requested = replace(original, generated_at=requested_time)
        prepared = association.PreparedCloseout(
            candidate_id=requested.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=requested,
            team_prepared=closeout_test_helpers._explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_verify_yes", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(30000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        record = active[0]
        self.assertEqual(record["status"], "PREPARED")
        self.assertEqual(record["application_ref"]["changeset_hash"], original_hash)
        self.assertEqual(record["changeset_hash"], original_hash)
        _, cached = association._load_prepared(
            fixture.settings,
            dict(record),
            NOW,
            OperationBudget(10000),
        )
        self.assertIsNotNone(cached)
        self.assertEqual(cached.changeset.generated_at, requested.generated_at)
        self.assertEqual(cached.changeset.fingerprint, requested.fingerprint)

        resumed = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("saved cache was prepared again"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(30000),
        )
        self.assertEqual(prepare_calls, 1)
        self.assertTrue(resumed.acknowledged, repr(resumed))
        self.assertEqual(resumed.association, "COMMITTED")
        self.assertEqual(resumed.changeset_hash, original_hash)

    def test_witness_only_recovery_keeps_hash_but_does_not_ack_missing_team_decision(self):
        from ei.changeset import apply_changeset

        fixture, validation, base_prepared = self._fixture()
        original = base_prepared.changeset
        applied = apply_changeset(original, fixture.settings, budget=OperationBudget(30000))
        self.assertTrue(applied.applied, applied.reason_code)
        self.assertIsNotNone(applied.application_ref)
        original_hash = applied.application_ref.changeset_hash
        requested_time = (
            datetime.fromisoformat(original.generated_at.replace("Z", "+00:00")) + timedelta(minutes=1)
        ).isoformat().replace("+00:00", "Z")
        requested = replace(original, generated_at=requested_time)
        prepared = association.PreparedCloseout(
            candidate_id=requested.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=requested,
            team_prepared=closeout_test_helpers._explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_commit_closeout", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(30000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        record = active[0]
        self.assertEqual(record["status"], "APPLIED")
        self.assertTrue(record["witness"])
        self.assertEqual(record["changeset_hash"], original_hash)
        self.assertTrue(delete_spool(SpoolRef.from_dict(record["spool_ref"]), fixture.settings, budget=OperationBudget(10000)))

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )
        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "PENDING")
        self.assertEqual(prepare_calls, 1)
        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "COMMITTED")
        self.assertEqual(active[0]["changeset_hash"], original_hash)
        self.assertTrue(active[0]["witness"])
        self.assertEqual(active[0]["team_result"]["status"], "UNKNOWN")
        self.assertIsNotNone(active[0]["spool_ref"])

        replay = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("committed replay prepared again"),
            now=NOW.replace(minute=2),
            budget=OperationBudget(30000),
        )
        self.assertFalse(replay.acknowledged, repr(replay))
        self.assertEqual(replay.association, "PENDING")
        self.assertEqual(replay.team_result["status"], "UNKNOWN")
        self.assertEqual(replay.changeset_hash, original_hash)

    def test_recovery_revalidates_binding_after_cache_read_before_apply(self):
        from ei.journal import iter_events

        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_apply_prepared", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARED")
        target_id = validation.context.target_ids[0]
        binding_path = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{target_id.removeprefix('sha256:')}.json"
        )
        original_load = association._load_prepared

        def load_then_remove_binding(*args, **kwargs):
            loaded = original_load(*args, **kwargs)
            binding_path.unlink()
            return loaded

        with patch.object(association, "_load_prepared", side_effect=load_then_remove_binding):
            with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
                recovered = association.recover_closeout_associations(
                    fixture.settings,
                    now=NOW,
                    budget=OperationBudget(30000),
                )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(prepare_calls, 1)
        remaining = self._active(fixture.settings)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["status"], "PREPARED")
        self.assertIsNone(remaining[0]["application_ref"])
        self.assertEqual(remaining[0]["witness"], [])
        matching_events = [
            event for event in iter_events(fixture.settings.paths.event_dir)
            if isinstance(event.payload, dict) and event.payload.get("changeset_id") == prepared.changeset.changeset_id
        ]
        self.assertEqual(matching_events, [])

    def test_recovery_cursor_keeps_unknown_and_reaches_after_finished_record(self):
        from ei.closeout_context import validate_adapter_context

        fixture, first_validation = closeout_test_helpers.CloseoutAssociationTests._validated_fixture(self, turns=6)
        validations = [first_validation]
        for start in (2, 4):
            validation = validate_adapter_context(
                fixture.settings,
                fixture.host_id,
                fixture.control_for(fixture.events[start : start + 2]),
                budget=OperationBudget(10000),
            )
            self.assertTrue(validation.valid, validation.reason_code)
            validations.append(validation)

        ordered = sorted(
            (
                association._new_intent(
                    fixture.settings,
                    validation,
                    CONTENT_HASH,
                    NOW,
                    OperationBudget(10000),
                )["record_id"],
                validation,
            )
            for validation in validations
        )
        for index, (_, validation) in enumerate(ordered):
            prepared = association.PreparedCloseout(
                candidate_id=f"no_result_{index}",
                content_hash=CONTENT_HASH,
                decision="NO",
                changeset=None,
                team_prepared={
                    "schema_version": 1,
                    "status": "NOT_ELIGIBLE",
                    "reason_code": "TEAM_DISABLED",
                    "normalized_payload": None,
                    "team_store_id": "",
                    "team_member_id": "",
                    "writer_id": "",
                    "team_root_hash": None,
                    "actor_hash": None,
                    "machine_hash": None,
                    "prepared_at": NOW.isoformat().replace("+00:00", "Z"),
                },
            )
            with patch.object(association, "_commit_closeout", side_effect=SimulatedPowerLoss):
                with self.assertRaises(SimulatedPowerLoss):
                    association.apply_associated_closeout(
                        fixture.settings,
                        validation,
                        content_hash=CONTENT_HASH,
                        prepare=lambda prepared=prepared: prepared,
                        now=NOW,
                        budget=OperationBudget(15000),
                    )

        first_id, first_validation = ordered[0]
        other_targets = {
            target_id
            for _, validation in ordered[1:]
            for target_id in validation.context.target_ids
        }
        unique_targets = set(first_validation.context.target_ids) - other_targets
        self.assertTrue(unique_targets)
        lost_binding_target = sorted(unique_targets)[0]
        binding_path = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{lost_binding_target.removeprefix('sha256:')}.json"
        )
        binding_path.unlink()

        first = association.recover_closeout_associations(
            fixture.settings,
            now=NOW,
            budget=OperationBudget(30000),
            max_records=1,
        )
        self.assertEqual(first["processed"], 1)
        self.assertEqual(first["results"][0]["record_id"], first_id)
        self.assertEqual(first["results"][0]["association"], "UNKNOWN")

        second_id = ordered[1][0]
        second = association.recover_closeout_associations(
            fixture.settings,
            now=NOW,
            budget=OperationBudget(30000),
            max_records=1,
        )
        self.assertEqual(second["results"][0]["record_id"], second_id)
        self.assertEqual(second["results"][0]["association"], "COMMITTED")

        third_id = ordered[2][0]
        third = association.recover_closeout_associations(
            fixture.settings,
            now=NOW,
            budget=OperationBudget(30000),
            max_records=1,
        )
        self.assertEqual(third["results"][0]["record_id"], third_id)
        self.assertEqual(third["results"][0]["association"], "COMMITTED")

        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            store = CloseoutStore(fixture.settings, budget=budget)
            self.assertEqual(store.read_record(first_id)["status"], "PREPARED")
            self.assertEqual(store.read_record(second_id)["status"], "COMMITTED")
            self.assertEqual(store.read_record(third_id)["status"], "COMMITTED")
            self.assertEqual([item["record_id"] for item in store.active_records()], [first_id])

    def test_recovery_adopts_authenticated_spool_written_before_reference(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        original_write_record = CloseoutStore.write_record

        def crash_before_reference(store, record):
            if record.get("status") == "PREPARED":
                raise SimulatedPowerLoss
            return original_write_record(store, record)

        with patch.object(CloseoutStore, "write_record", autospec=True, side_effect=crash_before_reference):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARING")
        self.assertIsNone(active[0]["spool_ref"])
        from ei.spool import _root as spool_root, _safe_path as spool_path

        planned_spool = spool_path(spool_root(fixture.settings), active[0]["spool_id"], OperationBudget(10000))
        self.assertTrue(planned_spool.exists())

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "COMMITTED")
        self.assertEqual(prepare_calls, 1)
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(fixture.settings, target_id).state, "SECURED")

    def test_recovery_after_partial_event_append_creates_one_marker(self):
        from ei import changeset as changeset_module
        from ei.journal import iter_events

        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        original_append = changeset_module.append_event
        appended = 0

        def append_one_then_crash(event, event_dir, **kwargs):
            nonlocal appended
            result = original_append(event, event_dir, **kwargs)
            appended += 1
            if appended == 1:
                raise SimulatedPowerLoss
            return result

        with patch.object(changeset_module, "append_event", side_effect=append_one_then_crash):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARED")
        self.assertIsNone(active[0]["application_ref"])
        self.assertEqual(active[0]["witness"], [])
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id)
            self.assertEqual(receipt.state, "WAITING")
            self.assertEqual(receipt.closeout_proofs, ())

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "COMMITTED")
        self.assertEqual(prepare_calls, 1)
        events = [
            event
            for event in iter_events(fixture.settings.paths.event_dir)
            if isinstance(event.payload, dict) and event.payload.get("changeset_id") == prepared.changeset.changeset_id
        ]
        marker_events = [event for event in events if event.event_type == "curation.changeset.applied"]
        self.assertEqual(len(marker_events), 1)
        self.assertEqual(len(events), len(prepared.changeset.operations) + 1)
        self.assertEqual(len({event.event_id for event in events}), len(events))

    def test_recovery_finishes_receipts_after_first_receipt_crash(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        original_record = association._record_receipt_locked
        writes = 0

        def save_first_receipt_then_crash(root, receipt, *, budget=None):
            nonlocal writes
            saved = original_record(root, receipt, budget=budget)
            writes += 1
            if writes == 1:
                raise SimulatedPowerLoss
            return saved

        with patch.object(association, "_record_receipt_locked", side_effect=save_first_receipt_then_crash):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "APPLIED")
        stored = [read_receipt(fixture.settings, target_id) for target_id in validation.context.target_ids]
        self.assertEqual(sum(bool(receipt.closeout_proofs) for receipt in stored), 1)
        self.assertEqual(sum(receipt.state == "SECURED" for receipt in stored), 1)

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "COMMITTED")
        self.assertEqual(prepare_calls, 1)
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id)
            self.assertEqual(receipt.state, "SECURED")
            self.assertEqual(len(receipt.closeout_proofs), 1)

    def test_committed_and_ack_crashes_replay_from_compact_witness(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        original_write = CloseoutStore.write_record

        def save_committed_then_crash(store, record):
            saved = original_write(store, record)
            if record.get("status") == "COMMITTED":
                raise SimulatedPowerLoss
            return saved

        with patch.object(CloseoutStore, "write_record", autospec=True, side_effect=save_committed_then_crash):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        committed = self._active(fixture.settings)
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0]["status"], "COMMITTED")
        self.assertTrue(committed[0]["witness"])

        original_finish = CloseoutStore.finish

        def finish_then_crash(store, record):
            result = original_finish(store, record)
            raise SimulatedPowerLoss

        with patch.object(CloseoutStore, "finish", autospec=True, side_effect=finish_then_crash):
            with self.assertRaises(SimulatedPowerLoss):
                association.recover_closeout_associations(
                    fixture.settings,
                    now=NOW,
                    budget=OperationBudget(30000),
                )

        self.assertEqual(self._active(fixture.settings), [])
        replay = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("ACK replay prepared again"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(15000),
        )
        self.assertTrue(replay.acknowledged)
        self.assertEqual(replay.association, "COMMITTED")
        self.assertEqual(prepare_calls, 1)

    def test_recovery_uses_verified_witness_after_spool_loss(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_record_receipt_locked", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "APPLIED")
        self.assertGreaterEqual(len(active[0]["witness"]), 2)
        persisted_hash = active[0]["changeset_hash"]
        self.assertIsInstance(persisted_hash, str)
        self.assertIsNotNone(active[0]["spool_ref"])
        ref = SpoolRef.from_dict(active[0]["spool_ref"])
        self.assertTrue(delete_spool(ref, fixture.settings, budget=OperationBudget(10000)))

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(30000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "PENDING")
        self.assertEqual(prepare_calls, 1)
        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "COMMITTED")
        self.assertEqual(active[0]["team_result"]["status"], "UNKNOWN")
        self.assertEqual(active[0]["changeset_hash"], persisted_hash)
        self.assertEqual(active[0]["spool_ref"], ref.to_dict())
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(fixture.settings, target_id).state, "SECURED")

    def test_locator_without_witness_and_lost_spool_stays_pending(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_verify_yes", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARED")
        self.assertIsNotNone(active[0]["application_ref"])
        self.assertEqual(active[0]["witness"], [])
        self.assertTrue(delete_spool(SpoolRef.from_dict(active[0]["spool_ref"]), fixture.settings, budget=OperationBudget(10000)))

        with patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=NOW,
                budget=OperationBudget(20000),
            )

        self.assertEqual(recovered["processed"], 1)
        self.assertEqual(recovered["results"][0]["association"], "PENDING")
        self.assertEqual(recovered["results"][0]["reason_code"], "CLOSEOUT_CACHE_PENDING")
        self.assertEqual(prepare_calls, 1)
        retained = self._active(fixture.settings)[0]
        self.assertEqual(retained["status"], "PREPARED")
        self.assertIsNotNone(retained["application_ref"])
        self.assertEqual(retained["witness"], [])
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id)
            self.assertEqual(receipt.state, "WAITING")
            self.assertEqual(receipt.closeout_proofs, ())

        expired = association.recover_closeout_associations(
            fixture.settings,
            now=NOW + timedelta(days=31),
            budget=OperationBudget(20000),
        )
        self.assertEqual(expired["processed"], 1)
        self.assertEqual(expired["results"][0]["association"], "PENDING")
        self.assertEqual(expired["results"][0]["reason_code"], "CLOSEOUT_CACHE_EXPIRED")
        self.assertEqual(self._active(fixture.settings), [])
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            lost = CloseoutStore(fixture.settings, budget=budget).read_record(retained["record_id"])
        self.assertEqual(lost["status"], "LOST")

    def test_expired_spool_cleanup_is_retained_and_retried_without_replay(self):
        fixture, validation, prepared = self._fixture()
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(association, "_apply_prepared", side_effect=SimulatedPowerLoss):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(30000),
                )

        active = self._active(fixture.settings)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "PREPARED")
        record_id = active[0]["record_id"]
        original_ref = dict(active[0]["spool_ref"])
        spool_ref = SpoolRef.from_dict(original_ref)
        event_root = fixture.settings.paths.event_dir

        def event_snapshot():
            return tuple(
                (str(path.relative_to(event_root)), path.read_bytes())
                for path in sorted(event_root.rglob("*.json"), key=lambda item: item.as_posix())
            )

        events_before = event_snapshot()
        expiry = NOW + timedelta(days=31)
        deletion_attempts = []
        durable_at_delete = []

        def fail_delete(ref, settings, *, budget=None):
            deletion_attempts.append(ref)
            durable_at_delete.append(
                CloseoutStore(settings, budget=OperationBudget(10000)).read_record(record_id)
            )
            raise SpoolError("SPOOL_DELETE_FAILED")

        with (
            patch.object(association, "delete_spool", side_effect=fail_delete),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("expired result was curated again")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("expired result was applied")),
        ):
            failed = association.recover_closeout_associations(
                fixture.settings,
                now=expiry,
                budget=OperationBudget(30000),
            )

        self.assertEqual(deletion_attempts, [spool_ref])
        self.assertEqual(durable_at_delete[0]["status"], "LOST")
        self.assertEqual(durable_at_delete[0]["spool_ref"], original_ref)
        self.assertEqual(failed["results"][0]["association"], "PENDING")
        self.assertEqual(failed["results"][0]["reason_code"], "CLOSEOUT_CLEANUP_PENDING")
        retained = self._active(fixture.settings)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["status"], "LOST")
        self.assertEqual(retained[0]["spool_ref"], original_ref)

        def crash_delete(ref, settings, *, budget=None):
            deletion_attempts.append(ref)
            raise SimulatedPowerLoss

        with (
            patch.object(association, "delete_spool", side_effect=crash_delete),
            patch.object(association, "_load_prepared", side_effect=AssertionError("LOST result was loaded")),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("LOST result was curated")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("LOST result was applied")),
        ):
            with self.assertRaises(SimulatedPowerLoss):
                association.recover_closeout_associations(
                    fixture.settings,
                    now=expiry,
                    budget=OperationBudget(30000),
                )

        retained = self._active(fixture.settings)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["status"], "LOST")
        self.assertEqual(retained[0]["spool_ref"], original_ref)

        real_delete = association.delete_spool
        successful_deletions = []

        def tracked_delete(ref, settings, *, budget=None):
            removed = real_delete(ref, settings, budget=budget)
            successful_deletions.append((ref, removed))
            return removed

        with (
            patch.object(association, "delete_spool", side_effect=tracked_delete),
            patch.object(association, "_load_prepared", side_effect=AssertionError("LOST result was loaded")),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("LOST result was curated")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("LOST result was applied")),
        ):
            cleaned = association.recover_closeout_associations(
                fixture.settings,
                now=expiry,
                budget=OperationBudget(30000),
            )

        self.assertEqual(successful_deletions, [(spool_ref, True)])
        self.assertEqual(cleaned["results"][0]["association"], "PENDING")
        self.assertEqual(cleaned["results"][0]["reason_code"], "CLOSEOUT_CACHE_EXPIRED")
        self.assertEqual(self._active(fixture.settings), [])
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            terminal = CloseoutStore(fixture.settings, budget=budget).read_record(record_id)
        self.assertEqual(terminal["status"], "LOST")
        self.assertIsNone(terminal["spool_ref"])
        self.assertEqual(prepare_calls, 1)
        self.assertEqual(deletion_attempts, [spool_ref, spool_ref])
        self.assertEqual(event_snapshot(), events_before)

    def test_expired_committed_team_handoff_retries_cleanup_without_ack(self):
        fixture, validation, prepared = self._fixture()
        prepared = replace(prepared, team_prepared=None)
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        first = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=prepare,
            now=NOW,
            budget=OperationBudget(30000),
        )
        self.assertEqual((first.knowledge, first.association), ("APPLIED", "PENDING"))
        self.assertFalse(first.acknowledged)
        self.assertEqual(prepare_calls, 1)

        initial = self._active(fixture.settings)[0]
        self.assertEqual(initial["status"], "COMMITTED")
        self.assertEqual(initial["team_result"]["status"], "UNKNOWN")
        actual_hash = initial["changeset_hash"]
        original_witness = list(initial["witness"])
        original_ref = dict(initial["spool_ref"])
        spool_ref = SpoolRef.from_dict(original_ref)
        expiry = datetime.fromisoformat(initial["expires_at"].replace("Z", "+00:00")) + timedelta(seconds=1)
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(fixture.settings, target_id).state, "SECURED")

        deletion_attempts = []
        durable_at_delete = []

        def fail_delete(ref, settings, *, budget=None):
            deletion_attempts.append(ref)
            durable_at_delete.append(self._active(settings)[0])
            raise SpoolError("SPOOL_DELETE_FAILED")

        with (
            patch.object(association, "delete_spool", side_effect=fail_delete),
            patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("expired handoff re-inferred")),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("expired handoff curated")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("expired handoff reapplied")),
        ):
            replay = association.apply_associated_closeout(
                fixture.settings,
                validation,
                content_hash=CONTENT_HASH,
                prepare=lambda: self.fail("expiry replay prepared again"),
                now=expiry,
                budget=OperationBudget(30000),
            )

        self.assertEqual(deletion_attempts, [spool_ref])
        self.assertEqual(durable_at_delete[0]["status"], "LOST")
        self.assertEqual(durable_at_delete[0]["team_result"]["status"], "UNKNOWN")
        self.assertEqual(durable_at_delete[0]["team_result"]["reason_code"], "TEAM_HANDOFF_EXPIRED")
        self.assertEqual(durable_at_delete[0]["changeset_hash"], actual_hash)
        self.assertEqual(durable_at_delete[0]["witness"], original_witness)
        self.assertEqual(durable_at_delete[0]["spool_ref"], original_ref)
        self.assertEqual((replay.knowledge, replay.association), ("APPLIED", "PENDING"))
        self.assertFalse(replay.acknowledged)
        self.assertEqual(replay.reason_code, "CLOSEOUT_CLEANUP_PENDING")
        self.assertEqual(len(self._active(fixture.settings)), 1)

        with (
            patch.object(association, "delete_spool", side_effect=SimulatedPowerLoss),
            patch.object(association, "_load_prepared", side_effect=AssertionError("LOST handoff was loaded")),
            patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("LOST handoff re-inferred")),
        ):
            with self.assertRaises(SimulatedPowerLoss):
                association.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=lambda: self.fail("LOST replay prepared again"),
                    now=expiry,
                    budget=OperationBudget(30000),
                )
        retained = self._active(fixture.settings)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["spool_ref"], original_ref)

        real_delete = association.delete_spool
        successful_deletions = []

        def tracked_delete(ref, settings, *, budget=None):
            deleted = real_delete(ref, settings, budget=budget)
            successful_deletions.append((ref, deleted))
            return deleted

        with (
            patch.object(association, "delete_spool", side_effect=tracked_delete),
            patch.object(association, "_load_prepared", side_effect=AssertionError("LOST handoff was loaded")),
            patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("LOST handoff re-inferred")),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("LOST handoff curated")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("LOST handoff reapplied")),
        ):
            recovered = association.recover_closeout_associations(
                fixture.settings,
                now=expiry,
                budget=OperationBudget(30000),
            )

        self.assertEqual(successful_deletions, [(spool_ref, True)])
        self.assertEqual(recovered["results"][0]["association"], "PENDING")
        self.assertEqual(recovered["results"][0]["reason_code"], "CLOSEOUT_CACHE_EXPIRED")
        self.assertEqual(self._active(fixture.settings), [])
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(fixture.settings, target_id).state, "SECURED")
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            terminal = CloseoutStore(fixture.settings, budget=budget).read_record(initial["record_id"])
        self.assertEqual(terminal["status"], "LOST")
        self.assertEqual(terminal["reason_code"], "CLOSEOUT_CACHE_EXPIRED")
        self.assertIsNone(terminal["spool_ref"])
        self.assertEqual(terminal["changeset_hash"], actual_hash)
        self.assertEqual(terminal["witness"], original_witness)
        self.assertEqual(prepare_calls, 1)

        replay_after_cleanup = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("terminal loss reserved or prepared again"),
            now=expiry,
            budget=OperationBudget(15000),
        )
        self.assertEqual(replay_after_cleanup.association, "PENDING")
        self.assertFalse(replay_after_cleanup.acknowledged)
        self.assertEqual(replay_after_cleanup.reason_code, "CLOSEOUT_CACHE_EXPIRED")
        self.assertEqual(self._active(fixture.settings), [])

    def test_terminal_team_summaries_require_matching_identity_and_complete_evidence(self):
        from ei.redaction import domain_hash

        def record_for(fixture, validation):
            proof = read_receipt(fixture.settings, validation.context.target_ids[0]).closeout_proofs[0]
            budget = OperationBudget(10000)
            with association._capture_lock(fixture.settings, budget):
                return CloseoutStore(fixture.settings, budget=budget).read_record(proof.record_id)

        other_fixture, other_validation, other_prepared = self._fixture()
        other_result = association.apply_associated_closeout(
            other_fixture.settings,
            other_validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: other_prepared,
            now=NOW,
            budget=OperationBudget(30000),
        )
        self.assertTrue(other_result.acknowledged, repr(other_result))
        other_record = record_for(other_fixture, other_validation)
        self.assertEqual(other_record["team_result"]["status"], "NOT_ELIGIBLE")

        fixture, validation, prepared = self._fixture()
        prepared = replace(prepared, team_prepared=None)
        first = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: prepared,
            now=NOW,
            budget=OperationBudget(30000),
        )
        self.assertEqual((first.knowledge, first.association), ("APPLIED", "PENDING"))
        record = self._active(fixture.settings)[0]
        self.assertEqual(record["team_result"]["status"], "UNKNOWN")
        original_ref = dict(record["spool_ref"])
        actual_hash = record["changeset_hash"]

        mismatched_personal = dict(record["team_result"])
        mismatched_personal.update(
            {
                "status": "DELIVERED",
                "reason_code": "TEAM_EVENT_RECORDED",
                "personal_event_hash": "sha256:" + "9" * 64,
                "team_store_hash": domain_hash("team_aaaaaaaaaaaaaaaa", "team-store-id"),
                "team_root_hash": domain_hash("C:/other/team-root", "team-root"),
                "delivery_event_id": "evt_20261005T120000000000Z_aaaaaaaaaaaa",
                "delivery_event_hash": "sha256:" + "d" * 64,
            }
        )
        missing_delivery_proof = dict(mismatched_personal)
        missing_delivery_proof.update(
            {
                "personal_event_hash": actual_hash,
                "delivery_event_id": None,
                "delivery_event_hash": None,
            }
        )
        inconsistent_negative = dict(record["team_result"])
        inconsistent_negative.update(
            {
                "status": "NOT_ELIGIBLE",
                "reason_code": "TEAM_DISABLED",
                "personal_event_hash": actual_hash,
                "delivery_event_id": "evt_20261005T120000000000Z_bbbbbbbbbbbb",
                "delivery_event_hash": "sha256:" + "e" * 64,
            }
        )
        variants = (
            ("another personal hash", mismatched_personal),
            ("missing delivered identity and hash", missing_delivery_proof),
            ("summary copied from another record and binding", other_record["team_result"]),
            ("inconsistent NOT_ELIGIBLE evidence", inconsistent_negative),
        )

        for name, summary in variants:
            with self.subTest(case=name):
                budget = OperationBudget(10000)
                with association._capture_lock(fixture.settings, budget):
                    store = CloseoutStore(fixture.settings, budget=budget)
                    current = store.read_record(record["record_id"])
                    current["team_result"] = dict(summary)
                    store.write_record(current)

                with (
                    patch.object(association, "delete_spool", side_effect=SpoolError("SPOOL_DELETE_FAILED")) as delete,
                    patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("compact summary triggered inference")),
                    patch("ei.curator.curate_candidate", side_effect=AssertionError("compact summary triggered curation")),
                    patch.object(association, "apply_changeset", side_effect=AssertionError("compact summary reapplied personal knowledge")),
                ):
                    result = association.apply_associated_closeout(
                        fixture.settings,
                        validation,
                        content_hash=CONTENT_HASH,
                        prepare=lambda: self.fail("compact replay prepared again"),
                        now=NOW.replace(minute=2),
                        budget=OperationBudget(30000),
                    )
                    delete.assert_not_called()

                self.assertEqual(result.knowledge, "APPLIED", repr(result))
                self.assertEqual(result.association, "PENDING", repr(result))
                self.assertFalse(result.acknowledged)
                retained = self._active(fixture.settings)
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0]["spool_ref"], original_ref)


if __name__ == "__main__":
    unittest.main()
