from __future__ import annotations

import importlib
import json
import os
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ei.capture_contract import CaptureReceipt, capture_key
from ei.capture_ledger import read_receipt, record_receipt
from ei.hook_entry import handle_normalized_hook
from ei.hooks import registry
from ei.journal import read_event
from ei.operation_runtime import OperationBudget
from tests.unit.test_closeout_context import InstalledAdapterFixture


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
SOURCE_HASH = "sha256:" + "a" * 64
CONTENT_HASH = "sha256:" + "b" * 64


def _explicit_team_disabled():
    return {
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
    }


class CloseoutAssociationTests(unittest.TestCase):
    def _sample_intent(self):
        stamp = NOW.isoformat().replace("+00:00", "Z")
        return {
            "schema_version": 1,
            "record_id": "co_" + "1" * 64,
            "status": "PREPARING",
            "host_hash": "sha256:" + "a" * 64,
            "instance_hash": "sha256:" + "b" * 64,
            "store_hash": "sha256:" + "c" * 64,
            "session_hash": "sha256:" + "d" * 64,
            "record_hash": "sha256:" + "e" * 64,
            "cwd_hash": "sha256:" + "f" * 64,
            "domain_hash": "sha256:" + "0" * 64,
            "target_ids": ["sha256:" + "2" * 64],
            "target_set_hash": "sha256:" + "3" * 64,
            "binding_digest": "sha256:" + "4" * 64,
            "content_hash": CONTENT_HASH,
            "created_at": stamp,
            "expires_at": "2026-11-04T12:00:00Z",
            "spool_id": "spool_" + "5" * 32,
            "spool_ref": None,
            "decision": None,
            "candidate_hash": None,
            "changeset_id_hash": None,
            "changeset_hash": None,
            "application_ref": None,
            "witness": [],
            "team_result": None,
            "reason_code": "CLOSEOUT_RESERVED",
            "result_digest": None,
        }

    def _association_api(self):
        try:
            module = importlib.import_module("ei.closeout_association")
        except ModuleNotFoundError as exc:
            if exc.name != "ei.closeout_association":
                raise
            self.fail("ei.closeout_association.apply_associated_closeout must be implemented")
        self.assertTrue(callable(getattr(module, "apply_associated_closeout", None)))
        self.assertTrue(hasattr(module, "PreparedCloseout"))
        return module

    def _validated_fixture(self, *, turns: int = 2):
        from ei.closeout_context import validate_adapter_context

        fixture = InstalledAdapterFixture(self, turns=turns)
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                result = handle_normalized_hook(
                    event, fixture.settings, budget=OperationBudget(5000)
                )
                self.assertTrue(result.continue_work)
            validation = validate_adapter_context(
                fixture.settings,
                fixture.host_id,
                fixture.control_for(fixture.events[:2]),
                budget=OperationBudget(5000),
            )
        previous_adapter = registry._ADAPTERS.get(fixture.host_id)
        registry._ADAPTERS[fixture.host_id] = fixture.adapter

        def restore_adapter():
            if previous_adapter is None:
                registry._ADAPTERS.pop(fixture.host_id, None)
            else:
                registry._ADAPTERS[fixture.host_id] = previous_adapter

        self.addCleanup(restore_adapter)
        self.assertTrue(validation.valid, validation.reason_code)
        return fixture, validation

    def _yes_changeset(self, validation):
        from ei.curator import curate_candidate

        context = validation.context
        assert context is not None
        host_id = context.identity.host_id
        family = "codex-compatible"
        candidate = {
            "decision": "YES",
            "title": "Verified closeout observation",
            "claim": "This verified closeout result records a reusable observation for the bound work scope.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": [SOURCE_HASH],
            "provenances": [SOURCE_HASH, "sha256:" + "c" * 64],
            "scopes": ["cli-agent", "general"],
            "applicability": [host_id],
            "domain": "fixture-domain",
            "cwd_fingerprint": context.scope.cwd_hash,
            "source_host_id": host_id,
            "source_host_family": family,
            "applicability_scope": "host",
            "applicable_host_ids": [host_id],
            "applicable_host_families": [],
        }
        return curate_candidate(
            candidate,
            [],
            None,
            operation_budget=OperationBudget(5000),
        )

    def test_two_target_commit_requires_real_marker(self):
        module = self._association_api()
        fixture, validation = self._validated_fixture(turns=3)
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        result = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=prepare,
            now=NOW,
            budget=OperationBudget(15000),
        )

        self.assertEqual(prepare_calls, 1, msg=f"association result: {result!r}")
        self.assertEqual((result.knowledge, result.association), ("APPLIED", "COMMITTED"), msg=f"association result: {result!r}")
        self.assertTrue(result.acknowledged)
        self.assertEqual(result.changeset_hash, changeset.fingerprint)
        self.assertEqual(len(result.event_ids), len(changeset.operations) + 1)
        marker_id = result.event_ids[-1]
        partition = datetime.fromisoformat(changeset.generated_at).strftime("%Y/%m")
        marker_path = Path(fixture.settings.paths.event_dir) / partition / f"{marker_id}.json"
        marker = read_event(marker_path)
        self.assertEqual(marker.event_type, "curation.changeset.applied")
        self.assertEqual(marker.payload["changeset_hash"], changeset.fingerprint)

        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
            self.assertEqual(receipt.state, "SECURED")
            self.assertEqual(receipt.covered_target_ids, (target_id,))
            self.assertEqual(len(receipt.closeout_proofs), 1)
            proof = receipt.closeout_proofs[0]
            self.assertEqual(proof.content_hash, CONTENT_HASH)
            self.assertEqual(proof.binding_digest, validation.target_binding_digest)
            self.assertTrue(proof.record_id)
            self.assertTrue(proof.target_set_hash.startswith("sha256:"))
            self.assertTrue(proof.result_digest.startswith("sha256:"))
            binding_path = (
                fixture.settings.paths.runtime_root
                / "state"
                / "capture"
                / "target-bindings"
                / f"{target_id.removeprefix('sha256:')}.json"
            )
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            self.assertEqual(binding["closeout_proofs"], [
                {
                    "record_id": proof.record_id,
                    "target_set_hash": proof.target_set_hash,
                    "content_hash": proof.content_hash,
                    "binding_digest": proof.binding_digest,
                    "result_digest": proof.result_digest,
                }
            ])
        third_id = capture_key(fixture.events[2].capture_identity)
        self.assertIsNotNone(third_id)
        self.assertEqual(read_receipt(fixture.settings, third_id).state, "WAITING")

        from ei.closeout_store import CloseoutStore

        proof_record_id = read_receipt(fixture.settings, validation.context.target_ids[0]).closeout_proofs[0].record_id
        alternate_targets = ("sha256:" + "8" * 64, "sha256:" + "9" * 64)
        with module._capture_lock(fixture.settings, OperationBudget(10000)):
            store = CloseoutStore(fixture.settings, budget=OperationBudget(10000))
            committed = store.read_record(proof_record_id)
            self.assertIsNotNone(committed)
            committed["target_ids"] = list(alternate_targets)
            committed["target_set_hash"] = module._target_set_hash(alternate_targets)
            store.write_record(committed)
        conflict = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("disjoint target replay reached preparation"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(10000),
        )
        self.assertFalse(conflict.acknowledged)
        self.assertEqual(conflict.association, "REJECTED")
        self.assertEqual(conflict.reason_code, "CLOSEOUT_TARGET_CONFLICT")

    def test_existing_application_generated_at_difference_uses_original_marker_hash(self):
        from ei.changeset import apply_changeset

        module = self._association_api()
        fixture, validation = self._validated_fixture()
        original = self._yes_changeset(validation)
        applied = apply_changeset(original, fixture.settings, budget=OperationBudget(30000))
        self.assertTrue(applied.applied, applied.reason_code)
        self.assertIsNotNone(applied.application_ref)
        original_hash = applied.application_ref.changeset_hash

        requested_time = (
            datetime.fromisoformat(original.generated_at.replace("Z", "+00:00")) + timedelta(minutes=1)
        ).isoformat().replace("+00:00", "Z")
        requested = replace(original, generated_at=requested_time)
        self.assertNotEqual(requested.fingerprint, original_hash)
        prepared = module.PreparedCloseout(
            candidate_id=requested.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=requested,
            team_prepared=_explicit_team_disabled(),
        )

        result = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: prepared,
            now=NOW,
            budget=OperationBudget(45000),
        )

        self.assertTrue(result.acknowledged, repr(result))
        self.assertEqual(result.association, "COMMITTED")
        self.assertEqual(result.changeset_hash, original_hash)
        self.assertNotEqual(result.changeset_hash, requested.fingerprint)

    def test_existing_application_semantic_difference_is_not_time_normalized(self):
        from ei.changeset import apply_changeset
        from ei.journal import iter_events

        module = self._association_api()
        fixture, validation = self._validated_fixture()
        original = self._yes_changeset(validation)
        applied = apply_changeset(original, fixture.settings, budget=OperationBudget(30000))
        self.assertTrue(applied.applied, applied.reason_code)
        changed = replace(original, policy_version=original.policy_version + "-different")
        prepared = module.PreparedCloseout(
            candidate_id=changed.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changed,
            team_prepared=_explicit_team_disabled(),
        )

        result = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: prepared,
            now=NOW,
            budget=OperationBudget(45000),
        )

        self.assertFalse(result.acknowledged)
        self.assertEqual(result.knowledge, "UNKNOWN")
        self.assertEqual(result.reason_code, "APPLICATION_PROOF_INVALID")
        matching_events = [
            event for event in iter_events(fixture.settings.paths.event_dir)
            if isinstance(event.payload, dict) and event.payload.get("changeset_id") == original.changeset_id
        ]
        self.assertEqual(len(matching_events), len(original.operations) + 1)

    def test_binding_removed_during_prepare_blocks_knowledge_apply(self):
        from ei.journal import iter_events

        module = self._association_api()
        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        target_id = validation.context.target_ids[0]
        binding_path = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{target_id.removeprefix('sha256:')}.json"
        )

        def prepare():
            binding_path.unlink()
            return prepared

        result = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=prepare,
            now=NOW,
            budget=OperationBudget(30000),
        )

        matching_events = [
            event for event in iter_events(fixture.settings.paths.event_dir)
            if isinstance(event.payload, dict) and event.payload.get("changeset_id") == changeset.changeset_id
        ]
        self.assertFalse(result.acknowledged)
        self.assertEqual((result.knowledge, result.association), ("UNKNOWN", "PENDING"))
        self.assertEqual(result.reason_code, "CLOSEOUT_TARGET_UNKNOWN")
        self.assertEqual(matching_events, [])

    def test_explicit_no_has_durable_evaluation_proof(self):
        module = self._association_api()
        fixture, validation = self._validated_fixture()
        prior_candidate = "cand_" + "d" * 20
        for target_id in validation.context.target_ids:
            record_receipt(
                fixture.settings,
                CaptureReceipt(
                    capture_id=target_id,
                    state="SECURED",
                    candidate_ids=(prior_candidate,),
                    covered_target_ids=(target_id,),
                    reason_code="EXISTING_SECURED",
                    updated_at=NOW,
                    candidate_hashes=((prior_candidate, SOURCE_HASH),),
                ),
                budget=OperationBudget(5000),
            )
        prepared = module.PreparedCloseout(
            candidate_id="cand_explicit_no",
            content_hash=CONTENT_HASH,
            decision="NO",
            changeset=None,
            team_prepared=_explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        first = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=prepare,
            now=NOW,
            budget=OperationBudget(15000),
        )
        from ei.closeout_store import CloseoutStore
        budget = OperationBudget(10000)
        with module._capture_lock(fixture.settings, budget):
            saved_intents = CloseoutStore(fixture.settings, budget=budget).active_records()
        later = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("durable NO replay prepared a second result"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(5000),
        )

        self.assertEqual(prepare_calls, 1, msg=f"association result: {first!r}")
        self.assertEqual(
            (first.knowledge, first.association),
            ("EVALUATED_NONE", "COMMITTED"),
            msg=f"first result: {first!r}; active: {saved_intents!r}",
        )
        self.assertTrue(first.acknowledged)
        self.assertIsNone(first.changeset_hash)
        self.assertEqual((later.knowledge, later.association), ("EVALUATED_NONE", "COMMITTED"))
        self.assertTrue(later.acknowledged)
        self.assertIsNone(later.changeset_hash)
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
            self.assertEqual(receipt.state, "SECURED")
            self.assertEqual(receipt.candidate_ids, (prior_candidate,))
            self.assertEqual(receipt.covered_target_ids, (target_id,))
            self.assertEqual(len(receipt.closeout_proofs), 1)
            self.assertEqual(receipt.closeout_proofs[0].content_hash, CONTENT_HASH)
            self.assertEqual(receipt.closeout_proofs[0].binding_digest, validation.target_binding_digest)
        record_id = read_receipt(fixture.settings, validation.context.target_ids[0]).closeout_proofs[0].record_id
        with module._capture_lock(fixture.settings, OperationBudget(10000)):
            durable = CloseoutStore(fixture.settings, budget=OperationBudget(10000)).read_record(record_id)
        self.assertEqual(durable["decision"], "NO")
        from ei.ids import fingerprint

        self.assertEqual(durable["candidate_hash"], fingerprint(prepared.candidate_id))
        self.assertIsNone(durable["changeset_id_hash"])
        self.assertIsNone(durable["changeset_hash"])
        self.assertEqual(durable["witness"], [])

    def test_typed_context_without_adapter_attestation_is_rejected(self):
        from ei.closeout_context import ContextValidation

        module = self._association_api()
        fixture, validation = self._validated_fixture()
        forged = ContextValidation(
            validation.context,
            validation.target_binding_digest,
            "OK",
        )
        result = module.apply_associated_closeout(
            fixture.settings,
            forged,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("forged context reached preparation"),
            now=NOW,
            budget=OperationBudget(5000),
        )
        self.assertIn(result.association, {"REJECTED", "UNKNOWN"})
        self.assertEqual(result.knowledge, "UNKNOWN")
        self.assertFalse(result.acknowledged)

    def test_changeset_host_and_scope_are_checked_against_registered_context(self):
        from ei.changeset import ChangeSet

        module = self._association_api()
        for field, value, expected_reason in (
            ("host", "untrusted-host", "CLOSEOUT_HOST_MISMATCH"),
            ("domain", "different-domain", "CLOSEOUT_SCOPE_UNKNOWN"),
        ):
            with self.subTest(field=field):
                fixture, validation = self._validated_fixture()
                changeset = self._yes_changeset(validation)
                mapping = changeset.to_dict()
                for operation in mapping["operations"]:
                    if field == "host":
                        operation["payload"]["source_host_id"] = value
                        operation["payload"]["applicable_host_ids"] = [value]
                    else:
                        operation["payload"][field] = value
                untrusted = ChangeSet.from_mapping(mapping)
                prepared = module.PreparedCloseout(
                    candidate_id=untrusted.candidate_id,
                    content_hash=CONTENT_HASH,
                    decision="YES",
                    changeset=untrusted,
                    team_prepared=_explicit_team_disabled(),
                )
                result = module.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=lambda: prepared,
                    now=NOW,
                    budget=OperationBudget(10000),
                )
                self.assertFalse(result.acknowledged)
                self.assertEqual(result.association, "PENDING")
                self.assertEqual(result.reason_code, expected_reason)
                for target_id in validation.context.target_ids:
                    receipt = read_receipt(fixture.settings, target_id)
                    self.assertEqual(receipt.state, "WAITING")
                    self.assertEqual(receipt.closeout_proofs, ())

    def test_replay_calls_prepare_once(self):
        module = self._association_api()
        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        first = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=prepare,
            now=NOW,
            budget=OperationBudget(15000),
        )
        second = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("committed replay prepared a second result"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(15000),
        )

        self.assertEqual(prepare_calls, 1, msg=f"association results: {first!r}, {second!r}")
        self.assertEqual((first.knowledge, second.association), ("APPLIED", "COMMITTED"))
        self.assertEqual(second.knowledge, "APPLIED")
        self.assertTrue(second.acknowledged)
        self.assertEqual(second.event_ids, first.event_ids)
        self.assertEqual(second.changeset_hash, first.changeset_hash)

    def test_concurrent_same_intent_prepares_once_and_only_one_acknowledges(self):
        module = self._association_api()
        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        entered_prepare = threading.Event()
        release_prepare = threading.Event()
        prepare_calls = 0
        outcome = {}

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            entered_prepare.set()
            if not release_prepare.wait(10):
                raise TimeoutError("prepare synchronization timeout")
            return prepared

        def run_first():
            try:
                outcome["first"] = module.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(30000),
                )
            except BaseException as exc:
                outcome["error"] = exc

        worker = threading.Thread(target=run_first, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered_prepare.wait(10), "first request did not reach prepare")
            second = module.apply_associated_closeout(
                fixture.settings,
                validation,
                content_hash=CONTENT_HASH,
                prepare=lambda: self.fail("concurrent replay prepared a second result"),
                now=NOW,
                budget=OperationBudget(15000),
            )
        finally:
            release_prepare.set()
            worker.join(30)

        self.assertFalse(worker.is_alive(), "first closeout request did not finish")
        self.assertNotIn("error", outcome, repr(outcome.get("error")))
        first = outcome["first"]
        self.assertEqual(prepare_calls, 1)
        self.assertTrue(first.acknowledged)
        self.assertFalse(second.acknowledged)
        self.assertEqual(second.association, "PENDING")

    def test_missing_team_prepared_value_stays_unknown_and_retains_active_spool(self):
        module = self._association_api()
        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
        )
        result = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: prepared,
            now=NOW,
            budget=OperationBudget(30000),
        )
        self.assertEqual(result.knowledge, "APPLIED")
        self.assertEqual(result.association, "PENDING")
        self.assertFalse(result.acknowledged)
        self.assertEqual(result.team_result["status"], "UNKNOWN")
        from ei.closeout_store import CloseoutStore
        budget = OperationBudget(10000)
        with module._capture_lock(fixture.settings, budget):
            active = CloseoutStore(fixture.settings, budget=budget).active_records()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "COMMITTED")
        self.assertIsNotNone(active[0]["spool_ref"])

    def test_receipt_deadline_does_not_commit_or_ack_partial_proof(self):
        module = self._association_api()
        from ei.closeout_store import CloseoutStore

        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        prepare_calls = 0

        def prepare():
            nonlocal prepare_calls
            prepare_calls += 1
            return prepared

        with patch.object(module, "_record_receipt_locked", side_effect=TimeoutError("deadline")):
            with self.assertRaises(TimeoutError):
                module.apply_associated_closeout(
                    fixture.settings,
                    validation,
                    content_hash=CONTENT_HASH,
                    prepare=prepare,
                    now=NOW,
                    budget=OperationBudget(10000),
                )

        budget = OperationBudget(10000)
        with module._capture_lock(fixture.settings, budget):
            active = CloseoutStore(fixture.settings, budget=budget).active_records()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "APPLIED")
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id)
            self.assertEqual(receipt.state, "WAITING")
            self.assertEqual(receipt.closeout_proofs, ())

        resumed = module.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=CONTENT_HASH,
            prepare=lambda: self.fail("deadline retry prepared a second result"),
            now=NOW.replace(minute=1),
            budget=OperationBudget(15000),
        )
        self.assertEqual(prepare_calls, 1)
        self.assertTrue(resumed.acknowledged)
        self.assertEqual(resumed.association, "COMMITTED")

    def test_waiting_receipt_with_closeout_proof_is_not_acknowledged(self):
        module = self._association_api()
        from ei import capture_ledger

        fixture, validation = self._validated_fixture()
        changeset = self._yes_changeset(validation)
        prepared = module.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash=CONTENT_HASH,
            decision="YES",
            changeset=changeset,
            team_prepared=_explicit_team_disabled(),
        )
        record_receipt = module._record_receipt_locked

        def preserve_waiting_with_proof(root, receipt, *, budget=None):
            saved = record_receipt(root, receipt, budget=budget)
            incomplete = replace(saved, state="WAITING", reason_code="CLOSEOUT_PENDING")
            encoded = (
                json.dumps(capture_ledger._serialize(incomplete), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            capture_ledger._write_path(
                root,
                capture_ledger._path(root, receipt.capture_id),
                encoded,
                budget=budget,
            )
            return saved

        with patch.object(module, "_record_receipt_locked", side_effect=preserve_waiting_with_proof):
            result = module.apply_associated_closeout(
                fixture.settings,
                validation,
                content_hash=CONTENT_HASH,
                prepare=lambda: prepared,
                now=NOW,
                budget=OperationBudget(5000),
            )

        self.assertFalse(result.acknowledged)
        self.assertEqual(result.association, "PENDING")
        self.assertEqual(result.reason_code, "CLOSEOUT_RECEIPT_READBACK_FAILED")
        for target_id in validation.context.target_ids:
            receipt = read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
            self.assertEqual(receipt.state, "WAITING")
            self.assertEqual(len(receipt.closeout_proofs), 1)

    def test_store_reserves_body_free_intent_before_spool(self):
        from ei.closeout_association import _capture_lock
        from ei.closeout_store import CloseoutStore

        fixture = InstalledAdapterFixture(self, turns=1)
        budget = OperationBudget(10000)
        store = CloseoutStore(fixture.settings, budget=budget)
        intent = self._sample_intent()
        with _capture_lock(fixture.settings, budget):
            saved = store.reserve(intent)
            self.assertEqual(saved, intent)
            self.assertEqual(store.read_record(intent["record_id"]), intent)
            self.assertEqual(store.active_records(), [intent])
        record_path = (
            fixture.settings.paths.runtime_dir
            / "state"
            / "closeout-associations"
            / f"{intent['record_id']}.json"
        )
        value = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertNotIn("candidate_id", value)
        self.assertNotIn("changeset", value)

    def test_store_enforces_64_records_and_16k_record_cap(self):
        from ei.closeout_association import _capture_lock, _target_set_hash
        from ei.closeout_store import CloseoutStore, CloseoutStoreError, _encoded

        fixture = InstalledAdapterFixture(self, turns=1)
        budget = OperationBudget(120000)
        store = CloseoutStore(fixture.settings, budget=budget)
        intents = []
        with _capture_lock(fixture.settings, budget):
            for index in range(1, 65):
                intent = self._sample_intent()
                intent["record_id"] = "co_" + f"{index:064x}"
                intent["spool_id"] = "spool_" + f"{index:032x}"
                if index == 1:
                    store.reserve(intent)
                else:
                    intents.append(intent)
            root = store.root
            for intent in intents:
                store._write_json(root, intent["record_id"] + ".json", intent, 16 * 1024)
            active_ids = ["co_" + f"{index:064x}" for index in range(1, 65)]
            store._write_json(root, "index.json", {"schema_version": 1, "active": sorted(active_ids)}, 16 * 1024)
            self.assertEqual(len(store.active_records(max_records=64)), 64)
            overflow = self._sample_intent()
            overflow["record_id"] = "co_" + f"{65:064x}"
            overflow["spool_id"] = "spool_" + f"{65:032x}"
            with self.assertRaises(CloseoutStoreError) as caught:
                store.reserve(overflow)
            self.assertEqual(caught.exception.reason_code, "CLOSEOUT_CAPACITY")

            oversized = self._sample_intent()
            oversized["record_id"] = "co_" + f"{1:064x}"
            oversized["spool_id"] = "spool_" + f"{1:032x}"
            oversized["status"] = "APPLIED"
            oversized["decision"] = "YES"
            oversized["candidate_hash"] = "sha256:" + "a" * 64
            oversized["changeset_id_hash"] = "sha256:" + "b" * 64
            oversized["changeset_hash"] = "sha256:" + "c" * 64
            oversized["result_digest"] = "sha256:" + "d" * 64
            oversized["target_ids"] = sorted("sha256:" + f"{index:064x}" for index in range(64))
            oversized["target_set_hash"] = _target_set_hash(tuple(oversized["target_ids"]))
            oversized["spool_ref"] = {
                "spool_id": oversized["spool_id"],
                "content_hash": CONTENT_HASH,
                "classification": "private-reusable",
                "created_at": oversized["created_at"],
                "expires_at": oversized["expires_at"],
                "key_id": None,
                "encrypted": True,
                "purpose": "validated-result",
            }
            oversized["witness"] = [
                {
                    "event_id": "evt_changeset_" + f"{index:032x}",
                    "occurred_at": "2026-10-05T12:00:00Z",
                    "integrity_digest": "f" * 64,
                }
                for index in range(65)
            ]
            marker_id = oversized["witness"][-1]["event_id"]
            oversized["application_ref"] = {
                "marker_id": marker_id,
                "occurred_at": "2026-10-05T12:00:00Z",
                "changeset_hash": oversized["changeset_hash"],
            }
            self.assertGreater(len(_encoded(oversized)), 16 * 1024)
            from ei.journal import validate_schema

            validate_schema("closeout-association", oversized)
            with self.assertRaises(CloseoutStoreError) as too_large:
                store.write_record(oversized)
            self.assertEqual(too_large.exception.reason_code, "CLOSEOUT_CAPACITY")

    def test_store_refuses_corrupt_or_incomplete_inventory(self):
        from ei.closeout_association import _capture_lock
        from ei.closeout_store import CloseoutStore, CloseoutStoreError

        fixture = InstalledAdapterFixture(self, turns=1)
        budget = OperationBudget(10000)
        store = CloseoutStore(fixture.settings, budget=budget)
        intent = self._sample_intent()
        with _capture_lock(fixture.settings, budget):
            store.reserve(intent)
        index_path = (
            fixture.settings.paths.runtime_dir
            / "state"
            / "closeout-associations"
            / "index.json"
        )
        index_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(CloseoutStoreError) as caught:
            store.active_records()
        self.assertEqual(caught.exception.reason_code, "CLOSEOUT_INDEX_UNKNOWN")

    def test_store_rejects_hidden_incomplete_cursor_record(self):
        from ei.closeout_association import _capture_lock
        from ei.closeout_store import CloseoutStore, CloseoutStoreError

        fixture = InstalledAdapterFixture(self, turns=1)
        budget = OperationBudget(10000)
        store = CloseoutStore(fixture.settings, budget=budget)
        intent = self._sample_intent()
        with _capture_lock(fixture.settings, budget):
            store.reserve(intent)
            store.advance_cursor(intent["record_id"])
            store._write_json(
                store.root,
                "index.json",
                {"schema_version": 1, "active": []},
                16 * 1024,
            )

            other = self._sample_intent()
            other["record_id"] = "co_" + "2" * 64
            other["spool_id"] = "spool_" + "6" * 32

            with self.subTest(operation="read_inventory"):
                with self.assertRaises(CloseoutStoreError) as caught:
                    store.active_records()
                self.assertEqual(caught.exception.reason_code, "CLOSEOUT_INDEX_UNKNOWN")

            with self.subTest(operation="read_record"):
                with self.assertRaises(CloseoutStoreError) as caught:
                    store.read_record(other["record_id"])
                self.assertEqual(caught.exception.reason_code, "CLOSEOUT_INDEX_UNKNOWN")

            with self.subTest(operation="reserve"):
                with self.assertRaises(CloseoutStoreError) as caught:
                    store.reserve(other)
                self.assertEqual(caught.exception.reason_code, "CLOSEOUT_INDEX_UNKNOWN")

    def test_store_rejects_index_replaced_between_check_and_open(self):
        from ei.closeout_association import _capture_lock
        from ei.closeout_store import CloseoutStore, CloseoutStoreError

        fixture = InstalledAdapterFixture(self, turns=1)
        budget = OperationBudget(10000)
        store = CloseoutStore(fixture.settings, budget=budget)
        with _capture_lock(fixture.settings, budget):
            store.reserve(self._sample_intent())
        index_path = fixture.settings.paths.runtime_dir / "state" / "closeout-associations" / "index.json"
        replacement_path = index_path.with_name("replacement.json")
        replacement_path.write_text('{"active":[],"schema_version":1}\n', encoding="utf-8")
        original_open = os.open
        replaced = False

        def replace_before_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if Path(path) == index_path and not replaced:
                replaced = True
                index_path.unlink()
                replacement_path.rename(index_path)
            return original_open(path, flags, *args, **kwargs)

        with patch("ei.closeout_store.os.open", side_effect=replace_before_open):
            with self.assertRaises(CloseoutStoreError) as caught:
                store.active_records()
        self.assertTrue(replaced)
        self.assertEqual(caught.exception.reason_code, "CLOSEOUT_INDEX_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
