from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

from ei.capture_contract import capture_key
from ei.capture_ledger import read_receipt
from ei.hook_entry import handle_normalized_hook
from ei.hooks import registry
from ei.ids import fingerprint
from ei.inference.base import ProviderResult
from ei.install_manifest import normalize_install_manifest, validate_install_manifest
from ei.journal import JournalIntegrityError, iter_events
from ei.operation_runtime import OperationBudget
from ei.redaction import domain_hash
from ei.team_outbox import list_team_outbox
from ei.team_store import initialize_team_store, scan_team_events
from tests.unit.test_closeout_context import InstalledAdapterFixture


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


class AdapterCloseoutTests(unittest.TestCase):
    def test_trusted_team_routing_reuses_prepared_decision_and_actual_hash_on_compact_replay(self):
        fixture = InstalledAdapterFixture(self, turns=3)
        team_root = fixture.settings.paths.engine_root.parent / "shared-team"
        team_store = initialize_team_store(team_root, now=NOW)
        fixture.settings = replace(
            fixture.settings,
            paths=replace(fixture.settings.paths, team_knowledge_root=team_root),
        )
        manifest = json.loads(fixture.settings.paths.install_manifest_path.read_text(encoding="utf-8"))
        manifest["knowledge_stores"]["team"] = {
            "enabled": True,
            "root": team_root.as_posix(),
            "store_id": team_store.store_id,
            "layout": "member-writer-events-v1",
            "team_member_id": "member-a",
            "writer_id": "writer_aaaaaaaaaaaaaaaa",
            "transport": "external-shared-folder",
            "transport_managed": False,
            "status": "READY",
        }
        manifest = normalize_install_manifest(manifest)
        validate_install_manifest(manifest, require_live_personal=False)
        fixture.settings.paths.install_manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )

        explicit_events = fixture.events[:2]
        target_ids = tuple(sorted(capture_key(event.capture_identity) for event in explicit_events))
        control = fixture.control_for(explicit_events)
        evidence_ref = "sha256:" + "a" * 64
        candidate = {
            "candidate_id": "adapter-closeout-team-compact-replay",
            "title": "Bounded closeout behavior",
            "claim": "A verified closeout applies knowledge only to its explicitly bound turns.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": [evidence_ref],
            "provenances": [evidence_ref, "sha256:" + "c" * 64],
            "scopes": ["cli-agent", "general"],
            "applicability": [fixture.host_id],
            "domain": "fixture-domain",
            "cwd_fingerprint": explicit_events[0].cwd_hash,
            "source_host_id": fixture.host_id,
            "source_host_family": fixture.spec.host_family,
        }
        payload = {
            "candidate": candidate,
            "gate_decision": {
                "decision": "YES",
                "reason_code": "evidence_verified",
                "candidate_title": candidate["title"],
                "candidate_claim": candidate["claim"],
                "evidence_refs": [evidence_ref],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "confidence": 0.95,
                "applicability_scope": "host",
                "applicable_host_ids": [fixture.host_id],
                "applicable_host_families": [],
            },
        }
        normalized_team = {
            "title": "Prepared team normalization",
            "claim": "The exact eligible team payload is frozen before personal apply.",
            "scope": ["adapter-closeout"],
            "preconditions": ["personal apply has a verified marker"],
            "failure_modes": ["replay must not call the provider again"],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        }
        provider_calls = []
        applied_marker_counts_at_prepare = []

        def generate(schema_name, input_json, budget):
            provider_calls.append((schema_name, dict(input_json)))
            applied_marker_counts_at_prepare.append(sum(
                event.event_type == "curation.changeset.applied"
                for event in iter_events(fixture.settings.paths.event_dir)
            ))
            return ProviderResult("fixture-provider", "success", output=dict(normalized_team))

        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                handled = handle_normalized_hook(event, fixture.settings, budget=OperationBudget(5000))
                self.assertTrue(handled.continue_work)
            with patch("ei.inference.router.ProviderRouter.generate", side_effect=generate), patch(
                "ei.team_routing.deliver_prepared_team_routing",
                side_effect=OSError("simulated interruption after personal apply"),
            ):
                first = registry.run_adapter_closeout(
                    fixture.host_id, control, payload, fixture.settings,
                    now=NOW, budget=OperationBudget(15000),
                )

            self.assertEqual(first.payload["knowledge"], "APPLIED", msg=str(first.payload))
            self.assertEqual(first.payload["association"]["status"], "PENDING", msg=str(first.payload))
            self.assertFalse(first.payload["association"]["acknowledged"])
            target_receipts = {
                target_id: read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
                for target_id in target_ids
            }
            record_id = target_receipts[target_ids[0]].closeout_proofs[0].record_id
            from ei.closeout_store import CloseoutStore

            compact = CloseoutStore(fixture.settings, budget=OperationBudget(10000)).read_record(record_id)
            self.assertIsNotNone(compact)
            actual_hash = compact["changeset_hash"]
            first_personal_events = tuple(iter_events(fixture.settings.paths.event_dir))
            self.assertEqual(scan_team_events(team_root, budget=OperationBudget(5000)).events, ())
            self.assertEqual(list_team_outbox(fixture.settings, budget=OperationBudget(5000)).count, 0)

            from ei.closeout_association import recover_closeout_associations
            with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("recovery re-inferred team decision")), patch(
                "ei.closeout_association._persist_team_summary",
                side_effect=OSError("simulated interruption after team append"),
            ):
                handoff_interrupted = recover_closeout_associations(
                    fixture.settings, now=NOW.replace(minute=1), budget=OperationBudget(15000),
                )
            self.assertEqual(handoff_interrupted["results"][0]["association"], "PENDING", msg=str(handoff_interrupted))
            after_interrupted_summary = tuple(scan_team_events(team_root, budget=OperationBudget(5000)).events)
            self.assertEqual(len(after_interrupted_summary), 1)

            with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("recovery re-inferred team decision")), patch(
                "ei.curator.curate_candidate",
                side_effect=AssertionError("recovery curated again"),
            ), patch(
                "ei.closeout_service.apply_changeset",
                side_effect=AssertionError("recovery applied personal knowledge again"),
            ):
                recovered = recover_closeout_associations(
                    fixture.settings, now=NOW.replace(minute=1), budget=OperationBudget(15000),
                )
            self.assertEqual(recovered["processed"], 1)
            self.assertEqual(recovered["results"][0]["association"], "COMMITTED", msg=str(recovered))
            recovered_team_events = tuple(scan_team_events(team_root, budget=OperationBudget(5000)).events)
            self.assertEqual(len(recovered_team_events), 1)
            self.assertEqual(recovered_team_events, after_interrupted_summary)

            with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("compact replay re-inferred team decision")), patch(
                "ei.curator.curate_candidate",
                side_effect=AssertionError("compact team replay curated again"),
            ), patch(
                "ei.closeout_service.apply_changeset",
                side_effect=AssertionError("compact team replay applied personal knowledge again"),
            ):
                replay = registry.run_adapter_closeout(
                    fixture.host_id, control, payload, fixture.settings,
                    now=NOW.replace(minute=1), budget=OperationBudget(15000),
                )

        self.assertEqual(applied_marker_counts_at_prepare, [0])
        self.assertEqual(len(provider_calls), 1)
        self.assertEqual(replay.payload["knowledge"], "APPLIED")
        self.assertEqual(replay.payload["association"]["status"], "COMMITTED")
        self.assertEqual(replay.payload["team"]["personal_event_hash"], actual_hash)
        self.assertEqual(tuple(iter_events(fixture.settings.paths.event_dir)), first_personal_events)
        self.assertEqual(tuple(scan_team_events(team_root, budget=OperationBudget(5000)).events), recovered_team_events)
        self.assertEqual(list_team_outbox(fixture.settings, budget=OperationBudget(5000)).count, 0)
        self.assertEqual(
            {target_id: read_receipt(fixture.settings, target_id, budget=OperationBudget(5000)) for target_id in target_ids},
            target_receipts,
        )
        routed = recovered_team_events[0]
        self.assertEqual(routed.payload["origin_event_hash"], domain_hash(actual_hash, "personal-event-origin"))
        self.assertEqual(
            routed.idempotency_key,
            domain_hash(actual_hash + team_store.store_id, "team-event-idempotency"),
        )
        for field, expected in normalized_team.items():
            self.assertEqual(routed.payload[field], expected)

    def test_registered_adapter_closeout_applies_and_covers_only_explicit_turns(self):
        fixture = InstalledAdapterFixture(self, turns=3)
        explicit_events = fixture.events[:2]
        target_ids = tuple(sorted(capture_key(event.capture_identity) for event in explicit_events))
        control = fixture.control_for(explicit_events)
        evidence_ref = "sha256:" + "a" * 64
        candidate = {
            "candidate_id": "adapter-closeout-two-turns",
            "title": "Bounded closeout behavior",
            "claim": "A verified closeout applies knowledge only to its explicitly bound turns.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": [evidence_ref],
            "provenances": [evidence_ref, "sha256:" + "c" * 64],
            "scopes": ["cli-agent", "general"],
            "applicability": [fixture.host_id],
            "domain": "fixture-domain",
            "cwd_fingerprint": explicit_events[0].cwd_hash,
            "source_host_id": fixture.host_id,
            "source_host_family": fixture.spec.host_family,
        }
        payload = {
            "candidate": candidate,
            "gate_decision": {
                "decision": "YES",
                "reason_code": "evidence_verified",
                "candidate_title": candidate["title"],
                "candidate_claim": candidate["claim"],
                "evidence_refs": [evidence_ref],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "confidence": 0.95,
                "applicability_scope": "host",
                "applicable_host_ids": [fixture.host_id],
                "applicable_host_families": [],
            },
        }

        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                result = handle_normalized_hook(
                    event, fixture.settings, budget=OperationBudget(5000)
                )
                self.assertTrue(result.continue_work)
            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("trusted structured closeout invoked a provider"),
            ), patch(
                "builtins.input",
                side_effect=AssertionError("trusted structured closeout requested input"),
            ):
                result = registry.run_adapter_closeout(
                    fixture.host_id,
                    control,
                    payload,
                    fixture.settings,
                    now=NOW,
                    budget=OperationBudget(15000),
                )

        self.assertEqual(result.exit_code, 0, msg=str(result.payload))
        self.assertEqual(result.payload["knowledge"], "APPLIED")
        self.assertEqual(result.payload["association"]["status"], "COMMITTED")
        self.assertTrue(result.payload["association"]["acknowledged"])
        for target_id in target_ids:
            receipt = read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
            self.assertEqual(receipt.state, "SECURED")
            self.assertEqual(receipt.covered_target_ids, (target_id,))
            self.assertEqual(len(receipt.closeout_proofs), 1)

        third_id = capture_key(fixture.events[2].capture_identity)
        self.assertIsNotNone(third_id)
        self.assertEqual(
            read_receipt(fixture.settings, third_id, budget=OperationBudget(5000)).state,
            "WAITING",
        )
        markers = [event for event in iter_events(fixture.settings.paths.event_dir)
                   if event.event_type == "curation.changeset.applied"]
        self.assertEqual(len(markers), 1)

    def test_trusted_privacy_rejected_no_retries_without_audit_id_collision(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        event = fixture.events[0]
        target_id = capture_key(event.capture_identity)
        self.assertIsNotNone(target_id)
        claim = "api_key=marker-api-key-123456789"
        candidate = {
            "candidate_id": "adapter-closeout-privacy-rejection",
            "title": "Privacy rejection fixture",
            "claim": claim,
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "domain": "fixture-domain",
            "source_host_id": fixture.host_id,
            "source_host_family": fixture.spec.host_family,
        }
        payload = {
            "candidate": candidate,
            "gate_decision": {
                "decision": "NO",
                "reason_code": "no_future_benefit",
                "candidate_title": candidate["title"],
                "candidate_claim": claim,
                "evidence_refs": [],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "confidence": 0.95,
                "applicability_scope": "host",
                "applicable_host_ids": [fixture.host_id],
                "applicable_host_families": [],
            },
        }

        audit_window_start = datetime.now(timezone.utc)
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            handled = handle_normalized_hook(
                event, fixture.settings, budget=OperationBudget(5000)
            )
            self.assertTrue(handled.continue_work)
            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("structured privacy rejection invoked a provider"),
            ) as provider, patch(
                "builtins.input",
                side_effect=AssertionError("privacy rejection requested interactive input"),
            ) as input_call:
                results = []
                for attempt in range(3):
                    try:
                        results.append(registry.run_adapter_closeout(
                            fixture.host_id,
                            fixture.control_for((event,)),
                            payload,
                            fixture.settings,
                            now=NOW.replace(minute=attempt),
                            budget=OperationBudget(15000),
                        ))
                    except JournalIntegrityError as exc:
                        self.fail(
                            "trusted privacy rejection retry must return its fixed refusal; "
                            f"audit append raised {exc}"
                        )
                provider.assert_not_called()
                input_call.assert_not_called()
        audit_window_end = datetime.now(timezone.utc)

        for result in results:
            self.assertEqual(result.payload["association"]["status"], "REJECTED")
            self.assertEqual(
                result.payload["association"]["reason_code"],
                "CLOSEOUT_PRIVACY_REJECTED",
            )
            self.assertFalse(result.payload["association"]["acknowledged"])
            self.assertEqual(result.payload["knowledge"], "DISCARDED")

        audit_events = [
            item for item in iter_events(fixture.settings.paths.event_dir)
            if item.event_type == "gate.decision"
        ]
        self.assertEqual(len(audit_events), 3)
        self.assertEqual(len({item.event_id for item in audit_events}), 3)
        for item in audit_events:
            occurred_at = datetime.fromisoformat(item.occurred_at.replace("Z", "+00:00"))
            self.assertGreaterEqual(occurred_at, audit_window_start)
            self.assertLessEqual(occurred_at, audit_window_end)
        self.assertNotIn("marker-api-key", json.dumps([item.payload for item in audit_events]))
        receipt = read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
        self.assertEqual(receipt.state, "WAITING")
        self.assertEqual(receipt.closeout_proofs, ())
        from ei.closeout_store import CloseoutStore

        self.assertEqual(
            CloseoutStore(fixture.settings, budget=OperationBudget(5000)).active_records(),
            [],
        )
        markers = [
            item for item in iter_events(fixture.settings.paths.event_dir)
            if item.event_type == "curation.changeset.applied"
        ]
        self.assertEqual(markers, [])

    def test_same_record_with_changed_semantic_content_conflicts_after_compact_cleanup(self):
        fixture = InstalledAdapterFixture(self, turns=3)
        explicit_events = fixture.events[:2]
        target_ids = tuple(sorted(capture_key(event.capture_identity) for event in explicit_events))
        control = fixture.control_for(explicit_events)
        evidence_ref = "sha256:" + "a" * 64
        candidate = {
            "candidate_id": "adapter-closeout-content-conflict",
            "title": "Stable closeout candidate",
            "claim": "A verified closeout applies only to its explicit targets.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": [evidence_ref],
            "provenances": [evidence_ref, "sha256:" + "c" * 64],
            "scopes": ["cli-agent", "general"],
            "applicability": [fixture.host_id],
            "domain": "fixture-domain",
            "cwd_fingerprint": explicit_events[0].cwd_hash,
            "source_host_id": fixture.host_id,
            "source_host_family": fixture.spec.host_family,
        }
        payload = {
            "candidate": candidate,
            "gate_decision": {
                "decision": "YES",
                "reason_code": "evidence_verified",
                "candidate_title": candidate["title"],
                "candidate_claim": candidate["claim"],
                "evidence_refs": [evidence_ref],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "confidence": 0.95,
                "applicability_scope": "host",
                "applicable_host_ids": [fixture.host_id],
                "applicable_host_families": [],
            },
        }

        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                handled = handle_normalized_hook(
                    event, fixture.settings, budget=OperationBudget(5000)
                )
                self.assertTrue(handled.continue_work)
            first = registry.run_adapter_closeout(
                fixture.host_id,
                control,
                payload,
                fixture.settings,
                now=NOW,
                budget=OperationBudget(15000),
            )
            self.assertEqual(first.payload["association"]["status"], "COMMITTED")
            self.assertTrue(first.payload["association"]["acknowledged"])

            before_receipts = {
                target_id: read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
                for target_id in target_ids
            }
            record_id = before_receipts[target_ids[0]].closeout_proofs[0].record_id
            from ei.closeout_store import CloseoutStore

            store = CloseoutStore(fixture.settings, budget=OperationBudget(10000))
            compact = store.read_record(record_id)
            self.assertIsNotNone(compact)
            self.assertEqual(compact["status"], "COMMITTED")
            self.assertIsNone(compact["spool_ref"])
            self.assertEqual(store.active_records(), [])
            before_events = list(iter_events(fixture.settings.paths.event_dir))

            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("same-content replay called a provider"),
            ) as provider, patch(
                "builtins.input",
                side_effect=AssertionError("same-content replay requested input"),
            ) as input_call, patch(
                "ei.curator.curate_candidate",
                side_effect=AssertionError("same-content replay curated again"),
            ) as curate, patch(
                "ei.closeout_service.apply_changeset",
                side_effect=AssertionError("same-content replay applied again"),
            ) as apply:
                same_replay = registry.run_adapter_closeout(
                    fixture.host_id,
                    control,
                    payload,
                    fixture.settings,
                    now=NOW.replace(minute=1),
                    budget=OperationBudget(15000),
                )
                provider.assert_not_called()
                input_call.assert_not_called()
                curate.assert_not_called()
                apply.assert_not_called()
            self.assertEqual(same_replay.payload["association"]["status"], "COMMITTED")
            self.assertTrue(same_replay.payload["association"]["acknowledged"])
            self.assertEqual(list(iter_events(fixture.settings.paths.event_dir)), before_events)

            changed_payload = copy.deepcopy(payload)
            changed_claim = candidate["claim"] + " The semantic claim changed on replay."
            changed_payload["candidate"]["claim"] = changed_claim
            changed_payload["gate_decision"]["candidate_claim"] = changed_claim
            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("content-conflict replay called a provider"),
            ) as provider, patch(
                "builtins.input",
                side_effect=AssertionError("content-conflict replay requested input"),
            ) as input_call, patch(
                "ei.curator.curate_candidate",
                side_effect=AssertionError("content-conflict replay curated again"),
            ) as curate, patch(
                "ei.closeout_service.apply_changeset",
                side_effect=AssertionError("content-conflict replay applied again"),
            ) as apply:
                replay = registry.run_adapter_closeout(
                    fixture.host_id,
                    control,
                    changed_payload,
                    fixture.settings,
                    now=NOW.replace(minute=1),
                    budget=OperationBudget(15000),
                )
                provider.assert_not_called()
                input_call.assert_not_called()
                curate.assert_not_called()
                apply.assert_not_called()

        self.assertEqual(replay.payload["association"]["status"], "REJECTED")
        self.assertFalse(replay.payload["association"]["acknowledged"])
        self.assertEqual(replay.payload["knowledge"], "UNKNOWN")
        after_receipts = {
            target_id: read_receipt(fixture.settings, target_id, budget=OperationBudget(5000))
            for target_id in target_ids
        }
        after_events = list(iter_events(fixture.settings.paths.event_dir))
        self.assertEqual(after_receipts, before_receipts)
        with self.subTest("journal unchanged"):
            self.assertEqual(after_events, before_events)
        with self.subTest("semantic content conflict reason"):
            self.assertEqual(
                replay.payload["association"]["reason_code"],
                "CLOSEOUT_CONTENT_CONFLICT",
            )

        third_id = capture_key(fixture.events[2].capture_identity)
        self.assertIsNotNone(third_id)
        second_control = fixture.control_for((fixture.events[2],))
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("structured second record invoked a provider"),
            ), patch("builtins.input", side_effect=AssertionError("second record requested input")):
                second_record = registry.run_adapter_closeout(
                    fixture.host_id,
                    second_control,
                    payload,
                    fixture.settings,
                    now=NOW.replace(minute=2),
                    budget=OperationBudget(15000),
                )
        self.assertEqual(second_record.payload["association"]["status"], "PENDING")
        self.assertFalse(second_record.payload["association"]["acknowledged"])
        self.assertEqual(
            second_record.payload["association"]["reason_code"], "TARGET_ALREADY_EXISTS"
        )
        self.assertEqual(read_receipt(fixture.settings, third_id).state, "WAITING")
        gate_events = [
            event for event in iter_events(fixture.settings.paths.event_dir)
            if event.event_type == "gate.decision"
        ]
        self.assertEqual(len(gate_events), 2)
        self.assertEqual(len({event.event_id for event in gate_events}), 2)

    def test_trusted_closeout_without_structured_evaluation_waits_without_inference(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        event = fixture.events[0]
        target_id = capture_key(event.capture_identity)
        self.assertIsNotNone(target_id)
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            handled = handle_normalized_hook(
                event, fixture.settings, budget=OperationBudget(5000)
            )
            self.assertTrue(handled.continue_work)
            with patch(
                "ei.inference.router.ProviderRouter.generate",
                side_effect=AssertionError("trusted closeout inferred a missing decision"),
            ), patch(
                "builtins.input",
                side_effect=AssertionError("trusted closeout requested input"),
            ):
                result = registry.run_adapter_closeout(
                    fixture.host_id,
                    fixture.control_for((event,)),
                    {"candidate": {"candidate_id": "unreviewed-closeout"}},
                    fixture.settings,
                    now=NOW,
                    budget=OperationBudget(5000),
                )

        self.assertEqual(result.exit_code, 5)
        self.assertEqual(result.payload["error_code"], "CLOSEOUT_EVALUATION_REQUIRED")
        self.assertEqual(result.payload["knowledge"], "UNKNOWN")
        self.assertEqual(result.payload["association"]["status"], "PENDING")
        self.assertFalse(result.payload["association"]["acknowledged"])
        self.assertEqual(read_receipt(fixture.settings, target_id).state, "WAITING")
        self.assertEqual(
            [event for event in iter_events(fixture.settings.paths.event_dir)
             if event.event_type == "curation.changeset.applied"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
