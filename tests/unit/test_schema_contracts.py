from __future__ import annotations

import copy
import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.journal import JournalIntegrityError, validate_schema
from tests.helpers import make_event_v2, make_observation_state


class SchemaContractTests(unittest.TestCase):
    def test_install_manifest_schema_is_v8_and_closed_for_store_descriptors(self):
        schema_path = Path(__file__).resolve().parents[2] / "schemas" / "install-manifest.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        self.assertEqual(schema["properties"]["schema_version"], {"const": 8})
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("knowledge_stores", schema["required"])
        self.assertIn("reconciliation", schema["required"])
        stores = schema["$defs"]["knowledgeStores"]
        self.assertFalse(stores["additionalProperties"])
        self.assertFalse(schema["$defs"]["personalKnowledgeStore"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["teamKnowledgeStore"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["reconciliation"]["additionalProperties"])

    def test_host_profile_schema_declares_exact_family_adapter_pairs(self):
        schema_path = Path(__file__).resolve().parents[2] / "schemas" / "host-profile.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        pairs = {
            (item["properties"]["host_family"]["const"], item["properties"]["adapter_id"]["const"])
            for item in schema["allOf"][0]["oneOf"]
        }
        self.assertEqual(
            pairs,
            {
                ("codex-compatible", "codex-cli"),
                ("claude-compatible", "claude-code"),
                ("gemini-compatible", "gemini-cli"),
                ("qwen-compatible", "qwen-code"),
            },
        )

    def test_host_profile_and_manifest_schema_ids_are_windows_safe_lowercase(self):
        schemas = Path(__file__).resolve().parents[2] / "schemas"
        profile = json.loads((schemas / "host-profile.schema.json").read_text(encoding="utf-8"))
        manifest = json.loads((schemas / "install-manifest.schema.json").read_text(encoding="utf-8"))
        profile_pattern = re.compile(profile["properties"]["host_id"]["pattern"])
        manifest_pattern = re.compile(manifest["properties"]["hosts"]["propertyNames"]["pattern"])
        self.assertIsNotNone(profile_pattern.fullmatch("test-compatible-cli"))
        self.assertIsNotNone(manifest_pattern.fullmatch("test-compatible-cli"))
        for host_id in (
            "MyCLI",
            "test:cli",
            "test.",
            "CON",
            "COM1",
            "LPT9",
            "codex",
            "claude",
            "gemini",
            "qwen",
            "codex-app",
            "codex-cli",
            "claude-code",
            "gemini-cli",
            "qwen-code",
        ):
            with self.subTest(host_id=host_id):
                self.assertIsNone(profile_pattern.fullmatch(host_id))
                if host_id in {"codex-cli", "claude-code", "gemini-cli", "qwen-code"}:
                    self.assertIsNotNone(manifest_pattern.fullmatch(host_id))
                else:
                    self.assertIsNone(manifest_pattern.fullmatch(host_id))

    def test_team_store_schemas_are_closed_and_use_append_only_layout(self):
        schemas = Path(__file__).resolve().parents[2] / "schemas"
        team_store = json.loads((schemas / "team-store-manifest.schema.json").read_text(encoding="utf-8"))
        team_event = json.loads((schemas / "team-event.schema.json").read_text(encoding="utf-8"))

        self.assertFalse(team_store["additionalProperties"])
        self.assertEqual(team_store["properties"]["layout"], {"const": "member-writer-events-v1"})
        self.assertFalse(team_event["additionalProperties"])
        self.assertEqual(team_event["properties"]["schema_version"], {"const": 2})

    def test_team_routing_and_outbox_schemas_are_closed(self):
        schemas = Path(__file__).resolve().parents[2] / "schemas"
        routing = json.loads((schemas / "team-routing-decision.schema.json").read_text(encoding="utf-8"))
        outbox = json.loads((schemas / "team-outbox-item.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(routing["additionalProperties"])
        self.assertFalse(routing["properties"]["normalized_payload"]["additionalProperties"])
        self.assertFalse(outbox["additionalProperties"])
        self.assertIn("spool_ref", outbox["required"])

    def test_hook_event_valid_and_forbids_transient_or_raw_content(self):
        valid = {
            "event_id": "evt_20260826T000000000000Z_abcdef123456",
            "idempotency_key": "sha256:" + "1" * 64,
            "host_id": "codex",
            "host_instance_id": "desktop-host-a",
            "host_event_name": "UserPromptSubmit",
            "normalized_event_name": "user_prompt_submit",
            "session_id_hash": "sha256:" + "2" * 64,
            "turn_id_hash": "sha256:" + "3" * 64,
            "cwd_hash": "sha256:" + "4" * 64,
            "source_ref": "turn://source/1",
            "source_hash": "sha256:" + "5" * 64,
            "payload_hash": "sha256:" + "6" * 64,
            "received_at": "2026-08-26T00:00:00Z",
            "privacy_classification": "private-reusable",
        }
        validate_schema("hook-event", valid)

        invalid_transient = copy.deepcopy(valid)
        invalid_transient["transient_input"] = "secret prompt"
        with self.assertRaisesRegex(JournalIntegrityError, "hook-event"):
            validate_schema("hook-event", invalid_transient)

        invalid_raw = copy.deepcopy(valid)
        invalid_raw["raw_response"] = {"secret": "body"}  # pragma: allowlist secret
        with self.assertRaisesRegex(JournalIntegrityError, "hook-event"):
            validate_schema("hook-event", invalid_raw)

    def test_queue_item_requires_spool_ref_and_forbids_body(self):
        valid = {
            "queue_id": "queue_20260826_0001",
            "event_id": "evt_20260826T000000000000Z_abcdef123456",
            "idempotency_key": "sha256:" + "1" * 64,
            "stage": "capture",
            "state": "PENDING",
            "attempts": 0,
            "created_at": "2026-08-26T00:00:00Z",
            "next_eligible_at": None,
            "source_ref": "turn://source/1",
            "source_hash": "sha256:" + "2" * 64,
            "host_id": "codex",
            "session_id_hash": "sha256:" + "3" * 64,
            "turn_id_hash": "sha256:" + "4" * 64,
            "payload_ref": {
                "spool_id": "spool_20260826_0001",
                "content_hash": "sha256:" + "5" * 64,
                "classification": "private-reusable",
                "created_at": "2026-08-26T00:00:00Z",
                "expires_at": "2026-08-27T00:00:00Z",
                "key_id": "key-2026-08",
                "encrypted": True,
            },
            "provider_preference": ["openai"],
            "privacy_classification": "private-reusable",
            "lease_owner": None,
            "lease_expires_at": None,
            "last_error_code": None,
        }
        validate_schema("queue-item", valid)

        invalid_body = copy.deepcopy(valid)
        invalid_body["body"] = "secret"
        with self.assertRaisesRegex(JournalIntegrityError, "queue-item"):
            validate_schema("queue-item", invalid_body)

        invalid_payload_ref = copy.deepcopy(valid)
        invalid_payload_ref["payload_ref"] = {"spool_id": "spool_only"}
        with self.assertRaisesRegex(JournalIntegrityError, "queue-item"):
            validate_schema("queue-item", invalid_payload_ref)

    def test_spool_item_and_envelope_require_aes_256_gcm_and_96_bit_nonce(self):
        spool_ref = {
            "spool_id": "spool_20260826_0001",
            "content_hash": "sha256:" + "1" * 64,
            "classification": "private-reusable",
            "created_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-08-27T00:00:00Z",
            "key_id": "key-2026-08",
            "encrypted": True,
        }
        validate_schema("spool-item", spool_ref)

        envelope = {
            "spool_id": "spool_20260826_0001",
            "algorithm": "AES-256-GCM",
            "nonce": "AAECAwQFBgcICQoL",
            "ciphertext": "AQIDBAUGBwgJCgsMDQ4PEA==",
            "aad_sha256": "sha256:" + "2" * 64,
            "content_sha256": "sha256:" + "3" * 64,
            "classification": "private-reusable",
            "created_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-08-27T00:00:00Z",
            "key_id": "key-2026-08",
        }
        validate_schema("spool-envelope", envelope)

        invalid_algorithm = copy.deepcopy(envelope)
        invalid_algorithm["algorithm"] = "AES-128-GCM"
        with self.assertRaisesRegex(JournalIntegrityError, "spool-envelope"):
            validate_schema("spool-envelope", invalid_algorithm)

        invalid_nonce = copy.deepcopy(envelope)
        invalid_nonce["nonce"] = "AQID"
        with self.assertRaisesRegex(JournalIntegrityError, "spool-envelope"):
            validate_schema("spool-envelope", invalid_nonce)

    def test_gate_decision_yes_no_only_and_changeset_operations_fixed(self):
        valid_gate = {
            "decision": "YES",
            "reason_code": "EVIDENCE_SUFFICIENT",
            "candidate_title": "タイトル",
            "candidate_claim": "20文字以上の検証済み判断をここに記録する",
            "evidence_refs": ["sha256:" + "1" * 64],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "confidence": 0.9,
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        }
        validate_schema("gate-decision", valid_gate)

        invalid_gate = copy.deepcopy(valid_gate)
        invalid_gate["decision"] = "MAYBE"
        with self.assertRaisesRegex(JournalIntegrityError, "gate-decision"):
            validate_schema("gate-decision", invalid_gate)

        valid_changeset = {
            "changeset_id": "chg_20260826_0001",
            "candidate_id": "cand_20260826_0001",
            "operations": [
                {
                    "operation": "CREATE_OBSERVATION",
                    "target_id": "obs_20260826_0001",
                    "payload": {"title": "タイトル"},
                },
                {
                    "operation": "NO_CHANGE",
                    "target_id": None,
                    "payload": {},
                },
            ],
            "source_hashes": ["sha256:" + "2" * 64],
            "policy_version": "2026-08-26",
            "generated_at": "2026-08-26T00:00:00Z",
            "provider_id": "openai",
        }
        validate_schema("change-set", valid_changeset)

        invalid_changeset = copy.deepcopy(valid_changeset)
        invalid_changeset["operations"][0]["operation"] = "DELETE_FILE"
        with self.assertRaisesRegex(JournalIntegrityError, "change-set"):
            validate_schema("change-set", invalid_changeset)

    def test_root_and_installed_scope_schemas_are_identical(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("change-set.schema.json", "gate-decision.schema.json"):
            with self.subTest(name=name):
                root_schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
                skill_schema = json.loads(
                    (root / "skills" / "external-intelligence" / "schemas" / name).read_text(encoding="utf-8")
                )
                self.assertEqual(root_schema, skill_schema)

    def test_host_receipt_and_release_evidence_subject_vs_attestation_rules(self):
        receipt = {
            "receipt_id": "rcpt_20260826_0001",
            "mode": "real",
            "host_id": "codex",
            "host_instance_id": "desktop-host-a",
            "host_version": "1.2.3",
            "os_family": "windows",
            "os_version": "11",
            "python_version": "3.11.9",
            "artifact_sha256": "sha256:" + "1" * 64,
            "event_sha256": "sha256:" + "2" * 64,
            "activation_state": "ACTIVE",
            "certified_at": "2026-08-26T00:00:00Z",
        }
        validate_schema("host-certification-receipt", receipt)

        fixture = copy.deepcopy(receipt)
        fixture["mode"] = "fixture"
        validate_schema("host-certification-receipt", fixture)

        manifest = {
            "evidence_type": "subject_manifest",
            "subject_commit_sha": "a" * 40,
            "manifest_sha256": "sha256:" + "3" * 64,
            "workflow_sha256": "sha256:" + "4" * 64,
            "certification_sha256": ["sha256:" + "5" * 64],
        }
        validate_schema("release-evidence", manifest)

        invalid_manifest = copy.deepcopy(manifest)
        invalid_manifest["evidence_commit_sha"] = "b" * 40
        with self.assertRaisesRegex(JournalIntegrityError, "release-evidence"):
            validate_schema("release-evidence", invalid_manifest)

        attestation = {
            "evidence_type": "post_push_attestation",
            "subject_commit_sha": "a" * 40,
            "evidence_commit_sha": "b" * 40,
            "manifest_sha256": "sha256:" + "3" * 64,
            "workflow_sha256": "sha256:" + "4" * 64,
            "certification_sha256": ["sha256:" + "5" * 64],
            "attested_at": "2026-08-26T00:00:00Z",
        }
        validate_schema("release-evidence", attestation)

        invalid_attestation = copy.deepcopy(attestation)
        del invalid_attestation["evidence_commit_sha"]
        with self.assertRaisesRegex(JournalIntegrityError, "release-evidence"):
            validate_schema("release-evidence", invalid_attestation)

    def test_event_and_observation_round_trip_examples_validate(self):
        event = make_event_v2()
        validate_schema("event", event.to_dict())

        invalid_event = event.to_dict()
        invalid_event["payload"]["raw_response"] = {"secret": "body"}  # pragma: allowlist secret
        with self.assertRaisesRegex(JournalIntegrityError, "event"):
            validate_schema("event", invalid_event)

        observation = make_observation_state()
        observation_payload = {
            "observation_id": observation.observation_id,
            "title": observation.title,
            "claim": observation.claim,
            "domain": observation.domain,
            "cwd_fingerprint": observation.cwd_fingerprint,
            "provenance_key": observation.provenance_key,
            "outcome_status": observation.outcome_status,
            "benefit": observation.benefit,
            "classification": observation.classification,
            "source_hash": observation.source_hash,
            "applicability": list(observation.applicability),
        }
        validate_schema("observation", observation_payload)

        invalid_observation = dict(observation_payload)
        invalid_observation["candidate_text"] = "raw source"
        with self.assertRaisesRegex(JournalIntegrityError, "observation"):
            validate_schema("observation", invalid_observation)


if __name__ == "__main__":
    unittest.main()
