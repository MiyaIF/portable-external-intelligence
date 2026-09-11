import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ei.config import load_settings
from ei.hooks.registry import normalize_hook_event
from ei.journal import append_event, iter_events
from ei.key_provider import InMemoryKeyProvider
from ei.maintainer import drain_queue, process_failure, run_maintenance
from ei.models import Event
from ei.queue import QueueState, enqueue_receipt, queue_health, read_queue_item
from ei.spool import write_spool
from ei.setup_contract import OrganizerSelection


class YesProvider:
    provider_id = "local-test"
    locality = "local"

    def available(self):
        return True

    def generate(self, schema_name, input_json, budget):
        from ei.inference.base import ProviderResult

        del schema_name, budget
        evidence = list(input_json.get("evidence_refs", ()))
        return ProviderResult(
            self.provider_id,
            "success",
            output={
                "decision": "YES",
                "reason_code": "evidence_verified",
                "candidate_title": str(input_json.get("title", "validated candidate")),
                "candidate_claim": str(input_json.get("claim", "")),
                "evidence_refs": evidence,
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "confidence": 0.95,
                "applicability_scope": "universal",
                "applicable_host_ids": [],
                "applicable_host_families": [],
            },
            schema_name="gate-decision",
        )


class ErrorProvider:
    locality = "local"

    def __init__(self, provider_id, error_code):
        self.provider_id = provider_id
        self.error_code = error_code
        self.calls = 0

    def available(self):
        return True

    def generate(self, schema_name, input_json, budget):
        from ei.inference.base import ProviderResult

        del schema_name, input_json, budget
        self.calls += 1
        return ProviderResult(self.provider_id, "failed", error_code=self.error_code)


def make_settings(root):
    workspace = Path(root).resolve()
    engine = workspace / "engine"
    (engine / "config").mkdir(parents=True, exist_ok=True)
    (engine / "config" / "defaults.json").write_text(
        json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}, ensure_ascii=False),
        encoding="utf-8",
    )
    settings = load_settings(engine, workspace / "codex", runtime_root=workspace / "runtime")
    return replace(
        settings,
        organizer=OrganizerSelection("READY", "ollama", None),
        provider_order=("ollama",),
    )


def source_hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


class MaintainerTests(unittest.TestCase):
    def _enqueue_candidate(self, settings, *, payload_ref=None):
        source = source_hash("candidate")
        event = Event.create_v2(
            "observation.recorded",
            "maintainer-test",
            "machine-test",
            {
                "observation_id": "obs_error",
                "title": "Queue candidate",
                "claim": "同じ構造を別案件でも検証し再利用可能な判断ルールとして記録する",
                "source_kind": "agent_direct",
                "source_ref_hash": source_hash("ref"),
                "source_hash": source,
                "evidence_refs": [source],
                "provenance_key": source,
                "cwd_fingerprint": source_hash("cwd:error"),
                "outcome_status": "success",
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
                "applicability_scope": "host",
                "applicable_host_ids": ["codex-cli"],
                "applicable_host_families": [],
            },
            datetime(2026, 8, 26, tzinfo=timezone.utc),
        )
        append_event(event, settings.paths.event_dir)
        return enqueue_receipt(event, payload_ref, settings)

    def test_malformed_response_retries_then_requires_attention(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            item = self._enqueue_candidate(settings)
            first = process_failure(item, "MALFORMED_RESPONSE", max_attempts=3, now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            self.assertEqual(first.state, QueueState.FAILED_RETRYABLE)
            second = process_failure(replace(first, attempts=3), "MALFORMED_RESPONSE", max_attempts=3, now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            self.assertEqual(second.state, QueueState.FAILED_NEEDS_ATTENTION)

    def test_persistable_privacy_safety_reasons_quarantine_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            item = self._enqueue_candidate(settings)
            for reason in (
                "SECRET_PATTERN_MATCH",
                "ABSOLUTE_PATH_FORBIDDEN",
                "UNICODE_CONTROL_FORBIDDEN",
                "IDENTIFIER_HASH_REQUIRED",
                "PERSONAL_OR_CLIENT_IDENTIFIER_FORBIDDEN",
                "MACHINE_LOCAL_SOURCE",
                "MACHINE_LOCAL_PATH",
                "PAYLOAD_TOO_LARGE",
                "CHANGESET_TOO_LARGE",
                "PRIVACY_REJECTED",
                "RAW_CONTENT_FORBIDDEN",
                "PATH_TRAVERSAL",
            ):
                with self.subTest(reason=reason):
                    updated = process_failure(
                        replace(item, attempts=1),
                        reason,
                        max_attempts=3,
                        now=datetime(2026, 8, 26, tzinfo=timezone.utc),
                    )
                    self.assertEqual(updated.state, QueueState.QUARANTINED)
                    self.assertEqual(updated.payload_ref, item.payload_ref)

    def test_unavailable_organizer_defers_without_discarding_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            key_provider = InMemoryKeyProvider("maintainer-unavailable-test-key", b"u" * 32)
            with patch("ei.spool.default_key_provider", return_value=key_provider):
                ref = write_spool(
                    json.dumps({"title": "candidate", "claim": "同じ構造を別案件でも検証し再利用可能な判断ルールとして記録する"}),
                    "private-reusable",
                    settings,
                    now=datetime(2026, 8, 26, tzinfo=timezone.utc),
                )
                item = self._enqueue_candidate(settings, payload_ref=ref)
                result = drain_queue(
                    settings,
                    provider=ErrorProvider("ollama", "PROVIDER_UNAVAILABLE"),
                    max_items=1,
                    now=datetime(2026, 8, 26, tzinfo=timezone.utc),
                )
                updated = read_queue_item(item.queue_id, settings)
                self.assertEqual(result.deferred, 1)
                self.assertEqual(updated.state, QueueState.DEFERRED)
                self.assertTrue(updated.payload_ref)

    def test_drain_is_bounded_and_processes_a_valid_queue_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            first = source_hash("first")
            second = source_hash("second")
            event = Event.create_v2(
                "observation.recorded",
                "maintainer-test",
                "machine-test",
                {
                    "observation_id": "obs_queue",
                    "title": "Queue candidate",
                    "claim": "同じ構造を別案件でも検証し再利用可能な判断ルールとして記録する",
                    "source_kind": "agent_direct",
                    "source_ref_hash": source_hash("ref"),
                    "source_hash": first,
                    "evidence_refs": [first, second],
                    "provenance_key": first,
                    "cwd_fingerprint": source_hash("cwd:one"),
                    "domain": "testing",
                    "outcome_status": "success",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "source_host_id": "codex-cli",
                    "source_host_family": "codex-compatible",
                    "applicability_scope": "host",
                    "applicable_host_ids": ["codex-cli"],
                    "applicable_host_families": [],
                },
                datetime(2026, 8, 26, tzinfo=timezone.utc),
            )
            append_event(event, settings.paths.event_dir)
            item = enqueue_receipt(event, None, settings)
            result = drain_queue(settings, provider=YesProvider(), max_items=1, time_budget_ms=5000)
            self.assertEqual(result.processed, 1)
            self.assertEqual(result.remaining, 0)
            self.assertEqual(queue_health(settings).terminal, 1)
            event_types = [entry.event_type for entry in iter_events(settings.paths.event_dir)]
            self.assertIn("curation.changeset.applied", event_types)
            self.assertIn(item.queue_id, result.completed_queue_ids)

    def test_maintenance_continues_after_independent_source_failure_and_gcs_expired_spool(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            valid = Path(tmp) / "valid.md"
            valid.write_text("## Reusable knowledge\n- 書込後は再読込して確認する\n", encoding="utf-8")
            invalid = Path(tmp) / "invalid.md"
            invalid.write_bytes(b"\xff\xfe")
            write_spool(
                "temporary private text",
                "private-reusable",
                settings,
                now=datetime(2020, 1, 1, tzinfo=timezone.utc),
                ttl_seconds=1,
                key_provider=InMemoryKeyProvider("maintainer-test-key", b"m" * 32),
            )
            result = run_maintenance(
                settings,
                source_paths=(valid, invalid),
                provider=YesProvider(),
                time_budget_ms=5000,
                sync_policy="disabled",
                now=datetime(2020, 1, 2, tzinfo=timezone.utc),
            )
            self.assertEqual(result.status, "partial", "MAINTENANCE_STATUS_UNEXPECTED")
            self.assertGreaterEqual(result.expired_spool, 1, "EXPIRED_SPOOL_NOT_COLLECTED")
            self.assertGreaterEqual(result.ingest_sources, 2, "INGEST_SOURCE_COUNT_INCOMPLETE")
            self.assertTrue(
                (settings.paths.knowledge_dir / "manifest.json").is_file(),
                "KNOWLEDGE_PROJECTION_MANIFEST_MISSING",
            )
            self.assertIn("projection", result.to_dict(), "MAINTENANCE_PROJECTION_MISSING")
            self.assertIn("personal", result.to_dict(), "MAINTENANCE_PERSONAL_SECTION_MISSING")
            self.assertEqual(result.to_dict()["team"], {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})


if __name__ == "__main__":
    unittest.main()
