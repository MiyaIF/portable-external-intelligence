import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ei.config import load_settings
from ei.hooks.registry import normalize_hook_event
from ei.index import build_index
from ei.journal import append_event, iter_events
from ei.key_provider import InMemoryKeyProvider
from ei.maintainer import _process_claimed, drain_queue, process_failure, run_maintenance
from ei.models import Event
from ei.project import project_events
from ei.queue import QueueState, claim_queue_item, enqueue_receipt, queue_health, read_queue_item
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
    def test_maintenance_default_budget_is_five_minutes_and_rejects_larger_values(self):
        import inspect
        from ei.operation_runtime import OperationBudget

        self.assertEqual(inspect.signature(run_maintenance).parameters["time_budget_ms"].default, 300000)
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            with self.assertRaisesRegex(ValueError, "TIME_BUDGET_MS_INVALID"):
                run_maintenance(settings, time_budget_ms=300001, budget=OperationBudget(300001))

    def test_ingest_keeps_completed_source_results_when_a_later_selection_hits_deadline(self):
        from ei.maintainer import _ingest
        from ei.operation_runtime import OperationBudget

        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            first = Path(tmp) / "first.md"
            second = Path(tmp) / "second.md"
            first.write_text("first", encoding="utf-8")
            second.write_text("second", encoding="utf-8")
            fake_clock = [10.0]
            budget = OperationBudget(10000)
            adapter = SimpleNamespace(host_id="codex-cli", capture_path="codex-memory", parse_skipped=0)
            errors = []

            def recover_page(*_args, **_kwargs):
                fake_clock[0] = budget.deadline
                return SimpleNamespace(
                    created_events=2, rejected=0, scanned=2, secured=2,
                    coverage="COMPLETE", reason_code="SOURCE_CORRELATION_UNKNOWN",
                )

            with patch("ei.maintainer.time.monotonic", side_effect=lambda: fake_clock[0]), \
                    patch("ei.maintainer._adapter", return_value=adapter), \
                    patch("ei.operation_runtime.capture_namespace", return_value=("sha256:" + "a" * 64, "store")), \
                    patch("ei.capture_recovery.recover_page", side_effect=recover_page):
                result = _ingest(settings, (first, second), errors, now=datetime(2026, 1, 1, tzinfo=timezone.utc), budget=budget)

            self.assertEqual(result[0:2], (1, 2))
            self.assertEqual(len(result[5]), 1)
            self.assertEqual(result[5][0]["created_events"], 2)
            self.assertEqual(errors[-1]["error_code"], "OPERATION_BUDGET_EXHAUSTED")

    def test_source_child_deadline_leaves_queue_projection_and_sync_gate_opportunity(self):
        from ei.operation_runtime import OperationBudget

        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            item = self._enqueue_candidate(settings, label="backlog-fairness")
            fake_clock = [100.0]
            key_provider = InMemoryKeyProvider("fairness-test-key", b"f" * 32)
            root_budget = None
            observed = {}

            def exhaust_source(_settings, _paths, errors, *, budget, **_kwargs):
                observed["source_deadline"] = budget.deadline
                fake_clock[0] = budget.deadline
                errors.append({"stage": "ingest", "error_code": "SOURCE_TIME_LIMIT"})
                row = {"status": "partial", "created_events": 2, "reason_code": "SOURCE_TIME_LIMIT"}
                return 1, 2, 0, 0, 0, (row,)

            with patch("ei.maintainer.time.monotonic", side_effect=lambda: fake_clock[0]), \
                    patch("ei.maintainer._ingest", side_effect=exhaust_source), \
                    patch("ei.spool.default_key_provider", return_value=key_provider):
                root_budget = OperationBudget(300000)
                result = run_maintenance(
                    settings, source_paths=(), provider=YesProvider(), time_budget_ms=300000,
                    sync_policy="auto", now=datetime(2026, 8, 26, tzinfo=timezone.utc), budget=root_budget,
                )

            self.assertLess(observed["source_deadline"], root_budget.deadline)
            self.assertEqual(result.queue["completed"], 1)
            self.assertIn(item.queue_id, result.queue["completed_queue_ids"])
            self.assertEqual(result.projection.get("freshness"), "CURRENT")
            self.assertIn("SOURCE_TIME_LIMIT", [row["error_code"] for row in result.errors])
            self.assertEqual(result.sync["status"], "blocked")
            self.assertEqual(result.sync["reason_code"], "PRE_SYNC_CHECKS_FAILED")

    def test_projection_still_updates_when_queue_processing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            event = Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                                 {"observation_id": "obs_saved", "claim": "確認する", "classification": "private-reusable"},
                                 event_id="evt_saved")
            source = append_event(event, settings.paths.event_dir)
            before = source.read_bytes()
            with patch("ei.maintainer.drain_queue", side_effect=RuntimeError("QUEUE_DRAIN_FAILED")):
                result = run_maintenance(settings, sync_policy="disabled")
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.projection.get("freshness"), "CURRENT")
            self.assertEqual(source.read_bytes(), before)
            index = build_index(settings.paths.knowledge_dir, settings.paths.knowledge_dir / "index.json")
            self.assertTrue((Path(index.index_path).parent / "observations/obs_saved.md").is_file())

    def test_concurrent_event_is_reported_as_pending_not_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            def append_after_projection(events, root, **kwargs):
                index = project_events(events, root, **kwargs)
                append_event(Event.create("observation.recorded", "2026-01-01T00:00:00+00:00",
                    "test", "test", {"observation_id": "obs_late", "claim": "遅延した記録",
                    "classification": "private-reusable"}, event_id="evt_late"), settings.paths.event_dir)
                return index
            with patch("ei.maintainer.project_events", side_effect=append_after_projection):
                result = run_maintenance(settings, sync_policy="disabled")
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.projection.get("freshness"), "STALE")
            self.assertIn("PROJECTION_STALE", [row["error_code"] for row in result.errors])
            self.assertEqual(run_maintenance(settings, sync_policy="disabled").projection["freshness"], "CURRENT")

    def _enqueue_candidate(self, settings, *, payload_ref=None, label="candidate"):
        source = source_hash(label)
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

    def test_auth_hold_is_shared_and_inference_deadline_is_not_hook_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            self._enqueue_candidate(settings, label="one")
            self._enqueue_candidate(settings, label="two")
            provider = ErrorProvider("ollama", "AUTH_FAILED")
            budgets = []
            generate = provider.generate
            def capture(schema, data, budget):
                budgets.append(budget)
                return generate(schema, data, budget)
            provider.generate = capture
            result = drain_queue(settings, provider=provider, time_budget_ms=10000)
            self.assertEqual(provider.calls, 1)
            self.assertEqual(result.deferred, 2)
            self.assertGreater(budgets[0].deadline_ms, settings.prompt_budget_ms)
            self.assertLessEqual(budgets[0].deadline_ms, 10000)
            self.assertTrue(budgets[0].run_id)

    def test_empty_queue_does_not_probe_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = ErrorProvider("ollama", "AUTH_FAILED")
            drain_queue(make_settings(tmp), provider=provider)
            self.assertEqual(provider.calls, 0)

    def test_candidates_in_one_drain_receive_the_same_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            self._enqueue_candidate(settings, label="one")
            self._enqueue_candidate(settings, label="two")
            provider = YesProvider()
            budgets = []
            generate = provider.generate
            def capture(schema, data, budget):
                budgets.append(budget)
                return generate(schema, data, budget)
            with patch.object(provider, "generate", side_effect=capture), patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                result = drain_queue(settings, provider=provider, time_budget_ms=10000)
            self.assertEqual(result.completed, 2)
            self.assertEqual(budgets[0].run_id, budgets[1].run_id)
            self.assertNotEqual(budgets[0].attempt_id, budgets[1].attempt_id)

    def test_exhausted_maintenance_budget_defers_without_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            self._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            item = claim_queue_item("worker", settings, now=now)
            provider = ErrorProvider("ollama", "AUTH_FAILED")
            outcome, updated = _process_claimed(item, settings, provider, now, maintenance_remaining_ms=0)
            self.assertEqual(outcome, "deferred")
            self.assertEqual(updated.last_error_code, "DEADLINE_EXCEEDED")
            self.assertEqual(provider.calls, 0)

    def test_storage_failure_preserves_recovery_opportunity_after_retry_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            item = self._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            with patch("ei.maintainer.save_validated_result", side_effect=OSError("disk full")):
                for step in range(5):
                    drain_queue(settings, provider=YesProvider(), now=now + timedelta(days=step))
            self.assertEqual(read_queue_item(item.queue_id, settings).state, QueueState.DEFERRED)

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
            key_provider = InMemoryKeyProvider("maintainer-drain-test-key", b"d" * 32)
            with patch("ei.spool.default_key_provider", return_value=key_provider):
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
                (Path(build_index(settings.paths.knowledge_dir, settings.paths.knowledge_dir / "index.json").index_path).parent / "manifest.json").is_file(),
                "KNOWLEDGE_PROJECTION_MANIFEST_MISSING",
            )
            self.assertIn("projection", result.to_dict(), "MAINTENANCE_PROJECTION_MISSING")
            self.assertIn("personal", result.to_dict(), "MAINTENANCE_PERSONAL_SECTION_MISSING")
            self.assertEqual(result.to_dict()["team"], {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})


if __name__ == "__main__":
    unittest.main()
