import tempfile
import unittest
import json
from contextlib import nullcontext
from types import SimpleNamespace
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ei.key_provider import InMemoryKeyProvider
from ei.maintainer import drain_queue
from ei.queue import read_queue_item, QueueState, enqueue_receipt
from ei.journal import append_event, iter_events
from ei.models import Event
from ei.maintainer import _candidate_for, _RouterAdapter, MaintenanceError
from ei.inference.cli_subscription import SubscriptionCLIProvider
from ei.inference.router import ProviderRouter
from ei.inference.base import InferenceBudget, ProviderResult
from ei.gate import GateDecision
from ei.inference.budget import BudgetLedger, BudgetPolicy
from ei.ids import stable_hash
from ei.setup_contract import OrganizerSelection
from ei.organizer_recovery import OrganizerRecovery, load_validated_result
from ei.spool import SpoolError, write_spool
from tests.unit import test_maintainer as fixtures


class OrganizerRestartTests(unittest.TestCase):
    def test_empty_queue_does_not_consume_pending_resume_or_call_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            ledger = BudgetLedger(settings)
            organizer = settings.organizer
            class Provider(fixtures.YesProvider):
                provider_id = "ollama"
            router = ProviderRouter([Provider()], organizer=organizer, budget_ledger=ledger)
            provider = router.selected()
            adapter = _RouterAdapter(router)
            path = settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json")
            fingerprint = "sha256:" + stable_hash({"organizer": router.organizer.to_dict(), "config": router.config})
            recovery = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"),
                datetime(2026, 9, 25, tzinfo=timezone.utc))
            self.assertEqual(recovery.request_auth_retry(provider, now=datetime(2026, 9, 25, tzinfo=timezone.utc),
                config_fingerprint=fingerprint)["status"], "RETRY_REQUESTED")
            before = recovery.snapshot()
            with patch.object(provider, "generate", wraps=provider.generate) as generate:
                result = drain_queue(settings, provider=adapter, now=datetime(2026, 9, 26, tzinfo=timezone.utc))
                generate.assert_not_called()
            self.assertEqual(result.attempted, 0)
            self.assertEqual(OrganizerRecovery(path, "ollama").snapshot(), before)

    def test_explicit_resume_retries_same_router_organizer_through_real_budget_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            fixtures.MaintainerTests()._enqueue_candidate(settings, label="auth-resume")
            # Admit two attempts for the first candidate plus the distinct
            # backlog candidate; refusal behavior is covered separately below.
            policy = replace(BudgetPolicy(), per_run_input_tokens=40_000, per_run_output_tokens=10_000,
                per_candidate_input_tokens=24_000, per_candidate_output_tokens=6_000)
            ledger = BudgetLedger(settings, policy=policy)
            now = datetime.now(timezone.utc)

            class AuthOnceProvider(fixtures.YesProvider):
                provider_id = "ollama"

                def __init__(self):
                    self.calls = 0

                def generate(self, schema_name, input_json, budget):
                    self.calls += 1
                    if self.calls == 1:
                        from ei.inference.base import ProviderResult
                        return ProviderResult(self.provider_id, "failed", error_code="AUTH_FAILED")
                    return super().generate(schema_name, input_json, budget)

            provider = AuthOnceProvider()
            router = ProviderRouter([provider], organizer=settings.organizer, budget_ledger=ledger)
            adapter = _RouterAdapter(router)
            path = settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json")
            fingerprint = "sha256:" + stable_hash({"organizer": router.organizer.to_dict(), "config": router.config})
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                first = drain_queue(settings, provider=adapter, now=now, time_budget_ms=30000)
                self.assertEqual(first.deferred, 1, f"first={first!r}; provider_calls={provider.calls}")
                held = OrganizerRecovery(path, "ollama").snapshot()
                self.assertEqual(held["reason_code"], "AUTH_FAILED")
                source = fixtures.source_hash("backlog-after-resume")
                backlog_event = Event.create_v2("observation.recorded", "maintainer-test", "machine-test", {
                    "observation_id": "obs_after_resume", "title": "Distinct backlog candidate",
                    "claim": "別の証拠を確認した後で再利用可能な判断を記録する", "source_kind": "agent_direct",
                    "source_ref_hash": fixtures.source_hash("backlog-ref"), "source_hash": source,
                    "evidence_refs": [source], "provenance_key": source,
                    "cwd_fingerprint": fixtures.source_hash("backlog-cwd"), "outcome_status": "success",
                    "benefit": "reduced_rework", "classification": "private-reusable",
                    "source_host_id": "codex-cli", "source_host_family": "codex-compatible",
                    "applicability_scope": "host", "applicable_host_ids": ["codex-cli"],
                    "applicable_host_families": [],
                }, now + timedelta(seconds=1))
                append_event(backlog_event, settings.paths.event_dir)
                enqueue_receipt(backlog_event, None, settings, now=now + timedelta(seconds=1))
                requested = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).request_auth_retry(
                    provider, now=now + timedelta(seconds=30), config_fingerprint=fingerprint)
                self.assertEqual(requested["status"], "RETRY_REQUESTED")
                retried = drain_queue(settings, provider=adapter, now=now + timedelta(hours=1), time_budget_ms=30000)

            self.assertEqual((retried.processed, retried.completed, retried.deferred), (2, 2, 0), repr(retried))
            self.assertEqual(provider.calls, 3)
            final = OrganizerRecovery(path, "ollama").snapshot()
            self.assertFalse(final["needs_action"])
            self.assertEqual(final["reason_code"], "READY")
            reservations = ledger.snapshot()["reservations"]
            self.assertEqual(len(reservations), 3)
            self.assertTrue(all(entry["settled"] for entry in reservations.values()))

    def test_second_explicit_resume_after_auth_failure_uses_real_router_and_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            fixtures.MaintainerTests()._enqueue_candidate(settings, label="auth-resume-twice")
            policy = replace(BudgetPolicy(), per_run_input_tokens=40_000, per_run_output_tokens=10_000,
                per_candidate_input_tokens=40_000, per_candidate_output_tokens=10_000)
            ledger = BudgetLedger(settings, policy=policy)
            now = datetime(2026, 9, 18, tzinfo=timezone.utc)

            class AuthFailsTwiceProvider(fixtures.YesProvider):
                provider_id = "ollama"

                def __init__(self):
                    self.calls = 0

                def generate(self, schema_name, input_json, budget):
                    self.calls += 1
                    if self.calls <= 2:
                        return ProviderResult(self.provider_id, "failed", error_code="AUTH_FAILED")
                    return super().generate(schema_name, input_json, budget)

            provider = AuthFailsTwiceProvider()
            router = ProviderRouter([provider], organizer=settings.organizer, budget_ledger=ledger)
            adapter = _RouterAdapter(router)
            path = settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json")
            fingerprint = "sha256:" + stable_hash({"organizer": router.organizer.to_dict(), "config": router.config})
            recovery = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)

            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                first = drain_queue(settings, provider=adapter, now=now, time_budget_ms=30000)
                self.assertEqual(first.deferred, 1)
                self.assertEqual(provider.calls, 1)
                first_due = datetime.fromisoformat(recovery.snapshot()["next_eligible_at"])
                self.assertEqual(recovery.request_auth_retry(provider, now=now,
                    config_fingerprint=fingerprint)["status"], "RETRY_REQUESTED")

                failed_resume = drain_queue(settings, provider=adapter, now=first_due, time_budget_ms=30000)
                self.assertEqual(failed_resume.deferred, 1)
                self.assertEqual(provider.calls, 2)
                failed_state = recovery.snapshot()
                self.assertEqual(failed_state["reason_code"], "AUTH_FAILED")
                self.assertTrue(failed_state["retry_consumed"])
                second_due = datetime.fromisoformat(failed_state["next_eligible_at"])
                request_at = second_due - timedelta(seconds=1)
                self.assertEqual(recovery.request_auth_retry(provider, now=request_at,
                    config_fingerprint=fingerprint)["status"], "RETRY_REQUESTED")
                fresh = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
                try:
                    pending = fresh.snapshot()
                except ValueError as exc:
                    self.fail(f"second explicit resume made organizer state unreadable: {exc}")
                self.assertTrue(pending["retry_consumed"])
                self.assertEqual(pending["retry_request"]["requested_at"], request_at.isoformat().replace("+00:00", "Z"))

                resumed = drain_queue(settings, provider=adapter, now=second_due, time_budget_ms=30000)

            self.assertEqual((resumed.processed, resumed.completed, resumed.deferred), (1, 1, 0))
            self.assertEqual(provider.calls, 3)
            ready = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).snapshot()
            self.assertFalse(ready["needs_action"])
            self.assertEqual(ready["reason_code"], "READY")
            self.assertFalse(ready["retry_consumed"])
            self.assertIsNone(ready["retry_request"])
            reservations = ledger.snapshot()["reservations"]
            self.assertEqual(len(reservations), 3)
            self.assertTrue(all(entry["settled"] for entry in reservations.values()))

    def test_after_call_failure_never_restores_admission_state(self):
        for failure in ("provider-budget-code", "provider-forged-flag", "settlement-failure"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                settings = fixtures.make_settings(tmp)
                fixtures.MaintainerTests()._enqueue_candidate(settings, label="first")
                ledger = BudgetLedger(settings)
                provider = fixtures.ErrorProvider("ollama", "TOKEN_CAP_EXCEEDED")
                result = ProviderResult("ollama", "failed", error_code="TOKEN_CAP_EXCEEDED",
                    admission_refused=failure == "provider-forged-flag")
                router = ProviderRouter([provider], organizer=settings.organizer, budget_ledger=ledger)
                adapter = _RouterAdapter(router)
                now = datetime.now(timezone.utc)
                fault = patch.object(ledger, "settle", side_effect=OSError("disk full")) if failure == "settlement-failure" else nullcontext()
                with patch.object(provider, "generate", return_value=result) as generate, fault:
                    self.assertEqual(drain_queue(settings, provider=adapter, now=now).deferred, 1)
                    fixtures.MaintainerTests()._enqueue_candidate(settings, label="second")
                    self.assertEqual(drain_queue(settings, provider=adapter, now=now).deferred, 1)
                    self.assertEqual(generate.call_count, 1)
                state = OrganizerRecovery(settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json"), "ollama").snapshot()
                self.assertEqual(state["attempts"], 1)
                self.assertEqual(state["reason_code"], "BUDGET_STORAGE_UNAVAILABLE" if failure == "settlement-failure" else "TOKEN_CAP_EXCEEDED")
                reservations = ledger.snapshot()["reservations"]
                self.assertEqual(len(reservations), 1)
                reservation = next(iter(reservations.values()))
                self.assertEqual((reservation["input_tokens"], reservation["output_tokens"]), (12000, 3000))
                self.assertEqual(reservation["settled"], failure != "settlement-failure")

    def test_prior_adapter_refusal_does_not_leak_into_gate_without_generate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            ledger = BudgetLedger(settings)
            provider = fixtures.ErrorProvider("ollama", "PROVIDER_UNAVAILABLE")
            adapter = _RouterAdapter(ProviderRouter([provider], organizer=settings.organizer, budget_ledger=ledger))
            rejected = adapter.generate("gate-decision", {}, InferenceBudget())
            self.assertTrue(rejected.admission_refused)
            self.assertTrue(adapter.admission_refused)
            fixtures.MaintainerTests()._enqueue_candidate(settings)
            # A gate can stop without generate; adapter evidence from another
            # operation must not turn an unknown failure into a proven refusal.
            with patch("ei.maintainer.decide_inheritance", return_value=GateDecision("FAILED", "VALIDATION_FAILED")):
                drain_queue(settings, provider=adapter)
            state = OrganizerRecovery(settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json"), "ollama").snapshot()
            self.assertEqual(state["attempts"], 1)
            self.assertEqual(state["reason_code"], "VALIDATION_FAILED")
            self.assertEqual(provider.calls, 0)

    def test_budget_admission_refusal_does_not_hold_other_candidate(self):
        for scope in ("candidate-attempt", "candidate-token", "run-token"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as tmp:
                settings = fixtures.make_settings(tmp)
                first = fixtures.MaintainerTests()._enqueue_candidate(settings, label="first")
                now = datetime.now(timezone.utc)
                policy = replace(BudgetPolicy(), retry_limit=1) if scope == "candidate-attempt" else BudgetPolicy()
                ledger = BudgetLedger(settings, policy=policy)
                seed = InferenceBudget(max_input_tokens=1, max_output_tokens=2000 if scope == "run-token" else 0,
                    candidate_id=first.queue_id, run_id="blocked-run" if scope == "run-token" else "prior-run")
                self.assertTrue(ledger.reserve("seed", "ollama", seed, now).allowed)
                provider = fixtures.YesProvider()
                provider.provider_id = "ollama"
                alternative = fixtures.ErrorProvider("subscription-cli", "PROVIDER_UNAVAILABLE")
                router = ProviderRouter([provider, alternative], organizer=settings.organizer, budget_ledger=ledger)
                recovery = OrganizerRecovery(settings.paths.runtime_dir / ("organizer-" + stable_hash("ollama") + ".json"), "ollama")
                before = recovery.snapshot()
                with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()), patch.object(provider, "generate", wraps=provider.generate) as generate, patch("ei.inference.router.datetime", wraps=datetime) as clock:
                    clock.now.return_value = now
                    refused = drain_queue(settings, provider=_RouterAdapter(router), now=now, run_id="blocked-run")
                    self.assertEqual(refused.deferred, 1)
                    self.assertEqual(generate.call_count, 0)
                    saved = read_queue_item(first.queue_id, settings)
                    self.assertEqual(saved.state, QueueState.DEFERRED)
                    self.assertEqual(saved.last_error_code, "ATTEMPT_CAP_EXCEEDED" if scope == "candidate-attempt" else "TOKEN_CAP_EXCEEDED")
                    after = recovery.snapshot()
                    expected_fingerprint = "sha256:" + stable_hash({"organizer": router.organizer.to_dict(), "config": router.config})
                    self.assertEqual(before["config_fingerprint"], "")
                    self.assertEqual(after["config_fingerprint"], expected_fingerprint)
                    self.assertEqual({**after, "config_fingerprint": before["config_fingerprint"]}, before)
                    second = fixtures.MaintainerTests()._enqueue_candidate(settings, label="second")
                    allowed = drain_queue(settings, provider=_RouterAdapter(router), now=now,
                        run_id="fresh-run" if scope == "run-token" else "blocked-run")
                    self.assertEqual(allowed.completed, 1)
                    self.assertEqual(read_queue_item(second.queue_id, settings).state, QueueState.DONE)
                    self.assertEqual(read_queue_item(first.queue_id, settings).state, QueueState.DEFERRED)
                    self.assertEqual(generate.call_count, 1)
                    self.assertEqual(alternative.calls, 0)
                    self.assertEqual(len(ledger.snapshot()["reservations"]), 2)

    def test_repeated_journal_storage_failure_keeps_cached_candidate_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            item = fixtures.MaintainerTests()._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            provider = fixtures.YesProvider()
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()), patch.object(provider, "generate", wraps=provider.generate) as generate:
                with patch("ei.changeset.append_event", side_effect=OSError("disk full")):
                    for day in range(5):
                        drain_queue(settings, provider=provider, now=now + timedelta(days=day))
                self.assertEqual(read_queue_item(item.queue_id, settings).state, QueueState.DEFERRED)
                result = drain_queue(settings, provider=provider, now=now + timedelta(days=5))
                self.assertEqual(result.completed, 1)
                self.assertEqual(generate.call_count, 1)

    def test_pending_candidate_requires_its_authenticated_capture_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            now = datetime.now(timezone.utc)
            capture = "sha256:" + "a" * 64
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                ref = write_spool({"claim": "reusable candidate"}, "public", settings, now=now, purpose="pending", capture_id=capture)
                item = fixtures.MaintainerTests()._enqueue_candidate(settings, payload_ref=ref)
                for wrong in (None, "sha256:" + "b" * 64):
                    with self.assertRaises(MaintenanceError):
                        _candidate_for(replace(item, capture_id=wrong), settings, now)
                self.assertEqual(_candidate_for(replace(item, capture_id=capture), settings, now)["claim"], "reusable candidate")

    def test_subscription_request_overhead_fits_reserved_input_and_completes_curation(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(fixtures.make_settings(tmp), organizer=OrganizerSelection("READY", "subscription-cli", "codex-cli"))
            fixtures.MaintainerTests()._enqueue_candidate(settings)
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                candidate = json.loads(kwargs["input"])["input"]
                output = fixtures.YesProvider().generate("gate-decision", candidate, None).output
                return SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr="")
            provider = SubscriptionCLIProvider(("synthetic-cli",), runner=runner)
            router = ProviderRouter([provider], settings=settings, provider_config={})
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                result = drain_queue(settings, provider=_RouterAdapter(router), time_budget_ms=10000)
            self.assertEqual(result.completed, 1)
            self.assertEqual(len(calls), 1)

    def test_partial_operation_append_reuses_saved_changeset(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            fixtures.MaintainerTests()._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            provider = fixtures.YesProvider()
            from ei.changeset import append_event
            calls = 0
            original_ids = {event.event_id for event in iter_events(settings.paths.event_dir, include_uncommitted=True)}
            def interrupt(event, event_dir, *, budget=None):
                nonlocal calls
                calls += 1
                self.assertIsNotNone(budget)
                if calls == 2:
                    raise OSError("SIMULATED_RESTART")
                return append_event(event, event_dir, budget=budget)
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()), patch.object(provider, "generate", wraps=provider.generate) as generate:
                with patch("ei.changeset.append_event", side_effect=interrupt):
                    drain_queue(settings, provider=provider, now=now)
                self.assertEqual(calls, 2)
                partial = [event for event in iter_events(settings.paths.event_dir, include_uncommitted=True) if event.event_id not in original_ids]
                self.assertEqual(len(partial), 1)
                self.assertNotEqual(partial[0].event_type, "curation.changeset.applied")
                self.assertEqual({event.event_id for event in iter_events(settings.paths.event_dir)}, original_ids)
                result = drain_queue(settings, provider=provider, now=now + timedelta(hours=1))
                self.assertEqual(result.completed, 1)
                self.assertEqual(generate.call_count, 1)
                self.assertEqual(sum(event.event_type == "curation.changeset.applied" for event in iter_events(settings.paths.event_dir)), 1)
                self.assertEqual(sum(event.event_id == partial[0].event_id for event in iter_events(settings.paths.event_dir, include_uncommitted=True)), 1)

    def test_journal_commit_before_projection_replays_without_another_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            item = fixtures.MaintainerTests()._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            provider = fixtures.YesProvider()
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()), patch.object(provider, "generate", wraps=provider.generate) as generate:
                with patch("ei.maintainer.project_events", side_effect=OSError("SIMULATED_RESTART")):
                    drain_queue(settings, provider=provider, now=now)
                before = [event.event_id for event in iter_events(settings.paths.event_dir)]
                result = drain_queue(settings, provider=provider, now=now + timedelta(hours=1))
                self.assertEqual(result.completed, 1)
                self.assertEqual(generate.call_count, 1)
                self.assertEqual([event.event_id for event in iter_events(settings.paths.event_dir)], before)
                self.assertTrue((settings.paths.knowledge_dir / "index.json").exists())

    def test_replay_requires_source_provider_capture_and_content_match_and_original_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            now = datetime.now(timezone.utc)
            with patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider()):
                source = write_spool({"title": "candidate", "claim": "同じ構造を別案件でも検証し再利用可能な判断ルールとして記録する"}, "private-reusable", settings, now=now, ttl_seconds=600)
                item = fixtures.MaintainerTests()._enqueue_candidate(settings, payload_ref=source)
                with patch("ei.maintainer.apply_changeset", side_effect=OSError("SIMULATED_RESTART")):
                    drain_queue(settings, provider=fixtures.YesProvider(), now=now)
                saved = read_queue_item(item.queue_id, settings)
                self.assertLessEqual(datetime.fromisoformat(saved.validated_result_ref.expires_at), datetime.fromisoformat(source.expires_at))
                candidate = _candidate_for(saved, settings, now)
                self.assertIsNotNone(load_validated_result(saved, candidate, "local-test", settings, now))
                for altered, body, provider_id in (
                    (replace(saved, source_hash="sha256:" + "f" * 64), candidate, "local-test"),
                    (saved, {**candidate, "claim": "different"}, "local-test"),
                    (saved, candidate, "another-provider"),
                    (replace(saved, capture_id="sha256:" + "f" * 64), candidate, "local-test"),
                ):
                    with self.assertRaises((ValueError, SpoolError)):
                        load_validated_result(altered, body, provider_id, settings, now)
                self.assertIsNotNone(load_validated_result(saved, candidate, "local-test", settings, now))

    def test_validated_result_survives_failure_without_second_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = fixtures.make_settings(tmp)
            item = fixtures.MaintainerTests()._enqueue_candidate(settings)
            now = datetime.now(timezone.utc)
            key = InMemoryKeyProvider()
            provider = fixtures.YesProvider()
            with patch("ei.spool.default_key_provider", return_value=key), patch.object(provider, "generate", wraps=provider.generate) as generate:
                with patch("ei.maintainer.apply_changeset", side_effect=OSError("SIMULATED_RESTART")):
                    drain_queue(settings, provider=provider, now=now)
                saved = read_queue_item(item.queue_id, settings)
                self.assertIsNotNone(saved.validated_result_ref)
                self.assertEqual(saved.validated_result_ref.purpose, "validated-result")
                result = drain_queue(settings, provider=provider, now=now + timedelta(hours=1))
                self.assertEqual(result.completed, 1)
                self.assertEqual(generate.call_count, 1)
                self.assertEqual(read_queue_item(item.queue_id, settings).state, QueueState.DONE)
                self.assertEqual(sum(event.event_type == "curation.changeset.applied" for event in iter_events(settings.paths.event_dir)), 1)
                aggregate = json.loads((settings.paths.runtime_dir / "gate-aggregate.json").read_text(encoding="utf-8"))
                self.assertEqual(sum(row["yes_count"] for row in aggregate["rows"].values()), 1)
