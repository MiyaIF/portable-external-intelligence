import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import timedelta
from ei.organizer_recovery import OrganizerRecovery, next_retry
from ei.gate import GateDecision
from ei.inference.cli_subscription import SubscriptionCLIProvider
from tests.unattended_helpers import NOW


class OrganizerRecoveryTests(unittest.TestCase):
    def test_initial_fingerprint_is_only_a_baseline_for_existing_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            before = recovery.snapshot()
            self.assertFalse(recovery.recover(Mock(provider_id="ollama"), config_fingerprint="sha256:" + "a" * 64))
            after = recovery.snapshot()
            self.assertEqual(after["config_fingerprint"], "sha256:" + "a" * 64)
            self.assertEqual({k: v for k, v in after.items() if k != "config_fingerprint"},
                             {k: v for k, v in before.items() if k != "config_fingerprint"})

    def test_validated_result_helpers_stop_before_io_on_expired_budget(self):
        from ei.organizer_recovery import save_validated_result, load_validated_result
        from ei.operation_runtime import OperationBudget
        item = Mock()
        for helper, args in ((save_validated_result, (item, {}, "ollama", GateDecision("NO", "no_evidence"), None, Mock(), NOW)),
                             (load_validated_result, (item, {}, "ollama", Mock(), NOW))):
            with self.subTest(helper=helper.__name__), patch("ei.organizer_recovery.write_spool") as write, patch("ei.organizer_recovery.read_spool") as read:
                try:
                    with self.assertRaises(TimeoutError):
                        helper(*args, budget=OperationBudget(0))
                except TypeError as exc:
                    self.fail(str(exc))
                write.assert_not_called()
                read.assert_not_called()

    def test_remaining_budget_after_inference_preserves_interrupted_hold(self):
        class ExpiringBudget:
            expired = False
            def check(self):
                if self.expired:
                    raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")
            def remaining_ms(self):
                return 0 if self.expired else 5000
        with tempfile.TemporaryDirectory() as tmp:
            budget = ExpiringBudget()
            path = Path(tmp) / "state.json"
            recovery = OrganizerRecovery(path, "ollama", operation_budget=budget)
            def operation():
                budget.expired = True
                return GateDecision("NO", "no_future_benefit", provider_id="ollama")
            with self.assertRaises(TimeoutError):
                recovery.run(operation, NOW)
            state = OrganizerRecovery(path, "ollama").snapshot()
            self.assertEqual(state["reason_code"], "PROVIDER_INTERRUPTED")
            self.assertEqual(state["attempts"], 1)

    def test_failed_refusal_restoration_keeps_durable_interruption_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            write = recovery.storage._write
            def persist_only_interruption(state):
                if state["reason_code"] != "PROVIDER_INTERRUPTED":
                    raise OSError("disk full during restoration")
                write(state)
            with patch.object(recovery.storage, "_write", side_effect=persist_only_interruption):
                with self.assertRaises(OSError):
                    recovery.run(lambda: GateDecision("DEFERRED", "TOKEN_CAP_EXCEEDED"), NOW, admission_refused=lambda: True)
            state = OrganizerRecovery(recovery.storage.path, "ollama").snapshot()
            self.assertEqual(state["attempts"], 1)
            self.assertEqual(state["reason_code"], "PROVIDER_INTERRUPTED")
            self.assertEqual(datetime_from(state["next_eligible_at"]), NOW + timedelta(seconds=300))

    def test_confirmed_admission_refusal_restores_prior_failure_without_resetting_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            failure = Mock(return_value=GateDecision("FAILED", "PROVIDER_TIMEOUT", provider_id="ollama"))
            recovery.run(failure, NOW)
            before = recovery.snapshot()
            refusal = Mock(return_value=GateDecision("DEFERRED", "ATTEMPT_CAP_EXCEEDED", provider_id="ollama"))
            recovery.run(refusal, NOW + timedelta(seconds=300), admission_refused=lambda: True)
            self.assertEqual(recovery.snapshot(), before)
            recovery.run(failure, NOW + timedelta(seconds=300))
            self.assertEqual(recovery.snapshot()["attempts"], 2)
            self.assertEqual(datetime_from(recovery.snapshot()["next_eligible_at"]), NOW + timedelta(seconds=1200))

    def test_admission_evidence_never_bypasses_existing_hold_or_unfinished_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            operation = Mock(side_effect=RuntimeError("interrupted"))
            with self.assertRaises(RuntimeError):
                recovery.run(operation, NOW, admission_refused=lambda: True)
            state = recovery.snapshot()
            self.assertEqual(state["attempts"], 1)
            self.assertEqual(state["reason_code"], "PROVIDER_INTERRUPTED")
            recovery.run(operation, NOW, admission_refused=lambda: True)
            self.assertEqual(operation.call_count, 1)
            self.assertEqual(recovery.snapshot(), state)

    def test_actual_subscription_latch_and_explicit_disable_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = SubscriptionCLIProvider(("synthetic-cli",), state_path=Path(tmp) / "adapter.json", runner=Mock())
            provider._write_state(state="AUTH_DISABLED", reason_code="AUTH_FAILED")
            recovery = OrganizerRecovery(Path(tmp) / "organizer.json", provider.provider_id)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id=provider.provider_id), NOW)
            self.assertFalse(provider.available())
            recovery.recover(provider, verified_auth=True)
            self.assertTrue(provider.available())
            provider.enabled = False
            recovery.recover(provider, verified_auth=True)
            self.assertFalse(provider.available())

    def test_changed_config_permits_retry_without_claiming_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama", config_fingerprint="sha256:" + "a" * 64)
            operation = Mock(return_value=GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"))
            recovery.run(operation, NOW)
            self.assertTrue(recovery.recover(Mock(provider_id="ollama"), config_fingerprint="sha256:" + "b" * 64))
            self.assertEqual(recovery.snapshot()["reason_code"], "CONFIG_CHANGED_RETRY")
            recovery.run(operation, NOW)
            self.assertTrue(recovery.snapshot()["needs_action"])

    def test_quota_uses_provider_deadline_and_storage_failure_never_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            from unittest.mock import patch
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            operation = Mock(return_value=GateDecision("DEFERRED", "QUOTA_EXHAUSTED", next_eligible_at=NOW + timedelta(days=1)))
            recovery.run(operation, NOW)
            recovery.run(operation, NOW + timedelta(hours=12))
            self.assertEqual(operation.call_count, 1)
            self.assertEqual(datetime_from(recovery.snapshot()["next_eligible_at"]), NOW + timedelta(days=1))
            with patch.object(recovery.storage, "_write", side_effect=OSError("disk full")), self.assertRaises(OSError):
                recovery.run(operation, NOW + timedelta(days=1))
            self.assertEqual(operation.call_count, 1)

    def test_auth_is_shared_across_candidates_and_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            call = Mock(return_value=GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"))
            first = OrganizerRecovery(path, "ollama")
            first.run(call, NOW)
            second = OrganizerRecovery(path, "ollama")
            self.assertEqual(second.run(call, NOW + timedelta(days=1)).reason_code, "AUTH_FAILED")
            self.assertEqual(call.call_count, 1)
            self.assertTrue(second.snapshot()["needs_action"])

    def test_timeout_has_bounded_retry_and_malformed_needs_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama", malformed_limit=2)
            call = Mock(return_value=GateDecision("FAILED", "PROVIDER_TIMEOUT", provider_id="ollama"))
            recovery.run(call, NOW)
            recovery.run(call, NOW + timedelta(seconds=299))
            self.assertEqual(call.call_count, 1)
            call.return_value = GateDecision("FAILED", "MALFORMED_RESPONSE", provider_id="ollama")
            recovery.run(call, NOW + timedelta(seconds=300))
            recovery.run(call, NOW + timedelta(seconds=1200))
            self.assertTrue(recovery.snapshot()["needs_action"])

    def test_only_verified_same_provider_recovery_unlocks_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "subscription-cli", config_fingerprint="sha256:" + "a" * 64)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="subscription-cli"), NOW)
            provider = Mock(provider_id="subscription-cli")
            self.assertFalse(recovery.recover(provider, config_fingerprint="sha256:" + "a" * 64))
            self.assertTrue(recovery.recover(provider, verified_auth=True))
            provider.repair_auth.assert_called_once()
            self.assertFalse(recovery.snapshot()["needs_action"])

    def test_explicit_auth_retry_cannot_repeat_after_failure(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            recovery = OrganizerRecovery(path, "ollama")
            fail = lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama")
            recovery.run(fail, NOW)
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            self.assertEqual(recovery.request_auth_retry(provider, now=NOW)["status"], "RETRY_REQUESTED")
            operation = Mock(side_effect=fail)
            recovery.run(operation, NOW + timedelta(hours=1), retry_provider=provider)
            restarted = OrganizerRecovery(path, "ollama")
            restarted.run(operation, NOW + timedelta(days=1), retry_provider=provider)
            self.assertEqual(operation.call_count, 1)
            self.assertTrue(restarted.snapshot()["needs_action"])

    def test_resume_request_coalesces_and_preserves_original_deadline(self):
        from types import SimpleNamespace
        fingerprint = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            before = recovery.snapshot()
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            first = recovery.request_auth_retry(provider, now=NOW + timedelta(seconds=10), config_fingerprint=fingerprint)
            second = recovery.request_auth_retry(provider, now=NOW + timedelta(seconds=20), config_fingerprint=fingerprint)
            self.assertEqual(first["status"], "RETRY_REQUESTED")
            self.assertEqual(second["status"], "ALREADY_REQUESTED")
            after = recovery.snapshot()
            self.assertEqual(after["attempts"], before["attempts"])
            self.assertEqual(after["next_eligible_at"], before["next_eligible_at"])
            self.assertEqual(after["retry_request"]["requested_at"], (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"))
            unchanged = recovery.storage.path.read_bytes()
            self.assertEqual(recovery.request_auth_retry(SimpleNamespace(provider_id="other", enabled=True),
                now=NOW + timedelta(seconds=30), config_fingerprint=fingerprint)["status"], "UNAVAILABLE")
            self.assertEqual(recovery.request_auth_retry(SimpleNamespace(provider_id="ollama", enabled=False),
                now=NOW + timedelta(seconds=30), config_fingerprint=fingerprint)["status"], "DISABLED")
            self.assertEqual(recovery.storage.path.read_bytes(), unchanged)

    def test_resume_dry_view_and_ready_state_do_not_create_a_request(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama")
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            self.assertEqual(recovery.preview_auth_retry(provider, now=NOW)["status"], "NO_ACTION")
            self.assertFalse(recovery.storage.path.exists())
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            before = recovery.storage.path.read_bytes()
            self.assertEqual(recovery.preview_auth_retry(provider, now=NOW + timedelta(seconds=1))["status"], "RETRY_REQUESTED")
            self.assertEqual(recovery.storage.path.read_bytes(), before)

    def test_new_explicit_request_after_resumed_auth_failure_is_readable_and_one_use(self):
        from types import SimpleNamespace
        fingerprint = "sha256:" + "d" * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            recovery = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            recovery.request_auth_retry(provider, now=NOW, config_fingerprint=fingerprint)
            first_due = datetime_from(recovery.snapshot()["next_eligible_at"])
            resumed_failure = Mock(return_value=GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"))
            recovery.run(resumed_failure, first_due, retry_provider=provider)
            self.assertEqual(resumed_failure.call_count, 1)
            consumed = recovery.snapshot()
            self.assertTrue(consumed["retry_consumed"])
            self.assertEqual(consumed["attempts"], 2)
            self.assertTrue(consumed["needs_action"])

            request_at = datetime_from(consumed["next_eligible_at"]) - timedelta(seconds=1)
            restarted = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            self.assertEqual(restarted.request_auth_retry(provider, now=request_at,
                config_fingerprint=fingerprint)["status"], "RETRY_REQUESTED")
            fresh = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            try:
                pending = fresh.snapshot()
            except ValueError as exc:
                self.fail(f"new request after resumed failure made durable state unreadable: {exc}")
            self.assertTrue(pending["retry_consumed"])
            self.assertEqual(pending["retry_request"]["requested_at"], request_at.isoformat().replace("+00:00", "Z"))
            due = datetime_from(pending["next_eligible_at"])
            self.assertEqual(pending["attempts"], consumed["attempts"])

            duplicate = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).request_auth_retry(
                provider, now=request_at + timedelta(seconds=1), config_fingerprint=fingerprint)
            self.assertEqual(duplicate["status"], "ALREADY_REQUESTED")
            self.assertEqual(OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).snapshot(), pending)
            operation = Mock(return_value=GateDecision("NO", "no_future_benefit", provider_id="ollama"))
            early = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).run(
                operation, due - timedelta(seconds=1), retry_provider=provider)
            self.assertEqual(early.decision, "DEFERRED")
            self.assertEqual(operation.call_count, 0)
            success = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).run(
                operation, due, retry_provider=provider)
            self.assertTrue(success.semantic)
            self.assertEqual(operation.call_count, 1)
            ready = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).snapshot()
            self.assertFalse(ready["needs_action"])
            self.assertEqual(ready["reason_code"], "READY")
            self.assertFalse(ready["retry_consumed"])
            self.assertIsNone(ready["retry_request"])

    def test_interrupted_resume_requires_a_new_explicit_request(self):
        from types import SimpleNamespace
        fingerprint = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            recovery = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            recovery.request_auth_retry(provider, now=NOW, config_fingerprint=fingerprint)
            interrupted = Mock(side_effect=RuntimeError("interrupted after durable consume"))
            first_due = datetime_from(recovery.snapshot()["next_eligible_at"])
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                recovery.run(interrupted, first_due, retry_provider=provider)
            restarted = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            interrupted_state = restarted.snapshot()
            self.assertEqual(interrupted_state["reason_code"], "PROVIDER_INTERRUPTED")
            self.assertTrue(interrupted_state["retry_consumed"])
            due = datetime_from(interrupted_state["next_eligible_at"])
            blocked = Mock(return_value=GateDecision("NO", "no_evidence", provider_id="ollama"))
            self.assertEqual(restarted.run(blocked, due, retry_provider=provider).decision, "DEFERRED")
            self.assertEqual(blocked.call_count, 0)

            request_at = due - timedelta(seconds=1)
            self.assertEqual(restarted.request_auth_retry(provider, now=request_at,
                config_fingerprint=fingerprint)["status"], "RETRY_REQUESTED")
            fresh = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint)
            try:
                pending = fresh.snapshot()
            except ValueError as exc:
                self.fail(f"new request after interruption made durable state unreadable: {exc}")
            self.assertTrue(pending["retry_consumed"])
            self.assertTrue(pending["needs_action"])
            self.assertEqual(pending["retry_request"]["requested_at"], request_at.isoformat().replace("+00:00", "Z"))
            duplicate = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).request_auth_retry(
                provider, now=request_at + timedelta(seconds=1), config_fingerprint=fingerprint)
            self.assertEqual(duplicate["status"], "ALREADY_REQUESTED")
            self.assertEqual(OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).snapshot(), pending)

            operation = Mock(return_value=GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"))
            early = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).run(
                operation, due - timedelta(seconds=1), retry_provider=provider)
            self.assertEqual(early.decision, "DEFERRED")
            self.assertEqual(operation.call_count, 0)
            failed = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).run(
                operation, due, retry_provider=provider)
            self.assertEqual(failed.reason_code, "AUTH_FAILED")
            self.assertEqual(operation.call_count, 1)
            failed_state = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).snapshot()
            self.assertTrue(failed_state["needs_action"])
            self.assertTrue(failed_state["retry_consumed"])
            self.assertIsNone(failed_state["retry_request"])
            blocked_again = OrganizerRecovery(path, "ollama", config_fingerprint=fingerprint).run(
                blocked, datetime_from(failed_state["next_eligible_at"]), retry_provider=provider)
            self.assertEqual(blocked_again.decision, "DEFERRED")
            self.assertEqual(blocked.call_count, 0)

    def test_proven_admission_refusal_restores_the_one_use_request(self):
        from types import SimpleNamespace
        fingerprint = "sha256:" + "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            recovery = OrganizerRecovery(Path(tmp) / "state.json", "ollama", config_fingerprint=fingerprint)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id="ollama"), NOW)
            provider = SimpleNamespace(provider_id="ollama", enabled=True)
            recovery.request_auth_retry(provider, now=NOW, config_fingerprint=fingerprint)
            before = recovery.snapshot()
            refusal = Mock(return_value=GateDecision("DEFERRED", "TOKEN_CAP_EXCEEDED", provider_id="ollama"))
            result = recovery.run(refusal, NOW + timedelta(hours=1), retry_provider=provider,
                admission_refused=lambda: True)
            self.assertEqual(result.reason_code, "TOKEN_CAP_EXCEEDED")
            self.assertEqual(refusal.call_count, 1)
            self.assertEqual(recovery.snapshot(), before)

    def test_subscription_resume_releases_only_local_auth_latch(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = SubscriptionCLIProvider(("synthetic-cli",), state_path=Path(tmp) / "adapter.json", runner=Mock())
            provider._write_state(state="AUTH_DISABLED", reason_code="AUTH_FAILED")
            recovery = OrganizerRecovery(Path(tmp) / "organizer.json", provider.provider_id)
            recovery.run(lambda: GateDecision("FAILED", "AUTH_FAILED", provider_id=provider.provider_id), NOW)
            self.assertFalse(provider.available())
            recovery.request_auth_retry(provider, now=NOW)
            decision = recovery.run(lambda: GateDecision("NO", "no_future_benefit", provider_id=provider.provider_id),
                NOW + timedelta(hours=1), retry_provider=provider)
            self.assertTrue(decision.semantic)
            self.assertTrue(provider.available())
            self.assertFalse(recovery.snapshot()["needs_action"])

    def test_longer_provider_deadline_wins(self):
        deadline = NOW + timedelta(days=1)
        self.assertEqual(next_retry(NOW, 1, deadline), deadline)
        self.assertEqual(next_retry(NOW, 1), NOW + timedelta(seconds=300))
        self.assertEqual(next_retry(NOW, 50), NOW + timedelta(seconds=21600))

    def test_short_deadline_does_not_shorten_backoff(self):
        self.assertEqual(next_retry(NOW, 2, NOW + timedelta(seconds=1)), NOW + timedelta(seconds=900))
        for attempt in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                next_retry(NOW, attempt)


def datetime_from(value):
    from datetime import datetime
    return datetime.fromisoformat(value)
