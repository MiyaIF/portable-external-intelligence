import json
import tempfile
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import Mock, patch

from ei.inference.budget import BudgetLedger, BudgetPolicy, BudgetLockError
from ei.inference.base import InferenceBudget, ProviderResult
from ei.inference.router import ProviderRouter
from ei.setup_contract import OrganizerSelection


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def policy(**overrides):
    value = {
        "schema_version": 1,
        "mode": "local_first_subscription_only",
        "limits": {
            "per_run": {"input_tokens": 10, "output_tokens": 10, "cost": "1"},
            "per_day": {"input_tokens": 100, "output_tokens": 100, "cost": "2"},
            "per_candidate": {"input_tokens": 5, "output_tokens": 5, "cost": "1"},
        },
        "retry": {"max_attempts": 4, "backoff_seconds": [300, 900, 3600, 21600]},
        "deadline": {"max_ms": 120000, "max_response_bytes": 1000},
        "cloud_api": {"enabled": False, "spend_cap": "0"},
        "subscription": {"on_quota": "DEFERRED_QUOTA"},
    }
    for key, value_override in overrides.items():
        if key == "per_candidate_input_tokens":
            value["limits"]["per_candidate"]["input_tokens"] = value_override
    return BudgetPolicy.from_mapping(value)


class BudgetTests(unittest.TestCase):
    def test_contended_ledger_uses_shared_short_budget(self):
        from ei.operation_runtime import OperationBudget
        import time
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            owner = BudgetLedger(path)
            descriptor = owner._acquire()
            try:
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    BudgetLedger(path, operation_budget=OperationBudget(30)).snapshot()
                self.assertLess(time.monotonic() - started, 1)
                self.assertFalse(path.exists())
            finally:
                owner._release(descriptor)

    def test_operation_budget_expiry_does_not_free_unsettled_reservation(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            ledger = BudgetLedger(path, policy=policy())
            allowance = InferenceBudget(max_input_tokens=1, max_output_tokens=1)
            self.assertTrue(ledger.reserve("attempt", "ollama", allowance, NOW).allowed)
            before = path.read_bytes()
            limited = BudgetLedger(path, policy=policy(), operation_budget=OperationBudget(0))
            with self.assertRaises(TimeoutError):
                limited.settle("attempt", ProviderResult("ollama", "success", input_tokens=0, metadata={"usage_known": True}), NOW)
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse(ledger.snapshot()["reservations"]["attempt"]["settled"])

    def test_admission_provenance_is_router_owned_and_operation_scoped(self):
        from ei.maintainer import _RouterAdapter
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            provider = Mock(provider_id="ollama", locality="local")
            provider.generate.return_value = ProviderResult("ollama", "failed", error_code="TOKEN_CAP_EXCEEDED", admission_refused=True)
            adapter = _RouterAdapter(ProviderRouter([provider], organizer=OrganizerSelection("READY", "ollama", None), budget_ledger=ledger))
            denied = adapter.generate("gate-decision", {}, InferenceBudget())
            self.assertTrue(denied.admission_refused)
            self.assertTrue(adapter.admission_refused)
            provider.generate.assert_not_called()
            allowed = adapter.generate("gate-decision", {}, InferenceBudget(max_input_tokens=1, max_output_tokens=0))
            self.assertFalse(allowed.admission_refused)
            self.assertFalse(adapter.admission_refused)
            self.assertEqual(provider.generate.call_count, 1)
            self.assertNotIn("admission_refused", allowed.to_dict())
            with patch.object(ledger, "reserve", side_effect=OSError("disk full")):
                self.assertFalse(adapter.generate("gate-decision", {}, InferenceBudget()).admission_refused)
            self.assertFalse(adapter.admission_refused)

    def test_reservation_cannot_outlive_remaining_call_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            provider = Mock(provider_id="ollama", locality="local")
            router = ProviderRouter([provider], organizer=OrganizerSelection("READY", "ollama", None), budget_ledger=ledger)
            with patch("ei.inference.router.monotonic", side_effect=[0, 1], create=True):
                result = router.generate("gate", "gate-decision", {}, InferenceBudget(max_input_tokens=1, max_output_tokens=1, deadline_ms=1))
            self.assertEqual(result.error_code, "DEADLINE_EXCEEDED")
            provider.generate.assert_not_called()

    def test_run_cap_survives_utc_midnight(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            budget = InferenceBudget(max_input_tokens=4, max_output_tokens=0, candidate_id="a", run_id="long-run")
            self.assertTrue(ledger.reserve("one", "ollama", budget, NOW).allowed)
            self.assertTrue(ledger.reserve("two", "ollama", budget, NOW + timedelta(days=1)).allowed)
            self.assertFalse(ledger.reserve("three", "ollama", replace(budget, candidate_id="b"), NOW + timedelta(days=1)).allowed)

    def test_permission_denied_lock_is_bounded_and_live_lock_not_evicted(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json")
            with patch("ei.inference.budget.os.open", side_effect=PermissionError), patch("ei.inference.budget.time.monotonic", side_effect=[0, 6]):
                with self.assertRaises(BudgetLockError):
                    ledger._acquire()
            descriptor = ledger._acquire()
            try:
                with patch("ei.inference.budget.time.monotonic", side_effect=[0, 6]):
                    with self.assertRaises(BudgetLockError):
                        BudgetLedger(ledger.path)._acquire()
            finally:
                ledger._release(descriptor)

    def test_process_exit_keeps_reservation_and_releases_os_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            code = "import os,sys;from datetime import datetime,timezone;from ei.inference.budget import BudgetLedger;from ei.inference.base import InferenceBudget;l=BudgetLedger(sys.argv[1]);l.reserve('crash','ollama',InferenceBudget(max_input_tokens=1,max_output_tokens=1),datetime.now(timezone.utc));l._acquire();os._exit(73)"
            result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code, str(path)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 73)
            snapshot = BudgetLedger(path).snapshot()
            self.assertFalse(snapshot["reservations"]["crash"]["settled"])

    def test_legacy_corrupt_quarantine_does_not_reopen_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            path.with_name("ledger.json.corrupt").write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                BudgetLedger(path).reserve("one", "ollama", InferenceBudget(), NOW)

    def test_router_reserves_before_call_and_failed_attempt_is_spent(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=replace(policy(), retry_limit=1))
            provider = Mock(provider_id="ollama", locality="local")
            provider.generate.return_value = ProviderResult("ollama", "failed", error_code="PROVIDER_TIMEOUT")
            router = ProviderRouter([provider], organizer=OrganizerSelection("READY", "ollama", None), budget_ledger=ledger)
            budget = InferenceBudget(max_input_tokens=1, max_output_tokens=0, candidate_id="a", run_id="run")
            self.assertEqual(router.generate("gate", "gate-decision", {}, replace(budget, attempt_id="one")).error_code, "PROVIDER_TIMEOUT")
            self.assertEqual(router.generate("gate", "gate-decision", {}, replace(budget, attempt_id="two")).error_code, "ATTEMPT_CAP_EXCEEDED")
            self.assertEqual(provider.generate.call_count, 1)

    def test_router_denial_and_disk_full_never_call_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            provider = Mock(provider_id="ollama", locality="local")
            router = ProviderRouter([provider], organizer=OrganizerSelection("READY", "ollama", None), budget_ledger=ledger)
            self.assertEqual(router.generate("gate", "gate-decision", {}, InferenceBudget()).error_code, "TOKEN_CAP_EXCEEDED")
            with patch.object(ledger, "_write", side_effect=OSError("disk full")):
                self.assertEqual(router.generate("gate", "gate-decision", {}, InferenceBudget(max_input_tokens=1, max_output_tokens=0)).error_code, "BUDGET_STORAGE_UNAVAILABLE")
            provider.generate.assert_not_called()

    def test_unknown_cloud_pricing_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = Mock(provider_id="cloud-api", locality="cloud")
            router = ProviderRouter([provider], organizer=OrganizerSelection("READY", "cloud-api", None), budget_ledger=BudgetLedger(Path(tmp) / "ledger.json"))
            self.assertEqual(router.generate("gate", "gate-decision", {}).error_code, "PROVIDER_COST_UNKNOWN")
            provider.generate.assert_not_called()

    def test_settle_known_usage_once_and_not_against_next_day(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            budget = InferenceBudget(max_input_tokens=5, max_output_tokens=0, candidate_id="a", run_id="run")
            ledger.reserve("one", "ollama", budget, NOW)
            result = ProviderResult("ollama", input_tokens=1, metadata={"usage_known": True, "cost_known": True})
            ledger.settle("one", result, NOW)
            ledger.settle("one", result, NOW)
            self.assertTrue(ledger.reserve("two", "ollama", replace(budget, max_input_tokens=4), NOW).allowed)
            self.assertFalse(ledger.reserve("three", "ollama", replace(budget, max_input_tokens=1), NOW).allowed)

    def test_reservation_survives_restart_and_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            budget = InferenceBudget(max_input_tokens=5, max_output_tokens=0, candidate_id="a", run_id="run")
            self.assertTrue(BudgetLedger(path, policy=policy()).reserve("one", "ollama", budget, NOW).allowed)
            restarted = BudgetLedger(path, policy=policy())
            self.assertEqual(restarted.reserve("one", "ollama", budget, NOW).reason_code, "ATTEMPT_ALREADY_RESERVED")
            self.assertFalse(restarted.reserve("two", "ollama", budget, NOW).allowed)

    def test_run_and_day_caps_cannot_be_split_by_purpose(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=replace(policy(), per_day_input_tokens=10))
            budget = InferenceBudget(max_input_tokens=5, max_output_tokens=0, candidate_id="a", run_id="shared")
            self.assertTrue(ledger.reserve("a", "ollama", budget, NOW).allowed)
            self.assertTrue(ledger.reserve("b", "ollama", replace(budget, candidate_id="b", purpose="curation"), NOW).allowed)
            result = ledger.reserve("c", "ollama", replace(budget, candidate_id="c"), NOW)
            self.assertEqual(result.remaining["scope"], "per_run")
            result = ledger.reserve("d", "ollama", replace(budget, candidate_id="d", run_id="other", purpose="other"), NOW)
            self.assertEqual(result.remaining["scope"], "per_day")
            self.assertTrue(ledger.reserve("e", "ollama", replace(budget, candidate_id="e", run_id="tomorrow"), NOW + timedelta(days=1)).allowed)

    def test_failure_and_unknown_usage_retain_reserved_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy())
            budget = InferenceBudget(max_input_tokens=5, max_output_tokens=0, candidate_id="a", run_id="run")
            ledger.reserve("one", "ollama", budget, NOW)
            ledger.settle("one", ProviderResult("ollama", "failed", error_code="PROVIDER_TIMEOUT"), NOW)
            ledger.settle("one", ProviderResult("ollama", "success"), NOW)
            self.assertFalse(ledger.reserve("two", "ollama", budget, NOW).allowed)

    def test_unknown_actual_cost_keeps_reserved_cost_and_settlement_failure_keeps_attempt(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=replace(policy(), retry_limit=1))
            budget = InferenceBudget(max_input_tokens=1, max_output_tokens=1, max_cost=Decimal("0.5"), candidate_id="a", run_id="run")
            ledger.reserve("one", "subscription-cli", budget, NOW)
            result = ProviderResult("subscription-cli", input_tokens=1, output_tokens=1, metadata={"usage_known": True})
            with patch.object(ledger, "_write", side_effect=OSError("disk full")), self.assertRaises(OSError):
                ledger.settle("one", result, NOW)
            self.assertFalse(ledger.snapshot()["reservations"]["one"]["settled"])
            ledger.settle("one", result, NOW)
            self.assertEqual(ledger.reserve("two", "subscription-cli", budget, NOW).reason_code, "ATTEMPT_CAP_EXCEEDED")
            self.assertEqual(ledger.snapshot()["entries"]["subscription-cli|2026-08-26|inheritance-gate"]["cost"], "0.50000000")

    def test_corrupt_ledger_does_not_restore_spending_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            path.write_text("{broken", encoding="utf-8")
            ledger = BudgetLedger(path, policy=policy())
            for _ in range(2):
                with self.assertRaises(ValueError):
                    ledger.reserve("one", "ollama", InferenceBudget(), NOW)
            self.assertEqual(path.read_text(encoding="utf-8"), "{broken")

    def test_concurrent_reserve_allows_only_one_at_cap(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            limited = replace(policy(), per_run_input_tokens=1)
            budget = InferenceBudget(max_input_tokens=1, max_output_tokens=0, candidate_id="a", run_id="run")
            def reserve(n):
                return BudgetLedger(path, policy=limited).reserve(str(n), "ollama", budget, NOW).allowed
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(reserve, range(8))), 1)

    def test_per_run_per_day_and_per_candidate_token_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=policy(), run_id="run-a", candidate_id="candidate-a")
            self.assertTrue(ledger.consume("ollama", 5, 0, Decimal("0"), NOW).allowed)
            self.assertEqual(ledger.consume("ollama", 1, 0, Decimal("0"), NOW).reason_code, "TOKEN_CAP_EXCEEDED")
            other_candidate = ledger.consume("ollama", 4, 0, Decimal("0"), NOW, candidate_id="candidate-b", run_id="run-b")
            self.assertTrue(other_candidate.allowed)
            self.assertTrue(ledger.consume("ollama", 1, 0, Decimal("0"), NOW, candidate_id="candidate-b", run_id="run-b").allowed)
            self.assertEqual(ledger.consume("ollama", 1, 0, Decimal("0"), NOW, candidate_id="candidate-b", run_id="run-b").reason_code, "TOKEN_CAP_EXCEEDED")

    def test_cost_cap_and_provider_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            limited = BudgetPolicy.from_mapping({
                "schema_version": 1,
                "mode": "local_first_subscription_only",
                "limits": {
                    "per_run": {"input_tokens": 100, "output_tokens": 100, "cost": "0.10"},
                    "per_day": {"input_tokens": 100, "output_tokens": 100, "cost": "1"},
                    "per_candidate": {"input_tokens": 100, "output_tokens": 100, "cost": "1"},
                },
                "retry": {"max_attempts": 4, "backoff_seconds": [300, 900, 3600, 21600]},
                "deadline": {"max_ms": 120000, "max_response_bytes": 1000},
                "cloud_api": {"enabled": False, "spend_cap": "0"},
                "subscription": {"on_quota": "DEFERRED_QUOTA"},
            })
            ledger = BudgetLedger(Path(tmp) / "ledger.json", policy=limited, run_id="run", candidate_id="candidate")
            self.assertTrue(ledger.consume("subscription-cli", 1, 1, Decimal("0.10"), NOW).allowed)
            self.assertEqual(ledger.consume("subscription-cli", 1, 1, Decimal("0.01"), NOW).reason_code, "COST_CAP_EXCEEDED")
            disabled = BudgetLedger(Path(tmp) / "disabled.json", policy=limited, disabled_providers={"cloud-api"})
            self.assertEqual(disabled.consume("cloud-api", 1, 1, Decimal("0"), NOW).reason_code, "PROVIDER_DISABLED")

    def test_deadline_is_a_budget_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = BudgetLedger(Path(tmp) / "ledger.json", policy=policy()).consume("ollama", 1, 1, Decimal("0"), NOW, deadline_ms=0)
            self.assertEqual(result.reason_code, "DEADLINE_EXCEEDED")

    def test_concurrent_consume_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            strict = BudgetPolicy.from_mapping({
                "schema_version": 1,
                "mode": "local_first_subscription_only",
                "limits": {
                    "per_run": {"input_tokens": 1, "output_tokens": 0, "cost": "0"},
                    "per_day": {"input_tokens": 100, "output_tokens": 0, "cost": "0"},
                    "per_candidate": {"input_tokens": 100, "output_tokens": 0, "cost": "0"},
                },
                "retry": {"max_attempts": 4, "backoff_seconds": [300, 900, 3600, 21600]},
                "deadline": {"max_ms": 120000, "max_response_bytes": 1000},
                "cloud_api": {"enabled": False, "spend_cap": "0"},
                "subscription": {"on_quota": "DEFERRED_QUOTA"},
            })
            path = Path(tmp) / "ledger.json"

            def consume():
                return BudgetLedger(path, policy=strict, run_id="same-run", candidate_id="same-candidate").consume("ollama", 1, 0, Decimal("0"), NOW).allowed

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: consume(), range(8)))
            self.assertEqual(sum(results), 1)
            snapshot = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(snapshot["entries"]["ollama|2026-08-26|inheritance-gate"]["input_tokens"], 1)


if __name__ == "__main__":
    unittest.main()
