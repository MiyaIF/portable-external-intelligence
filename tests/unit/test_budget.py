import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from ei.inference.budget import BudgetLedger, BudgetPolicy


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