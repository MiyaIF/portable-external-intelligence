import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from ei.inference.base import InferenceBudget
from ei.inference.cli_subscription import SubscriptionCLIProvider


class SubscriptionQuotaIntegrationTests(unittest.TestCase):
    def test_quota_candidate_is_deferred_and_available_for_later_drain(self):
        with tempfile.TemporaryDirectory() as tmp:
            responses = [
                SimpleNamespace(returncode=1, stdout="", stderr="quota exceeded; reset later"),
                SimpleNamespace(returncode=0, stdout='{"decision":"YES"}', stderr=""),
            ]

            def runner(*args, **kwargs):
                del args, kwargs
                return responses.pop(0)

            state_path = Path(tmp) / "provider-state.json"
            provider = SubscriptionCLIProvider(
                ("subscription-cli", "--structured"),
                state_path=state_path,
                runner=runner,
            )
            first = provider.generate("gate-decision", {"candidate": "safe"}, InferenceBudget(max_input_tokens=1000, max_output_tokens=1000))
            self.assertTrue(first.deferred)
            self.assertEqual(first.error_code, "QUOTA_EXHAUSTED")
            self.assertIsNotNone(first.next_eligible_at)
            self.assertIn("QUOTA_DEFERRED", state_path.read_text(encoding="utf-8"))
            self.assertTrue(provider.available())
            second = provider.generate("gate-decision", {"candidate": "safe"}, InferenceBudget(max_input_tokens=1000, max_output_tokens=1000))
            self.assertTrue(second.ok)
            self.assertEqual(second.output["decision"], "YES")


if __name__ == "__main__":
    unittest.main()