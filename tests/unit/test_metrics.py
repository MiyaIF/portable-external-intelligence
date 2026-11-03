import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.metrics import aggregate_usage, collect_local_metrics
from ei.operation_runtime import OperationBudget


class MetricsTests(unittest.TestCase):
    def _database(self, root, count=1):
        path = root / "usage.sqlite"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE turn_usage(id INTEGER, input_tokens INTEGER, cached_input_tokens INTEGER, created_at TEXT)")
            connection.executemany("INSERT INTO turn_usage VALUES (?, 100, 80, '2026-09-18')", ((number,) for number in range(count)))
        connection.close()
        return path

    def test_zero_budget_does_not_discover_or_replace_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "usage-latest.json"
            snapshot.write_text("previous", encoding="utf-8")
            with patch("ei.metrics.os.scandir", side_effect=AssertionError("no discovery")):
                with self.assertRaisesRegex(TimeoutError, "OPERATION_BUDGET_EXHAUSTED"):
                    collect_local_metrics(root, root, budget=OperationBudget(0))
            self.assertEqual(snapshot.read_text(encoding="utf-8"), "previous")

    def test_sqlite_interruption_retains_snapshot_then_next_run_progresses(self):
        class InterruptedBudget:
            checks = 0

            def remaining_ms(self):
                return 30000

            def check(self):
                self.checks += 1
                if self.checks >= 40:
                    raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._database(root, 5000)
            snapshot = root / "usage-latest.json"
            snapshot.write_text("previous", encoding="utf-8")
            with self.assertRaisesRegex(TimeoutError, "OPERATION_BUDGET_EXHAUSTED"):
                collect_local_metrics(root, root, budget=InterruptedBudget())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), "previous")
            result = collect_local_metrics(root, root, budget=OperationBudget(30000))
            self.assertEqual(result.status, "OK")
            self.assertEqual(result.aggregate.user_environment.turns, 5000)
            self.assertEqual(json.loads(snapshot.read_text(encoding="utf-8"))["aggregate"]["user_environment"]["input_tokens"], 500000)

    def test_aggregation_checks_residual_budget_inside_iteration(self):
        def rows():
            yield {"id": "one", "source": "local_sqlite", "input": 100, "cached": 80}
            raise AssertionError("zero budget must not consume rows")
        with self.assertRaises(TimeoutError):
            aggregate_usage(rows(), budget=OperationBudget(0))

    def test_external_reference_never_enters_user_totals(self):
        rows = [
            {"id": "local-1", "source": "local_sqlite", "input": 100, "cached": 80},
            {"id": "article", "source": "external_article_copy", "input": 48_350_000, "cached": 47_720_000},
        ]
        result = aggregate_usage(rows)
        self.assertEqual(result.user_environment.input_tokens, 100)
        self.assertEqual(result.user_environment.cached_input_tokens, 80)
        self.assertEqual(result.external_reference.input_tokens, 48_350_000)

    def test_duplicate_turn_usage_is_counted_once(self):
        rows = [
            {"id": "turn-1", "source": "local_sqlite", "input": 100, "cached": 80},
            {"id": "turn-1", "source": "local_sqlite", "input": 100, "cached": 80},
        ]
        self.assertEqual(aggregate_usage(rows).user_environment.input_tokens, 100)


if __name__ == "__main__":
    unittest.main()
