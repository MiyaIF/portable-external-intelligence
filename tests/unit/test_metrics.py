import unittest

from ei.metrics import aggregate_usage


class MetricsTests(unittest.TestCase):
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
