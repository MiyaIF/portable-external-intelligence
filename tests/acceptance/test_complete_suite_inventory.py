from __future__ import annotations

import unittest
from pathlib import Path

from ei.test_runner import discover_test_modules


class CompleteSuiteInventoryTests(unittest.TestCase):
    def test_every_tracked_test_module_has_a_unique_module_name(self) -> None:
        root = Path(__file__).resolve().parents[2]
        modules = discover_test_modules(root)
        self.assertGreater(len(modules), 0)
        names = [item.module_name for item in modules]
        self.assertEqual(names, sorted(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(item.relative_path.startswith("tests/") for item in modules))


if __name__ == "__main__":
    unittest.main()
