from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import importlib.util


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit-production-source.py"
SPEC = importlib.util.spec_from_file_location("audit_production_source", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
audit_paths = MODULE.audit_paths


class ProductionPlaceholderTests(unittest.TestCase):
    def test_team_store_and_projection_are_real_production_paths(self) -> None:
        root = Path(__file__).resolve().parents[2]
        violations = audit_paths(root, ["src/ei/team_store.py", "src/ei/team_projection.py"])
        self.assertEqual(violations, [])

    def test_audit_rejects_all_forbidden_production_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {
                "empty_pass.py": "def unfinished():\n    pass\n",
                "unhandled.py": "def unfinished():\n    raise NotImplementedError()\n",
                "constant_success.py": "def fake_success():\n    return True\n",
                "test_import.py": "from unittest.mock import Mock\n",
            }
            for name, source in cases.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_text(source, encoding="utf-8")
                    violations = audit_paths(root, [str(path)])
                    self.assertTrue(violations)
                    if name == "empty_pass.py":
                        self.assertTrue(any("EMPTY_PASS" in item for item in violations))
                    elif name == "unhandled.py":
                        self.assertTrue(any("UNHANDLED_NOT_IMPLEMENTED" in item for item in violations))
                    elif name == "constant_success.py":
                        self.assertTrue(any("CONSTANT_SUCCESS_ROUTE" in item for item in violations))
                    else:
                        self.assertTrue(any("TEST_ONLY_IMPORT" in item for item in violations))


if __name__ == "__main__":
    unittest.main()
