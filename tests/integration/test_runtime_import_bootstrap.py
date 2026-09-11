from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ei.installer import SetupSelection, _ensure_venv


class RuntimeImportBootstrapTests(unittest.TestCase):
    def test_created_venv_imports_engine_package_without_pythonpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine 日本語 space"
            package = engine / "src" / "ei"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("BOOTSTRAP_MARKER = 'ready'\n", encoding="utf-8")
            selection = SetupSelection(
                engine_root=engine,
                knowledge_root=root / "knowledge",
                runtime_root=root / "runtime",
                hosts=("codex-cli",),
                python_exe=Path(sys.executable),
            )

            contaminated_python_environment = {
                "PYTHONHOME": str(root / "invalid-python-home"),
                "PYTHONIOENCODING": "ascii",
                "PYTHONPATH": str(root / "untrusted-python-path"),
                "PYTHONUTF8": "0",
                "__PYVENV_LAUNCHER__": str(root / "wrong-python-launcher"),
            }
            with mock.patch.dict(os.environ, contaminated_python_environment):
                python, created = _ensure_venv(selection, Path(sys.executable))
                bootstrap = next((engine / ".venv").rglob("portable_external_intelligence_source.pth"))
                bootstrap.unlink()
                reused_python, reused_created = _ensure_venv(selection, Path(sys.executable))
            environment = os.environ.copy()
            environment.pop("PYTHONPATH", None)
            environment["PYTHONNOUSERSITE"] = "1"
            completed = subprocess.run(
                [str(python), "-B", "-c", "import ei; print(ei.BOOTSTRAP_MARKER)"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertTrue(created)
            self.assertFalse(reused_created)
            expected_python = engine.resolve() / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            self.assertEqual(python, expected_python)
            self.assertEqual(reused_python, python)
            self.assertTrue(bootstrap.is_file())
            self.assertNotIn(str(engine), bootstrap.read_text(encoding="ascii"))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "ready")


if __name__ == "__main__":
    unittest.main()
