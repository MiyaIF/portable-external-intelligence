from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("SCRIPT_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DependencyLockTests(unittest.TestCase):
    def test_checked_in_locks_match_exact_inputs_and_pyproject(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "scripts/verify-dependency-lock.py",
                "--pyproject",
                "pyproject.toml",
                "--build-lock",
                "requirements-build.lock",
                "--runtime-lock",
                "requirements-runtime.lock",
                "--ci-lock",
                "requirements-ci.lock",
                "--workflow-dir",
                ".github/workflows",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("sha256=", completed.stdout)

    def test_lock_parser_accepts_pip_compile_multiline_hashes_and_extras(self):
        module = _load_script("verify_dependency_lock", "verify-dependency-lock.py")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.lock"
            raw = "\n".join(
                [
                    "cachecontrol[filecache]==0.14.4 \\",
                    "    --hash=sha256:" + "a" * 64 + " \\",
                    "    --hash=sha256:" + "b" * 64,
                ]
            ) + "\n"
            path.write_text(raw, encoding="utf-8")
            entries = module._parse_lock(path)
        self.assertEqual(entries["cachecontrol"].version, "0.14.4")
        self.assertEqual(len(entries["cachecontrol"].hashes), 2)

    def test_sbom_is_deterministic_and_has_no_absolute_root(self):
        module = _load_script("generate_sbom", "generate-sbom.py")
        first = module.build_sbom(ROOT)
        second = module.build_sbom(ROOT)
        self.assertEqual(first, second)
        serialized = str(first)
        self.assertNotIn(str(ROOT), serialized)
        self.assertEqual(first["spdxVersion"], "SPDX-2.3")
        self.assertGreater(len(first["packages"]), 3)
        for package in first["packages"]:
            self.assertTrue(package["checksums"])
            self.assertTrue(str(package["downloadLocation"]).startswith("https://pypi.org/project/"))


if __name__ == "__main__":
    unittest.main()
