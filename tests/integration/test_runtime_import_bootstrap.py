from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ei.config import load_settings
from ei.installer import SetupSelection, _ensure_venv, setup, update


class RuntimeImportBootstrapTests(unittest.TestCase):
    def _runtime_install(self, root: Path):
        profile = mock.patch.dict(os.environ, {
            "APPDATA": str(root / "appdata"), "LOCALAPPDATA": str(root / "localappdata"),
        })
        profile.start()
        self.addCleanup(profile.stop)
        notification = mock.patch("ei.installer._run_windows_notification_registration", return_value={
            "status": "UNAVAILABLE", "verified": False, "reason_code": "TEST_NO_NOTIFICATION_SERVICE",
        })
        notification.start()
        self.addCleanup(notification.stop)
        engine = root / "engine 日本語 space"
        for directory in ("src", "config", "schemas", "skills", "templates", "hooks"):
            shutil.copytree(Path.cwd() / directory, engine / directory,
                            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        lock = engine / "requirements-runtime.lock"
        self._write_dependency_lock(root, lock, "1.0")
        home = root / "codex-home"
        home.mkdir()
        selection = SetupSelection(
            engine_root=engine, knowledge_root=root / "knowledge",
            runtime_root=root / "runtime", hosts=("codex-cli",),
            organizer_provider="subscription-cli", organizer_host="codex-cli",
            host_homes={"codex-cli": home}, python_exe=Path(sys.executable),
            non_interactive=True, accept_plan=True,
        )
        installed = setup(selection)
        self.assertTrue(installed.ok, installed.to_dict())
        settings = load_settings(engine, runtime_root=root / "runtime")
        python = Path(json.loads(installed.manifest_path.read_text(encoding="utf-8"))["python_exe"])
        (root / "knowledge" / "existing-note.md").write_text("keep existing knowledge\n", encoding="utf-8")
        return selection, settings, python, lock

    def _write_dependency_lock(self, root: Path, lock: Path, version: str) -> None:
        # A real, offline wheel keeps pip/venv behavior in the regression test.
        wheel = root / f"ei_update_fixture-{version}-py3-none-any.whl"
        info = f"ei_update_fixture-{version}.dist-info"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(f"{info}/METADATA", f"Metadata-Version: 2.1\nName: ei-update-fixture\nVersion: {version}\n")
            archive.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            archive.writestr(f"{info}/RECORD", "")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        lock.write_text(f"--no-index\n{wheel.as_uri()} --hash=sha256:{digest}\n", encoding="utf-8")

    def _dependency_version(self, python: Path) -> str:
        result = subprocess.run(
            [str(python), "-I", "-B", "-c",
             "from importlib.metadata import version; print(version('ei-update-fixture'))"],
            capture_output=True, encoding="utf-8", check=True,
        )
        return result.stdout.strip()

    def _file_hashes(self, root: Path) -> dict[str, str]:
        return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.rglob("*") if path.is_file()}

    def test_already_current_update_applies_changed_runtime_lock_only_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection, settings, python, lock = self._runtime_install(root)
            knowledge_before = self._file_hashes(root / "knowledge")
            manifest_before = settings.paths.install_manifest_path.read_bytes()
            state_path = root / "runtime" / "venv-bootstrap-state.json"
            state_before = state_path.read_bytes()
            self.assertEqual(self._dependency_version(python), "1.0")
            self._write_dependency_lock(root, lock, "2.0")

            checked = update(settings, check_only=True)
            self.assertTrue(checked.ok, checked.to_dict())
            self.assertEqual(checked.reconciliation["status"], "ALREADY_CURRENT")
            skipped = update(replace(selection, python_exe=python, skip_venv=True))
            self.assertTrue(skipped.ok, skipped.to_dict())
            self.assertEqual(self._dependency_version(python), "1.0")
            self.assertEqual(state_path.read_bytes(), state_before)

            updated = update(settings)
            self.assertTrue(updated.ok, updated.to_dict())
            self.assertEqual(updated.reconciliation["status"], "ALREADY_CURRENT")
            self.assertEqual(self._dependency_version(python), "2.0")
            state_after = state_path.read_bytes()
            self.assertNotEqual(state_after, state_before)
            self.assertEqual(settings.paths.install_manifest_path.read_bytes(), manifest_before)
            self.assertEqual(self._file_hashes(root / "knowledge"), knowledge_before)

            # An unchanged lock must not reinstall dependencies on every update.
            real_run = subprocess.run
            def reject_pip(command, *args, **kwargs):
                if "pip" in command:
                    raise AssertionError("unchanged runtime lock reinstalled dependencies")
                return real_run(command, *args, **kwargs)
            with mock.patch("ei.installer.subprocess.run", side_effect=reject_pip):
                repeated = update(settings)
            self.assertTrue(repeated.ok, repeated.to_dict())
            self.assertEqual(state_path.read_bytes(), state_after)
            self.assertEqual(self._file_hashes(root / "knowledge"), knowledge_before)

    def test_already_current_update_reports_dependency_failure_without_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, settings, python, lock = self._runtime_install(root)
            runtime_before = self._file_hashes(root / "runtime")
            knowledge_before = self._file_hashes(root / "knowledge")
            home_before = self._file_hashes(root / "codex-home")
            self._write_dependency_lock(root, lock, "2.0")
            # A corrupt download/hash must fail before installation or a receipt.
            wheel = root / "ei_update_fixture-2.0-py3-none-any.whl"
            with wheel.open("ab") as stream:
                stream.write(b"corrupted after lock generation")
            failed = update(settings)
            self.assertFalse(failed.ok, failed.to_dict())
            self.assertTrue(failed.errors)
            self.assertEqual(self._dependency_version(python), "1.0")
            self.assertEqual(self._file_hashes(root / "runtime"), runtime_before)
            self.assertEqual(self._file_hashes(root / "knowledge"), knowledge_before)
            self.assertEqual(self._file_hashes(root / "codex-home"), home_before)

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
