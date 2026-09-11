from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.cli import main
from ei.config import load_active_install_manifest, load_settings
from ei.doctor import run_doctor
from ei.installer import SetupSelection, setup
from ei.remote_assurance import build_remote_assurance_receipt, classify_remote, write_remote_assurance_receipt


class ManifestRestartIntegrationTests(unittest.TestCase):
    def _installed(self, root: Path) -> tuple[Path, Path, Path]:
        engine = Path.cwd()
        knowledge = root / "private knowledge 日本語"
        runtime = root / "runtime 日本語"
        home = root / "host home"
        home.mkdir()
        result = setup(
            SetupSelection(
                engine_root=engine,
                knowledge_root=knowledge,
                runtime_root=runtime,
                hosts=("codex-cli",),
                host_homes={"codex-cli": home},
                python_exe=Path(__import__("sys").executable),
                providers=("ollama", "subscription-cli"),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                experiment=True,
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
        )
        self.assertTrue(result.ok, result.to_dict())
        remote = root / "private-remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(knowledge), "remote", "add", "origin", str(remote)], check=True)
        subprocess.run(["git", "-C", str(knowledge), "push", "origin", "HEAD:refs/heads/main"], check=True, capture_output=True)
        descriptor = classify_remote(remote)
        write_remote_assurance_receipt(runtime, build_remote_assurance_receipt(descriptor))
        manifest_path = runtime / "install-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sync_enabled"] = True
        manifest["knowledge_repository"].update(
            {
                "mode": "github-existing",
                "remote_name": "origin",
                "remote_fingerprint": descriptor.fingerprint,
                "remote_classification": "local_path",
                "branch": "main",
                "connected": True,
                "initial_push_complete": True,
                "sync_enabled": True,
            }
        )
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return engine.resolve(), knowledge.resolve(), runtime.resolve()

    def test_load_settings_restores_roots_provider_sync_and_experiment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, knowledge, runtime = self._installed(Path(tmp))

            manifest = load_active_install_manifest(runtime, expected_engine_root=engine)
            settings = load_settings(engine, runtime_root=runtime)

            self.assertEqual(manifest["schema_version"], 8)
            self.assertEqual(manifest["knowledge_stores"]["personal"]["root"], str(knowledge))
            self.assertIsNone(manifest["knowledge_stores"]["team"])
            self.assertEqual(Path(manifest["knowledge_root"]), knowledge)
            self.assertEqual(settings.paths.engine_root, engine)
            self.assertEqual(settings.paths.knowledge_root, knowledge)
            self.assertEqual(settings.paths.runtime_root, runtime)
            self.assertEqual(settings.provider_order, ("subscription-cli",))
            self.assertEqual(settings.privacy_profile, "private-reusable")
            self.assertTrue(settings.sync_enabled)
            self.assertEqual(settings.sync_remote, "origin")
            self.assertEqual(settings.sync_branch, "main")
            self.assertEqual(settings.sync_remote_fingerprint, manifest["knowledge_repository"]["remote_fingerprint"])
            self.assertEqual(settings.sync_remote_classification, "local_path")
            self.assertTrue(settings.experiment_enabled)

    def test_explicit_root_mismatch_and_foreign_manifest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = self._installed(root)
            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_ENGINE_MISMATCH$"):
                load_settings(engine_root=root / "other-engine", runtime_root=runtime)
            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_KNOWLEDGE_MISMATCH$"):
                load_settings(engine_root=engine, knowledge_root=root / "other-knowledge", runtime_root=runtime)

            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["runtime_root"] = str(root / "foreign-runtime")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_RUNTIME_MISMATCH$"):
                load_active_install_manifest(runtime, expected_engine_root=engine)

    def test_runtime_commands_use_manifest_without_repeating_knowledge_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, _, runtime = self._installed(Path(tmp))
            commands = (
                ["status", "--repo", str(engine), "--runtime-root", str(runtime), "--json"],
                ["doctor", "--repo", str(engine), "--runtime-root", str(runtime), "--json"],
                ["recall", "--repo", str(engine), "--runtime-root", str(runtime), "--query", "reusable knowledge", "--json"],
                ["maintain", "--repo", str(engine), "--runtime-root", str(runtime), "--dry-run", "--json"],
            )
            for command in commands:
                with self.subTest(command=command[0]):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main(command)
                    self.assertEqual(code, 0, output.getvalue())
                    payload = json.loads(output.getvalue())
                    if command[0] == "status":
                        self.assertTrue(payload["sync"]["enabled"])

    def test_strict_doctor_accepts_generated_schema_v2_skill_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, _, runtime = self._installed(Path(tmp))

            report = run_doctor(load_settings(engine, runtime_root=runtime), strict=True)

            hosts_check = next(item for item in report.checks if item["name"] == "hosts")
            host = hosts_check["hosts"][0]
            self.assertTrue(hosts_check["ok"], hosts_check)
            self.assertTrue(host["skill"]["binding"]["ok"], host["skill"]["binding"])
            self.assertIsNone(host["skill"]["binding"]["reason_code"])

    def test_doctor_detects_when_a_verified_github_remote_becomes_public(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, knowledge, runtime = self._installed(Path(tmp))
            remote = "https://github.com/MiyaIF/knowledge-now-public.git"
            subprocess.run(["git", "-C", str(knowledge), "remote", "set-url", "origin", remote], check=True)
            descriptor = classify_remote(remote, visibility="private")
            write_remote_assurance_receipt(runtime, build_remote_assurance_receipt(descriptor))
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["knowledge_repository"]["remote_fingerprint"] = descriptor.fingerprint
            manifest["knowledge_repository"]["remote_classification"] = descriptor.classification
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            settings = load_settings(engine, runtime_root=runtime)

            with patch("ei.remote_assurance._probe_github_visibility", return_value=("public", "github_api")):
                report = run_doctor(settings, strict=True)

            knowledge_check = next(item for item in report.checks if item["name"] == "knowledge_repository")
            self.assertFalse(knowledge_check["ok"])
            self.assertEqual(knowledge_check["reason_code"], "PRIVATE_REMOTE_REQUIRED")

    def test_strict_doctor_detects_missing_skill_runtime_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, _, runtime = self._installed(Path(tmp))
            manifest = json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8"))
            binding_path = Path(manifest["hosts"]["codex-cli"]["skill_binding_path"])
            binding_path.unlink()

            report = run_doctor(load_settings(engine, runtime_root=runtime), strict=True)

            hosts_check = next(item for item in report.checks if item["name"] == "hosts")
            host = hosts_check["hosts"][0]
            self.assertFalse(hosts_check["ok"])
            self.assertFalse(host["skill"]["binding"]["ok"])
            self.assertEqual(host["skill"]["binding"]["reason_code"], "SKILL_BINDING_MISSING")

    def test_strict_doctor_detects_tampered_generated_skill_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, _, runtime = self._installed(Path(tmp))
            manifest = json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8"))
            context_path = Path(manifest["hosts"]["codex-cli"]["context_path"])
            content = context_path.read_text(encoding="utf-8")
            self.assertIn("launcher.py", content)
            context_path.write_text(content.replace("launcher.py", "launcher-tampered.py", 1), encoding="utf-8")

            report = run_doctor(load_settings(engine, runtime_root=runtime), strict=True)

            hosts_check = next(item for item in report.checks if item["name"] == "hosts")
            host = hosts_check["hosts"][0]
            self.assertFalse(hosts_check["ok"])
            self.assertFalse(host["context"]["ok"])
            self.assertEqual(host["context"]["reason_code"], "MANAGED_CONTEXT_MISMATCH")


if __name__ == "__main__":
    unittest.main()
