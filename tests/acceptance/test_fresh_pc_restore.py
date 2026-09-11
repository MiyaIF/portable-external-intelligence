from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ei.certification import REQUIRED_HOST_IDS
from ei.config import load_settings
from ei.installer import SetupSelection, UninstallOptions, setup as setup_engine, uninstall, update
from ei.knowledge_repository import inspect_knowledge_repository
from ei.remote_assurance import build_remote_assurance_receipt, classify_remote, write_remote_assurance_receipt
from ei.skill_installer import canonical_tree_hash


class FreshPcRestoreTests(unittest.TestCase):
    def test_isolated_profile_install_doctor_and_hook_paths_are_portable(self) -> None:
        source_repo = Path.cwd().resolve()
        with tempfile.TemporaryDirectory(prefix="ei-fresh-profile-") as tmp:
            root = Path(tmp)
            clone = root / "ei clone 日本語"
            shutil.copytree(
                source_repo,
                clone,
                ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".superpowers", "artifacts", "build"),
            )
            homes = {
                "codex-cli": root / "homes" / "codex profile",
                "claude-code": root / "homes" / "claude profile",
                "gemini-cli": root / "homes" / "gemini profile",
                "qwen-code": root / "homes" / "qwen profile",
            }
            for host_id, home in homes.items():
                home.mkdir(parents=True, exist_ok=True)
                context_name = {
                    "codex-cli": "AGENTS.md",
                    "claude-code": "CLAUDE.md",
                    "gemini-cli": "GEMINI.md",
                    "qwen-code": "QWEN.md",
                }[host_id]
                (home / context_name).write_text(f"# user {host_id}\n", encoding="utf-8")
            knowledge = root / "private knowledge 日本語"
            runtime = root / "machine runtime 日本語"
            environment = {
                **os.environ,
                "PYTHONPATH": str(clone / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "CODEX_HOME": str(homes["codex-cli"]),
                "CLAUDE_CONFIG_DIR": str(homes["claude-code"]),
                "GEMINI_HOME": str(homes["gemini-cli"]),
                "QWEN_HOME": str(homes["qwen-code"]),
            }
            setup_args = [
                sys.executable,
                "-B",
                "-m",
                "ei.installer",
                "--setup",
                "--engine-root",
                str(clone),
                "--knowledge-root",
                str(knowledge),
                "--knowledge-mode",
                "local",
                "--runtime-root",
                str(runtime),
                "--organizer-provider",
                "subscription-cli",
                "--organizer-host",
                "codex-cli",
                "--python-exe",
                sys.executable,
                "--skip-venv",
                "--non-interactive",
                "--accept-plan",
                "--json",
            ]
            for host_id, home in homes.items():
                setup_args.extend(("--hosts", host_id, "--host-home", f"{host_id}={home}"))
            setup = subprocess.run(setup_args, cwd=clone, env=environment, capture_output=True, text=True)
            self.assertEqual(setup.returncode, 0, setup.stdout + setup.stderr)
            result = json.loads(setup.stdout)
            self.assertTrue(result["ok"], result)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(set(manifest["hosts"]), set(REQUIRED_HOST_IDS))
            self.assertEqual(set(manifest["supported_hosts"]), set(REQUIRED_HOST_IDS))
            source_skill = clone / "skills" / "external-intelligence"
            source_hash = canonical_tree_hash(source_skill)
            self.assertEqual(manifest["skill_source_hash"], source_hash)
            self.assertFalse(Path(manifest["runtime_root"]).is_relative_to(clone))
            for host_id in REQUIRED_HOST_IDS:
                record = manifest["hosts"][host_id]
                self.assertEqual(record["source_skill_hash"], source_hash)
                self.assertEqual(record["installed_skill_hash"], source_hash)
                self.assertTrue(Path(record["skill_destination"]).is_dir())
                self.assertIn(f"# user {host_id}", Path(record["context_path"]).read_text(encoding="utf-8"))

            doctor = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ei.cli",
                    "doctor",
                    "--engine-root",
                    str(clone),
                    "--runtime-root",
                    str(runtime),
                    "--json",
                ],
                cwd=clone,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(doctor.returncode, 0, doctor.stdout + doctor.stderr)
            doctor_value = json.loads(doctor.stdout)
            self.assertIn("checks", doctor_value)

    def _connected_local_install(self, root: Path):
        engine = Path.cwd().resolve()
        knowledge = root / "knowledge"
        runtime = root / "runtime"
        home = root / "home"
        home.mkdir()
        result = setup_engine(
            SetupSelection(
                engine_root=engine,
                knowledge_root=knowledge,
                runtime_root=runtime,
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": home},
                python_exe=Path(sys.executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
        )
        self.assertTrue(result.ok, result.to_dict())
        remote = root / "knowledge-remote.git"
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
                "remote_classification": descriptor.classification,
                "branch": "main",
                "connected": True,
                "initial_push_complete": True,
                "sync_enabled": True,
            }
        )
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return engine, knowledge, runtime, manifest_path, descriptor.fingerprint

    def test_update_preserves_knowledge_commit_digest_and_remote_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, knowledge, runtime, manifest_path, fingerprint = self._connected_local_install(Path(tmp))
            before = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)
            before_head = subprocess.run(["git", "-C", str(knowledge), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

            result = update(load_settings(engine, runtime_root=runtime))

            self.assertTrue(result.ok, result.to_dict())
            after = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)
            after_head = subprocess.run(["git", "-C", str(knowledge), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            updated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(after.root_digest, before.root_digest)
            self.assertEqual(after_head, before_head)
            self.assertEqual(updated_manifest["knowledge_repository"]["remote_fingerprint"], fingerprint)
            self.assertEqual(updated_manifest["knowledge_repository"]["mode"], "github-existing")

    def test_default_uninstall_records_and_preserves_knowledge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine, knowledge, runtime, manifest_path, fingerprint = self._connected_local_install(Path(tmp))
            settings = load_settings(engine, runtime_root=runtime)
            before = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)

            result = uninstall(settings, UninstallOptions())

            self.assertTrue(result.ok, result.to_dict())
            after = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)
            self.assertEqual(after.root_digest, before.root_digest)
            self.assertEqual(after.remote_names, before.remote_names)
            self.assertTrue(result.knowledge["retained"])
            self.assertEqual(result.knowledge["remote_fingerprint"], fingerprint)
            uninstalled_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(uninstalled_manifest["knowledge_retained"])


if __name__ == "__main__":
    unittest.main()
