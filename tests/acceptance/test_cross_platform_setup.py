import json
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.config import load_settings
from ei.installer import SetupSelection, UninstallOptions, setup, uninstall, update
from ei.skill_installer import canonical_tree_hash


class CrossPlatformSetupAcceptanceTests(unittest.TestCase):
    def test_public_setup_wrappers_expose_personal_and_optional_team_controls(self):
        powershell = (Path.cwd() / "scripts" / "setup.ps1").read_text(encoding="utf-8").casefold()
        posix = (Path.cwd() / "scripts" / "setup.sh").read_text(encoding="utf-8").casefold()
        for token in ("personal-knowledge-root", "team-knowledge-root", "team-member-id", "no-team-knowledge"):
            self.assertIn(token, powershell)
            self.assertIn(token, posix)

    def test_all_supported_cli_hosts_restore_update_and_uninstall_portably(self):
        source_repo = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clone = root / "clone with spaces"
            shutil.copytree(
                source_repo,
                clone,
                ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".superpowers"),
            )
            homes = {
                "codex-cli": root / "homes" / "codex profile",
                "claude-code": root / "homes" / "claude profile",
                "gemini-cli": root / "homes" / "gemini profile",
                "qwen-code": root / "homes" / "qwen profile",
            }
            for host_id, home in homes.items():
                home.mkdir(parents=True, exist_ok=True)
                context_name = "AGENTS.md" if host_id.startswith("codex") else {
                    "claude-code": "CLAUDE.md",
                    "gemini-cli": "GEMINI.md",
                    "qwen-code": "QWEN.md",
                }[host_id]
                context_path = home / context_name
                if not context_path.exists():
                    context_path.write_text(f"# user {host_id}\n", encoding="utf-8")
            runtime = root / "machine local runtime"
            knowledge = root / "private knowledge root"
            hosts = ("codex-cli", "claude-code", "gemini-cli", "qwen-code")
            selection = SetupSelection(
                repo_root=clone,
                knowledge_root=knowledge,
                runtime_root=runtime,
                hosts=hosts,
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes=homes,
                python_exe=Path(__import__("sys").executable),
                privacy_profile="private-reusable",
                sync=False,
                experiment=False,
                scheduler=False,
                skill_mode="copy",
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            self.assertEqual(first.status, "SETUP_COMPLETE")
            self.assertEqual(first.knowledge["repository"]["status"], "READY")
            capabilities = {item["host_id"]: item for item in first.to_dict()["hosts"]}
            self.assertEqual(capabilities["gemini-cli"]["skill_activation_mode"], "CONSENT_REQUIRED")
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 8)
            self.assertEqual(manifest["knowledge_repository"]["root"], str(knowledge.resolve()))
            self.assertFalse(manifest["knowledge_repository"]["connected"])
            self.assertEqual(set(manifest["hosts"]), set(hosts))
            source_skill = clone / "skills" / "external-intelligence"
            source_hash = canonical_tree_hash(source_skill)
            self.assertEqual(manifest["skill_source_hash"], source_hash)
            self.assertEqual(manifest["hosts"]["gemini-cli"]["skill_activation_mode"], "CONSENT_REQUIRED")
            for host_id in hosts:
                record = manifest["hosts"][host_id]
                self.assertEqual(record["source_skill_hash"], source_hash)
                self.assertEqual(record["installed_skill_hash"], source_hash)
                self.assertTrue(Path(record["skill_destination"]).is_dir())
                binding_path = Path(record["skill_binding_path"])
                self.assertTrue(binding_path.is_file())
                self.assertEqual(
                    record["skill_binding_hash"],
                    "sha256:" + hashlib.sha256(binding_path.read_bytes()).hexdigest(),
                )
                binding = json.loads(binding_path.read_text(encoding="utf-8"))
                self.assertEqual(binding["engine_root"], str(clone.resolve()))
                self.assertEqual(binding["knowledge_root"], str(knowledge.resolve()))
                self.assertEqual(binding["runtime_root"], str(runtime.resolve()))
                self.assertEqual(binding["skill_destination"], record["skill_destination"])
                context = Path(record["context_path"]).read_text(encoding="utf-8")
                self.assertIn("launcher.py", context)
                self.assertIn("-I", context)
                self.assertIn("-B", context)
                expected_host_id = "codex-cli" if host_id.startswith("codex") else host_id
                expected_user = f"# user {expected_host_id}"
                self.assertIn(expected_user, context)
                self.assertIn("--engine-root", context)
                self.assertIn(str(clone.resolve()), context)
                self.assertIn("--runtime-root", context)
                self.assertIn(str(runtime.resolve()), context)
            codex_hooks = json.loads((homes["codex-cli"] / "hooks.json").read_text(encoding="utf-8"))
            codex_ids = {
                entry["id"]
                for entries in codex_hooks["hooks"].values()
                for entry in entries
                if isinstance(entry, dict) and isinstance(entry.get("id"), str)
            }
            self.assertTrue(any(item.startswith("ei-codex-cli-") for item in codex_ids))
            self.assertFalse(any(item.endswith("-codex-app") for item in codex_ids))
            command_values = [
                handler.get(key)
                for entries in codex_hooks["hooks"].values()
                for entry in entries
                if isinstance(entry, dict)
                for handler in entry.get("hooks", [])
                if isinstance(handler, dict)
                for key in ("command", "commandWindows")
                if key in handler
            ]
            self.assertTrue(command_values)
            self.assertTrue(all("--engine-root" in value and "--knowledge-root" in value and "--runtime-root" in value for value in command_values))
            self.assertTrue(all(str(knowledge.resolve()) in value and str(runtime.resolve()) in value for value in command_values))
            self.assertTrue((runtime / "queue").is_dir())
            self.assertFalse(runtime.is_relative_to(clone))
            tracked = subprocess.run(
                ["git", "-C", str(source_repo), "ls-files", "--error-unmatch", "skills/external-intelligence/SKILL.md"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(tracked.returncode, 0, tracked.stderr)
            missing_binding = Path(manifest["hosts"]["codex-cli"]["skill_binding_path"])
            missing_binding.unlink()
            settings = load_settings(
                engine_root=clone,
                knowledge_root=knowledge,
                codex_home=homes["codex-cli"],
                runtime_root=runtime,
                host_homes=homes,
            )
            updated = update(settings)
            self.assertTrue(updated.ok, updated.to_dict())
            self.assertTrue(missing_binding.is_file())
            preflight = updated.to_dict()["preflight"]
            self.assertEqual(preflight["current"]["source_skill_hash"], source_hash)
            self.assertIn(preflight["migration"]["status"], {"NOT_CONFIGURED", "DRY_RUN"})
            self.assertTrue(Path(preflight["artifact_path"]).is_file())
            self.assertTrue((runtime / "canary-invalidation.json").is_file())
            removed = uninstall(settings, UninstallOptions(remove_skills=True, remove_runtime=False, remove_runtime_cache=False, remove_scheduler=True, remove_venv=False))
            self.assertTrue(removed.ok, removed.to_dict())
            for host_id in hosts:
                record = manifest["hosts"][host_id]
                expected_host_id = "codex-cli" if host_id.startswith("codex") else host_id
                expected_user = f"# user {expected_host_id}"
                self.assertIn(expected_user, Path(record["context_path"]).read_text(encoding="utf-8"))
                self.assertFalse(Path(record["skill_destination"]).exists())
                self.assertFalse(Path(record["skill_binding_path"]).exists())
            self.assertTrue(source_skill.is_dir())
            self.assertTrue((runtime / "install-manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
