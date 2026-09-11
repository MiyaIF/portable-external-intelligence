import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.installer as installer
from ei.certification import REQUIRED_HOST_IDS
from ei.installer import SetupSelection
from ei.recovery import inspect_setup_operation_recovery


def _require_contract(condition: bool, code: str) -> None:
    if not condition:
        raise AssertionError(code)


class RollbackAcceptanceTests(unittest.TestCase):
    def test_rollback_scope_does_not_expand_to_host_set(self):
        self.assertEqual(len(REQUIRED_HOST_IDS), 4)

    @unittest.skipUnless(os.name == "nt", "PowerShell rollback wrapper contract is Windows-specific")
    def test_config_backup_restores_exact_original_bytes(self):
        repo = Path.cwd()
        python_exe = Path(sys.executable)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "codex"
            home.mkdir()
            config = home / "config.toml"
            hooks = home / "hooks.json"
            config.write_bytes(b"model = \"unchanged\"\r\n")
            hooks.write_bytes(b'{"hooks":{"Stop":[{"id":"user-stop","hooks":[]}]}}\n')
            original_config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
            original_hooks_hash = hashlib.sha256(hooks.read_bytes()).hexdigest()
            install = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repo / "scripts" / "install.ps1"), "-RepoPath", str(repo), "-CodexHome", str(home), "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli", "-PythonExe", str(python_exe), "-SkipVenv", "-NoScheduledTask"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            _require_contract(install.returncode == 0, "ROLLBACK_INSTALL_WRAPPER_FAILED")
            manifest = home / "external-intelligence" / "install-manifest.json"
            manifest_sha256 = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
            uninstall = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repo / "scripts" / "uninstall.ps1"), "-ManifestPath", str(manifest), "-PythonExe", str(python_exe), "-ConfirmManifestSha256", manifest_sha256, "-RestoreConfigBackup"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            _require_contract(uninstall.returncode == 0, "ROLLBACK_UNINSTALL_WRAPPER_FAILED")
            _require_contract(original_config_hash == hashlib.sha256(config.read_bytes()).hexdigest(), "ROLLBACK_CONFIG_BYTES_MISMATCH")
            hooks_after = json.loads(hooks.read_text(encoding="utf-8"))
            _require_contract([item["id"] for item in hooks_after["hooks"]["Stop"]] == ["user-stop"], "ROLLBACK_HOOKS_CONTENT_MISMATCH")
            _require_contract(original_hooks_hash != hashlib.sha256(hooks.read_bytes()).hexdigest(), "ROLLBACK_HOOKS_WERE_NOT_CANONICALISED")

    def test_interrupted_setup_rolls_back_only_this_invocation(self):
        repo = Path.cwd()
        python_exe = Path(sys.executable)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "codex"
            runtime = root / "runtime"
            home.mkdir()
            config = home / "config.toml"
            hooks = home / "hooks.json"
            agents = home / "AGENTS.md"
            original_config = b'model = "keep"\r\n'
            original_hooks = b'{"hooks":{"Stop":[{"id":"user-stop","hooks":[]}]}}\n'
            original_agents = b"# user instructions\n"
            config.write_bytes(original_config)
            hooks.write_bytes(original_hooks)
            agents.write_bytes(original_agents)
            selection = SetupSelection(
                repo_root=repo,
                runtime_root=runtime,
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": home},
                python_exe=python_exe,
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            original_mutate = installer._Transaction.mutate_file
            calls = {"count": 0}

            def fail_on_second(transaction, target, raw, **kwargs):
                calls["count"] += 1
                if calls["count"] == 2:
                    raise RuntimeError("forced interruption")
                return original_mutate(transaction, target, raw, **kwargs)

            with patch.object(installer._Transaction, "mutate_file", fail_on_second):
                result = installer.setup(selection)
            self.assertFalse(result.ok)
            self.assertEqual(result.rollback["status"], "ROLLED_BACK")
            self.assertEqual(config.read_bytes(), original_config)
            self.assertEqual(hooks.read_bytes(), original_hooks)
            self.assertEqual(agents.read_bytes(), original_agents)
            self.assertFalse((runtime / "install-manifest.json").exists())
            retained_knowledge = Path(str(result.knowledge["repository"]["root"]))
            self.assertTrue((retained_knowledge / "knowledge-repository.json").is_file())
            self.assertTrue(result.knowledge["repository"]["status"] == "READY")
            self.assertIn("KNOWLEDGE_RETAINED_FOR_RETRY", result.rollback["reason_codes"])
            self.assertTrue(any(path.name.startswith("config.toml.before-ei-") for path in root.rglob("config.toml.before-ei-*")))
            recovery = inspect_setup_operation_recovery(runtime)
            self.assertEqual(recovery.status, "complete")
            self.assertIsNone(recovery.resume_stage)

if __name__ == "__main__":
    unittest.main()
