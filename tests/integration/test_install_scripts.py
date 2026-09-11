import hashlib
import json
import shutil
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _require_contract(condition: bool, code: str) -> None:
    if not condition:
        raise AssertionError(code)


class InstallScriptTests(unittest.TestCase):
    def test_setup_bootstrap_import_does_not_require_runtime_crypto_dependency(self):
        repo = Path.cwd()
        script = """
import importlib.abc
import sys

class BlockCryptography(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptography' or fullname.startswith('cryptography.'):
            raise ModuleNotFoundError('blocked runtime dependency')
        return None

sys.meta_path.insert(0, BlockCryptography())
import ei.installer
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(repo / "src")
        result = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=repo,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper contract is Windows-specific")
    def test_install_is_idempotent_and_uninstall_preserves_unrelated_data(self):
        repo = Path.cwd()
        python_exe = sys.executable
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "codex"
            codex_home.mkdir()
            original_agents = "# Existing global instructions\n\nKeep client text separate from internal decisions.\n"
            (codex_home / "AGENTS.md").write_text(original_agents, encoding="utf-8")
            (codex_home / "config.toml").write_text('model = "existing-model-value"\n\n[desktop]\ndefaultTerminalLocation = "right"\n', encoding="utf-8")
            (codex_home / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"id": "user-stop", "hooks": []}]}}, indent=2) + "\n", encoding="utf-8")
            script = repo / "scripts" / "install.ps1"
            args = ["-RepoPath", str(repo), "-CodexHome", str(codex_home), "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli", "-PythonExe", python_exe, "-SkipVenv", "-NoScheduledTask"]
            first = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
            _require_contract(first.returncode == 0, "INSTALL_SCRIPT_FIRST_RUN_FAILED")
            config_once = (codex_home / "config.toml").read_bytes()
            hooks_once = (codex_home / "hooks.json").read_bytes()
            agents_once = (codex_home / "AGENTS.md").read_bytes()
            second = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
            _require_contract(second.returncode == 0, "INSTALL_SCRIPT_SECOND_RUN_FAILED")
            _require_contract(config_once == (codex_home / "config.toml").read_bytes(), "INSTALL_SCRIPT_CONFIG_NOT_IDEMPOTENT")
            _require_contract(hooks_once == (codex_home / "hooks.json").read_bytes(), "INSTALL_SCRIPT_HOOKS_NOT_IDEMPOTENT")
            _require_contract(agents_once == (codex_home / "AGENTS.md").read_bytes(), "INSTALL_SCRIPT_AGENTS_NOT_IDEMPOTENT")
            _require_contract((codex_home / "AGENTS.md").read_text(encoding="utf-8").count("external-intelligence:begin v1") == 1, "INSTALL_SCRIPT_AGENTS_BLOCK_DUPLICATED")
            hooks = json.loads(hooks_once)
            _require_contract("user-stop" in {item["id"] for item in hooks["hooks"]["Stop"]}, "INSTALL_SCRIPT_USER_HOOK_REMOVED")
            manifest = codex_home / "external-intelligence" / "install-manifest.json"
            _require_contract(manifest.exists(), "INSTALL_SCRIPT_MANIFEST_MISSING")
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            _require_contract(manifest_data["agents_block_version"] == "v1", "INSTALL_SCRIPT_AGENTS_VERSION_INVALID")
            _require_contract(Path(manifest_data["agents_backup"]).exists(), "INSTALL_SCRIPT_AGENTS_BACKUP_MISSING")

            manifest_sha256 = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
            uninstall = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repo / "scripts" / "uninstall.ps1"), "-ManifestPath", str(manifest), "-PythonExe", python_exe, "-ConfirmManifestSha256", manifest_sha256], capture_output=True, text=True, encoding="utf-8", errors="replace")
            _require_contract(uninstall.returncode == 0, "INSTALL_SCRIPT_UNINSTALL_FAILED")
            hooks_after = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
            _require_contract([item["id"] for item in hooks_after["hooks"]["Stop"]] == ["user-stop"], "INSTALL_SCRIPT_UNINSTALL_HOOKS_MISMATCH")
            _require_contract("[desktop]" in (codex_home / "config.toml").read_text(encoding="utf-8"), "INSTALL_SCRIPT_UNINSTALL_CONFIG_REMOVED")
            _require_contract((codex_home / "AGENTS.md").read_text(encoding="utf-8") == original_agents, "INSTALL_SCRIPT_UNINSTALL_AGENTS_MISMATCH")

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper contract is Windows-specific")
    def test_check_only_renders_scheduler_without_creating_venv_or_task_state(self):
        repo = Path.cwd()
        python_exe = sys.executable
        venv_existed = (repo / ".venv").exists()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "codex"
            result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repo / "scripts" / "install.ps1"), "-RepoPath", str(repo), "-CodexHome", str(codex_home), "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli", "-PythonExe", python_exe, "-CheckOnly"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CodexExternalIntelligenceMaintenance-v1", result.stdout)
            self.assertEqual((repo / ".venv").exists(), venv_existed)
            self.assertFalse((codex_home / "external-intelligence" / "scheduler-state.json").exists())

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper contract is Windows-specific")
    def test_check_only_does_not_create_any_external_target(self):
        repo = Path.cwd()
        python_exe = sys.executable
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "profile with spaces" / "codex"
            runtime = root / "runtime with spaces"
            knowledge = root / "knowledge with spaces"
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(repo / "scripts" / "setup.ps1"),
                    "-Repo",
                    str(repo),
                    "-RuntimeRoot",
                    str(runtime),
                    "-KnowledgeMode",
                    "local",
                    "-KnowledgeRoot",
                    str(knowledge),
                    "-Hosts",
                    "codex-cli",
                    "-OrganizerProvider",
                    "subscription-cli",
                    "-OrganizerHost",
                    "codex-cli",
                    "-HostHome",
                    f"codex-cli={codex_home}",
                    "-PythonExe",
                    python_exe,
                    "-SkipVenv",
                    "-CheckOnly",
                    "-NonInteractive",
                    "-Scheduler",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(codex_home.exists())
            self.assertFalse(runtime.exists())
            self.assertFalse(knowledge.exists())

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper contract is Windows-specific")
    def test_first_change_creates_same_directory_backup_and_manifest_metadata(self):
        repo = Path.cwd()
        python_exe = sys.executable
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "profile"
            runtime = root / "runtime"
            knowledge = root / "knowledge"
            codex_home.mkdir()
            original_config = b'model = "existing"\r\n'
            config = codex_home / "config.toml"
            config.write_bytes(original_config)
            (codex_home / "hooks.json").write_text('{"hooks":{"Stop":[{"id":"user-stop","hooks":[]}]}}\n', encoding="utf-8")
            (codex_home / "AGENTS.md").write_text("# user instructions\n", encoding="utf-8")
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(repo / "scripts" / "setup.ps1"),
                    "-Repo",
                    str(repo),
                    "-RuntimeRoot",
                    str(runtime),
                    "-KnowledgeMode",
                    "local",
                    "-KnowledgeRoot",
                    str(knowledge),
                    "-Hosts",
                    "codex-cli",
                    "-OrganizerProvider",
                    "subscription-cli",
                    "-OrganizerHost",
                    "codex-cli",
                    "-HostHome",
                    f"codex-cli={codex_home}",
                    "-PythonExe",
                    python_exe,
                    "-SkipVenv",
                    "-NonInteractive",
                    "-AcceptPlan",
                    "-Json",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            manifest = runtime / "install-manifest.json"
            self.assertTrue(manifest.is_file())
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertTrue(manifest_data["installed_at"])
            self.assertTrue(manifest_data["config_backup"])
            backup = Path(manifest_data["config_backup"])
            self.assertTrue(backup.is_file())
            self.assertIn(".before-ei-", backup.name)
            self.assertEqual(backup.read_bytes(), original_config)
            self.assertEqual(payload["status"], "SETUP_COMPLETE")

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper contract is Windows-specific")
    def test_noninteractive_setup_missing_required_paths_exits_two(self):
        repo = Path.cwd()
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(repo / "scripts" / "setup.ps1"),
                "-Repo",
                str(repo),
                "-PythonExe",
                sys.executable,
                "-NonInteractive",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("SETUP_NON_INTERACTIVE_PATHS_AND_HOSTS_REQUIRED", result.stdout)

    def test_posix_wrappers_pass_shell_syntax_when_sh_is_available(self):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable in this environment")
        for name in ("setup.sh", "update.sh", "uninstall.sh", "doctor.sh"):
            result = subprocess.run([shell, "-n", str(Path.cwd() / "scripts" / name)], capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")

    def test_setup_wrappers_forward_the_complete_plan_contract_without_eval(self):
        powershell = (Path.cwd() / "scripts" / "setup.ps1").read_text(encoding="utf-8")
        posix = (Path.cwd() / "scripts" / "setup.sh").read_text(encoding="utf-8")
        for token in (
            "knowledge-mode",
            "knowledge-root",
            "personal-knowledge-root",
            "team-knowledge-root",
            "team-member-id",
            "no-team-knowledge",
            "runtime-root",
            "github-repository",
            "github-executable",
            "remote-name",
            "branch",
            "accept-plan",
            "confirm-github-create",
            "no-sync",
            "organizer-provider",
            "organizer-host",
        ):
            self.assertIn(token, powershell.casefold())
            self.assertIn(token, posix.casefold())
        self.assertNotIn("invoke-expression", powershell.casefold())
        self.assertNotIn("install-scheduled-task.ps1", powershell.casefold())
        self.assertNotIn("eval ", posix.casefold())

    def test_setup_wrappers_preserve_legacy_personal_aliases(self):
        powershell = (Path.cwd() / "scripts" / "setup.ps1").read_text(encoding="utf-8")
        posix = (Path.cwd() / "scripts" / "setup.sh").read_text(encoding="utf-8")
        self.assertIn("KnowledgeRoot", powershell)
        self.assertIn("PersonalKnowledgeRoot", powershell)
        self.assertIn("--knowledge-root", posix)
        self.assertIn("--personal-knowledge-root", posix)

if __name__ == "__main__":
    unittest.main()
