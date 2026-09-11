import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ScheduledTaskScriptTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Task Scheduler wrapper contract is Windows-specific")
    def test_check_only_renders_without_registering_a_real_task(self):
        repo = Path.cwd()
        python_exe = sys.executable
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "codex home 日本語"
            command = [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repo / "scripts" / "install-scheduled-task.ps1"),
                "-RepoPath", str(repo), "-CodexHome", str(home), "-PythonExe", python_exe, "-CheckOnly",
            ]
            environment = os.environ.copy()
            environment.update({"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"})
            completed = subprocess.run(command, env=environment, capture_output=True)
            stderr = completed.stderr.decode("utf-8", errors="replace")
            self.assertEqual(completed.returncode, 0, stderr)
            output = json.loads(completed.stdout.decode("utf-8", errors="strict"))
            self.assertEqual(output["task_name"], "CodexExternalIntelligenceMaintenance-v1")
            self.assertEqual(output["argv"][:4], ["-m", "ei.cli", "maintain", "--json"])
            self.assertNotIn("cmd /c", output["arguments"].casefold())
            self.assertIn("registration_preview", output)
            self.assertEqual(output["registration_preview"]["repetition_interval"], "PT30M")
            self.assertEqual(output["registration_preview"]["repetition_duration"], "P3650D")
            self.assertFalse(output["registration_preview"]["stop_at_duration_end"])
            self.assertEqual(output["registration_preview"]["principal_source"], "current-user-default")
            self.assertEqual(output["registration_preview"]["logon_type"], "Interactive")
            self.assertEqual(output["registration_preview"]["run_level"], "Limited")
            self.assertEqual(output["registration_preview"]["trigger_mode"], "once-with-repetition")
            self.assertFalse((home / "external-intelligence" / "scheduler-state.json").exists())

    def test_scripts_contain_no_cmd_shell_bridge(self):
        repo = Path.cwd()
        for name in ("install-scheduled-task.ps1", "remove-scheduled-task.ps1", "install-launchd.sh", "install-systemd-user.sh"):
            text = (repo / "scripts" / name).read_text(encoding="utf-8")
            self.assertNotIn("cmd /c", text.casefold())
            self.assertNotIn("sh -c", text.casefold())
            self.assertNotIn("bash -c", text.casefold())
            self.assertIn("runtime-root", text.casefold())
        windows = (repo / "scripts" / "install-scheduled-task.ps1").read_text(encoding="utf-8")
        self.assertNotIn("New-ScheduledTaskPrincipal", windows)
        self.assertNotIn("-Principal $principal", windows)
        self.assertNotIn("-AtLogOn", windows)
        for name in ("certify-host.sh", "install-launchd.sh", "install-systemd-user.sh"):
            text = (repo / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn("engine-root", text.casefold())
            self.assertIn("knowledge-root", text.casefold())


if __name__ == "__main__":
    unittest.main()
