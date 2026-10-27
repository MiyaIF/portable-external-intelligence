import json
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support.sitecustomize import (
    NotificationIsolation,
    _install_guard,
    is_powershell_execution_policy_refusal,
)


@contextlib.contextmanager
def _sentinel_process_boundary():
    original_run = subprocess.run
    original_popen = subprocess.Popen
    calls = []
    popen_result = object()

    def sentinel_run(*args, **kwargs):
        command = args[0] if args else kwargs.get("args")
        calls.append(("run", command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="sentinel-output", stderr="")

    class SentinelPopen:
        def __new__(cls, *args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            calls.append(("popen", command, kwargs))
            return popen_result

    subprocess.run = sentinel_run
    subprocess.Popen = SentinelPopen
    try:
        _install_guard()
        yield calls, popen_result
    finally:
        subprocess.run = original_run
        subprocess.Popen = original_popen


class ScheduledTaskScriptTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Task Scheduler wrapper contract is Windows-specific")
    def test_check_only_renders_without_registering_a_real_task(self):
        repo = Path.cwd()
        python_exe = sys.executable
        with NotificationIsolation() as isolation:
            self.assertIsNotNone(isolation.root)
            root = isolation.root / "scheduled-task-check-only"
            root.mkdir()
            home = root / "codex home 日本語"
            script = repo / "scripts" / "install-scheduled-task.ps1"
            harness = root / "scheduled-task-check-only-harness.ps1"
            harness.write_text(
                r'''param(
  [string]$TargetScript,
  [string]$RepoPath,
  [string]$CodexHome,
  [string]$KnowledgeRoot,
  [string]$RuntimeRoot,
  [string]$PythonExe,
  [string]$PrivateSystemRoot
)
$ErrorActionPreference = 'Stop'
function Register-ScheduledTask { [Console]::Error.WriteLine('TEST_FORBIDDEN_REGISTER_SCHEDULED_TASK'); throw 'SCHEDULED_TASK_REGISTRATION_FORBIDDEN' }
function Unregister-ScheduledTask { [Console]::Error.WriteLine('TEST_FORBIDDEN_UNREGISTER_SCHEDULED_TASK'); throw 'SCHEDULED_TASK_UNREGISTRATION_FORBIDDEN' }
$env:SystemRoot = [IO.Path]::GetFullPath($PrivateSystemRoot)
& $TargetScript -RepoPath $RepoPath -CodexHome $CodexHome -KnowledgeRoot $KnowledgeRoot -RuntimeRoot $RuntimeRoot -PythonExe $PythonExe -CheckOnly
exit $LASTEXITCODE
''',
                encoding="utf-8",
                newline="\n",
            )
            host_system_root = os.environ.get("WINDIR")
            self.assertTrue(
                host_system_root
                and (Path(host_system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").is_file()
            )
            environment = os.environ.copy()
            environment["SystemRoot"] = str(Path(host_system_root).resolve())
            environment["PYTHONIOENCODING"] = "ascii"
            environment["PYTHONUTF8"] = "0"
            environment["PYTHONPATH"] = os.pathsep.join(
                filter(None, (str(repo / "tests" / "support"), str(repo / "src"), environment.get("PYTHONPATH")))
            )
            command = [
                "powershell.exe", "-NoProfile", "-File", str(harness),
                "-TargetScript", str(script), "-RepoPath", str(repo), "-CodexHome", str(home),
                "-KnowledgeRoot", str(root / "knowledge"), "-RuntimeRoot", str(root / "runtime"),
                "-PythonExe", python_exe, "-PrivateSystemRoot", os.environ["EI_TEST_NOTIFICATION_PRIVATE_SYSTEM_ROOT"],
            ]
            completed = subprocess.run(command, env=environment, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
            stderr = completed.stderr.decode("utf-8", errors="replace")
            if is_powershell_execution_policy_refusal(completed.stdout, completed.stderr):
                self.skipTest("PowerShell execution policy refused the CheckOnly harness; no override was used, so rendering remains unverified")
            self.assertEqual(completed.returncode, 0, stderr)
            output = json.loads(completed.stdout.decode("utf-8", errors="strict"))
            self.assertNotIn("TEST_FORBIDDEN_REGISTER_SCHEDULED_TASK", stderr)
            self.assertNotIn("TEST_FORBIDDEN_UNREGISTER_SCHEDULED_TASK", stderr)
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
            self.assertFalse((root / "runtime" / "scheduler-state.json").exists())

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

    def test_run_rejects_execution_policy_override_forms_before_delegation(self):
        commands = (
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "unsafe.ps1"],
            ["PWSH.EXE", "-ep", "Unrestricted", "-Command", "Get-ExecutionPolicy"],
            ["powershell.exe", "-ExecutionPolicy:RemoteSigned", "-Command", "Get-ExecutionPolicy"],
            ["pwsh", "-EP=Bypass", "-Command", "Get-ExecutionPolicy"],
            ["cmd.exe", "/d", "/c", "powershell.exe -ExecutionPolicy Bypass -File unsafe.ps1"],
        )
        with _sentinel_process_boundary() as (calls, _):
            for command in commands:
                with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(AssertionError, "TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED"):
                        subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(calls, [])

    def test_run_rejects_policy_changing_commands_and_case_variants(self):
        commands = (
            ["powershell.exe", "-NoProfile", "-Command", "Set-ExecutionPolicy Bypass -Scope Process"],
            ["pwsh.exe", "-Command", "set-executionpolicy -ExecutionPolicy Unrestricted -Scope CurrentUser"],
            ["PowerShell", "-c", "& Set-ExecutionPolicy -Scope Process Bypass"],
        )
        with _sentinel_process_boundary() as (calls, _):
            for command in commands:
                with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(AssertionError, "TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED"):
                        subprocess.run(command, check=False)
            self.assertEqual(calls, [])

    def test_popen_check_call_and_check_output_cannot_bypass_policy_guard(self):
        command = ["pwsh.exe", "-ep", "Bypass", "-File", "unsafe.ps1"]
        with _sentinel_process_boundary() as (calls, _):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(AssertionError, "TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED"):
                    subprocess.Popen(command)
                with self.assertRaisesRegex(AssertionError, "TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED"):
                    subprocess.check_call(command)
                with self.assertRaisesRegex(AssertionError, "TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED"):
                    subprocess.check_output(["powershell.exe", "-Command", "Set-ExecutionPolicy Bypass -Scope Process"])
            self.assertEqual(calls, [])

    def test_safe_python_git_and_read_only_policy_commands_delegate(self):
        with _sentinel_process_boundary() as (calls, popen_result):
            python_result = subprocess.run(["python.exe", "-c", "print('safe')"], capture_output=True, text=True)
            git_result = subprocess.run(["git", "status", "--short"], capture_output=True, text=True)
            policy_result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Get-ExecutionPolicy -List"], capture_output=True, text=True)
            process = subprocess.Popen(["git", "status", "--short"])
            self.assertEqual(python_result.stdout, "sentinel-output")
            self.assertEqual(git_result.stdout, "sentinel-output")
            self.assertEqual(policy_result.stdout, "sentinel-output")
            self.assertIs(process, popen_result)
            self.assertEqual([call[0] for call in calls], ["run", "run", "run", "popen"])

    def test_direct_notification_popen_is_blocked_and_isolation_restores_boundaries(self):
        original_run = subprocess.run
        original_popen = subprocess.Popen
        calls = []

        def sentinel_run(*args, **kwargs):
            calls.append(("run", args, kwargs))
            return subprocess.CompletedProcess(args[0] if args else kwargs.get("args"), 0)

        class SentinelPopen:
            def __new__(cls, *args, **kwargs):
                calls.append(("popen", args, kwargs))
                return object()

        helper = [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-File", str(Path.cwd() / "scripts" / "notifications" / "register-windows-notification.ps1"),
            "-Action", "Register", "-Target", r"C:\temp\target.lnk",
        ]
        subprocess.run = sentinel_run
        subprocess.Popen = SentinelPopen
        try:
            with NotificationIsolation():
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(AssertionError, "NOTIFICATION_TEST_UNEXPECTED_HELPER_CALL"):
                        subprocess.Popen(helper)
                self.assertEqual(calls, [])
            self.assertIs(subprocess.run, sentinel_run)
            self.assertIs(subprocess.Popen, SentinelPopen)
            self.assertEqual(calls, [])
        finally:
            subprocess.run = original_run
            subprocess.Popen = original_popen


if __name__ == "__main__":
    unittest.main()
