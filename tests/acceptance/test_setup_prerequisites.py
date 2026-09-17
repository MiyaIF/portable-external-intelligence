"""Run the bootstrap shells; replace only discovery/install OS boundaries.

No test is permitted to invoke a real package manager or change host software.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
SHELL = shutil.which("sh")


@unittest.skipUnless(POWERSHELL, "PowerShell not installed")
class WindowsPrerequisiteTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell not installed")
    def test_windows_powershell_51_runs_the_same_bootstrap(self):
        from unittest.mock import patch
        environment = os.environ.copy()
        environment.pop("PSModulePath", None)  # do not inherit PowerShell 7 module paths into PS5
        policy = subprocess.run([shutil.which("powershell.exe"), "-NoProfile", "-Command", "Get-ExecutionPolicy"], capture_output=True, text=True, timeout=10, env=environment)
        if policy.returncode != 0:
            self.skipTest("Unable to inspect host execution policy without changing it")
        if policy.stdout.strip() in {"Restricted", "AllSigned"}:
            self.skipTest("Host execution policy does not permit unsigned script files; policy is not changed")
        with patch(__name__ + ".POWERSHELL", shutil.which("powershell.exe")):
            self.test_setup_wrapper_check_only_accepts_bootstrap_and_scheduler_controls()

    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell not installed")
    def test_windows_powershell_51_preserves_native_python_bootstrap_arguments(self):
        # Parse the actual bootstrap literal as data and invoke it with --help.
        # This tests PS5's native argv marshalling without changing script policy.
        wrapper = (ROOT / "scripts/setup.ps1").as_posix().replace("'", "''")
        python = Path(sys.executable).as_posix().replace("'", "''")
        source = (ROOT / "src").as_posix().replace("'", "''")
        harness = f"""
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{wrapper}', [ref]$null, [ref]$null)
$assignment = $ast.Find({{param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$bootstrap'}}, $true)
$nativeCode = $assignment.Right.Find({{param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]}}, $true).Value
& '{python}' -I -B -X utf8 -c $nativeCode '{source}' --help
exit $LASTEXITCODE
"""
        result = subprocess.run([shutil.which("powershell.exe"), "-NoProfile", "-Command", harness], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ei.installer", result.stdout)

    def test_setup_wrapper_check_only_accepts_bootstrap_and_scheduler_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = subprocess.run([
                POWERSHELL, "-NoProfile", "-File", str(ROOT / "scripts/setup.ps1"),
                "-CheckOnly", "-NonInteractive", "-InstallPrerequisites", "-NoScheduler", "-Json",
                "-KnowledgeMode", "local", "-KnowledgeRoot", str(root / "knowledge"), "-RuntimeRoot", str(root / "runtime"),
                "-Hosts", "codex-cli", "-HostHome", f"codex-cli={root / 'host'}",
                "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli",
                "-PythonExe", sys.executable, "-SkipVenv",
            ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertEqual(json.loads(completed.stdout)["status"], "CHECK_ONLY")
            self.assertEqual(list(root.iterdir()), [])

    def run_bootstrap(self, *, installed=False, flags="", answer="no", failure=False, unavailable=False):
        script = (ROOT / "scripts" / "prerequisites.ps1").as_posix().replace("'", "''")
        harness = f"""
$ErrorActionPreference = 'Stop'
. '{script}'
$script:eiFixtureReady = ${str(installed).lower()}
$script:eiFixtureCalls = @()
function Find-EiPython {{ param($Requested) if ($script:eiFixtureReady) {{ 'fixture-python' }} }}
function Test-EiGit {{ return $script:eiFixtureReady }}
function Read-Host {{ param($Prompt) return '{answer}' }}
function Get-EiDependencyManager {{ {'return $null' if unavailable else "return 'fixture-manager'"} }}
function Invoke-EiDependencyInstall {{
    param($Manager, $PackageId, $NonInteractive)
    $script:eiFixtureCalls += $PackageId
    {'throw "PREREQUISITE_INSTALL_FAILED"' if failure else '$script:eiFixtureReady = $true'}
}}
try {{
    $resolved = Resolve-EiPrerequisites {flags}
    @{{status='ok'; python=$resolved; installs=@($script:eiFixtureCalls)}} | ConvertTo-Json -Compress
}} catch {{
    @{{status='blocked'; error=$_.Exception.Message; installs=@($script:eiFixtureCalls)}} | ConvertTo-Json -Compress
}}
"""
        completed = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", harness], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_existing_dependencies_skip_installs(self):
        result = self.run_bootstrap(installed=True)
        self.assertEqual(result, {"status": "ok", "python": "fixture-python", "installs": []})

    def test_explicit_install_consent_installs_missing_packages_then_continues(self):
        result = self.run_bootstrap(flags="-NonInteractive -InstallPrerequisites")
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["installs"], ["Git.Git", "Python.Python.3.13"])
        self.assertEqual(result["python"], "fixture-python")

    def test_no_consent_check_only_or_decline_never_install(self):
        for flags in ("-NonInteractive", "-CheckOnly -InstallPrerequisites", ""):
            with self.subTest(flags=flags):
                result = self.run_bootstrap(flags=flags)
                self.assertEqual(result["status"], "blocked", result)
                self.assertEqual(result["installs"], [])

    def test_failure_or_unavailable_manager_does_not_continue(self):
        for options in ({"failure": True}, {"unavailable": True}):
            with self.subTest(options=options):
                result = self.run_bootstrap(flags="-InstallPrerequisites", **options)
                self.assertEqual(result["status"], "blocked", result)


@unittest.skipUnless(SHELL, "POSIX shell not installed")
class PosixPrerequisiteTests(unittest.TestCase):
    def test_apt_install_disallows_package_removal(self):
        script = (ROOT / "scripts/prerequisites.sh").as_posix()
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "apt-get"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8", newline="\n")
            fake.chmod(0o755)
            # Git Bash needs a POSIX PATH entry, not the C: spelling.
            harness = f". '{script}'; id() {{ printf '0'; }}; PATH=\"$(cd '{Path(tmp).as_posix()}' && pwd):$PATH\"; ei_install_dependencies apt-get git python3 python3-venv"
            result = subprocess.run([SHELL, "-c", harness], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["install", "--no-remove", "-y", "git", "python3", "python3-venv"])

    def test_macos_uses_native_route_even_when_brew_exists(self):
        script = (ROOT / "scripts/prerequisites.sh").as_posix()
        harness = f""". '{script}'
uname() {{ printf Darwin; }}
brew() {{ printf 'UNEXPECTED_BREW'; return 99; }}
ei_dependency_manager
"""
        result = subprocess.run([SHELL, "-c", harness], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "macos-native")

    def test_setup_wrapper_check_only_accepts_bootstrap_and_scheduler_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = subprocess.run([
                SHELL, str(ROOT / "scripts/setup.sh"),
                "--check-only", "--non-interactive", "--install-prerequisites", "--no-scheduler", "--json",
                "--knowledge-mode", "local", "--knowledge-root", str(root / "knowledge"), "--runtime-root", str(root / "runtime"),
                "--hosts", "codex-cli", "--host-home", f"codex-cli={root / 'host'}",
                "--organizer-provider", "subscription-cli", "--organizer-host", "codex-cli",
                "--python-exe", sys.executable, "--skip-venv",
            ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertEqual(json.loads(completed.stdout)["status"], "CHECK_ONLY")
            self.assertEqual(list(root.iterdir()), [])

    def run_bootstrap(self, *, installed=False, install=0, check_only=0, failure=False):
        # Source and invoke the real orchestration without relying on this PC's
        # package manager, PATH layout, administrator rights, or network.
        script = (ROOT / "scripts" / "prerequisites.sh").as_posix()
        with tempfile.TemporaryDirectory() as tmp:
            marker = (Path(tmp) / "installed").as_posix()
            calls = (Path(tmp) / "calls").as_posix()
            harness = f"""
. '{script}'
ei_find_python() {{ if [ '{int(installed)}' = 1 ] || [ -f '{marker}' ]; then printf '%s\\n' /fixture/python; else return 1; fi; }}
ei_git_available() {{ [ '{int(installed)}' = 1 ] || [ -f '{marker}' ]; }}
ei_dependency_manager() {{ printf '%s\\n' apt-get; }}
ei_install_dependencies() {{
    printf '%s\\n' "$@" > '{calls}'
    {'return 9' if failure else ": > '" + marker + "'"}
}}
ei_ensure_prerequisites '' 1 {check_only} {install}
"""
            completed = subprocess.run([SHELL, "-c", harness], capture_output=True, text=True, encoding="utf-8", timeout=30)
            invoked = Path(calls).read_text(encoding="utf-8").splitlines() if Path(calls).exists() else []
            return completed, invoked

    def test_missing_dependencies_stop_without_consent(self):
        result, calls = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PREREQUISITE", result.stderr)
        self.assertEqual(calls, [])

    def test_existing_dependencies_do_not_install(self):
        result, calls = self.run_bootstrap(installed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/fixture/python")
        self.assertEqual(calls, [])

    def test_approved_install_rechecks_and_continues(self):
        result, calls = self.run_bootstrap(install=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/fixture/python")
        self.assertEqual(calls, ["apt-get", "git", "python3", "python3-venv"])

    def test_check_only_never_installs_even_with_consent_flag(self):
        result, calls = self.run_bootstrap(install=1, check_only=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_install_failure_blocks_later_setup(self):
        result, calls = self.run_bootstrap(install=1, failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PREREQUISITE_INSTALL_FAILED", result.stderr)
        self.assertTrue(calls)


if __name__ == "__main__":
    unittest.main()
