"""Exercise native setup flow with fake OS commands; never install on the host."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHELL = shutil.which("sh")


@unittest.skipUnless(SHELL, "POSIX shell not installed")
class MacosNativePrerequisiteTests(unittest.TestCase):
    def test_macos_system_python_stub_is_not_executed_without_developer_tools(self):
        script = (ROOT / "scripts/prerequisites.sh").as_posix()
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "unexpected-stub-execution"
            harness = f"""
. '{script}'
uname() {{ printf Darwin; }}
ei_python_location() {{ printf /usr/bin/python3; }}
ei_macos_run() {{ [ "$*" = 'xcode-select -p' ] || exit 90; return 1; }}
python3() {{ : > '{marker.as_posix()}'; printf /fixture/python; }}
ei_find_python python3
"""
            result = subprocess.run([SHELL, "-c", harness], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_macos_official_python_is_rechecked_outside_old_path(self):
        script = (ROOT / "scripts/prerequisites.sh").as_posix()
        harness = f"""
. '{script}'
uname() {{ printf Darwin; }}
ei_probe_python() {{
  [ "$1" = /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 ] || return 1
  printf '%s\\n' /fixture/new-official-python
}}
ei_find_python ''
"""
        result = subprocess.run([SHELL, "-c", harness], capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(result.stdout.strip(), "/fixture/new-official-python")

    def run_native(self, *, interactive=True, consent=1, check_only=0,
                   git_ready=False, python_ready=False, failure="", answer="\n\n"):
        script = (ROOT / "scripts/prerequisites.sh").as_posix()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commands = root / "commands"
            git_marker = root / "git-ready"
            python_marker = root / "python-ready"
            downloads = root / "downloads"
            downloads.mkdir()
            if git_ready:
                git_marker.touch()
            if python_ready:
                python_marker.touch()
            harness = f"""
. '{script}'
uname() {{ printf Darwin; }}
ei_is_interactive() {{ [ '{int(interactive)}' = 1 ]; }}
ei_macos_tools_available() {{ [ '{failure}' != tools ]; }}
ei_git_available() {{ [ -f '{git_marker.as_posix()}' ]; }}
ei_find_python() {{ [ -f '{python_marker.as_posix()}' ] && printf '%s\\n' /fixture/python; }}
brew() {{ printf 'UNEXPECTED_BREW' >> '{commands.as_posix()}'; return 99; }}
ei_macos_run() {{
    printf '%s\\n' "$*" >> '{commands.as_posix()}'
    case "$1" in
      xcode-select)
        [ "$2" = --install ] || return 90
        [ '{failure}' != clt-start ] || return 1
        [ '{failure}' = clt-cancel ] || : > '{git_marker.as_posix()}' ;;
      curl)
        [ '{failure}' != download ] || return 22
        while [ "$#" -gt 0 ]; do
          if [ "$1" = --output ]; then shift; printf fixture > "$1"; break; fi
          shift
        done ;;
      shasum)
        if [ '{failure}' = checksum ]; then printf '%s\\n' '0000000000000000000000000000000000000000000000000000000000000000  package'
        else printf '%s\\n' '3b7eaf7f29825f796e8267024435540ddf1f17fc9a97ad58095daa7a75bfdcd3  package'; fi ;;
      pkgutil) [ '{failure}' != signature ] ;;
      spctl) [ '{failure}' != gatekeeper ] ;;
      open)
        [ '{failure}' != open ] || return 1
        [ '{failure}' = python-cancel ] || : > '{python_marker.as_posix()}' ;;
      *) return 91 ;;
    esac
}}
TMPDIR='{downloads.as_posix()}'
ei_ensure_prerequisites '' {0 if interactive else 1} {check_only} {consent}
"""
            # Keep POSIX terminal input as LF even when the test runner is on Windows.
            raw = subprocess.run([SHELL, "-c", harness], input=answer.encode("utf-8"),
                                 capture_output=True, timeout=20)
            result = subprocess.CompletedProcess(raw.args, raw.returncode,
                                                 raw.stdout.decode("utf-8"), raw.stderr.decode("utf-8"))
            calls = commands.read_text(encoding="utf-8").splitlines() if commands.exists() else []
            leftover = list(downloads.iterdir())
            return result, calls, leftover

    def test_missing_macos_dependencies_use_apple_and_python_installers(self):
        result, calls, leftover = self.run_native()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/fixture/python")
        self.assertEqual(calls[0], "xcode-select --install")
        self.assertEqual([line.split()[0] for line in calls],
                         ["xcode-select", "curl", "shasum", "pkgutil", "spctl", "open"])
        self.assertIn("--proto =https", calls[1])
        self.assertIn("--disable", calls[1])
        self.assertIn("https://www.python.org/ftp/python/3.13.15/python-3.13.15-macos11.pkg", calls[1])
        self.assertNotIn("--insecure", calls[1])
        self.assertIn("--check-signature", calls[3])
        self.assertIn("--type install", calls[4])
        self.assertTrue(calls[5].startswith("open -W -n "), calls[5])
        self.assertIn("Git以外", result.stderr)
        self.assertEqual(leftover, [])

    def test_installed_software_is_reused_without_native_commands(self):
        result, calls, _ = self.run_native(git_ready=True, python_ready=True, interactive=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])

    def test_only_missing_dependency_is_installed(self):
        for git_ready, python_ready in ((True, False), (False, True)):
            with self.subTest(git_ready=git_ready):
                result, calls, _ = self.run_native(git_ready=git_ready, python_ready=python_ready)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(any(line.startswith("xcode-select") for line in calls), not git_ready)
                self.assertEqual(any(line.startswith("curl") for line in calls), not python_ready)

    def test_check_only_and_no_consent_have_no_install_side_effects(self):
        for options in ({"check_only": 1}, {"consent": 0, "answer": "no\n"},
                        {"consent": 0, "answer": ""}, {"interactive": False}):
            with self.subTest(options=options):
                result, calls, leftover = self.run_native(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(leftover, [])

    def test_noninteractive_native_install_explains_user_action(self):
        result, calls, _ = self.run_native(interactive=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PREREQUISITE_INTERACTIVE_REQUIRED", result.stderr)
        self.assertIn("python.org", result.stderr)
        self.assertEqual(calls, [])

    def test_cancelled_git_install_does_not_start_python_install(self):
        for failure in ("clt-start", "clt-cancel"):
            with self.subTest(failure=failure):
                result, calls, _ = self.run_native(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, ["xcode-select --install"])

    def test_unverified_package_never_opens_installer(self):
        for failure in ("download", "checksum", "signature", "gatekeeper", "tools"):
            with self.subTest(failure=failure):
                result, calls, leftover = self.run_native(git_ready=True, failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(line.startswith("open") for line in calls), calls)
                self.assertEqual(leftover, [])

    def test_acknowledgement_does_not_replace_python_postcheck(self):
        result, calls, leftover = self.run_native(git_ready=True, failure="python-cancel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PREREQUISITE_POSTCHECK_FAILED", result.stderr)
        self.assertTrue(any(line.startswith("open") for line in calls))
        self.assertEqual(leftover, [])

    def test_uncertain_installer_launch_retains_package_for_running_gui(self):
        result, calls, leftover = self.run_native(git_ready=True, failure="open")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(line.startswith("open") for line in calls))
        self.assertEqual(len(leftover), 1)
        self.assertIn("PREREQUISITE_PACKAGE_RETAINED", result.stderr)


if __name__ == "__main__":
    unittest.main()
