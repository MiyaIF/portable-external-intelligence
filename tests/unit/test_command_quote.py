import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ei.command_quote import (
    CommandQuoteError,
    build_hook_argv,
    build_observe_argv,
    build_skill_launcher_argv,
    quote_command,
    quote_posix_command,
    quote_windows_command,
)


class CommandQuoteTests(unittest.TestCase):
    def test_hook_argv_uses_explicit_personal_root_and_omits_disabled_team(self):
        argv = build_hook_argv(
            sys.executable,
            host_id="codex-cli",
            engine_root=Path("C:/engine"),
            personal_knowledge_root=Path("C:/personal"),
            team_knowledge_root=None,
            runtime_root=Path("C:/runtime"),
            host_home=Path("C:/home"),
        )
        self.assertIn("--personal-knowledge-root", argv)
        self.assertNotIn("--team-knowledge-root", argv)

    def test_hook_argv_contains_all_three_roots_and_home(self):
        argv = build_hook_argv(
            r"C:\Program Files\Python\python.exe",
            host_id="claude-code",
            engine_root=r"C:\作業\engine root",
            knowledge_root=r"C:\private\knowledge root",
            runtime_root=r"C:\machine\runtime root",
            host_home="C:" + chr(92) + "Users" + chr(92) + "A&B" + chr(92) + "Claude Home",
        )
        self.assertEqual(argv[0], r"C:\Program Files\Python\python.exe")
        self.assertEqual(argv[argv.index("--host-id") + 1], "claude-code")
        for name in ("--engine-root", "--knowledge-root", "--runtime-root", "--codex-home"):
            self.assertIn(name, argv)
            self.assertTrue(argv[argv.index(name) + 1])
        self.assertIn("-I", argv)
        self.assertIn(str(Path(r"C:\作業\engine root") / "src"), argv)

    def test_skill_launcher_starts_the_first_python_in_isolated_no_bytecode_mode(self):
        argv = build_skill_launcher_argv(
            sys.executable,
            skill_destination=Path("/host skills/external-intelligence"),
            engine_root=Path("/trusted engine"),
            runtime_root=Path("/machine runtime"),
        )
        self.assertEqual(argv[1:6], ("-I", "-B", "-X", "utf8", "-c"))
        self.assertIn("launcher.py", argv[7])
        self.assertEqual(argv[argv.index("--engine-root") + 1], str(Path("/trusted engine")))
        self.assertEqual(argv[argv.index("--runtime-root") + 1], str(Path("/machine runtime")))

    def test_posix_quote_round_trips_metacharacters(self):
        argv = (
            "/opt/Python With Space/bin/python",
            "-B",
            "-m",
            "ei.hook_entry",
            "--engine-root",
            "/tmp/日本語 'single' \"double\" & (group) $value",
        )
        rendered = quote_posix_command(argv)
        self.assertEqual(shlex.split(rendered, posix=True), list(argv))
        self.assertEqual(quote_command(argv, platform="posix"), rendered)

    @unittest.skipUnless(os.name == "nt", "Windows CreateProcess argv contract")
    def test_windows_quote_round_trips_and_does_not_run_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "injected.txt"
            hostile_argument = str(Path(tmp) / "日本語 host") + " & echo INJECTED > " + str(marker) + " (x) $value"
            argv = (
                sys.executable,
                "-c",
                "import json,sys; print(json.dumps(sys.argv[1:]))",
                hostile_argument,
            )
            rendered = quote_windows_command(argv)
            completed = subprocess.run(rendered, shell=False, capture_output=True, text=True, encoding="utf-8", check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout), [hostile_argument])
            self.assertFalse(marker.exists())

    def test_invalid_control_character_and_incomplete_root_set_are_rejected(self):
        with self.assertRaises(CommandQuoteError):
            quote_posix_command(("python\x00", "-B"))
        with self.assertRaises(CommandQuoteError):
            build_observe_argv("python", engine_root="engine")

    def test_hook_and_observe_commands_do_not_import_from_active_project_or_pythonpath(self):
        engine = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            active = root / "active-project"
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            marker = root / "project-imported.txt"
            package = active / "ei"
            package.mkdir(parents=True)
            knowledge.mkdir()
            runtime.mkdir()
            (package / "__init__.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            poison = root / "poison"
            poison.mkdir()
            (poison / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('sitecustomize', encoding='utf-8')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(poison)
            commands = (
                (
                    build_hook_argv(
                        sys.executable,
                        host_id="codex-cli",
                        engine_root=engine,
                        knowledge_root=knowledge,
                        runtime_root=runtime,
                    ),
                    "{}",
                ),
                (
                    build_observe_argv(
                        sys.executable,
                        engine_root=engine,
                        knowledge_root=knowledge,
                        runtime_root=runtime,
                    ),
                    "{}",
                ),
            )
            for argv, payload in commands:
                with self.subTest(entry=argv):
                    marker.unlink(missing_ok=True)
                    completed = subprocess.run(
                        argv,
                        cwd=active,
                        env=environment,
                        input=payload,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                        timeout=15,
                    )
                    self.assertFalse(marker.exists(), completed.stdout + completed.stderr)
                    self.assertIsInstance(json.loads(completed.stdout), dict)


if __name__ == "__main__":
    unittest.main()
