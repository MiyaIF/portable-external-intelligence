import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings, load_settings
from ei.task_scheduler import TASK_NAME, build_maintenance_action, build_launchd_plist, build_systemd_user_unit, build_systemd_user_timer, register_scheduler, remove_scheduler_state, write_scheduler_state


class TaskSchedulerTests(unittest.TestCase):
    def _portable_action(self, root: Path):
        engine = root / "engine"
        knowledge = root / "knowledge"
        runtime = root / "runtime"
        engine.mkdir()
        knowledge.mkdir()
        python = root / "python"
        python.write_bytes(b"python")
        settings = Settings(paths=RuntimePaths(engine, knowledge, runtime))
        return settings, build_maintenance_action(settings, python), python

    def test_register_scheduler_uses_platform_script_and_verifies_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._portable_action(Path(tmp))
            script = settings.paths.engine_root / "scripts" / "install-systemd-user.sh"
            script.parent.mkdir()
            script.write_text("#!/usr/bin/env sh\n", encoding="utf-8")
            completed = __import__("subprocess").CompletedProcess([], 0, "registered", "")
            verified = {"ok": True, "registered": True, "reason_code": "OK", "task_name": TASK_NAME}
            with patch("ei.task_scheduler.subprocess.run", return_value=completed) as process, patch(
                "ei.task_scheduler.inspect_registered_task", return_value=verified
            ):
                result = register_scheduler(settings, action, settings.paths.engine_root, platform_name="Linux")
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "REGISTERED")
            command = process.call_args.args[0]
            self.assertIsInstance(command, list)
            self.assertIn(str(settings.paths.knowledge_root), command)
            self.assertNotIn("sh -c", " ".join(command))

    def test_register_scheduler_failure_is_stable_and_resumable(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._portable_action(Path(tmp))
            script = settings.paths.engine_root / "scripts" / "install-systemd-user.sh"
            script.parent.mkdir()
            script.write_text("#!/usr/bin/env sh\n", encoding="utf-8")
            completed = __import__("subprocess").CompletedProcess([], 9, "", "failure details")
            with patch("ei.task_scheduler.subprocess.run", return_value=completed):
                result = register_scheduler(settings, action, settings.paths.engine_root, platform_name="Linux")
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "REGISTRATION_FAILED")
            self.assertEqual(result["reason_code"], "SCHEDULER_REGISTRATION_FAILED")
            self.assertTrue(result["retryable"])
            state = json.loads((settings.paths.runtime_root / "scheduler-state.json").read_text(encoding="utf-8"))
            self.assertFalse(state["registered"])
    def test_action_keeps_paths_as_separate_argv_values_and_uses_guardrails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "clone with spaces"
            home = Path(tmp) / "profile with spaces" / ".codex"
            (root / "config").mkdir(parents=True)
            (root / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5},"sync":{"enabled":true},"scheduler":{"task_name":"CodexExternalIntelligenceMaintenance-v1"}}',
                encoding="utf-8",
            )
            python = root / ".venv" / "Scripts" / "python.exe"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"synthetic-python-executable")
            settings = load_settings(root, home)
            action = build_maintenance_action(settings)
            self.assertEqual(action.task_name, TASK_NAME)
            self.assertEqual(action.argv[:4], ("-m", "ei.cli", "maintain", "--json"))
            self.assertIn(str(root.resolve()), action.argv)
            self.assertIn(str(home.resolve()), action.argv)
            self.assertIn(str(settings.paths.runtime_root), action.argv)
            self.assertIn("--engine-root", action.argv)
            self.assertIn("--knowledge-root", action.argv)
            self.assertIn("--runtime-root", action.argv)
            self.assertIn("-m ei.cli maintain --json", action.arguments)
            self.assertNotIn("cmd /c", action.arguments.casefold())
            self.assertEqual(action.execution_time_limit_seconds, 600)
            self.assertEqual(action.multiple_instance_policy, "IgnoreNew")
            self.assertEqual(action.run_level, "Limited")
            self.assertTrue(action.start_when_available)
            self.assertFalse(action.wake_to_run)
            self.assertEqual(action.triggers, ("every_30_minutes",))
            self.assertIn("--sync", action.argv)
            self.assertEqual(action.executable_sha256, hashlib.sha256(python.read_bytes()).hexdigest())

    def test_scheduler_state_is_local_and_reusable_for_doctor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            python = root / ".venv" / "Scripts" / "python.exe"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"python")
            settings = load_settings(root, root / "codex")
            action = build_maintenance_action(settings)
            state_path = write_scheduler_state(settings, action, False)
            self.assertTrue(state_path.exists())
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertFalse(state["registered"])
            self.assertEqual(state["task_name"], TASK_NAME)
            self.assertEqual(state["action"]["executable_sha256"], hashlib.sha256(b"python").hexdigest())
            self.assertTrue(remove_scheduler_state(settings))
            self.assertFalse(state_path.exists())


    def test_portable_scheduler_renderers_use_explicit_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "clone"
            home = Path(tmp) / "home"
            (root / "config").mkdir(parents=True)
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"python")
            settings = load_settings(root, home, runtime_root=Path(tmp) / "runtime")
            action = build_maintenance_action(settings, python)
            plist = build_launchd_plist(action)
            unit = build_systemd_user_unit(action)
            timer = build_systemd_user_timer(action)
            self.assertIn("<array>", plist)
            self.assertIn(str(python.resolve()), plist)
            self.assertNotIn("sh -c", plist)
            self.assertIn("ExecStart=", unit)
            self.assertIn(str(python.resolve()), unit)
            self.assertIn("OnUnitActiveSec=", timer)
            self.assertNotIn("bash -c", unit)
            self.assertNotIn("sh -c", unit)
if __name__ == "__main__":
    unittest.main()
