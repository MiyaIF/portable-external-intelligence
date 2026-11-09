import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings, load_settings
from ei.task_scheduler import TASK_NAME, build_maintenance_action, build_launchd_plist, build_systemd_user_unit, build_systemd_user_timer, current_principal, inspect_registered_task, register_scheduler, remove_scheduler_state, write_scheduler_state


class TaskSchedulerTests(unittest.TestCase):
    def _write_lf(self, path: Path, content: str) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)

    def test_linux_timer_has_two_native_same_anchor_opportunities_without_rounding(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            _, action, _ = self._portable_action(Path(tmp))
            for interval in (7, 30, 90, 100000):
                timer = build_systemd_user_timer(replace(action, triggers=(f"every_{interval}_minutes",)))
                self.assertEqual([line for line in timer.splitlines() if line.startswith("OnUnitActiveSec=")],
                                 [f"OnUnitActiveSec={interval}min", f"OnUnitActiveSec={2 * interval}min"])
                self.assertIn("OnBootSec=2min", timer)
                self.assertNotIn("OnCalendar", timer)
            with self.assertRaisesRegex(ValueError, "SCHEDULER_INTERVAL_OUT_OF_RANGE"):
                build_systemd_user_timer(replace(action, triggers=(f"every_{2**64}_minutes",)))

    def _portable_action(self, root: Path):
        engine = root / "engine"
        knowledge = root / "knowledge"
        runtime = root / "runtime"
        engine.mkdir()
        knowledge.mkdir()
        python = root / "python"
        python.write_bytes(b"python")
        settings = Settings(paths=RuntimePaths(engine, knowledge, runtime))
        with patch("ei.task_scheduler.platform.system", return_value="Linux"):
            action = build_maintenance_action(settings, python)
        return settings, action, python

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

    def test_linux_inspection_rejects_owned_legacy_timer_definition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings, action, _ = self._portable_action(root)
            unit_dir = root / "systemd-user"
            unit_dir.mkdir()
            service = unit_dir / f"{TASK_NAME}.service"
            timer = unit_dir / f"{TASK_NAME}.timer"
            self._write_lf(service, build_systemd_user_unit(action))
            self._write_lf(timer,
                f"[Unit]\nDescription={TASK_NAME} timer\n\n[Timer]\nOnBootSec=2min\n"
                f"OnUnitActiveSec=30min\nPersistent=true\nUnit={TASK_NAME}.service\n\n"
                "[Install]\nWantedBy=timers.target\n"
            )
            write_scheduler_state(settings, action, True)
            completed = subprocess.CompletedProcess([], 0, "active", "")
            with patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}), patch(
                "ei.task_scheduler.subprocess.run", return_value=completed
            ):
                result = inspect_registered_task(settings, platform_name="Linux")
            self.assertTrue(result["registered"])
            self.assertFalse(result["checks"]["timer_interval"])
            self.assertFalse(result["ok"])

    def test_linux_registration_upgrades_legacy_timer_when_explicitly_reconciled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings, action, _ = self._portable_action(root)
            script = settings.paths.engine_root / "scripts" / "install-systemd-user.sh"
            script.parent.mkdir()
            script.write_text("#!/usr/bin/env sh\n", encoding="utf-8")
            unit_dir = root / "systemd-user"
            unit_dir.mkdir()
            service = unit_dir / f"{TASK_NAME}.service"
            timer = unit_dir / f"{TASK_NAME}.timer"
            self._write_lf(service, build_systemd_user_unit(action))
            self._write_lf(timer,
                f"[Unit]\nDescription={TASK_NAME} timer\n\n[Timer]\nOnBootSec=2min\n"
                f"OnUnitActiveSec=30min\nPersistent=true\nUnit={TASK_NAME}.service\n\n"
                "[Install]\nWantedBy=timers.target\n"
            )
            write_scheduler_state(settings, action, True)
            completed = subprocess.CompletedProcess([], 0, "active", "")

            def run(command, **_kwargs):
                if any(str(argument).endswith("install-systemd-user.sh") for argument in command):
                    self._write_lf(service, build_systemd_user_unit(action))
                    self._write_lf(timer, build_systemd_user_timer(action))
                return completed

            with patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}), patch(
                "ei.task_scheduler.subprocess.run", side_effect=run
            ) as process:
                result = register_scheduler(settings, action, settings.paths.engine_root, platform_name="Linux")
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "REGISTERED")
            self.assertEqual(timer.read_text(encoding="utf-8"), build_systemd_user_timer(action))
            self.assertTrue(any(
                any(str(argument).endswith("install-systemd-user.sh") for argument in call.args[0])
                for call in process.call_args_list
            ))

    def test_linux_registration_preserves_same_name_artifact_without_owned_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings, action, _ = self._portable_action(root)
            script = settings.paths.engine_root / "scripts" / "install-systemd-user.sh"
            script.parent.mkdir()
            script.write_text("#!/usr/bin/env sh\n", encoding="utf-8")
            unit_dir = root / "systemd-user"
            unit_dir.mkdir()
            collision = unit_dir / f"{TASK_NAME}.timer"
            raw = "[Unit]\nDescription=someone else's timer\n"
            collision.write_text(raw, encoding="utf-8")
            completed = subprocess.CompletedProcess([], 0, "active", "")
            with patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}), patch(
                "ei.task_scheduler.subprocess.run", return_value=completed
            ) as process:
                result = register_scheduler(settings, action, settings.paths.engine_root, platform_name="Linux")
            self.assertEqual(result["reason_code"], "SCHEDULER_ARTIFACT_CONFLICT")
            self.assertEqual(collision.read_text(encoding="utf-8"), raw)
            self.assertFalse(any(str(call.args[0][0]).endswith("install-systemd-user.sh") for call in process.call_args_list))

    def test_windows_registration_does_not_bypass_policy_and_reports_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._portable_action(Path(tmp))
            script = settings.paths.engine_root / "scripts" / "install-scheduled-task.ps1"
            script.parent.mkdir()
            script.write_text("# test boundary\n", encoding="utf-8")
            denied = subprocess.CompletedProcess([], 1, "", "PSSecurityException")
            with patch("ei.task_scheduler.subprocess.run", return_value=denied) as process:
                result = register_scheduler(settings, action, settings.paths.engine_root, platform_name="Windows")
            command = process.call_args.args[0]
            self.assertNotIn("-ExecutionPolicy", command)
            self.assertNotIn("Bypass", command)
            self.assertEqual(result["status"], "REGISTRATION_DENIED")
            self.assertEqual(result["reason_code"], "SCHEDULER_REGISTRATION_DENIED")
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
            with patch("ei.task_scheduler.platform.system", return_value="Linux"):
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

    def test_windows_maintenance_action_uses_utf8_pythonw_and_requires_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "engine"
            (root / "config").mkdir(parents=True)
            (root / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8"
            )
            console = root / ".venv" / "Scripts" / "python.exe"
            windowless = console.with_name("pythonw.exe")
            console.parent.mkdir(parents=True)
            console.write_bytes(b"console interpreter")
            windowless.write_bytes(b"windowless interpreter")
            settings = load_settings(root, Path(tmp) / "codex")

            with patch("ei.task_scheduler.platform.system", return_value="Windows"):
                action = build_maintenance_action(settings)

            self.assertEqual(action.executable, windowless.resolve())
            self.assertEqual(action.argv[:3], ("-X", "utf8", "-m"))
            self.assertEqual(action.executable_sha256, hashlib.sha256(windowless.read_bytes()).hexdigest())

            windowless.unlink()
            with patch("ei.task_scheduler.platform.system", return_value="Windows"):
                with self.assertRaisesRegex(FileNotFoundError, "SCHEDULER_PYTHONW_NOT_FOUND"):
                    build_maintenance_action(settings)

    def test_windows_registration_keeps_console_python_for_renderer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8"
            )
            script = engine / "scripts" / "install-scheduled-task.ps1"
            script.parent.mkdir()
            script.write_text("# isolated registration fixture\n", encoding="utf-8")
            console = engine / ".venv" / "Scripts" / "python.exe"
            windowless = console.with_name("pythonw.exe")
            console.parent.mkdir(parents=True)
            console.write_bytes(b"console interpreter")
            windowless.write_bytes(b"windowless interpreter")
            settings = load_settings(engine, root / "codex")
            with patch("ei.task_scheduler.platform.system", return_value="Windows"):
                action = build_maintenance_action(settings)
            completed = subprocess.CompletedProcess([], 0, "registered", "")
            verified = {"ok": True, "registered": True, "reason_code": "OK", "task_name": TASK_NAME}
            with patch("ei.task_scheduler.subprocess.run", return_value=completed) as process, patch(
                "ei.task_scheduler.inspect_registered_task", return_value=verified
            ):
                result = register_scheduler(settings, action, engine, platform_name="Windows")

            self.assertTrue(result["ok"])
            command = process.call_args.args[0]
            python_exe = command[command.index("-PythonExe") + 1]
            self.assertEqual(Path(python_exe), console.resolve())
            self.assertNotEqual(Path(python_exe), action.executable)

    def test_saved_windows_action_passes_platform_specific_state_validation(self):
        from ei.task_scheduler import _expected_action_argv, _state_action_checks

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "engine"
            (root / "config").mkdir(parents=True)
            (root / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8"
            )
            console = root / ".venv" / "Scripts" / "python.exe"
            windowless = console.with_name("pythonw.exe")
            console.parent.mkdir(parents=True)
            console.write_bytes(b"console interpreter")
            windowless.write_bytes(b"windowless interpreter")
            settings = load_settings(root, Path(tmp) / "codex")
            with patch("ei.task_scheduler.platform.system", return_value="Windows"):
                action = build_maintenance_action(settings)
            state_path = write_scheduler_state(settings, action, True)
            saved = json.loads(state_path.read_text(encoding="utf-8"))["action"]

            # The explicit selected platform controls validation, not the host running this test.
            with patch("ei.task_scheduler.platform.system", return_value="Linux"):
                checks, full_argv, executable = _state_action_checks(settings, saved, platform_name="Windows")
                windows_expected = _expected_action_argv(settings, platform_name="Windows")
                linux_expected = _expected_action_argv(settings, platform_name="Linux")

            self.assertTrue(all(checks.values()), checks)
            self.assertEqual(executable, windowless.resolve())
            self.assertEqual(full_argv[:4], [str(windowless.resolve()), "-X", "utf8", "-m"])
            self.assertEqual(windows_expected[:3], ("-X", "utf8", "-m"))
            self.assertEqual(linux_expected[:3], ("-m", "ei.cli", "maintain"))

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell query is platform-specific")
    def test_windows_inspection_uses_utf8_bytes_and_suppresses_child_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "エンジン"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8"
            )
            console = engine / ".venv" / "Scripts" / "python.exe"
            windowless = console.with_name("pythonw.exe")
            console.parent.mkdir(parents=True)
            console.write_bytes(b"console interpreter")
            windowless.write_bytes(b"windowless interpreter")
            settings = load_settings(engine, root / "codex_日本語")
            with patch("ei.task_scheduler.platform.system", return_value="Windows"):
                action = build_maintenance_action(settings)
            write_scheduler_state(settings, action, True)
            live = {
                "TaskName": TASK_NAME,
                "Execute": str(action.executable),
                "Arguments": action.arguments,
                "WorkingDirectory": str(engine.resolve()),
                "UserId": current_principal(),
                "RunLevel": "Limited",
                "LastTaskResult": 0,
                "LastRunTime": None,
                "NextRunTime": "2030-01-01T00:00:00+00:00",
                "State": "Ready",
                "Enabled": True,
            }
            successful = subprocess.CompletedProcess(
                [], 0, json.dumps(live, ensure_ascii=False).encode("utf-8"), b""
            )
            invalid_utf8 = subprocess.CompletedProcess([], 0, b"\xff", b"")
            with patch(
                "ei.task_scheduler.subprocess.run", side_effect=(successful, invalid_utf8)
            ) as process:
                result = inspect_registered_task(settings, platform_name="Windows")
                malformed = inspect_registered_task(settings, platform_name="Windows")

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["identity_verified"])
            self.assertEqual(malformed["reason_code"], "SCHEDULER_QUERY_INVALID")
            self.assertEqual(process.call_count, 2)
            for call in process.call_args_list:
                kwargs = call.kwargs
                self.assertTrue(kwargs["capture_output"])
                self.assertFalse(kwargs["text"])
                self.assertEqual(kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)
                self.assertNotIn("encoding", kwargs)
                self.assertIn("[Console]::OutputEncoding", call.args[0][-1])

    @unittest.skipUnless(os.name == "nt", "Windows console suppression is platform-specific")
    def test_windows_scheduler_query_suppresses_console_window(self):
        from ei.operation_runtime import OperationBudget
        from ei.task_scheduler import _scheduler_query

        completed = subprocess.CompletedProcess([], 0, "ok", "")
        with patch("ei.task_scheduler.subprocess.run", return_value=completed) as process:
            _scheduler_query(["powershell.exe", "-NoProfile"], OperationBudget(1000))
        self.assertEqual(process.call_args.kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)

    def test_scheduler_state_is_local_and_reusable_for_doctor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            python = root / ".venv" / "Scripts" / "python.exe"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"python")
            settings = load_settings(root, root / "codex")
            with patch("ei.task_scheduler.platform.system", return_value="Linux"):
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
            with patch("ei.task_scheduler.platform.system", return_value="Linux"):
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
