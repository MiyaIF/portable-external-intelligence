from __future__ import annotations

import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.task_scheduler as task_scheduler
from ei.config import RuntimePaths, Settings
from ei.installer import SetupSelection, UninstallOptions, _Transaction, setup, uninstall
from ei.task_scheduler import (
    TASK_NAME,
    build_launchd_plist,
    build_maintenance_action,
    build_systemd_user_timer,
    build_systemd_user_unit,
    current_principal,
    inspect_registered_task,
    write_scheduler_state,
)


class SchedulerInstallerProductionDefectTests(unittest.TestCase):
    def _scheduler_fixture(self, root: Path):
        engine = root / "engine source"
        knowledge = root / "private knowledge"
        runtime = root / "machine runtime"
        engine.mkdir(parents=True)
        knowledge.mkdir(parents=True)
        python = root / "python executable"
        python.write_bytes(b"stable-python-content")
        settings = Settings(paths=RuntimePaths(engine, knowledge, runtime))
        action = build_maintenance_action(settings, python)
        write_scheduler_state(settings, action, True)
        return settings, action, python

    @staticmethod
    def _manager_result(returncode: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(["scheduler-manager"], returncode, stdout, "")

    def test_macos_inspection_rejects_successful_status_without_persisted_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, _, _ = self._scheduler_fixture(Path(tmp))
            agents = Path(tmp) / "launch agents override"
            agents.mkdir()
            with (
                patch.dict(os.environ, {"EI_LAUNCH_AGENTS_DIR": str(agents)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()),
                patch.object(task_scheduler.os, "getuid", return_value=501, create=True),
            ):
                result = inspect_registered_task(settings, platform_name="Darwin")

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason_code"], "SCHEDULER_CONTRACT_FAILED")
            self.assertFalse(result["checks"]["persisted_artifact"])

    def test_macos_inspection_requires_exact_plist_argv_working_directory_and_content_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, python = self._scheduler_fixture(Path(tmp))
            agents = Path(tmp) / "launch agents override"
            agents.mkdir()
            plist_path = agents / f"{TASK_NAME}.plist"
            document = plistlib.loads(build_launchd_plist(action).encode("utf-8"))
            document["ProgramArguments"][-1] = "--tampered"
            document["WorkingDirectory"] = str(Path(tmp) / "wrong working directory")
            plist_path.write_bytes(plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=False))
            python.write_bytes(b"changed-python-content")

            with (
                patch.dict(os.environ, {"EI_LAUNCH_AGENTS_DIR": str(agents)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()),
                patch.object(task_scheduler.os, "getuid", return_value=501, create=True),
            ):
                result = inspect_registered_task(settings, platform_name="macOS")

            self.assertFalse(result["ok"])
            self.assertFalse(result["checks"]["program_arguments"])
            self.assertFalse(result["checks"]["working_directory"])
            self.assertFalse(result["checks"]["executable_content_identity"])

    def test_linux_inspection_reads_override_unit_files_and_requires_exact_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._scheduler_fixture(Path(tmp))
            unit_dir = Path(tmp) / "systemd user override"
            unit_dir.mkdir()
            service_path = unit_dir / f"{TASK_NAME}.service"
            timer_path = unit_dir / f"{TASK_NAME}.timer"
            service_path.write_text(build_systemd_user_unit(action), encoding="utf-8")
            timer_path.write_text(build_systemd_user_timer(action), encoding="utf-8")

            with (
                patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()),
            ):
                result = inspect_registered_task(settings, platform_name="Linux")

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["checks"]["service_argv"])
            self.assertTrue(result["checks"]["working_directory"])
            self.assertTrue(result["checks"]["executable_hash"])
            self.assertTrue(result["checks"]["executable_content_identity"])
            self.assertEqual(result["artifact_paths"]["service"], str(service_path))
            self.assertEqual(result["artifact_paths"]["timer"], str(timer_path))

    def test_linux_inspection_rejects_status_only_when_executable_content_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, python = self._scheduler_fixture(Path(tmp))
            unit_dir = Path(tmp) / "systemd user override"
            unit_dir.mkdir()
            (unit_dir / f"{TASK_NAME}.service").write_text(build_systemd_user_unit(action), encoding="utf-8")
            (unit_dir / f"{TASK_NAME}.timer").write_text(build_systemd_user_timer(action), encoding="utf-8")
            python.write_bytes(b"tampered-python-content")

            with (
                patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()),
            ):
                result = inspect_registered_task(settings, platform_name="linux")

            self.assertFalse(result["ok"])
            self.assertFalse(result["checks"]["executable_hash"])
            self.assertFalse(result["checks"]["executable_content_identity"])

    def test_linux_inspection_requires_sync_flag_to_match_current_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._scheduler_fixture(Path(tmp))
            unit_dir = Path(tmp) / "systemd user override"
            unit_dir.mkdir()
            service_path = unit_dir / f"{TASK_NAME}.service"
            timer_path = unit_dir / f"{TASK_NAME}.timer"
            service_path.write_text(build_systemd_user_unit(action), encoding="utf-8")
            timer_path.write_text(build_systemd_user_timer(action), encoding="utf-8")
            sync_settings = Settings(paths=settings.paths, sync_enabled=True)

            with (
                patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()),
            ):
                result = inspect_registered_task(sync_settings, platform_name="linux")

            self.assertFalse(result["ok"])
            self.assertFalse(result["checks"]["action_argv"])

    def test_inspection_reports_malformed_state_as_contract_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, _, _ = self._scheduler_fixture(Path(tmp))
            state_path = settings.paths.runtime_root / "scheduler-state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["action"]["executable"] = "\u0000invalid"
            state_path.write_text(json.dumps(state), encoding="utf-8")

            with patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()):
                result = inspect_registered_task(settings, platform_name="linux")

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason_code"], "SCHEDULER_CONTRACT_FAILED")

    def test_unregister_linux_verifies_and_removes_job_owned_artifacts_and_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._scheduler_fixture(Path(tmp))
            unit_dir = Path(tmp) / "systemd user override"
            unit_dir.mkdir()
            service_path = unit_dir / f"{TASK_NAME}.service"
            timer_path = unit_dir / f"{TASK_NAME}.timer"
            service_path.write_text(build_systemd_user_unit(action), encoding="utf-8")
            timer_path.write_text(build_systemd_user_timer(action), encoding="utf-8")

            with (
                patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()) as process,
            ):
                result = task_scheduler.unregister_scheduler(settings, platform_name="Linux")

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "UNREGISTERED")
            self.assertTrue(result["job_removed"])
            self.assertFalse(service_path.exists())
            self.assertFalse(timer_path.exists())
            self.assertFalse((settings.paths.runtime_root / "scheduler-state.json").exists())
            self.assertTrue(any(call.args[0][:4] == ["systemctl", "--user", "disable", "--now"] for call in process.call_args_list))

    def test_unregister_preserves_mismatched_linux_job_and_owned_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._scheduler_fixture(Path(tmp))
            unit_dir = Path(tmp) / "systemd user override"
            unit_dir.mkdir()
            service_path = unit_dir / f"{TASK_NAME}.service"
            timer_path = unit_dir / f"{TASK_NAME}.timer"
            service_path.write_text(build_systemd_user_unit(action).replace("--json", "--wrong"), encoding="utf-8")
            timer_path.write_text(build_systemd_user_timer(action), encoding="utf-8")

            with (
                patch.dict(os.environ, {"EI_SYSTEMD_USER_DIR": str(unit_dir)}, clear=False),
                patch("ei.task_scheduler.subprocess.run", return_value=self._manager_result()) as process,
            ):
                result = task_scheduler.unregister_scheduler(settings, platform_name="linux")

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason_code"], "SCHEDULER_IDENTITY_MISMATCH")
            self.assertTrue(service_path.exists())
            self.assertTrue(timer_path.exists())
            self.assertTrue((settings.paths.runtime_root / "scheduler-state.json").exists())
            self.assertEqual(process.call_count, 2)

    def test_unregister_windows_verifies_live_action_before_removing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings, action, _ = self._scheduler_fixture(Path(tmp))
            live = {
                "TaskName": TASK_NAME,
                "Execute": str(action.executable),
                "Arguments": action.arguments,
                "WorkingDirectory": str(action.working_directory),
                "UserId": current_principal().split("\\")[-1],
                "RunLevel": "Limited",
                "LastTaskResult": 0,
                "LastRunTime": None,
                "NextRunTime": "2030-01-01T00:00:00+00:00",
                "State": "Ready",
            }
            with patch(
                "ei.task_scheduler.subprocess.run",
                side_effect=(
                    self._manager_result(stdout=json.dumps(live)),
                    self._manager_result(),
                ),
            ) as process:
                result = task_scheduler.unregister_scheduler(settings, platform_name="Windows", powershell_exe="powershell-test.exe")

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "UNREGISTERED")
            self.assertFalse((settings.paths.runtime_root / "scheduler-state.json").exists())
            inspection_query = process.call_args_list[0].args[0][-1]
            self.assertIn("RunLevel=[string]$task.Principal.RunLevel", inspection_query)
            self.assertIn("State=[string]$task.State", inspection_query)
            self.assertIn("ToString('o')", inspection_query)
            self.assertEqual(process.call_args_list[1].args[0][0], "powershell-test.exe")

    def _installed_manifest(self, root: Path) -> Path:
        host_home = root / "host home"
        host_home.mkdir()
        (host_home / "AGENTS.md").write_text("# existing instructions\n", encoding="utf-8")
        runtime = root / "runtime"
        selection = SetupSelection(
            engine_root=Path.cwd(),
            knowledge_root=root / "knowledge",
            runtime_root=runtime,
            hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            host_homes={"codex-cli": host_home},
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )
        result = setup(selection)
        self.assertTrue(result.ok, result.to_dict())
        return runtime / "install-manifest.json"

    def test_uninstall_check_only_uses_scheduler_unregister_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._installed_manifest(Path(tmp))
            scheduler_result = {"ok": True, "status": "CHECK_ONLY", "reason_code": "OK", "registered": True}
            with patch("ei.task_scheduler.unregister_scheduler", return_value=scheduler_result) as unregister:
                result = uninstall(manifest_path, UninstallOptions(check_only=True))

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["result"]["scheduler"], scheduler_result)
            unregister.assert_called_once()

    def test_uninstall_apply_uses_scheduler_unregister_before_committing_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._installed_manifest(Path(tmp))
            scheduler_result = {"ok": True, "status": "UNREGISTERED", "reason_code": "OK", "registered": False}
            with patch("ei.task_scheduler.unregister_scheduler", return_value=scheduler_result) as unregister:
                result = uninstall(manifest_path, UninstallOptions())

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["result"]["scheduler"], scheduler_result)
            unregister.assert_called_once()

    def test_transaction_rollback_is_noop_after_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            transaction = _Transaction(runtime)
            transaction.commit()

            result = transaction.rollback()

            self.assertEqual(result["status"], "COMMITTED")
            self.assertFalse(result["rolled_back"])
            self.assertEqual(json.loads(transaction.journal_path.read_text(encoding="utf-8"))["status"], "COMMITTED")

    def test_setup_retains_installed_state_when_post_commit_diagnostics_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_home = root / "host home"
            host_home.mkdir()
            (host_home / "AGENTS.md").write_text("# existing instructions\n", encoding="utf-8")
            runtime = root / "runtime"
            knowledge = root / "knowledge"
            selection = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=knowledge,
                runtime_root=runtime,
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": host_home},
                python_exe=Path(sys.executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )

            with patch("ei.installer.run_doctor", side_effect=RuntimeError("diagnostics unavailable")):
                result = setup(selection)

            self.assertFalse(result.ok)
            self.assertEqual(result.status, "DIAGNOSTICS_BLOCKED")
            self.assertEqual(result.errors[0]["stage"], "diagnostics")
            self.assertEqual(result.rollback["status"], "INSTALLATION_RETAINED")
            self.assertFalse(result.rollback["rolled_back"])
            manifest_path = runtime / "install-manifest.json"
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(json.loads(manifest_path.read_text(encoding="utf-8"))["status"], "INSTALLED")
            journals = list((runtime / "transactions").glob("tx_*.json"))
            self.assertTrue(journals)
            self.assertTrue(all(json.loads(path.read_text(encoding="utf-8"))["status"] == "COMMITTED" for path in journals))


if __name__ == "__main__":
    unittest.main()
