from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.installer import SetupResult, SetupSelection, _guided_interactive_selection, _main, setup
from ei.task_scheduler import (
    TASK_NAME, build_maintenance_action, current_principal,
    inspect_registered_task, write_scheduler_state,
)
from ei.config import RuntimePaths, Settings
from ei.setup_activation import activation_report, setup_result_with_guidance


class SetupOnboardingTests(unittest.TestCase):
    def test_explicit_no_scheduler_is_retained_in_legacy_wizard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = argparse.Namespace(
                setup=True, engine_root=Path.cwd(), knowledge_root=root / "knowledge",
                runtime_root=root / "runtime", work_hosts=["codex-cli"],
                host_home=[f"codex-cli={root / 'host'}"],
                organizer_provider=None, knowledge_mode="local", team_knowledge=False,
                sync=False, scheduler=False, providers=["ollama"], privacy_profile="public",
                experiment=True, skill_mode="link", python_exe=sys.executable, skip_venv=True,
            )
            output = io.StringIO()
            questions = []

            def respond():
                question = output.getvalue().splitlines()[-1]
                questions.append(question)
                return "ollama" if len(questions) == 1 else "yes"

            with contextlib.redirect_stdout(output), patch("builtins.input", side_effect=respond):
                selected = _guided_interactive_selection(args)
            self.assertFalse(selected.scheduler)
            self.assertFalse(any("scheduler" in question for question in questions))
            self.assertFalse((root / "runtime").exists())

    def test_same_configuration_rerun_refreshes_status_in_noninteractive_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = SetupSelection(engine_root=Path.cwd(), knowledge_root=root / "knowledge", runtime_root=root / "runtime", hosts=("codex-cli",), host_homes={"codex-cli": root / "host"}, organizer_provider="subscription-cli", organizer_host="codex-cli", skip_venv=True, python_exe=Path(sys.executable), non_interactive=True, accept_plan=True)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            second = setup(selection)
            self.assertTrue(second.ok, second.to_dict())
            self.assertEqual(second.reconciliation["status"], "ALREADY_CURRENT")
            before = second.manifest_path.read_bytes()
            from types import SimpleNamespace
            receipt = {"host_id": "codex-cli", "hook_status": "HOOK_VERIFIED", "static_checks": {"valid": True}}
            with patch("ei.setup_activation.read_hook_status", return_value=SimpleNamespace(to_dict=lambda: receipt)):
                value = setup_result_with_guidance(selection, second)
            self.assertEqual(value["activation"]["hooks"][0]["status"], "VERIFIED")
            self.assertEqual(second.manifest_path.read_bytes(), before)

    def test_user_acknowledgement_does_not_verify_hook(self):
        selection = SetupSelection(hosts=("codex-cli",), scheduler=False)
        result = SetupResult(ok=True, status="SETUP_COMPLETE", manifest_path=Path("fixture-manifest.json"))
        with patch("builtins.input", return_value="yes"), patch("ei.setup_activation.read_hook_status", side_effect=AssertionError("no receipt requested")), contextlib.redirect_stdout(io.StringIO()):
            value = setup_result_with_guidance(selection, result, interactive=True)
        self.assertEqual(value["activation"]["hooks"][0]["status"], "UNVERIFIED")
        self.assertEqual(value["activation"]["maintenance"]["status"], "DISABLED")

    def test_recheck_reads_receipts_and_actual_scheduler_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = SetupSelection(engine_root=Path.cwd(), knowledge_root=root / "knowledge", runtime_root=root / "runtime", hosts=("codex-cli",), host_homes={"codex-cli": root / "host"}, organizer_provider="subscription-cli", organizer_host="codex-cli", skip_venv=True, python_exe=Path(sys.executable), non_interactive=True, accept_plan=True)
            result = setup(selection)
            self.assertTrue(result.ok, result.to_dict())
            manifest_before = result.manifest_path.read_bytes()
            from dataclasses import replace
            selection = replace(selection, scheduler=True)
            receipt = {"host_id": "codex-cli", "hook_status": "HOOK_VERIFIED", "static_checks": {"valid": True}, "received_events": ["session.start", "prompt.before", "turn.stop", "session.end"]}
            from types import SimpleNamespace
            with patch("builtins.input", side_effect=["r", ""]), patch("ei.setup_activation.read_hook_status", return_value=SimpleNamespace(to_dict=lambda: receipt)), patch("ei.setup_activation.inspect_registered_task", return_value={"ok": True, "registered": True}), contextlib.redirect_stdout(io.StringIO()):
                value = setup_result_with_guidance(selection, result, interactive=True)
            self.assertEqual(value["activation"]["hooks"][0]["status"], "VERIFIED")
            self.assertEqual(value["activation"]["maintenance"]["status"], "ENABLED")
            self.assertEqual(value["activation"]["automatic_operation"], "UNVERIFIED")
            self.assertEqual(result.manifest_path.read_bytes(), manifest_before)

    def test_retained_installation_reports_hook_steps_when_scheduler_failed(self):
        selection = SetupSelection(hosts=("codex-cli",), scheduler=True)
        result = SetupResult(ok=False, status="SCHEDULER_SETUP_BLOCKED", rollback={"status": "INSTALLATION_RETAINED"})
        value = setup_result_with_guidance(selection, result)
        self.assertIn("activation", value)
        self.assertFalse(value["ok"])
        self.assertEqual(value["activation"]["hooks"][0]["status"], "UNVERIFIED")
        self.assertEqual(value["activation"]["maintenance"]["status"], "UNVERIFIED")

    def test_failed_setup_without_retained_installation_has_no_activation_prompt(self):
        selection = SetupSelection(hosts=("codex-cli",))
        result = SetupResult(ok=False, status="KNOWLEDGE_SETUP_FAILED")
        with patch("builtins.input", side_effect=AssertionError("must not prompt")):
            value = setup_result_with_guidance(selection, result, interactive=True)
        self.assertNotIn("activation", value)

    def test_check_only_does_not_prompt_or_read_receipts(self):
        selection = SetupSelection(hosts=("codex-cli",))
        result = SetupResult(ok=True, status="CHECK_ONLY")
        with patch("builtins.input", side_effect=AssertionError("must not prompt")), patch("ei.setup_activation.read_hook_status", side_effect=AssertionError("must not read/write receipts")):
            value = setup_result_with_guidance(selection, result, interactive=True, check_only=True)
        self.assertNotIn("activation", value)

    def test_static_configuration_or_registration_alone_is_not_verification(self):
        report = activation_report(["codex-cli"], [{"host_id": "codex-cli", "hook_status": "HOOK_VERIFIED", "static_checks": {"valid": False}}], {"status": "REGISTERED", "registered": True}, True)
        self.assertEqual(report["hooks"][0]["status"], "UNVERIFIED")
        self.assertEqual(report["maintenance"]["status"], "UNVERIFIED")

    def test_setup_reports_pending_hook_and_stopped_maintenance_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = SetupSelection(
                engine_root=Path.cwd(), knowledge_root=root / "knowledge", runtime_root=root / "runtime",
                hosts=("codex-cli",), scheduler=True, non_interactive=True,
            )
            result = SetupResult(
                ok=True, status="SETUP_COMPLETE",
                hosts=({"host_id": "codex-cli", "hook_status": "HOOK_UNVERIFIED"},),
                scheduler={"requested": True, "status": "REGISTERED", "verification": {"ok": False, "reason_code": "SCHEDULER_CONTRACT_FAILED"}},
            )
            output = io.StringIO()
            with patch("sys.argv", ["ei.installer", "--setup", "--non-interactive", "--json"]), patch("ei.installer._interactive_selection", return_value=selection), patch("ei.installer.setup", return_value=result), contextlib.redirect_stdout(output):
                code = _main()
            self.assertEqual(code, 0)
            value = json.loads(output.getvalue())
            self.assertIn("activation", value)
            self.assertEqual(value["activation"]["hooks"][0]["status"], "UNVERIFIED")
            self.assertIn("/hooks", value["activation"]["hooks"][0]["next_action"])
            self.assertEqual(value["activation"]["maintenance"]["status"], "UNVERIFIED")
            self.assertEqual(value["activation"]["automatic_operation"], "UNVERIFIED")
            self.assertFalse(root.joinpath("runtime").exists())

    def test_guided_setup_asks_before_enabling_automatic_maintenance(self):
        for answer, expected in (("yes", True), ("no", False)):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = io.StringIO()
                questions = []
                args = argparse.Namespace(
                    setup=True,
                    engine_root=Path.cwd(), knowledge_root=root / "knowledge",
                    runtime_root=root / "runtime", work_hosts=["codex-cli"],
                    host_home=[f"codex-cli={root / 'host'}"],
                    organizer_provider="subscription-cli", organizer_host="codex-cli",
                    knowledge_mode="local", team_knowledge=False, sync=False,
                    scheduler=None, python_exe=sys.executable, skip_venv=True,
                )

                def respond():
                    question = output.getvalue().splitlines()[-1]
                    questions.append(question)
                    if "記憶の整理を定期的に実行" in question:
                        return answer
                    if "この内容を適用" in question:
                        return "yes"
                    return "no"

                with contextlib.redirect_stdout(output), patch("builtins.input", side_effect=respond):
                    selected = _guided_interactive_selection(args)
                self.assertTrue(any("記憶の整理を定期的に実行" in question for question in questions))
                self.assertEqual(selected.scheduler, expected)
                self.assertFalse(selected.sync)
                self.assertFalse((root / "runtime").exists())

    def test_disabled_windows_task_is_not_reported_as_operational(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            engine.mkdir()
            python = root / "python"
            python.write_bytes(b"fixture executable")
            settings = Settings(paths=RuntimePaths(engine, root / "knowledge", root / "runtime"))
            action = build_maintenance_action(settings, python)
            write_scheduler_state(settings, action, True)
            live = {
                "TaskName": TASK_NAME, "Execute": str(action.executable),
                "Arguments": action.arguments, "WorkingDirectory": str(engine),
                "UserId": current_principal(), "RunLevel": "Limited",
                "LastTaskResult": 0, "LastRunTime": "2030-01-01T00:00:00Z",
                "NextRunTime": "2030-01-01T00:30:00Z", "State": "Disabled", "Enabled": False,
            }
            with patch("ei.task_scheduler.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(live), "")):
                result = inspect_registered_task(settings, platform_name="Windows")
            self.assertFalse(result["ok"], result)
            self.assertTrue(result["identity_verified"], result)
            self.assertFalse(result["checks"]["manager_enabled"])


if __name__ == "__main__":
    unittest.main()
