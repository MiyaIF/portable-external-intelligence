from __future__ import annotations

import os
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from ei.installer import (
    SetupSelection,
    WINDOWS_NOTIFICATION_MAX_RECORD_BYTES,
    WINDOWS_NOTIFICATION_MAX_SHORTCUT_BYTES,
    _Transaction,
    _main,
    _notification_artifacts_match,
    _read_notification_receipt,
    _recover_pending_transactions,
    _run_windows_notification_registration,
    _uninstall_from_manifest,
    _windows_notification_locations,
    setup,
    UninstallOptions,
)


REPOSITORY = Path(__file__).resolve().parents[2]


from tests.support.sitecustomize import NotificationIsolationMixin, is_powershell_execution_policy_refusal


class UnattendedSetupIntegrationTests(NotificationIsolationMixin, unittest.TestCase):
    def _fake_notification_helper(self, action: str, target: Path, *, expected_shortcut_sha256: str | None = None, expected_registration_sha256: str | None = None) -> dict[str, object]:
        shortcut = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
        registration = Path(os.environ["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
        if action == "register":
            if shortcut.exists() or registration.exists():
                return {"status": "CONFLICT", "verified": False}
            shortcut.parent.mkdir(parents=True, exist_ok=True)
            registration.parent.mkdir(parents=True, exist_ok=True)
            shortcut_raw = b"fake shortcut bytes"
            shortcut.write_bytes(shortcut_raw)
            registration_raw = json.dumps({
                "schema_version": 1,
                "app_id": "MiyaIF.ExternalIntelligence",
                "shortcut_sha256": hashlib.sha256(shortcut_raw).hexdigest(),
                "target": str(target),
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            registration.write_bytes(registration_raw)
            return {
                "status": "REGISTERED",
                "verified": True,
                "target": str(target),
                "shortcut_sha256": hashlib.sha256(shortcut_raw).hexdigest(),
                "registration_sha256": hashlib.sha256(registration_raw).hexdigest(),
            }
        if action == "verify":
            if not shortcut.is_file() or not registration.is_file():
                return {"status": "UNAVAILABLE", "verified": False}
            return {
                "status": "CURRENT",
                "verified": True,
                "target": str(target),
                "shortcut_sha256": hashlib.sha256(shortcut.read_bytes()).hexdigest(),
                "registration_sha256": hashlib.sha256(registration.read_bytes()).hexdigest(),
            }
        if action == "unregister":
            if shortcut.exists() and hashlib.sha256(shortcut.read_bytes()).hexdigest() != expected_shortcut_sha256:
                return {"status": "CONFLICT", "verified": False}
            if registration.exists() and hashlib.sha256(registration.read_bytes()).hexdigest() != expected_registration_sha256:
                return {"status": "CONFLICT", "verified": False}
            if shortcut.exists():
                shortcut.unlink()
            if registration.exists():
                registration.unlink()
            return {"status": "REMOVED", "verified": True}
        raise AssertionError(f"unexpected helper action: {action}")

    def _windows_notification_environment(self, root: Path) -> dict[str, str]:
        system_root = root / "Windows"
        executable = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"fake powershell executable")
        return {
            "SystemRoot": str(system_root),
            "APPDATA": str(root / "Roaming"),
            "LOCALAPPDATA": str(root / "Local"),
        }

    def _selection_for_runtime(self, runtime: Path) -> SetupSelection:
        host = runtime.parent / "host"
        host.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=REPOSITORY,
            personal_knowledge_root=runtime.parent / "knowledge",
            runtime_root=runtime,
            hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            host_homes={"codex-cli": host},
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def test_windows_registration_is_recorded_and_reused_only_with_owned_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            calls: list[str] = []

            def helper(action: str, target: Path, **kwargs: object) -> dict[str, object]:
                calls.append(action)
                return self._fake_notification_helper(action, target, **kwargs)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=helper, create=True
            ):
                first = setup(selection)
                sidecar = selection.runtime_root / "windows-notification-ownership.json"
                self.assertTrue(first.ok, first.to_dict())
                self.assertEqual(first.notification_registration["status"], "REGISTERED")
                receipt = json.loads(sidecar.read_text(encoding="utf-8"))
                self.assertEqual(receipt["schema_version"], 1)
                self.assertEqual(receipt["status"], "REGISTERED")
                self.assertNotIn("shortcut_path", receipt)
                self.assertNotIn("registration_path", receipt)
                second = setup(selection)

            self.assertTrue(second.ok, second.to_dict())
            self.assertEqual(second.notification_registration["status"], "CURRENT")
            self.assertEqual(calls, ["register", "verify"])
            self.assertEqual(json.loads(sidecar.read_text(encoding="utf-8")), receipt)

    def test_notification_receipt_and_artifact_reads_are_bounded_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            receipt_path = runtime / "windows-notification-ownership.json"
            receipt_path.write_bytes(b"{" + (b"x" * WINDOWS_NOTIFICATION_MAX_RECORD_BYTES))
            shortcut = root / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = root / "Local" / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            shortcut.parent.mkdir(parents=True)
            registration.parent.mkdir(parents=True)
            target = root / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            locations = {"shortcut": shortcut, "registration": registration, "target": target}
            receipt = {"shortcut_sha256": "a" * 64, "registration_sha256": "b" * 64}
            original_fdopen = os.fdopen
            read_sizes: list[int] = []

            class TrackingFile:
                def __init__(self, wrapped: object) -> None:
                    self.wrapped = wrapped

                def __enter__(self) -> "TrackingFile":
                    self.wrapped.__enter__()
                    return self

                def __exit__(self, *args: object) -> object:
                    return self.wrapped.__exit__(*args)

                def fileno(self) -> int:
                    return self.wrapped.fileno()

                def read(self, size: int = -1) -> bytes:
                    read_sizes.append(size)
                    return self.wrapped.read(size)

            def tracking_fdopen(descriptor: int, mode: str) -> TrackingFile:
                return TrackingFile(original_fdopen(descriptor, mode))

            with patch("pathlib.Path.read_bytes", side_effect=AssertionError("unbounded Path.read_bytes used")), patch(
                "ei.installer.os.fdopen", side_effect=tracking_fdopen
            ):
                self.assertEqual(_read_notification_receipt(receipt_path, target), {"status": "INVALID"})
                shortcut.write_bytes(b"s" * (WINDOWS_NOTIFICATION_MAX_SHORTCUT_BYTES + 1))
                self.assertFalse(_notification_artifacts_match(locations, receipt, allow_missing=True))
                shortcut.unlink()
                registration.write_bytes(b"r" * (WINDOWS_NOTIFICATION_MAX_RECORD_BYTES + 1))
                self.assertFalse(_notification_artifacts_match(locations, receipt, allow_missing=True))

            self.assertEqual(read_sizes, [])

    def test_windows_registration_collision_is_never_adopted_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            shortcut.parent.mkdir(parents=True)
            shortcut.write_bytes(b"user-owned")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ) as helper:
                result = setup(selection)

            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.notification_registration["status"], "CONFLICT")
            self.assertEqual(shortcut.read_bytes(), b"user-owned")
            self.assertFalse((selection.runtime_root / "windows-notification-ownership.json").exists())
            helper.assert_not_called()

    def test_modified_ownership_receipt_is_not_followed_for_setup_or_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ):
                installed = setup(selection)
                self.assertTrue(installed.ok, installed.to_dict())
                receipt_path = selection.runtime_root / "windows-notification-ownership.json"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt["shortcut_path"] = str(root / "untrusted-target")
                receipt["extra"] = "x" * 9000
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
                registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
                shortcut_before = shortcut.read_bytes()
                registration_before = registration.read_bytes()
                with patch("ei.installer._run_windows_notification_registration", side_effect=AssertionError("invalid receipt followed into the OS helper")):
                    reapplied = setup(selection)
                    removed = _uninstall_from_manifest(installed.manifest_path, UninstallOptions(remove_skills=False, remove_scheduler=False))

            self.assertTrue(reapplied.ok, reapplied.to_dict())
            self.assertEqual(reapplied.notification_registration["status"], "UNVERIFIED")
            self.assertFalse(removed.ok)
            self.assertEqual(removed.notification_registration["status"], "UNVERIFIED")
            self.assertEqual(shortcut.read_bytes(), shortcut_before)
            self.assertEqual(registration.read_bytes(), registration_before)
            self.assertEqual(receipt_path.read_text(encoding="utf-8"), json.dumps(receipt))

    def test_windows_helper_uses_fixed_argv_without_execution_policy_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"SystemRoot": str(root / "Windows")}
            target = Path(env["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            response = {"status": "CURRENT", "verified": True, "target": str(target)}
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout=json.dumps(response), stderr=""),
            ) as process:
                result = _run_windows_notification_registration("verify", target)

            self.assertEqual(result["status"], "CURRENT")
            command = process.call_args.args[0]
            self.assertIn("-File", command)
            self.assertIn("-Action", command)
            self.assertIn("Verify", command)
            self.assertIn("-Target", command)
            self.assertNotIn("-ExecutionPolicy", command)
            self.assertFalse(process.call_args.kwargs["shell"])
            self.assertEqual(process.call_args.kwargs["creationflags"], 0x08000000 if os.name == "nt" else 0)

    def test_uninstall_removes_only_unchanged_notification_files_with_valid_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            helper = self._fake_notification_helper
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=helper, create=True
            ):
                installed = setup(selection)
                self.assertTrue(installed.ok, installed.to_dict())
                shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
                registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
                receipt_path = selection.runtime_root / "windows-notification-ownership.json"
                shortcut.write_bytes(b"modified by the user")
                result = _uninstall_from_manifest(installed.manifest_path, UninstallOptions(remove_skills=False, remove_scheduler=False))

            self.assertFalse(result.ok)
            self.assertEqual(shortcut.read_bytes(), b"modified by the user")
            self.assertTrue(registration.is_file())
            self.assertTrue(receipt_path.is_file())

    def test_uninstall_check_only_does_not_invoke_notification_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ):
                installed = setup(selection)
                self.assertTrue(installed.ok, installed.to_dict())
                with patch("ei.installer._run_windows_notification_registration", side_effect=AssertionError("check-only called OS helper")):
                    result = _uninstall_from_manifest(installed.manifest_path, UninstallOptions(remove_skills=False, remove_scheduler=False, check_only=True))

            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.status, "CHECK_ONLY")

    def test_notification_receipt_write_failure_prevents_external_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            original = _Transaction.mutate_file

            def fail_sidecar(self: _Transaction, target: Path, raw: bytes, *, details: object = None) -> Path | None:
                if target.name == "windows-notification-ownership.json":
                    raise ValueError("OWNERSHIP_RECEIPT_WRITE_FAILED")
                return original(self, target, raw, details=details)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ) as helper, patch.object(_Transaction, "mutate_file", new=fail_sidecar):
                result = setup(selection)

            shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.notification_registration["status"], "UNVERIFIED")
            helper.assert_not_called()
            self.assertFalse(shortcut.exists() or registration.exists())

    def test_notification_journal_rollback_failure_preserves_prepared_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            original_mutate = _Transaction.mutate_file
            original_rollback = _Transaction.rollback

            def write_then_fail(self: _Transaction, target: Path, raw: bytes, *, details: object = None) -> Path | None:
                result = original_mutate(self, target, raw, details=details)
                if target.name == "windows-notification-ownership.json" and json.loads(raw).get("status") == "PREPARED":
                    raise OSError("simulated post-write journal failure")
                return result

            def fail_notification_rollback(self: _Transaction) -> dict[str, object]:
                if any(entry.get("details", {}).get("kind") == "windows-notification-ownership" for entry in self.entries):
                    raise OSError("simulated notification rollback failure")
                return original_rollback(self)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ) as helper, patch.object(_Transaction, "mutate_file", new=write_then_fail), patch.object(
                _Transaction, "rollback", new=fail_notification_rollback
            ):
                result = setup(selection)

            receipt_path = selection.runtime_root / "windows-notification-ownership.json"
            self.assertEqual(result.notification_registration["status"], "UNVERIFIED", result.to_dict())
            self.assertTrue(receipt_path.is_file(), result.to_dict())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            journal_path = selection.runtime_root / "transactions" / (receipt["transaction_id"] + ".json")
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.notification_registration["status"], "UNVERIFIED")
            self.assertEqual(result.notification_registration["reason_code"], "OWNERSHIP_JOURNAL_ROLLBACK_FAILED_OSError")
            self.assertEqual(receipt["status"], "PREPARED")
            self.assertEqual(journal["status"], "IN_PROGRESS")
            helper.assert_not_called()

    def test_unverified_os_response_commit_failure_retains_prepared_recovery_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            original_commit = _Transaction.commit

            def fail_notification_commit(self: _Transaction) -> None:
                if any(entry.get("details", {}).get("kind") == "windows-notification-ownership" for entry in self.entries):
                    raise OSError("simulated journal finalization failure")
                original_commit(self)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration",
                return_value={"status": "FAILED", "verified": False, "reason_code": "OS_RESPONSE_UNVERIFIED"},
                create=True,
            ), patch.object(_Transaction, "commit", new=fail_notification_commit):
                result = setup(selection)

            receipt_path = selection.runtime_root / "windows-notification-ownership.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            journal_path = selection.runtime_root / "transactions" / (receipt["transaction_id"] + ".json")
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.notification_registration["status"], "UNVERIFIED")
            self.assertEqual(result.notification_registration["reason_code"], "OS_RESPONSE_UNVERIFIED_JOURNAL_FINALIZE_FAILED_OSError")
            self.assertEqual(receipt["status"], "PREPARED")
            self.assertEqual(journal["status"], "IN_PROGRESS")
            recovered = _recover_pending_transactions(selection.runtime_root.resolve(strict=True))
            self.assertEqual(recovered[0]["status"], "PRESERVED_UNVERIFIED")
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(json.loads(journal_path.read_text(encoding="utf-8"))["status"], "IN_PROGRESS")
            no_retry = patch(
                "ei.installer._run_windows_notification_registration",
                side_effect=AssertionError("journal without committed no-effect evidence must not retry"),
                create=True,
            )
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), no_retry as helper:
                retried = setup(selection)
            self.assertTrue(retried.ok, retried.to_dict())
            self.assertEqual(retried.notification_registration["reason_code"], "OWNERSHIP_RECOVERY_REQUIRED")
            helper.assert_not_called()
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(json.loads(journal_path.read_text(encoding="utf-8"))["status"], "IN_PROGRESS")

    def test_prepared_receipt_requires_committed_no_effect_journal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration",
                return_value={"status": "UNAVAILABLE", "verified": False, "reason_code": "OS_HELPER_START_FAILED"},
                create=True,
            ):
                installed = setup(selection)
            receipt_path = selection.runtime_root / "windows-notification-ownership.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            journal_path = selection.runtime_root / "transactions" / (receipt["transaction_id"] + ".json")
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journal["status"] = "IN_PROGRESS"
            journal_path.write_text(json.dumps(journal), encoding="utf-8")
            no_retry = patch(
                "ei.installer._run_windows_notification_registration",
                side_effect=AssertionError("journal without committed no-effect evidence must not retry"),
                create=True,
            )
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), no_retry as helper:
                retried = setup(selection)

            self.assertTrue(installed.ok, installed.to_dict())
            self.assertTrue(retried.ok, retried.to_dict())
            self.assertEqual(retried.notification_registration["reason_code"], "OWNERSHIP_RECOVERY_REQUIRED")
            helper.assert_not_called()
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)

    def test_notification_process_start_failure_is_classified_as_no_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            target = Path(env["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer.subprocess.run", side_effect=FileNotFoundError("executable start refused")
            ):
                response = _run_windows_notification_registration("register", target)

            self.assertEqual(response, {
                "status": "UNAVAILABLE",
                "verified": False,
                "reason_code": "OS_HELPER_START_FAILED",
            })

    def test_known_start_failure_prepared_attempt_retries_and_uninstalls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration",
                return_value={"status": "UNAVAILABLE", "verified": False, "reason_code": "OS_HELPER_START_FAILED"},
                create=True,
            ):
                first = setup(selection)

            receipt_path = selection.runtime_root / "windows-notification-ownership.json"
            first_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            first_journal = json.loads((selection.runtime_root / "transactions" / (first_receipt["transaction_id"] + ".json")).read_text(encoding="utf-8"))
            self.assertTrue(first.ok, first.to_dict())
            self.assertEqual(first.notification_registration["status"], "UNVERIFIED")
            self.assertEqual(first_receipt["status"], "PREPARED")
            self.assertEqual(first_journal["status"], "COMMITTED")

            calls: list[str] = []

            def helper(action: str, target: Path, **kwargs: object) -> dict[str, object]:
                calls.append(action)
                return self._fake_notification_helper(action, target, **kwargs)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=helper, create=True
            ):
                retried = setup(selection)
                removed = _uninstall_from_manifest(
                    retried.manifest_path,
                    UninstallOptions(remove_skills=False, remove_scheduler=False, remove_runtime=True),
                )

            self.assertTrue(retried.ok, retried.to_dict())
            self.assertEqual(retried.notification_registration["status"], "REGISTERED", retried.to_dict())
            self.assertTrue(removed.ok, removed.to_dict())
            self.assertEqual(removed.notification_registration["status"], "REMOVED")
            self.assertEqual(calls, ["register", "unregister"])
            self.assertFalse(receipt_path.exists())
            self.assertFalse((Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk").exists())
            self.assertFalse((Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json").exists())

    def test_known_no_effect_prepared_attempt_does_not_block_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration",
                return_value={"status": "DENIED", "verified": False, "reason_code": "EXECUTION_POLICY_BLOCKED"},
                create=True,
            ):
                installed = setup(selection)

            helper = patch("ei.installer._run_windows_notification_registration", side_effect=AssertionError("no-artifact uninstall must not invoke helper"), create=True)
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), helper as called:
                removed = _uninstall_from_manifest(
                    installed.manifest_path,
                    UninstallOptions(remove_skills=False, remove_scheduler=False, remove_runtime=True),
                )

            self.assertTrue(installed.ok, installed.to_dict())
            self.assertTrue(removed.ok, removed.to_dict())
            self.assertEqual(removed.notification_registration["status"], "NOT_OWNED")
            called.assert_not_called()
            self.assertFalse((selection.runtime_root / "windows-notification-ownership.json").exists())

    def test_unknown_partial_notification_effect_remains_protected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"

            def partial_response(action: str, target: Path, **kwargs: object) -> dict[str, object]:
                if action == "register":
                    shortcut.parent.mkdir(parents=True, exist_ok=True)
                    shortcut.write_bytes(b"partial helper-created artifact")
                return {"status": "UNVERIFIED", "verified": False, "reason_code": "OS_RESPONSE_UNVERIFIED"}

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=partial_response, create=True
            ):
                installed = setup(selection)

            receipt_path = selection.runtime_root / "windows-notification-ownership.json"
            receipt_before = receipt_path.read_bytes()
            artifact_before = shortcut.read_bytes()
            unexpected = patch("ei.installer._run_windows_notification_registration", side_effect=AssertionError("ambiguous artifact must not be retried or removed"), create=True)
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), unexpected as called:
                retried = setup(selection)
                removed = _uninstall_from_manifest(
                    installed.manifest_path,
                    UninstallOptions(remove_skills=False, remove_scheduler=False, remove_runtime=True),
                )

            self.assertTrue(installed.ok, installed.to_dict())
            self.assertEqual(installed.notification_registration["status"], "UNVERIFIED")
            self.assertTrue(retried.ok, retried.to_dict())
            self.assertEqual(retried.notification_registration["status"], "UNVERIFIED")
            self.assertFalse(removed.ok)
            self.assertIn(removed.notification_registration["status"], {"UNVERIFIED", "CONFLICT"})
            called.assert_not_called()
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            self.assertEqual(shortcut.read_bytes(), artifact_before)

    def test_registered_receipt_save_failure_rolls_back_created_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            helper_calls: list[str] = []

            def helper(action: str, target: Path, **kwargs: object) -> dict[str, object]:
                helper_calls.append(action)
                return self._fake_notification_helper(action, target, **kwargs)

            original = _Transaction.mutate_file

            def fail_registered_receipt(self: _Transaction, target: Path, raw: bytes, *, details: object = None) -> Path | None:
                if target.name == "windows-notification-ownership.json" and json.loads(raw).get("status") == "REGISTERED":
                    raise ValueError("OWNERSHIP_RECEIPT_SAVE_FAILED")
                return original(self, target, raw, details=details)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=helper, create=True
            ), patch.object(_Transaction, "mutate_file", new=fail_registered_receipt):
                result = setup(selection)

            shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.notification_registration["status"], "UNVERIFIED")
            self.assertEqual(helper_calls, ["register", "unregister"])
            self.assertFalse(shortcut.exists() or registration.exists())
            self.assertFalse((selection.runtime_root / "windows-notification-ownership.json").exists())

    def test_later_setup_transaction_failure_removes_only_new_notification_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            helper_calls: list[str] = []

            def helper(action: str, target: Path, **kwargs: object) -> dict[str, object]:
                helper_calls.append(action)
                return self._fake_notification_helper(action, target, **kwargs)

            original = _Transaction.commit
            commit_calls = 0

            def fail_main_commit(self: _Transaction) -> None:
                nonlocal commit_calls
                commit_calls += 1
                if commit_calls == 2:
                    raise OSError("simulated setup journal commit failure")
                original(self)

            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=helper, create=True
            ), patch.object(_Transaction, "commit", new=fail_main_commit):
                result = setup(selection)

            shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            self.assertFalse(result.ok, result.to_dict())
            self.assertEqual(helper_calls, ["register", "unregister"])
            self.assertFalse(shortcut.exists() or registration.exists())
            self.assertFalse((selection.runtime_root / "windows-notification-ownership.json").exists(), result.to_dict())

    def test_uninstall_retry_cleans_partial_deletion_using_only_receipted_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = self._windows_notification_environment(root)
            selection = self._selection_for_runtime(root / "runtime")
            with patch.dict(os.environ, env, clear=False), patch("ei.installer.sys.platform", "win32"), patch(
                "ei.installer._run_windows_notification_registration", side_effect=self._fake_notification_helper, create=True
            ):
                installed = setup(selection)
                self.assertTrue(installed.ok, installed.to_dict())
                shortcut = Path(env["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
                registration = Path(env["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
                registration.unlink()
                result = _uninstall_from_manifest(installed.manifest_path, UninstallOptions(remove_skills=False, remove_scheduler=False))

            self.assertTrue(result.ok, result.to_dict())
            self.assertFalse(shortcut.exists() or registration.exists())
            self.assertFalse((selection.runtime_root / "windows-notification-ownership.json").exists())

    def test_check_only_with_every_operation_flag_does_not_run_tests_or_create_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            knowledge = root / "knowledge"
            host = root / "host"
            argv = [
                "ei.installer", "--setup", "--repo", str(REPOSITORY),
                "--knowledge-mode", "local", "--knowledge-root", str(knowledge),
                "--runtime-root", str(runtime), "--work-host", "codex-cli",
                "--host-home", f"codex-cli={host}", "--organizer-provider", "ollama",
                "--no-scheduler", "--skip-venv", "--non-interactive", "--accept-plan",
                "--check-only", "--verify-operation", "--allow-model-test",
                "--allow-notification-test", "--json",
            ]
            with patch("sys.argv", argv), patch(
                "ei.setup_activation.verify_operation", side_effect=AssertionError("check-only must not run operation verification")
            ), patch(
                "ei.operation_activation.send_native_notification", side_effect=AssertionError("check-only must not send notifications")
            ), patch(
                "ei.installer._run_windows_notification_registration", side_effect=AssertionError("check-only must not reach notification helper")
            ), contextlib.redirect_stdout(io.StringIO()):
                code = _main()
            self.assertEqual(code, 0)
            self.assertFalse(runtime.exists())
            self.assertFalse(knowledge.exists())
            self.assertFalse(host.exists())

    def test_direct_notification_guard_rejects_unexpected_target(self) -> None:
        import importlib

        try:
            support = importlib.import_module("tests.support.sitecustomize")
        except ModuleNotFoundError:
            self.fail("the shared test-only notification guard must exist")
        with support.NotificationIsolation() as isolation:
            outside_target = isolation.root / "outside" / "powershell.exe"
            with self.assertRaisesRegex(AssertionError, "NOTIFICATION_TEST_UNEXPECTED_TARGET"):
                _run_windows_notification_registration("register", outside_target)
            shortcut = isolation.root / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = isolation.root / "Local" / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            self.assertFalse(shortcut.exists())
            self.assertFalse(registration.exists())

    @unittest.skipUnless(sys.platform == "win32", "notification helper process boundary is Windows-specific")
    def test_child_notification_guard_rejects_unexpected_helper_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            environment = self.notification_child_environment(target=target)
            code = (
                "import os,runpy,subprocess,sys\n"
                "from pathlib import Path\n"
                "runner = subprocess.run\n"
                "if not getattr(runner, '_ei_notification_isolation', False):\n"
                "    print('NOTIFICATION_TEST_GUARD_NOT_INSTALLED', file=sys.stderr)\n"
                "    raise SystemExit(124)\n"
                "sys.path.insert(0, str(Path(os.environ['EI_TEST_NOTIFICATION_HELPER_ROOT']) / 'src'))\n"
                "sys.argv = ['ei.installer', '--setup', '--repo', os.environ['EI_TEST_NOTIFICATION_HELPER_ROOT'],\n"
                "    '--engine-root', os.environ['EI_TEST_NOTIFICATION_HELPER_ROOT'], '--runtime-root',\n"
                "    str(Path(os.environ['EI_TEST_NOTIFICATION_ROOT']) / 'runtime'), '--knowledge-mode', 'local',\n"
                "    '--knowledge-root', str(Path(os.environ['EI_TEST_NOTIFICATION_ROOT']) / 'knowledge'),\n"
                "    '--hosts', 'codex-cli', '--host-home', 'codex-cli=' + str(Path(os.environ['EI_TEST_NOTIFICATION_ROOT']) / 'host'),\n"
                "    '--organizer-provider', 'subscription-cli', '--organizer-host', 'codex-cli',\n"
                "    '--skip-venv', '--no-scheduler', '--non-interactive', '--accept-plan', '--json']\n"
                "try:\n"
                "    runpy.run_module('ei.installer', run_name='__main__')\n"
                "finally:\n"
                "    print('ENGINE_ENTRY_RETURNED')\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", code],
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("NOTIFICATION_TEST_UNEXPECTED_HELPER_CALL", result.stderr, result.stdout + result.stderr)
            self.assertIn("ENGINE_ENTRY_RETURNED", result.stdout)
            self.assertNotIn("NOTIFICATION_TEST_GUARD_NOT_INSTALLED", result.stderr)
            shortcut = Path(environment["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"
            registration = Path(environment["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"
            self.assertFalse(shortcut.exists())
            self.assertFalse(registration.exists())

    def test_enabled_child_bootstrap_failure_stops_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = self._windows_notification_environment(root)
            environment["EI_TEST_NOTIFICATION_ISOLATION"] = "1"
            environment["EI_TEST_NOTIFICATION_BOOTSTRAP_FAILURE"] = "1"
            environment["EI_TEST_NOTIFICATION_ROOT"] = str(root)
            environment["EI_TEST_NOTIFICATION_TARGET"] = str(root / "expected" / "python.exe")
            environment["PYTHONPATH"] = os.pathsep.join((
                str(REPOSITORY / "tests" / "support"),
                str(REPOSITORY / "src"),
                os.environ.get("PYTHONPATH", ""),
            ))
            code = (
                "import runpy,sys\n"
                "source=sys.argv.pop(1);sys.path.insert(0,source)\n"
                "try:\n"
                "    runpy.run_module('ei.installer',run_name='__main__')\n"
                "finally:\n"
                "    print('CHILD_ENTRY_RAN')\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", code, str(REPOSITORY / "src"), "--unknown-test-argument"],
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("CHILD_ENTRY_RAN", result.stdout)
            self.assertIn("NOTIFICATION_TEST_BOOTSTRAP_FAILED", result.stderr)

    def test_enabled_child_early_import_failure_stops_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = self._windows_notification_environment(root)
            environment["EI_TEST_NOTIFICATION_ISOLATION"] = "1"
            environment["EI_TEST_NOTIFICATION_BOOTSTRAP_IMPORT_FAILURE"] = "1"
            environment["EI_TEST_NOTIFICATION_ROOT"] = str(root)
            environment["EI_TEST_NOTIFICATION_TARGET"] = str(root / "expected" / "python.exe")
            environment["PYTHONPATH"] = os.pathsep.join((
                str(REPOSITORY / "tests" / "support"),
                str(REPOSITORY / "src"),
                os.environ.get("PYTHONPATH", ""),
            ))
            code = (
                "import runpy,sys\n"
                "source=sys.argv.pop(1);sys.path.insert(0,source)\n"
                "try:\n"
                "    runpy.run_module('ei.installer',run_name='__main__')\n"
                "finally:\n"
                "    print('CHILD_ENTRY_RAN')\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", code, str(REPOSITORY / "src"), "--unknown-test-argument"],
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("CHILD_ENTRY_RAN", result.stdout)
            self.assertIn("NOTIFICATION_TEST_BOOTSTRAP_FAILED", result.stderr)
            self.assertIn("10106", result.stderr)

    def test_enabled_child_first_support_import_failure_stops_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = self._windows_notification_environment(root)
            environment["EI_TEST_NOTIFICATION_ISOLATION"] = "1"
            environment["EI_TEST_NOTIFICATION_INITIAL_IMPORT_FAILURE"] = "1"
            environment["EI_TEST_NOTIFICATION_ROOT"] = str(root)
            environment["EI_TEST_NOTIFICATION_TARGET"] = str(root / "expected" / "python.exe")
            environment["PYTHONPATH"] = os.pathsep.join((
                str(REPOSITORY / "tests" / "support"),
                str(REPOSITORY / "src"),
                os.environ.get("PYTHONPATH", ""),
            ))
            code = (
                "import runpy,sys\n"
                "source=sys.argv.pop(1);sys.path.insert(0,source)\n"
                "try:\n"
                "    runpy.run_module('ei.installer',run_name='__main__')\n"
                "finally:\n"
                "    print('CHILD_ENTRY_RAN')\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", code, str(REPOSITORY / "src"), "--unknown-test-argument"],
                env={**os.environ, **environment},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("CHILD_ENTRY_RAN", result.stdout)
            self.assertIn("NOTIFICATION_TEST_BOOTSTRAP_FAILED:10106", result.stderr)

    @unittest.skipUnless(sys.platform == "win32", "PowerShell wrapper is Windows-specific")
    def test_isolated_powershell_wrapper_child_bootstrap_failure_stops_engine_entry(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python_shim = self.powershell_python_shim()
            environment = self.notification_child_environment()
            host_system_root = os.environ.get("WINDIR")
            self.assertTrue(host_system_root and (Path(host_system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").is_file())
            environment["SystemRoot"] = str(Path(host_system_root).resolve())
            environment["EI_TEST_NOTIFICATION_BOOTSTRAP_IMPORT_FAILURE"] = "1"
            completed = subprocess.run(
                [
                    powershell, "-NoProfile", "-NonInteractive", "-File", str(REPOSITORY / "scripts" / "setup.ps1"),
                    "-Repo", str(REPOSITORY), "-RuntimeRoot", str(root / "runtime"),
                    "-KnowledgeMode", "local", "-KnowledgeRoot", str(root / "knowledge"),
                    "-Hosts", "codex-cli", "-HostHome", f"codex-cli={root / 'host'}",
                    "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli",
                    "-PythonExe", str(python_shim), "-SkipVenv", "-CheckOnly", "-NonInteractive", "-Json",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=environment,
                check=False,
            )
            self.assertEqual(completed.returncode, 125, completed.stdout + completed.stderr)
            self.assertIn("NOTIFICATION_TEST_BOOTSTRAP_FAILED", completed.stderr)
            self.assertIn("10106", completed.stderr)
            self.assertNotIn('"status":"CHECK_ONLY"', completed.stdout)
            self.assertFalse((root / "runtime").exists())

    @unittest.skipUnless(sys.platform == "win32", "PowerShell wrapper is Windows-specific")
    def test_isolated_wrapper_check_only_requires_private_child_systemroot(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        python_shim = self.powershell_python_shim()
        environment = self.notification_child_environment()
        host_system_root = os.environ.get("WINDIR")
        self.assertTrue(host_system_root and (Path(host_system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").is_file())
        environment["SystemRoot"] = str(Path(host_system_root).resolve())
        trace_path = Path(environment["EI_TEST_NOTIFICATION_ROOT"]) / "python-shim-argv.json"
        environment["EI_TEST_PYTHON_SHIM_TRACE"] = str(trace_path)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            knowledge = root / "knowledge"
            host_home = root / "host"
            completed = subprocess.run(
                [
                    powershell, "-NoProfile", "-NonInteractive", "-File", str(REPOSITORY / "scripts" / "setup.ps1"),
                    "-Repo", str(REPOSITORY), "-RuntimeRoot", str(runtime),
                    "-KnowledgeMode", "local", "-KnowledgeRoot", str(knowledge),
                    "-Hosts", "codex-cli", "-HostHome", f"codex-cli={host_home}",
                    "-OrganizerProvider", "subscription-cli", "-OrganizerHost", "codex-cli",
                    "-PythonExe", str(python_shim), "-SkipVenv", "-CheckOnly", "-NonInteractive", "-Json",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=environment,
                check=False,
            )
            if is_powershell_execution_policy_refusal(completed.stdout, completed.stderr):
                self.skipTest("PowerShell execution policy refused setup.ps1; private-root wrapper evidence remains unverified on this host")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "CHECK_ONLY")
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            raw_arguments = trace["rawArguments"]
            forwarded_arguments = trace["forwardedArguments"]
            self.assertEqual(raw_arguments.count("--python-exe"), 1, raw_arguments)
            raw_python_index = raw_arguments.index("--python-exe")
            self.assertEqual(raw_arguments[raw_python_index + 1], str(python_shim.resolve()))
            self.assertEqual(forwarded_arguments.count("--python-exe"), 1, forwarded_arguments)
            self.assertEqual(forwarded_arguments[:5], raw_arguments[:5])
            self.assertIn("sitecustomize", forwarded_arguments[5])
            self.assertEqual(forwarded_arguments[6], raw_arguments[5])
            raw_cli_arguments = raw_arguments[6:]
            forwarded_cli_arguments = forwarded_arguments[7:]
            self.assertEqual(raw_cli_arguments.count("--python-exe"), 1, raw_cli_arguments)
            mapped_python_index = forwarded_cli_arguments.index("--python-exe")
            raw_cli_python_index = raw_cli_arguments.index("--python-exe")
            self.assertEqual(forwarded_cli_arguments[mapped_python_index + 1], str(Path(sys.executable).resolve()))
            restored_arguments = list(forwarded_cli_arguments)
            restored_arguments[mapped_python_index + 1] = raw_cli_arguments[raw_cli_python_index + 1]
            self.assertEqual(restored_arguments, raw_cli_arguments)
            self.assertFalse(runtime.exists())
            self.assertFalse(knowledge.exists())
            self.assertFalse(host_home.exists())
            self.assertFalse((Path(environment["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk").exists())
            self.assertFalse((Path(environment["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json").exists())

    @unittest.skipUnless(sys.platform == "win32", "PowerShell shim is Windows-specific")
    def test_powershell_python_shim_rejects_unknown_argv_and_returns_its_own_path(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        shim = self.powershell_python_shim()
        environment = self.notification_child_environment()
        host_system_root = os.environ.get("WINDIR")
        self.assertTrue(host_system_root and (Path(host_system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").is_file())
        environment["SystemRoot"] = str(Path(host_system_root).resolve())
        probe = "import sys,venv,ensurepip; sys.exit(1) if sys.version_info < (3,11) else None; print(sys.executable)"
        verified = subprocess.run(
            [powershell, "-NoProfile", "-File", str(shim), "-I", "-B", "-c", probe],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(Path(verified.stdout.strip()).resolve(), shim.resolve())
        shim_literal = shim.as_posix().replace("'", "''")
        probe_literal = probe.replace("'", "''")
        nested = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-Command",
                f"$outerSystemRoot = $env:SystemRoot; $resolved = & '{shim_literal}' -I -B -c '{probe_literal}'; $probeExit = $LASTEXITCODE; Write-Output ('EI_TEST_PROBE_RESULT=' + $resolved); Write-Output ('EI_TEST_PROBE_EXIT=' + $probeExit); Write-Output ('EI_TEST_OUTER_SYSTEMROOT_RESTORED=' + [string]::Equals($env:SystemRoot, $outerSystemRoot, [StringComparison]::OrdinalIgnoreCase))",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(nested.returncode, 0, nested.stdout + nested.stderr)
        self.assertIn(f"EI_TEST_PROBE_RESULT={shim}", nested.stdout)
        self.assertIn("EI_TEST_PROBE_EXIT=0", nested.stdout)
        self.assertIn("EI_TEST_OUTER_SYSTEMROOT_RESTORED=True", nested.stdout)
        rejected = subprocess.run(
            [powershell, "-NoProfile", "-File", str(shim), "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(rejected.returncode, 64, rejected.stdout + rejected.stderr)
        self.assertIn("EI_TEST_PYTHON_SHIM_ARGV_INVALID", rejected.stderr)
        mismatched = dict(environment)
        mismatched["EI_TEST_NOTIFICATION_PRIVATE_SYSTEM_ROOT"] = str(Path(environment["EI_TEST_NOTIFICATION_ROOT"]) / "not-windows")
        private_rejected = subprocess.run(
            [powershell, "-NoProfile", "-File", str(shim), "-I", "-B", "-c", probe],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=mismatched,
            check=False,
        )
        self.assertEqual(private_rejected.returncode, 125, private_rejected.stdout + private_rejected.stderr)
        self.assertIn("EI_TEST_PYTHON_SHIM_PRIVATE_SYSTEMROOT_INVALID", private_rejected.stderr)
        self.assertNotIn("EI_TEST_PROBE", private_rejected.stdout)
        private_root = Path(environment["EI_TEST_NOTIFICATION_ROOT"])
        setup_prefix = [
            "-I", "-B", "-X", "utf8", "-c",
            "import runpy,sys;source=sys.argv.pop(1);sys.path.insert(0,source);runpy.run_module('ei.installer',run_name='__main__')",
            str(REPOSITORY / "src"), "--setup",
        ]
        valid_setup_tail = [
            "--privacy-profile", "private-reusable", "--skill-mode", "copy",
            "--repo", str(REPOSITORY), "--knowledge-mode", "local",
            "--knowledge-root", str(private_root / "known"),
            "--runtime-root", str(private_root / "runtime"),
            "--hosts", "codex-cli", "--host-home", f"codex-cli={private_root / 'host'}",
            "--organizer-provider", "subscription-cli", "--organizer-host", "codex-cli",
            "--skip-venv", "--check-only", "--non-interactive", "--json",
        ]
        malformed_setup_arguments = (
            ("missing", setup_prefix + valid_setup_tail),
            ("duplicate", setup_prefix + ["--python-exe", str(shim.resolve()), "--python-exe", str(shim.resolve())] + valid_setup_tail),
            ("mismatched", setup_prefix + ["--python-exe", sys.executable] + valid_setup_tail),
            ("unknown", setup_prefix + ["--python-exe", str(shim.resolve())] + valid_setup_tail + ["--unexpected-test-option"]),
        )
        for case, arguments in malformed_setup_arguments:
            with self.subTest(case=case):
                case_environment = dict(environment)
                case_trace = private_root / f"invalid-{case}-argv.json"
                case_environment["EI_TEST_PYTHON_SHIM_TRACE"] = str(case_trace)
                malformed = subprocess.run(
                    [powershell, "-NoProfile", "-NonInteractive", "-File", str(shim), *arguments],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    env=case_environment,
                    check=False,
                )
                self.assertEqual(malformed.returncode, 64, malformed.stdout + malformed.stderr)
                self.assertIn("EI_TEST_PYTHON_SHIM_ARGV_INVALID", malformed.stderr)
                self.assertFalse(case_trace.exists())

        missing_manifest = private_root / "missing-uninstall-manifest.json"
        uninstall_arguments = [
            "-B", "-m", "ei.installer", "--uninstall", "--manifest", str(missing_manifest),
            "--python-exe", str(shim.resolve()), "--json",
        ]
        trace_path = private_root / "python-shim-argv.json"
        environment["EI_TEST_PYTHON_SHIM_TRACE"] = str(trace_path)
        uninstall = subprocess.run(
            [powershell, "-NoProfile", "-File", str(shim), *uninstall_arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(uninstall.returncode, 6, uninstall.stdout + uninstall.stderr)
        self.assertIn("FileNotFoundError", uninstall.stdout + uninstall.stderr)
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        raw_arguments = trace["rawArguments"]
        forwarded_arguments = trace["forwardedArguments"]
        self.assertEqual(raw_arguments.count("--python-exe"), 1, raw_arguments)
        raw_python_index = raw_arguments.index("--python-exe")
        self.assertEqual(raw_arguments[raw_python_index + 1], str(shim.resolve()))
        self.assertEqual(forwarded_arguments.count("--python-exe"), 1, forwarded_arguments)
        mapped_python_index = forwarded_arguments.index("--python-exe")
        self.assertEqual(forwarded_arguments[mapped_python_index + 1], str(Path(sys.executable).resolve()))
        restored_arguments = list(forwarded_arguments)
        restored_arguments[mapped_python_index + 1] = raw_arguments[raw_python_index + 1]
        self.assertEqual(restored_arguments, raw_arguments)
        uninstall_unknown = subprocess.run(
            [powershell, "-NoProfile", "-File", str(shim), *uninstall_arguments, "--unexpected-test-option"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(uninstall_unknown.returncode, 64, uninstall_unknown.stdout + uninstall_unknown.stderr)
        self.assertIn("EI_TEST_PYTHON_SHIM_ARGV_INVALID", uninstall_unknown.stderr)

    def test_isolated_python_interpreter_installs_guard_before_engine_bootstrap(self) -> None:
        python_exe = self.isolated_python_executable()
        environment = self.notification_child_environment()
        code = (
            "import subprocess,sys\n"
            "print('EI_TEST_GUARD=' + str(getattr(subprocess.run, '_ei_notification_isolation', False)))\n"
            "print('EI_TEST_ISOLATED=' + str(sys.flags.isolated))\n"
        )
        result = subprocess.run(
            [str(python_exe), "-I", "-B", "-c", code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["EI_TEST_GUARD=True", "EI_TEST_ISOLATED=1"])

    def test_powershell_wrapper_forwards_operation_flags_and_exit_status(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo with spaces"
            (repo / "src").mkdir(parents=True)
            capture = root / "captured args.txt"
            fake_python = root / "fake python.cmd"
            fake_python.write_text(
                "@echo off\r\n"
                'if "%~3"=="-c" (echo %~f0& exit /b 0)\r\n'
                'echo %*>>"%EI_SETUP_CAPTURE%"\r\n'
                "exit /b 23\r\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["EI_SETUP_CAPTURE"] = str(capture)
            completed = subprocess.run(
                [
                    powershell, "-NoProfile", "-NonInteractive", "-File",
                    str(REPOSITORY / "scripts" / "setup.ps1"),
                    "-Repo", str(repo), "-PythonExe", str(fake_python),
                    "-CheckOnly", "-NonInteractive", "-VerifyOperation",
                    "-AllowModelTest", "-AllowNotificationTest", "-Json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
                check=False,
            )
            self.assertEqual(completed.returncode, 23, completed.stdout + completed.stderr)
            forwarded = capture.read_text(encoding="utf-8")
            for flag in (
                "--check-only", "--verify-operation", "--allow-model-test", "--allow-notification-test",
            ):
                self.assertIn(flag, forwarded)

    def test_shell_wrapper_forwards_flags_exit_status_and_rejects_unknown_options(self) -> None:
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX sh is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "captured args.txt"
            fake_python = root / "fake-python"
            fake_python.write_text(
                "#!/bin/sh\n"
                'if [ "$3" = "-c" ]; then printf \'%s\\n\' "$0"; exit 0; fi\n'
                'printf \'%s\\n\' "$*" >> "$EI_SETUP_CAPTURE"\n'
                "exit 23\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = dict(os.environ)
            environment["EI_SETUP_CAPTURE"] = str(capture)
            wrapper = str(REPOSITORY / "scripts" / "setup.sh")
            common = [
                shell, wrapper, "--repo", str(REPOSITORY), "--python-exe", str(fake_python),
                "--check-only", "--non-interactive", "--verify-operation",
                "--allow-model-test", "--allow-notification-test",
            ]
            completed = subprocess.run(common, capture_output=True, text=True, timeout=30, env=environment, check=False)
            self.assertEqual(completed.returncode, 23, completed.stdout + completed.stderr)
            forwarded = capture.read_text(encoding="utf-8")
            for flag in (
                "--check-only", "--verify-operation", "--allow-model-test", "--allow-notification-test",
            ):
                self.assertIn(flag, forwarded)
            rejected = subprocess.run(
                [shell, wrapper, "--unknown-option"], capture_output=True, text=True, timeout=30,
                env=environment, check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("unknown option", rejected.stderr)

    @unittest.skipUnless(sys.platform == "win32", "managed PROPVARIANT ABI check requires Windows PowerShell")
    def test_propvariant_managed_layout_matches_native_pointer_width_without_com(self) -> None:
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        helper = (REPOSITORY / "scripts" / "notifications" / "register-windows-notification.ps1").as_posix().replace("'", "''")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = (
                "$ErrorActionPreference = 'Stop'\n"
                "$tokens = $null; $parseErrors = $null\n"
                f"$ast = [System.Management.Automation.Language.Parser]::ParseFile('{helper}', [ref]$tokens, [ref]$parseErrors)\n"
                "if ($parseErrors.Count -ne 0) { throw 'HELPER_SOURCE_PARSE_FAILED' }\n"
                "$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-EiShellLinkInteropSource' }, $true)\n"
                "if (-not $function) { throw 'INTEROP_SOURCE_FUNCTION_NOT_FOUND' }\n"
                "Invoke-Expression $function.Extent.Text\n"
                "$source = Get-EiShellLinkInteropSource\n"
                "Add-Type -TypeDefinition $source -ErrorAction Stop\n"
                "$variant = New-Object 'EIWinNotify.PropVariant'\n"
                "$size = [Runtime.InteropServices.Marshal]::SizeOf($variant)\n"
                "$variantType = $variant.GetType()\n"
                "$pointerOffset = [Runtime.InteropServices.Marshal]::OffsetOf($variantType, 'pointer').ToInt64()\n"
                "$pointerSize = [IntPtr]::Size\n"
                "$expectedSize = if ($pointerSize -eq 8) { 24 } else { 16 }\n"
                "if ($size -ne $expectedSize) { [Console]::Out.WriteLine(\"PROPVARIANT_ABI_SIZE_UNEXPECTED expected=$expectedSize observed=$size pointer=$pointerSize\"); exit 41 }\n"
                "$countOffset = [Runtime.InteropServices.Marshal]::OffsetOf($variantType, 'arrayCount').ToInt64()\n"
                "$arrayOffset = [Runtime.InteropServices.Marshal]::OffsetOf($variantType, 'arrayPointer').ToInt64()\n"
                "$expectedArrayOffset = if ($pointerSize -eq 8) { 16 } else { 12 }\n"
                "if ($pointerOffset -ne 8 -or $countOffset -ne 8 -or $arrayOffset -ne $expectedArrayOffset) { throw 'PROPVARIANT_ABI_OFFSETS_UNEXPECTED' }\n"
                "Write-Output ('PROCESS_BITS=' + ($pointerSize * 8))\n"
                "Write-Output ('PROPVARIANT_SIZE=' + $size)\n"
                "Write-Output ('ARRAY_POINTER_OFFSET=' + $arrayOffset)\n"
            )
            environment = self.notification_child_environment()
            environment["SystemRoot"] = os.environ.get("WINDIR", os.environ["SystemRoot"])
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", harness],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pointer_size = 8 if "PROCESS_BITS=64" in result.stdout else 4
            expected_size = 24 if pointer_size == 8 else 16
            self.assertIn(f"PROPVARIANT_SIZE={expected_size}", result.stdout)
            self.assertIn(f"ARRAY_POINTER_OFFSET={16 if pointer_size == 8 else 12}", result.stdout)


if __name__ == "__main__":
    unittest.main()
