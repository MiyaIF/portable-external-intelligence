import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings
import ei.operation_activation as operation_activation


class OperationActivationTests(unittest.TestCase):
    def test_api_acceptance_is_not_display_confirmation(self):
        evidence = dict(binding="VERIFIED", hook="VERIFIED", accumulation="VERIFIED",
                        recall="VERIFIED", scheduler_run="VERIFIED", scheduler_monitor="VERIFIED",
                        notification_send="SENT",
                        notification_display="UNVERIFIED", scheduler_requested=True)
        self.assertEqual(operation_activation.activation_readiness(evidence), "UNVERIFIED")
        evidence["notification_display"] = "VERIFIED"
        self.assertEqual(operation_activation.activation_readiness(evidence), "VERIFIED")

    def test_unrequested_scheduler_is_disabled(self):
        evidence = dict(binding="VERIFIED", hook="VERIFIED", accumulation="VERIFIED",
                        recall="VERIFIED", scheduler_run="VERIFIED", scheduler_monitor="VERIFIED",
                        notification_display="VERIFIED", scheduler_requested=False)
        self.assertEqual(operation_activation.activation_readiness(evidence), "DISABLED")

    def test_scheduler_request_requires_an_exact_boolean(self):
        evidence = dict(binding="VERIFIED", hook="VERIFIED", accumulation="VERIFIED",
                        recall="VERIFIED", scheduler_run="VERIFIED", scheduler_monitor="VERIFIED",
                        notification_display="VERIFIED", scheduler_requested=0)
        self.assertEqual(operation_activation.activation_readiness(evidence), "UNVERIFIED")

    def test_each_work_host_must_have_its_own_verified_binding_and_hook(self):
        evidence = dict(
            hosts={
                "codex-cli": {"binding": "VERIFIED", "hook": "VERIFIED", "accumulation": "VERIFIED", "recall": "VERIFIED"},
                "claude-code": {"binding": "VERIFIED", "hook": "UNVERIFIED", "accumulation": "VERIFIED", "recall": "VERIFIED"},
            },
            scheduler_run="VERIFIED", scheduler_monitor="VERIFIED",
            notification_display="VERIFIED", scheduler_requested=True,
        )
        self.assertEqual(operation_activation.activation_readiness(evidence), "UNVERIFIED")

    def _settings(self, root: Path) -> Settings:
        return Settings(paths=RuntimePaths(
            engine_root=root / "engine",
            knowledge_root=root / "knowledge",
            runtime_root=root / "runtime",
        ))

    def _load_evidence(self, settings: Settings):
        loader = getattr(operation_activation, "load_operation_evidence", None)
        self.assertTrue(callable(loader), "validated evidence loader is required")
        return loader(settings)

    def _ensure_state(self, settings: Settings):
        ensure = getattr(operation_activation, "ensure_operation_state", None)
        self.assertTrue(callable(ensure), "non-destructive operation-state initialization is required")
        return ensure(settings)

    def _state(self, *, evidence=None, notifications=True, allow_model=False, allow_notification=False):
        return {
            "schema_version": 1,
            "settings": {
                "notifications": {"enabled": notifications, "channel": "os"},
                "initial_test": {"allow_model_test": allow_model, "allow_notification_test": allow_notification},
            },
            "evidence": {} if evidence is None else evidence,
        }

    def test_missing_evidence_file_is_unverified_without_creating_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            self.assertEqual(self._load_evidence(settings), {})
            self.assertFalse((root / "runtime" / "automatic-operation.json").exists())

    def test_malformed_and_oversized_operation_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.runtime_dir.mkdir(parents=True)
            target = settings.paths.runtime_dir / "automatic-operation.json"
            for raw in (b"{", b" " * 65537):
                with self.subTest(size=len(raw)):
                    target.write_bytes(raw)
                    self.assertEqual(self._load_evidence(settings), {})

    def test_invalid_boolean_settings_are_rejected_without_truthiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.runtime_dir.mkdir(parents=True)
            target = settings.paths.runtime_dir / "automatic-operation.json"
            for section, key, invalid in (("notifications", "enabled", 1), ("initial_test", "allow_model_test", "false")):
                with self.subTest(section=section, key=key):
                    document = self._state()
                    document["settings"][section][key] = invalid
                    target.write_text(json.dumps(document), encoding="utf-8")
                    self.assertEqual(self._load_evidence(settings), {})

    def test_prompt_and_credential_fields_are_not_accepted_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.runtime_dir.mkdir(parents=True)
            target = settings.paths.runtime_dir / "automatic-operation.json"
            document = self._state(evidence={"prompt": "private test body", "api_key": "secret"})
            target.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(self._load_evidence(settings), {})

    def test_initial_state_separates_daily_notifications_from_test_consents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, reason = self._ensure_state(self._settings(root))
            self.assertIsNone(reason)
            self.assertEqual(state, {
                "schema_version": 1,
                "settings": {
                    "notifications": {"enabled": True, "channel": "os"},
                    "initial_test": {"allow_model_test": False, "allow_notification_test": False},
                },
                "evidence": {},
            })
            self.assertLessEqual((root / "runtime" / "automatic-operation.json").stat().st_size, 65536)

    def test_schema_is_closed_and_keeps_scheduler_selection_out_of_operation_settings(self):
        schema_path = Path(__file__).resolve().parents[2] / "schemas" / "operation-activation.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        settings = schema["properties"]["settings"]["properties"]
        self.assertNotIn("scheduler_requested", settings)
        self.assertEqual(set(settings["notifications"]["properties"]), {"enabled", "channel"})
        self.assertEqual(set(settings["initial_test"]["properties"]), {"allow_model_test", "allow_notification_test"})

    def test_verify_operation_without_consents_does_not_attempt_native_test(self):
        from ei.operation_activation import verify_operation

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            with patch("ei.operation_activation._invoke_isolated_host_test", side_effect=AssertionError("model test must be consented")), patch(
                "ei.operation_activation.send_native_notification", side_effect=AssertionError("notification test must be consented")
            ):
                result = verify_operation(settings, allow_model_test=False, allow_notification_test=False)
            self.assertEqual(
                set(result),
                {"automatic_operation", "notification_send", "reason_codes", "evidence"},
            )
            self.assertEqual(result["automatic_operation"], "UNVERIFIED")
            self.assertEqual(result["notification_send"], "NOT_ATTEMPTED")
            self.assertIn("OPERATION_TEST_CONSENT_REQUIRED", result["reason_codes"])
            state = json.loads((settings.paths.runtime_root / "automatic-operation.json").read_text(encoding="utf-8"))
            self.assertFalse(state["settings"]["initial_test"]["allow_model_test"])
            self.assertFalse(state["settings"]["initial_test"]["allow_notification_test"])

    def test_notification_send_acceptance_is_not_display_confirmation_and_confirmation_is_one_shot(self):
        from ei.notifications.base import DeliveryResult
        from ei.operation_activation import verify_operation

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            with patch("ei.operation_activation.send_native_notification", return_value=DeliveryResult("SENT", "OS_ACCEPTED")) as sender:
                sent = verify_operation(settings, allow_model_test=False, allow_notification_test=True)
                self.assertEqual(sent["evidence"]["notification"]["send"], "SENT")
                self.assertEqual(sent["evidence"]["notification"]["display"], "UNVERIFIED")
                self.assertEqual(sent["notification_send"], "SENT")
                confirmed = verify_operation(settings, allow_model_test=False, allow_notification_test=False, confirmed_notification_seen=True)
            self.assertEqual(sender.call_count, 1)
            self.assertEqual(confirmed["notification_send"], "NOT_ATTEMPTED")
            self.assertEqual(confirmed["evidence"]["notification"]["send"], "SENT")
            self.assertEqual(confirmed["evidence"]["notification"]["display"], "VERIFIED")
            self.assertEqual(confirmed["evidence"]["notification"]["observation"], "USER_CONFIRMED_DISPLAY")

    def test_invalid_state_returns_without_overwriting_or_sending(self):
        from ei.operation_activation import verify_operation

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            settings.paths.runtime_root.mkdir(parents=True)
            target = settings.paths.runtime_root / "automatic-operation.json"
            target.write_bytes(b"{invalid")
            with patch("ei.operation_activation.send_native_notification", side_effect=AssertionError("must not send")):
                result = verify_operation(settings, allow_model_test=False, allow_notification_test=True)
            self.assertEqual(result, {
                "automatic_operation": "UNVERIFIED",
                "notification_send": "NOT_ATTEMPTED",
                "reason_codes": ["OPERATION_STATE_INVALID"],
                "evidence": {},
            })
            self.assertEqual(target.read_bytes(), b"{invalid")

    def test_explicit_model_test_without_isolation_remains_unverified(self):
        from ei.operation_activation import verify_operation
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            certification = SimpleNamespace(status="PASSED", real_evidence=True, receipt={"host_version": "1.2.3"})
            hook = SimpleNamespace(static_checks={"valid": True})
            with patch("ei.operation_activation._configured_work_hosts", return_value=("codex-cli",)), patch(
                "ei.certification.certify_host", return_value=certification
            ) as certify, patch("ei.canary.read_hook_status", return_value=hook), patch(
                "ei.operation_activation._invoke_isolated_host_test", return_value={"status": "UNVERIFIED", "reason_code": "ISOLATION_UNAVAILABLE"}
            ) as driver:
                result = verify_operation(settings, allow_model_test=True, allow_notification_test=False)
            self.assertEqual(result["automatic_operation"], "UNVERIFIED")
            self.assertIn("ISOLATION_UNAVAILABLE", result["reason_codes"])
            self.assertEqual(driver.call_count, 1)
            certify.assert_called_once_with(
                "codex-cli", "codex-cli", "real", settings, allow_version_probe=False
            )

    def test_retained_end_to_end_and_display_evidence_are_reported_without_retesting(self):
        from types import SimpleNamespace
        from ei.operation_activation import verify_operation

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            engine_hash = "sha256:" + "a" * 64
            binding_hash = "sha256:" + "b" * 64
            now = "2026-09-24T00:00:00Z"
            host_evidence = {
                "binding": "VERIFIED", "hook": "VERIFIED", "accumulation": "VERIFIED", "recall": "VERIFIED",
                "host_version": "1.2.3", "engine_code_sha256": engine_hash, "binding_sha256": binding_hash,
                "os_family": "Windows", "os_version": "test", "channel": "work-cli",
                "tested_at": now, "observation": "SYNTHETIC_END_TO_END",
                "candidate_ref_sha256": engine_hash, "event_ref_sha256": binding_hash, "recall_ref_sha256": engine_hash,
            }
            notification_evidence = {
                "send": "SENT", "display": "VERIFIED", "channel": "os",
                "os_family": "Windows", "os_version": "test", "tested_at": now,
                "observation": "USER_CONFIRMED_DISPLAY", "test_ref_sha256": engine_hash,
            }
            state = self._state(evidence={
                "hosts": {"codex-cli": host_evidence}, "notification": notification_evidence,
            })
            settings.paths.runtime_dir.mkdir(parents=True)
            (settings.paths.runtime_dir / "automatic-operation.json").write_text(json.dumps(state), encoding="utf-8")
            certification = SimpleNamespace(status="PASSED", real_evidence=True, receipt={"host_version": "1.2.3"})
            hook = SimpleNamespace(static_checks={"valid": True})
            with patch("ei.operation_activation._engine_code_digest", return_value=engine_hash), patch(
                "ei.operation_activation._read_install_manifest", return_value={"scheduler_requested": False, "work_hosts": ["codex-cli"]}
            ), patch("ei.operation_activation._configured_work_hosts", return_value=("codex-cli",)), patch(
                "ei.operation_activation._os_identity", return_value=("Windows", "test")
            ), patch("ei.operation_activation._binding_digest", return_value=binding_hash), patch(
                "ei.certification.certify_host", return_value=certification
            ), patch("ei.canary.read_hook_status", return_value=hook), patch(
                "ei.operation_activation._invoke_isolated_host_test", side_effect=AssertionError("retained end-to-end evidence must not be rerun")
            ), patch(
                "ei.operation_activation.send_native_notification", side_effect=AssertionError("confirmed display evidence must not resend")
            ):
                result = verify_operation(settings, allow_model_test=True, allow_notification_test=True)

            self.assertIn("SYNTHETIC_END_TO_END_EVIDENCE_RETAINED", result["reason_codes"])
            self.assertIn("NOTIFICATION_DISPLAY_EVIDENCE_RETAINED", result["reason_codes"])
            self.assertEqual(result["evidence"]["hosts"]["codex-cli"]["observation"], "SYNTHETIC_END_TO_END")
            self.assertEqual(result["evidence"]["notification"]["display"], "VERIFIED")

    def test_hook_static_receipt_read_failure_is_exposed_in_reason_codes(self):
        from types import SimpleNamespace
        from ei.operation_activation import verify_operation

        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            certification = SimpleNamespace(status="PASSED", real_evidence=True, receipt={"host_version": "1.2.3"})
            with patch("ei.operation_activation._read_install_manifest", return_value={"scheduler_requested": False, "work_hosts": ["codex-cli"]}), patch(
                "ei.operation_activation._configured_work_hosts", return_value=("codex-cli",)
            ), patch("ei.certification.certify_host", return_value=certification), patch(
                "ei.canary.read_hook_status", side_effect=OSError("receipt unavailable")
            ):
                result = verify_operation(settings, allow_model_test=False, allow_notification_test=False)

            self.assertIn("HOOK_STATIC_CHECK_UNAVAILABLE", result["reason_codes"])
            self.assertEqual(result["evidence"]["hosts"]["codex-cli"]["binding"], "UNVERIFIED")

    def test_existing_disabled_settings_and_evidence_are_preserved_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.runtime_dir.mkdir(parents=True)
            target = settings.paths.runtime_dir / "automatic-operation.json"
            document = self._state(evidence={}, notifications=False, allow_model=False, allow_notification=False)
            raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
            target.write_bytes(raw)
            state, reason = self._ensure_state(settings)
            self.assertIsNone(reason)
            self.assertEqual(state, document)
            self.assertEqual(target.read_bytes(), raw)

    def test_invalid_existing_state_is_retained_for_manual_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.runtime_dir.mkdir(parents=True)
            target = settings.paths.runtime_dir / "automatic-operation.json"
            raw = b"{invalid"
            target.write_bytes(raw)
            state, reason = self._ensure_state(settings)
            self.assertIsNone(state)
            self.assertEqual(reason, "OPERATION_STATE_INVALID")
            self.assertEqual(target.read_bytes(), raw)

    def _verified_evidence(self):
        first_hash = "sha256:" + "a" * 64
        second_hash = "sha256:" + "b" * 64
        return {
            "hosts": {
                "codex-cli": {
                    "binding": "VERIFIED", "hook": "VERIFIED", "accumulation": "VERIFIED", "recall": "VERIFIED",
                    "host_version": "1.2.3", "engine_code_sha256": first_hash, "binding_sha256": first_hash,
                    "os_family": "Linux", "os_version": "test", "channel": "work-cli",
                    "tested_at": "2026-09-24T00:00:00Z", "observation": "SYNTHETIC_END_TO_END",
                    "candidate_ref_sha256": first_hash, "event_ref_sha256": second_hash, "recall_ref_sha256": first_hash,
                },
                "claude-code": {
                    "binding": "VERIFIED", "hook": "VERIFIED", "accumulation": "VERIFIED", "recall": "VERIFIED",
                    "host_version": "2.0.0", "engine_code_sha256": first_hash, "binding_sha256": second_hash,
                    "os_family": "Linux", "os_version": "test", "channel": "work-cli",
                    "tested_at": "2026-09-24T00:00:00Z", "observation": "SYNTHETIC_END_TO_END",
                    "candidate_ref_sha256": first_hash, "event_ref_sha256": second_hash, "recall_ref_sha256": first_hash,
                },
            },
            "scheduler": {
                "run": "VERIFIED", "monitor": "UNVERIFIED", "engine_code_sha256": first_hash,
                "binding_sha256": second_hash, "os_family": "Linux", "os_version": "test",
                "tested_at": "2026-09-24T00:00:00Z", "observation": "SCHEDULER_MONITOR_UNSUPPORTED",
            },
            "notification": {
                "send": "SENT", "display": "UNVERIFIED", "channel": "os", "os_family": "Linux",
                "os_version": "test", "tested_at": "2026-09-24T00:00:00Z", "observation": "OS_SEND_ACCEPTED",
                "test_ref_sha256": first_hash,
            },
        }

    def _invalidate(self, evidence, current_binding):
        invalidate = getattr(operation_activation, "invalidate_operation_evidence", None)
        self.assertTrue(callable(invalidate), "selective evidence invalidation is required")
        return invalidate(evidence, current_binding)

    def test_binding_change_invalidates_only_the_affected_host(self):
        evidence = self._verified_evidence()
        unchanged = json.loads(json.dumps(evidence))
        changed_hash = "sha256:" + "c" * 64
        current = {
            "engine_code_sha256": "sha256:" + "a" * 64,
            "os_family": "Linux", "os_version": "test", "notification_channel": "os",
            "scheduler_binding_sha256": "sha256:" + "b" * 64,
            "hosts": {
                "codex-cli": {"binding_sha256": changed_hash, "host_version": "1.2.3", "channel": "work-cli"},
                "claude-code": {"binding_sha256": "sha256:" + "b" * 64, "host_version": "2.0.0", "channel": "work-cli"},
            },
        }
        result = self._invalidate(evidence, current)
        self.assertEqual(result["hosts"]["codex-cli"]["binding"], "UNVERIFIED")
        self.assertEqual(result["hosts"]["codex-cli"]["recall"], "UNVERIFIED")
        self.assertEqual(result["hosts"]["claude-code"], unchanged["hosts"]["claude-code"])
        self.assertEqual(result["scheduler"], unchanged["scheduler"])
        self.assertEqual(result["notification"], unchanged["notification"])
        self.assertEqual(evidence, unchanged)

    def test_notification_channel_change_invalidates_only_display_evidence(self):
        evidence = self._verified_evidence()
        current = {
            "engine_code_sha256": "sha256:" + "a" * 64,
            "os_family": "Linux", "os_version": "test", "notification_channel": "none",
            "scheduler_binding_sha256": "sha256:" + "b" * 64,
            "hosts": {
                "codex-cli": {"binding_sha256": "sha256:" + "a" * 64, "host_version": "1.2.3", "channel": "work-cli"},
                "claude-code": {"binding_sha256": "sha256:" + "b" * 64, "host_version": "2.0.0", "channel": "work-cli"},
            },
        }
        result = self._invalidate(evidence, current)
        self.assertEqual(result["notification"]["display"], "UNVERIFIED")
        self.assertEqual(result["notification"]["send"], "UNVERIFIED")
        self.assertEqual(result["hosts"], evidence["hosts"])
        self.assertEqual(result["scheduler"], evidence["scheduler"])

    def test_host_version_change_preserves_binding_but_invalidates_runtime_behavior(self):
        evidence = self._verified_evidence()
        current = {
            "engine_code_sha256": "sha256:" + "a" * 64,
            "os_family": "Linux", "os_version": "test", "notification_channel": "os",
            "scheduler_binding_sha256": "sha256:" + "b" * 64,
            "hosts": {
                "codex-cli": {"binding_sha256": "sha256:" + "a" * 64, "host_version": "1.2.4", "channel": "work-cli"},
                "claude-code": {"binding_sha256": "sha256:" + "b" * 64, "host_version": "2.0.0", "channel": "work-cli"},
            },
        }
        result = self._invalidate(evidence, current)
        self.assertEqual(result["hosts"]["codex-cli"]["binding"], "VERIFIED")
        self.assertEqual(result["hosts"]["codex-cli"]["hook"], "UNVERIFIED")
        self.assertEqual(result["hosts"]["codex-cli"]["accumulation"], "UNVERIFIED")
        self.assertEqual(result["hosts"]["claude-code"], evidence["hosts"]["claude-code"])


if __name__ == "__main__":
    unittest.main()
