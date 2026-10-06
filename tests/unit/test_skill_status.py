import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


class SkillStatusTests(unittest.TestCase):
    def setUp(self):
        scripts = Path(__file__).resolve().parents[2] / "skills/external-intelligence/scripts"
        spec = importlib.util.spec_from_file_location("ei_status_test", scripts / "status.py")
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules), patch.object(sys, "path", [str(scripts), *sys.path]):
            spec.loader.exec_module(self.module)

    def test_queue_summary_requires_health_evidence(self):
        self.assertTrue(hasattr(self.module, "_summarize_queue"), "queue summary is missing")
        healthy = {"corrupt": 0, "needs_attention": 0, "deferred": 0, "retryable": 0,
                   "ready": 0, "in_progress": 0, "emergency_items": 0}
        for field, expected in (("corrupt", "NEEDS_ATTENTION"),
                                ("needs_attention", "NEEDS_ATTENTION"),
                                ("deferred", "DEFERRED"), ("retryable", "DEFERRED"),
                                ("ready", "PENDING"), ("emergency_items", "PENDING"),
                                ("in_progress", "PROCESSING")):
            with self.subTest(field=field):
                check = {"health": {**healthy, field: 1}, "stale_leases": 0}
                self.assertEqual(self.module._summarize_queue(check)["status"], expected)
        self.assertEqual(self.module._summarize_queue({"health": healthy, "stale_leases": 1})["status"], "NEEDS_ATTENTION")
        self.assertEqual(self.module._summarize_queue({"health": healthy, "stale_leases": 0})["status"], "READY")
        for missing in (None, {}, {"health": {}}, {"health": {**healthy, "corrupt": "invalid"}}):
            self.assertEqual(self.module._summarize_queue(missing)["status"], "UNKNOWN")

    def test_nonstrict_doctor_success_does_not_verify_hook(self):
        self.assertTrue(hasattr(self.module, "_summarize_doctor"), "doctor summary is missing")
        report = {"ok": True, "checks": [{"name": "hosts", "hosts": [{
            "host_id": "codex-cli", "hook": {"ok": True, "static": {"valid": True},
            "live": {"hook_status": "HOOK_UNVERIFIED"}}, "skill": {}}]}]}
        result = self.module._summarize_doctor(report)
        self.assertEqual(result["Hook"]["status"], "UNVERIFIED")
        self.assertNotEqual(result["health_status"], "healthy")
        row = report["checks"][0]["hosts"][0]
        row["hook"]["live"]["hook_status"] = "HOOK_VERIFIED"
        self.assertEqual(self.module._summarize_doctor(report)["Hook"]["status"], "VERIFIED")
        report["checks"][0]["hosts"].append({"host_id": "gemini-cli", "hook": {}})
        self.assertNotEqual(self.module._summarize_doctor(report)["Hook"]["status"], "VERIFIED")

    def test_missing_diagnostics_do_not_claim_any_component_healthy(self):
        self.assertTrue(hasattr(self.module, "_summarize_doctor"), "doctor summary is missing")
        result = self.module._summarize_doctor({})
        self.assertEqual(result["health_status"], "unknown")
        self.assertEqual(result["queue"]["status"], "UNKNOWN")
        self.assertEqual(result["spool"]["status"], "UNKNOWN")
        self.assertEqual(result["Skill"]["status"], "UNKNOWN")

    def test_other_doctor_warning_prevents_healthy_even_when_components_pass(self):
        report = {"ok": True, "checks": [
            {"name": "hosts", "hosts": [{"host_id": "codex-cli", "hook": {
                "ok": True, "static": {"valid": True}, "live": {"hook_status": "HOOK_VERIFIED"}},
                "skill": {"ok": True, "binding": {"ok": True}, "source_hash": "a",
                          "installed_hash": "a", "actual_hash": "a"}}]},
            {"name": "queue", "stale_leases": 0, "health": dict.fromkeys(
                ("corrupt", "needs_attention", "deferred", "retryable", "ready", "in_progress", "emergency_items"), 0)},
            {"name": "spool", "health": {}, "invalid_envelopes": 0, "expired_envelopes": 0},
            {"name": "provider", "eligible": 1, "organizer": {"status": "READY"}},
            {"name": "projection", "freshness": "CURRENT"}]}
        self.assertEqual(self.module._summarize_doctor(report)["health_status"], "healthy")
        report["checks"].append({"name": "privacy", "ok": True, "reason_code": "RAW_FIELD_DETECTED"})
        self.assertEqual(self.module._summarize_doctor(report)["health_status"], "degraded")

    def test_malformed_check_container_is_unknown(self):
        for checks in (None, 1, "not-a-report", {}):
            self.assertEqual(self.module._summarize_doctor({"checks": checks})["health_status"], "unknown")

    def test_provider_cap_is_reported_without_hardcoding_a_zero_budget(self):
        result = self.module._summarize_doctor({"checks": [{"name": "provider", "cloud_spend_cap": 7,
            "eligible": 1, "organizer": {"status": "READY"}}]})
        self.assertEqual(result["provider"].get("cloud_spend_cap"), 7)
        self.assertIsNone(self.module._summarize_doctor({})["provider"].get("cloud_spend_cap"))


if __name__ == "__main__":
    unittest.main()
