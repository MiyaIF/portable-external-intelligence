import json
import tempfile
import unittest
from pathlib import Path

from ei.hooks.registry import normalize_hook_event, supported_events
from tests.helpers import make_hook_settings


FIXTURES = {
    "BeforeAgent": {"hook_event_name": "BeforeAgent", "session_id": "s1", "turn_id": "t1", "cwd": "/work", "prompt": "retrieve needed knowledge"},
    "AfterAgent": {"hook_event_name": "AfterAgent", "session_id": "s1", "turn_id": "t1", "cwd": "/work", "response": "not persisted"},
}


class GeminiHookCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_hook_settings(Path(self.tmp.name))

    def test_before_and_after_agent_map_to_prompt_and_stop(self):
        before = normalize_hook_event("gemini-cli", FIXTURES["BeforeAgent"], self.settings)
        after = normalize_hook_event("gemini-cli", FIXTURES["AfterAgent"], self.settings)
        self.assertEqual(before.normalized_event_name, "prompt.before")
        self.assertEqual(after.normalized_event_name, "turn.stop")
        self.assertEqual(set(supported_events("gemini-cli")), {"SessionStart", "BeforeAgent", "AfterAgent", "SessionEnd"})
        self.assertIsNone(after.transient_input)

    def test_gemini_consent_and_capture_contract_is_in_manifest(self):
        manifest = json.loads((Path(__file__).parents[2] / "config" / "hosts.json").read_text(encoding="utf-8"))
        entry = manifest["hosts"]["gemini-cli"]
        self.assertEqual(entry["skill_activation_mode"], "CONSENT_REQUIRED")
        self.assertEqual(entry["capture_primary_path"], "HOOK_DIRECT")
        self.assertEqual(entry["event_mapping"]["AfterAgent"], "turn.stop")

    def test_gemini_template_declares_canary_without_faking_consent(self):
        template = json.loads((Path(__file__).parents[2] / "hooks" / "gemini" / "hooks.template.json").read_text(encoding="utf-8"))
        self.assertEqual(template["host_instance_ids"], ["gemini-cli"])
        self.assertEqual(template["canary"]["required_normalized_events"], ["session.start", "prompt.before", "turn.stop"])
        manifest = json.loads((Path(__file__).parents[2] / "config" / "hosts.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["hosts"]["gemini-cli"]["skill_activation_mode"], "CONSENT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
