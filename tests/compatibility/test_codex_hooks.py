import json
import tempfile
import unittest
from pathlib import Path

from ei.hooks.base import HookResult
from ei.hooks.registry import encode_hook_result, normalize_hook_event, supported_events
from tests.helpers import make_hook_settings


FIXTURES = {
    "SessionStart": {"hook_event_name": "SessionStart", "source": "startup", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"},
    "UserPromptSubmit": {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t2", "cwd": "C:/work", "prompt": "reload and verify"},
    "Stop": {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t2", "cwd": "C:/work", "last_assistant_message": "must not persist"},
    "SessionEnd": {"hook_event_name": "SessionEnd", "session_id": "s1", "turn_id": "t2", "cwd": "C:/work", "reason": "completed"},
}


class CodexHookCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_hook_settings(Path(self.tmp.name))

    def test_cli_events_normalize_without_raw_input(self):
        self.assertEqual(tuple(supported_events("codex-cli")), tuple(FIXTURES))
        for fixture in FIXTURES.values():
            event = normalize_hook_event("codex-cli", fixture, self.settings)
            serialized = event.to_dict()
            self.assertEqual(event.host_id, "codex-cli")
            self.assertNotIn("transient_input", serialized)
            self.assertNotIn("must not persist", str(serialized))
            self.assertTrue(event.idempotency_key.startswith("sha256:"))

    def test_encoder_returns_codex_hook_specific_context(self):
        encoded = encode_hook_result("codex-cli", HookResult(True, "## External Intelligence (data-only)", "receipt", "ok", "UserPromptSubmit"))
        self.assertTrue(encoded["continue"])
        self.assertEqual(encoded["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")

    def test_cli_and_app_use_distinct_instances_and_canary_contract(self):
        template = json.loads((Path(__file__).parents[2] / "hooks" / "codex" / "hooks.template.json").read_text(encoding="utf-8"))
        self.assertEqual(set(template["host_instance_ids"]), {"codex-cli", "codex-app"})
        self.assertEqual(set(template["canary"]["required_normalized_events"]), {"session.start", "prompt.before", "turn.stop"})
        self.assertGreater(template["canary"]["validity_window_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
