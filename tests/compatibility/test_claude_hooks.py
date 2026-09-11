import tempfile
import unittest
from pathlib import Path

from ei.hooks.registry import normalize_hook_event, supported_events
from tests.helpers import make_hook_settings


FIXTURES = {"SessionStart": {"hook_event_name": "SessionStart", "session_id": "s1", "turn_id": "t1", "cwd": "/work"}, "UserPromptSubmit": {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t2", "cwd": "/work", "prompt": "再読込"}, "Stop": {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t2", "cwd": "/work"}, "SessionEnd": {"hook_event_name": "SessionEnd", "session_id": "s1", "turn_id": "t2", "cwd": "/work"}}


class ClaudeHookCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_hook_settings(Path(self.tmp.name))

    def test_claude_event_set_and_normalization(self):
        self.assertEqual(set(supported_events("claude-code")), set(FIXTURES))
        event = normalize_hook_event("claude-code", FIXTURES["UserPromptSubmit"], self.settings)
        self.assertEqual(event.normalized_event_name, "prompt.before")
        self.assertEqual(event.host_id, "claude-code")
        self.assertIsNotNone(event.transient_input)


if __name__ == "__main__":
    unittest.main()