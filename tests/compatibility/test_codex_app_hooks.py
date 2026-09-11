import json
import tempfile
import unittest
from pathlib import Path

from ei.hooks.registry import normalize_hook_event
from tests.helpers import make_hook_settings


FIXTURES = {"SessionStart": {"hook_event_name": "SessionStart", "session_id": "s-app", "turn_id": "t-app", "cwd": "C:/app"}}


class CodexAppHookCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = make_hook_settings(Path(self.tmp.name))

    def test_codex_app_is_distinct_from_codex_cli(self):
        payload = {**FIXTURES["SessionStart"], "host_instance_id": "codex-app-desktop"}
        event = normalize_hook_event("codex-app", payload, self.settings)
        self.assertEqual(event.host_id, "codex-app")
        self.assertEqual(event.host_instance_id, "codex-app-desktop")
        self.assertNotEqual(event.host_id, "codex-cli")

    def test_codex_app_is_declared_as_a_separate_instance(self):
        template = json.loads((Path(__file__).parents[2] / "hooks" / "codex" / "hooks.template.json").read_text(encoding="utf-8"))
        self.assertIn("codex-app", template["host_instance_ids"])
        self.assertIn("codex-cli", template["host_instance_ids"])


if __name__ == "__main__":
    unittest.main()
