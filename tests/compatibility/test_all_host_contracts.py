from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from ei.certification import REQUIRED_EVENT_NAMES, REQUIRED_HOST_IDS
from ei.hooks.registry import get_adapter, hook_config_fragment, supported_events
from tests.helpers import make_hook_settings


class AllHostContractTests(unittest.TestCase):
    def test_every_supported_cli_host_has_a_distinct_adapter_and_event_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            for host_id in REQUIRED_HOST_IDS:
                with self.subTest(host_id=host_id):
                    adapter = get_adapter(host_id)
                    self.assertTrue(supported_events(host_id))
                    self.assertIsNotNone(adapter)
                    self.assertTrue(settings.paths.runtime_root != settings.paths.repo_root)
                    fragment = hook_config_fragment(
                        host_id,
                        Path(tmp) / "Python With Spaces" / "python.exe",
                        settings.paths.engine_root,
                        settings.paths.knowledge_root,
                        settings.paths.runtime_root,
                    )
                    self.assertIn("--engine-root", fragment["command"])
                    self.assertIn("--knowledge-root", fragment["command"])
                    self.assertIn("--runtime-root", fragment["command"])
                    if host_id.startswith("codex"):
                        self.assertIn("commandWindows", fragment)

    def test_builtin_hosts_declare_public_adapter_and_family_identity(self) -> None:
        manifest = json.loads((Path(__file__).parents[2] / "config" / "hosts.json").read_text(encoding="utf-8"))
        expected = {
            "codex-cli": "codex-compatible",
            "claude-code": "claude-compatible",
            "gemini-cli": "gemini-compatible",
            "qwen-code": "qwen-compatible",
        }
        for host_id, family in expected.items():
            with self.subTest(host_id=host_id):
                self.assertEqual(manifest["hosts"][host_id]["adapter_id"], host_id)
                self.assertEqual(manifest["hosts"][host_id]["host_family"], family)

    def test_required_normalized_event_names_are_explicit(self) -> None:
        self.assertEqual(
            set(REQUIRED_EVENT_NAMES),
            {"session.start", "prompt.before", "turn.stop", "session.end"},
        )


if __name__ == "__main__":
    unittest.main()
