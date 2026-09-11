from __future__ import annotations

import tempfile
import unittest
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ei.inference.router as router_module
from ei.hook_entry import handle_hook
from ei.config import HostSpec
from ei.hooks.base import HookResult
from ei.hooks.registry import encode_hook_result, hook_config_fragment, normalize_hook_event, supported_events
from tests.helpers import make_hook_settings


class ProfiledHookCompatibilityTests(unittest.TestCase):
    def test_custom_host_reuses_gemini_payload_contract_and_keeps_custom_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = make_hook_settings(root)

            custom_home = root / "custom-home"
            settings = replace(
                base,
                hosts={
                    "test-compatible-cli": HostSpec(
                        host_id="test-compatible-cli",
                        display_name="Test Compatible CLI",
                        executable_names=("test-compatible",),
                        hook_config_path=custom_home / ".config/test-compatible/settings.json",
                        global_context_path=custom_home / ".config/test-compatible/context.md",
                        skill_roots=(custom_home / ".config/test-compatible/skills",),
                        event_mapping={
                            "SessionStart": "session.start",
                            "BeforeAgent": "prompt.before",
                            "AfterAgent": "turn.stop",
                            "SessionEnd": "session.end",
                        },
                        hook_feature_key=None,
                        hook_feature_default=False,
                        skill_activation_mode="CONSENT_REQUIRED",
                        capture_primary_path="HOOK_DIRECT",
                        capture_order=("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
                        minimum_supported_version=None,
                        host_family="gemini-compatible",
                        adapter_id="gemini-cli",
                        profile_hash="sha256:" + "a" * 64,
                    )
                },
            )
            payload = {
                "hook_event_name": "BeforeAgent",
                "session_id": "s1",
                "turn_id": "t1",
                "cwd": "/work",
                "prompt": "retrieve needed knowledge",
            }

            event = normalize_hook_event("test-compatible-cli", payload, settings)

            self.assertEqual(event.host_id, "test-compatible-cli")
            self.assertEqual(event.host_instance_id, "test-compatible-cli")
            self.assertEqual(event.normalized_event_name, "prompt.before")
            self.assertEqual(event.source_host_id, "test-compatible-cli")
            self.assertEqual(event.source_host_family, "gemini-compatible")
            self.assertNotEqual(event.idempotency_key, normalize_hook_event("gemini-cli", payload, settings).idempotency_key)
            self.assertEqual(set(supported_events("test-compatible-cli", settings)), {"SessionStart", "BeforeAgent", "AfterAgent", "SessionEnd"})
            fragment = hook_config_fragment(
                "test-compatible-cli",
                Path(sys.executable),
                root,
                base.paths.knowledge_root,
                base.paths.runtime_root,
                settings=settings,
            )
            self.assertIn("test-compatible-cli", fragment["command"])
            encoded = encode_hook_result("test-compatible-cli", HookResult(True, "context", "receipt", "ok", "BeforeAgent"), settings)
            self.assertEqual(encoded["hookSpecificOutput"]["hookEventName"], "BeforeAgent")
            response = handle_hook(payload, settings, host_id="test-compatible-cli")
            self.assertTrue(response["continue"])
            receipt = (settings.paths.runtime_root / "hook-receipts.jsonl").read_text(encoding="utf-8")
            self.assertIn('"host_id":"test-compatible-cli"', receipt)

    def test_custom_organizer_uses_profile_adapter_transport_and_executable_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir()
            manifest = runtime / "install-manifest.json"
            manifest.write_text('{"hosts":{"test-compatible-cli":{}}}', encoding="utf-8")
            host = HostSpec(
                host_id="test-compatible-cli",
                display_name="Test Compatible CLI",
                executable_names=("test-compatible",),
                hook_config_path=root / "home" / "settings.json",
                global_context_path=root / "home" / "context.md",
                skill_roots=(root / "home" / "skills",),
                event_mapping={"SessionStart": "session.start", "BeforeAgent": "prompt.before", "AfterAgent": "turn.stop", "SessionEnd": "session.end"},
                hook_feature_key=None,
                hook_feature_default=False,
                skill_activation_mode="CONSENT_REQUIRED",
                capture_primary_path="HOOK_DIRECT",
                capture_order=("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
                minimum_supported_version=None,
                host_family="gemini-compatible",
                adapter_id="gemini-cli",
                profile_hash="sha256:" + "a" * 64,
            )
            settings = SimpleNamespace(
                hosts={"test-compatible-cli": host},
                paths=SimpleNamespace(install_manifest_path=manifest),
            )
            with patch.object(router_module, "_resolve_host_command", return_value=(str(root / "test-compatible.exe"),)):
                entry = router_module._auto_subscription_entry(
                    settings,
                    {"enabled": False, "argv": [], "auto_from_selected_host": True},
                )

            self.assertEqual(entry["transport"], "gemini-cli")
            self.assertEqual(entry["argv"], [str(root / "test-compatible.exe")])


if __name__ == "__main__":
    unittest.main()
