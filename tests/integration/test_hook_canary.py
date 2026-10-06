import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.canary import _read_receipts, read_hook_status
from ei.config import RuntimePaths
from ei.hook_entry import run_hook
from ei.hooks.base import HookResult
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory
from tests.helpers import make_hook_settings


def portable_settings(root: Path, *, include_formula_pattern: bool = False):
    workspace = Path(root).resolve()
    engine = workspace / "engine"
    knowledge_root = workspace / "knowledge"
    knowledge = knowledge_root / "knowledge"
    runtime = workspace / "runtime"
    codex_home = workspace / "host" / "codex"
    for directory in (engine, knowledge_root, knowledge, runtime, codex_home):
        directory.mkdir(parents=True, exist_ok=True)
    base = make_hook_settings(engine)
    if include_formula_pattern:
        (knowledge / "index.md").write_text(
            "formula pattern\n書込後に対象範囲を再読込して検証する\n",
            encoding="utf-8",
        )
    paths = RuntimePaths(engine_root=engine, personal_knowledge_root=knowledge_root, runtime_root=runtime,
        codex_home=codex_home, event_dir=engine / "events", knowledge_dir=knowledge,
        local_state_dir=runtime / "state", metrics_dir=runtime / "metrics", cache_dir=runtime / "cache",
        locks_dir=runtime / "locks", config_path=codex_home / "config.toml",
        hooks_path=codex_home / "hooks.json", agents_path=codex_home / "AGENTS.md")
    return replace(base, paths=paths)


class HookCanaryIntegrationTests(unittest.TestCase):
    def test_run_hook_accepts_bounded_bytes_and_records_receipt_before_recall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = portable_settings(root, include_formula_pattern=True)
            result = run_hook("codex-cli", json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "prompt-secret"}).encode("utf-8"), 1000, settings)
            self.assertIsInstance(result, HookResult)
            self.assertTrue(result.continue_work)
            self.assertNotIn("prompt-secret", (settings.paths.runtime_dir / "hook-receipts.jsonl").read_text(encoding="utf-8"))
            self.assertTrue((settings.paths.runtime_dir / "canary-receipts.jsonl").exists())

    def test_real_event_set_is_instance_bound_and_stop_is_durable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = portable_settings(root)
            for index, event in enumerate(("SessionStart", "UserPromptSubmit", "Stop")):
                payload = {"hook_event_name": event, "session_id": "s1", "turn_id": f"t{index}", "cwd": "C:/work", "prompt": "safe"} if event == "UserPromptSubmit" else {"hook_event_name": event, "session_id": "s1", "turn_id": f"t{index}", "cwd": "C:/work"}
                run_hook("codex-cli", json.dumps(payload).encode("utf-8"), 1000, settings)
            self.assertEqual(len(_read_receipts(settings)), 3)
            self.assertEqual(read_hook_status("codex-cli", "codex-cli", settings).received_events, ("prompt.before", "session.start", "turn.stop"))
            from ei.capture_ledger import list_receipts
            targets = list_receipts(settings)
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].state, "UNKNOWN")
            self.assertEqual(targets[0].candidate_ids, ())
            self.assertFalse((settings.paths.runtime_dir / "state" / "capture" / "target-bindings").exists())
            self.assertFalse(any(runtime_inventory(settings.paths.queue_dir, prefix="queue_")))

    def test_malformed_and_unknown_host_fail_open_without_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = portable_settings(Path(tmp))
            malformed = run_hook("codex-cli", b'{"prompt":"secret"', 1000, settings)
            unknown = run_hook("unknown-agent", b'{"hook_event_name":"SessionStart"}', 1000, settings)
            self.assertTrue(malformed.continue_work)
            self.assertTrue(unknown.continue_work)
            self.assertNotIn("secret", (settings.paths.runtime_dir / "hook-errors.jsonl").read_text(encoding="utf-8"))

    def test_deadline_returns_empty_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = portable_settings(Path(tmp), include_formula_pattern=True)
            completed = HookResult(True, "retrieved context", "receipt-1", "ok", "UserPromptSubmit")
            clock = iter((0.0, 1.0))
            with (
                patch("ei.hook_entry.handle_normalized_hook", return_value=completed),
                patch("ei.hook_entry.time.monotonic", side_effect=lambda: next(clock, 1.0)),
            ):
                result = run_hook("codex-cli", json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "reload"}).encode("utf-8"), 1, settings)
            self.assertTrue(result.continue_work)
            self.assertEqual(result.status, "DEADLINE_EXCEEDED")
            self.assertEqual(result.additional_context, "")


if __name__ == "__main__":
    unittest.main()
