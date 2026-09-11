import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ei.hook_entry as hook_entry
from ei.hook_status import HookStatus
from ei.hook_entry import _read_stdin_bounded, handle_hook, handle_normalized_hook, normalize_hook_event, run_hook
from tests.helpers import make_hook_settings


class HookEntryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_user_prompt_submit_returns_additional_context(self):
        payload = {"session_id": "s1", "turn_id": "t1", "cwd": "C:/work/project", "hook_event_name": "UserPromptSubmit", "prompt": "find the missing formula", "model": "test-model", "permission_mode": "default"}
        result = handle_hook(payload, settings=make_hook_settings(self.root, include_formula_pattern=True))
        self.assertEqual(result["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
        self.assertIn("additionalContext", result["hookSpecificOutput"])
        self.assertLessEqual(len(result["hookSpecificOutput"]["additionalContext"]), 5000)
        self.assertTrue((self.root / "codex" / "external-intelligence" / "state" / "last-successful-query.json").exists())
        receipt = (self.root / "codex" / "external-intelligence" / "hook-receipts.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("find the missing formula", receipt)

    def test_experiment_gate_keeps_control_context_empty_and_records_exposure(self):
        settings = replace(make_hook_settings(self.root, include_formula_pattern=True), experiment_enabled=True, experiment_id="retrieval-v1")
        session = next(f"session-{index}" for index in range(1000) if __import__("ei.experiment", fromlist=["assign_variant"]).assign_variant(f"session-{index}", "retrieval-v1").value == "control")
        result = handle_hook({"hook_event_name": "UserPromptSubmit", "session_id": session, "cwd": "C:/work/project", "domain": "general", "prompt": "check formula"}, settings)
        self.assertEqual(result, {"continue": True})
        exposures = self.root / "codex" / "external-intelligence" / "experiment-exposures.jsonl"
        self.assertTrue(exposures.exists())
        self.assertIn('"variant":"control"', exposures.read_text(encoding="utf-8"))

    def test_recall_passes_event_host_family_to_retrieval_query(self):
        settings = make_hook_settings(self.root)
        event = normalize_hook_event(
            "codex-cli",
            {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "reuse rule"},
            settings,
        )
        captured = {}

        def capture(query, patterns, policy=None):
            captured["query"] = query
            return []

        with patch.object(hook_entry, "rank_patterns", side_effect=capture):
            self.assertEqual(hook_entry._recall(event, "reuse rule", settings, "prompt", 5000), ([], ""))
        self.assertEqual(captured["query"].host_id, event.source_host_id)
        self.assertEqual(captured["query"].host_family, event.source_host_family)

    def test_structured_index_failure_does_not_fall_back_to_markdown_recall(self):
        settings = make_hook_settings(self.root)
        settings.paths.knowledge_dir.mkdir(parents=True, exist_ok=True)
        (settings.paths.knowledge_dir / "index.json").write_text("{}", encoding="utf-8")
        (settings.paths.knowledge_dir / "index.md").write_text(
            "## Active Patterns\n- [pat_markdown_fallback] reuse rule\n",
            encoding="utf-8",
        )
        event = normalize_hook_event(
            "codex-cli",
            {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "reuse rule"},
            settings,
        )
        hits, context = hook_entry._recall(event, "reuse rule", settings, "prompt", 5000)
        self.assertEqual(hits, [])
        self.assertEqual(context, "")
        errors = settings.paths.runtime_dir / "hook-errors.jsonl"
        self.assertIn('"reason_code":"INDEX_UNAVAILABLE"', errors.read_text(encoding="utf-8"))

    def test_experiment_recall_filters_host_scope_before_exposure(self):
        settings = replace(make_hook_settings(self.root), experiment_enabled=True, experiment_id="retrieval-v1")
        event = normalize_hook_event(
            "codex-cli",
            {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "reuse rule"},
            settings,
        )
        family_pattern = {
            "pattern_id": "pat_gemini_only",
            "cluster_id": "pat_gemini_only",
            "status": "active",
            "classification": "private-reusable",
            "rule": "reuse rule",
            "applicability_scope": "family",
            "applicable_host_ids": [],
            "applicable_host_families": ["gemini-compatible"],
        }
        with (
            patch.object(hook_entry, "_parse_patterns", return_value=[family_pattern]),
            patch.object(hook_entry, "prepare_exposure", return_value=SimpleNamespace(additional_context="")) as prepare,
            patch.object(hook_entry, "rank_patterns", return_value=[]) as rank,
        ):
            handle_normalized_hook(event, settings)
        self.assertEqual(prepare.call_args.args[3], [family_pattern])
        self.assertEqual(prepare.call_args.kwargs["host_id"], event.source_host_id)
        self.assertEqual(prepare.call_args.kwargs["host_family"], event.source_host_family)
        rank.assert_not_called()

    def test_unknown_event_fails_open_without_context(self):
        result = handle_hook({"hook_event_name": "FutureEvent"}, settings=make_hook_settings(self.root))
        self.assertEqual(result, {"continue": True})

    def test_unknown_event_error_log_does_not_persist_raw_event_name(self):
        settings = make_hook_settings(self.root)
        raw_event = "C:" + r"\Users\alice\confidential-client-event"

        result = handle_hook({"hook_event_name": raw_event}, settings=settings)

        self.assertEqual(result, {"continue": True})
        log = (settings.paths.runtime_dir / "hook-errors.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(raw_event, log)
        self.assertIn('"event":"unsupported"', log)

    def test_unsafe_host_instance_id_is_hashed_before_persistence(self):
        settings = make_hook_settings(self.root)
        raw_instance = "C:" + r"\Users\alice\private-workstation"

        event = normalize_hook_event(
            "codex-cli",
            {
                "hook_event_name": "SessionStart",
                "host_instance_id": raw_instance,
                "session_id": "s1",
                "turn_id": "t1",
                "cwd": "C:/work",
            },
            settings,
        )

        self.assertNotEqual(event.host_instance_id, raw_instance)
        self.assertRegex(event.host_instance_id, r"^instance_[0-9a-f]{24}$")

    def test_unknown_host_fails_open_without_fabricated_adapter(self):
        result = handle_hook({"hook_event_name": "SessionStart"}, settings=make_hook_settings(self.root), host_id="unknown-agent")
        self.assertEqual(result, {"continue": True})

    def test_stop_writes_only_sanitized_local_queue(self):
        result = handle_hook({"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work/project", "prompt": "do-not-write-this-secret"}, settings=make_hook_settings(self.root))
        self.assertEqual(result, {"continue": True})
        queue = self.root / "codex" / "external-intelligence" / "state" / "hook-queue.jsonl"
        self.assertTrue(queue.exists())
        self.assertNotIn("do-not-write-this-secret", queue.read_text(encoding="utf-8"))

    def test_recursion_guard_short_circuits(self):
        with patch.dict(os.environ, {"EI_INTERNAL": "1"}):
            result = handle_hook({"hook_event_name": "UserPromptSubmit", "prompt": "not captured"}, make_hook_settings(self.root))
        self.assertEqual(result, {"continue": True})
        self.assertFalse((self.root / "codex" / "external-intelligence" / "hook-receipts.jsonl").exists())

    def test_bounded_stdin_rejects_oversized_input(self):
        with patch("sys.stdin", io.StringIO("x" * 1025)):
            with self.assertRaisesRegex(ValueError, "HOOK_INPUT_TOO_LARGE"):
                _read_stdin_bounded(1024)

    def test_hook_stdio_prefers_utf8_bytes_over_windows_console_encoding(self):
        payload = '{"prompt":"日本語"}'.encode("utf-8")

        class BinaryInput:
            def __init__(self, value: bytes) -> None:
                self.buffer = io.BytesIO(value)

            def read(self, *_args: object) -> str:
                raise AssertionError("text-mode stdin must not be used")

        class BinaryOutput:
            def __init__(self) -> None:
                self.buffer = io.BytesIO()

            def write(self, _value: str) -> int:
                raise AssertionError("text-mode stdout must not be used")

            def flush(self) -> None:
                return None

        output = BinaryOutput()
        with patch("sys.stdin", BinaryInput(payload)):
            self.assertEqual(_read_stdin_bounded(1024), payload.decode("utf-8"))
        with patch("sys.stdout", output):
            hook_entry._write_stdout_json({"context": "日本語"}, ensure_ascii=False)
        self.assertEqual(json.loads(output.buffer.getvalue().decode("utf-8")), {"context": "日本語"})

    def test_deadline_returns_empty_context_and_sanitized_status(self):
        settings = replace(make_hook_settings(self.root), prompt_budget_ms=1)
        event = normalize_hook_event("codex-cli", {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work", "prompt": "reload"}, settings)
        with patch("ei.hook_entry.time.monotonic", side_effect=[0.0, 1.0]):
            result = handle_normalized_hook(event, settings)
        self.assertEqual(result.status, "DEADLINE_EXCEEDED")
        self.assertEqual(result.additional_context, "")

    def test_run_hook_accepts_bounded_json_bytes_and_returns_hook_result(self):
        settings = make_hook_settings(self.root)
        payload = json.dumps({"hook_event_name": "SessionStart", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"}).encode("utf-8")
        result = run_hook("codex-cli", payload, 2000, settings)
        self.assertTrue(result.continue_work)
        self.assertEqual(result.host_event_name, "SessionStart")
        self.assertTrue(result.receipt_id)
        status = HookStatus.from_mapping({
            "host_id": "codex-cli",
            "host_instance_id": "codex-cli",
            "hook_status": "HOOK_UNVERIFIED",
            "team": {"status": "DISABLED", "reason_code": "TEAM_DISABLED"},
        })
        self.assertEqual(status.to_dict()["team"]["status"], "DISABLED")


if __name__ == "__main__":
    unittest.main()
