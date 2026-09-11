import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class HookIntegrationTests(unittest.TestCase):
    def test_explicit_personal_root_hook_argument_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            personal = root / "personal"
            runtime = root / "runtime"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text(
                '{"retrieval":{"max_chars":5000,"max_results":5}}',
                encoding="utf-8",
            )
            (personal / "knowledge").mkdir(parents=True)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ei.hook_entry",
                    "SessionStart",
                    "--host-id",
                    "codex-cli",
                    "--engine-root",
                    str(engine),
                    "--personal-knowledge-root",
                    str(personal),
                    "--runtime-root",
                    str(runtime),
                ],
                input='{"hook_event_name":"SessionStart"}',
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout).get("continue"))

    def test_all_fixtures_produce_fail_open_json_without_prompt_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text("{\"retrieval\":{\"max_chars\":5000,\"max_results\":5}}", encoding="utf-8")
            (knowledge / "knowledge").mkdir(parents=True)
            (knowledge / "knowledge" / "index.md").write_text("formula pattern\n再読込して数式を確認する\n", encoding="utf-8")
            codex_home = root / "codex"
            for fixture in sorted(Path("tests/fixtures/hooks").glob("*.json")):
                payload = json.loads(fixture.read_text(encoding="utf-8"))
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ei.hook_entry",
                        payload["hook_event_name"],
                        "--engine-root",
                        str(engine),
                        "--knowledge-root",
                        str(knowledge),
                        "--runtime-root",
                        str(runtime),
                        "--codex-home",
                        str(codex_home),
                    ],
                    input=json.dumps(payload, ensure_ascii=False),
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    check=False,
                    env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
                )
                self.assertEqual(completed.returncode, 0, fixture.name)
                output = json.loads(completed.stdout)
                self.assertTrue(output.get("continue"))
                self.assertNotIn("prompt-secret", completed.stderr)
                if payload["hook_event_name"] == "UserPromptSubmit":
                    context = output["hookSpecificOutput"]["additionalContext"]
                    self.assertLessEqual(len(context), 5000)

    def test_all_host_adapters_route_to_common_entrypoint(self):
        fixtures = {
            "codex-cli": {"hook_event_name": "SessionStart"},
            "codex-app": {"hook_event_name": "SessionStart", "host_instance_id": "codex-app"},
            "claude-code": {"hook_event_name": "UserPromptSubmit", "prompt": "safe"},
            "gemini-cli": {"hook_event_name": "BeforeAgent", "prompt": "safe"},
            "qwen-code": {"hook_event_name": "Stop"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text("{\"retrieval\":{\"max_chars\":5000,\"max_results\":5}}", encoding="utf-8")
            knowledge.mkdir()
            for host_id, payload in fixtures.items():
                completed = subprocess.run(
                    [sys.executable, "-m", "ei.hook_entry", payload["hook_event_name"], "--host-id", host_id, "--engine-root", str(engine), "--knowledge-root", str(knowledge), "--runtime-root", str(runtime), "--codex-home", str(root / "home")],
                    input=json.dumps(payload), text=True, encoding="utf-8", capture_output=True, check=False, env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
                )
                self.assertEqual(completed.returncode, 0, host_id + completed.stderr)
                self.assertTrue(json.loads(completed.stdout).get("continue"))

    def test_malformed_json_returns_exit_code_two_without_echoing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = subprocess.run(
                [sys.executable, "-m", "ei.hook_entry", "UserPromptSubmit", "--engine-root", str(root), "--knowledge-root", str(root / "knowledge"), "--runtime-root", str(root / "runtime")],
                input='{"prompt":"prompt-secret"',
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
            )
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn("prompt-secret", completed.stderr)


if __name__ == "__main__":
    unittest.main()
