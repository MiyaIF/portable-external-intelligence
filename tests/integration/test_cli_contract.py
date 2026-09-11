import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ei.cli import EXIT_INPUT, EXIT_OK, main


class CliContractTests(unittest.TestCase):
    def _repo(self, root):
        (root / "config").mkdir(parents=True, exist_ok=True)
        (root / "config" / "defaults.json").write_text(
            json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}, ensure_ascii=False),
            encoding="utf-8",
        )

    def _common(self, root):
        return ["--repo", str(root), "--codex-home", str(root / "codex"), "--runtime-root", str(Path(str(root) + "-runtime")), "--json"]

    def test_help_exposes_complete_command_surface(self):
        from ei.cli import _build_parser

        help_text = _build_parser().format_help()
        for command in (
            "setup", "update", "uninstall", "doctor", "status", "queue",
            "recall", "closeout", "maintain", "sync", "inventory-existing",
            "migrate-existing", "metrics", "experiment-report",
        ):
            self.assertIn(command, help_text)

    def test_help_lists_contract_options_for_each_command(self):
        from ei.cli import _build_parser

        parser = _build_parser()
        root_subparsers = next(action for action in parser._actions if getattr(action, "choices", None) is not None)
        expected = {
            "setup": ("--repo", "--runtime-root", "--host", "--host-profile", "--providers", "--check-only", "--json"),
            "update": ("--check-only", "--target-ref", "--json"),
            "uninstall": ("--manifest", "--remove-queue", "--remove-spool", "--json"),
            "doctor": ("--strict", "--repair-plan", "--json"),
            "status": ("--host", "--json"),
            "recall": ("--query", "--cwd", "--max-chars", "--json"),
            "closeout": ("--input-json", "--json"),
            "maintain": ("--source", "--time-budget-ms", "--sync-policy", "--json"),
            "sync": ("--retry-now", "--dry-run", "--json"),
            "inventory-existing": ("--source", "--allow-global-source", "--json"),
            "migrate-existing": ("--source", "--inventory", "--apply-plan-hash", "--json"),
            "metrics": ("--sqlite", "--from", "--to", "--json"),
            "experiment-report": ("--experiment-id", "--output", "--json"),
        }
        for command, options in expected.items():
            help_text = root_subparsers.choices[command].format_help()
            for option in options:
                self.assertIn(option, help_text, command)

        queue_parser = root_subparsers.choices["queue"]
        queue_subparsers = next(action for action in queue_parser._actions if getattr(action, "choices", None) is not None)
        queue_help = queue_subparsers.choices["drain"].format_help()
        for option in ("--max-items", "--time-budget-ms", "--now", "--json"):
            self.assertIn(option, queue_help)
    def test_invalid_argument_is_exit_two_and_json_stdout_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["recall", *self._common(root)])
            self.assertEqual(code, EXIT_INPUT)
            value = json.loads(output.getvalue())
            self.assertFalse(value["ok"])
            self.assertIn("error_code", value)

    def test_explicit_runtime_root_is_used_and_status_is_json_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["status", *self._common(root)])
            self.assertEqual(code, EXIT_OK)
            value = json.loads(output.getvalue())
            self.assertIn("queue", value)
            self.assertNotIn(str(root / "runtime"), output.getvalue())

    def test_global_auto_inventory_is_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["inventory-existing", *self._common(root)])
            self.assertEqual(code, EXIT_INPUT)
            value = json.loads(output.getvalue())
            self.assertEqual(value["error_code"], "GLOBAL_SOURCE_APPROVAL_REQUIRED")


if __name__ == "__main__":
    unittest.main()
