from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.test_runner as test_runner
from ei.test_runner import (
    TestModule,
    TestRunnerError,
    discover_test_modules,
    run_complete_suite,
    run_test_module,
)


class TestRunnerTests(unittest.TestCase):
    def _module_root(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="ei-test-runner-"))
        (root / "tests").mkdir()
        (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
        return root

    def test_discovery_is_deterministic_and_duplicate_module_names_are_rejected(self) -> None:
        root = self._module_root()
        tracked = [
            "tests/z/test_later.py",
            "tests/test_first.py",
            "tests/__init__.py",
            "tests/z/__init__.py",
        ]
        modules = discover_test_modules(root, tracked_files=tracked)
        self.assertEqual([item.module_name for item in modules], ["tests.test_first", "tests.z.test_later"])
        with self.assertRaisesRegex(TestRunnerError, "DUPLICATE_TEST_MODULE"):
            discover_test_modules(root, tracked_files=["tests/test_same.py", "tests/test_same.py"])

    def test_windows_test_children_use_a_hidden_process_group(self) -> None:
        with (
            patch.object(test_runner.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True),
            patch.object(test_runner.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True),
        ):
            self.assertEqual(test_runner._child_creation_flags("nt"), 0x08000200)
            self.assertEqual(test_runner._child_creation_flags("posix"), 0)

    def test_child_crash_is_reported_as_failure(self) -> None:
        root = self._module_root()
        relative = "tests/test_crash.py"
        (root / relative).write_text("raise SystemExit(17)\n", encoding="utf-8")
        result = run_test_module(
            TestModule("tests.test_crash", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "crashed")
        self.assertNotEqual(result.returncode, 0)

    def test_timeout_kills_only_the_child_and_records_bounded_log(self) -> None:
        root = self._module_root()
        relative = "tests/test_timeout.py"
        (root / relative).write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        result = run_test_module(
            TestModule("tests.test_timeout", relative),
            root,
            timeout_seconds=0.1,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
            max_log_bytes=128,
        )
        self.assertEqual(result.status, "timed_out")
        self.assertTrue(result.log_path)
        self.assertLessEqual(Path(result.log_path).stat().st_size, 128)

    def test_stderr_is_captured_without_becoming_success(self) -> None:
        root = self._module_root()
        relative = "tests/test_stderr.py"
        (root / relative).write_text(
            "import sys\nimport unittest\n\nclass StderrTest(unittest.TestCase):\n    def test_failure(self):\n        sys.stderr.write('diagnostic-stderr\\n')\n        self.fail('expected failure')\n",
            encoding="utf-8",
        )
        result = run_test_module(
            TestModule("tests.test_stderr", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("diagnostic-stderr", Path(result.log_path).read_text(encoding="utf-8"))

    def test_explicit_environment_is_forwarded_to_the_test_child(self) -> None:
        root = self._module_root()
        relative = "tests/test_environment.py"
        (root / relative).write_text(
            "import os\nimport unittest\n\n"
            "class EnvironmentTest(unittest.TestCase):\n"
            "    def test_marker(self):\n"
            "        self.assertEqual(os.environ.get('EI_TEST_ISOLATED_MARKER'), 'isolated')\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["EI_TEST_ISOLATED_MARKER"] = "isolated"

        result = run_test_module(
            TestModule("tests.test_environment", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
            environment=environment,
        )

        self.assertEqual(result.status, "passed")

    def test_failure_exposes_only_a_stable_uppercase_reason_code(self) -> None:
        root = self._module_root()
        relative = "tests/test_reason.py"
        (root / relative).write_text(
            "import unittest\n\nclass ReasonTest(unittest.TestCase):\n    def test_failure(self):\n        raise ValueError('PORTABLE_PATH_MISMATCH')\n",
            encoding="utf-8",
        )
        result = run_test_module(
            TestModule("tests.test_reason", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error_code, "PORTABLE_PATH_MISMATCH")

    def test_missing_dependency_reason_includes_only_the_safe_test_case_name(self) -> None:
        root = self._module_root()
        relative = "tests/test_missing.py"
        (root / relative).write_text(
            "import unittest\n\nclass MissingTest(unittest.TestCase):\n    def test_missing_fixture(self):\n        open('absent-fixture.json', encoding='utf-8')\n",
            encoding="utf-8",
        )
        result = run_test_module(
            TestModule("tests.test_missing", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error_code, "TEST_DEPENDENCY_MISSING_TEST_MISSING_FIXTURE")

    def test_missing_dependency_reason_supports_a_long_safe_test_case_name(self) -> None:
        root = self._module_root()
        relative = "tests/test_long_missing.py"
        test_name = "test_maintenance_continues_after_independent_source_failure_and_gcs_expired_spool"
        (root / relative).write_text(
            "import unittest\n\nclass MissingTest(unittest.TestCase):\n"
            f"    def {test_name}(self):\n"
            "        open('absent-fixture.json', encoding='utf-8')\n",
            encoding="utf-8",
        )
        result = run_test_module(
            TestModule("tests.test_long_missing", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.error_code,
            "TEST_DEPENDENCY_MISSING_" + test_name.upper(),
        )

    def test_explicit_platform_skip_is_accounted_without_child_execution(self) -> None:
        root = self._module_root()
        relative = "tests/test_platform_skip.py"
        (root / relative).write_text("PLATFORM_SKIP = True\n", encoding="utf-8")
        result = run_test_module(
            TestModule("tests.test_platform_skip", relative),
            root,
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.tests_run, 0)
        self.assertEqual(result.returncode, 0)

    def test_zero_test_module_fails_and_aggregate_exit_is_false(self) -> None:
        root = self._module_root()
        (root / "tests" / "test_pass.py").write_text(
            textwrap.dedent(
                """
                import unittest
                class PassTest(unittest.TestCase):
                    def test_pass(self):
                        self.assertEqual(2 + 2, 4)
                """
            ),
            encoding="utf-8",
        )
        (root / "tests" / "test_empty.py").write_text("VALUE = 1\n", encoding="utf-8")
        output = root / "summary.json"
        summary = run_complete_suite(
            root,
            output=output,
            tracked_files=["tests/test_pass.py", "tests/test_empty.py"],
            timeout_seconds=2,
            python_executable=Path(sys.executable),
            log_dir=root / "logs",
        )
        self.assertFalse(summary.successful)
        self.assertEqual(summary.counts["modules"], 2)
        self.assertEqual(summary.counts["zero_test"], 1)
        self.assertEqual(summary.counts["passed"], 1)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["successful"], False)


if __name__ == "__main__":
    unittest.main()
