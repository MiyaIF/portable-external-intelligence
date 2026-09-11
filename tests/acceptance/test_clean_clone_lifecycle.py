from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ei.config import PUBLIC_CLI_HOST_IDS
from ei.gate import GateDecision
from ei.test_runner import discover_test_modules


ROOT = Path(__file__).resolve().parents[2]


def _load_certifier():
    spec = importlib.util.spec_from_file_location("certify_public_clone", ROOT / "scripts" / "certify-public-clone.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("CERTIFIER_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CleanCloneLifecycleTests(unittest.TestCase):
    def test_failure_output_exposes_only_bounded_path_free_suite_diagnostics(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "counts": {"modules": 2, "passed": 1, "failed": 1, "crashed": 0, "timed_out": 0},
                        "modules": [
                            {"module": "tests.unit.test_portable", "status": "failed", "error_code": "TEST_ASSERTION_FAILED"},
                            {"module": r"X:\private\secret.py", "status": "failed", "error_code": "RAW_PATH"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            diagnostics = module._suite_failure_diagnostics(summary)

        self.assertEqual(diagnostics["counts"]["failed"], 1)
        self.assertEqual(diagnostics["modules"], [{"module": "tests.unit.test_portable", "status": "failed", "error_code": "TEST_ASSERTION_FAILED"}])
        failure = module.CertificationError("COMPLETE_SUITE_FAILED", diagnostics=diagnostics)
        output = io.StringIO()
        with patch.object(module, "certify", side_effect=failure), redirect_stdout(output):
            result = module.main(["--output", "unused.json", "--offline-fixtures"])
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(payload["diagnostics"], diagnostics)
        self.assertNotIn("private", output.getvalue())

    def test_each_dependency_lock_has_a_distinct_failure_code(self) -> None:
        module = _load_certifier()
        self.assertEqual(module._lock_failure_code("requirements-build.lock"), "BUILD_LOCK_INSTALL_FAILED")
        self.assertEqual(module._lock_failure_code("requirements-runtime.lock"), "RUNTIME_LOCK_INSTALL_FAILED")
        self.assertEqual(module._lock_failure_code("requirements-ci.lock"), "CI_LOCK_INSTALL_FAILED")

    def test_certifier_installs_the_single_built_wheel_instead_of_the_source_tree(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            package_dir = Path(tmp)
            wheel = package_dir / "external_intelligence_engine-1.0.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            (package_dir / "external_intelligence_engine-1.0.0.tar.gz").write_bytes(b"sdist")

            selected = module._built_wheel(package_dir)

        self.assertEqual(selected, wheel)
        self.assertEqual(
            module._package_install_arguments(Path("python"), selected),
            [Path("python"), "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", selected],
        )

    def test_certifier_rejects_missing_or_ambiguous_built_wheels(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            package_dir = Path(tmp)
            with self.assertRaisesRegex(module.CertificationError, "PACKAGE_WHEEL_MISSING"):
                module._built_wheel(package_dir)
            (package_dir / "first.whl").write_bytes(b"first")
            (package_dir / "second.whl").write_bytes(b"second")
            with self.assertRaisesRegex(module.CertificationError, "PACKAGE_WHEEL_AMBIGUOUS"):
                module._built_wheel(package_dir)

    def test_complete_suite_runs_directly_with_isolated_environment_and_progress(self) -> None:
        module = _load_certifier()
        summary_payload = {
            "successful": True,
            "counts": {"modules": 1, "tests": 1, "tests_skipped": 0},
            "modules": [],
        }
        summary = type(
            "Summary",
            (),
            {
                "successful": True,
                "to_dict": lambda self, *, repo_root=None: summary_payload,
            },
        )()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            clone = workspace / "clone with spaces 日本語"
            clone.mkdir()
            output = workspace / "summary.json"
            environment = {"EI_CERTIFICATION_ENV": "isolated"}
            with patch.object(module, "run_complete_suite", return_value=summary) as runner:
                result = module._bounded_complete_suite(
                    clone,
                    output=output,
                    log_dir=workspace / "logs",
                    python_executable=Path(sys.executable),
                    environment=environment,
                    timeout_seconds=12.5,
                )

        self.assertEqual(result, summary_payload)
        runner.assert_called_once_with(
            clone,
            output=output,
            jobs=1,
            timeout_seconds=12.5,
            python_executable=Path(sys.executable),
            log_dir=workspace / "logs",
            progress_stream=module.sys.stdout,
            environment=environment,
        )

    def test_failed_process_reports_only_a_bounded_reason_category(self) -> None:
        module = _load_certifier()
        completed = type(
            "Completed",
            (),
            {
                "returncode": 1,
                "stdout": "",
                "stderr": "ERROR: No matching distribution found for package==1.0 at /private/path",
            },
        )()
        with patch.object(module.subprocess, "run", return_value=completed):
            with self.assertRaises(module.CertificationError) as caught:
                module._run(
                    ["python", "-m", "pip"],
                    cwd=ROOT,
                    env={},
                    timeout=1,
                    code="RUNTIME_LOCK_INSTALL_FAILED",
                )
        self.assertEqual(caught.exception.diagnostics, {"process_reason": "NO_MATCHING_DISTRIBUTION"})

    def test_bounded_runner_inventory_contains_this_certification_module(self) -> None:
        modules = discover_test_modules(ROOT)
        paths = {item.relative_path for item in modules}
        # The file is intentionally also runnable before the R16 commit has
        # made it part of the Git inventory.
        if "tests/acceptance/test_clean_clone_lifecycle.py" in paths:
            self.assertIn("tests/acceptance/test_clean_clone_lifecycle.py", paths)
        self.assertEqual(
            PUBLIC_CLI_HOST_IDS,
            ("codex-cli", "claude-code", "gemini-cli", "qwen-code"),
        )

    def test_certifier_receipt_contract_is_path_free_and_digest_bound(self) -> None:
        module = _load_certifier()
        value = module._base_receipt(
            source_commit="a" * 40,
            clone_commit="a" * 40,
            source_tree="b" * 40,
            clone_tree="b" * 40,
            inventory_hash="sha256:" + "1" * 64,
            workflow_hash="sha256:" + "2" * 64,
            lock_hash="sha256:" + "3" * 64,
            source_audit_hash="sha256:" + "4" * 64,
            public_audit_hash="sha256:" + "5" * 64,
            packages={"package.whl": "sha256:" + "6" * 64},
            steps=[{"name": "fixture", "status": "passed", "duration_seconds": 0.001}],
            counts={"modules": 1, "tests": 1, "tests_skipped": 0},
            started=0.0,
            status="PASSED",
        )
        self.assertTrue(module._validate_receipt(value))
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(str(ROOT), serialized)
        self.assertNotIn(str(Path.home()), serialized)

    def test_receipt_write_does_not_follow_predictable_hardlink_temp(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "receipt.json"
            victim = root / "victim.txt"
            victim.write_text("preserve", encoding="utf-8")
            predictable = output.with_name(output.name + f".{os.getpid()}.tmp")
            try:
                os.link(victim, predictable)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hardlink fixture unavailable: {type(exc).__name__}")

            module._write_receipt(output, {"status": "PASSED"})

            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"status": "PASSED"})

    def test_isolated_environment_uses_private_home_and_removes_credential_variables(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            homes = {host: workspace / host for host in PUBLIC_CLI_HOST_IDS}
            environment = module._isolated_environment(workspace, homes)
            self.assertEqual(environment["EI_CERTIFICATION_ENV"], "isolated")
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["PYTHONUTF8"], "1")
            self.assertEqual(environment["PYTHONIOENCODING"], "utf-8")
            temporary_root = Path(environment["TMPDIR"])
            self.assertEqual(temporary_root, temporary_root.resolve())
            self.assertTrue(temporary_root.is_dir())
            self.assertEqual(environment["TMP"], str(temporary_root))
            self.assertEqual(environment["TEMP"], str(temporary_root))
            self.assertNotEqual(Path(environment["HOME"]).resolve(), Path.home().resolve())
            self.assertFalse(any("token" in key.casefold() or "secret" in key.casefold() for key in environment))

    def test_certifier_requires_offline_fixture_mode_before_work(self) -> None:
        module = _load_certifier()
        with self.assertRaisesRegex(module.CertificationError, "OFFLINE_FIXTURES_REQUIRED"):
            module.certify(ROOT, offline_fixtures=False)

    def test_certifier_lifecycle_uses_one_shot_local_setup_and_safe_previews(self) -> None:
        module = _load_certifier()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clone = root / "clone with spaces 日本語"
            roots = {
                "knowledge": root / "private knowledge 日本語",
                "runtime": root / "machine runtime 日本語",
            }
            homes = {host: root / "host homes" / host for host in PUBLIC_CLI_HOST_IDS}
            commands = module._local_lifecycle_commands(clone, roots, Path(sys.executable), homes)

        setup = commands["setup"]
        self.assertIn("--knowledge-mode", setup)
        self.assertEqual(setup[setup.index("--knowledge-mode") + 1], "local")
        self.assertIn("--accept-plan", setup)
        self.assertIn("--no-sync", setup)
        self.assertNotIn("--scheduler", setup)
        self.assertNotIn("knowledge", setup[:4])
        self.assertEqual(setup.count("--organizer-provider"), 1)
        self.assertEqual(setup[setup.index("--organizer-provider") + 1], "subscription-cli")
        self.assertEqual(setup.count("--organizer-host"), 1)
        self.assertEqual(setup[setup.index("--organizer-host") + 1], "codex-cli")
        self.assertIn("--check-only", commands["update_check"])
        self.assertIn("--check-only", commands["uninstall_check"])
        self.assertNotIn("--check-only", commands["uninstall_apply"])
        self.assertNotIn("--knowledge-root", commands["doctor_from_manifest"])

    def test_uninstall_apply_reuses_the_previewed_manifest_digest(self) -> None:
        module = _load_certifier()
        digest = "sha256:" + "a" * 64

        confirmed = module._confirmed_uninstall_command(
            ["-m", "ei.installer", "--uninstall", "--json"],
            {
                "ok": True,
                "manifest_sha256": digest,
                "result": {"status": "CHECK_ONLY"},
            },
        )

        self.assertEqual(confirmed[-2:], ["--confirm-manifest-sha256", digest])

    def test_uninstall_apply_rejects_a_missing_preview_digest(self) -> None:
        module = _load_certifier()

        with self.assertRaisesRegex(module.CertificationError, "UNINSTALL_CHECK_FAILED"):
            module._confirmed_uninstall_command(
                ["-m", "ei.installer", "--uninstall", "--json"],
                {"result": {"status": "CHECK_ONLY"}},
            )

    def test_closeout_fixture_is_a_valid_semantic_no_decision(self) -> None:
        module = _load_certifier()
        payload = module._closeout_fixture_payload()

        decision = GateDecision.from_mapping(payload)

        self.assertEqual(decision.decision, "NO")
        self.assertEqual(decision.reason_code, "one_off_fact")


if __name__ == "__main__":
    unittest.main()
