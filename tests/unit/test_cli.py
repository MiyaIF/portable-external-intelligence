import contextlib
import io
import inspect
import json
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import ei.installer as installer_module
import ei.cli as cli_module
from ei.cli import EXIT_INPUT, EXIT_PRIVACY, main
from ei.installer import SetupSelection, UninstallOptions, _hook_targets, _main as installer_main, _normalise_selection, _organizer_for_selection, _settings_for_selection, install as installer_install, setup as installer_setup, uninstall as installer_uninstall, update as installer_update
from ei.journal import iter_events
from ei.setup_contract import resolve_organizer


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class CliTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "config").mkdir()
        (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")

    def _direct_payload(self) -> dict[str, object]:
        return {
            "session_id": "session-private-123",
            "turn_id": "turn-private-456",
            "capture_index": 1,
            "title": "検証後の再読込",
            "claim": "外部書込後は対象範囲を再読込して数式と値を検証する",
            "source_ref": "session-local",
            "cwd": "C:/work/private-project",
            "domain": "spreadsheet-operations",
            "outcome_status": "success",
            "benefit": "avoided_failure",
            "classification": "private-reusable",
            "source_host_id": "codex-cli",
            "source_host_family": "codex-compatible",
        }

    def test_invalid_json_is_exit_two_and_secret_is_exit_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            runtime = root / "runtime"
            common = ["--repo", str(root), "--codex-home", str(root / "codex"), "--runtime-root", str(runtime)]
            self.assertEqual(main(["observe", *common, "--json-input", "{" ]), EXIT_INPUT)
            secret = json.dumps({
                "title": "bad",
                "claim": bearer_secret("A" * 32),
                "source_ref": "test",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
            })
            self.assertEqual(main(["observe", *common, "--json-input", secret]), EXIT_PRIVACY)

    def test_stdin_direct_capture_returns_result_and_hashes_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            stdout = io.StringIO()
            old_stdin = __import__("sys").stdin
            try:
                __import__("sys").stdin = io.StringIO(json.dumps(self._direct_payload(), ensure_ascii=False))
                with contextlib.redirect_stdout(stdout):
                    code = main(["observe", "--repo", str(root), "--codex-home", str(root / "codex"), "--runtime-root", str(root / "runtime"), "--stdin-json", "--json"])
            finally:
                __import__("sys").stdin = old_stdin
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["created"])
            self.assertEqual(result["reason_code"], "CREATED")
            event = next(iter_events(root / "events"))
            self.assertEqual(event.payload["capture_path"], "agent_direct")
            self.assertNotIn("session-private-123", json.dumps(event.payload, ensure_ascii=False))
            self.assertNotIn("turn-private-456", json.dumps(event.payload, ensure_ascii=False))
            self.assertNotIn("C:/work/private-project", json.dumps(event.payload, ensure_ascii=False))

    def test_stdin_payload_limit_fails_without_echoing_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            payload = self._direct_payload()
            payload["padding"] = "SENSITIVE-PADDING-" * 3000
            stdout = io.StringIO()
            old_stdin = __import__("sys").stdin
            try:
                __import__("sys").stdin = io.StringIO(json.dumps(payload))
                with contextlib.redirect_stdout(stdout):
                    code = main(["observe", "--repo", str(root), "--codex-home", str(root / "codex"), "--runtime-root", str(root / "runtime"), "--stdin-json", "--json"])
            finally:
                __import__("sys").stdin = old_stdin
            self.assertEqual(code, EXIT_INPUT)
            self.assertIn("CAPTURE_PAYLOAD_TOO_LARGE", stdout.getvalue())
            self.assertNotIn("SENSITIVE-PADDING", stdout.getvalue())

    def test_closeout_input_json_reads_a_file_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            input_path = root / "closeout.json"
            input_path.write_text(
                json.dumps({"decision": "NO", "reason_code": "no_evidence", "classification": "private-reusable"}),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = __import__("ei.cli", fromlist=["main"]).main(
                    [
                        "closeout",
                        "--repo", str(root), "--codex-home", str(root / "codex"),
                        "--runtime-root", str(Path(str(root) + "-runtime")),
                        "--input-json", str(input_path),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "discarded")
    def test_inventory_existing_writes_sanitized_report(self):
        fixture = Path("tests/fixtures/migration/legacy-memory-repo")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            source = root / "memories"
            shutil.copytree(fixture, source)
            report = root / "inventory.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "inventory-existing",
                        "--repo",
                        str(root),
                        "--codex-home",
                        str(root / "codex"),
                        "--memory-root",
                        str(source),
                        "--inventory",
                        str(report),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            value = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(value["balance_holds"])
            self.assertEqual(value["counts"]["unclassified"], 0)
            self.assertNotIn(str(source), report.read_text(encoding="utf-8"))
            self.assertIn(value["inventory_hash"], stdout.getvalue())

    def _setup_arguments(self, root: Path) -> list[str]:
        return [
            "setup",
            "--repo",
            str(Path.cwd()),
            "--knowledge-mode",
            "local",
            "--knowledge-root",
            str(root / "private knowledge"),
            "--runtime-root",
            str(root / "runtime"),
            "--hosts",
            "codex-cli",
            "--organizer-provider",
            "ollama",
            "--host-home",
            f"codex-cli={root / 'host home'}",
            "--python-exe",
            sys.executable,
            "--skip-venv",
        ]

    def test_setup_personal_alias_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaisesRegex(ValueError, "PERSONAL_KNOWLEDGE_ROOT_CONFLICT"):
                SetupSelection(
                    engine_root=root / "engine",
                    knowledge_root=root / "legacy",
                    personal_knowledge_root=root / "personal",
                    runtime_root=root / "runtime",
                )

    def test_team_flags_are_mutually_exclusive(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "setup",
                    "--repo",
                    str(Path.cwd()),
                    "--team-knowledge-root",
                    "shared",
                    "--team-member-id",
                    "member-a",
                    "--no-team-knowledge",
                    "--json",
                ]
            )
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "ARGUMENTS_INVALID")

    def test_team_knowledge_is_tri_state_and_member_requires_enablement(self) -> None:
        omitted = SetupSelection()
        self.assertIsNone(omitted.team_knowledge)
        disabled = SetupSelection(team_knowledge=False)
        self.assertFalse(disabled.team_knowledge)
        enabled = SetupSelection(team_knowledge_root="shared", team_member_id="member-a")
        self.assertTrue(enabled.team_knowledge)
        self.assertEqual(enabled.team_member_id, "member-a")
        with self.assertRaisesRegex(ValueError, "TEAM_MEMBER_ID_REQUIRED"):
            SetupSelection(team_knowledge_root="shared")

    def test_noninteractive_check_only_accepts_explicit_one_shot_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([*self._setup_arguments(root), "--non-interactive", "--accept-plan", "--check-only", "--json"])
            self.assertEqual(code, 0, output.getvalue())
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["status"], "CHECK_ONLY")
            self.assertEqual(payload["knowledge"]["mode"], "local")
            self.assertFalse((root / "private knowledge").exists())
            self.assertFalse((root / "runtime").exists())

    def test_already_current_check_only_json_exposes_no_mutation_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                first_code = main([*self._setup_arguments(root), "--non-interactive", "--accept-plan", "--json"])
            self.assertEqual(first_code, 0)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([*self._setup_arguments(root), "--non-interactive", "--accept-plan", "--check-only", "--json"])
            self.assertEqual(code, 0, output.getvalue())
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["status"], "CHECK_ONLY")
            self.assertEqual(payload["reconciliation"]["status"], "ALREADY_CURRENT")
            self.assertEqual(payload["plan"], [])
            self.assertFalse(
                any(item.get("action") in {"create", "update", "remove", "create-or-update"} for item in payload["plan"])
            )

    def test_noninteractive_apply_without_accept_plan_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([*self._setup_arguments(root), "--non-interactive", "--json"])
            self.assertEqual(code, EXIT_INPUT)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "SETUP_PLAN_ACCEPTANCE_REQUIRED")
            self.assertFalse((root / "private knowledge").exists())
            self.assertFalse((root / "runtime").exists())

    def test_noninteractive_setup_requires_explicit_organizer_and_work_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            arguments = [
                "setup",
                "--repo",
                str(Path.cwd()),
                "--knowledge-mode",
                "local",
                "--knowledge-root",
                str(root / "knowledge"),
                "--runtime-root",
                str(root / "runtime"),
                "--non-interactive",
                "--accept-plan",
                "--json",
            ]
            with contextlib.redirect_stdout(output):
                code = main(arguments)

            self.assertEqual(code, EXIT_INPUT)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "SETUP_NON_INTERACTIVE_PATHS_AND_HOSTS_REQUIRED")

    def test_explicit_unresolved_organizer_does_not_fallback_to_legacy_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selected = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "knowledge",
                runtime_root=root / "runtime",
                work_hosts=("codex-cli",),
                providers=("ollama",),
                organizer_provider="subscription-cli",
                skip_venv=True,
            )

            normalized = _normalise_selection(selected)
            organizer = _organizer_for_selection(normalized, Path.cwd())

            self.assertEqual(organizer.status, "SELECTION_REQUIRED")
            self.assertEqual(normalized.organizer_provider, "subscription-cli")
            self.assertIsNone(normalized.organizer_host)

    def test_explicit_ready_organizer_replaces_legacy_provider_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normalized = _normalise_selection(
                SetupSelection(
                    engine_root=Path.cwd(),
                    knowledge_root=root / "knowledge",
                    runtime_root=root / "runtime",
                    work_hosts=("codex-cli",),
                    providers=("ollama", "subscription-cli"),
                    organizer_provider="subscription-cli",
                    organizer_host="codex-cli",
                    skip_venv=True,
                )
            )

            self.assertEqual(normalized.providers, ("subscription-cli",))

    def test_resolve_organizer_rejects_empty_work_hosts(self):
        result = resolve_organizer("ollama", None, (), {"ollama"})

        self.assertEqual(result.status, "SELECTION_REQUIRED")
        self.assertEqual(result.reason_code, "ORGANIZER_SELECTION_REQUIRED")

    def test_direct_selection_rejects_empty_work_hosts_without_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "WORK_HOSTS_REQUIRED"):
                _normalise_selection(
                    SetupSelection(
                        engine_root=Path.cwd(),
                        knowledge_root=root / "knowledge",
                        runtime_root=root / "runtime",
                        hosts=(),
                        work_hosts=(),
                        organizer_provider="ollama",
                        skip_venv=True,
                    )
                )

    def test_legacy_install_and_caller_pass_explicit_organizer(self):
        self.assertIn("organizer_provider", inspect.signature(installer_install).parameters)
        self.assertIn("organizer_host", inspect.signature(installer_install).parameters)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with patch("ei.installer.install", return_value={"ok": True}) as install_mock, patch.object(
                sys,
                "argv",
                [
                    "ei.installer",
                    "--repo",
                    str(Path.cwd()),
                    "--codex-home",
                    str(root / "codex"),
                    "--skip-venv",
                    "--organizer-provider",
                    "subscription-cli",
                    "--organizer-host",
                    "codex-cli",
                ],
            ), contextlib.redirect_stdout(output):
                code = installer_main()

            self.assertEqual(code, 0, output.getvalue())
            call = install_mock.call_args
            self.assertEqual(call.kwargs["organizer_provider"], "subscription-cli")
            self.assertEqual(call.kwargs["organizer_host"], "codex-cli")

    def test_multiple_legacy_provider_values_require_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            arguments = [
                *self._setup_arguments(root),
                "--providers",
                "ollama",
                "--providers",
                "subscription-cli",
                "--non-interactive",
                "--accept-plan",
                "--check-only",
                "--json",
            ]
            with contextlib.redirect_stdout(output):
                code = main(arguments)

            self.assertEqual(code, EXIT_INPUT)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "ORGANIZER_SELECTION_REQUIRED")

    def test_json_setup_without_noninteractive_is_rejected_without_prompting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([*self._setup_arguments(root), "--accept-plan", "--json"])
            self.assertEqual(code, EXIT_INPUT)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "SETUP_JSON_REQUIRES_NON_INTERACTIVE")

    def test_interactive_wizard_collects_roots_mode_and_final_approval(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "chosen knowledge"
            runtime = root / "chosen runtime"
            fake_result = __import__("unittest.mock", fromlist=["Mock"]).Mock()
            fake_result.ok = True
            fake_result.to_dict.return_value = {"ok": True, "status": "SETUP_COMPLETE"}
            answers = [
                "",
                "ollama",
                "local",
                str(knowledge),
                str(runtime),
                "no",
                "",
                "",
                "",
                "",
                "",
                "",
                "yes",
            ]
            output = io.StringIO()
            old_stdin = sys.stdin
            try:
                sys.stdin = Tty()
                with patch("ei.installer.Path.home", return_value=root / "user-home"), patch("builtins.input", side_effect=answers), patch("ei.cli.installer_setup", return_value=fake_result) as install, contextlib.redirect_stdout(output):
                    code = main(
                        [
                            "setup",
                            "--repo",
                            str(Path.cwd()),
                            "--host-home",
                            f"codex-cli={root / 'host home'}",
                            "--python-exe",
                            sys.executable,
                            "--skip-venv",
                        ]
                    )
            finally:
                sys.stdin = old_stdin
            self.assertEqual(code, 0, output.getvalue())
            selection = install.call_args.args[0]
            self.assertEqual(selection.knowledge_mode, "local")
            self.assertEqual(Path(selection.knowledge_root), knowledge.resolve())
            self.assertEqual(Path(selection.runtime_root), runtime.resolve())
            self.assertTrue(selection.accept_plan)
            self.assertIn("Setup plan", output.getvalue())

    def test_interactive_wizard_explains_roles_and_accepts_multiple_work_hosts(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            fake_result = __import__("unittest.mock", fromlist=["Mock"]).Mock()
            fake_result.ok = True
            fake_result.to_dict.return_value = {"ok": True, "status": "SETUP_COMPLETE"}
            answers = [
                "1",       # organizer provider: subscription CLI
                "1",       # organizer host: Codex CLI
                "1,2",     # work hosts: Codex CLI and Claude Code
                "no",      # custom compatible CLI
                "local",   # knowledge mode
                str(knowledge),
                str(runtime),
                "no",      # optional team knowledge
                "yes",     # apply the final summary
            ]
            output = io.StringIO()
            old_stdin = sys.stdin
            try:
                sys.stdin = Tty()
                with patch("ei.installer.Path.home", return_value=root / "user-home"), patch("builtins.input", side_effect=answers), patch("ei.cli.installer_setup", return_value=fake_result) as install, contextlib.redirect_stdout(output):
                    code = main(
                        [
                            "setup",
                            "--repo",
                            str(Path.cwd()),
                            "--host-home",
                            f"codex-cli={root / 'codex home'}",
                            "--host-home",
                            f"claude-code={root / 'claude home'}",
                            "--python-exe",
                            sys.executable,
                            "--skip-venv",
                        ]
                    )
            finally:
                sys.stdin = old_stdin
            self.assertEqual(code, 0, output.getvalue())
            rendered = output.getvalue()
            self.assertIn("外部知能は1つ", rendered)
            self.assertIn("記憶の整理AI", rendered)
            self.assertIn("作業・記憶取得CLI", rendered)
            self.assertIn("複数選べます", rendered)
            selection = install.call_args.args[0]
            self.assertEqual(selection.organizer_provider, "subscription-cli")
            self.assertEqual(selection.organizer_host, "codex-cli")
            self.assertEqual(selection.work_hosts, ("codex-cli", "claude-code"))
            self.assertTrue(selection.accept_plan)

    def test_status_separates_one_organizer_from_all_work_hosts_and_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "runtime" / "install-manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "organizer": {"status": "READY", "provider_id": "subscription-cli", "host_id": "codex-cli"},
                        "work_hosts": ["codex-cli", "claude-code"],
                        "hosts": {"codex-cli": {}, "claude-code": {}},
                    }
                ),
                encoding="utf-8",
            )
            paths = SimpleNamespace(
                install_manifest_path=manifest_path,
                local_state_dir=root / "state",
                runtime_root=root / "runtime",
                event_dir=root / "events",
            )
            settings = SimpleNamespace(
                paths=paths,
                hosts={},
                sync_enabled=False,
                experiment_enabled=False,
                experiment_id="retrieval-v1",
            )
            output = io.StringIO()
            with patch("ei.cli._status_host", side_effect=lambda _settings, _manifest, host_id: {"host_id": host_id, "hook": {}, "skill": {}, "capture_primary": "NATIVE_SOURCE"}), patch(
                "ei.cli.queue_health", return_value=SimpleNamespace(to_dict=lambda: {"status": "ready"})
            ), patch("ei.cli.spool_health", return_value=SimpleNamespace(to_dict=lambda: {"status": "ready"})), patch(
                "ei.cli._capture_health", return_value={"status": "ready"}
            ), patch("ei.cli._provider_status", return_value={"status": "ready"}), patch(
                "ei.cli._projection_status", return_value={"status": "ready"}
            ), patch("ei.cli.team_status_snapshot", return_value={"status": "DISABLED"}), patch(
                "ei.cli.measurement_paths", return_value={"exposures": root / "e", "outcomes": root / "o"}
            ), patch("ei.cli.read_measurement_records", return_value=[]), contextlib.redirect_stdout(output):
                code = cli_module._status(SimpleNamespace(settings=settings, host=[]))
            self.assertEqual(code, 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value["organizer"]["provider_id"], "subscription-cli")
            self.assertEqual(value["organizer"]["host_id"], "codex-cli")
            self.assertEqual(value["work_hosts"], ["codex-cli", "claude-code"])
            self.assertEqual(value["queue"], {"status": "ready"})

    def test_interactive_wizard_builds_custom_profile_without_writing_before_approval(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = __import__("unittest.mock", fromlist=["Mock"]).Mock()
            result.ok = True
            result.to_dict.return_value = {"ok": True, "status": "SETUP_COMPLETE"}
            answers = [
                "1", "1", "1", "yes", "1", "1", "Test Compatible CLI",
                "test-compatible", str(root / "custom-home"),
                ".config/test/settings.json", ".config/test/context.md", ".config/test/skills",
                "local", str(root / "knowledge"), str(root / "runtime"), "no", "yes",
            ]
            output = io.StringIO()
            old_stdin = sys.stdin
            try:
                sys.stdin = Tty()
                with patch("ei.installer.Path.home", return_value=root / "user-home"), patch("builtins.input", side_effect=answers), patch("ei.cli.installer_setup", return_value=result) as install, contextlib.redirect_stdout(output):
                    code = main(
                        [
                            "setup", "--repo", str(Path.cwd()),
                            "--host-home", f"codex-cli={root / 'codex-home'}",
                            "--python-exe", sys.executable, "--skip-venv",
                        ]
                    )
            finally:
                sys.stdin = old_stdin
            self.assertEqual(code, 0, output.getvalue())
            selection = install.call_args.args[0]
            self.assertEqual(selection.work_hosts, ("codex-cli", "test-compatible-cli"))
            self.assertEqual(selection.host_profile_documents["test-compatible-cli"]["adapter_id"], "codex-cli")
            self.assertFalse((root / "runtime" / "host-profiles").exists())

    def test_guided_rerun_without_runtime_flag_restores_default_runtime_and_team(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user_home = root / "user-home"
            codex_home = root / "codex-home"
            custom_home = root / "custom-home"
            personal = root / "personal-knowledge"
            team = root / "team-knowledge"
            default_runtime = user_home / ".external-intelligence" / "runtime"
            first_answers = [
                "1", "1", "1", "yes", "new", "1", "Test Compatible CLI",
                "test-compatible", str(custom_home), ".config/test/settings.json",
                ".config/test/context.md", ".config/test/skills", "1", str(personal),
                "", "yes", str(team), "member-a", "yes",
            ]
            second_answers = ["", "", "", "no", "", "", "yes"]
            args = [
                "setup", "--repo", str(Path.cwd()), "--host-home", f"codex-cli={codex_home}",
                "--python-exe", sys.executable, "--skip-venv",
            ]
            old_stdin = sys.stdin
            try:
                with patch("ei.installer.Path.home", return_value=user_home), patch("builtins.input", side_effect=first_answers):
                    sys.stdin = Tty()
                    self.assertEqual(main(args), 0)
                self.assertTrue((default_runtime / "install-manifest.json").is_file())
                # Keep the marker inside the allowlisted members tree so the
                # team-store contract remains valid on the rerun.
                sentinel = team / "members" / "member-a" / "keep.json"
                sentinel.parent.mkdir(parents=True, exist_ok=True)
                sentinel.write_text("keep", encoding="utf-8")
                with patch("ei.installer.Path.home", return_value=user_home), patch("builtins.input", side_effect=second_answers):
                    sys.stdin = Tty()
                    self.assertEqual(main(["setup", "--repo", str(Path.cwd()), "--python-exe", sys.executable, "--skip-venv"]), 0)
            finally:
                sys.stdin = old_stdin
            manifest = json.loads((default_runtime / "install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["runtime_root"], str(default_runtime.resolve()))
            self.assertEqual(manifest["knowledge_root"], str(personal.resolve()))
            self.assertEqual(manifest["work_hosts"], ["codex-cli", "test-compatible-cli"])
            self.assertEqual(manifest["organizer"]["provider_id"], "subscription-cli")
            self.assertTrue(manifest["knowledge_stores"]["team"]["enabled"])
            self.assertEqual(manifest["knowledge_stores"]["team"]["team_member_id"], "member-a")
            self.assertTrue((default_runtime / "host-profiles" / "test-compatible-cli.json").is_file())
            self.assertTrue(sentinel.is_file())

    def test_noninteractive_github_new_requires_exact_confirmation_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            arguments = self._setup_arguments(root)
            mode_index = arguments.index("local")
            arguments[mode_index] = "github-new"
            arguments.extend(["--github-repository", "MiyaIF/private-knowledge", "--non-interactive", "--accept-plan", "--json"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(arguments)
            self.assertEqual(code, EXIT_INPUT)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "GITHUB_CREATE_CONFIRMATION_REQUIRED")
            self.assertFalse((root / "private knowledge").exists())
            self.assertFalse((root / "runtime").exists())

    def test_public_setup_installs_synthetic_profile_and_persists_custom_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "test-compatible-cli",
                        "display_name": "Test Compatible CLI",
                        "host_family": "gemini-compatible",
                        "adapter_id": "gemini-cli",
                        "executable_names": ["test-compatible"],
                        "hook_config_path": ".config/test-compatible/settings.json",
                        "global_context_path": ".config/test-compatible/context.md",
                        "skill_roots": [".config/test-compatible/skills"],
                    }
                ),
                encoding="utf-8",
            )
            custom_home = root / "custom-home"
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            output = io.StringIO()
            arguments = [
                "setup",
                "--repo",
                str(Path.cwd()),
                "--knowledge-mode",
                "local",
                "--knowledge-root",
                str(knowledge),
                "--runtime-root",
                str(runtime),
                "--work-host",
                "test-compatible-cli",
                "--host-profile",
                str(profile),
                "--host-home",
                f"test-compatible-cli={custom_home}",
                "--organizer-provider",
                "ollama",
                "--python-exe",
                sys.executable,
                "--skip-venv",
                "--non-interactive",
                "--accept-plan",
                "--json",
            ]
            with contextlib.redirect_stdout(output):
                code = main(arguments)

            self.assertEqual(code, 0, output.getvalue())
            manifest = json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["supported_hosts"], ["codex-cli", "claude-code", "gemini-cli", "qwen-code"])
            self.assertEqual(manifest["work_hosts"], ["test-compatible-cli"])
            record = manifest["hosts"]["test-compatible-cli"]
            self.assertEqual(record["host_id"], "test-compatible-cli")
            self.assertRegex(record["profile_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(record["profile_path"], "host-profiles/test-compatible-cli.json")
            self.assertNotIn(str(profile), json.dumps(manifest))

    def test_public_setup_check_only_does_not_install_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "test-compatible-cli",
                        "display_name": "Test Compatible CLI",
                        "host_family": "gemini-compatible",
                        "adapter_id": "gemini-cli",
                        "executable_names": ["test-compatible"],
                        "hook_config_path": ".config/test-compatible/settings.json",
                        "global_context_path": ".config/test-compatible/context.md",
                        "skill_roots": [".config/test-compatible/skills"],
                    }
                ),
                encoding="utf-8",
            )
            runtime = root / "runtime"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "setup",
                        "--repo",
                        str(Path.cwd()),
                        "--knowledge-mode",
                        "local",
                        "--knowledge-root",
                        str(root / "knowledge"),
                        "--runtime-root",
                        str(runtime),
                        "--work-host",
                        "test-compatible-cli",
                        "--host-profile",
                        str(profile),
                        "--host-home",
                        f"test-compatible-cli={root / 'custom-home'}",
                        "--organizer-provider",
                        "ollama",
                        "--python-exe",
                        sys.executable,
                        "--skip-venv",
                        "--non-interactive",
                        "--accept-plan",
                        "--check-only",
                        "--json",
                    ]
                )

            self.assertEqual(code, 0, output.getvalue())
            self.assertFalse(runtime.exists())

    def test_rejected_profile_setup_does_not_install_runtime_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "test-compatible-cli",
                        "display_name": "Test Compatible CLI",
                        "host_family": "gemini-compatible",
                        "adapter_id": "gemini-cli",
                        "executable_names": ["test-compatible"],
                        "hook_config_path": ".config/test-compatible/settings.json",
                        "global_context_path": ".config/test-compatible/context.md",
                        "skill_roots": [".config/test-compatible/skills"],
                    }
                ),
                encoding="utf-8",
            )
            runtime = root / "runtime"
            selection = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "knowledge",
                runtime_root=runtime,
                work_hosts=("test-compatible-cli",),
                host_profiles=(profile,),
                host_homes={"test-compatible-cli": root / "custom-home"},
                organizer_provider="ollama",
                python_exe=sys.executable,
                skip_venv=True,
                non_interactive=True,
            )
            with self.assertRaisesRegex(ValueError, "SETUP_PLAN_ACCEPTANCE_REQUIRED"):
                installer_setup(selection)
            self.assertFalse(runtime.exists())

    def test_profile_update_is_transactional_and_check_only_preserves_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            document = {
                "schema_version": 1,
                "host_id": "test-compatible-cli",
                "display_name": "Test Compatible CLI",
                "host_family": "gemini-compatible",
                "adapter_id": "gemini-cli",
                "executable_names": ["test-compatible"],
                "hook_config_path": ".config/test-compatible/settings.json",
                "global_context_path": ".config/test-compatible/context.md",
                "skill_roots": [".config/test-compatible/skills"],
            }
            profile.write_text(json.dumps(document), encoding="utf-8")
            runtime = root / "runtime"
            home = root / "custom-home"
            knowledge = root / "knowledge"

            def selection() -> SetupSelection:
                return SetupSelection(
                    engine_root=Path.cwd(),
                    knowledge_root=knowledge,
                    runtime_root=runtime,
                    work_hosts=("test-compatible-cli",),
                    host_profiles=(profile,),
                    host_homes={"test-compatible-cli": home},
                    organizer_provider="ollama",
                    python_exe=sys.executable,
                    skip_venv=True,
                    non_interactive=True,
                    accept_plan=True,
                )

            first = installer_setup(selection())
            self.assertTrue(first.ok, first.to_dict())
            runtime_profile = runtime / "host-profiles" / "test-compatible-cli.json"
            manifest_path = runtime / "install-manifest.json"
            original_profile = runtime_profile.read_bytes()
            original_manifest = manifest_path.read_bytes()

            tampered = json.loads(original_profile.decode("utf-8"))
            tampered["display_name"] = "Tampered Runtime Profile"
            runtime_profile.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_MANIFEST_MISMATCH"):
                installer_setup(selection(), check_only=True)
            runtime_profile.write_bytes(original_profile)

            wrong_locator = json.loads(original_manifest.decode("utf-8"))
            wrong_locator["hosts"]["test-compatible-cli"]["profile_path"] = "host-profiles/wrong.json"
            manifest_path.write_text(json.dumps(wrong_locator), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ACTIVE_INSTALL_MANIFEST_INVALID"):
                installer_setup(selection(), check_only=True)
            manifest_path.write_bytes(original_manifest)

            document["display_name"] = "Updated Test Compatible CLI"
            profile.write_text(json.dumps(document), encoding="utf-8")
            check = installer_setup(selection(), check_only=True)
            self.assertTrue(check.ok, check.to_dict())
            self.assertEqual(runtime_profile.read_bytes(), original_profile)
            self.assertEqual(manifest_path.read_bytes(), original_manifest)

            updated = installer_setup(selection())
            self.assertTrue(updated.ok, updated.to_dict())
            updated_profile = runtime_profile.read_bytes()
            updated_manifest = manifest_path.read_bytes()
            self.assertNotEqual(updated_profile, original_profile)
            self.assertNotEqual(updated_manifest, original_manifest)

            document["display_name"] = "Failed Test Compatible CLI"
            profile.write_text(json.dumps(document), encoding="utf-8")
            with patch("ei.installer.write_schema_v7_manifest", side_effect=ValueError("INJECTED_MANIFEST_FAILURE")):
                failed = installer_setup(selection())
            self.assertFalse(failed.ok)
            self.assertEqual(runtime_profile.read_bytes(), updated_profile)
            self.assertEqual(manifest_path.read_bytes(), updated_manifest)

    def test_manifest_profile_is_rehydrated_for_update_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            document = {
                "schema_version": 1,
                "host_id": "test-compatible-cli",
                "display_name": "Test Compatible CLI",
                "host_family": "gemini-compatible",
                "adapter_id": "gemini-cli",
                "executable_names": ["test-compatible"],
                "hook_config_path": ".config/test-compatible/settings.json",
                "global_context_path": ".config/test-compatible/context.md",
                "skill_roots": [".config/test-compatible/skills"],
            }
            profile.write_text(json.dumps(document), encoding="utf-8")
            runtime = root / "runtime"
            selection = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "knowledge",
                runtime_root=runtime,
                work_hosts=("test-compatible-cli",),
                host_profiles=(profile,),
                host_homes={"test-compatible-cli": root / "custom-home"},
                organizer_provider="ollama",
                python_exe=sys.executable,
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            settings = _settings_for_selection(selection)
            installed = installer_setup(selection)
            self.assertTrue(installed.ok, installed.to_dict())
            manifest_path = runtime / "install-manifest.json"
            runtime_profile = runtime / "host-profiles" / "test-compatible-cli.json"
            profile.unlink()

            checked_update = installer_update(settings, check_only=True)
            self.assertTrue(checked_update.ok, checked_update.to_dict())
            original_atomic_write = installer_module._atomic_write

            def fail_preflight(path: Path, raw: bytes) -> None:
                if path.name == "update-preflight.json":
                    raise OSError("injected preflight write failure")
                original_atomic_write(path, raw)

            with patch("ei.installer._atomic_write", side_effect=fail_preflight):
                blocked_preflight = installer_update(settings)
            self.assertFalse(blocked_preflight.ok)
            self.assertEqual(blocked_preflight.status, "DIAGNOSTICS_BLOCKED")
            self.assertEqual(blocked_preflight.rollback.get("status"), "INSTALLATION_RETAINED")
            self.assertFalse(blocked_preflight.rollback.get("rolled_back"))
            self.assertTrue(manifest_path.is_file())

            applied_update = installer_update(settings)
            self.assertTrue(applied_update.ok, applied_update.to_dict())
            def fail_invalidation(path: Path, raw: bytes) -> None:
                if path.name == "canary-invalidation.json":
                    raise OSError("injected invalidation write failure")
                original_atomic_write(path, raw)

            with patch("ei.installer._atomic_write", side_effect=fail_invalidation):
                blocked_invalidation = installer_update(settings)
            self.assertFalse(blocked_invalidation.ok)
            self.assertEqual(blocked_invalidation.status, "DIAGNOSTICS_BLOCKED")
            self.assertEqual(blocked_invalidation.rollback.get("status"), "INSTALLATION_RETAINED")
            self.assertFalse(blocked_invalidation.rollback.get("rolled_back"))
            checked_uninstall = installer_uninstall(manifest_path, UninstallOptions(check_only=True))
            self.assertTrue(checked_uninstall["ok"], checked_uninstall)

            tampered = json.loads(runtime_profile.read_text(encoding="utf-8"))
            tampered["display_name"] = "Tampered Runtime Profile"
            runtime_profile.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_MANIFEST_MISMATCH"):
                installer_update(settings, check_only=True)
            runtime_profile.write_bytes(json.dumps(document, sort_keys=True, indent=2).encode("utf-8") + b"\n")
            runtime_profile.unlink()
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE"):
                installer_uninstall(manifest_path, UninstallOptions(check_only=True))
            runtime_profile.write_bytes(json.dumps(document, sort_keys=True, indent=2).encode("utf-8") + b"\n")
            uninstalled = installer_uninstall(manifest_path, UninstallOptions(remove_runtime=False))
            self.assertTrue(uninstalled["ok"], uninstalled)

    def test_host_id_aliases_collide_and_custom_codex_adapter_uses_profile_path(self):
        with self.assertRaisesRegex(ValueError, "HOST_ID_COLLISION"):
            SetupSelection(work_hosts=("codex", "codex-cli"))
        with self.assertRaisesRegex(ValueError, "HOST_ID_INVALID"):
            SetupSelection(work_hosts=("MyCLI",))
        self.assertEqual(SetupSelection(work_hosts=("CODEX",)).work_hosts, ("codex-cli",))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "test-compatible-cli.profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "test-compatible-cli",
                        "display_name": "Codex Compatible Fixture",
                        "host_family": "codex-compatible",
                        "adapter_id": "codex-cli",
                        "executable_names": ["fixture-compatible"],
                        "hook_config_path": "settings.json",
                        "global_context_path": "AGENTS.md",
                        "skill_roots": ["skills"],
                    }
                ),
                encoding="utf-8",
            )
            home = root / "custom-home"
            selection = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "knowledge",
                runtime_root=root / "runtime",
                work_hosts=("test-compatible-cli",),
                host_profiles=(profile,),
                host_homes={"test-compatible-cli": home},
                organizer_provider="ollama",
                python_exe=sys.executable,
                skip_venv=True,
            )
            settings = _settings_for_selection(selection)
            targets, _ = _hook_targets(settings, selection.managed_hosts, Path.cwd(), Path(sys.executable))
            self.assertIn((home / "settings.json").resolve(), targets)
            self.assertNotIn(settings.paths.hooks_path, targets)

    def test_host_migration_receipt_ids_use_canonical_host_rule(self):
        selected = SetupSelection(
            work_hosts=("codex-cli",),
            legacy_host_migrations=(
                {
                    "from_host_id": "CODEX",
                    "to_host_id": "CODEX-CLI",
                    "status": "MIGRATED_TO_CLI",
                    "reason_code": "HOST_UNSUPPORTED",
                },
            ),
        )
        self.assertEqual(selected.legacy_host_migrations[0]["from_host_id"], "codex-cli")
        self.assertEqual(selected.legacy_host_migrations[0]["to_host_id"], "codex-cli")
        with self.assertRaisesRegex(ValueError, "HOST_ID_INVALID"):
            SetupSelection(
                work_hosts=("codex-cli",),
                legacy_host_migrations=(
                    {
                        "from_host_id": "MyCLI",
                        "to_host_id": None,
                        "status": "UNSUPPORTED",
                        "reason_code": "HOST_UNSUPPORTED",
                    },
                ),
            )


if __name__ == "__main__":
    unittest.main()
