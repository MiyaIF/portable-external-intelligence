import json
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace

from ei.canary import _command_ok, static_canary
from ei.command_quote import build_hook_argv, quote_posix_command, quote_windows_command
from ei.config import RuntimePaths
from ei.hooks.base import parse_hook_command
from ei.hooks.registry import hook_config_fragment
from ei.install_config import validate_hook_commands
from tests.helpers import make_hook_settings


def _canonical_commands() -> tuple[tuple[str, ...], str, str]:
    host_home = str(Path("C:/") / "Users" / "tester" / ".codex")
    argv = build_hook_argv(
        r"C:\Program Files\Python\python.exe",
        host_id="codex-cli",
        engine_root=r"C:\engine root",
        knowledge_root=r"C:\private knowledge",
        runtime_root=r"C:\machine runtime",
        host_home=host_home,
    )
    return argv, quote_posix_command(argv), quote_windows_command(argv)


def _fragment(posix_command: str, windows_command: str | None = None) -> dict[str, object]:
    handler: dict[str, object] = {"type": "command", "command": posix_command}
    if windows_command is not None:
        handler["commandWindows"] = windows_command
    return {"hooks": {"SessionStart": [{"hooks": [handler]}]}}


def _render(argv: tuple[str, ...], platform: str) -> str:
    return quote_windows_command(argv) if platform == "windows" else quote_posix_command(argv)


def _replace_command_values(value: object, posix_command: str, windows_command: str) -> object:
    if isinstance(value, dict):
        result = {key: _replace_command_values(child, posix_command, windows_command) for key, child in value.items()}
        if result.get("type") == "command":
            if "command" in result:
                result["command"] = posix_command
            if "commandWindows" in result:
                result["commandWindows"] = windows_command
        return result
    if isinstance(value, list):
        return [_replace_command_values(child, posix_command, windows_command) for child in value]
    return value


class HookCommandValidationTests(unittest.TestCase):
    def test_all_adapter_fragments_are_consumable_by_the_shared_validator(self) -> None:
        for host_id in ("codex-cli", "codex-app", "claude-code", "gemini-cli", "qwen-code"):
            with self.subTest(host_id=host_id):
                fragment = hook_config_fragment(
                    host_id,
                    r"C:\Program Files\Python\python.exe",
                    r"C:\engine root",
                    r"C:\knowledge root",
                    r"C:\runtime root",
                )
                validate_hook_commands({"hooks": {"SessionStart": [{"hooks": [fragment]}]}})

    def test_platform_parsers_round_trip_builder_output_only(self) -> None:
        argv, posix_command, windows_command = _canonical_commands()

        self.assertEqual(parse_hook_command(posix_command, "posix"), argv)
        self.assertEqual(parse_hook_command(windows_command, "windows"), argv)

        noncanonical_posix = posix_command.replace("'", '"', 2)
        noncanonical_windows = windows_command.replace(" -B ", ' "-B" ', 1)
        with self.assertRaises(ValueError):
            parse_hook_command(noncanonical_posix, "posix")
        with self.assertRaises(ValueError):
            parse_hook_command(noncanonical_windows, "windows")

    def test_validator_accepts_only_the_canonical_posix_and_windows_pair(self) -> None:
        argv, posix_command, windows_command = _canonical_commands()

        validate_hook_commands(_fragment(posix_command, windows_command))
        self.assertTrue(_command_ok(posix_command, "codex-cli"))
        self.assertTrue(_command_ok(windows_command, "codex-cli"))

        mutations: dict[str, tuple[str, ...]] = {}

        python_c = list(argv)
        python_c[1:1] = ["-c", "print(1)"]
        mutations["python -c"] = tuple(python_c)

        stdin_mode = list(argv)
        stdin_mode[1:1] = ["-"]
        mutations["stdin mode"] = tuple(stdin_mode)

        mutations["extra argument"] = (*argv, "--stdin-json")
        engine_flag = argv.index("--engine-root")
        knowledge_flag = argv.index("--knowledge-root")
        mutations["duplicate argument"] = (*argv, "--engine-root", argv[engine_flag + 1])

        reordered = list(argv)
        reordered[engine_flag : knowledge_flag + 2] = [
            argv[knowledge_flag],
            argv[knowledge_flag + 1],
            argv[engine_flag],
            argv[engine_flag + 1],
        ]
        mutations["order changed"] = tuple(reordered)

        wrong_module = list(argv)
        wrong_module[wrong_module.index("ei.hook_entry")] = "ei.other_entry"
        mutations["wrong module"] = tuple(wrong_module)

        wrong_executable = list(argv)
        wrong_executable[0] = "node"
        mutations["wrong executable"] = tuple(wrong_executable)

        for name, mutated in mutations.items():
            with self.subTest(name=name):
                posix_mutation = _render(mutated, "posix")
                windows_mutation = _render(mutated, "windows")
                with self.assertRaises(ValueError):
                    validate_hook_commands(_fragment(posix_mutation, windows_mutation))
                self.assertFalse(_command_ok(posix_mutation, "codex-cli"))
                self.assertFalse(_command_ok(windows_mutation, "codex-cli"))

    def test_validator_rejects_platform_commands_that_decode_to_different_argv(self) -> None:
        argv, posix_command, _ = _canonical_commands()
        different_host = list(argv)
        different_host[different_host.index("--host-id") + 1] = "codex-app"

        with self.assertRaises(ValueError):
            validate_hook_commands(_fragment(posix_command, _render(tuple(different_host), "windows")))

    def test_static_canary_rejects_a_tampered_installed_managed_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = make_hook_settings(root)
            runtime = root.parent / (root.name + "-runtime")
            paths = RuntimePaths(
                repo_root=root,
                codex_home=root / "codex",
                runtime_dir=runtime,
                event_dir=root / "events",
                knowledge_dir=root / "knowledge",
                local_state_dir=runtime / "state",
                metrics_dir=runtime / "metrics",
                cache_dir=runtime / "cache",
                locks_dir=runtime / "locks",
                config_path=root / "codex" / "config.toml",
                hooks_path=root / "codex" / "hooks.json",
                agents_path=root / "codex" / "AGENTS.md",
            )
            settings = replace(base, paths=paths)
            source_root = Path(__file__).parents[2]
            template_path = source_root / "hooks" / "codex" / "hooks.template.json"
            template = json.loads(template_path.read_text(encoding="utf-8"))
            target = root / "hooks" / "codex" / "hooks.template.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(template), encoding="utf-8")
            schema_target = root / "schemas" / "hook-event.schema.json"
            schema_target.parent.mkdir(parents=True, exist_ok=True)
            schema_target.write_bytes((source_root / "schemas" / "hook-event.schema.json").read_bytes())
            settings.paths.config_path.parent.mkdir(parents=True, exist_ok=True)
            settings.paths.config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")

            argv, _, _ = _canonical_commands()
            tampered = list(argv)
            tampered[1:1] = ["-c", "print(1)"]
            installed = _replace_command_values(template, _render(tuple(tampered), "posix"), _render(tuple(tampered), "windows"))
            settings.paths.hooks_path.write_text(json.dumps(installed), encoding="utf-8")

            result = static_canary("codex-cli", "cli-1", settings)

            self.assertFalse(result.valid)
            self.assertFalse(result.checks["command_argv"])

            different_host = list(argv)
            different_host[different_host.index("--host-id") + 1] = "codex-app"
            installed = _replace_command_values(template, _render(tuple(different_host), "posix"), _render(tuple(different_host), "windows"))
            settings.paths.hooks_path.write_text(json.dumps(installed), encoding="utf-8")

            result = static_canary("codex-cli", "cli-1", settings)

            self.assertFalse(result.valid)
            self.assertFalse(result.checks["command_argv"])


if __name__ == "__main__":
    unittest.main()
