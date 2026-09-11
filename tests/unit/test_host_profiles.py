from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.host_profiles as host_profiles
from ei.host_profiles import (
    build_host_profile,
    install_host_profiles,
    load_host_profile,
    load_installed_host_profiles,
)


def valid_profile() -> dict[str, object]:
    return {
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


class HostProfileTests(unittest.TestCase):
    def test_profile_is_bound_to_host_home_without_changing_its_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "custom home"
            profile = build_host_profile(valid_profile(), home)

            self.assertEqual(profile.host_id, "test-compatible-cli")
            self.assertEqual(profile.host_family, "gemini-compatible")
            self.assertEqual(profile.adapter_id, "gemini-cli")
            self.assertEqual(profile.hook_config_path, (home / ".config/test-compatible/settings.json").resolve())
            self.assertEqual(profile.global_context_path, (home / ".config/test-compatible/context.md").resolve())

    def test_profile_rejects_extra_command_and_parent_traversal_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            document = valid_profile()
            document["command"] = ["powershell", "-Command", "Write-Output unsafe"]
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_INVALID"):
                build_host_profile(document, home)

            document = valid_profile()
            document["hook_config_path"] = "../outside/settings.json"
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_PATH_INVALID"):
                build_host_profile(document, home)

    def test_profile_rejects_unsafe_values_and_mismatched_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            for key, value in (
                ("host_id", "bad/id"),
                ("adapter_id", "unknown-adapter"),
                ("host_family", "gemini-compatible"),
                ("executable_names", ["test-compatible --unsafe"]),
            ):
                document = valid_profile()
                if key == "host_family":
                    document["adapter_id"] = "codex-cli"
                else:
                    document[key] = value
                with self.subTest(key=key):
                    with self.assertRaisesRegex(ValueError, "HOST_PROFILE_"):
                        build_host_profile(document, home)

    def test_install_and_load_profiles_use_runtime_copy_without_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source-profile.json"
            source.write_text(json.dumps(valid_profile()), encoding="utf-8")
            runtime = root / "runtime"

            installed = install_host_profiles((source,), runtime)
            self.assertEqual(set(installed), {"test-compatible-cli"})
            stored = runtime / "host-profiles" / "test-compatible-cli.json"
            self.assertTrue(stored.is_file())
            self.assertNotIn(str(source), stored.read_text(encoding="utf-8"))
            self.assertEqual(set(load_installed_host_profiles(runtime)), {"test-compatible-cli"})

    def test_runtime_profile_rejects_duplicate_host_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.json"
            second = root / "second.json"
            first.write_text(json.dumps(valid_profile()), encoding="utf-8")
            second.write_text(json.dumps(valid_profile()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_DUPLICATE"):
                install_host_profiles((first, second), root / "runtime")

    def test_runtime_copy_failure_is_reported_without_accepting_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "profile.json"
            source.write_text(json.dumps(valid_profile()), encoding="utf-8")
            runtime_file = root / "runtime"
            runtime_file.write_text("not a directory", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_RUNTIME_WRITE_FAILED"):
                install_host_profiles((source,), runtime_file)

    def test_profile_rejects_noncanonical_and_windows_reserved_host_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            for host_id in ("MyCLI", "test:cli", "test.", "CON", "COM1", "codex-app"):
                document = valid_profile()
                document["host_id"] = host_id
                with self.subTest(host_id=host_id):
                    with self.assertRaisesRegex(ValueError, "HOST_PROFILE_INVALID"):
                        build_host_profile(document, home)

    def test_runtime_loader_requires_filename_to_match_profile_host_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            profile_dir = runtime / "host-profiles"
            profile_dir.mkdir(parents=True)
            (profile_dir / "wrong.json").write_text(json.dumps(valid_profile()), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_LOCATOR_INVALID"):
                load_installed_host_profiles(runtime)

    def test_install_profiles_rolls_back_all_targets_when_a_later_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.json"
            second_document = valid_profile()
            second_document["host_id"] = "second-compatible-cli"
            second = root / "second.json"
            first.write_text(json.dumps(valid_profile()), encoding="utf-8")
            second.write_text(json.dumps(second_document), encoding="utf-8")
            runtime = root / "runtime"
            existing_target = runtime / "host-profiles" / "test-compatible-cli.json"
            existing_target.parent.mkdir(parents=True)
            existing_bytes = b"previous profile bytes"
            existing_target.write_bytes(existing_bytes)
            original_write = host_profiles._atomic_write
            calls = 0

            def fail_second(path: Path, raw: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected profile write failure")
                original_write(path, raw)

            with patch("ei.host_profiles._atomic_write", side_effect=fail_second):
                with self.assertRaisesRegex(ValueError, "HOST_PROFILE_RUNTIME_WRITE_FAILED"):
                    install_host_profiles((first, second), runtime)
            self.assertEqual(existing_target.read_bytes(), existing_bytes)
            self.assertFalse((runtime / "host-profiles" / "second-compatible-cli.json").exists())

    def test_profile_source_and_runtime_reparse_components_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "source-dir"
            source_dir.mkdir()
            source_real = source_dir / "profile.json"
            source_real.write_text(json.dumps(valid_profile()), encoding="utf-8")
            linked_source_dir = root / "linked-source"
            runtime_real = root / "runtime-real"
            runtime_real.mkdir()
            linked_runtime = root / "linked-runtime"
            try:
                linked_source_dir.symlink_to(source_dir, target_is_directory=True)
                linked_runtime.symlink_to(runtime_real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")

            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_READ_FAILED"):
                load_host_profile(linked_source_dir / "profile.json", root / "home")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_LOCATOR_INVALID"):
                load_installed_host_profiles(linked_runtime)

            runtime = root / "runtime"
            runtime.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (runtime / "host-profiles").symlink_to(outside, target_is_directory=True)
            source = root / "source.json"
            source.write_text(json.dumps(valid_profile()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_RUNTIME_WRITE_FAILED"):
                install_host_profiles((source,), runtime)

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_profile_runtime_rejects_windows_junction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            junction = root / "runtime-junction"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_LOCATOR_INVALID"):
                load_installed_host_profiles(junction)

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_empty_profile_directory_junction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir()
            outside = root / "outside"
            outside.mkdir()
            junction = runtime / "host-profiles"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE_LOCATOR_INVALID"):
                load_installed_host_profiles(runtime)

    def test_invalid_profiles_do_not_scaffold_or_modify_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = root / "valid.json"
            invalid = root / "invalid.json"
            valid.write_text(json.dumps(valid_profile()), encoding="utf-8")
            invalid_document = valid_profile()
            invalid_document["host_id"] = "invalid:host"
            invalid.write_text(json.dumps(invalid_document), encoding="utf-8")

            missing_runtime = root / "missing-runtime"
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE"):
                install_host_profiles((valid, invalid), missing_runtime)
            self.assertFalse(missing_runtime.exists())

            existing_runtime = root / "existing-runtime"
            existing_runtime.mkdir()
            existing_profile_dir = existing_runtime / "host-profiles"
            existing_profile_dir.mkdir()
            marker = existing_profile_dir / "marker.txt"
            marker.write_bytes(b"unchanged")
            with self.assertRaisesRegex(ValueError, "HOST_PROFILE"):
                install_host_profiles((valid, invalid), existing_runtime)
            self.assertEqual(marker.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
