import os
import tempfile
import unittest
from pathlib import Path

from ei.config import HostSpec
from ei.skill_installer import canonical_tree_hash, install_skill, remove_installed_skill


def make_host(home: Path, host_id: str = "codex-cli") -> HostSpec:
    return HostSpec(
        host_id,
        host_id,
        (host_id,),
        home / "hooks.json",
        home / "AGENTS.md",
        (home / "skills",),
        {},
        None,
        False,
        "AUTO_ALLOWED",
        "HOOK_DIRECT",
        ("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
        None,
    )


class SkillInstallerTests(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        source = root / "source" / "external-intelligence"
        (source / "workflows").mkdir(parents=True)
        (source / "SKILL.md").write_text("# External intelligence\n", encoding="utf-8")
        (source / "workflows" / "closeout.md").write_text("closeout\n", encoding="utf-8")
        return source

    def test_copy_is_hash_checked_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            host = make_host(root / "codex")
            first = install_skill(source, host, "copy")
            second = install_skill(source, host, "copy", previous_hash=first.installed_hash)
            self.assertTrue(first.changed)
            self.assertEqual(first.source_hash, first.installed_hash)
            self.assertFalse(second.changed)
            self.assertEqual(first.installed_hash, second.installed_hash)
            self.assertEqual(canonical_tree_hash(source), canonical_tree_hash(first.destination))
            self.assertTrue((source / "SKILL.md").is_file())

    def test_changed_source_requires_previous_install_hash_and_creates_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            host = make_host(root / "codex")
            first = install_skill(source, host, "copy")
            (source / "workflows" / "new.md").write_text("new\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SKILL_INSTALL_CONFLICT"):
                install_skill(source, host, "copy")
            updated = install_skill(source, host, "copy", previous_hash=first.installed_hash)
            self.assertTrue(updated.changed)
            self.assertIsNotNone(updated.backup_path)
            self.assertTrue(updated.backup_path.is_dir())
            self.assertEqual(updated.source_hash, updated.installed_hash)

    def test_uninstall_refuses_modified_copy_unless_forced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            host = make_host(root / "codex")
            installed = install_skill(source, host, "copy")
            (installed.destination / "SKILL.md").write_text("# user modification\n", encoding="utf-8")
            conflict = remove_installed_skill(installed.destination, installed.installed_hash)
            self.assertFalse(conflict["removed"])
            self.assertEqual(conflict["reason_code"], "UNINSTALL_CONFLICT")
            removed = remove_installed_skill(installed.destination, installed.installed_hash, force=True)
            self.assertTrue(removed["removed"])
            self.assertFalse(installed.destination.exists())

    def test_link_mode_is_explicit_and_never_falls_back_to_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            host = make_host(root / "codex")
            try:
                installed = install_skill(source, host, "link")
            except ValueError as exc:
                if str(exc) == "SKILL_LINK_UNAVAILABLE":
                    self.skipTest("symbolic links are unavailable in this environment")
                raise
            self.assertTrue(installed.destination.is_symlink())
            self.assertEqual(installed.destination.resolve(), source.resolve())
            removed = remove_installed_skill(installed.destination, installed.installed_hash)
            self.assertTrue(removed["removed"])

    def test_source_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            link = source / "outside.txt"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable in this environment")
            with self.assertRaisesRegex(ValueError, "SKILL_SOURCE_SYMLINK_ESCAPE"):
                canonical_tree_hash(source)

    def test_source_bytecode_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self._source(Path(tmp))
            cache = source / "scripts" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "helper.cpython-313.pyc").write_bytes(b"untrusted-bytecode")

            with self.assertRaisesRegex(ValueError, "SKILL_SOURCE_RUNTIME_ARTIFACT"):
                canonical_tree_hash(source)


if __name__ == "__main__":
    unittest.main()
