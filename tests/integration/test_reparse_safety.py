from __future__ import annotations

import tempfile
import unittest
import os
import subprocess
from pathlib import Path

from ei.migrate import build_root_migration_plan
from ei.safe_fs import SafeFilesystemError, safe_remove_tree


class ReparseSafetyIntegrationTests(unittest.TestCase):
    def test_root_migration_rejects_reparse_source_without_copying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "legacy"
            destination = root / "new"
            runtime = root / "runtime"
            source.mkdir()
            (source / "events").mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = source / "events" / "event.json"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex((ValueError, SafeFilesystemError), "UNSAFE_REPARSE_POINT"):
                build_root_migration_plan(source, destination, runtime)
            self.assertFalse(destination.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

    def test_tree_delete_rejects_reparse_child_before_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            target = root / "tree"
            root.mkdir()
            target.mkdir()
            outside = Path(tmp) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = target / "outside.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex(SafeFilesystemError, "UNSAFE_REPARSE_POINT"):
                safe_remove_tree(root, target)
            self.assertTrue(target.exists())
            self.assertTrue(outside.exists())

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_junction_to_outside_is_rejected_before_tree_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            target = root / "tree"
            outside = Path(tmp) / "outside"
            root.mkdir()
            target.mkdir()
            outside.mkdir()
            protected = outside / "protected.txt"
            protected.write_text("do not delete", encoding="utf-8")
            junction = target / "outside"
            result = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable: " + (result.stderr or result.stdout).strip())
            with self.assertRaisesRegex(SafeFilesystemError, "UNSAFE_REPARSE_POINT"):
                safe_remove_tree(root, target)
            self.assertTrue(protected.exists())


if __name__ == "__main__":
    unittest.main()
