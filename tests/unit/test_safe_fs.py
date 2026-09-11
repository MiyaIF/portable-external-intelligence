from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch

import ei.safe_fs as safe_fs

from ei.safe_fs import (
    SafeFilesystemError,
    assert_safe_target,
    create_ownership_record,
    safe_atomic_write,
    safe_copy_file,
    safe_copy_tree,
    safe_ensure_directory,
    safe_move,
    safe_remove_tree,
    safe_replace,
    safe_symlink,
    safe_unlink,
    safe_unlink_link,
    tree_digest,
    validate_ownership_record,
)


class SafeFilesystemTests(unittest.TestCase):
    def test_canonical_containment_uses_one_path_coordinate_system(self) -> None:
        lexical_root = Path(r"C:\Profiles\RUNNER~1\Temp\root")
        lexical_target = lexical_root / "nested"
        canonical_root = Path(r"C:\Profiles\runner-account\Temp\root")
        canonical_target = canonical_root / "nested"

        def canonicalize(value: Path | str, *, require_exists: bool = False) -> Path:
            del require_exists
            return canonical_root if Path(value) == lexical_root else canonical_target

        with patch("ei.safe_fs.canonical_path", side_effect=canonicalize):
            root, target = safe_fs._canonical_contained_paths(lexical_root, lexical_target)

        self.assertEqual(root, canonical_root)
        self.assertEqual(target, canonical_target)

    def test_tree_copy_allows_source_and_destination_on_different_volumes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "source-root"
            destination_root = root / "destination-root"
            source = source_root / "skill"
            destination = destination_root / "installed-skill"
            source.mkdir(parents=True)
            destination_root.mkdir()
            (source / "SKILL.md").write_text("portable\n", encoding="utf-8")
            source_canonical = source_root.resolve()
            destination_canonical = destination_root.resolve()

            def volume_probe(left: Path, right: Path) -> bool:
                pair = {left.resolve(), right.resolve()}
                if pair == {source_canonical, destination_canonical}:
                    return False
                return True

            with patch("ei.safe_fs._same_volume", side_effect=volume_probe):
                safe_copy_tree(source_root, source, destination_root, destination)

            self.assertEqual((destination / "SKILL.md").read_text(encoding="utf-8"), "portable\n")

    def test_ensure_directory_and_tree_copy_use_contained_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            safe_ensure_directory(root / "source" / "nested")
            source = root / "source"
            (source / "SKILL.md").write_text("skill\n", encoding="utf-8")
            destination = root / "destination"
            safe_copy_tree(source.parent, source, root, destination)
            self.assertEqual((destination / "SKILL.md").read_text(encoding="utf-8"), "skill\n")
            moved = root / "moved"
            safe_move(root, destination, root, moved)
            self.assertFalse(destination.exists())
            self.assertEqual((moved / "SKILL.md").read_text(encoding="utf-8"), "skill\n")

    def test_atomic_write_and_copy_are_contained_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            source = root / "source.txt"
            source.write_bytes(b"source")
            target = root / "nested" / "target.txt"
            target.parent.mkdir()
            safe_atomic_write(root, target, b"written")
            self.assertEqual(target.read_bytes(), b"written")
            copied = root / "copy.txt"
            safe_copy_file(root, source, root, copied, expected_digest="sha256:" + hashlib.sha256(b"source").hexdigest())
            self.assertEqual(copied.read_bytes(), b"source")

    def test_tree_delete_requires_containment_ownership_and_expected_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            target = root / "owned"
            (target / "nested").mkdir(parents=True)
            (target / "nested" / "file.txt").write_text("owned", encoding="utf-8")
            expected = tree_digest(target)
            owner = create_ownership_record(root, target, kind="test-tree", expected_digest=expected)
            validate_ownership_record(owner, root, target, kind="test-tree", expected_digest=expected)
            safe_remove_tree(root, target, owner=owner, kind="test-tree", expected_digest=expected)
            self.assertFalse(target.exists())

            outside = Path(tmp) / "outside"
            outside.mkdir()
            with self.assertRaisesRegex(SafeFilesystemError, "SAFE_PATH_OUTSIDE_ROOT"):
                safe_remove_tree(root, outside)

    def test_digest_or_owner_mismatch_stops_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "file.txt"
            target.write_text("original", encoding="utf-8")
            owner = create_ownership_record(root, target, kind="test-file", expected_digest="sha256:" + "0" * 64)
            with self.assertRaisesRegex(SafeFilesystemError, "SAFE_OWNERSHIP_MISMATCH"):
                safe_unlink(root, target, owner=owner, kind="test-file", expected_digest="sha256:" + "1" * 64)
            self.assertTrue(target.exists())
            with self.assertRaisesRegex(SafeFilesystemError, "SAFE_DIGEST_MISMATCH"):
                safe_unlink(root, target, expected_digest="sha256:" + "0" * 64)
            self.assertTrue(target.exists())

    def test_symlink_to_outside_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            protected = outside / "protected.txt"
            protected.write_text("do not delete", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(protected)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex(SafeFilesystemError, "SAFE_PATH_OUTSIDE_ROOT|UNSAFE_REPARSE_POINT"):
                safe_unlink(root, link)
            self.assertTrue(protected.exists())
            self.assertTrue(link.exists() or link.is_symlink())

    def test_managed_link_can_be_removed_without_touching_external_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            protected = outside / "protected.txt"
            protected.write_text("keep", encoding="utf-8")
            link = root / "skill"
            try:
                safe_symlink(root, link, outside)
            except SafeFilesystemError as exc:
                if exc.code == "SAFE_LINK_CREATE_FAILED":
                    self.skipTest("symlink fixture unavailable")
                raise
            self.assertTrue(safe_unlink_link(root, link, expected_target=outside))
            self.assertFalse(link.exists())
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep")

    def test_safe_replace_rejects_outside_and_existing_destination_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            source = root / "source.tmp"
            source.write_text("safe", encoding="utf-8")
            destination = root / "destination.txt"
            destination.write_text("old", encoding="utf-8")
            with self.assertRaisesRegex(SafeFilesystemError, "SAFE_DESTINATION_EXISTS|SAFE_TYPE_INVALID"):
                safe_replace(root, source, root, destination, source_type="file", replace_existing=False)
            self.assertEqual(destination.read_text(encoding="utf-8"), "old")
            assert_safe_target(root, root / "missing", allow_missing=True)


if __name__ == "__main__":
    unittest.main()
