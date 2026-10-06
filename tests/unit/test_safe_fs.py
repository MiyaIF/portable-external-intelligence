from __future__ import annotations

import tempfile
import unittest
import hashlib
import stat
from types import SimpleNamespace
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import ei.safe_fs as safe_fs
from ei.operation_runtime import OperationBudget

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
    def test_nested_deadline_is_not_relabelled_as_filesystem_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            (nested / "body").write_bytes(b"keep")
            original = safe_fs._budget_entries
            def interrupted(directory, budget):
                if directory == nested:
                    raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")
                return original(directory, budget)
            with patch("ei.safe_fs._budget_entries", side_effect=interrupted):
                for action in (tree_digest, safe_fs._tree_entries):
                    with self.subTest(action=action.__name__), self.assertRaises(TimeoutError):
                        action(root, budget=OperationBudget(1000))
            self.assertEqual((nested / "body").read_bytes(), b"keep")

    def test_budgeted_digest_matches_legacy_bytes_mode_and_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "b").mkdir()
            (root / "b" / "z").write_bytes(b"binary\x00\xff" * 20000)
            (root / "a").write_bytes(b"first")
            self.assertEqual(tree_digest(root), tree_digest(root, budget=OperationBudget(5000)))
            self.assertEqual(safe_fs._file_digest(root / "a"), safe_fs._file_digest(root / "a", budget=OperationBudget(5000)))
            with self.assertRaises(TimeoutError):
                tree_digest(root, budget=OperationBudget(0))

    def test_partial_cleanup_keeps_owner_and_can_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "owned"
            target.mkdir()
            for name in ("a", "b"):
                (target / name).write_text(name)
            record = create_ownership_record(root, target, kind="sync-worktree")
            marker = root / "owned.json"
            safe_fs.write_ownership_record(marker, record, root=root)
            budget = OperationBudget(5000)
            original = safe_fs.safe_unlink

            def unlink_then_expire(*args, **kwargs):
                result = original(*args, **kwargs)
                budget.deadline = 0
                return result

            with patch("ei.safe_fs.safe_unlink", side_effect=unlink_then_expire):
                with self.assertRaises(TimeoutError):
                    safe_remove_tree(root, target, owner=record, kind="sync-worktree", budget=budget)
            self.assertTrue(marker.is_file())
            self.assertEqual(len(list(target.iterdir())), 1)
            self.assertTrue(safe_remove_tree(root, target, owner=record, kind="sync-worktree", budget=OperationBudget(5000)))
            self.assertTrue(marker.is_file())

    def test_reparse_probe_uses_one_nofollow_snapshot_for_all_attributes(self):
        cases = ((stat.S_IFREG, 0, 0, False), (stat.S_IFLNK, 0, 0, True),
                 (stat.S_IFDIR, 0x400, 0, True), (stat.S_IFREG, 0, 123, True))
        for mode, attributes, tag, expected in cases:
            with self.subTest(mode=mode, attributes=attributes, tag=tag):
                calls = []
                def probe(path, *, follow_symlinks=True):
                    calls.append(follow_symlinks)
                    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes, st_reparse_tag=tag)
                with patch.object(Path, "stat", probe):
                    self.assertEqual(safe_fs._is_reparse(Path("fixture")), expected)
                self.assertEqual(calls, [False])

    def test_missing_component_is_allowed_but_denied_and_unknown_are_fail_closed(self):
        for error, expected in ((FileNotFoundError(), False), (PermissionError(), True), (OSError(), True), (ValueError(), True)):
            with self.subTest(error=type(error).__name__), patch.object(Path, "stat", side_effect=error) as probe:
                self.assertEqual(safe_fs._is_reparse(Path("fixture")), expected)
                self.assertEqual(probe.call_count, 1)

    def test_component_traversal_probes_each_component_once_without_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "missing" / "child"
            original = Path.stat
            calls = []
            def probe(path, *, follow_symlinks=True):
                calls.append((str(path), follow_symlinks))
                return original(path, follow_symlinks=follow_symlinks)
            with patch.object(Path, "stat", probe):
                safe_fs._reparse_components(target)
                first = list(calls)
                calls.clear()
                safe_fs._reparse_components(target)
            self.assertEqual(calls, first)
            self.assertTrue(all(not follows for _, follows in calls))
            self.assertTrue(all(count == 1 for count in Counter(path for path, _ in calls).values()))

    def test_dangling_symlink_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / "dangling"
            try:
                link.symlink_to(root / "missing")
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink fixture unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex(SafeFilesystemError, "UNSAFE_REPARSE_POINT"):
                assert_safe_target(root, link)
            self.assertTrue(link.is_symlink())

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
