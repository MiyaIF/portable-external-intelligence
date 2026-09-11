import hashlib
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.journal import append_event, iter_events
from ei.cli import main
from ei.migrate import (
    apply_root_migration,
    build_root_migration_plan,
    cleanup_legacy_root,
    load_root_migration_plan,
    rollback_root_migration,
    write_root_migration_plan,
)
from ei.models import Event
from ei.recovery import inspect_root_migration_recovery, recover_root_migration_staging


class CombinedRootMigrationAcceptanceTests(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        source = root / "legacy-memory"
        (source / "events").mkdir(parents=True)
        (source / "knowledge").mkdir()
        (source / "policies" / "user-overrides").mkdir(parents=True)
        (source / "experiments").mkdir()
        (source / "knowledge-repository.json").write_text(
            json.dumps({"schema_version": 1, "repository_kind": "private-knowledge"}) + "\n",
            encoding="utf-8",
        )
        (source / ".gitignore").write_text("runtime/\n", encoding="utf-8")
        (source / "knowledge" / "stale-projection.md").write_text("stale projection\n", encoding="utf-8")
        (source / "policies" / "user-overrides" / "retention.json").write_text(
            '{"retention_days": 30}\n', encoding="utf-8"
        )
        (source / "experiments" / "baseline.json").write_text(
            '{"experiment_id":"fixture","arm":"A"}\n', encoding="utf-8"
        )
        event = Event.create_v2(
            "pattern.promoted",
            "test",
            "machine-a",
            {
                "pattern_id": "pattern-safe-copy",
                "rule": "Verify the copied artifact before using it.",
                "classification": "private-reusable",
                "provenances": ["sha256:" + "1" * 64],
                "applicability": ["migration"],
            },
        )
        append_event(event, source / "events")
        return source

    @staticmethod
    def _snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
        return {
            path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*")
            if path.is_file()
        }

    def test_apply_is_lossless_rebuilds_projection_and_rollback_is_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "knowledge-repository"
            runtime = root / "machine-runtime"
            before = self._snapshot(source)
            plan = build_root_migration_plan(source, destination, runtime)
            plan_path = write_root_migration_plan(plan, runtime / "migration-plan.json")
            loaded = load_root_migration_plan(plan_path)
            self.assertEqual(loaded.plan_hash, plan.plan_hash)

            result = apply_root_migration(loaded)
            self.assertEqual(result.status, "complete")
            self.assertTrue((destination / "knowledge" / "index.json").is_file())
            self.assertTrue((destination / "knowledge" / "manifest.json").is_file())
            self.assertEqual(
                [event.event_id for event in iter_events(destination / "events")],
                list(plan.event_ids),
            )
            self.assertEqual(before, self._snapshot(source))
            receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["plan_hash"], plan.plan_hash)
            self.assertEqual(receipt["runtime_root"], str(runtime.resolve()))

            with self.assertRaisesRegex(ValueError, "MIGRATION_ROLLBACK_CONFIRMATION_REQUIRED"):
                rollback_root_migration(result)
            self.assertTrue(destination.exists())
            rolled_back = rollback_root_migration(result, confirm_plan_hash=plan.plan_hash)
            self.assertEqual(rolled_back.status, "rolled_back")
            self.assertFalse(destination.exists())
            self.assertEqual(before, self._snapshot(source))

    def test_changed_source_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            plan = build_root_migration_plan(source, root / "knowledge", root / "runtime")
            target = source / "experiments" / "baseline.json"
            target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MIGRATION_SOURCE_CHANGED"):
                apply_root_migration(plan)

    def test_interrupted_copy_has_no_partial_destination_and_empty_destination_is_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "knowledge"
            plan = build_root_migration_plan(source, destination, root / "runtime")
            with self.assertRaisesRegex(RuntimeError, "MIGRATION_INTERRUPTED"):
                apply_root_migration(plan, interrupt_after_files=1)
            self.assertFalse(destination.exists())
            self.assertFalse(any(path.name.startswith(".knowledge.migration-") for path in root.iterdir()))

            destination.mkdir()
            with self.assertRaisesRegex(ValueError, "MIGRATION_DESTINATION_COLLISION"):
                apply_root_migration(plan)

    def test_duplicate_event_and_tampered_plan_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            event_path = next((source / "events").rglob("*.json"))
            duplicate = source / "events" / "duplicate.json"
            shutil.copyfile(event_path, duplicate)
            with self.assertRaisesRegex(ValueError, "MIGRATION_DUPLICATE_EVENT_ID"):
                build_root_migration_plan(source, root / "knowledge", root / "runtime")

            duplicate.unlink()
            plan = build_root_migration_plan(source, root / "knowledge", root / "runtime")
            plan_path = write_root_migration_plan(plan, root / "plan.json")
            document = json.loads(plan_path.read_text(encoding="utf-8"))
            document["plan_hash"] = "sha256:" + "0" * 64
            plan_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MIGRATION_PLAN_HASH_INVALID"):
                load_root_migration_plan(plan_path)

    def test_projection_mismatch_and_cleanup_requirements_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "knowledge"
            runtime = root / "runtime"
            plan = build_root_migration_plan(source, destination, runtime)
            import ei.project as project_module

            with patch.object(project_module, "project_events", lambda events, target: None):
                with self.assertRaisesRegex(ValueError, "MIGRATION_PROJECTION_MISMATCH"):
                    apply_root_migration(plan)
            self.assertFalse(destination.exists())

            result = apply_root_migration(plan)
            backup = root / "backup"
            shutil.copytree(source, backup)
            with self.assertRaisesRegex(ValueError, "MIGRATION_CLEANUP_APPROVAL_REQUIRED"):
                cleanup_legacy_root(plan, confirm_plan_hash="sha256:" + "f" * 64, verified_backup=backup)
            self.assertTrue((source / "events").exists())
            removed = cleanup_legacy_root(plan, confirm_plan_hash=plan.plan_hash, verified_backup=backup)
            self.assertEqual(removed, len(plan.files))
            self.assertFalse(any((source / Path(*item.relative_path.split("/"))).exists() for item in plan.files))
            self.assertTrue(result.receipt_path.is_file())

    def test_cli_inspect_apply_and_rollback_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            plan_path = runtime / "migration" / "plan.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "migration", "inspect", "--repo", str(source),
                            "--knowledge-root", str(knowledge), "--runtime-root", str(runtime),
                            "--plan-output", str(plan_path), "--json",
                        ]
                    ),
                    0,
                )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "migration", "apply", "--plan", str(plan_path),
                            "--confirm-plan-hash", plan["plan_hash"], "--json",
                        ]
                    ),
                    0,
                )
            receipt = runtime / "migration" / (plan["plan_hash"].removeprefix("sha256:") + ".json")
            self.assertTrue(receipt.is_file())
            receipt_alias = receipt.parent.parent / "MIGRAT~1" / receipt.name
            with patch("ei.migrate.absolute_path", return_value=receipt_alias), patch(
                "ei.migrate.assert_safe_target",
                return_value=receipt,
            ), contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "migration", "rollback", "--receipt", str(receipt),
                            "--confirm-plan-hash", plan["plan_hash"], "--json",
                        ]
                    ),
                    0,
                )
            self.assertFalse(knowledge.exists())

    def test_abandoned_staging_is_reported_and_exact_plan_recovery_is_confirmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "knowledge"
            runtime = root / "runtime"
            plan = build_root_migration_plan(source, destination, runtime)
            staging = destination.parent / (
                f".{destination.name}.migration-{plan.plan_hash.removeprefix('sha256:')}-"
                "0123456789abcdef0123456789abcdef"  # pragma: allowlist secret
            )
            (staging / "events").mkdir(parents=True)
            (staging / "events" / "partial.json").write_text("partial\n", encoding="utf-8")
            status = inspect_root_migration_recovery(destination, runtime)
            self.assertEqual(status.status, "staging_recovery_required")
            self.assertEqual(status.staging_names, (staging.name,))
            with self.assertRaisesRegex(ValueError, "MIGRATION_RECOVERY_CONFIRMATION_REQUIRED"):
                recover_root_migration_staging(destination, runtime, plan.plan_hash)
            recovered = recover_root_migration_staging(destination, runtime, plan.plan_hash, confirm=True)
            self.assertEqual(recovered.status, "clean")
            self.assertFalse(staging.exists())


if __name__ == "__main__":
    unittest.main()
