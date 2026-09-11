import contextlib
import io
import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ei import migrate as migrate_module
from ei.cli import EXIT_INPUT, main
from ei.config import load_settings
from ei.inventory import inventory_existing_state
from ei.journal import iter_events
from ei.migrate import execute_migration, plan_migration


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class ExistingMigrationTests(unittest.TestCase):
    def _settings(self, root: Path):
        (root / "config").mkdir(exist_ok=True)
        (root / "config" / "defaults.json").write_text(
            json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
            encoding="utf-8",
        )
        return load_settings(
            repo_root=root,
            codex_home=root / "codex",
            runtime_root=root / "runtime",
            host_homes={},
        )

    def test_read_only_classified_idempotent_migration(self):
        fixture = Path("tests/fixtures/migration/current-memory-tree")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            shutil.copytree(fixture, source)
            (source / "project-c").mkdir()
            (source / "project-c" / "secret.md").write_text(
                "## Reusable knowledge\n- " + bearer_secret("A" * 32) + "\n", encoding="utf-8"
            )
            before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.rglob("*") if path.is_file()}
            settings = self._settings(root)
            plan = plan_migration(source, settings)
            self.assertGreater(len(plan.items), 0)
            applied = execute_migration(plan)
            self.assertGreaterEqual(applied.imported, 3)
            self.assertGreaterEqual(applied.duplicates, 1)
            self.assertGreaterEqual(applied.external_references, 2)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.rglob("*") if path.is_file()})
            second_plan = plan_migration(source, settings)
            second = execute_migration(second_plan)
            self.assertEqual(second.imported, 0)
            self.assertEqual(second.secret_rejected, 1)

    def test_new_inventory_plan_execute_api_keeps_article_out_of_user_baseline(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            inventory = inventory_existing_state([fixture], settings)
            plan = plan_migration(inventory, settings)
            self.assertEqual(plan.inventory.inventory_hash, inventory.inventory_hash)
            result = execute_migration(plan, inventory, settings)
            self.assertGreater(result.imported, 0)
            self.assertGreater(result.external_references, 0)
            events = list(iter_events(settings.paths.event_dir))
            article_events = [
                event for event in events
                if event.event_type == "source.reference.recorded"
                and event.payload.get("classification") == "external-reference"
            ]
            self.assertTrue(article_events)
            self.assertFalse(
                any(
                    event.event_type == "observation.recorded"
                    and event.payload.get("source_kind") == "external_article_copy"
                    for event in events
                )
            )
            self.assertNotIn("48,350,000", json.dumps([event.to_dict() for event in events], ensure_ascii=False))
            self.assertNotIn("98.7%", json.dumps([event.to_dict() for event in events], ensure_ascii=False))

    def test_apply_refuses_changed_source_after_dry_run(self):
        fixture = Path("tests/fixtures/migration/current-memory-tree")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            shutil.copytree(fixture, source)
            settings = self._settings(root)
            plan = plan_migration(source, settings)
            target = source / "project-a" / "reusable.md"
            target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MIGRATION_SOURCE_CHANGED"):
                execute_migration(plan)

    def test_apply_refuses_changed_unsupported_source_after_dry_run(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            shutil.copytree(fixture, source)
            settings = self._settings(root)
            inventory = inventory_existing_state([source], settings)
            plan = plan_migration(inventory, settings)
            target = source / "unsupported" / "sample.bin"
            target.write_bytes(target.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "MIGRATION_SOURCE_CHANGED"):
                execute_migration(plan, inventory, settings)

    def test_apply_refuses_incomplete_privacy_scan(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            inventory = inventory_existing_state([fixture], settings)
            broken = replace(inventory, privacy_scan_complete=False)
            plan = plan_migration(broken, settings)
            with self.assertRaisesRegex(ValueError, "MIGRATION_PRIVACY_SCAN_INCOMPLETE"):
                execute_migration(plan, broken, settings)

    def test_unsupported_source_has_terminal_disposition_instead_of_unclassified_row(self):
        fixture = Path("tests/fixtures/migration/legacy-memory-repo")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            shutil.copytree(fixture, source)
            settings = self._settings(root)
            inventory = inventory_existing_state([source], settings)
            unsupported = [row for row in inventory.rows if row.reason_code == "UNSUPPORTED_SOURCE_KIND"]
            self.assertTrue(unsupported)
            self.assertTrue(all(row.disposition == "unsupported_format" for row in unsupported))
            self.assertEqual(inventory.unclassified, 0)

    def test_checkpoint_resumes_after_interrupted_append_without_duplicate_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            source.mkdir()
            (source / "MEMORY.md").write_text(
                "# Reusable knowledge\n- First independent rule\n- Second independent rule\n",
                encoding="utf-8",
            )
            settings = self._settings(root)
            inventory = inventory_existing_state([source], settings)
            plan = plan_migration(inventory, settings)
            original = migrate_module.append_event
            calls = {"count": 0}

            def fail_on_second(event, event_dir):
                calls["count"] += 1
                if calls["count"] == 2:
                    raise OSError("injected interruption")
                return original(event, event_dir)

            with mock.patch.object(migrate_module, "append_event", side_effect=fail_on_second):
                with self.assertRaisesRegex(OSError, "injected interruption"):
                    execute_migration(plan, inventory, settings)

            checkpoint = settings.paths.local_state_dir / "migration" / (plan.plan_hash + ".json")
            self.assertTrue(checkpoint.exists())
            resumed = execute_migration(plan, inventory, settings)
            self.assertEqual(resumed.imported, 1)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 2)
            self.assertEqual(json.loads(checkpoint.read_text(encoding="utf-8"))["status"], "complete")
            rollback = settings.paths.local_state_dir / "migration" / (plan.plan_hash + ".rollback.json")
            self.assertTrue(rollback.exists())

    def test_cli_isolated_fixture_commands_require_explicit_runtime_and_source(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            runtime = settings.paths.runtime_root
            inventory_path = runtime / "inventory.json"
            report_path = runtime / "preview.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "inventory-existing",
                        "--repo",
                        str(root),
                        "--runtime-root",
                        str(runtime),
                        "--codex-home",
                        str(root / "codex"),
                        "--source",
                        str(fixture),
                        "--inventory",
                        str(inventory_path),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(inventory_path.exists())
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "migrate-existing",
                        "--repo",
                        str(root),
                        "--runtime-root",
                        str(runtime),
                        "--codex-home",
                        str(root / "codex"),
                        "--source",
                        str(fixture),
                        "--dry-run",
                        "--report",
                        str(report_path),
                        "--inventory",
                        str(inventory_path),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(report_path.exists())
            self.assertNotIn(str(fixture), stdout.getvalue())

    def test_cli_dry_run_writes_inventory_and_apply_requires_matching_inventory(self):
        fixture = Path("tests/fixtures/migration/legacy-memory-repo")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memories"
            shutil.copytree(fixture, source)
            (source / "unknown.txt").unlink()
            settings = self._settings(root)
            report = root / "migration.json"
            inventory = root / "inventory.json"
            common = [
                "migrate-existing",
                "--repo",
                str(root),
                "--codex-home",
                str(root / "codex"),
                "--source",
                str(source),
                "--report",
                str(report),
                "--inventory",
                str(inventory),
            ]
            self.assertEqual(main([*common, "--dry-run", "--json"]), 0)
            preview = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(inventory.exists())
            self.assertEqual(preview["inventory"]["inventory_hash"], json.loads(inventory.read_text(encoding="utf-8"))["inventory_hash"])
            self.assertEqual(main([*common, "--apply", "--expected-plan-hash", preview["plan_hash"], "--json"]), 0)
            inventory.write_text(inventory.read_text(encoding="utf-8").replace(preview["inventory"]["inventory_hash"], "0" * 64), encoding="utf-8")
            self.assertEqual(main([*common, "--apply", "--expected-plan-hash", preview["plan_hash"], "--json"]), EXIT_INPUT)


if __name__ == "__main__":
    unittest.main()
