import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from ei.models import Event
from ei.project import project_events
from ei.index import read_index_items
from ei.operation_runtime import OperationBudget
from unittest.mock import patch


def rule_event(number):
    return Event.create("pattern.promoted", f"2026-01-{number:02d}T00:00:00Z", "test", "test",
                        {"pattern_id": "pat_bound", "rule": f"verified rule {number}", "classification": "private-reusable"},
                        event_id=f"evt_rule_{number}")


class ProjectionTests(unittest.TestCase):
    def test_generation_attributes_control_is_exact_and_user_rules_are_preserved(self):
        for content in (b"* text=auto\n", b".projection-generations/** -text\nother -text\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                project_events([rule_event(1)], root)
                control = root / ".gitattributes"
                control.write_bytes(content)
                previous = (root / "index.json").read_bytes()
                with self.assertRaisesRegex(ValueError, "PROJECTION_ATTRIBUTES_CONFLICT"):
                    project_events([rule_event(2)], root, budget=OperationBudget(10000))
                self.assertEqual(control.read_bytes(), content)
                self.assertEqual((root / "index.json").read_bytes(), previous)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = root / ".gitattributes"
            control.write_bytes(b".projection-generations/** -text\r\n")
            project_events([rule_event(1)], root, budget=OperationBudget(10000))
            self.assertEqual(control.read_bytes(), b".projection-generations/** -text\r\n")

    def test_copied_generation_remains_readable_and_rebuilds_with_bounded_retention(self):
        from ei.index import build_index
        with tempfile.TemporaryDirectory() as tmp:
            source, clone = Path(tmp) / "source", Path(tmp) / "clone"
            project_events([rule_event(1)], source, budget=OperationBudget(10000))
            shutil.copytree(source, clone)
            before = build_index(clone, clone / "index.json")
            self.assertEqual(read_index_items(before)[0]["rule"], "verified rule 1")
            for number in (2, 3, 4):
                current = project_events([rule_event(number)], clone, budget=OperationBudget(10000))
                self.assertEqual(read_index_items(current)[0]["rule"], f"verified rule {number}")
                self.assertLessEqual(len(list((clone / ".projection-generations").iterdir())), 3)
            self.assertEqual(read_index_items(build_index(source, source / "index.json"))[0]["rule"], "verified rule 1")

    def test_unreleased_root_bound_marker_is_preserved_as_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = project_events([rule_event(1)], root, budget=OperationBudget(10000))
            marker = index.index_path.parent / ".ei-projection-owner.json"
            value = json.loads(marker.read_bytes())
            value.pop("generation_binding", None)
            value["root_binding"] = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
            marker.write_text(json.dumps(value), encoding="utf-8")
            before = marker.read_bytes()
            with self.assertRaisesRegex(ValueError, "PROJECTION_GENERATION_UNOWNED"):
                project_events([rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual(marker.read_bytes(), before)
            self.assertEqual(read_index_items(index)[0]["rule"], "verified rule 1")

    def test_changed_rendering_cannot_reuse_old_generation_by_source_hash(self):
        from ei import project
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = project_events([rule_event(1)], root, budget=OperationBudget(10000))
            original = project._pattern_markdown
            with patch("ei.project._pattern_markdown", side_effect=lambda *args: original(*args) + "\nNew renderer version\n"):
                second = project_events([rule_event(1)], root, budget=OperationBudget(10000))
            self.assertNotEqual(first.generation_hash, second.generation_hash)
            self.assertNotIn("New renderer version", read_index_items(first)[0]["rule"])
            self.assertIn("New renderer version", read_index_items(second)[0]["rule"])

    def test_fixed_generation_size_limit_preserves_published_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([rule_event(1)], root)
            before = (root / "index.json").read_bytes()
            with patch("ei.project._GENERATION_MAX_BYTES", 100):
                with self.assertRaisesRegex(ValueError, "PROJECTION_STORAGE_LIMIT"):
                    project_events([rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual((root / "index.json").read_bytes(), before)

    def test_more_than_three_generation_entries_is_not_implicitly_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([rule_event(1)], root)
            container = root / ".projection-generations"
            container.mkdir()
            for number in range(4):
                (container / f"{number:064x}").mkdir()
            before = (root / "index.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "PROJECTION_GENERATION_UNOWNED|PROJECTION_STORAGE_LIMIT"):
                project_events([rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual(len(list(container.iterdir())), 4)
            self.assertEqual((root / "index.json").read_bytes(), before)

    def test_first_bounded_generation_creates_current_human_entrypoint(self):
        from ei.project import projection_mirror_status
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            index = project_events([rule_event(1)], root, budget=OperationBudget(5000))
            self.assertEqual(read_index_items(index)[0]["rule"], "verified rule 1")
            self.assertEqual(projection_mirror_status(root), "CURRENT")

    def test_interrupted_preparation_keeps_old_recall_and_resumes_owned_files(self):
        from ei import project
        from ei.index import build_index
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prior = project_events([rule_event(1)], root)
            before = (root / "index.json").read_bytes()
            original_write = project._write_bounded
            def interrupt(root_arg, path, raw, budget):
                original_write(root_arg, path, raw, budget)
                if path.name == "pat_bound.md" and b"verified rule 2" in raw:
                    raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")
            with patch("ei.project._write_bounded", side_effect=interrupt):
                with self.assertRaises(TimeoutError):
                    project_events([rule_event(1), rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual((root / "index.json").read_bytes(), before)
            self.assertEqual(read_index_items(prior)[0]["rule"], "verified rule 1")
            current = project_events([rule_event(1), rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual(read_index_items(current)[0]["rule"], "verified rule 2")
            self.assertEqual(build_index(root, root / "index.json").generation_hash, current.generation_hash)

    def test_after_publication_interruption_exposes_pending_mirror_and_repairs_first(self):
        from ei import project
        from ei.index import build_index
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([rule_event(1)], root)
            original_write = project._write_bounded
            def interrupt(root_arg, path, raw, budget):
                original_write(root_arg, path, raw, budget)
                if path == root / "index.json":
                    raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")
            with patch("ei.project._write_bounded", side_effect=interrupt):
                with self.assertRaises(TimeoutError):
                    project_events([rule_event(1), rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual(read_index_items(build_index(root, root / "index.json"))[0]["rule"], "verified rule 2")
            self.assertEqual(project.projection_mirror_status(root), "PENDING")
            original_prepare = project._prepare_generation
            def verify_repaired(*args, **kwargs):
                self.assertEqual(project.projection_mirror_status(root), "CURRENT")
                return original_prepare(*args, **kwargs)
            with patch("ei.project._prepare_generation", side_effect=verify_repaired):
                project_events([rule_event(1), rule_event(2)], root, budget=OperationBudget(10000))
            self.assertEqual(project.projection_mirror_status(root), "CURRENT")

    def test_generation_retention_is_bounded_and_expired_handle_rejects(self):
        from ei.index import build_index
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handles = []
            for number in range(1, 5):
                handles.append(project_events([rule_event(number)], root, budget=OperationBudget(10000)))
                self.assertLessEqual(len(list((root / ".projection-generations").iterdir())), 3)
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_EXPIRED"):
                read_index_items(handles[0])
            self.assertEqual(read_index_items(handles[-2])[0]["rule"], "verified rule 3")
            self.assertEqual(read_index_items(build_index(root, root / "index.json"))[0]["rule"], "verified rule 4")

    def test_unowned_generation_and_extra_file_are_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = project_events([rule_event(1)], root)
            current = project_events([rule_event(2)], root, budget=OperationBudget(10000))
            extra = current.index_path.parent / "user-file.txt"
            extra.write_text("keep user data")
            before = (root / "index.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "PROJECTION_GENERATION_UNOWNED"):
                project_events([rule_event(3)], root, budget=OperationBudget(10000))
            self.assertEqual(extra.read_text(encoding="utf-8"), "keep user data")
            self.assertEqual((root / "index.json").read_bytes(), before)
            self.assertEqual(read_index_items(first)[0]["rule"], "verified rule 1")

    def test_more_than_thousand_historical_events_project_with_sufficient_existing_allowance(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            events = [replace(rule_event(1), event_id=f"evt_history_{n:04d}") for n in range(1001)]
            index = project_events(events, Path(tmp), budget=OperationBudget(30000))
            raw = json.loads(index.index_path.read_text(encoding="utf-8"))
            self.assertEqual(raw["source_state"]["event_count"], 1001)
            self.assertEqual(read_index_items(index)[0]["rule"], "verified rule 1")

    def test_doctor_resolves_generation_and_reports_temporary_mirror_lag(self):
        from ei.doctor import _projection_check
        from tests.unattended_helpers import make_settings
        from ei.journal import append_event, iter_events
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            event = rule_event(1)
            append_event(event, settings.paths.event_dir)
            project_events(iter_events(settings.paths.event_dir), settings.paths.knowledge_dir, budget=OperationBudget(10000))
            check = _projection_check(settings, True, 1)
            self.assertEqual(check["freshness"], "CURRENT")
            self.assertEqual(check.get("human_mirror"), "CURRENT")
            (settings.paths.knowledge_dir / "index.md").write_text("previous entrypoint")
            check = _projection_check(settings, True, 1)
            self.assertEqual(check["freshness"], "CURRENT")
            self.assertEqual(check.get("human_mirror"), "PENDING")

    def test_bounded_generation_preserves_previous_recall_and_updates_human_entrypoint(self):
        from ei.index import build_index
        from ei.operation_runtime import OperationBudget
        from dataclasses import replace
        old = Event.create("pattern.promoted", "2026-01-01T00:00:00Z", "test", "test",
                           {"pattern_id": "pat_bound", "rule": "previous verified rule", "classification": "private-reusable"}, event_id="evt_old")
        new = replace(old, event_id="evt_new", occurred_at="2026-01-02T00:00:00Z", payload={**old.payload, "rule": "current verified rule"})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = project_events([old], root)
            previous_child = (root / "rules/pat_bound.md").read_bytes()
            try:
                current = project_events([old, new], root, budget=OperationBudget(5000))
            except TypeError as exc:
                self.fail(str(exc))
            self.assertNotEqual(current.index_path, root / "index.json")
            self.assertEqual(read_index_items(previous)[0]["rule"], "previous verified rule")
            self.assertEqual(read_index_items(build_index(root, root / "index.json"))[0]["rule"], "current verified rule")
            self.assertEqual((root / "rules/pat_bound.md").read_bytes(), previous_child)
            self.assertIn(".projection-generations/", (root / "index.md").read_text(encoding="utf-8"))

    def test_zero_budget_and_interrupted_generation_do_not_publish(self):
        from ei.operation_runtime import OperationBudget
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([], root)
            original = (root / "index.json").read_bytes()
            try:
                with self.assertRaises(TimeoutError):
                    project_events([], root, budget=OperationBudget(0))
            except TypeError as exc:
                self.fail(str(exc))
            self.assertEqual((root / "index.json").read_bytes(), original)

    def test_index_links_to_readable_details_and_keeps_legacy_mirrors(self):
        event = Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"observation_id": "obs_guide", "title": "確認の順序",
                              "claim": "変更後に保存結果を確認する", "classification": "private-reusable"},
                             event_id="evt_guide")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([event], root)
            text = (root / "index.md").read_text(encoding="utf-8")
            self.assertIn("[確認の順序](observations/obs_guide.md)", text)
            self.assertIn("有効化済み: 0", text)
            self.assertIn("生成時点", text)
            detail = (root / "observations/obs_guide.md").read_text(encoding="utf-8")
            self.assertIn("2026-01-01T00:00:00+00:00", detail)
            self.assertEqual((root / "memories/obs_guide.md").read_bytes(),
                             (root / "observations/obs_guide.md").read_bytes())

    def test_candidate_explanation_does_not_become_retrieved_rule(self):
        rule = "実際の適用根拠を確認する"
        event = Event.create("pattern.candidate_created", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"pattern_id": "pat_guide", "cluster_id": "cluster_guide", "rule": rule,
                              "classification": "private-reusable"}, event_id="evt_guide")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = project_events([event], root)
            detail = (root / "candidates/pat_guide.md").read_text(encoding="utf-8")
            self.assertIn("CANDIDATE_EVIDENCE_UNAVAILABLE", detail)
            self.assertIn("根拠を復元できない", detail)
            items = list(read_index_items(index, ["pat_guide"]))
            self.assertEqual(items[0]["rule"], rule)

    def test_markdown_title_cannot_inject_an_image_or_extra_list_entry(self):
        event = Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"observation_id": "obs_label", "title": "![image](https://example.invalid)\n- extra",
                              "claim": "確認", "classification": "private-reusable"}, event_id="evt_label")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([event], root)
            text = (root / "index.md").read_text(encoding="utf-8")
            self.assertNotIn("![image]", text)
            self.assertNotIn("\n- extra", text)
            self.assertIn("(observations/obs_label.md)", text)

    def test_semantically_identical_crlf_projection_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([], root)
            target = root / "index.md"
            crlf = target.read_bytes().replace(b"\n", b"\r\n")
            target.write_bytes(crlf)
            before_mtime = target.stat().st_mtime_ns

            project_events([], root)

            self.assertEqual(target.read_bytes(), crlf)
            self.assertEqual(target.stat().st_mtime_ns, before_mtime)

    def test_rebuild_removes_projection_files_that_are_no_longer_generated(self):
        observation = Event.create(
            "observation.recorded",
            "2026-08-25T00:00:00+00:00",
            "test",
            "machine",
            {
                "observation_id": "obs_stale",
                "title": "stale",
                "claim": "remove stale projection",
                "classification": "private-reusable",
            },
            event_id="evt_stale",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([observation], root)
            stale = root / "memories" / "obs_stale.md"
            self.assertTrue(stale.exists())

            project_events([], root)

            self.assertFalse(stale.exists())

    def test_rebuild_is_byte_identical_and_tombstone_is_archived(self):
        events = [
            Event.create(
                "observation.recorded",
                "2026-08-25T00:00:00+00:00",
                "test",
                "machine",
                {
                    "observation_id": "obs_1",
                    "title": "再読込",
                    "claim": "書込後は再読込して検証する",
                    "domain": "spreadsheet",
                    "cwd_fingerprint": "cwd:a",
                    "provenance_key": "source:a",
                    "outcome_status": "success",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "source_hash": "hash:a",
                },
                event_id="evt_observation_1",
            ),
            Event.create(
                "pattern.promoted",
                "2026-08-25T00:01:00+00:00",
                "test",
                "machine",
                {
                    "pattern_id": "pat_1",
                    "cluster_id": "cluster_1",
                    "rule": "再利用ルール",
                    "provenances": ["source:a", "source:b"],
                    "scopes": ["cwd:a", "cwd:b"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                },
                event_id="evt_pattern_1",
            ),
            Event.create(
                "pattern.tombstoned",
                "2026-08-25T00:02:00+00:00",
                "test",
                "machine",
                {"pattern_id": "pat_1", "reason": "SUPERSEDED_INACTIVE"},
                event_id="evt_tombstone_1",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            first = project_events(events, root)
            self.assertTrue((root / "rules" / "always-on.md").exists())
            self.assertTrue((root / "archive" / "pat_1.md").exists())
            index_document = json.loads((root / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index_document["schema_version"], 2)
            self.assertIn("pat_1", index_document["archive_pattern_ids"])
            first_bytes = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            second = project_events(events, root)
            second_bytes = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)
            self.assertEqual(first_bytes, second_bytes)
            self.assertNotIn("pat_1", (root / "index.md").read_text(encoding="utf-8").split("## Active")[1].split("##")[0])
            self.assertIn("pat_1", (root / "index.md").read_text(encoding="utf-8"))
            self.assertTrue((root / "archive" / "pat_1.md").exists())


if __name__ == "__main__":
    unittest.main()
