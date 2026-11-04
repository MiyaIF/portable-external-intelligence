import json
import tempfile
import unittest
from pathlib import Path

from ei.index import build_index, load_recall_index, read_index_item, read_index_items, read_recall_items
from ei.models import Event
from ei.project import project_events
from ei.retrieve import RetrievalQuery, search_index


class IndexTests(unittest.TestCase):
    def test_project_reference_observation_is_unpromoted_and_exact_cwd_scoped(self):
        cwd_fingerprint = "sha256:" + "a" * 64
        event = Event.create(
            "observation.recorded",
            "2026-09-01T00:00:00+00:00",
            "test",
            "machine",
            {
                "observation_id": "obs_project_reference",
                "title": "safe retry receipt",
                "claim": "A safe retry receipt prevents duplicate writes after a timeout.",
                "domain": "operations",
                "cwd_fingerprint": cwd_fingerprint,
                "provenance_key": "source:task-15",
                "outcome_status": "success",
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "precondition": "The first write may have completed before the timeout.",
                "failure_mode": "Retrying without checking can duplicate the write.",
                "exception": "Use this only when the receipt is bound to the same operation.",
                "version_constraint": ">=1.0,<2",
            },
            event_id="evt_project_reference",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([event], root)
            index = load_recall_index(root, root / "index.json")
            query = RetrievalQuery(prompt="safe retry receipt", cwd_fingerprint=cwd_fingerprint, version="1.5")

            hits = search_index(index, query)

            self.assertEqual([hit.pattern_id for hit in hits], ["obs_project_reference"])
            self.assertEqual(hits[0].knowledge_kind, "project-reference")
            self.assertEqual(read_index_items(index), ())
            self.assertEqual(
                search_index(index, RetrievalQuery(prompt=query.prompt, cwd_fingerprint="sha256:" + "b" * 64, version="1.5")),
                [],
            )
            self.assertEqual(search_index(index, RetrievalQuery(prompt=query.prompt, version="1.5")), [])
            self.assertEqual(search_index(index, RetrievalQuery(prompt=query.prompt, cwd_fingerprint=cwd_fingerprint)), [])
            self.assertEqual(search_index(index, RetrievalQuery(prompt=query.prompt, cwd_fingerprint=cwd_fingerprint, version="2.0")), [])
            self.assertEqual(search_index(index, RetrievalQuery(prompt="", cwd_fingerprint=cwd_fingerprint, version="1.5")), [])
            self.assertEqual(index.active_pattern_ids, ())

    def test_project_reference_roundtrips_multiple_host_and_applicability_lists(self):
        from ei.operation_runtime import OperationBudget

        cwd_fingerprint = "sha256:" + "9" * 64
        claim = "A multi-host reliability receipt can be reused only in this project."
        event = Event.create(
            "observation.recorded", "2026-09-01T00:00:00+00:00", "test", "machine",
            {
                "observation_id": "obs_multi_host",
                "claim": claim,
                "domain": "operations",
                "applicability": ["operations", "reliability"],
                "cwd_fingerprint": cwd_fingerprint,
                "classification": "private-reusable",
                "version_constraint": ">=1.0,<2",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
                "applicability_scope": "host",
                "applicable_host_ids": ["codex-cli", "gemini-cli"],
                "applicable_host_families": [],
            },
            event_id="evt_multi_host",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([event], root, budget=OperationBudget(10000))
            index = load_recall_index(root, root / "index.json")

            hits = search_index(index, RetrievalQuery(
                prompt="multi-host reliability receipt",
                domain="reliability",
                host_id="gemini-cli",
                host_family="gemini-compatible",
                cwd_fingerprint=cwd_fingerprint,
                version="1.5",
            ))

        self.assertEqual([hit.pattern_id for hit in hits], ["obs_multi_host"])
        self.assertEqual(hits[0].knowledge_kind, "project-reference")

    def test_large_project_reference_selection_checks_deadline_before_body_reads(self):
        from unittest.mock import patch
        from ei.operation_runtime import OperationBudget

        cwd_fingerprint = "sha256:" + "7" * 64
        events = [
            Event.create(
                "observation.recorded", "2026-09-01T00:00:00+00:00", "test", "machine",
                {
                    "observation_id": f"obs_deadline_{number:03d}",
                    "claim": f"Project-scoped deadline receipt number {number}.",
                    "cwd_fingerprint": cwd_fingerprint,
                    "classification": "private-reusable",
                },
                event_id=f"evt_deadline_{number:03d}",
            )
            for number in range(256)
        ]

        class SelectionBudget:
            def __init__(self):
                self.armed = False
                self.checks_after_binding = 0

            def check(self):
                if self.armed:
                    self.checks_after_binding += 1
                    if self.checks_after_binding >= 2:
                        raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(events, root, budget=OperationBudget(120000))
            index = load_recall_index(root, root / "index.json")
            budget = SelectionBudget()
            from ei import index as index_module
            real_bound = index_module._bound_recall_document

            def bind_then_arm(index_arg, *, budget=None):
                result = real_bound(index_arg, budget=budget)
                budget.armed = True
                return result

            with patch("ei.index._bound_recall_document", side_effect=bind_then_arm), patch(
                "ei.index._read_item", wraps=index_module._read_item
            ) as read_item:
                with self.assertRaisesRegex(TimeoutError, "OPERATION_BUDGET_EXHAUSTED"):
                    read_recall_items(index, cwd_fingerprint, budget=budget)

        self.assertEqual(budget.checks_after_binding, 2)
        self.assertEqual(read_item.call_count, 0)

    def test_recall_bounds_total_selected_raw_bodies_at_64_mib(self):
        import hashlib

        mib = 1024 * 1024

        def write_legacy_index(root, sizes):
            rules = root / "rules"
            rules.mkdir(parents=True)
            item_ids = []
            files = {}
            for number, size in enumerate(sizes):
                item_id = f"pat_size_{number:02d}"
                item_ids.append(item_id)
                prefix = f"# {item_id}\n\n- Status: active\n\n".encode("utf-8")
                body = prefix + b"x" * max(0, size - len(prefix)) if size >= len(prefix) else b"x" * size
                path = rules / f"{item_id}.md"
                path.write_bytes(body)
                files[f"rules/{item_id}.md"] = hashlib.sha256(body).hexdigest()
            document = {
                "schema_version": 2,
                "active_pattern_ids": item_ids,
                "candidate_pattern_ids": [],
                "archive_pattern_ids": [],
                "observation_ids": [],
                "files": files,
            }
            index_path = root / "index.json"
            index_path.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
            return load_recall_index(root, index_path)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "within-limit"
            index = write_legacy_index(root, [8 * mib] * 8)
            items = read_recall_items(index, "")
            self.assertEqual(len(items), 8)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "over-limit"
            index = write_legacy_index(root, [8 * mib] * 8 + [1])
            with self.assertRaisesRegex(ValueError, "PROJECTION_STORAGE_LIMIT"):
                read_recall_items(index, "")

    def test_recall_loader_does_not_read_unrelated_large_item_body(self):
        import os
        from unittest.mock import patch
        from ei.operation_runtime import OperationBudget

        cwd_fingerprint = "sha256:" + "c" * 64
        active = Event.create(
            "pattern.promoted", "2026-09-01T00:00:00+00:00", "test", "machine",
            {"pattern_id": "pat_active", "rule": "Active verified procedure", "classification": "private-reusable"},
            event_id="evt_active",
        )
        unrelated = Event.create(
            "pattern.candidate_created", "2026-09-01T00:00:00+00:00", "test", "machine",
            {"pattern_id": "pat_unrelated", "rule": "large unrelated body " + ("x" * 1_000_000), "classification": "private-reusable"},
            event_id="evt_unrelated",
        )
        observation = Event.create(
            "observation.recorded", "2026-09-01T00:00:00+00:00", "test", "machine",
            {"observation_id": "obs_selected", "title": "selected reference", "claim": "A selected reference is scoped to this exact project.",
             "cwd_fingerprint": cwd_fingerprint, "classification": "private-reusable"},
            event_id="evt_selected",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([active, unrelated, observation], root, budget=OperationBudget(30000))
            pointer = json.loads((root / "index.json").read_text(encoding="utf-8"))
            unrelated_path = root / pointer["projection_generation"]["path"] / "library" / "pat_unrelated.md"
            opened = []
            real_open = os.open

            def tracked_open(path, *args, **kwargs):
                opened.append(Path(os.fsdecode(path)).resolve())
                return real_open(path, *args, **kwargs)

            with patch("ei.index.os.open", side_effect=tracked_open):
                index = load_recall_index(root, root / "index.json")
                items = read_recall_items(index, cwd_fingerprint)

            self.assertEqual({item["item_id"] for item in items}, {"pat_active", "obs_selected"})
            self.assertIn((root / pointer["projection_generation"]["path"] / "memories" / "obs_selected.md").resolve(), opened)
            self.assertNotIn(unrelated_path.resolve(), opened)

    def test_recall_rejects_selected_body_hash_mismatch_and_missing_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            index = project_events([self._observation_event("sha256:" + "d" * 64)], root)
            loaded = load_recall_index(root, root / "index.json")
            selected = index.index_path.parent / "memories" / "obs_recall_test.md"
            selected.write_text(selected.read_text(encoding="utf-8") + "altered\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INDEX_ITEM_HASH_MISMATCH"):
                read_recall_items(loaded, "sha256:" + "d" * 64)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rules").mkdir()
            (root / "rules" / "pat_missing_hash.md").write_text("# Missing hash\n\n- Status: active\n\nVerified rule\n", encoding="utf-8")
            document = {"schema_version": 2, "active_pattern_ids": ["pat_missing_hash"], "candidate_pattern_ids": [],
                        "archive_pattern_ids": [], "observation_ids": [], "files": {}}
            (root / "index.json").write_text(json.dumps(document), encoding="utf-8")
            loaded = load_recall_index(root, root / "index.json")
            with self.assertRaisesRegex(ValueError, "INDEX_ITEM_HASH_REQUIRED"):
                read_recall_items(loaded, "")

    def test_recall_rejects_selected_body_reparse_point(self):
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

        cwd_fingerprint = "sha256:" + "f" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([self._observation_event(cwd_fingerprint)], root)
            loaded = load_recall_index(root, root / "index.json")
            selected = loaded.index_path.parent / "memories" / "obs_recall_test.md"
            original = Path.stat

            def reparse_probe(path, *, follow_symlinks=True):
                if Path(path) == selected and not follow_symlinks:
                    return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0, st_reparse_tag=0)
                return original(path, follow_symlinks=follow_symlinks)

            with patch.object(Path, "stat", reparse_probe):
                with self.assertRaisesRegex(ValueError, "UNSAFE_REPARSE_POINT"):
                    read_recall_items(loaded, cwd_fingerprint)

    def test_legacy_recall_index_and_selected_body_require_exact_hash_bindings(self):
        import hashlib
        from unittest.mock import patch

        cwd_fingerprint = "sha256:" + "9" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            memories = root / "memories"
            memories.mkdir(parents=True)
            selected = memories / "obs_legacy.md"
            body = (
                "# Legacy project reference\n\n"
                f"- Cwd fingerprint: {cwd_fingerprint}\n"
                "- Classification: private-reusable\n"
                "- Recorded at: 2026-09-01T00:00:00+00:00\n\n"
                "Check the receipt before retrying.\n"
            ).encode("utf-8")
            selected.write_bytes(body)
            index_path = root / "index.json"
            index_path.write_text(json.dumps({
                "schema_version": 2,
                "active_pattern_ids": [],
                "candidate_pattern_ids": [],
                "archive_pattern_ids": [],
                "observation_ids": ["obs_legacy"],
                "project_reference_ids_by_cwd": {cwd_fingerprint: ["obs_legacy"]},
                "files": {"memories/obs_legacy.md": hashlib.sha256(body).hexdigest()},
            }), encoding="utf-8")
            loaded = load_recall_index(root, index_path)
            original = Path.read_bytes

            def forbid_unbound_selected_read(path):
                if Path(path) == selected:
                    raise AssertionError("legacy selected item bypassed safe identity reader")
                return original(path)

            with patch.object(Path, "read_bytes", forbid_unbound_selected_read):
                items = read_recall_items(loaded, cwd_fingerprint)
            self.assertEqual([item["item_id"] for item in items], ["obs_legacy"])

            selected.write_bytes(body + b"tampered\n")
            with self.assertRaisesRegex(ValueError, "INDEX_ITEM_HASH_MISMATCH"):
                read_recall_items(loaded, cwd_fingerprint)

            index_path.write_bytes(index_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "INDEX_BINDING_INVALID"):
                read_recall_items(loaded, cwd_fingerprint)

    def test_recall_loader_checks_generation_expiry_and_deadline(self):
        from ei.operation_runtime import OperationBudget

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            first = self._observation_event("sha256:" + "e" * 64)
            loaded = None
            for number in range(3):
                project_events([first, Event.create(
                    "observation.recorded", f"2026-09-0{number + 2}T00:00:00+00:00", "test", "machine",
                    {"observation_id": f"obs_update_{number}", "claim": f"Project update {number}.",
                     "cwd_fingerprint": "sha256:" + "e" * 64, "classification": "private-reusable"},
                    event_id=f"evt_update_{number}",
                )], root, budget=OperationBudget(10000))
                if number == 0:
                    loaded = load_recall_index(root, root / "index.json")
            self.assertIsNotNone(loaded)
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_EXPIRED"):
                read_recall_items(loaded, "sha256:" + "e" * 64)
            with self.assertRaises(TimeoutError):
                load_recall_index(root, root / "index.json", budget=OperationBudget(0))

    def test_recall_revalidates_reference_count_after_previous_generation_resolution(self):
        import hashlib
        from dataclasses import replace
        from ei.operation_runtime import OperationBudget

        cwd_fingerprint = "sha256:" + "8" * 64
        observation = self._observation_event(cwd_fingerprint)
        update = Event.create(
            "observation.recorded", "2026-09-02T00:00:00+00:00", "test", "machine",
            {"observation_id": "obs_generation_update", "claim": "A new project observation.",
             "cwd_fingerprint": cwd_fingerprint, "classification": "private-reusable"},
            event_id="evt_generation_update",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([observation], root, budget=OperationBudget(30000))
            prior_index = load_recall_index(root, root / "index.json")
            project_events([observation, update], root, budget=OperationBudget(30000))

            pointer_path = root / "index.json"
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            previous = pointer["projection_generation"]["previous"]
            generation = root / previous["path"]
            snapshot_index = generation / "index.json"
            snapshot = json.loads(snapshot_index.read_text(encoding="utf-8"))
            snapshot["project_reference_ids_by_cwd"] = {cwd_fingerprint: ["obs_recall_test"] * 120001}
            snapshot_raw = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            snapshot_index.write_bytes(snapshot_raw)

            manifest_path = generation / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["index.json"] = hashlib.sha256(snapshot_raw).hexdigest()
            manifest_raw = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            manifest_path.write_bytes(manifest_raw)
            manifest_hash = hashlib.sha256(manifest_raw).hexdigest()
            renamed_generation = generation.parent / manifest_hash
            generation.rename(renamed_generation)

            pointer["projection_generation"]["previous"] = {
                "path": f".projection-generations/{manifest_hash}",
                "manifest_sha256": manifest_hash,
            }
            pointer_path.write_text(json.dumps(pointer, ensure_ascii=False), encoding="utf-8")
            previous_index = replace(prior_index, generation_hash=manifest_hash, manifest_sha256=manifest_hash)

            with self.assertRaisesRegex(ValueError, "PROJECTION_STORAGE_LIMIT"):
                read_recall_items(previous_index, cwd_fingerprint)

    @staticmethod
    def _observation_event(cwd_fingerprint):
        return Event.create(
            "observation.recorded", "2026-09-01T00:00:00+00:00", "test", "machine",
            {"observation_id": "obs_recall_test", "claim": "A project reference stays in the current project.",
             "cwd_fingerprint": cwd_fingerprint, "classification": "private-reusable"},
            event_id="evt_recall_test",
        )

    def test_bounded_index_rejects_knowledge_root_alias_before_resolution(self):
        import os
        import subprocess
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside, alias = root / "knowledge", root / "alias"
            project_events(self._events(), outside, budget=OperationBudget(10000))
            if os.name == "nt":
                result = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(outside)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0)
            else:
                alias.symlink_to(outside, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, "UNSAFE_REPARSE_POINT"):
                    build_index(alias, alias / "index.json", budget=OperationBudget(5000))
            finally:
                alias.rmdir() if os.name == "nt" else alias.unlink()

    def test_generation_handle_rechecks_bound_index_bytes(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            index = project_events(self._events(), Path(tmp), budget=OperationBudget(10000))
            document = json.loads(index.index_path.read_bytes())
            document["always_on_chars"] = 0
            index.index_path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "PROJECTION_MANIFEST_MISMATCH"):
                read_index_item(index, "pat_formula")

    def test_zero_budget_does_not_read_item(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            index = project_events(self._events(), Path(tmp))
            with self.assertRaises(TimeoutError):
                read_index_item(index, "pat_formula", budget=OperationBudget(0))

    def test_generation_path_must_match_its_manifest_identity(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            index = project_events(self._events(), root, budget=OperationBudget(10000))
            replacement = index.index_path.parent.with_name("0" * 64)
            index.index_path.parent.rename(replacement)
            path = root / "index.json"
            document = json.loads(path.read_text())
            document["projection_generation"]["path"] = replacement.relative_to(root).as_posix()
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_INVALID"):
                build_index(root, path)

    def test_read_file_rejects_same_path_replacement_during_read(self):
        from ei.index import _read_projection_bytes
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            path.write_bytes(b"first")
            real_fstat = os.fstat
            def changed(fd):
                result = real_fstat(fd)
                path.write_bytes(b"different length")
                return result
            with patch("ei.index.os.fstat", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "INDEX_FILE_CHANGED"):
                    _read_projection_bytes(path)

    def test_present_null_generation_pointer_does_not_fallback_to_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events(self._events(), root)
            path = root / "index.json"
            document = json.loads(path.read_text())
            document["projection_generation"] = None
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_INVALID"):
                build_index(root, path)

    def test_budget_exhaustion_is_not_reported_as_corruption(self):
        from ei.operation_runtime import OperationBudget
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events(self._events(), root)
            with patch("ei.index._read_projection_bytes", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")):
                with self.assertRaises(TimeoutError):
                    build_index(root, root / "index.json", budget=OperationBudget(1000))

    def _events(self):
        return [
            Event.create(
                "pattern.promoted",
                "2026-08-25T00:00:00+00:00",
                "test",
                "machine",
                {
                    "pattern_id": "pat_formula",
                    "cluster_id": "cluster_formula",
                    "rule": "書込後は対象範囲を再読込し数式と値を検証する",
                    "provenances": ["source:a", "source:b"],
                    "scopes": ["cwd:a", "cwd:b"],
                    "applicability": ["spreadsheet"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                },
                event_id="evt_pattern_formula",
            ),
        ]

    def test_build_and_read_index_is_immutable_handle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index = build_index(root, root / "index.json")
            self.assertEqual(index.schema_version, "2")
            self.assertEqual(index.item_count, 1)
            item = read_index_item(index, "pat_formula")
            self.assertEqual(item["rule"], "書込後は対象範囲を再読込し数式と値を検証する")
            self.assertEqual(item["applicability"], ["spreadsheet"])
            hits = search_index(index, RetrievalQuery(prompt="再読込 数式", domain="spreadsheet"))
            self.assertEqual([hit.pattern_id for hit in hits], ["pat_formula"])

    def test_corrupt_projection_is_rejected_by_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index_document = json.loads((root / "index.json").read_text(encoding="utf-8"))
            target = root / "rules" / "pat_formula.md"
            target.write_text(target.read_text(encoding="utf-8") + "改ざん\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INDEX_FILE_HASH_MISMATCH"):
                build_index(root, root / "index.json")
            index_document["files"] = index_document["files"]

    def test_item_id_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index = build_index(root, root / "index.json")
            with self.assertRaisesRegex(ValueError, "INDEX_ITEM_ID_INVALID"):
                read_index_item(index, "../secret")


if __name__ == "__main__":
    unittest.main()
