import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ei.config import load_settings
from ei.experiment import ExperimentConfig, assign_arm, summarize_experiment
from ei.measurement_events import (
    ExposureRecord,
    OutcomeRecord,
    measurement_paths,
    record_exposure,
    record_outcome,
)
from ei.metrics import read_deduplicated_usage


class HostNeutralMeasurementTests(unittest.TestCase):
    def test_exposure_rejects_runtime_alias_before_resolving_it(self):
        import os
        import subprocess
        from types import SimpleNamespace
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside, link = root / "outside", root / "runtime-link"
            outside.mkdir()
            if os.name == "nt":
                result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0)
            else:
                link.symlink_to(outside, target_is_directory=True)
            try:
                settings = SimpleNamespace(paths=SimpleNamespace(runtime_root=link))
                value = ExposureRecord(experiment_id="test", session_id_hash="one", task_id_hash="one", arm="control")
                with self.assertRaisesRegex(ValueError, "UNSAFE_REPARSE_POINT"):
                    record_exposure(value, settings, budget=OperationBudget(5000))
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                link.rmdir() if os.name == "nt" else link.unlink()

    def test_exposure_budget_preserves_log_on_interrupted_scan_and_lock_contention(self):
        from ei.measurement_events import _exclusive_lock
        from ei.operation_runtime import OperationBudget
        from tests.integration.test_unattended_operation import RemainingBudget
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            first = ExposureRecord(experiment_id="test", session_id_hash="one", task_id_hash="one", query_fingerprint="query", arm="control", protocol_hash=ExperimentConfig.defaults().protocol_hash)
            second = ExposureRecord(experiment_id="test", session_id_hash="two", task_id_hash="two", query_fingerprint="query", arm="control", protocol_hash=ExperimentConfig.defaults().protocol_hash)
            with self.assertRaises(TimeoutError):
                record_exposure(first, settings, budget=OperationBudget(0))
            path = measurement_paths(settings)["exposures"]
            self.assertFalse(path.exists())
            record_exposure(first, settings)
            before = path.read_bytes()
            budget = RemainingBudget()
            loads = json.loads
            def expire(raw):
                value = loads(raw)
                budget.remaining = 0
                return value
            with patch("ei.measurement_events.json.loads", side_effect=expire), self.assertRaises(TimeoutError):
                record_exposure(second, settings, budget=budget)
            self.assertEqual(path.read_bytes(), before)
            with _exclusive_lock(path.with_name(path.name + ".lock")):
                with self.assertRaises(TimeoutError):
                    record_exposure(second, settings, budget=OperationBudget(30))
            self.assertEqual(path.read_bytes(), before)
            record_exposure(second, settings, budget=OperationBudget(5000))
            record_exposure(second, settings, budget=OperationBudget(5000))
            self.assertEqual(len(path.read_text().splitlines()), 2)

    def _settings(self, root: Path):
        (root / "config").mkdir()
        (root / "config" / "defaults.json").write_text(
            json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
            encoding="utf-8",
        )
        return load_settings(repo_root=root, codex_home=root / "home", runtime_root=root / "runtime", host_homes={})

    def test_exposure_and_outcome_are_hashed_deduplicated_and_raw_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            exposure = ExposureRecord(
                experiment_id="retrieval-v1",
                session_id_hash="private-session",
                task_id_hash="private-task",
                query_fingerprint="raw query must never be stored",
                arm="treatment",
                candidate_ids=("pat_1", "pat_2"),
                selected_ids=("pat_1",),
                injected_chars=240,
                retrieval_latency_ms=12,
                host_id="codex-cli",
                model_family="gpt",
                domain="spreadsheet",
                protocol_hash=ExperimentConfig.defaults().protocol_hash,
            )
            outcome = OutcomeRecord(
                experiment_id="retrieval-v1",
                session_id_hash="private-session",
                task_id_hash="private-task",
                exposure_id=exposure.exposure_id,
                host_id="codex-cli",
                model_family="gpt",
                domain="spreadsheet",
                repeated_search=1,
                rework=0,
                failure=0,
                completion=1,
                turns_to_completion=3,
                retry_count=0,
                metric_sources={
                    "repeated_search": "direct_outcome_events",
                    "rework": "direct_outcome_events",
                    "failure": "direct_outcome_events",
                    "completion": "direct_outcome_events",
                    "turns_to_completion": "hook_events",
                },
                provenance=("private-provenance",),
            )
            first = record_exposure(exposure, settings)
            second = record_exposure(exposure, settings)
            self.assertEqual(first, second)
            self.assertEqual(record_outcome(outcome, settings), outcome.outcome_id)
            paths = measurement_paths(settings)
            self.assertEqual(len(paths["exposures"].read_text(encoding="utf-8").splitlines()), 1)
            serialized = paths["exposures"].read_text(encoding="utf-8") + paths["outcomes"].read_text(encoding="utf-8")
            self.assertNotIn("private-session", serialized)
            self.assertNotIn("private-task", serialized)
            self.assertNotIn("raw query must never be stored", serialized)
            self.assertNotIn("private-provenance", serialized)
            self.assertIn("session_id_hash", serialized)

    def test_control_violation_is_contamination_and_causal_effect_is_blocked(self):
        config = ExperimentConfig.defaults()
        session_hash = "sha256:" + "1" * 12
        exposures = [{
            "experiment_id": config.experiment_id,
            "protocol_hash": config.protocol_hash,
            "session_id_hash": session_hash,
            "task_id_hash": "sha256:" + "2" * 12,
            "variant": "control",
            "arm": "control",
            "candidate_ids": ["pat_1"],
            "selected_ids": ["pat_1"],
            "injected_chars": 10,
            "context_injected": True,
            "observed_at": "2026-08-01T00:00:00Z",
            "eligible": True,
        }]
        summary = summarize_experiment(exposures, [], config)
        self.assertEqual(summary["conclusion"], "CAUSAL_EFFECT_NOT_IDENTIFIED")
        self.assertGreater(summary["audit"]["contamination_count"], 0)

    def test_sqlite_unknown_schema_is_not_guessed_and_database_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "unknown.sqlite"
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE transcript (prompt TEXT, response TEXT)")
                connection.execute("INSERT INTO transcript VALUES ('private prompt', 'private response')")
                connection.commit()
            finally:
                connection.close()
            before = database.read_bytes()
            result = read_deduplicated_usage(database)
            self.assertEqual(result.status, "SQLITE_SCHEMA_UNSUPPORTED")
            self.assertEqual(result.schema.reason_code, "SQLITE_SCHEMA_UNSUPPORTED")
            self.assertEqual(database.read_bytes(), before)
            self.assertNotIn("private prompt", json.dumps(result.__dict__, default=str))
            self.assertNotIn("private response", json.dumps(result.__dict__, default=str))


    def test_sqlite_deduplicates_host_session_turn_source_key_and_separates_article(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "usage.sqlite"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "CREATE TABLE turn_usage (id TEXT, input_tokens INTEGER, cached_input_tokens INTEGER, created_at TEXT, host_id TEXT, session_id_hash TEXT, turn_id_hash TEXT, source_key TEXT, classification TEXT)"
                )
                rows = [
                    ("one", 100, 80, "2026-08-01T00:00:00Z", "h", "s", "t", "source", "local"),
                    ("two", 900, 700, "2026-08-01T00:00:00Z", "h", "s", "t", "source", "local"),
                    ("three", 50, 40, "2026-08-01T00:00:00Z", "h", "s2", "t2", "article", "external_article_copy"),
                ]
                connection.executemany("INSERT INTO turn_usage VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
                connection.commit()
            finally:
                connection.close()
            result = read_deduplicated_usage(database)
            self.assertEqual(result.status, "OK")
            self.assertEqual(len(result.rows), 2)
            self.assertEqual(result.aggregate.user_environment.input_tokens, 100)
            self.assertEqual(result.aggregate.external_reference.input_tokens, 50)
            self.assertTrue(result.schema.schema_sha256)
if __name__ == "__main__":
    unittest.main()
