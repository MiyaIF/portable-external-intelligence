import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ei.cli import main
from ei.index import build_index
from ei.incidents import incident_id
from ei.maintainer import QueueDrainResult, run_maintenance
from ei.operation_health import HealthInput
from ei.operation_runtime import OperationBudget
from ei.reconciliation import ReconciliationResult
from tests.helpers import make_hook_settings


class MaintenanceTests(unittest.TestCase):
    def test_closeout_recovery_precedes_spool_gc_and_uses_the_shared_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
            budget = OperationBudget(30000)
            calls = []

            def recover(selected_settings, *, now, budget, max_records):
                calls.append(("closeout_recovery", selected_settings, now, budget, max_records))
                return {"processed": 0, "results": [], "reason_code": "CLOSEOUT_RECOVERY_COMPLETE"}

            def gc(selected_settings, *, now, budget):
                calls.append(("spool_gc", selected_settings, now, budget))
                return 0

            with patch("ei.pending_capture.reconcile_pending", return_value={}), \
                    patch("ei.maintainer._ingest", return_value=(0, 0, 0, 0, 0, ())), \
                    patch("ei.closeout_association.recover_closeout_associations", side_effect=recover), \
                    patch("ei.maintainer.gc_expired_spool", side_effect=gc), \
                    patch("ei.maintainer.drain_queue", return_value=QueueDrainResult("success", 0, 0, 0, 0, 0, 0, 0, 0)), \
                    patch("ei.maintainer._events", return_value=[]), \
                    patch("ei.maintainer.reconcile_lifecycle", return_value=ReconciliationResult(0, 0, 0, 0, 0, 0, 0, 0)), \
                    patch("ei.maintainer.project_events", return_value=None), \
                    patch("ei.maintainer._maintain_team", return_value={"status": "DISABLED", "reason_code": "TEAM_DISABLED"}), \
                    patch("ei.maintainer._metric_summary", return_value={"status": "unknown"}), \
                    patch("ei.task_scheduler.inspect_scheduler_opportunities", return_value={"requested": False, "missed_eligible_runs": None, "next_run_at": None, "reason_code": "DISABLED"}), \
                    patch("ei.operation_runtime.collect_operation_snapshot", return_value=(HealthInput(), {})), \
                    patch("ei.operation_runtime.write_operation_snapshot", side_effect=lambda settings, snapshot, **kwargs: snapshot), \
                    patch("ei.operation_runtime.service_operation", return_value={"reason_code": "OK", "issues": [], "notifications_sent": 0}), \
                    patch("ei.operation_runtime.settings_binding", return_value="sha256:" + "a" * 64):
                run_maintenance(settings, now=now, budget=budget, time_budget_ms=30000)

            self.assertEqual([call[0] for call in calls], ["closeout_recovery", "spool_gc"])
            self.assertIs(calls[0][1], settings)
            self.assertIs(calls[0][2], now)
            self.assertIs(calls[0][3], budget)
            self.assertEqual(calls[0][4], 64)
            self.assertIs(calls[1][3], budget)

    def test_recovery_traversal_complete_does_not_resolve_pending_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
            resolutions_seen = []

            def service(_settings, *, verified_resolutions=(), **_kwargs):
                resolutions_seen.extend(verified_resolutions)
                return {"reason_code": "OK", "issues": [], "notifications_sent": 0}

            unresolved = HealthInput(
                closeout_pending_count=None,
                closeout_pending_bytes=None,
                closeout_pending_status="UNKNOWN",
                closeout_unknown_count=1,
            )
            recovery = {
                "processed": 1,
                "results": [{"association": "PENDING", "reason_code": "CLOSEOUT_PROOF_PENDING"}],
                "reason_code": "CLOSEOUT_RECOVERY_COMPLETE",
            }
            with patch("ei.pending_capture.reconcile_pending", return_value={}), \
                    patch("ei.maintainer._ingest", return_value=(0, 0, 0, 0, 0, ())), \
                    patch("ei.closeout_association.recover_closeout_associations", return_value=recovery), \
                    patch("ei.maintainer.gc_expired_spool", return_value=0), \
                    patch("ei.maintainer.drain_queue", return_value=QueueDrainResult("success", 0, 0, 0, 0, 0, 0, 0, 0)), \
                    patch("ei.maintainer._events", return_value=[]), \
                    patch("ei.maintainer.reconcile_lifecycle", return_value=ReconciliationResult(0, 0, 0, 0, 0, 0, 0, 0)), \
                    patch("ei.maintainer.project_events", return_value=None), \
                    patch("ei.maintainer._maintain_team", return_value={"status": "DISABLED", "reason_code": "TEAM_DISABLED"}), \
                    patch("ei.maintainer._metric_summary", return_value={"status": "unknown"}), \
                    patch("ei.task_scheduler.inspect_scheduler_opportunities", return_value={"requested": False, "missed_eligible_runs": None, "next_run_at": None, "reason_code": "DISABLED"}), \
                    patch("ei.operation_runtime.collect_operation_snapshot", return_value=(unresolved, {})), \
                    patch("ei.operation_runtime.write_operation_snapshot", side_effect=lambda _settings, snapshot, **_kwargs: snapshot), \
                    patch("ei.operation_runtime.service_operation", side_effect=service), \
                    patch("ei.operation_runtime.settings_binding", return_value="sha256:" + "a" * 64):
                result = run_maintenance(settings, now=now, budget=OperationBudget(30000), time_budget_ms=30000)

            self.assertIn("CLOSEOUT_METADATA_UNKNOWN", {row["error_code"] for row in result.errors})
            self.assertNotIn(incident_id("CLOSEOUT_ASSOCIATION_PENDING", "closeout-store"), resolutions_seen)
            self.assertNotIn(incident_id("CLOSEOUT_METADATA_UNKNOWN", "closeout-store"), resolutions_seen)

    def test_maintenance_is_idempotent_and_partial_failure_preserves_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            engine = workspace / "engine"
            knowledge_root = workspace / "knowledge"
            knowledge = knowledge_root / "knowledge"
            runtime = workspace / "runtime"
            codex_home = workspace / "host" / "codex"
            inputs = workspace / "inputs"
            for directory in (engine, knowledge_root, knowledge, runtime, codex_home, inputs):
                directory.mkdir(parents=True, exist_ok=True)
            (engine / "config").mkdir()
            (engine / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            valid = inputs / "valid.md"
            valid.write_text("## Reusable knowledge\n- 書込後は再読込して確認する\n", encoding="utf-8")
            common = ["--engine-root", str(engine), "--knowledge-root", str(knowledge_root), "--codex-home", str(codex_home), "--runtime-root", str(runtime)]
            def current_manifest():
                index = build_index(knowledge, knowledge / "index.json")
                return (index.index_path.parent / "manifest.json").read_bytes()
            first_code = main(["maintain", *common, "--source", str(valid), "--json"])
            self.assertEqual(first_code, 0)
            manifest = current_manifest()
            second_code = main(["maintain", *common, "--source", str(valid), "--json"])
            self.assertEqual(second_code, 0)
            self.assertEqual(manifest, current_manifest())
            invalid = inputs / "invalid.md"
            invalid.write_bytes(b"\xff\xfe")
            output = io.StringIO()
            with redirect_stdout(output):
                partial_code = main(["maintain", *common, "--source", str(valid), "--source", str(invalid), "--json"])
            self.assertEqual(partial_code, 0)
            result = json.loads(output.getvalue())
            health = json.loads((runtime / "health.json").read_text(encoding="utf-8"))
            self.assertEqual(health["status"], "partial")
            self.assertEqual(result["ingest_parse_skipped"], 1)
            self.assertEqual({item["error_code"] for item in health["errors"]}, {"SOURCE_PARTIAL"})
            self.assertEqual(result["ingest_results"][1]["coverage"], "UNKNOWN")
            self.assertEqual(result["ingest_results"][1]["secured"], 0)
            self.assertEqual(health["knowledge_stores"]["personal"]["status"], "READY")
            self.assertEqual(health["knowledge_stores"]["team"], {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
            self.assertEqual(manifest, current_manifest())


if __name__ == "__main__":
    unittest.main()
