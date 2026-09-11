from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ei.cli import _recall
from ei.config import RuntimePaths, Settings
from ei.models import Event
from ei.team_store import append_team_event, initialize_team_store
from ei.project import project_events


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def personal_event(*, host_scoped: bool = False) -> Event:
    payload = {
        "pattern_id": "pat_personal_host" if host_scoped else "pat_personal",
        "cluster_id": "cluster_personal_host" if host_scoped else "cluster_personal",
        "rule": "前回の検証手順を再利用し、変更点だけ追加確認する",
        "provenances": ["source:personal"],
        "scopes": ["general"],
        "applicability": ["general"],
        "benefit_count": 1,
        "classification": "private-reusable",
    }
    if host_scoped:
        payload.update(
            {
                "source_host_id": "test-compatible-cli",
                "source_host_family": "gemini-compatible",
                "applicability_scope": "family",
                "applicable_host_ids": [],
                "applicable_host_families": ["gemini-compatible"],
            }
        )
    return Event.create(
        "pattern.promoted",
        "2026-09-05T00:00:00Z",
        "test",
        "machine",
        payload,
        event_id="evt_personal_host" if host_scoped else "evt_personal",
    )


def team_event() -> Event:
    idempotency = "sha256:" + "a" * 64
    return Event.create_v2(
        "team.knowledge.recorded",
        actor="team-member-hash",
        machine_id="team-machine-hash",
        occurred_at=NOW,
        idempotency_key=idempotency,
        payload={
            "knowledge_scope": "team",
            "origin_event_hash": "sha256:" + "b" * 64,
            "idempotency_key": idempotency,
            "title": "Team rule",
            "claim": "チームで共有した検証手順を再利用し、変更点だけ追加確認する",
            "scope": ["general"],
            "preconditions": ["同じ問題構造が再発している"],
            "failure_modes": ["検証を省略して再作業になる"],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        },
    )


class PersonalTeamRecallIntegrationTests(unittest.TestCase):
    def _settings(self, root: Path, *, team: bool, personal_events: list[Event] | None = None) -> Settings:
        personal = root / "personal"
        team_root = root / "shared-team" if team else None
        paths = RuntimePaths(
            engine_root=root / "engine",
            personal_knowledge_root=personal,
            team_knowledge_root=team_root,
            runtime_root=root / "runtime",
        )
        settings = Settings(
            paths=paths,
            hosts={
                "test-compatible-cli": SimpleNamespace(host_family="gemini-compatible"),
                "codex-cli": SimpleNamespace(host_family="codex-compatible"),
            },
            retrieval_max_results=5,
            retrieval_max_chars=5000,
        )
        project_events(personal_events or [personal_event()], paths.knowledge_dir)
        if team_root is not None:
            initialize_team_store(team_root, now=NOW, random_id=lambda: "0123456789abcdef")
            append_team_event(team_root, "member-a", "writer_aaaaaaaaaaaaaaaa", team_event())
        return settings

    def _recall_json(self, settings: Settings, query: str = "検証手順", host: str = "") -> dict[str, object]:
        args = argparse.Namespace(
            query=query,
            max_chars=None,
            cwd=None,
            host=host,
            session_id="integration-session",
            settings=settings,
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(_recall(args), 0)
        return json.loads(output.getvalue())

    def test_enabled_recall_merges_personal_and_team_under_one_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self._recall_json(self._settings(Path(raw), team=True))
            self.assertEqual(result["status"], "ok")
            scopes = {item["knowledge_scope"] for item in result["hits"]}
            self.assertIn("personal", scopes)
            self.assertIn("team", scopes)
            self.assertIn("Scope: personal", result["context"])
            self.assertIn("Scope: team", result["context"])
            self.assertLessEqual(result["context_chars"], 5000)
            self.assertEqual(result["team_projection"]["status"], "UPDATED")

    def test_unavailable_team_keeps_personal_recall(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = self._settings(Path(raw), team=False)
            # Attach a team descriptor whose shared root is absent.  The
            # personal index must still be searchable and the failure is a
            # sanitized status only.
            paths = RuntimePaths(
                engine_root=Path(raw) / "engine",
                personal_knowledge_root=Path(raw) / "personal",
                team_knowledge_root=Path(raw) / "missing-team",
                runtime_root=Path(raw) / "runtime",
            )
            settings = Settings(paths=paths, retrieval_max_results=5, retrieval_max_chars=5000)
            project_events([personal_event()], paths.knowledge_dir)
            result = self._recall_json(settings)
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["hits"])
            self.assertEqual(result["team_projection"]["reason_codes"], ["TEAM_KNOWLEDGE_UNAVAILABLE"])
            self.assertTrue(result["team_projection"].get("status") in {"UNAVAILABLE", "DISABLED"})

    def test_personal_host_filter_keeps_universal_team_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = self._settings(
                Path(raw),
                team=True,
                personal_events=[personal_event(host_scoped=True)],
            )
            result = self._recall_json(settings, host="codex-cli")
            self.assertEqual(result["status"], "ok")
            self.assertNotIn("pat_personal_host", {item["pattern_id"] for item in result["hits"]})
            self.assertTrue(any(item["knowledge_scope"] == "team" for item in result["hits"]))

    def test_manual_cli_uses_configured_host_family_for_family_rule(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = self._settings(
                Path(raw),
                team=False,
                personal_events=[personal_event(host_scoped=True)],
            )
            result = self._recall_json(settings, host="test-compatible-cli")
            self.assertIn("pat_personal_host", {item["pattern_id"] for item in result["hits"]})

    def test_disabled_recall_does_not_call_team_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = self._settings(Path(raw), team=False)
            with patch("ei.team_projection.refresh_team_projection") as refresh:
                result = self._recall_json(settings)
            self.assertEqual(result["team_projection"], {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
            refresh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
