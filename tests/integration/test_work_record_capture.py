from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from ei.cli import _recall
from ei.inference.base import ProviderResult
from ei.key_provider import InMemoryKeyProvider
from ei.journal import iter_events
from ei.maintainer import run_maintenance
from ei.queue import list_queue_items
from ei.setup_contract import OrganizerSelection
from tests.unit.test_closeout_context import InstalledAdapterFixture
from tests.unit.test_maintainer import YesProvider


class _WorkRecordProvider(YesProvider):
    provider_id = "work-record-integration"

    def __init__(self):
        self.extractions = 0

    def generate(self, schema_name, input_json, budget):
        if schema_name == "work-record-extraction":
            self.extractions += 1
            return ProviderResult(self.provider_id, "success", output={
                "result": "candidate",
                "title": "完了後に対象範囲を再読込する",
                "claim": "作業結果を確定した後は、対象範囲を再読込し、保存された値と表示状態を照合する。確認で差異があれば入力値に戻って修正し、同じ範囲を再度読み込んで保存状態が一致するまで検証を繰り返す。",
            }, schema_name=schema_name)
        return super().generate(schema_name, input_json, budget)


def _write_turn(path: Path, project: Path, session_id: str, turn_id: str) -> None:
    rows = [
        {"type": "session_meta", "payload": {"id": session_id, "cwd": str(project), "originator": "codex_cli_rs", "source": "cli"}},
        {"type": "turn_context", "payload": {"turn_id": turn_id, "cwd": str(project)}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": "作業結果を確定し、保存後に対象範囲を再読込して値を照合してください。"}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "対象範囲を再読込して保存値を照合しました。"}]}},
        {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "確認を完了しました。"}},
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def _run_recall(settings, *, query: str, project: Path, domain: str) -> dict:
    output = io.StringIO()
    with redirect_stdout(output):
        code = _recall(
            SimpleNamespace(
                query=query, max_chars=None, cwd=str(project), host="codex-cli", domain=domain,
                scope=(), version="", session_id="work-record-integration", settings=settings,
            )
        )
    if code != 0:
        raise AssertionError(f"recall exit={code}: {output.getvalue()}")
    return json.loads(output.getvalue())


class WorkRecordCaptureIntegrationTests(unittest.TestCase):
    def test_captured_turns_flow_through_project_save_and_scoped_recall(self):
        fixture = InstalledAdapterFixture(self, turns=0)
        manifest_path = fixture.settings.paths.install_manifest_path
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["skill_auto_apply"] = True
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        settings = replace(fixture.settings, organizer=OrganizerSelection("READY", "ollama", None), skill_auto_apply=True)
        sessions = settings.hosts["codex-cli"].hook_config_path.parent / "sessions"
        project_a = settings.paths.engine_root / "project-a"
        unrelated = settings.paths.engine_root / "unrelated-project"
        for project in (project_a, unrelated):
            project.mkdir(parents=True)
        _write_turn(sessions / "2026" / "11" / "05" / "rollout-project-a.jsonl", project_a, "session-a", "turn-a")
        provider = _WorkRecordProvider()

        from unittest.mock import patch
        key_patch = patch("ei.spool.default_key_provider", return_value=InMemoryKeyProvider("work-record-key", b"w" * 32))
        key_patch.start()
        self.addCleanup(key_patch.stop)
        result = run_maintenance(settings, provider=provider, max_queue_items=8)

        self.assertEqual(result.capture["work_records"]["secured"], 1, msg=str(result.capture))
        self.assertEqual(provider.extractions, 1)
        self.assertEqual(result.queue["completed"], 1, msg=str(result.queue))
        self.assertFalse(list_queue_items(settings, include_terminal=False))
        self.assertTrue(any(event.event_type == "observation.recorded" for event in iter_events(settings.paths.event_dir)))

        query = "対象範囲を再読込し保存された値と表示状態を照合する"
        same_project = _run_recall(settings, query=query, project=project_a, domain="")
        other_project = _run_recall(settings, query=query, project=unrelated, domain="")

        self.assertTrue(same_project["hits"], msg=str(same_project))
        self.assertTrue(all(hit["knowledge_kind"] == "project-reference" for hit in same_project["hits"]))
        self.assertEqual(other_project["hits"], [], msg=str(other_project))


if __name__ == "__main__":
    unittest.main()
