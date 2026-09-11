from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch

from ei.capture import record_agent_observation
from ei.cli import _recall
from ei.inference.base import ProviderResult
from ei.inference.router import ProviderRouter
from ei.installer import (
    SetupSelection,
    UninstallOptions,
    _settings_for_selection,
    setup,
    uninstall,
    update,
)
from ei.journal import iter_events
from ei.maintainer import _RouterAdapter, drain_queue
from ei.models import CaptureContext, ObservationInput
from ei.project import project_events
from ei.queue import QueueState, enqueue_receipt, list_queue_items, read_queue_item
from ei.reconciliation import reconcile_lifecycle


CUSTOM_PROFILE: dict[str, object] = {
    "schema_version": 1,
    "host_id": "test-compatible-cli",
    "display_name": "Test Compatible CLI",
    "host_family": "gemini-compatible",
    "adapter_id": "gemini-cli",
    "executable_names": ["test-compatible-cli"],
    "hook_config_path": ".config/test-compatible/settings.json",
    "global_context_path": ".config/test-compatible/context.md",
    "skill_roots": [".config/test-compatible/skills"],
}


class RecordingOrganizer:
    locality = "subscription"

    def __init__(self, *, available: bool = True, provider_id: str = "subscription-cli") -> None:
        self.provider_id = provider_id
        self.calls = 0
        self.available = available
        self.reason_code = "PROVIDER_UNAVAILABLE"

    def generate(self, schema_name: str, input_json: Mapping[str, Any], budget: Any) -> ProviderResult:
        del budget
        self.calls += 1
        if not self.available:
            return ProviderResult(
                self.provider_id,
                "deferred",
                error_code=self.reason_code,
                schema_name=schema_name,
            )
        return ProviderResult(
            self.provider_id,
            "success",
            output={
                "decision": "YES",
                "reason_code": "evidence_verified",
                "candidate_title": input_json.get("title", "Reusable rule"),
                "candidate_claim": input_json.get("claim", ""),
                "evidence_refs": list(input_json.get("evidence_refs", ())),
                "benefit": input_json.get("benefit", "reduced_rework"),
                "classification": input_json.get("classification", "private-reusable"),
                "confidence": 0.95,
                "applicability_scope": input_json.get("applicability_scope", "host"),
                "applicable_host_ids": list(input_json.get("applicable_host_ids", ())),
                "applicable_host_families": list(input_json.get("applicable_host_families", ())),
            },
            schema_name=schema_name,
        )


class SingleIntelligenceMultiCliAcceptanceTests(unittest.TestCase):
    def _selection(self, root: Path) -> SetupSelection:
        homes = {
            "codex-cli": root / "homes" / "codex-cli",
            "test-compatible-cli": root / "homes" / "test-compatible-cli",
            "gemini-cli": root / "homes" / "gemini-cli",
        }
        (homes["codex-cli"] / "AGENTS.md").parent.mkdir(parents=True, exist_ok=True)
        (homes["codex-cli"] / "AGENTS.md").write_text("# instructions\n", encoding="utf-8")
        (homes["test-compatible-cli"] / ".config" / "test-compatible").mkdir(parents=True, exist_ok=True)
        (homes["test-compatible-cli"] / ".config" / "test-compatible" / "context.md").write_text("# instructions\n", encoding="utf-8")
        (homes["gemini-cli"] / "GEMINI.md").parent.mkdir(parents=True, exist_ok=True)
        (homes["gemini-cli"] / "GEMINI.md").write_text("# instructions\n", encoding="utf-8")
        profile_path = root / "test-compatible-cli.profile.json"
        profile_path.write_text(json.dumps(CUSTOM_PROFILE), encoding="utf-8")
        return SetupSelection(
            engine_root=Path.cwd(),
            knowledge_root=root / "personal-knowledge",
            runtime_root=root / "runtime",
            work_hosts=("codex-cli", "test-compatible-cli"),
            host_homes=homes,
            host_profiles=(profile_path,),
            organizer_provider="subscription-cli",
            organizer_host="gemini-cli",
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def _capture(
        self,
        settings: Any,
        *,
        host_id: str,
        family: str,
        scope: str,
        phrase: str,
        number: int,
    ) -> tuple[str, object]:
        if scope == "universal":
            applicable_ids: tuple[str, ...] = ()
            applicable_families: tuple[str, ...] = ()
        elif scope == "family":
            applicable_ids = ()
            applicable_families = (family,)
        else:
            applicable_ids = (host_id,)
            applicable_families = ()
        observation = ObservationInput(
            title=f"Reusable {scope} guidance",
            claim=phrase,
            source_kind="agent_direct",
            source_ref=f"source-{scope}-{number}",
            cwd=f"project-{scope}-{number}",
            domain=f"domain-{scope}",
            outcome_status="success",
            benefit="reduced_rework",
            classification="private-reusable",
            applicability=(f"tag-{scope}",),
            source_host_id=host_id,
            source_host_family=family,
            applicability_scope=scope,
            applicable_host_ids=applicable_ids,
            applicable_host_families=applicable_families,
        )
        context = CaptureContext(
            session_id=f"session-{scope}-{number}",
            turn_id=f"turn-{scope}-{number}",
            capture_index=1,
            source_host_id=host_id,
            source_host_family=family,
        )
        captured = record_agent_observation(observation, context, settings)
        self.assertTrue(captured.created, captured)
        events = list(iter_events(settings.paths.event_dir))
        event = next(item for item in events if item.event_id == captured.event_id)
        queued = enqueue_receipt(event, None, settings)
        return captured.event_id or "", queued

    def _recall(self, settings: Any, query: str, host_id: str, *, domain: str = "") -> dict[str, Any]:
        args = argparse.Namespace(
            query=query,
            max_chars=None,
            cwd=None,
            host=host_id,
            domain=domain,
            scope=(),
            version="",
            session_id=f"recall-{host_id}",
            settings=settings,
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(_recall(args), 0)
        return json.loads(output.getvalue())

    @staticmethod
    def _tree_digest(root: Path) -> str:
        digest = hashlib.sha256()
        if not root.exists():
            return digest.hexdigest()
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
        return digest.hexdigest()

    @staticmethod
    def _journal_digest(settings: Any) -> tuple[str, ...]:
        return tuple(
            sorted(
                hashlib.sha256(json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
                for event in iter_events(settings.paths.event_dir)
            )
        )

    def test_two_work_hosts_share_one_intelligence_and_one_organizer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = self._selection(root)
            installed = setup(selection)
            self.assertTrue(installed.ok, installed.to_dict())
            manifest_path = root / "runtime" / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIsInstance(manifest["organizer"], dict)
            self.assertNotIn("organizers", manifest)
            self.assertEqual(manifest["organizer"]["status"], "READY")
            self.assertEqual(manifest["organizer"]["provider_id"], "subscription-cli")
            self.assertEqual(manifest["organizer"]["host_id"], "gemini-cli")
            self.assertEqual(len([manifest["organizer"]]), 1)
            self.assertEqual(set(manifest["work_hosts"]), {"codex-cli", "test-compatible-cli"})

            settings = _settings_for_selection(selection)
            universal_phrase = "UNIVERSALSTONE: use the same verification sequence before every release review to reduce repeated investigation and rework."
            family_phrase = "FAMILYSTONE: when the compatible family reports a configuration mismatch, record the exact boundary before repeating the validation."
            host_phrase = "HOSTSTONE: for this named compatible host, keep the local adapter check beside the result so later recalls do not broaden the rule."
            captured: list[str] = []
            for number in (1, 2):
                event_id, _ = self._capture(
                    settings,
                    host_id="codex-cli",
                    family="codex-compatible",
                    scope="universal",
                    phrase=universal_phrase,
                    number=number,
                )
                captured.append(event_id)
                event_id, _ = self._capture(
                    settings,
                    host_id="test-compatible-cli",
                    family="gemini-compatible",
                    scope="family",
                    phrase=family_phrase,
                    number=number,
                )
                captured.append(event_id)
                event_id, _ = self._capture(
                    settings,
                    host_id="test-compatible-cli",
                    family="gemini-compatible",
                    scope="host",
                    phrase=host_phrase,
                    number=number,
                )
                captured.append(event_id)

            duplicate_observation = ObservationInput(
                title="Reusable family guidance",
                claim=family_phrase,
                source_kind="agent_direct",
                source_ref="source-family-1",
                cwd="project-family-1",
                domain="domain-family",
                outcome_status="success",
                benefit="reduced_rework",
                classification="private-reusable",
                applicability=("tag-family",),
                source_host_id="test-compatible-cli",
                source_host_family="gemini-compatible",
                applicability_scope="family",
                applicable_host_families=("gemini-compatible",),
            )
            replay = record_agent_observation(
                duplicate_observation,
                CaptureContext(
                    session_id="session-family-1",
                    turn_id="turn-family-1",
                    capture_index=1,
                    source_host_id="test-compatible-cli",
                    source_host_family="gemini-compatible",
                ),
                settings,
            )
            self.assertFalse(replay.created)
            self.assertEqual(replay.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 6)
            self.assertEqual(len(list_queue_items(settings)), 6)

            organizer = RecordingOrganizer()
            alternative = RecordingOrganizer(provider_id="ollama")
            router = ProviderRouter(
                [organizer, alternative],
                organizer=settings.organizer,
            )
            drained = drain_queue(
                settings,
                provider=_RouterAdapter(router),
                max_items=20,
                time_budget_ms=600000,
                now=datetime(2026, 9, 10, tzinfo=timezone.utc),
            )
            self.assertEqual(drained.completed, 6, drained.to_dict())
            self.assertGreater(organizer.calls, 0)
            self.assertEqual(alternative.calls, 0)
            self.assertTrue(all(item.state == QueueState.DONE for item in list_queue_items(settings)))

            reconcile_lifecycle(
                list(iter_events(settings.paths.event_dir)),
                settings.paths.event_dir,
                now_utc=datetime(2026, 9, 11, tzinfo=timezone.utc),
            )
            project_events(list(iter_events(settings.paths.event_dir)), settings.paths.knowledge_dir)
            settings = _settings_for_selection(selection)

            self.assertEqual(len(captured), 6)
            universal_hits = self._recall(settings, universal_phrase, "qwen-code", domain="domain-universal")["hits"]
            family_hits = self._recall(settings, family_phrase, "test-compatible-cli", domain="domain-family")["hits"]
            family_hits_other_host = self._recall(settings, family_phrase, "qwen-code", domain="domain-family")["hits"]
            host_hits = self._recall(settings, host_phrase, "test-compatible-cli", domain="domain-host")["hits"]
            host_hits_other_host = self._recall(settings, host_phrase, "codex-cli", domain="domain-host")["hits"]
            self.assertIn(universal_phrase, {item["rule"] for item in universal_hits})
            self.assertIn(family_phrase, {item["rule"] for item in family_hits})
            self.assertEqual(family_hits_other_host, [])
            self.assertIn(host_phrase, {item["rule"] for item in host_hits})
            self.assertNotIn(host_phrase, {item["rule"] for item in host_hits_other_host})

            outage_observation_id, outage_item = self._capture(
                settings,
                host_id="test-compatible-cli",
                family="gemini-compatible",
                scope="host",
                phrase="OUTAGESTONE: keep a new outage candidate in the durable queue and retry it after the organizer becomes available again.",
                number=3,
            )
            del outage_observation_id
            stopped = RecordingOrganizer(available=False)
            deferred = drain_queue(
                settings,
                provider=stopped,
                max_items=1,
                time_budget_ms=600000,
                now=datetime(2026, 9, 10, 0, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(deferred.deferred, 1, deferred.to_dict())
            self.assertEqual(read_queue_item(outage_item.queue_id, settings).state, QueueState.DEFERRED)
            self.assertIn(family_phrase, {item["rule"] for item in self._recall(settings, family_phrase, "test-compatible-cli", domain="domain-family")["hits"]})

            personal_root = root / "personal-knowledge"
            before_identity = self._tree_digest(personal_root)
            before_journal = self._journal_digest(settings)
            switched = update(replace(selection, organizer_host="test-compatible-cli"))
            self.assertTrue(switched.ok, switched.to_dict())
            switched_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(switched_manifest["organizer"]["host_id"], "test-compatible-cli")
            self.assertEqual(before_identity, self._tree_digest(personal_root))
            self.assertEqual(before_journal, self._journal_digest(_settings_for_selection(selection)))

            removed_selection = replace(
                selection,
                hosts=("codex-cli",),
                work_hosts=("codex-cli",),
                organizer_host="codex-cli",
                host_homes={"codex-cli": selection.host_homes["codex-cli"]},
                host_profiles=(),
            )
            removed = update(removed_selection)
            self.assertTrue(removed.ok, removed.to_dict())
            self.assertFalse((root / "runtime" / "host-profiles" / "test-compatible-cli.json").exists())
            after_remove_settings = _settings_for_selection(removed_selection)
            self.assertEqual(before_journal, self._journal_digest(after_remove_settings))
            self.assertNotIn(
                family_phrase,
                {item["rule"] for item in self._recall(after_remove_settings, family_phrase, "qwen-code", domain="domain-family")["hits"]},
            )

            reregistered = update(selection)
            self.assertTrue(reregistered.ok, reregistered.to_dict())
            restored_settings = _settings_for_selection(selection)
            self.assertIn(family_phrase, {item["rule"] for item in self._recall(restored_settings, family_phrase, "test-compatible-cli", domain="domain-family")["hits"]})
            self.assertNotIn(host_phrase, {item["rule"] for item in self._recall(restored_settings, host_phrase, "codex-cli", domain="domain-host")["hits"]})
            self.assertEqual(before_identity, self._tree_digest(personal_root))
            self.assertEqual(before_journal, self._journal_digest(restored_settings))

            with patch("ei.team_projection.refresh_team_projection", side_effect=AssertionError("team store read")):
                disabled_result = self._recall(restored_settings, family_phrase, "test-compatible-cli", domain="domain-family")
            self.assertEqual(disabled_result["knowledge_stores"]["team"]["status"], "DISABLED")

            uninstalled = uninstall(manifest_path, UninstallOptions(remove_runtime=False))
            self.assertTrue(uninstalled["ok"], uninstalled)
            self.assertEqual(before_identity, self._tree_digest(personal_root))
            self.assertEqual(before_journal, self._journal_digest(restored_settings))


if __name__ == "__main__":
    unittest.main()
