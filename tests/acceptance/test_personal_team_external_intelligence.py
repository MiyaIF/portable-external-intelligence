from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from ei.models import Event
from ei.project import project_events
from ei.team_store import append_team_event


REPO_ROOT = Path(__file__).resolve().parents[2]
_JOURNEYS: dict[str, dict[str, object]] = {}
_WORKSPACES: list[Path] = []


def _ignore_clone(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lowered = name.casefold()
        if name == ".git" or name == "artifacts" or name == "build" or name == "dist":
            ignored.add(name)
        elif name == ".superpowers" or name.startswith(".pycache") or lowered == "__pycache__":
            ignored.add(name)
        elif lowered in {".pytest_cache", ".mypy_cache"}:
            ignored.add(name)
    return ignored


def _run_json(command: list[str], *, cwd: Path, env: Mapping[str, str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(env),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"CLI failed ({completed.returncode}):\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"CLI did not return JSON:\nstdout={completed.stdout}\nstderr={completed.stderr}"
        ) from exc
    if not isinstance(value, dict):
        raise AssertionError(f"CLI JSON must be an object: {value!r}")
    return value


def _journey_environment(clone: Path) -> dict[str, str]:
    environment = dict(os.environ)
    source_path = str(clone / "src")
    previous = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = source_path if not previous else source_path + os.pathsep + previous
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return environment


def _initialize_clean_clone(clone: Path) -> None:
    commands = [
        ["git", "init", "--quiet", str(clone)],
        ["git", "-C", str(clone), "config", "user.name", "Acceptance Fixture"],
        ["git", "-C", str(clone), "config", "user.email", "acceptance@example.invalid"],
        ["git", "-C", str(clone), "add", "--all"],
        ["git", "-C", str(clone), "commit", "--quiet", "-m", "clean clone fixture"],
    ]
    for command in commands:
        completed = subprocess.run(command, cwd=clone, check=False, capture_output=True, text=True, encoding="utf-8")
        if completed.returncode != 0:
            raise AssertionError(f"clean clone git setup failed: {completed.stdout}\n{completed.stderr}")


def run_clean_clone_setup(*, team: bool) -> dict[str, object]:
    """Run the public setup CLI in an isolated, generated clone workspace."""

    workspace = Path(tempfile.mkdtemp(prefix="ei-public-journey-"))
    _WORKSPACES.append(workspace)
    clone = workspace / "clone"
    shutil.copytree(REPO_ROOT, clone, ignore=_ignore_clone)
    _initialize_clean_clone(clone)
    personal_root = workspace / "personal knowledge"
    runtime_root = workspace / "machine runtime"
    host_home = workspace / "codex home"
    team_root = workspace / "shared team" if team else None
    team_member_id = "member-" + uuid.uuid4().hex[:12] if team else None
    command = [
        sys.executable,
        "-B",
        "-m",
        "ei.cli",
        "setup",
        "--engine-root",
        str(clone),
        "--personal-knowledge-root",
        str(personal_root),
        "--runtime-root",
        str(runtime_root),
        "--hosts",
        "codex-cli",
        "--organizer-provider",
        "subscription-cli",
        "--organizer-host",
        "codex-cli",
        "--host-home",
        f"codex-cli={host_home}",
        "--knowledge-mode",
        "local",
        "--skip-venv",
        "--non-interactive",
        "--accept-plan",
        "--no-sync",
        "--json",
    ]
    if team_root is not None:
        command.extend(
            [
                "--team-knowledge-root",
                str(team_root),
                "--team-member-id",
                str(team_member_id),
            ]
        )
    result = _run_json(command, cwd=clone, env=_journey_environment(clone))
    manifest_path = Path(str(result.get("manifest_path", ""))).resolve()
    writer_id: str | None = None
    store_id: str | None = None
    stores = result.get("knowledge_stores")
    if isinstance(stores, Mapping) and isinstance(stores.get("team"), Mapping):
        candidate_store = stores["team"].get("store_id")
        if isinstance(candidate_store, str) and candidate_store:
            store_id = candidate_store
        candidate_writer = stores["team"].get("writer_id")
        if isinstance(candidate_writer, str) and candidate_writer:
            writer_id = candidate_writer
    if writer_id is None or store_id is None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            team_descriptor = manifest.get("knowledge_stores", {}).get("team", {})
            if isinstance(team_descriptor, Mapping):
                if isinstance(team_descriptor.get("store_id"), str):
                    store_id = team_descriptor["store_id"]
                if isinstance(team_descriptor.get("writer_id"), str):
                    writer_id = team_descriptor["writer_id"]
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            writer_id = writer_id or None
            store_id = store_id or None
    _JOURNEYS[str(manifest_path)] = {
        "workspace": workspace,
        "clone": clone,
        "command": tuple(command),
        "environment": _journey_environment(clone),
        "personal_root": personal_root,
        "runtime_root": runtime_root,
        "host_home": host_home,
        "team_root": team_root,
        "team_member_id": team_member_id,
        "writer_id": writer_id,
        "store_id": store_id,
    }
    return result


def _personal_event() -> Event:
    return Event.create(
        "pattern.promoted",
        "2026-09-05T00:00:00Z",
        "acceptance",
        "acceptance-machine",
        {
            "pattern_id": "pat_acceptance_personal",
            "cluster_id": "cluster_acceptance_personal",
            "rule": "前回の検証手順を再利用し、変更点だけ追加確認する",
            "provenances": ["source:personal-acceptance"],
            "scopes": ["general"],
            "applicability": ["general"],
            "benefit_count": 1,
            "classification": "private-reusable",
        },
        event_id="evt_acceptance_personal",
    )


def _team_event() -> Event:
    idempotency = "sha256:" + "a" * 64
    return Event.create_v2(
        "team.knowledge.recorded",
        actor="team-member-hash",
        machine_id="team-machine-hash",
        occurred_at=datetime(2026, 9, 5, tzinfo=timezone.utc),
        idempotency_key=idempotency,
        payload={
            "knowledge_scope": "team",
            "origin_event_hash": "sha256:" + "b" * 64,
            "idempotency_key": idempotency,
            "title": "検証手順のチームルール",
            "claim": "チームで共有した検証手順を再利用し、変更点だけ追加確認する",
            "scope": ["general"],
            "preconditions": ["同じ問題構造が再発している"],
            "failure_modes": ["検証を省略して再作業になる"],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        },
    )


def _metadata_for(setup_result: Mapping[str, object]) -> dict[str, object]:
    manifest = Path(str(setup_result["manifest_path"])).resolve()
    try:
        return _JOURNEYS[str(manifest)]
    except KeyError as exc:
        raise AssertionError(f"Unknown setup journey: {manifest}") from exc


def run_two_store_recall(setup_result: Mapping[str, object]) -> dict[str, object]:
    """Seed one event in each store, then run the public recall CLI."""

    metadata = _metadata_for(setup_result)
    team_root = metadata.get("team_root")
    if not isinstance(team_root, Path):
        raise AssertionError("two-store recall requires a team-enabled setup")
    personal_root = metadata["personal_root"]
    runtime_root = metadata["runtime_root"]
    clone = metadata["clone"]
    if not isinstance(personal_root, Path) or not isinstance(runtime_root, Path) or not isinstance(clone, Path):
        raise AssertionError("journey metadata is invalid")

    project_events([_personal_event()], personal_root / "knowledge")
    team_member_id = metadata.get("team_member_id")
    if not isinstance(team_member_id, str):
        raise AssertionError("team member metadata is invalid")
    writer_id = metadata.get("writer_id")
    if not isinstance(writer_id, str):
        writer_id = "writer_" + uuid.uuid4().hex
        metadata["writer_id"] = writer_id
    append_team_event(team_root, team_member_id, writer_id, _team_event())
    command = [
        sys.executable,
        "-B",
        "-m",
        "ei.cli",
        "recall",
        "--engine-root",
        str(clone),
        "--runtime-root",
        str(runtime_root),
        "--query",
        "検証手順",
        "--max-chars",
        "5000",
        "--json",
    ]
    return _run_json(command, cwd=clone, env=_journey_environment(clone))


def _rerun_setup(setup_result: Mapping[str, object]) -> dict[str, object]:
    metadata = _metadata_for(setup_result)
    command = metadata.get("command")
    clone = metadata.get("clone")
    environment = metadata.get("environment")
    if not isinstance(command, tuple) or not isinstance(clone, Path) or not isinstance(environment, Mapping):
        raise AssertionError("journey metadata is invalid")
    return _run_json(list(command), cwd=clone, env=environment)


class PersonalTeamExternalIntelligenceAcceptanceTests(unittest.TestCase):
    def test_public_personal_only_and_team_enabled_journeys(self) -> None:
        personal = run_clean_clone_setup(team=False)
        self.assertEqual(personal["status"], "SETUP_COMPLETE")
        self.assertEqual(personal["knowledge_stores"]["team"]["status"], "DISABLED")
        self.assertEqual(personal["team_activity"], {"filesystem": 0, "provider": 0, "prompt_chars": 0})

        team = run_clean_clone_setup(team=True)
        self.assertEqual(team["status"], "SETUP_COMPLETE")
        recalled = run_two_store_recall(team)
        self.assertLessEqual(len(recalled["hits"]), 5)
        self.assertLessEqual(recalled["context_chars"], 5000)
        self.assertEqual({hit["knowledge_scope"] for hit in recalled["hits"]}, {"personal", "team"})

    def test_second_identical_setup_is_already_current(self) -> None:
        result = run_clean_clone_setup(team=True)
        second = _rerun_setup(result)
        self.assertEqual(second["status"], "SETUP_COMPLETE")
        self.assertEqual(second["reconciliation"]["status"], "ALREADY_CURRENT")

    def test_managed_file_conflict_is_not_overwritten(self) -> None:
        result = run_clean_clone_setup(team=False)
        metadata = _metadata_for(result)
        host_home = metadata["host_home"]
        self.assertIsInstance(host_home, Path)
        target = host_home / "AGENTS.md"
        before = target.read_text(encoding="utf-8")
        target.write_text(before + "\n# user-owned change\n", encoding="utf-8")
        with self.assertRaises(AssertionError) as raised:
            _rerun_setup(result)
        self.assertIn("MANAGED_TARGET_CONFLICT", str(raised.exception))
        self.assertEqual(target.read_text(encoding="utf-8"), before + "\n# user-owned change\n")

    def test_partial_and_conflict_shared_files_do_not_hide_valid_events(self) -> None:
        result = run_clean_clone_setup(team=True)
        recalled = run_two_store_recall(result)
        metadata = _metadata_for(result)
        team_root = metadata["team_root"]
        self.assertIsInstance(team_root, Path)
        team_member_id = metadata["team_member_id"]
        writer_id = metadata["writer_id"]
        self.assertIsInstance(team_member_id, str)
        self.assertIsInstance(writer_id, str)
        event_dir = team_root / "members" / team_member_id / "writers" / writer_id / "events" / "2026" / "09" / "05"
        (event_dir / ".partial-invalid").write_text("partial\n", encoding="utf-8")
        (event_dir / "event-conflict.json").write_text("conflict\n", encoding="utf-8")
        recalled_again = run_two_store_recall(result)
        self.assertTrue(any(hit["knowledge_scope"] == "team" for hit in recalled["hits"]))
        self.assertTrue(any(hit["knowledge_scope"] == "team" for hit in recalled_again["hits"]))
        issues = set(recalled_again["team_projection"].get("reason_codes", []))
        self.assertTrue({"TEAM_PARTIAL_FILE", "TEAM_CONFLICT_COPY"} & issues)

    def test_generated_journey_values_are_not_in_public_export(self) -> None:
        result = run_clean_clone_setup(team=True)
        metadata = _metadata_for(result)
        generated = {
            str(value)
            for value in (
                metadata["personal_root"],
                metadata["runtime_root"],
                metadata["team_root"],
                metadata["store_id"],
                metadata["team_member_id"],
                metadata["writer_id"],
            )
            if value is not None and str(value)
        }
        destination = metadata["workspace"] / "public export"
        command = [
            sys.executable,
            "-B",
            "scripts/create-public-export.py",
            "--source",
            str(metadata["clone"]),
            "--destination",
            str(destination),
            "--policy",
            str(metadata["clone"] / "release" / "publication-policy.json"),
            "--allowlist",
            str(metadata["clone"] / "config" / "public-export-allowlist.json"),
            "--skip-validation",
            "--no-repeat-check",
            "--json",
        ]
        completed = subprocess.run(
            command,
            cwd=metadata["clone"],
            env=metadata["environment"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        public_suffixes = {".md", ".py", ".toml", ".json", ".yml", ".yaml", ".sh", ".ps1"}
        for path in destination.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in public_suffixes:
                continue
            if any(part in {".git", "artifacts", "build", "__pycache__"} for part in path.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for value in generated:
                self.assertNotIn(value, text, str(path))


def tearDownModule() -> None:
    for workspace in reversed(_WORKSPACES):
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
