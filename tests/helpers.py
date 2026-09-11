from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.models import ClusterState, Event, ObservationState, RetrievalHit


def make_event_v2(**overrides) -> Event:
    value = Event.create_v2(
        event_type="observation.recorded",
        actor="host:test",
        machine_id="machine-default",
        payload={"claim": "検証済みの再利用可能な判断ルールを記録する"},
        occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
    )
    return replace(value, **overrides)


def make_observation_state(**overrides) -> ObservationState:
    value = ObservationState(
        observation_id="obs_default",
        title="default",
        claim="検証済みの再利用可能な判断ルールを記録する",
        domain="general",
        cwd_fingerprint="cwd:default",
        provenance_key="source:default",
        outcome_status="success",
        benefit="reduced_rework",
        classification="private-reusable",
    )
    return replace(value, **overrides)


def make_cluster_state(**overrides) -> ClusterState:
    value = ClusterState(
        cluster_id="cluster_default",
        pattern_id=None,
        status="raw",
        rule="検証済みの再利用可能な判断ルールを記録する",
        provenances=frozenset(),
        scopes=frozenset(),
        benefit_count=0,
        contradiction_provenances=frozenset(),
        classification="private-reusable",
        last_used_at=None,
    )
    return replace(value, **overrides)


def make_retrieval_hit(**overrides) -> RetrievalHit:
    value = RetrievalHit(
        pattern_id="pat_default",
        cluster_id="cluster_default",
        score=0.5,
        rule="検証済みの再利用可能な判断ルールを記録する",
        applicability=("general",),
        evidence_count=1,
        updated_at="2026-08-25T00:00:00Z",
    )
    return replace(value, **overrides)


def make_hook_settings(root: Path, include_formula_pattern: bool = False) -> Settings:
    root = Path(root).resolve()
    codex_home = root / "codex"
    runtime = codex_home / "external-intelligence"
    paths = RuntimePaths(
        repo_root=root,
        codex_home=codex_home,
        runtime_dir=runtime,
        event_dir=root / "events",
        knowledge_dir=root / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=codex_home / "config.toml",
        hooks_path=codex_home / "hooks.json",
        agents_path=codex_home / "AGENTS.md",
    )
    settings = Settings(paths=paths, retrieval_max_chars=5000, retrieval_max_results=5)
    if include_formula_pattern:
        settings.paths.knowledge_dir.mkdir(parents=True, exist_ok=True)
        (settings.paths.knowledge_dir / "index.md").write_text(
            "formula pattern\n書込後に対象範囲を再読込して検証する\n",
            encoding="utf-8",
        )
    return settings
