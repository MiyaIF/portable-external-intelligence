from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..config import HostSpec
from ..host_profiles import canonical_host_id as _canonical_host_id
from ..ids import stable_hash
from .base import BaseHookAdapter, HookAdapter, HookResult, NormalizedHookEvent
from .claude import ClaudeAdapter
from .codex import CodexAdapter, CodexAppAdapter
from .gemini import GeminiAdapter
from .qwen import QwenAdapter


_ADAPTERS: dict[str, HookAdapter] = {
    "codex-cli": CodexAdapter(),
    "codex-app": CodexAppAdapter(),
    "claude-code": ClaudeAdapter(),
    "gemini-cli": GeminiAdapter(),
    "qwen-code": QwenAdapter(),
}
_PROFILED_ADAPTERS: dict[str, HookAdapter] = {}
_HOST_FAMILIES = {
    "codex-cli": "codex-compatible",
    "codex-app": "codex-compatible",
    "claude-code": "claude-compatible",
    "gemini-cli": "gemini-compatible",
    "qwen-code": "qwen-compatible",
}


def canonical_host_id(host_id: str) -> str:
    return _canonical_host_id(host_id)


def _fallback_spec(host_id: str) -> HostSpec:
    adapter = _ADAPTERS[host_id]
    if host_id == "gemini-cli":
        event_mapping = {"SessionStart": "session.start", "BeforeAgent": "prompt.before", "AfterAgent": "turn.stop", "SessionEnd": "session.end"}
        activation = "CONSENT_REQUIRED"
        context_name = "GEMINI.md"
    else:
        event_mapping = {event: normalized for event, normalized in (("SessionStart", "session.start"), ("UserPromptSubmit", "prompt.before"), ("Stop", "turn.stop"), ("SessionEnd", "session.end"))}
        activation = "AUTO_ALLOWED"
        context_name = "AGENTS.md" if host_id in {"codex-cli", "codex-app"} else {"claude-code": "CLAUDE.md", "qwen-code": "QWEN.md"}[host_id]
    return HostSpec(
        host_id=host_id,
        display_name=host_id,
        executable_names=(host_id,),
        hook_config_path=Path("${HOST_HOME}") / "settings.json",
        global_context_path=Path("${HOST_HOME}") / context_name,
        skill_roots=(Path("${HOST_HOME}") / "skills",),
        event_mapping=event_mapping,
        hook_feature_key="features.hooks" if host_id in {"codex-cli", "codex-app"} else None,
        hook_feature_default=False,
        skill_activation_mode=activation,
        capture_primary_path="HOOK_DIRECT",
        capture_order=("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
        minimum_supported_version="0.1.0" if host_id in {"codex-cli", "codex-app"} else None,
        host_family=_HOST_FAMILIES.get(host_id, ""),
        adapter_id=host_id,
    )


class ProfiledHookAdapter(BaseHookAdapter):
    """Reuse a public adapter while retaining a custom host identity."""

    def __init__(self, host_id: str, host_family: str, delegate: HookAdapter) -> None:
        self.host_id = host_id
        self.host_family = host_family
        self.delegate = delegate
        self.adapter_id = getattr(delegate, "host_id", getattr(delegate, "adapter_id", ""))
        self.event_names = tuple(delegate.supported_events())
        self.command_field = getattr(delegate, "command_field", "command")
        self.windows_command_field = getattr(delegate, "windows_command_field", None)

    def normalize(self, payload: Mapping[str, Any], spec: HostSpec | None = None) -> NormalizedHookEvent:
        selected_spec = spec or _fallback_spec(self.adapter_id)
        normalized = self.delegate.normalize(payload, selected_spec)
        instance = normalized.host_instance_id
        if instance == getattr(self.delegate, "host_id", ""):
            instance = self.host_id
        basis = {
            "host_id": self.host_id,
            "host_instance_id": instance,
            "host_event_name": normalized.host_event_name,
            "normalized_event_name": normalized.normalized_event_name,
            "session_id_hash": normalized.session_id_hash,
            "turn_id_hash": normalized.turn_id_hash,
            "cwd_hash": normalized.cwd_hash,
            "payload_hash": normalized.payload_hash,
        }
        idempotency_key = "sha256:" + stable_hash(basis)
        event_id = "evt_" + normalized.received_at.strftime("%Y%m%dT%H%M%S%fZ") + "_" + stable_hash({"idempotency_key": idempotency_key, "received_at": payload.get("received_at", "")})[:12]
        return replace(
            normalized,
            event_id=event_id,
            idempotency_key=idempotency_key,
            host_id=self.host_id,
            host_instance_id=instance,
            source_host_id=self.host_id,
            source_host_family=self.host_family,
        )

    def encode(self, result: HookResult) -> Mapping[str, Any]:
        return self.delegate.encode(result)


def get_adapter(host_id: str, settings: Any = None) -> HookAdapter:
    canonical = canonical_host_id(host_id)
    try:
        return _ADAPTERS[canonical]
    except KeyError as exc:
        cached = _PROFILED_ADAPTERS.get(canonical)
        if cached is not None and settings is None:
            return cached
        hosts = getattr(settings, "hosts", {}) if settings is not None else {}
        spec = hosts.get(canonical) if isinstance(hosts, Mapping) else None
        adapter_id = getattr(spec, "adapter_id", None) if spec is not None else None
        family = getattr(spec, "host_family", None) if spec is not None else None
        if isinstance(adapter_id, str) and adapter_id in _ADAPTERS and isinstance(family, str) and family:
            adapter = ProfiledHookAdapter(canonical, family, _ADAPTERS[adapter_id])
            _PROFILED_ADAPTERS[canonical] = adapter
            return adapter
        raise ValueError("HOST_UNSUPPORTED") from exc


def _spec_for(host_id: str, settings: Any) -> HostSpec:
    canonical = canonical_host_id(host_id)
    hosts = getattr(settings, "hosts", {}) if settings is not None else {}
    if isinstance(hosts, Mapping) and canonical in hosts:
        return hosts[canonical]
    return _fallback_spec(canonical)


def normalize_hook_event(host_id: str, payload: Mapping[str, Any], settings: Any) -> NormalizedHookEvent:
    canonical = canonical_host_id(host_id)
    adapter = get_adapter(canonical, settings)
    return adapter.normalize(payload, _spec_for(canonical, settings))


def encode_hook_result(host_id: str, result: HookResult, settings: Any = None) -> Mapping[str, Any]:
    return get_adapter(host_id, settings).encode(result)


def supported_events(host_id: str, settings: Any = None) -> Sequence[str]:
    return get_adapter(host_id, settings).supported_events()


def hook_config_fragment(host_id: str, executable: Path, repo_root: Path, knowledge_root: Path | None = None, runtime_root: Path | None = None, settings: Any = None) -> Mapping[str, Any]:
    return get_adapter(host_id, settings).config_fragment(Path(executable), Path(repo_root), Path(knowledge_root) if knowledge_root is not None else None, Path(runtime_root) if runtime_root is not None else None)


__all__ = [
    "canonical_host_id",
    "encode_hook_result",
    "get_adapter",
    "hook_config_fragment",
    "normalize_hook_event",
    "ProfiledHookAdapter",
    "supported_events",
]
