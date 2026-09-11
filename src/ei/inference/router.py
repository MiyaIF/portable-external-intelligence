from __future__ import annotations

import json
import os
import re
import shutil
from decimal import Decimal
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence

from .base import InferenceBudget, InferenceProvider, ProviderResult, unavailable_result
from .budget import BudgetLedger, BudgetPolicy
from .cli_subscription import SubscriptionCLIProvider
from ..host_profiles import canonical_host_id
from ..setup_contract import OrganizerSelection
from .local_openai import LocalOpenAICompatibleProvider
from .ollama import OllamaProvider


class ProviderSelectionError(RuntimeError):
    """Raised when no configured provider is eligible for the requested operation."""

    def __init__(self, reason_code: str, provider_ids: Sequence[str] = ()) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.provider_ids = tuple(provider_ids)


class ConfiguredUnavailableProvider:
    locality = "cloud"

    def __init__(self, provider_id: str, *, enabled: bool = False) -> None:
        self.provider_id = provider_id
        self.enabled = enabled

    def available(self) -> bool:
        return self.enabled

    def generate(self, schema_name: str, input_json: Mapping[str, Any], budget: InferenceBudget | Mapping[str, Any] | None) -> ProviderResult:
        del input_json, budget
        return unavailable_result(self.provider_id, "PROVIDER_DISABLED", schema_name=schema_name)


def _read_config(settings: Any = None, provider_config: Mapping[str, Any] | str | Path | None = None) -> dict[str, Any]:
    source: Any = provider_config
    if source is None and settings is not None:
        source = Path(settings.paths.engine_root) / "config" / "inference-providers.json"
    if source is None:
        return {}
    if isinstance(source, Mapping):
        return dict(source)
    try:
        value = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("INFERENCE_PROVIDER_CONFIG_READ_FAILED") from exc
    if not isinstance(value, dict):
        raise ValueError("INFERENCE_PROVIDER_CONFIG_INVALID")
    return value


def _provider_entry(config: Mapping[str, Any], provider_id: str) -> Mapping[str, Any]:
    entries = config.get("providers", {})
    if isinstance(entries, Mapping) and isinstance(entries.get(provider_id), Mapping):
        return entries[provider_id]
    return {}


_HOST_TRANSPORTS = {
    "codex-cli": "codex-cli",
    "claude-code": "claude-code",
    "gemini-cli": "gemini-cli",
    "qwen-code": "qwen-code",
}


def _host_transport(host_id: str, settings: Any = None) -> str | None:
    try:
        canonical = canonical_host_id(host_id)
    except (TypeError, ValueError):
        return None
    direct = _HOST_TRANSPORTS.get(canonical)
    if direct is not None:
        return direct
    hosts = getattr(settings, "hosts", {}) if settings is not None else {}
    spec = hosts.get(canonical) if isinstance(hosts, Mapping) else None
    adapter_id = getattr(spec, "adapter_id", None) if spec is not None else None
    return _HOST_TRANSPORTS.get(adapter_id) if isinstance(adapter_id, str) else None
_NPM_SHIM_SCRIPT = re.compile(
    r'["\']%dp0%[\\/](?P<script>node_modules[\\/][^"\'\r\n]+?\.(?:cjs|mjs|js))["\']',
    re.IGNORECASE,
)


def _npm_shim_command(shim_path: Path) -> tuple[str, ...] | None:
    try:
        shim = shim_path.expanduser().resolve()
        if not shim.is_file() or shim.stat().st_size > 128 * 1024:
            return None
        source = shim.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    match = _NPM_SHIM_SCRIPT.search(source)
    if match is None:
        return None
    relative = PureWindowsPath(match.group("script"))
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    script = shim.parent.joinpath(*relative.parts).resolve()
    try:
        if not script.is_relative_to(shim.parent) or not script.is_file():
            return None
    except (OSError, ValueError):
        return None
    bundled_node = (shim.parent / "node.exe").resolve()
    node_value = str(bundled_node) if bundled_node.is_file() else shutil.which("node.exe") or shutil.which("node")
    if not node_value:
        return None
    node = Path(node_value).expanduser().resolve()
    if not node.is_file() or node.suffix.casefold() not in {".exe", ".com"}:
        return None
    return str(node), str(script)


def _resolve_host_command(executable_name: str, *, platform: str | None = None) -> tuple[str, ...] | None:
    if not isinstance(executable_name, str) or not executable_name or "\x00" in executable_name:
        return None
    selected_platform = (platform or os.name).casefold()
    if selected_platform not in {"nt", "windows", "win32"}:
        resolved = shutil.which(executable_name)
        return (str(Path(resolved).expanduser().resolve()),) if resolved else None
    suffix = Path(executable_name).suffix.casefold()
    candidates = (executable_name, f"{executable_name}.exe") if not suffix else (executable_name,)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if not resolved:
            continue
        path = Path(resolved).expanduser().resolve()
        if not path.is_file():
            continue
        resolved_suffix = path.suffix.casefold()
        if resolved_suffix in {".exe", ".com"}:
            return (str(path),)
        if resolved_suffix in {".cmd", ".bat"}:
            command = _npm_shim_command(path)
            if command is not None:
                return command
    return None


def _selected_host_ids(settings: Any) -> tuple[str, ...]:
    if settings is None:
        return ()
    try:
        manifest_path = Path(settings.paths.install_manifest_path)
        if not manifest_path.is_file() or manifest_path.stat().st_size > 2 * 1024 * 1024:
            return ()
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (AttributeError, OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return ()
    hosts = value.get("hosts") if isinstance(value, Mapping) else None
    if not isinstance(hosts, Mapping):
        return ()
    configured_hosts = getattr(settings, "hosts", {})
    if not isinstance(configured_hosts, Mapping):
        return ()
    return tuple(host_id for host_id in hosts if host_id in configured_hosts and _host_transport(str(host_id), settings) is not None)


def _auto_subscription_entry(settings: Any, entry: Mapping[str, Any], organizer_host_id: str | None = None) -> dict[str, Any]:
    configured = dict(entry)
    if not configured.get("auto_from_selected_host"):
        return configured
    # A subscription organizer is bound to its explicitly selected host.  Do
    # not infer a command from work-host order: that silently changes the
    # organizer when another host is added or reordered.
    if organizer_host_id is None and not hasattr(settings, "organizer"):
        # Compatibility for the direct helper contract used by older callers.
        # ProviderRouter itself always passes the manifest organizer host.
        host_ids = _selected_host_ids(settings)
    else:
        host_ids = (organizer_host_id,) if organizer_host_id else ()
    for host_id in host_ids:
        if host_id not in getattr(settings, "hosts", {}):
            continue
        host = settings.hosts[host_id]
        executable_names = getattr(host, "executable_names", ())
        if isinstance(executable_names, str):
            executable_names = (executable_names,)
        for executable_name in executable_names:
            if not isinstance(executable_name, str) or not executable_name:
                continue
            command = _resolve_host_command(executable_name)
            if command:
                configured.update(
                    {
                        "enabled": True,
                        "argv": list(command),
                        "transport": _host_transport(host_id, settings),
                    }
                )
                return configured
    return configured


class ProviderRouter:
    def __init__(
        self,
        providers: Iterable[InferenceProvider] | None = None,
        *,
        settings: Any = None,
        provider_config: Mapping[str, Any] | str | Path | None = None,
        budget_ledger: BudgetLedger | None = None,
        organizer: OrganizerSelection | None = None,
    ) -> None:
        self.settings = settings
        selected_organizer = organizer
        if selected_organizer is None and settings is not None:
            selected_organizer = getattr(settings, "organizer", None)
        if selected_organizer is None:
            selected_organizer = OrganizerSelection(
                "SELECTION_REQUIRED", None, None, "ORGANIZER_SELECTION_REQUIRED"
            )
        if not isinstance(selected_organizer, OrganizerSelection):
            raise ValueError("ORGANIZER_INVALID")
        self.organizer = selected_organizer
        # A setup-required organizer is authoritative.  Do not inspect or
        # construct provider configuration until setup has selected one.
        self.config = {} if self.organizer.status == "SELECTION_REQUIRED" else _read_config(settings, provider_config)
        configured_order = self.config.get("provider_order", self.config.get("order", ()))
        if not isinstance(configured_order, (list, tuple)):
            raise ValueError("PROVIDER_ORDER_INVALID")
        selected_order = getattr(settings, "provider_order", ()) if settings is not None else ()
        if selected_order and not isinstance(selected_order, (list, tuple)):
            raise ValueError("PROVIDER_ORDER_INVALID")
        order_source = selected_order or configured_order
        self.provider_order = tuple(str(item) for item in order_source if isinstance(item, str) and item)
        if providers is not None:
            self.providers = tuple(providers)
            provider_ids = tuple(getattr(item, "provider_id", "") for item in self.providers)
            if any(not item for item in provider_ids) or len(set(provider_ids)) != len(provider_ids):
                raise ValueError("PROVIDER_ID_INVALID")
            if not self.provider_order:
                self.provider_order = provider_ids
        else:
            self.providers = self._build_configured_providers()
        self._by_id = {provider.provider_id: provider for provider in self.providers}
        self.budget_ledger = budget_ledger

    def _build_configured_providers(self) -> tuple[InferenceProvider, ...]:
        if self.settings is not None and hasattr(self.settings, "organizer"):
            # The manifest organizer is the only production provider route.
            # A selection-required manifest intentionally constructs no
            # provider; ``selected`` will expose the stable setup error.
            order = (
                (self.organizer.provider_id,)
                if self.organizer.status == "READY" and self.organizer.provider_id
                else ()
            )
        else:
            # Keep the direct, pre-manifest constructor usable for older test
            # and compatibility callers; it cannot affect production routing
            # because Settings always carries an organizer selection.
            order = self.provider_order or ("local-openai-compatible", "ollama", "subscription-cli", "cloud-api")
        result: list[InferenceProvider] = []
        for provider_id in order:
            entry = _provider_entry(self.config, provider_id)
            if provider_id == "local-openai-compatible":
                result.append(LocalOpenAICompatibleProvider.from_config(entry))
            elif provider_id == "ollama":
                result.append(OllamaProvider.from_config(entry))
            elif provider_id == "subscription-cli":
                state_path = None
                schema_root = None
                working_directory = None
                if self.settings is not None:
                    state_path = Path(self.settings.paths.runtime_dir) / "provider-state.json"
                    schema_root = Path(self.settings.paths.engine_root) / "schemas"
                    working_directory = Path(self.settings.paths.runtime_dir)
                    organizer_host = (
                        self.organizer.host_id
                        if self.organizer.status == "READY"
                        and self.organizer.provider_id == "subscription-cli"
                        else ""
                    )
                    entry = _auto_subscription_entry(self.settings, entry, organizer_host)
                result.append(
                    SubscriptionCLIProvider.from_config(
                        entry,
                        state_path=state_path,
                        schema_root=schema_root,
                        working_directory=working_directory,
                    )
                )
            elif provider_id == "cloud-api":
                result.append(ConfiguredUnavailableProvider(provider_id, enabled=bool(entry.get("enabled", False))))
        return tuple(result)

    def _ordered_ids(self, policy: Mapping[str, Any]) -> tuple[str, ...]:
        requested = policy.get("provider_order") if isinstance(policy, Mapping) else None
        if requested is None:
            requested = self.provider_order
        if not isinstance(requested, (list, tuple)):
            requested = self.provider_order
        ids = [str(item) for item in requested if isinstance(item, str) and item in self._by_id]
        ids.extend(provider.provider_id for provider in self.providers if provider.provider_id not in ids)
        return tuple(ids)

    @staticmethod
    def _is_available(provider: InferenceProvider) -> bool:
        value = getattr(provider, "available", False)
        return bool(value() if callable(value) else value)

    def eligible_providers(self, policy: Mapping[str, Any] | None = None) -> tuple[InferenceProvider, ...]:
        selected_policy = policy if isinstance(policy, Mapping) else {}
        allowed = selected_policy.get("allowed_providers")
        allowed_set = frozenset(allowed) if isinstance(allowed, (list, tuple, set, frozenset)) else None
        disabled = selected_policy.get("disabled_providers")
        disabled_set = frozenset(disabled) if isinstance(disabled, (list, tuple, set, frozenset)) else frozenset()
        cloud_cap_value = selected_policy.get("cloud_spend_cap", self.config.get("cloud_spend_cap", 0))
        try:
            cloud_cap = Decimal(str(cloud_cap_value))
        except Exception as exc:
            del exc
            raise ValueError("CLOUD_SPEND_CAP_INVALID")
        # Eligibility is a diagnostic view of the configured organizer, not a
        # priority list.  A disabled/unavailable organizer yields no eligible
        # provider; an alternate must never appear as an implicit fallback.
        if self.organizer.status != "READY" or not self.organizer.provider_id:
            return ()
        provider = self._by_id.get(self.organizer.provider_id)
        if provider is None:
            return ()
        provider_id = provider.provider_id
        if allowed_set is not None and provider_id not in allowed_set:
            return ()
        if provider_id in disabled_set or not self._is_available(provider):
            return ()
        if getattr(provider, "locality", "") == "cloud" and cloud_cap <= 0:
            return ()
        return (provider,)

    def choose(self, task: str, policy: Mapping[str, Any] | None = None) -> InferenceProvider:
        if not isinstance(task, str) or not task:
            raise ValueError("INFERENCE_TASK_REQUIRED")
        del policy
        return self.selected()

    def selected(self) -> InferenceProvider:
        """Return the one configured organizer, without availability fallback."""

        if self.organizer.status != "READY":
            raise ProviderSelectionError(
                "ORGANIZER_SELECTION_REQUIRED", tuple(self._by_id)
            )
        provider_id = self.organizer.provider_id
        provider = self._by_id.get(provider_id) if provider_id else None
        if provider is None:
            raise ProviderSelectionError(
                "ORGANIZER_PROVIDER_NOT_CONFIGURED", tuple(self._by_id)
            )
        return provider

    def _ledger_for(self, budget: InferenceBudget) -> BudgetLedger | None:
        if self.budget_ledger is not None:
            return self.budget_ledger
        if self.settings is None:
            return None
        return BudgetLedger(self.settings, run_id=budget.candidate_id or None, candidate_id=budget.candidate_id, purpose=budget.purpose)

    def generate(
        self,
        stage: str,
        schema_name: str,
        input_json: Mapping[str, Any],
        budget: InferenceBudget | Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        if not isinstance(stage, str) or not stage:
            raise ValueError("INFERENCE_TASK_REQUIRED")
        current_budget = InferenceBudget.from_value(budget)
        del policy
        provider = self.selected()
        ledger = self._ledger_for(current_budget)
        result = provider.generate(schema_name, input_json, current_budget)
        if not result.ok or ledger is None:
            return result
        from datetime import datetime, timezone

        consumed = ledger.consume(
            provider.provider_id,
            result.input_tokens,
            result.output_tokens,
            result.cost,
            datetime.now(timezone.utc),
            purpose=current_budget.purpose,
            candidate_id=current_budget.candidate_id,
            deadline_ms=current_budget.deadline_ms,
        )
        if not consumed.allowed:
            return ProviderResult(
                provider.provider_id,
                "failed",
                error_code=consumed.reason_code,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cost=result.cost,
                schema_name=schema_name,
            )
        return result


__all__ = ["ConfiguredUnavailableProvider", "ProviderRouter", "ProviderSelectionError"]
