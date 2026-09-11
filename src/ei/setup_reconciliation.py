"""Pure desired-state setup reconciliation planning.

The planner deliberately has no installer or filesystem dependency.  It accepts
detached mappings from the active manifest, setup selection, and a read-only
live-state probe, then returns an immutable plan that an installer can apply
after its final stale-plan check.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Literal, Mapping


ActionKind = Literal[
    "prepare-personal",
    "prepare-team",
    "remove-host",
    "write-managed",
    "install-skill",
    "write-binding",
    "scheduler-enable",
    "scheduler-disable",
    "write-manifest",
]

_ACTION_ORDER: dict[str, int] = {
    "prepare-personal": 10,
    "prepare-team": 20,
    "remove-host": 30,
    "write-managed": 40,
    "install-skill": 50,
    "write-binding": 60,
    "scheduler-enable": 70,
    "scheduler-disable": 70,
    "write-manifest": 80,
}

_VOLATILE_KEYS = frozenset(
    {
        "timestamp",
        "timestamps",
        "occurred_at",
        "created_at",
        "installed_at",
        "uninstalled_at",
        "generated_at",
        "started_at",
        "updated_at",
        "completed_at",
        "transaction_id",
        "transaction_ids",
        "receipt",
        "receipt_path",
        "receipt_paths",
        "receipt_sha256",
        "operation_receipt",
        "diagnostic",
        "diagnostics",
        "diagnostic_output",
        "desired_state_digest",
        "live_state_digest",
    }
)

_PERSONAL_IDENTITY_KEYS = (
    "mode",
    "remote_name",
    "remote_fingerprint",
    "remote_classification",
    "branch",
)


@dataclass(frozen=True)
class ReconciliationAction:
    kind: ActionKind
    target: str
    before_hash: str | None
    after_hash: str | None
    owned: bool

    def __post_init__(self) -> None:
        if self.kind not in _ACTION_ORDER or not isinstance(self.target, str) or not self.target:
            raise ValueError("SETUP_ACTION_INVALID")
        if self.before_hash is not None and not isinstance(self.before_hash, str):
            raise ValueError("SETUP_ACTION_INVALID")
        if self.after_hash is not None and not isinstance(self.after_hash, str):
            raise ValueError("SETUP_ACTION_INVALID")
        if type(self.owned) is not bool:
            raise ValueError("SETUP_ACTION_INVALID")

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "target": self.target,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "owned": self.owned,
        }


@dataclass(frozen=True)
class SetupReconciliationPlan:
    status: Literal["CREATED", "UPDATED", "ALREADY_CURRENT", "BLOCKED"]
    desired_state_digest: str
    live_state_digest: str
    actions: tuple[ReconciliationAction, ...]
    changed_paths: tuple[str, ...]
    retained_paths: tuple[str, ...]
    errors: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        if self.status not in {"CREATED", "UPDATED", "ALREADY_CURRENT", "BLOCKED"}:
            raise ValueError("SETUP_PLAN_INVALID")
        for digest in (self.desired_state_digest, self.live_state_digest):
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise ValueError("SETUP_PLAN_INVALID")
        if not isinstance(self.actions, tuple) or any(not isinstance(item, ReconciliationAction) for item in self.actions):
            raise ValueError("SETUP_PLAN_INVALID")
        if not isinstance(self.changed_paths, tuple) or any(not isinstance(item, str) for item in self.changed_paths):
            raise ValueError("SETUP_PLAN_INVALID")
        if not isinstance(self.retained_paths, tuple) or any(not isinstance(item, str) for item in self.retained_paths):
            raise ValueError("SETUP_PLAN_INVALID")
        if not isinstance(self.errors, tuple) or any(not isinstance(item, Mapping) for item in self.errors):
            raise ValueError("SETUP_PLAN_INVALID")

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "desired_state_digest": self.desired_state_digest,
            "live_state_digest": self.live_state_digest,
            "actions": [item.to_dict() for item in self.actions],
            "changed_paths": list(self.changed_paths),
            "retained_paths": list(self.retained_paths),
            "errors": [dict(item) for item in self.errors],
        }


def _mapping(value: object, code: str = "SETUP_STATE_INVALID") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(code)
    return value


def _deep(value: object) -> Any:
    return copy.deepcopy(value)


def _json_ready(value: object) -> object:
    """Convert detached state to JSON without invoking filesystem/path APIs."""

    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_ready(item) for item in value), key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _without_volatile(value: object) -> object:
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            lowered = name.casefold()
            if lowered in _VOLATILE_KEYS:
                continue
            if lowered.endswith("_receipt_path") or lowered.endswith("_diagnostics"):
                continue
            result[name] = _without_volatile(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_without_volatile(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_without_volatile(item) for item in value), key=lambda item: json.dumps(_json_ready(item), ensure_ascii=False, sort_keys=True))
    return _json_ready(value)


def state_digest(value: Mapping[str, Any]) -> str:
    """Return the stable SHA-256 digest used by desired and live state."""

    _mapping(value)
    body = _without_volatile(value)
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _value_hash(value: object) -> str:
    raw = json.dumps(_json_ready(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _normal_path(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value:
        return None
    # This is lexical normalization only.  The planner must not resolve or
    # touch a path because that would turn a read-only plan into an I/O action.
    normalized = value.replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized.casefold() if os.name == "nt" else normalized


def _nested(mapping: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = mapping.get(key)
    return value if isinstance(value, Mapping) else None


def _state_manifest(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    manifest = state.get("manifest")
    return manifest if isinstance(manifest, Mapping) else None


def _state_value(state: Mapping[str, Any], *keys: str) -> object:
    for source in (state, _state_manifest(state)):
        if isinstance(source, Mapping):
            for key in keys:
                if key in source:
                    return source[key]
    return None


def _personal_store(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for source in (state, _state_manifest(state)):
        if not isinstance(source, Mapping):
            continue
        value = source.get("personal")
        if isinstance(value, Mapping):
            return value
        stores = source.get("knowledge_stores")
        if isinstance(stores, Mapping) and isinstance(stores.get("personal"), Mapping):
            return stores["personal"]
        repository = source.get("knowledge_repository")
        if isinstance(repository, Mapping):
            return repository
    return None


def _team_store(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for source in (state, _state_manifest(state)):
        if not isinstance(source, Mapping):
            continue
        if "team" in source:
            value = source.get("team")
            return value if isinstance(value, Mapping) else None
        stores = source.get("knowledge_stores")
        if isinstance(stores, Mapping):
            value = stores.get("team")
            return value if isinstance(value, Mapping) else None
    return None


def _root(state: Mapping[str, Any], kind: str) -> object:
    if kind == "personal":
        top_keys = ("personal_knowledge_root", "personal_root", "knowledge_root")
    elif kind == "team":
        top_keys = ("team_knowledge_root", "team_root")
    else:
        top_keys = ("runtime_root",)
    value = _state_value(state, *top_keys)
    if value is not None:
        return value
    store = _personal_store(state) if kind == "personal" else _team_store(state) if kind == "team" else None
    if isinstance(store, Mapping):
        return store.get("root")
    return None


def _personal_identity(state: Mapping[str, Any]) -> dict[str, object]:
    store = _personal_store(state) or {}
    return {key: store.get(key) for key in _PERSONAL_IDENTITY_KEYS}


def _enabled(store: Mapping[str, Any] | None) -> bool | None:
    if not isinstance(store, Mapping):
        return None
    value = store.get("enabled")
    return value if type(value) is bool else None


def _merge_mapping(base: object, update: Mapping[str, Any]) -> dict[str, Any]:
    result = _deep(base) if isinstance(base, Mapping) else {}
    for key, value in update.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge_mapping(result[key], value)
        else:
            result[key] = _deep(value)
    return result


def _set_store(state: dict[str, Any], kind: str, value: Mapping[str, Any] | None) -> None:
    state[kind] = _deep(value) if value is not None else None
    stores = state.get("knowledge_stores")
    if isinstance(stores, Mapping):
        stores_copy = dict(stores)
        stores_copy[kind] = _deep(value) if value is not None else None
        state["knowledge_stores"] = stores_copy
    manifest = state.get("manifest")
    if isinstance(manifest, Mapping):
        manifest_copy = dict(manifest)
        manifest_stores = manifest_copy.get("knowledge_stores")
        if isinstance(manifest_stores, Mapping):
            manifest_copy["knowledge_stores"] = {**manifest_stores, kind: _deep(value) if value is not None else None}
        else:
            manifest_copy[kind] = _deep(value) if value is not None else None
        state["manifest"] = manifest_copy


def _set_personal_root(state: dict[str, Any], value: object) -> None:
    state["personal_knowledge_root"] = _deep(value)
    # Keep the legacy compatibility view in sync when it is present or when
    # no explicit personal-root name existed in the input.
    if "knowledge_root" in state or "personal_root" not in state:
        state["knowledge_root"] = _deep(value)
    personal = dict(_personal_store(state) or {})
    personal["root"] = _deep(value)
    personal.setdefault("enabled", True)
    _set_store(state, "personal", personal)


def _set_team_field(state: dict[str, Any], key: str, value: object) -> None:
    team = dict(_team_store(state) or {})
    team[key] = _deep(value)
    if key == "enabled":
        team["status"] = "READY" if value is True else "DISABLED"
    _set_store(state, "team", team)


def _apply_explicit(state: dict[str, Any], explicit: Mapping[str, Any]) -> None:
    team_disable = explicit.get("no_team_knowledge") is True or explicit.get("team_knowledge") is False or explicit.get("team_enabled") is False
    team_enable = explicit.get("team_knowledge") is True or explicit.get("team_enabled") is True
    for key, value in explicit.items():
        if key in {"desired_state_digest", "no_team_knowledge", "team_knowledge", "team_enabled"}:
            continue
        if key in {"personal_root", "personal_knowledge_root", "knowledge_root"}:
            _set_personal_root(state, value)
            continue
        if key in {"team_root", "team_knowledge_root"}:
            _set_team_field(state, "root", value)
            team_enable = True
            continue
        if key == "team_member_id":
            _set_team_field(state, "team_member_id", value)
            continue
        if key in {"remote_fingerprint", "personal_remote_fingerprint"}:
            personal = dict(_personal_store(state) or {})
            personal["remote_fingerprint"] = _deep(value)
            _set_store(state, "personal", personal)
            continue
        if key in {"sync", "sync_enabled"}:
            state["sync_enabled"] = _deep(value)
            personal = dict(_personal_store(state) or {})
            personal["sync_enabled"] = _deep(value)
            _set_store(state, "personal", personal)
            continue
        if key == "experiment":
            state["experiment_enabled"] = _deep(value)
            continue
        if key in {"scheduler", "hosts", "managed_targets"} or key == "providers" or key == "privacy_profile" or key in {"engine_root", "runtime_root"}:
            state[key] = _deep(value)
            continue
        if key == "personal":
            merged = _merge_mapping(_personal_store(state), _mapping(value))
            _set_store(state, "personal", merged)
            continue
        if key == "team":
            if value is None:
                _set_store(state, "team", None)
            else:
                merged = _merge_mapping(_team_store(state), _mapping(value))
                _set_store(state, "team", merged)
            continue
        if key == "knowledge_stores":
            stores = _mapping(value)
            if "personal" in stores:
                _set_store(state, "personal", _mapping(stores["personal"]))
            if "team" in stores:
                team_value = stores["team"]
                _set_store(state, "team", _mapping(team_value) if isinstance(team_value, Mapping) else None)
            continue
        if isinstance(value, Mapping) and isinstance(state.get(key), Mapping):
            state[key] = _merge_mapping(state[key], value)
        else:
            state[key] = _deep(value)

    if team_disable:
        if _team_store(state) is not None:
            _set_team_field(state, "enabled", False)
    elif team_enable:
        if _team_store(state) is not None:
            _set_team_field(state, "enabled", True)


def build_desired_state(
    current: Mapping[str, Any] | None = None,
    explicit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a detached desired-state mapping from current plus options.

    Omitted team options are intentionally not touched.  On a first setup an
    empty current mapping gets a mandatory personal store and a disabled/no
    team store; later tasks can add the concrete roots and identities.
    """

    if current is not None and not isinstance(current, Mapping):
        raise ValueError("SETUP_STATE_INVALID")
    selected = {} if current is None else _deep(current)
    if not selected:
        selected = {
            "personal": {"enabled": True},
            "team": None,
            "providers": [],
            "privacy_profile": "private-reusable",
            "experiment_enabled": False,
            "hosts": {},
            "scheduler": {"enabled": False},
        }
    options = {} if explicit is None else dict(_mapping(explicit))
    _apply_explicit(selected, options)
    selected.setdefault("personal", {"enabled": True})
    selected.setdefault("team", _deep(_team_store(selected)))
    selected["desired_state_digest"] = state_digest(selected)
    reconciliation = selected.get("reconciliation")
    if isinstance(reconciliation, Mapping):
        selected["reconciliation"] = {**reconciliation, "desired_state_digest": selected["desired_state_digest"]}
    return selected


def _error(code: str, target_kind: str) -> dict[str, object]:
    values: dict[str, tuple[bool, bool, str, str]] = {
        "PERSONAL_ROOT_CHANGE_REQUIRES_MIGRATION": (False, True, "Run an explicit personal-root migration.", "ei migrate plan"),
        "PERSONAL_REMOTE_CHANGE_REQUIRES_MIGRATION": (False, True, "Run an explicit personal-remote migration.", "ei migrate plan"),
        "TEAM_ROOT_CHANGE_REQUIRES_MIGRATION": (False, True, "Run an explicit team-store reattach or migration.", "ei migrate plan"),
        "RUNTIME_ROOT_CHANGE_REQUIRES_MIGRATION": (False, True, "Run an explicit runtime migration.", "ei migrate plan"),
        "MANAGED_TARGET_CONFLICT": (False, True, "Review the managed target and approve a fresh setup plan.", "ei setup --check-only"),
        "ACTIVE_RUNTIME_MISMATCH": (False, True, "Repair or remove the binding owned by the other runtime.", "ei setup --check-only"),
        "TEAM_ROOT_CONTRACT_INVALID": (True, True, "Repair the selected team store and retry setup.", "ei setup --check-only"),
        "TEAM_STORE_MANIFEST_INVALID": (True, True, "Repair the selected team store manifest and retry setup.", "ei setup --check-only"),
        "TEAM_STORE_ID_MISMATCH": (False, True, "Use the original team store or run an explicit migration.", "ei migrate plan"),
        "TEAM_ROOT_UNAVAILABLE": (True, False, "Make the selected team store available and retry setup.", "ei setup --check-only"),
        "SETUP_PLAN_STALE": (True, False, "Re-run setup planning before applying changes.", "ei setup --check-only"),
        "LIVE_STATE_MISMATCH": (True, False, "Re-read the live state and create a fresh plan.", "ei setup --check-only"),
    }
    retryable, risk, action, command = values.get(code, (False, True, "Review the setup state and create a fresh plan.", "ei setup --check-only"))
    return {
        "error_code": code,
        "retryable": retryable,
        "data_loss_risk": risk,
        "user_action": action,
        "recovery_command": command,
        "target_kind": target_kind,
    }


def _managed_records(state: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("managed_targets", "managed", "target_hashes"):
        value = state.get(key)
        if isinstance(value, Mapping):
            return value
    manifest = _state_manifest(state)
    if isinstance(manifest, Mapping):
        value = manifest.get("managed_targets")
        if isinstance(value, Mapping):
            return value
    return {}


def _record_hash(record: object) -> object:
    if isinstance(record, Mapping):
        for key in ("hash", "live_hash", "current_hash", "installed_hash"):
            if key in record:
                return record[key]
    return record


def _ownership_hash(record: object) -> object:
    if isinstance(record, Mapping):
        for key in ("ownership_hash", "manifest_hash", "owned_hash", "expected_hash"):
            if key in record:
                return record[key]
    return None


def _managed_conflict(current: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
    current_records = _managed_records(current)
    live_records = _managed_records(live)
    for target, current_record in current_records.items():
        if not isinstance(current_record, Mapping) or current_record.get("owned") is not True:
            continue
        expected = _ownership_hash(current_record)
        actual = _record_hash(live_records.get(target, current_record))
        if expected is not None and actual is not None and actual != expected:
            return True
    for target, live_record in live_records.items():
        if not isinstance(live_record, Mapping) or live_record.get("owned") is not True:
            continue
        expected = _ownership_hash(live_record)
        actual = _record_hash(live_record)
        if expected is not None and actual is not None and actual != expected:
            return True
    return False


def _binding_runtime_mismatch(desired: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
    runtime = _normal_path(_root(desired, "runtime"))
    if runtime is None:
        return False
    candidates: list[object] = []
    hosts = live.get("hosts")
    if isinstance(hosts, Mapping):
        candidates.extend(hosts.values())
    bindings = live.get("bindings")
    if isinstance(bindings, Mapping):
        candidates.extend(bindings.values())
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        bound = None
        for key in ("runtime_root", "binding_runtime_root", "bound_runtime_root", "runtime"):
            if key in item:
                bound = item[key]
                break
        if bound is not None and _normal_path(bound) != runtime:
            return True
    return False


def _team_identity_changed(current: Mapping[str, Any], desired: Mapping[str, Any]) -> bool:
    current_team = _team_store(current)
    desired_team = _team_store(desired)
    if current_team is None or desired_team is None:
        return False
    current_root = _normal_path(current_team.get("root"))
    desired_root = _normal_path(desired_team.get("root"))
    if current_root != desired_root:
        return True
    current_id = current_team.get("store_id")
    desired_id = desired_team.get("store_id")
    return current_id is not None and desired_id is not None and current_id != desired_id


def _identity_error(current: Mapping[str, Any], desired: Mapping[str, Any]) -> dict[str, object] | None:
    current_personal_root = _normal_path(_root(current, "personal"))
    desired_personal_root = _normal_path(_root(desired, "personal"))
    if current_personal_root is not None and desired_personal_root is not None and current_personal_root != desired_personal_root:
        return _error("PERSONAL_ROOT_CHANGE_REQUIRES_MIGRATION", "personal-root")

    current_team = _team_store(current)
    desired_team = _team_store(desired)
    if current_team is not None and desired_team is not None and _team_identity_changed(current, desired):
        return _error("TEAM_ROOT_CHANGE_REQUIRES_MIGRATION", "team-store")

    current_runtime = _normal_path(_root(current, "runtime"))
    desired_runtime = _normal_path(_root(desired, "runtime"))
    if current_runtime is not None and desired_runtime is not None and current_runtime != desired_runtime:
        return _error("RUNTIME_ROOT_CHANGE_REQUIRES_MIGRATION", "runtime-root")

    current_personal_store = _personal_store(current)
    current_personal = _personal_identity(current)
    desired_personal = _personal_identity(desired)
    # A first setup has no persisted repository identity to protect.  The
    # desired local mode is created by the installer; it must not be treated
    # as a remote-identity migration from an empty state.
    if current_personal_store is not None and current_personal != desired_personal:
        return _error("PERSONAL_REMOTE_CHANGE_REQUIRES_MIGRATION", "personal-remote")
    return None


def _field(state: Mapping[str, Any], key: str, default: object = None) -> object:
    value = _state_value(state, key)
    return default if value is None else value


def _host_map(state: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _state_value(state, "hosts")
    return value if isinstance(value, Mapping) else {}


def _live_target_missing(live: Mapping[str, Any], target: object, expected: object) -> bool:
    """Return whether an owned target recorded in the manifest is absent live.

    A missing target is a repair case, not a user conflict.  The installer
    records the read-only probe as ``hash=None`` so the pure planner can ask
    for the corresponding owned write without touching the filesystem.
    """

    if not isinstance(target, str) or not target or not isinstance(expected, str):
        return False
    live_record = _managed_records(live).get(target)
    return isinstance(live_record, Mapping) and live_record.get("hash") is None


def _host_action_changes(
    current: Mapping[str, Any],
    desired: Mapping[str, Any],
    live: Mapping[str, Any] | None = None,
) -> tuple[list[ReconciliationAction], list[str], bool]:
    actions: list[ReconciliationAction] = []
    changed: list[str] = []
    managed_change = False
    current_hosts = _host_map(current)
    desired_hosts = _host_map(desired)
    for host in sorted(set(current_hosts) - set(desired_hosts)):
        actions.append(ReconciliationAction("remove-host", f"hosts/{host}", _value_hash(current_hosts[host]), None, True))
        changed.append(f"hosts/{host}")
    for host in sorted(set(desired_hosts) - set(current_hosts)):
        record = desired_hosts[host]
        after = _value_hash(record)
        actions.append(ReconciliationAction("install-skill", f"hosts/{host}/skill", None, after, True))
        actions.append(ReconciliationAction("write-binding", f"hosts/{host}/binding", None, after, True))
        changed.append(f"hosts/{host}")
    for host in sorted(set(current_hosts) & set(desired_hosts)):
        current_record = current_hosts[host]
        desired_record = desired_hosts[host]
        repair_binding = False
        repair_skill = False
        if isinstance(current_record, Mapping) and isinstance(desired_record, Mapping) and isinstance(live, Mapping):
            repair_binding = _live_target_missing(
                live,
                current_record.get("skill_binding_path"),
                current_record.get("skill_binding_hash"),
            )
            repair_skill = _live_target_missing(
                live,
                current_record.get("skill_destination"),
                current_record.get("installed_skill_hash"),
            )
        if _without_volatile(current_record) == _without_volatile(desired_record) and not (repair_binding or repair_skill):
            continue
        if isinstance(current_record, Mapping) and isinstance(desired_record, Mapping):
            binding_changed = current_record.get("skill_binding_hash") != desired_record.get("skill_binding_hash") or current_record.get("binding_hash") != desired_record.get("binding_hash")
            skill_changed = current_record.get("installed_skill_hash") != desired_record.get("installed_skill_hash") or current_record.get("skill_hash") != desired_record.get("skill_hash")
            if binding_changed or repair_binding:
                actions.append(ReconciliationAction("write-binding", f"hosts/{host}/binding", None if repair_binding else _value_hash(current_record), _value_hash(desired_record), True))
            if skill_changed or repair_skill:
                actions.append(ReconciliationAction("install-skill", f"hosts/{host}/skill", None if repair_skill else _value_hash(current_record), _value_hash(desired_record), True))
        managed_change = managed_change or _without_volatile(current_record) != _without_volatile(desired_record)
        changed.append(f"hosts/{host}")
    return actions, changed, managed_change


def _settings_changes(current: Mapping[str, Any], desired: Mapping[str, Any]) -> list[str]:
    changed: list[str] = []
    for key in ("providers", "privacy_profile", "experiment_enabled", "engine_root", "sync_enabled"):
        if _without_volatile(_field(current, key)) != _without_volatile(_field(desired, key)):
            changed.append(key)
    current_team = _team_store(current)
    desired_team = _team_store(desired)
    if _enabled(current_team) != _enabled(desired_team):
        changed.append("team")
    if isinstance(current_team, Mapping) and isinstance(desired_team, Mapping) and current_team.get("team_member_id") != desired_team.get("team_member_id"):
        changed.append("team_member_id")
    return changed


def _retained_paths(current: Mapping[str, Any], desired: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for state in (current, desired):
        retained = state.get("retained_paths")
        if isinstance(retained, (list, tuple)):
            values.extend(str(item) for item in retained if isinstance(item, (str, os.PathLike)))
    for state in (current, desired):
        for kind in ("personal", "team"):
            root = _root(state, kind)
            if root is not None:
                values.append(os.fspath(root) if isinstance(root, os.PathLike) else str(root))
    return tuple(dict.fromkeys(values))


def plan_setup_reconciliation(
    current: Mapping[str, Any],
    desired: Mapping[str, Any],
    live: Mapping[str, Any],
) -> SetupReconciliationPlan:
    """Compare detached state and return a deterministic, read-only plan."""

    current_map = _mapping(current)
    desired_map = _mapping(desired)
    live_map = _mapping(live)
    desired_digest = state_digest(desired_map)
    live_digest = state_digest(live_map)
    retained = _retained_paths(current_map, desired_map)

    identity = _identity_error(current_map, desired_map)
    if identity is not None:
        return SetupReconciliationPlan("BLOCKED", desired_digest, live_digest, (), (), retained, (identity,))
    if _binding_runtime_mismatch(desired_map, live_map):
        error = _error("ACTIVE_RUNTIME_MISMATCH", "host-binding")
        return SetupReconciliationPlan("BLOCKED", desired_digest, live_digest, (), (), retained, (error,))
    live_team = _team_store(live_map)
    if isinstance(live_team, Mapping) and isinstance(live_team.get("live_error"), str):
        code = str(live_team["live_error"])
        if code not in {"TEAM_ROOT_CONTRACT_INVALID", "TEAM_STORE_MANIFEST_INVALID", "TEAM_STORE_ID_MISMATCH", "TEAM_ROOT_UNAVAILABLE"}:
            code = "TEAM_ROOT_CONTRACT_INVALID"
        error = _error(code, "team-store")
        return SetupReconciliationPlan("BLOCKED", desired_digest, live_digest, (), (), retained, (error,))
    if _managed_conflict(current_map, live_map):
        error = _error("MANAGED_TARGET_CONFLICT", "managed-target")
        return SetupReconciliationPlan("BLOCKED", desired_digest, live_digest, (), (), retained, (error,))

    actions: list[ReconciliationAction] = []
    changed: list[str] = []
    if _personal_store(current_map) is None and _personal_store(desired_map) is not None:
        actions.append(ReconciliationAction("prepare-personal", "personal", None, _value_hash(_personal_store(desired_map)), False))
        changed.append("personal")

    current_team = _team_store(current_map)
    desired_team = _team_store(desired_map)
    if isinstance(desired_team, Mapping) and _enabled(desired_team) is True and (_enabled(current_team) is not True):
        actions.append(ReconciliationAction("prepare-team", "team", None, _value_hash(desired_team), False))
        changed.append("team")

    host_actions, host_changed, host_managed_change = _host_action_changes(current_map, desired_map, live_map)
    actions.extend(host_actions)
    changed.extend(host_changed)

    setting_changes = _settings_changes(current_map, desired_map)
    if host_managed_change:
        setting_changes.append("hosts")
    if setting_changes:
        before = {key: _field(current_map, key) for key in setting_changes if key not in {"team", "team_member_id", "hosts"}}
        before["team"] = _team_store(current_map)
        before["hosts"] = _host_map(current_map)
        after = {key: _field(desired_map, key) for key in setting_changes if key not in {"team", "team_member_id", "hosts"}}
        after["team"] = _team_store(desired_map)
        after["hosts"] = _host_map(desired_map)
        actions.append(ReconciliationAction("write-managed", "managed-settings", _value_hash(before), _value_hash(after), True))
        changed.extend(setting_changes)

    current_scheduler = _field(current_map, "scheduler", {})
    desired_scheduler = _field(desired_map, "scheduler", {})
    current_scheduler_enabled = current_scheduler.get("enabled") is True if isinstance(current_scheduler, Mapping) else current_scheduler is True
    desired_scheduler_enabled = desired_scheduler.get("enabled") is True if isinstance(desired_scheduler, Mapping) else desired_scheduler is True
    if current_scheduler_enabled != desired_scheduler_enabled:
        kind: ActionKind = "scheduler-enable" if desired_scheduler_enabled else "scheduler-disable"
        actions.append(ReconciliationAction(kind, "scheduler", _value_hash(current_scheduler), _value_hash(desired_scheduler), True))
        changed.append("scheduler")

    actions.sort(key=lambda item: (_ACTION_ORDER[item.kind], item.target))
    if actions:
        actions.append(ReconciliationAction("write-manifest", "install-manifest", state_digest(current_map), desired_digest, True))
        changed.append("install-manifest")
    changed_tuple = tuple(dict.fromkeys(changed))
    if not actions:
        status: Literal["CREATED", "UPDATED", "ALREADY_CURRENT", "BLOCKED"] = "ALREADY_CURRENT"
    elif not current_map:
        status = "CREATED"
    else:
        status = "UPDATED"
    return SetupReconciliationPlan(status, desired_digest, live_digest, tuple(actions), changed_tuple, retained, ())


def assert_plan_current(
    plan: SetupReconciliationPlan,
    live: Mapping[str, Any] | None = None,
    maybe_live: Mapping[str, Any] | None = None,
    *,
    current: Mapping[str, Any] | None = None,
) -> SetupReconciliationPlan:
    """Recompute the live digest immediately before apply.

    ``maybe_live`` is accepted for a compatibility call shape of
    ``assert_plan_current(plan, current, live)``; the current mapping is not
    needed for the stale check and is intentionally ignored.
    """

    if not isinstance(plan, SetupReconciliationPlan):
        raise ValueError("SETUP_PLAN_INVALID")
    candidate = maybe_live if maybe_live is not None else live
    if candidate is None:
        raise ValueError("SETUP_PLAN_INVALID")
    _mapping(candidate)
    if state_digest(candidate) != plan.live_state_digest:
        raise ValueError("SETUP_PLAN_STALE")
    return plan


__all__ = [
    "ActionKind",
    "ReconciliationAction",
    "SetupReconciliationPlan",
    "assert_plan_current",
    "build_desired_state",
    "plan_setup_reconciliation",
    "state_digest",
]
