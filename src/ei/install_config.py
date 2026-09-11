from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .hooks.base import extract_hook_command_fields, validate_hook_command_fields

MANAGED_HOOK_IDS = frozenset(
    {
        "ei-session-start-v1",
        "ei-user-prompt-submit-v1",
        "ei-stop-v1",
        "ei-session-end-v1",
        "ei-codex-cli-sessionstart-v1",
        "ei-codex-cli-userpromptsubmit-v1",
        "ei-codex-cli-stop-v1",
        "ei-codex-cli-sessionend-v1",
        "ei-claude-code-sessionstart-v1",
        "ei-claude-code-userpromptsubmit-v1",
        "ei-claude-code-stop-v1",
        "ei-claude-code-sessionend-v1",
        "ei-gemini-cli-sessionstart-v1",
        "ei-gemini-cli-beforeagent-v1",
        "ei-gemini-cli-afteragent-v1",
        "ei-gemini-cli-sessionend-v1",
        "ei-qwen-code-sessionstart-v1",
        "ei-qwen-code-userpromptsubmit-v1",
        "ei-qwen-code-stop-v1",
        "ei-qwen-code-sessionend-v1",
    }
)
_SECTION = re.compile(r"^\s*\[(?P<section>[A-Za-z0-9_.-]+)\]\s*$")
_KEY = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+)\s*=.*$")
_CONFIG_VALUES = {
    "features": {"memories": "true", "hooks": "true"},
    "memories": {
        "generate_memories": "true",
        "use_memories": "true",
        "disable_on_external_context": "false",
    },
}


def _sections(lines: list[str]) -> dict[str, int]:
    locations: dict[str, int] = {}
    for index, line in enumerate(lines):
        match = _SECTION.match(line.rstrip("\r\n"))
        if not match:
            continue
        section = match.group("section")
        if section in locations:
            raise ValueError(f"DUPLICATE_TOML_SECTION:{section}")
        locations[section] = index
    return locations


def _text_style(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"


def merge_config_toml(text: str) -> str:
    """Merge only engine-owned TOML keys while preserving comments and line style."""
    if not isinstance(text, str):
        raise TypeError("TOML_TEXT_REQUIRED")
    style = _text_style(text)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    had_trailing_newline = normalized.endswith("\n")
    lines = normalized.splitlines()
    locations = _sections(lines)
    for section, values in _CONFIG_VALUES.items():
        if section not in locations:
            if lines and lines[-1].strip():
                lines.append("")
            lines.append(f"[{section}]")
            lines.extend(f"{key} = {value}" for key, value in values.items())
            locations[section] = len(lines) - len(values) - 1
            continue
        start = locations[section]
        end = next((index for index in range(start + 1, len(lines)) if _SECTION.match(lines[index].strip())), len(lines))
        for key, value in values.items():
            replacement = f"{key} = {value}"
            for index in range(start + 1, end):
                match = _KEY.match(lines[index])
                if match and match.group("key") == key:
                    lines[index] = f"{match.group('indent')}{replacement}"
                    break
            else:
                lines.insert(end, replacement)
                end += 1
                for name, position in list(locations.items()):
                    if position >= end - 1 and name != section:
                        locations[name] = position + 1
    result = "\n".join(lines)
    if had_trailing_newline:
        result += "\n"
    return result.replace("\n", style)


def managed_ids_from_config(value: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()
    hooks = value.get("hooks")
    if not isinstance(hooks, Mapping):
        return found
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                identifier = item["id"]
                if identifier in MANAGED_HOOK_IDS or identifier.startswith("ei-"):
                    found.add(identifier)
    return found


def managed_ids_from_fragment(managed: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()
    hooks = managed.get("hooks")
    if not isinstance(hooks, Mapping):
        return found
    for entries in hooks.values():
        if not isinstance(entries, list):
            raise ValueError("MANAGED_HOOKS_NOT_LIST")
        for item in entries:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not item["id"]:
                raise ValueError("MANAGED_HOOK_ENTRY_INVALID")
            found.add(item["id"])
    return found


def _remove_ids(values: list[Any], managed_ids: set[str]) -> list[Any]:
    return [item for item in values if not (isinstance(item, Mapping) and str(item.get("id", "")) in managed_ids)]


def merge_hooks(existing: Mapping[str, Any], managed: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(existing, Mapping) or not isinstance(managed, Mapping):
        raise ValueError("HOOKS_OBJECT_REQUIRED")
    result = copy.deepcopy(dict(existing))
    result_hooks = result.setdefault("hooks", {})
    managed_hooks = managed.get("hooks", {})
    if not isinstance(result_hooks, dict) or not isinstance(managed_hooks, Mapping):
        raise ValueError("HOOKS_SHAPE_INVALID")
    managed_ids = set(MANAGED_HOOK_IDS)
    managed_ids.update(managed_ids_from_fragment(managed))
    for event_name, managed_items in managed_hooks.items():
        if not isinstance(managed_items, list):
            raise ValueError(f"MANAGED_HOOKS_NOT_LIST:{event_name}")
        current = result_hooks.setdefault(event_name, [])
        if not isinstance(current, list):
            raise ValueError(f"HOOKS_NOT_LIST:{event_name}")
        result_hooks[event_name] = _remove_ids(current, managed_ids) + copy.deepcopy(managed_items)
    for event_name, current in list(result_hooks.items()):
        if event_name not in managed_hooks and isinstance(current, list):
            result_hooks[event_name] = _remove_ids(current, managed_ids)
    return result


def remove_managed_hooks(existing: Mapping[str, Any], managed_ids: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(existing, Mapping):
        raise ValueError("HOOKS_OBJECT_REQUIRED")
    result = copy.deepcopy(dict(existing))
    hooks = result.get("hooks")
    if hooks is None:
        return result
    if not isinstance(hooks, dict):
        raise ValueError("HOOKS_SHAPE_INVALID")
    ids = set(MANAGED_HOOK_IDS) if managed_ids is None else set(managed_ids)
    for event_name, values in list(hooks.items()):
        if isinstance(values, list):
            hooks[event_name] = _remove_ids(values, ids)
    return result


def validate_hook_commands(value: Mapping[str, Any]) -> None:
    """Reject any managed hook command that is not canonical for its platform."""

    if not isinstance(value, Mapping):
        raise ValueError("HOOKS_OBJECT_REQUIRED")
    hooks = value.get("hooks")
    if not isinstance(hooks, Mapping):
        raise ValueError("HOOKS_SHAPE_INVALID")
    seen = 0
    layout: tuple[str, ...] | None = None
    argv: tuple[str, ...] | None = None
    for entries in hooks.values():
        if not isinstance(entries, list):
            raise ValueError("HOOKS_NOT_LIST")
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ValueError("HOOK_ENTRY_INVALID")
            handlers = entry.get("hooks")
            if not isinstance(handlers, list):
                raise ValueError("HOOK_HANDLERS_NOT_LIST")
            for handler in handlers:
                if not isinstance(handler, Mapping) or handler.get("type") != "command":
                    raise ValueError("HOOK_COMMAND_HANDLER_INVALID")
                fields = extract_hook_command_fields(handler)
                candidate = validate_hook_command_fields(fields)
                current_layout = tuple(sorted(fields))
                if layout is None:
                    layout = current_layout
                elif layout != current_layout:
                    raise ValueError("HOOK_COMMAND_FIELDS_INVALID")
                if argv is None:
                    argv = candidate
                elif argv != candidate:
                    raise ValueError("HOOK_COMMAND_ARGV_MISMATCH")
                seen += 1
    if seen == 0:
        raise ValueError("HOOK_COMMAND_MISSING")


__all__ = ["MANAGED_HOOK_IDS", "managed_ids_from_config", "managed_ids_from_fragment", "merge_config_toml", "merge_hooks", "remove_managed_hooks", "validate_hook_commands"]
