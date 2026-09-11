from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from ..command_quote import build_hook_argv, quote_command, quote_posix_command, quote_windows_command
from ..config import HostSpec
from ..host_profiles import canonical_host_id, is_custom_host_id
from ..ids import stable_hash
from ..privacy import inspect_text


MAX_HOOK_INPUT_BYTES = 64 * 1024
HOOK_COMMAND_FIELDS = ("command", "commandWindows", "commandUnix", "commandPosix")
_HOOK_COMMAND_TEMPLATES = frozenset({"{{HOOK_COMMAND}}", "{{HOOK_COMMAND_POSIX}}", "{{HOOK_COMMAND_WINDOWS}}"})
_PYTHON_EXECUTABLE_NAMES = frozenset({"python", "python.exe", "python3", "python3.exe"})
_KNOWN_HOOK_HOST_IDS = frozenset({"codex-cli", "codex-app", "claude-code", "gemini-cli", "qwen-code"})
_SAFE_INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RAW_KEYS = frozenset(
    {
        "prompt",
        "query",
        "query_text",
        "message",
        "response",
        "assistant_message",
        "last_assistant_message",
        "tool_output",
        "tool_response",
        "transcript",
        "raw_transcript",
        "content",
        "command_output",
    }
)
_HASH_KEYS = frozenset({"session_id", "turn_id", "cwd", "source_ref", "project_path", "transcript_path"})


def _command_platform(platform: str | None) -> str:
    selected = (platform or ("windows" if os.name == "nt" else "posix")).casefold()
    if selected in {"windows", "win32", "nt"}:
        return "windows"
    if selected in {"posix", "linux", "darwin", "macos", "unix"}:
        return "posix"
    raise ValueError("HOOK_COMMAND_PLATFORM_INVALID")


def _parse_windows_command(command: str) -> tuple[str, ...]:
    """Parse the Windows argv grammar used by ``subprocess.list2cmdline``."""

    if "\x00" in command or any(ord(char) < 0x20 and char not in "\t" for char in command):
        raise ValueError("HOOK_COMMAND_CONTROL_CHARACTER")
    result: list[str] = []
    index = 0
    length = len(command)
    while True:
        while index < length and command[index] in " \t":
            index += 1
        if index >= length:
            return tuple(result)
        argument: list[str] = []
        in_quotes = False
        while index < length:
            character = command[index]
            if character in " \t" and not in_quotes:
                break
            if character == "\\":
                start = index
                while index < length and command[index] == "\\":
                    index += 1
                slashes = index - start
                if index < length and command[index] == '"':
                    argument.extend("\\" * (slashes // 2))
                    if slashes % 2:
                        argument.append('"')
                        index += 1
                    else:
                        index += 1
                        in_quotes = not in_quotes
                else:
                    argument.extend("\\" * slashes)
                continue
            if character == '"':
                in_quotes = not in_quotes
                index += 1
                continue
            argument.append(character)
            index += 1
        if in_quotes:
            raise ValueError("HOOK_COMMAND_UNBALANCED_QUOTES")
        result.append("".join(argument))


def parse_hook_command(command: str, platform: str | None = None) -> tuple[str, ...]:
    """Parse a hook command and require the exact platform builder spelling."""

    if not isinstance(command, str) or not command:
        raise ValueError("HOOK_COMMAND_INVALID")
    selected = _command_platform(platform)
    tokens = _parse_windows_command(command) if selected == "windows" else tuple(shlex.split(command, posix=True))
    if not tokens:
        raise ValueError("HOOK_COMMAND_EMPTY")
    rendered = quote_windows_command(tokens) if selected == "windows" else quote_posix_command(tokens)
    if rendered != command:
        raise ValueError("HOOK_COMMAND_NOT_CANONICAL")
    return tokens


def _is_python_executable(value: str) -> bool:
    name = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
    if name in _PYTHON_EXECUTABLE_NAMES:
        return True
    if name.startswith("python3."):
        version = name[len("python3.") :]
        if version.endswith(".exe"):
            version = version[:-4]
        return bool(version) and version.isdigit()
    return False


def validate_hook_command(
    command: str,
    *,
    platform: str | None = None,
    expected_host_id: str | None = None,
    allow_template: bool = False,
) -> tuple[str, ...] | None:
    """Validate one command against the canonical hook argv contract."""

    if isinstance(command, str) and allow_template and command in _HOOK_COMMAND_TEMPLATES:
        return None
    if not isinstance(command, str) or "{{" in command or "}}" in command:
        raise ValueError("HOOK_COMMAND_UNRENDERED")
    tokens = parse_hook_command(command, platform)
    if len(tokens) not in {17, 19, 21, 23}:
        raise ValueError("HOOK_COMMAND_ARGV_LENGTH_INVALID")
    if not _is_python_executable(tokens[0]):
        raise ValueError("HOOK_COMMAND_EXECUTABLE_INVALID")
    if tokens[1:6] != ("-I", "-B", "-X", "utf8", "-c") or tokens[8:10] != ("ei.hook_entry", "--host-id"):
        raise ValueError("HOOK_COMMAND_ENTRYPOINT_INVALID")
    host_id = tokens[10]
    try:
        canonical_command_host = canonical_host_id(host_id)
    except ValueError as exc:
        raise ValueError("HOOK_COMMAND_HOST_INVALID") from exc
    # Hook commands are persisted identity-bearing values; aliases and
    # non-canonical custom spellings must not create a second identity.
    if canonical_command_host != host_id:
        raise ValueError("HOOK_COMMAND_HOST_INVALID")
    if expected_host_id is None:
        if canonical_command_host not in _KNOWN_HOOK_HOST_IDS and not is_custom_host_id(canonical_command_host):
            raise ValueError("HOOK_COMMAND_HOST_INVALID")
    else:
        try:
            canonical_expected = canonical_host_id(expected_host_id)
        except ValueError as exc:
            raise ValueError("HOOK_COMMAND_HOST_INVALID") from exc
        if canonical_expected != expected_host_id or host_id != canonical_expected:
            raise ValueError("HOOK_COMMAND_HOST_INVALID")
    if tokens[11] != "--engine-root" or tokens[13] not in {"--knowledge-root", "--personal-knowledge-root"}:
        raise ValueError("HOOK_COMMAND_ROOT_ORDER_INVALID")
    personal_flag = tokens[13]
    cursor = 15
    legacy_flag_index = None
    if personal_flag == "--personal-knowledge-root":
        if cursor < len(tokens) and tokens[cursor] == "--knowledge-root":
            legacy_flag_index = cursor
            cursor += 2
    if cursor < len(tokens) and tokens[cursor] == "--team-knowledge-root":
        team_flag_index = cursor
        cursor += 2
    else:
        team_flag_index = None
    runtime_flag_index = cursor
    if runtime_flag_index + 1 >= len(tokens):
        raise ValueError("HOOK_COMMAND_ROOT_ORDER_INVALID")
    if tokens[runtime_flag_index] != "--runtime-root":
        raise ValueError("HOOK_COMMAND_OPTION_INVALID")
    tail = len(tokens) - (runtime_flag_index + 2)
    if tail not in {0, 2}:
        raise ValueError("HOOK_COMMAND_OPTION_INVALID")
    if tail == 2 and tokens[runtime_flag_index + 2] != "--codex-home":
        raise ValueError("HOOK_COMMAND_OPTION_INVALID")
    try:
        arguments = {
            "host_id": host_id,
            "engine_root": tokens[12],
            "runtime_root": tokens[runtime_flag_index + 1],
            "host_home": tokens[runtime_flag_index + 3] if len(tokens) == runtime_flag_index + 4 else None,
        }
        if personal_flag == "--personal-knowledge-root":
            arguments["personal_knowledge_root"] = tokens[14]
        else:
            arguments["knowledge_root"] = tokens[14]
        if team_flag_index is not None:
            arguments["team_knowledge_root"] = tokens[team_flag_index + 1]
        if legacy_flag_index is not None:
            arguments["knowledge_root"] = tokens[legacy_flag_index + 1]
        canonical = build_hook_argv(tokens[0], **arguments)
        if legacy_flag_index is not None and personal_flag == "--personal-knowledge-root":
            insertion = canonical.index("--personal-knowledge-root") + 2
            canonical = (*canonical[:insertion], "--knowledge-root", tokens[legacy_flag_index + 1], *canonical[insertion:])
    except (TypeError, ValueError) as exc:
        raise ValueError("HOOK_COMMAND_ARGV_INVALID") from exc
    if canonical != tokens:
        raise ValueError("HOOK_COMMAND_ARGV_INVALID")
    return tokens


def extract_hook_command_fields(handler: Mapping[str, Any]) -> dict[str, Any]:
    """Extract only supported command fields and reject command aliases."""

    if not isinstance(handler, Mapping):
        raise ValueError("HOOK_COMMAND_HANDLER_INVALID")
    fields = {key: handler[key] for key in HOOK_COMMAND_FIELDS if key in handler}
    unknown = [key for key in handler if isinstance(key, str) and key.casefold().startswith("command") and key not in HOOK_COMMAND_FIELDS]
    if unknown:
        raise ValueError("HOOK_COMMAND_FIELD_INVALID")
    if not fields:
        raise ValueError("HOOK_COMMAND_MISSING")
    return fields


def validate_hook_command_fields(
    fields: Mapping[str, Any],
    *,
    expected_host_id: str | None = None,
    allow_templates: bool = False,
) -> tuple[str, ...] | None:
    """Validate platform variants and require them to represent one argv."""

    if not isinstance(fields, Mapping) or not fields:
        raise ValueError("HOOK_COMMAND_MISSING")
    names = set(fields)
    if not names.issubset(HOOK_COMMAND_FIELDS):
        raise ValueError("HOOK_COMMAND_FIELD_INVALID")
    if "commandWindows" in names:
        if names != {"command", "commandWindows"}:
            raise ValueError("HOOK_COMMAND_FIELDS_INVALID")
        platforms = {"command": "posix", "commandWindows": "windows"}
        templates = {"command": "{{HOOK_COMMAND_POSIX}}", "commandWindows": "{{HOOK_COMMAND_WINDOWS}}"}
    elif "commandUnix" in names or "commandPosix" in names:
        if names not in ({"commandUnix"}, {"commandPosix"}):
            raise ValueError("HOOK_COMMAND_FIELDS_INVALID")
        field = next(iter(names))
        platforms = {field: "posix"}
        templates = {field: "{{HOOK_COMMAND_POSIX}}"}
    elif names == {"command"}:
        platforms = {"command": _command_platform(None)}
        templates = {"command": "{{HOOK_COMMAND}}"}
    else:
        raise ValueError("HOOK_COMMAND_FIELDS_INVALID")

    parsed: tuple[str, ...] | None = None
    saw_template = False
    saw_command = False
    for field, platform in platforms.items():
        command = fields[field]
        if not isinstance(command, str) or not command:
            raise ValueError("HOOK_COMMAND_INVALID")
        if allow_templates and command in _HOOK_COMMAND_TEMPLATES:
            if command != templates[field]:
                raise ValueError("HOOK_COMMAND_TEMPLATE_INVALID")
            saw_template = True
            continue
        saw_command = True
        candidate = validate_hook_command(command, platform=platform, expected_host_id=expected_host_id)
        if parsed is None:
            parsed = candidate
        elif parsed != candidate:
            raise ValueError("HOOK_COMMAND_ARGV_MISMATCH")
    if saw_template and saw_command:
        raise ValueError("HOOK_COMMAND_TEMPLATE_MIXED")
    return None if saw_template else parsed


def _hash_identifier(value: object) -> str:
    if value is None or value == "":
        return ""
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sanitized_value(key: str, value: Any) -> Any:
    lowered = key.casefold()
    if lowered in _RAW_KEYS:
        return None
    if lowered in _HASH_KEYS:
        return _hash_identifier(value)
    if isinstance(value, Mapping):
        return {str(child_key): child_value for child_key, child_value in ((key, _sanitized_value(str(key), child)) for key, child in value.items()) if child_value is not None}
    if isinstance(value, (list, tuple)):
        return [_sanitized_value(lowered, child) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def sanitize_hook_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        cleaned = _sanitized_value(key, value)
        if cleaned is not None:
            sanitized[key] = cleaned
    return sanitized


@dataclass(frozen=True)
class NormalizedHookEvent:
    event_id: str
    idempotency_key: str
    host_id: str
    host_instance_id: str
    host_event_name: str
    normalized_event_name: str
    session_id_hash: str
    turn_id_hash: str
    cwd_hash: str
    source_ref: str | None
    source_hash: str
    payload_hash: str
    received_at: datetime
    privacy_classification: str
    transient_input: str | None = None
    source_host_id: str = ""
    source_host_family: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize only the sanitized envelope; transient input is never serialized."""
        return {
            "event_id": self.event_id,
            "idempotency_key": self.idempotency_key,
            "host_id": self.host_id,
            "host_instance_id": self.host_instance_id,
            "host_event_name": self.host_event_name,
            "normalized_event_name": self.normalized_event_name,
            "session_id_hash": self.session_id_hash,
            "turn_id_hash": self.turn_id_hash,
            "cwd_hash": self.cwd_hash,
            "source_ref": self.source_ref,
            "source_hash": self.source_hash,
            "payload_hash": self.payload_hash,
            "received_at": self.received_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "privacy_classification": self.privacy_classification,
            "source_host_id": self.source_host_id,
            "source_host_family": self.source_host_family,
        }


@dataclass(frozen=True)
class HookResult:
    continue_work: bool
    additional_context: str = ""
    receipt_id: str | None = None
    status: str = "ok"
    host_event_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "continue_work": bool(self.continue_work),
            "additional_context": self.additional_context,
            "receipt_id": self.receipt_id,
            "status": self.status,
            "host_event_name": self.host_event_name,
        }


@runtime_checkable
class HookAdapter(Protocol):
    host_id: str
    adapter_id: str

    def supported_events(self) -> Sequence[str]: ...

    def normalize(self, payload: Mapping[str, Any], spec: HostSpec) -> NormalizedHookEvent: ...

    def encode(self, result: HookResult) -> Mapping[str, Any]: ...

    def config_fragment(
        self,
        executable: Path,
        repo_root: Path,
        knowledge_root: Path | None = None,
        runtime_root: Path | None = None,
    ) -> Mapping[str, Any]: ...


class BaseHookAdapter:
    host_id = ""
    adapter_id = ""
    event_names: tuple[str, ...] = ()
    command_field = "command"
    windows_command_field: str | None = None

    def supported_events(self) -> Sequence[str]:
        return self.event_names

    def _host_event_name(self, payload: Mapping[str, Any]) -> str:
        for key in ("hook_event_name", "event_name", "event"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def normalize(self, payload: Mapping[str, Any], spec: HostSpec) -> NormalizedHookEvent:
        if not isinstance(payload, Mapping):
            raise ValueError("HOOK_PAYLOAD_OBJECT_REQUIRED")
        host_event_name = self._host_event_name(payload)
        if host_event_name not in self.event_names:
            raise ValueError("HOOK_EVENT_UNSUPPORTED")
        try:
            payload_bytes = _canonical_bytes(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("HOOK_PAYLOAD_INVALID") from exc
        if len(payload_bytes) > MAX_HOOK_INPUT_BYTES:
            raise ValueError("HOOK_INPUT_TOO_LARGE")
        sanitized = sanitize_hook_payload(payload)
        event_name = spec.event_mapping.get(host_event_name, host_event_name)
        session_hash = _hash_identifier(payload.get("session_id")) or _hash_identifier("<missing-session>")
        turn_hash = _hash_identifier(payload.get("turn_id")) or _hash_identifier("<missing-turn>")
        cwd_hash = _hash_identifier(payload.get("cwd")) or _hash_identifier("<missing-cwd>")
        source_value = payload.get("source_ref")
        source_ref = _hash_identifier(source_value) if source_value else None
        source_hash = source_ref or "sha256:" + stable_hash(sanitized)
        payload_hash = "sha256:" + hashlib.sha256(_canonical_bytes(sanitized)).hexdigest()
        instance = payload.get("host_instance_id") or self.host_id
        if not isinstance(instance, str) or not instance:
            instance = self.host_id
        elif not _SAFE_INSTANCE_ID_RE.fullmatch(instance):
            instance = "instance_" + hashlib.sha256(instance.encode("utf-8", "replace")).hexdigest()[:24]
        transient = next((payload.get(key) for key in ("prompt", "user_prompt", "message") if isinstance(payload.get(key), str)), None)
        source_kind = payload.get("source_kind", "hook")
        source_kind = source_kind if isinstance(source_kind, str) else "hook"
        privacy = inspect_text(transient or "", source_kind, source_value if isinstance(source_value, str) else "hook-event")
        basis = {
            "host_id": self.host_id,
            "host_instance_id": instance,
            "host_event_name": host_event_name,
            "normalized_event_name": event_name,
            "session_id_hash": session_hash,
            "turn_id_hash": turn_hash,
            "cwd_hash": cwd_hash,
            "payload_hash": payload_hash,
        }
        idempotency_key = "sha256:" + stable_hash(basis)
        received_at = datetime.now(timezone.utc)
        event_id = "evt_" + received_at.strftime("%Y%m%dT%H%M%S%fZ") + "_" + stable_hash({"idempotency_key": idempotency_key, "received_at": payload.get("received_at", "")})[:12]
        return NormalizedHookEvent(
            event_id=event_id,
            idempotency_key=idempotency_key,
            host_id=self.host_id,
            host_instance_id=instance,
            host_event_name=host_event_name,
            normalized_event_name=event_name,
            session_id_hash=session_hash,
            turn_id_hash=turn_hash,
            cwd_hash=cwd_hash,
            source_ref=source_ref,
            source_hash=source_hash,
            payload_hash=payload_hash,
            received_at=received_at,
            privacy_classification=privacy.classification.value,
            transient_input=transient,
            source_host_id=self.host_id,
            source_host_family=getattr(spec, "host_family", "") or "",
        )

    def encode(self, result: HookResult) -> Mapping[str, Any]:
        output: dict[str, Any] = {"continue": bool(result.continue_work)}
        if result.additional_context:
            output["hookSpecificOutput"] = {
                "hookEventName": result.host_event_name or "UserPromptSubmit",
                "additionalContext": result.additional_context,
            }
        return output

    def config_fragment(
        self,
        executable: Path,
        repo_root: Path,
        knowledge_root: Path | None = None,
        runtime_root: Path | None = None,
    ) -> Mapping[str, Any]:
        if knowledge_root is None or runtime_root is None:
            raise ValueError("HOOK_ROOTS_REQUIRED")
        argv = build_hook_argv(
            executable,
            host_id=self.host_id,
            engine_root=repo_root,
            knowledge_root=knowledge_root,
            runtime_root=runtime_root,
        )
        fragment: dict[str, Any] = {
            "id": f"ei-{self.host_id}-v1",
            "type": "command",
            self.command_field: quote_posix_command(argv) if self.windows_command_field else quote_command(argv),
        }
        if self.windows_command_field:
            fragment[self.windows_command_field] = quote_windows_command(argv)
        return fragment


def fail_open_result(event_name: str = "", status: str = "HOOK_FAIL_OPEN") -> HookResult:
    return HookResult(True, "", None, status, event_name)


__all__ = [
    "BaseHookAdapter",
    "HOOK_COMMAND_FIELDS",
    "HookAdapter",
    "HookResult",
    "MAX_HOOK_INPUT_BYTES",
    "NormalizedHookEvent",
    "extract_hook_command_fields",
    "fail_open_result",
    "parse_hook_command",
    "sanitize_hook_payload",
    "validate_hook_command",
    "validate_hook_command_fields",
]
