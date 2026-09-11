from __future__ import annotations

import hashlib
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .command_quote import build_observe_argv, build_skill_launcher_argv, quote_command

BEGIN_MARKER = "<!-- external-intelligence:begin v1 -->"
END_MARKER = "<!-- external-intelligence:end v1 -->"
TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "templates" / "global-agents.external-intelligence.md"
_CONTEXT_TEMPLATE_NAMES = {
    "codex-cli": "AGENTS.md",
    "codex-app": "AGENTS.md",
    "claude-code": "CLAUDE.md",
    "gemini-cli": "GEMINI.md",
    "qwen-code": "QWEN.md",
}
_COMMAND_PATTERN = re.compile(
    r"Use the generated command (?P<python>.+?) with one UTF-8 JSON object on stdin",
    re.MULTILINE,
)
_TEMPLATE_PLACEHOLDER_PATTERN = re.compile(r"\{\{[A-Z][A-Z0-9_]*\}\}")


@dataclass(frozen=True)
class AgentsMergeResult:
    content: str
    changed: bool
    original_sha256: str | None
    installed_sha256: str


def _render_template(
    template: str,
    replacements: dict[str, str],
    *,
    max_template_chars: int,
    error_code: str,
) -> str:
    placeholders = set(_TEMPLATE_PLACEHOLDER_PATTERN.findall(template))
    if (
        template.count(BEGIN_MARKER) != 1
        or template.count(END_MARKER) != 1
        or len(template) >= max_template_chars
        or placeholders != set(replacements)
    ):
        raise ValueError(error_code)
    rendered = _TEMPLATE_PLACEHOLDER_PATTERN.sub(
        lambda match: replacements[match.group(0)],
        template,
    )
    if rendered.count(BEGIN_MARKER) != 1 or rendered.count(END_MARKER) != 1:
        raise ValueError(error_code)
    return rendered


def _marker_bounds(existing: str) -> tuple[int, int] | None:
    begins = [index for index in range(len(existing)) if existing.startswith(BEGIN_MARKER, index)]
    ends = [index for index in range(len(existing)) if existing.startswith(END_MARKER, index)]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0] > ends[0]:
        raise ValueError("AGENTS_MARKER_CORRUPT")
    after_begin = begins[0] + len(BEGIN_MARKER)
    if BEGIN_MARKER in existing[after_begin : ends[0]] or END_MARKER in existing[ends[0] + len(END_MARKER) :]:
        raise ValueError("AGENTS_MARKER_CORRUPT")
    return begins[0], ends[0]


def _merge_block(existing: str, rendered_block: str) -> str:
    if rendered_block.count(BEGIN_MARKER) != 1 or rendered_block.count(END_MARKER) != 1:
        raise ValueError("MANAGED_BLOCK_INVALID")
    bounds = _marker_bounds(existing)
    if bounds is None:
        separator = "" if not existing or existing.endswith((chr(10), chr(13))) else chr(10)
        return existing + separator + rendered_block
    start, end = bounds
    end_marker_end = end + len(END_MARKER)
    current = existing[start:end_marker_end]
    if current in {rendered_block, rendered_block.rstrip(chr(13) + chr(10))}:
        return existing
    return existing[:start] + rendered_block + existing[end_marker_end:]


def render_global_agents(python_exe: str | Path) -> str:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    command = quote_command(build_observe_argv(python_exe))
    return _render_template(
        template,
        {"{{OBSERVE_COMMAND}}": command},
        max_template_chars=1800,
        error_code="AGENTS_TEMPLATE_INVALID",
    )


def render_managed_context(
    host_id: str,
    python_exe: str | Path,
    repo_root: str | Path,
    runtime_root: str | Path,
    skill_destination: str | Path | None = None,
    knowledge_root: str | Path | None = None,
    *,
    personal_knowledge_root: str | Path | None = None,
    team_knowledge_root: str | Path | None = None,
) -> str:
    template_name = _CONTEXT_TEMPLATE_NAMES.get(host_id)
    if not template_name:
        raise ValueError("HOST_UNSUPPORTED")
    template_path = Path(__file__).resolve().parents[2] / "templates" / "context" / template_name
    if not template_path.is_file():
        raise ValueError("CONTEXT_TEMPLATE_MISSING")
    if skill_destination is None:
        raise ValueError("SKILL_DESTINATION_REQUIRED")
    destination = Path(os.path.abspath(str(Path(skill_destination).expanduser())))
    personal = personal_knowledge_root if personal_knowledge_root is not None else knowledge_root
    if personal is None:
        command_argv = build_observe_argv(python_exe)
    else:
        command_argv = build_observe_argv(
            python_exe,
            engine_root=Path(repo_root).resolve(),
            knowledge_root=Path(personal).resolve(),
            runtime_root=Path(runtime_root).resolve(),
        )
    command = quote_command(command_argv)
    skill_command = quote_command(
        build_skill_launcher_argv(
            python_exe,
            skill_destination=destination,
            engine_root=Path(repo_root).resolve(),
            runtime_root=Path(runtime_root).resolve(),
        )
    )
    template = template_path.read_text(encoding="utf-8")
    replacements = {
        "{{OBSERVE_COMMAND}}": command,
        "{{SKILL_LAUNCH_COMMAND}}": skill_command,
        "{{SKILL_DESTINATION}}": str(destination),
    }
    return _render_template(
        template,
        replacements,
        max_template_chars=2600,
        error_code="CONTEXT_TEMPLATE_INVALID",
    )


def merge_global_agents(existing: str, rendered_block: str) -> str:
    return _merge_block(existing, rendered_block)


def merge_managed_context(path: Path, rendered: str, marker_id: str = "v1") -> AgentsMergeResult:
    if marker_id != "v1":
        raise ValueError("MANAGED_MARKER_VERSION_UNSUPPORTED")
    target = Path(path)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    content = _merge_block(existing, rendered)
    original_hash = sha256_text(existing) if target.exists() else None
    return AgentsMergeResult(content, content != existing, original_hash, sha256_text(content))


def remove_global_agents(existing: str) -> str:
    bounds = _marker_bounds(existing)
    if bounds is None:
        return existing
    start, end = bounds
    remainder_start = end + len(END_MARKER)
    if existing.startswith(chr(13) + chr(10), remainder_start):
        remainder_start += 2
    elif existing.startswith(chr(10), remainder_start):
        remainder_start += 1
    return existing[:start] + existing[remainder_start:]


def remove_managed_context(existing: str, marker_id: str = "v1") -> str:
    if marker_id != "v1":
        raise ValueError("MANAGED_MARKER_VERSION_UNSUPPORTED")
    return remove_global_agents(existing)


def inspect_global_agents(path: Path) -> dict[str, object]:
    target = Path(path)
    if not target.exists():
        return {"ok": False, "reason_code": "AGENTS_MISSING", "path": str(target), "command_exists": False}
    try:
        content = target.read_text(encoding="utf-8")
        bounds = _marker_bounds(content)
    except (OSError, UnicodeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "AGENTS_READ_FAILED"
        return {"ok": False, "reason_code": reason, "path": str(target), "command_exists": False}
    if bounds is None:
        return {"ok": False, "reason_code": "AGENTS_MARKER_MISSING", "path": str(target), "command_exists": False}
    start, end = bounds
    block = content[start : end + len(END_MARKER)]
    command_match = _COMMAND_PATTERN.search(block)
    python_exe = ""
    if command_match:
        command_text = command_match.group("python").strip().strip(chr(96)).strip()
        try:
            tokens = shlex.split(command_text, posix=os.name != "nt")
        except ValueError:
            tokens = command_text.split()
        python_exe = tokens[0] if tokens else ""
    command_exists = bool(python_exe) and Path(python_exe).is_file()
    return {
        "ok": command_exists,
        "reason_code": "OK" if command_exists else "AGENTS_COMMAND_MISSING",
        "path": str(target),
        "command_exists": command_exists,
        "python_exe": python_exe,
        "marker_pair": True,
        "managed_block_sha256": managed_block_sha256(block),
    }


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def managed_block_sha256(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    return sha256_text(normalized)


def _atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + f".{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8", newline=chr(10))
    try:
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def install_global_agents(path: Path, python_exe: str | Path, backup_timestamp: str) -> tuple[AgentsMergeResult, Path | None]:
    target = Path(path)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    rendered = render_global_agents(python_exe)
    result = merge_managed_context(target, rendered)
    backup = None
    if result.changed:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(f"{target.name}.before-ei-{backup_timestamp}")
            backup.write_bytes(target.read_bytes())
        _atomic_write_text(target, result.content)
    return result, backup


__all__ = [
    "AgentsMergeResult",
    "BEGIN_MARKER",
    "END_MARKER",
    "install_global_agents",
    "inspect_global_agents",
    "managed_block_sha256",
    "merge_global_agents",
    "merge_managed_context",
    "remove_global_agents",
    "remove_managed_context",
    "render_global_agents",
    "render_managed_context",
    "sha256_text",
]
