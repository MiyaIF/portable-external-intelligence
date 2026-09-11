from __future__ import annotations

from .base import BaseHookAdapter


class ClaudeAdapter(BaseHookAdapter):
    host_id = "claude-code"
    adapter_id = "claude-hooks-v1"
    event_names = ("SessionStart", "UserPromptSubmit", "Stop", "SessionEnd")
    windows_command_field = None
