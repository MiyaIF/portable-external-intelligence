from __future__ import annotations

from .base import BaseHookAdapter


class CodexAdapter(BaseHookAdapter):
    host_id = "codex-cli"
    adapter_id = "codex-hooks-v1"
    event_names = ("SessionStart", "UserPromptSubmit", "Stop", "SessionEnd")
    windows_command_field = "commandWindows"


class CodexAppAdapter(CodexAdapter):
    host_id = "codex-app"
    adapter_id = "codex-app-hooks-v1"
