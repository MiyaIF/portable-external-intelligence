from __future__ import annotations

from .base import BaseHookAdapter


class QwenAdapter(BaseHookAdapter):
    host_id = "qwen-code"
    adapter_id = "qwen-hooks-v1"
    event_names = ("SessionStart", "UserPromptSubmit", "Stop", "SessionEnd")
    windows_command_field = None
