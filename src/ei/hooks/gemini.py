from __future__ import annotations

from .base import BaseHookAdapter, HookResult


class GeminiAdapter(BaseHookAdapter):
    host_id = "gemini-cli"
    adapter_id = "gemini-hooks-v1"
    event_names = ("SessionStart", "BeforeAgent", "AfterAgent", "SessionEnd")
    windows_command_field = None

    def encode(self, result: HookResult):
        output = {"continue": bool(result.continue_work)}
        if result.additional_context:
            output["hookSpecificOutput"] = {
                "hookEventName": result.host_event_name or "BeforeAgent",
                "additionalContext": result.additional_context,
            }
        return output
