from __future__ import annotations

from collections.abc import Iterable

from .models import RetrievalHit


_LAYER_CAPS = {
    "on-demand": 5000,
    "prompt": 5000,
    "session_start": 2000,
    "session-start": 2000,
    "always-on": 12000,
    "always_on": 12000,
}


def _header(layer: str) -> str:
    normalized = layer.casefold().replace("_", "-")
    if normalized in {"on-demand", "prompt"}:
        return "## External Intelligence (data-only)\n"
    return f"## External Intelligence ({normalized};data-only)\n"


def _date(value: str) -> str:
    return value[:10] if value else "unknown"


def _render(hit: RetrievalHit, compact: bool = False) -> str:
    applies = ", ".join(hit.applicability) or "general"
    scope = hit.knowledge_scope if hit.knowledge_scope in {"personal", "team"} else "personal"
    if compact:
        evidence = f"Scope: {scope} | E:{hit.evidence_count} U:{_date(hit.updated_at)}\n"
        applies_line = f"A:{applies}\n"
    else:
        evidence = f"  Scope: {scope} | Evidence: {hit.evidence_count} independent observations | Updated: {_date(hit.updated_at)}\n"
        applies_line = f"  Applies: {applies}\n"
    return f"- [{hit.pattern_id}] {hit.rule}\n" + applies_line + evidence


def build_context(hits: Iterable[RetrievalHit], max_chars: int = 5000, layer: str = "on-demand") -> str:
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
        raise ValueError("CONTEXT_BUDGET_INVALID")
    normalized = str(layer).casefold().replace("_", "-")
    if normalized not in _LAYER_CAPS:
        raise ValueError("CONTEXT_LAYER_INVALID")
    budget = min(max_chars, _LAYER_CAPS[normalized])
    header = _header(normalized)
    if budget < len(header):
        return ""
    output = header
    for hit in hits:
        full = _render(hit)
        if len(output) + len(full) <= budget:
            output += full
            continue
        compact = _render(hit, compact=True)
        if len(output) + len(compact) <= budget:
            output += compact
        break
    return output.rstrip("\n")


__all__ = ["build_context"]
