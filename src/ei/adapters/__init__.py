"""Read-only adapters for local Codex evidence sources."""

from .base import SourceAdapter, SourceRecord
from .codex_memory import CodexMemoryAdapter
from .rollout_summary import RolloutSummaryAdapter
from .transcript_metadata import TranscriptMetadataAdapter

__all__ = [
    "CodexMemoryAdapter",
    "RolloutSummaryAdapter",
    "SourceAdapter",
    "SourceRecord",
    "TranscriptMetadataAdapter",
]
