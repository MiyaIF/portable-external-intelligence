from datetime import datetime, timezone
from pathlib import Path

from ei.capture_contract import CaptureIdentity
from ei.config import RuntimePaths, Settings


NOW = datetime(2026, 9, 18, tzinfo=timezone.utc)


def make_settings(root: Path) -> Settings:
    return Settings(
        paths=RuntimePaths(
            engine_root=root / "engine",
            knowledge_root=root / "knowledge",
            runtime_root=root / "runtime",
        )
    )


def identity(record: str = "a") -> CaptureIdentity:
    return CaptureIdentity(
        "codex-cli",
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        "sha256:" + "3" * 64,
        "sha256:" + "4" * 64,
        "sha256:" + record * 64,
    )
