from __future__ import annotations

import sys
from typing import Any


def write_utf8(value: Any, *, end: str = "\n", stream: Any | None = None) -> None:
    """Write Unicode deterministically to a console, pipe, or redirected text stream."""

    target = sys.stdout if stream is None else stream
    text = str(value) + end
    raw = getattr(target, "buffer", None)
    if raw is not None:
        raw.write(text.encode("utf-8"))
        raw.flush()
        return
    target.write(text)
    target.flush()


__all__ = ["write_utf8"]
