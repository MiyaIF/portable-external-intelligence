from __future__ import annotations

import sqlite3
from pathlib import Path


def create_known_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE turn_usage (id TEXT PRIMARY KEY, input_tokens INTEGER NOT NULL, cached_input_tokens INTEGER NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO turn_usage VALUES (?, ?, ?, ?)",
            [
                ("turn-1", 100, 80, "2026-08-25T00:00:00Z"),
                ("turn-2", 250, 200, "2026-08-25T00:01:00Z"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def create_unknown_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE unknown_usage (key TEXT, amount INTEGER)")
        connection.execute("INSERT INTO unknown_usage VALUES ('x', 1)")
        connection.commit()
    finally:
        connection.close()
