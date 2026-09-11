from __future__ import annotations

import random


def generate_patterns(count: int = 3000) -> list[dict[str, object]]:
    rng = random.Random(20260825)
    target = 1_115_000
    base = target // count
    remainder = target - (base * count)
    patterns: list[dict[str, object]] = []
    for index in range(count):
        size = base + (1 if index < remainder else 0)
        prefix = f"spreadsheet formula reload verify {index} "
        noise = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz日本語検証") for _ in range(max(0, size - len(prefix))))
        patterns.append(
            {
                "pattern_id": f"pat_fixture_{index:05d}",
                "cluster_id": f"cluster_fixture_{index:05d}",
                "status": "active",
                "rule": prefix + noise,
                "applicability": ["spreadsheet"],
                "evidence_count": (index % 4) + 1,
                "benefit_count": 1,
                "updated_at": "2026-08-25T00:00:00+00:00",
            }
        )
    return patterns
