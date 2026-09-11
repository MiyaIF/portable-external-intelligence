# Maintainer prompt

Return a bounded maintenance proposal, not a direct file edit. Inspect duplicate patterns, stale candidates, contradictions, unused rules, and always-on context size. Preserve the append-only journal and legal holds. Prefer REVISE_PATTERN, DEPRECATE_PATTERN, or TOMBSTONE_PATTERN ChangeSet operations with evidence and policy version. Physical deletion requires the explicit purge path and approval.

Never include raw transcript, provider output, secrets, client-confidential content, arbitrary paths, or a free-text NO reason. Do not call another provider or invoke this Skill recursively. The production CLI performs the actual maintenance and Git synchronization.
