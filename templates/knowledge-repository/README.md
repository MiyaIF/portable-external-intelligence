# Private knowledge repository

This repository stores sanitized external-intelligence events and rebuildable
knowledge projections. It is separate from the public engine source and from
machine-local runtime state.

Keep credentials, raw prompts or responses, raw tool output, client data,
SQLite databases, and absolute personal paths out of this repository. Events
are append-only; corrections and deletions are represented by validated
tombstone or redaction events and a projection rebuild.

Synchronization starts disabled. Enable it only after the engine has verified
the remote visibility and the resulting sync plan.
