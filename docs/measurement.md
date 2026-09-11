# Measurement boundaries

- Local Codex SQLite is opened with `mode=ro` and is never migrated or written
- A schema is accepted only when the exact known `turn_usage(id, input_tokens, cached_input_tokens, created_at)` columns are present
- Duplicate local turn IDs are counted once
- `external_article_copy` and `external_reference` are retained in a separate total and never enter `user_environment`
- The article figures copied from another source are not user telemetry, quota evidence, or causal evidence
- Unknown schemas, missing linkage, and unavailable metrics remain explicitly unavailable
- Raw local usage snapshots stay under the machine-local runtime directory; only approved aggregate reports may be synchronized
## Release measurement and causal boundary

For user-environment usage evidence, read the configured local Codex SQLite source in read-only mode, accept only the known schema, deduplicate turn IDs, and store only approved aggregates in the machine-local runtime. The copied article values (`4,835万`, `98.7%`, `+1%`, and the character counts) are external references, not this installation's baseline or effect evidence.

The A/B path is preregistered in `docs/experiment-protocol.md`: deterministic assignment, treatment-only scoped recall, the same eligibility rule, authoritative exposure/outcome linkage, explicit missingness, no contamination, at least 50 eligible units per arm, at least 14 calendar days, power at least 0.80, alpha at most 0.05, and a causal report. A provider defer, missing receipt, unavailable schema, or contaminated linkage stays visible and does not become zero or success.

Descriptive cache/reuse, retrieval count, retry count, time, quality, and quota observations are reported separately. A high cache ratio may have several causes; it does not prove that the external-intelligence layer caused the ratio or reduced quota use. Until every preregistered condition passes, the release state is `effect_validated=awaiting_sample` and any causal request returns `CAUSAL_EFFECT_NOT_IDENTIFIED`.