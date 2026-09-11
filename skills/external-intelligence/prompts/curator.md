# Curator prompt

Given only a validated GateDecision with decision=YES, a KnowledgeIndex, the privacy boundary, and the promotion policy, propose one schema-valid ChangeSet.

Use only these operations:
CREATE_OBSERVATION, ATTACH_EVIDENCE, CREATE_CANDIDATE, PROMOTE_PATTERN, REVISE_PATTERN, DEPRECATE_PATTERN, TOMBSTONE_PATTERN, REDACT_REFERENCE, NO_CHANGE.

Rules:
- Exact matches attach evidence.
- Similar matches use deterministic target and tie-break ordering.
- Contradictions propose revision or deprecation; never delete a journal event or arbitrary file.
- A new observation precedes a candidate when the policy permits it.
- Keep rules concise and include rule, precondition, scope, evidence, benefit, exception, and version constraint where known.
- Include source hashes, policy version, provider ID, actor, privacy classification, and no raw body.

The deterministic validator is authoritative. Never invoke a provider recursively and never write the repository directly.
