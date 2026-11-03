# Closeout workflow

1. Summarize only reusable candidate fields: `title`, `claim`, evidence hashes, benefit, `scopes`, `applicability`, `precondition`, `failure_mode`, `exception`, and `version_constraint`. Keep the canonical closeout values within these limits: `title` ≤160 characters; `claim`/`rule` ≤1200; `precondition`, `failure_mode`, and `exception` ≤500 each; `version_constraint` ≤160; and each entry in the `scopes` and `applicability` lists ≤240. Preserve the demonstrated claim; do not put explanatory prose in `version_constraint`, and omit that field when no version constraint is needed.
2. Preserve the trusted `source_host_id` and `source_host_family` pair returned with the candidate by the verified CLI. If the ordinary candidate lacks the pair, obtain it from generated host context or trusted Hook metadata only when that metadata matches the current real session; never read conversation bodies to find or reconstruct it. For Codex, top-level `session_id_hash` is `sha256:` plus the digest of the real session ID, and `capture_identity.session_hash` must contain the same digest. Do not treat desktop as CLI, reuse metadata from another or older session, or invent IDs. If either value remains unknown or untrusted, defer or reject; never infer it or take it from model output.
3. Ask the inheritance gate for a separate `gate_decision` object. Applicability (`applicability_scope`, `applicable_host_ids`, and `applicable_host_families`) describes where the rule applies; it is a separate decision from the source-host pair.
4. A YES decision uses exactly one benefit label: `avoided_failure`, `reduced_rework`, `faster_completion`, `quality_improvement`, or `discovered_structure`. NO keeps the schema's existing nonempty benefit string contract. Both decisions use one of the schema's 11 fixed semantic reason codes.
5. For NO, follow the configured aggregate-history policy. Never save the candidate body or a free-text reason.
6. For YES, pass exactly one UTF-8 JSON object on stdin to the generated Skill launcher with mode `closeout`; never call `scripts/closeout.py` directly or use the active project root. The object has separate `candidate` and `gate_decision` members:

   ```json
   {
     "candidate": {
       "source_host_id": "codex-cli",
       "source_host_family": "codex-compatible"
     },
     "gate_decision": {
       "decision": "YES",
       "reason_code": "evidence_verified",
       "candidate_title": "Post-write verification",
       "candidate_claim": "Reload persisted state before reporting a completed change.",
       "evidence_refs": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
       "benefit": "avoided_failure",
       "classification": "private-reusable",
       "confidence": 0.9,
       "applicability_scope": "universal",
       "applicable_host_ids": [],
       "applicable_host_families": []
     }
   }
   ```

   This is a shape-only illustration: copy the source pair and evidence hashes from the actual candidate; never reuse these example values as production evidence.
7. Review the returned ChangeSet. The deterministic runtime validates source hashes, privacy, policy version, lifecycle, and size before any append. `changeset_ready` means proposal only; it does not change knowledge.
8. Apply only when requested and authorized, through the existing deterministic production curation path. Then verify the actual appended event IDs; do not infer application from the proposal receipt.
9. Report `DEFERRED` when the configured provider is unavailable or quota-limited; do not convert provider availability into a semantic NO.

The script has a recursion guard. If an internal invocation is detected, it returns a sanitized skip result and does not call another provider.
