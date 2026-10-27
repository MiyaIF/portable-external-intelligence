# Inheritance gate prompt

You are deciding whether one structured observation is worth inheriting across future CLI-agent tasks. DATA_JSON contains candidate context, including the trusted `source_host_id` and `source_host_family` pair supplied by the verified CLI.

Return only the `gate_decision` object, matching `schemas/gate-decision.schema.json`; do not wrap it in a `candidate` envelope or emit source-host metadata. Source identity is not inferred from the claim and must not be copied from model output. If the trusted pair is absent or unknown, defer or reject rather than guessing.

- decision is YES or NO.
- reason_code is exactly one of: evidence_verified, evidence_repeated, novel_structure, project_specific, one_off_fact, no_evidence, no_future_benefit, duplicate_without_new_evidence, secret_or_confidential, transient_state, already_encoded.
- candidate_claim is a concise reusable claim of at least 20 characters.
- evidence_refs contains hashes only.
- For YES, benefit is exactly one of: avoided_failure, reduced_rework, faster_completion, quality_improvement, discovered_structure. For NO, retain the schema's existing nonempty string contract.
- For YES, choose applicability_scope, applicable_host_ids, and applicable_host_families independently from the source-host identity; follow the schema's scope/list constraints.
- classification is public or private-reusable.
- confidence is between 0 and 1.

Do not include a transcript, prompt, response, credentials, client text, file body, or free-text decision history. A NO decision is an aggregate outcome; the candidate body is discarded. Do not call another agent or provider from this prompt.
