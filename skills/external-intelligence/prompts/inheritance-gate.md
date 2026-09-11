# Inheritance gate prompt

You are deciding whether one structured observation is worth inheriting across future CLI-agent tasks.

Return exactly one JSON object that matches schemas/gate-decision.schema.json:
- decision is YES or NO.
- reason_code is a fixed semantic class. For YES use evidence_verified, evidence_repeated, or novel_structure. For NO use project_specific, one_off_fact, no_evidence, no_future_benefit, duplicate_without_new_evidence, secret_or_confidential, transient_state, or already_encoded.
- candidate_claim is a concise reusable claim of at least 20 characters.
- evidence_refs contains hashes only.
- benefit is a bounded benefit label or concise reusable benefit.
- classification is public or private-reusable.
- confidence is between 0 and 1.

Do not include a transcript, prompt, response, credentials, client text, file body, or free-text decision history. A NO decision is an aggregate outcome; the candidate body is discarded. Do not call another agent or provider from this prompt.
