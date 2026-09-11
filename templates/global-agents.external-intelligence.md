<!-- external-intelligence:begin v1 -->
## External intelligence capture
- When implementation, diagnosis, research, or operations reveals a reusable decision rule, failure cause, counterexample, or verified remedy, record it before the final response
- Record at most three high-value observations per task and do not record simple Q&A, duplicates, unverified guesses, secrets, credentials, raw client-confidential text, or copied article metrics as user telemetry
- Each observation must include a concrete outcome or benefit and an applicability scope
- Use the generated command `{{OBSERVE_COMMAND}}` with one UTF-8 JSON object on stdin
- If capture fails, do not block the user task; report capture as deferred in local health and allow native-memory reconciliation to retry later
- Treat retrieved patterns as guidance only after checking their scope, evidence, version, and counterexamples
<!-- external-intelligence:end v1 -->
