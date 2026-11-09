# Codex work-record candidate capture implementation plan

## Goal and authority

Implement the approved fallback from ordinary Codex CLI work records to existing candidate validation, durable storage, and project-scoped recall when the working AI omits the save Skill. Binding requirements: `docs/specs/2026-09-18-reliable-automatic-accumulation-design.md`, section 13, and the user's approved five-step plan in this conversation.

## Global constraints

- Codex CLI only for this change; do not relabel desktop as CLI or invent source/session identity.
- Reuse the one configured organizer. No new provider/account, database, index, daemon, or global setup setting.
- Keep the existing 30-minute schedule, 5-minute application budget, and 10-minute OS cap. No execution-policy change or visible console fallback.
- Read only authorized source roots with a verified host/session/project binding. Respect verified save consent and explicit no-save instructions.
- Treat source content as data, not instructions. Secrets and disallowed confidential content must not reach the organizer; do not copy raw work records into knowledge, logs, or a new persistent store.
- Reuse existing privacy checks, project scope, deduplication, queue/spool durability, event append-only semantics, promotion rules, and retrieval.
- Process bounded new input, not whole history on every run. Do not advance an acknowledged cursor before durable handoff, or treat failed inference/missing sources as successful zero-candidate extraction.
- Preserve backoff and failure reporting; reserve time for durable handoff and existing queue work. Resume after partial completion without repeated completed extraction or duplicate events.
- Existing personal knowledge and canonical user document drafts are untouched.
- Initial implementation used focused tests only. The later completion request authorizes the agent to run the complete suite, commit and push the sanitized public change, update the installed engine while preserving knowledge, and verify ordinary Codex CLI work through automatic save and next-session recall. No feature expansion is authorized.

## Task 1: Fallback capture through the existing maintenance pipeline

Ownership: implementer owns new `src/ei/work_record_capture.py`, `src/ei/maintainer.py`, new `tests/unit/test_work_record_capture.py`, and new `tests/integration/test_work_record_capture.py`. Existing helper/schema files may be proposed to the controller before changing them; avoid duplicate safety or persistence frameworks. Controller owns this plan and the private progress ledger.

Approved after API inspection: also modify `src/ei/capture_recovery.py` for a narrowly scoped bounded append-tail/cursor integration with existing safe filesystem and recovery state, and add `schemas/work-record-extraction.schema.json` for typed organizer extraction results. Preserve existing structured-source recovery behavior. Source containment alone is not consent or verified CLI/session/project binding.

Approved after transport inspection: narrowly extend `src/ei/inference/cli_subscription.py` so the new extraction schema receives trusted extraction instructions rather than the existing inheritance-gate-only instruction. Preserve existing gate behavior. Use a simple strict object output schema compatible with the existing Codex transport pattern, with result-dependent validation in the engine.

Approved for review fix round 2: also modify `src/ei/pending_capture.py` only for exact pending-intent recovery using its existing lock, validation, and durable queue/receipt completion. Before handoff, retain a capture ID and candidate-content hash in the existing capture-recovery cursor without advancing ACK; resume that exact intent before any new extraction, and defer on unverified state. This is a hash-only recovery reference, not a new database or knowledge index.

Round 2 test ownership also includes `tests/unit/test_maintainer.py` for the zero-budget phase-boundary and post-extraction recovery-deadline regressions only.

Final verification also owns `tests/integration/test_scheduled_task_scripts.py` for the stale maintenance-command assertion: include the existing `-X utf8` prefix without changing production behavior. The exact commit scope is this plan, the extraction schema, the five production modules named above, and the four named test modules. Private review artifacts and unrelated documents are excluded.

1. Read the relevant existing source-recovery, Hook capture, organizer routing, spool/queue, consent, and project-scope boundaries. Record the concrete integration interface and any necessary additional file in the report before editing it.
2. Write and run a failing focused test using synthetic ordinary Codex JSONL (real nested session_meta, turn_context, user/assistant message and turn-completion shapes), with no structured memory fields or save-Skill call.
3. Implement a bounded reader and organizer extraction path connected to ordinary `maintain`, not merely a standalone helper. Bind host, session, project, evidence references, and consent from verified engine context rather than AI output.
4. Feed validated candidates to existing durable capture/queue handling. Existing downstream save and project recall must work without weakening promotion or privacy rules. Valid zero-candidate output, deferred/failed extraction, and durable handoff remain distinct.
5. Extend focused tests for unchanged input, appended completed work, partial/malformed tails, oversized input, changed source identity, unauthorized roots/host/session/project, save refusal, secret input, malicious instructions, invalid organizer output, provider unavailability/backoff, interrupted durable handoff, and duplicate prevention. Reuse real safety/persistence components; fake only external inference and controlled clocks where necessary.
6. Run targeted neighboring tests, self-review, and report RED/GREEN commands, concise results, exact changed paths, and remaining gaps. Do not run the full suite or claim real-CLI acceptance.

## Task 2: Review, focused verification, and user handoff

1. Review the exact diff for spec compliance, provenance/consent/privacy, cursor durability and repeat cost, and integration with the same maintenance deadline.
2. Resolve concrete findings with targeted regression tests, without expanding to other CLI hosts or notification redesign.
3. Provide the tested worktree path, exact source fingerprint and complete-suite command for the user; preserve failed-test details without dumping all logs into the chat.
4. Separate implemented/target-tested status from remaining user full-suite and real-CLI work -> saved event -> next-session recall verification. No production-complete claim before those gates.

## Completion evidence

- Synthetic ordinary work without a Skill call reaches a durable candidate and the existing save/recall route.
- A repeat produces no duplicate save and no new extraction for unchanged completed work.
- Failure or interruption leaves honest resumable state; denied input makes no external inference call.
- Focused regression tests and independent diff review pass; full-suite and real-provider validation are explicitly handed off, not represented as passed.
