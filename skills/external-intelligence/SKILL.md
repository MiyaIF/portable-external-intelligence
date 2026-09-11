---
name: external-intelligence
description: One portable CLI-agent Skill for bounded recall, inheritance closeout, curation, maintenance, sync, repair, and status. It never stores raw transcripts or secrets.
---

# External Intelligence

This is the single user-visible Skill for the external-intelligence repository. Do not create sibling Skills for gate, curator, recall, or maintainer. Route the requested mode to the matching workflow:

- recall: retrieve only eligible knowledge needed for the current task.
- closeout: validate one structured closeout object, run the YES/NO inheritance boundary, and return a ChangeSet proposal.
- maintain: delegate ingestion, reconciliation, projection, and health maintenance to the production CLI.
- sync: delegate allowlisted conflict-safe Git synchronization to the production CLI.
- repair: run doctor-guided diagnostics and return a repair plan; never overwrite trusted state automatically.
- status: return bounded Hook, Skill, queue, spool, provider, sync, and experiment state.

The source Skill directory is Git-tracked. Setup copies it to the selected CLI agent's Skill directory and records the installed tree hash. A copied Skill is not a new source of truth. The repository event journal is authoritative; knowledge projections are rebuildable.

## Safety and data boundary

The Skill may receive a structured candidate or query, but it must not persist raw prompts, transcripts, tool output, credentials, cookies, tokens, or client-confidential text. NO decisions carry only aggregate reason classes. A YES decision must contain evidence hashes, a reusable claim, benefit, and public or private-reusable classification. The deterministic runtime validates and applies ChangeSets; an AI provider may suggest JSON but may not write files directly or request arbitrary paths.

Setup writes a machine-local binding beside the installed Skill. That binding, together with the active install manifest, is authoritative for the engine, private knowledge, runtime, and Python executable. Invoke only the generated Skill launcher command written into the managed global context, then append one allowed mode and its bounded arguments. The launcher starts the first Python process with isolated, no-bytecode options before any Skill import, validates the binding, clears caller Python environment overrides, and dispatches the selected workflow. Direct `scripts/*.py` execution is unsupported and rejected. Never pass the active project as an engine or runtime root. Runtime state belongs outside the repository. The source repository remains the place to review, back up, update, and restore the Skill and knowledge projections.

## Provider and host boundary

Local LLMs are preferred when configured. Subscription/free-tier providers are deferred when their quota or rate limit is reached. Paid cloud providers remain disabled unless the configured budget permits them. The Skill never treats quota exhaustion as a semantic NO.

The public host boundary is CLI-only: Codex CLI, Claude Code, Gemini CLI, and Qwen Code. Gemini Skill activation is a consented enrichment step and is not required for primary capture. A valid Gemini hook receipt may coexist with CONSENT_REQUIRED. Codex App is not a supported public host; if a legacy selection names it, the installer must migrate it to Codex CLI or classify it unsupported and write the explicit runtime migration receipt. Never count the desktop application as a supported or certified host.

## Output contract

Return one bounded JSON object for script calls. Do not echo input transcripts or provider responses. Use the production CLI for maintenance, synchronization, and doctor-guided repair. A successful ChangeSet is only a proposed/applied journal transition; it is not evidence that causal A/B effect has been proven. If a workflow cannot run because a provider quota, consent, remote, or scheduler is unavailable, return the explicit deferred/blocked state and preserve the retry path.
