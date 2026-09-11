# Production Completion Contract

This checklist is the release gate for the complete Task 1–19 delivery.
`SETUP_COMPLETE`, `HOST_ACTIVATION_VERIFIED`, `software_complete`,
`production_enabled`, and `effect_validated` are independent states. One state
must not be inferred from another.

## Software completion

All items below must have reproducible evidence in the branch and CI:

- [ ] Tasks 1–19 are implemented in production source
- [ ] Full unittest and integration suite passes on the supported Python versions
- [ ] Performance contract passes with the configured p95 retrieval limit
- [ ] Source audit finds no production `pass`, stub, `NotImplementedError`, fixed test-only route, or unhandled placeholder
- [ ] Input validation, exit codes, sanitized logs, idempotency, locking, backup, rollback, and concurrency behavior are tested
- [ ] Capture, ingest, deduplication, clustering, contradiction detection, promotion, revision, deprecation, tombstone, and retrieval are tested
- [ ] Hooks, installer, uninstaller, doctor, scheduler, migration, Git synchronization, metrics, and A/B paths are tested
- [ ] Existing evidence inventory balances every discovered source into imported, referenced, skipped-with-reason, or rejected
- [ ] Privacy and secret scans pass, including the unrelated external workspace boundary
- [ ] Fresh-machine restoration and rollback procedures pass in an isolated temporary environment
- [ ] CI is green for Python 3.11 and 3.13 on Windows

The software state is `software_complete=true` only after every box is checked and CI evidence is retained. Local tests alone do not satisfy the CI item.

## Production activation

These actions change the user’s real Codex environment and require explicit approval at execution time:

- [ ] Confirm the intended private Git remote and write permission
- [ ] Run one-shot setup CheckOnly against the real engine, knowledge mode/root, runtime root, and selected CLI homes
- [ ] Verify the same approved apply creates/restores the knowledge repository and reports `SETUP_COMPLETE`
- [ ] Approve backup creation and install the managed hooks
- [ ] Confirm hook trust hashes and run strict doctor
- [ ] Register the exact scheduled task with limited privileges and verify the live action
- [ ] Run inventory and migration dry-run; review all source dispositions
- [ ] Apply migration only after all historical and unknown sources have an explicit disposition
- [ ] Execute retrieval from a new session and verify the selected context audit record
- [ ] Run maintenance successfully and verify projection, lifecycle, metrics, and sync status
- [ ] Enable automatic promotion only after the promotion policy and rollback path are reviewed
- [ ] Push the synchronized repository only after the target remote and commit are confirmed

Until all applicable items are evidenced, `production_enabled=false`. A successful CheckOnly run is not a production install.

## Effect validation

The A/B contract requires:

- [ ] A preregistered experiment ID, protocol hash, eligibility rule, primary metric, arm assignment, missing-data policy, and stopping rule
- [ ] At least 50 eligible units in each arm
- [ ] At least 14 days of exposure and outcome capture
- [ ] Exposure-to-outcome linkage for the primary metric with explicit missingness
- [ ] Power of at least 0.80 under the preregistered effect and variance assumptions
- [ ] Metric provenance bound to local evidence or an authoritative external source
- [ ] No contamination, assignment drift, or post-treatment eligibility change that invalidates the analysis
- [ ] An analysis report that distinguishes descriptive cache/reuse observations from causal outcomes

Until all items pass, `effect_validated=awaiting_sample` and the report must state `CAUSAL_EFFECT_NOT_IDENTIFIED` when a causal conclusion is requested.

## Current handoff state

At repository handoff, the expected status is:

```text
software_complete: pending final CI and release evidence
production_enabled: false until explicit real-environment approval and preflight
effect_validated: awaiting_sample until the longitudinal preregistered experiment passes
external_state_changes: none
```

The implementation may be fully present while one or more activation or effect gates remain false. Do not replace these states with a single “complete” label.
## Candidate evidence recorded for this repository

The release candidate subject SHA is generated from the reviewed sanitized
source/export at release time. The subject manifest must contain that exact
SHA and no `evidence_commit_sha`; a later evidence commit is recorded only by
post-push CI attestation.

Current evidence status:

| Gate | Candidate state | Required next evidence |
|---|---|---|
| Software | `NOT_COMPLETE` / local contracts and audits only | full required CI for the exact evidence SHA and sanitized attestation |
| Real host/OS | missing | separate real receipts for the four public CLI host IDs and required OS profiles |
| Production | `false` | approved setup, Hook/Skill discovery, recall, closeout, migration, sync, doctor, rollback |
| Effect | `awaiting_sample` | preregistered 14-day, 50-per-arm, power/provenance/missingness/contamination result |
| External state | unchanged | explicit approval before global setup, trust/consent, migration apply, push, or tag |

Release operators must preserve the subject/evidence SHA separation. `release/completion-report.md` is a candidate report, not a final completion claim. `PRODUCTION_COMPLETE` is forbidden while any row above is unmet.
# Public release checklist

The public candidate must pass the publication policy, current-tree audit, and (when preparing a fresh export) the reachable-history audit. Run the checks against the exact candidate SHA and keep scanner receipts sanitized.

```powershell
python -B scripts/audit-public-release.py --repo . --policy release/publication-policy.json --working-tree --json
python -B scripts/audit-public-release.py --repo . --policy release/publication-policy.json --reachable-history --require-scanner-receipts --json
```

The audit reports check IDs and safe evidence paths only. It never prints matched secret values, raw prompts, transcript content, or private credentials. A failed check blocks the corresponding publication gate.

## Final evidence evaluator

After the sanitized export exists, generate evidence only for its public root
SHA and pass the resulting path-free receipts to:

```powershell
python -B scripts/verify-release-evidence.py --manifest release/evidence-manifest.json --completion-only --export-receipt <export receipt> --publication-receipt <publication receipt> --release-receipts <release receipts> --security-evidence <security remediation> --production-evidence <production evidence> --effect-evidence <A/B evidence> --completion-output <completion JSON>
```

The evaluator reports the four states independently. It requires all eight
release receipts, the complete dynamic finding set from the sealed security
scan with every finding fixed, all 20 real CLI/OS receipts, all lifecycle
receipts, and the preregistered A/B gates before asserting the corresponding
upper state. A/B effect evidence is a sidecar bound to the immutable evidence
index digest; it is never embedded while that digest is constructed. Do not
hand-edit `release/evidence-manifest.json`.
