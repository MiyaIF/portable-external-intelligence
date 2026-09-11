# Production rollout

This runbook separates local software readiness, public release readiness,
real-host production activation, and A/B effect validation. External actions
such as global setup, scheduler registration, migration apply, provider spend,
remote changes, and public push require explicit owner approval.

## Stage 0: isolated preflight

Use a temporary clone, private knowledge root, runtime root, and four isolated
CLI home directories. Use spaces and non-ASCII characters in at least one path.

1. Run setup `--check-only` and inspect every target.
2. Apply one-shot setup in `local` mode in the isolated homes with
   synchronization and scheduler disabled; verify knowledge readiness and
   `SETUP_COMPLETE` in the same result.
3. Run strict doctor, fixture canaries, recall, closeout, maintenance, update,
   uninstall, restore, and rollback checks.
4. Confirm the temporary homes can be recreated from the clone without manual
   edits.

## Stage 1: real CLI activation

For each selected CLI, complete its own official trust/consent flow and record
the actual executable/version, host instance, required event hashes, Skill
discovery, and OS profile. A file-copy or fixture result is not sufficient.
Gemini consent is independent of Hook verification. Codex App is not in the
public target matrix.

Keep automatic promotion disabled until evidence provenance, privacy
classification, and cross-project independence have been reviewed.

The public production matrix is the declared Cartesian set of the four CLI
hosts and five OS profiles (20 host/OS pairs). Every pair must have a real,
hash-bound receipt before `PRODUCTION_COMPLETE`; hosted CI does not substitute
for a real host.

## Stage 2: lifecycle promotion

Enable automatic promotion only when the event journal and projection have a
known-good backup, each promoted rule has independent evidence, contradictions
are retained as events, and strict doctor is healthy. Monitor candidates,
promotions, revisions, deprecations, tombstones, capture deferrals, provider
deferrals, and projection failures.

The inheritance gate may answer NO without storing the candidate body. If
aggregate NO history is enabled, only the fixed reason class and sanitized
metadata are retained. YES passes through the curator and deterministic
ChangeSet validator.

## Stage 3: private sync and scheduling

1. Confirm the knowledge remote is private or local-only and approve its
   fingerprint.
2. Run a dry sync plan with no unrelated worktree changes.
3. Register the optional scheduler only after its direct argv passes check-only.
4. Verify one bounded maintenance run and its sanitized receipt.
5. Exercise a disposable two-machine clone and a semantic conflict.

No public engine remote may receive private knowledge. Offline, quota-limited,
or conflict states are retryable/blocked and are never silently overwritten.

## Stage 4: A/B measurement

Use the preregistered protocol in `docs/experiment-protocol.md`. Keep control
and treatment eligibility, provenance, missingness handling, and contamination
rules fixed. Displayed token/cache numbers and copied article metrics are
descriptive only. `EFFECT_VALIDATED` remains false until duration, per-arm
sample, power, linkage, provenance, missingness, and contamination gates pass.

Generate the path-free effect record from the analyzed summary and validate
its analysis digest. A hand-entered boolean or a copied token/cache number is
not effect evidence.

## Independent release states

```text
SETUP_COMPLETE       knowledge + managed machine installation
HOST_ACTIVATION_VERIFIED official CLI Hook + Skill evidence
PUBLIC_SOURCE_READY  sanitized source/history audit
PUBLIC_RELEASE_READY exact public SHA + hosted/package/scanner evidence
PRODUCTION_COMPLETE   real CLI lifecycle + recovery/sync/scheduler evidence
EFFECT_VALIDATED      preregistered A/B gates passed
```

The canonical JSON evidence is generated from receipts. A missing external
receipt is reported as `awaiting_real_host_receipts` or `awaiting_sample`; it
does not become a false pass.

The final evaluator also requires the sanitized export receipt, publication
receipt, hosted CI/package/SBOM/secret/dependency/workflow/
security-remediation/clean-clone receipts, and the dynamically enumerated
security remediation record to be bound to the same public subject SHA and CI
artifact digest. Use `scripts/verify-release-evidence.py
--completion-only` to emit the independent gate JSON.

## Rollback

Disable promotion and scheduling, preserve audit/diagnostic files, and either
append a deprecation/tombstone or rebuild the projection from the last trusted
event state. Restore a managed CLI file only after validating the ownership
bound backup. Re-run doctor and lifecycle checks. Never rewrite or delete the
append-only journal to conceal an incident.
