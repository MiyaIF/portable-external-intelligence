# Public publication runbook

This runbook publishes only a sanitized fresh-root export. The private
development repository and its history are never pushed to the public target.

## Owner decisions

The current policy values are Apache-2.0, author `MiyaIF`, the approved
GitHub noreply identity, owner `MiyaIF`, repository
`portable-external-intelligence`, GitHub private vulnerability reporting plus
`SECURITY.md`, and Issues/PRs with DCO and no CLA. Change these values only by
an owner-reviewed policy update.

## Local preparation

1. Run the bounded test runner and source/security/dependency audits.
2. Run the clean-clone lifecycle in a destination outside the source,
   knowledge, and runtime roots.
3. Generate the public export from an exact clean source SHA and allowlist.

   ```text
   python -B scripts/create-public-export.py --source <private development clone> --destination <new directory outside all three roots> --policy release/publication-policy.json --allowlist config/public-export-allowlist.json --receipt <sanitized receipt outside the export> --json
   ```

   The command refuses a dirty source, a nonempty or reparse-point
   destination, source/knowledge/runtime containment, and an unexpected
   source SHA. The default run performs public/history, source, workflow,
   dependency, build, bounded-suite, and clean-clone checks. The
   `--skip-validation` option is for structural tests only and produces an
   explicitly `exported_unvalidated` receipt.

   If validation is interrupted after the root commit is created, resume it
   without copying or rewriting the export:

   ```text
   python -B scripts/create-public-export.py --source <same clean source clone> --destination <existing export> --policy release/publication-policy.json --allowlist config/public-export-allowlist.json --receipt <same receipt path> --expected-source-sha <exact source SHA> --resume-validation --json
   ```

   Resume is fail-closed. It reconstructs a deterministic reference export
   from the exact clean source and accepts the existing directory only when
   it is clean, contains one commit, and has the identical root SHA, tree ID,
   tree digest, policy, allowlist, and author identity. A changed or extra
   file, reparse point, second commit, stale receipt, or source mismatch
   requires a new export; resume never repairs or rewrites the directory.
4. Verify the new repository has one sanitized root commit, the approved
   author identity, normalized modes/line endings, no private paths, no raw
   data, and no old private history. Re-run the export with the same source
   SHA, policy, allowlist, and tool version and compare the recorded tree IDs.
5. Generate evidence for the new public subject SHA only. The export receipt
   is an export certificate; it does not substitute for hosted CI, real-host,
   activation, rollback, or A/B evidence.

## Read-only GitHub plan

The publication planner resolves the owner/repository from policy and prints
the root SHA, requested public settings, security features, ruleset, required
hosted checks, and plan digest. It must not create a repository or push:

```text
python -B scripts/configure-public-github.py plan --source <public export> --policy release/publication-policy.json --output <publication plan>
```

Review the exact digest before any external mutation. Public creation, push,
security configuration, branch rules, and release tags require explicit owner
approval. Never use a force push or self-hosted runner.

The planner exits nonzero when the target is already present or cannot be
proven absent. `--offline` is a fail-closed no-network mode for local
structural checks; it records `target_observation.status=unknown` and cannot
be used as publication approval. After reviewing the plan, create an
independent approval artifact in a different file. Its digest covers the
artifact fields other than `approval_sha256`:

```json
{
  "approval_type": "github_publication_approval",
  "schema_version": 1,
  "plan_sha256": "sha256:<reviewed-plan-digest>",
  "approved_at": "2026-08-28T00:00:00Z",
  "approval_sha256": "sha256:<canonical-approval-digest>"
}
```

Apply requires that artifact and the same policy/source pair. It never derives
approval from the plan file itself:

```text
python -B scripts/configure-public-github.py apply --source <public export> --policy release/publication-policy.json --plan <publication plan> --approval <independent approval artifact> --output <publication receipt>
```

The apply command is the only path that creates/configures the repository or
pushes. Its sanitized receipt contains hashes, URLs, feature states, and
status; it does not contain tokens, local paths, private history, or raw
evidence.

## Post-public verification

After an approved publication, fetch into a second clean directory and compare
tree ID and public root SHA with the export receipt. Run the reachable-history
audit, dependency and secret scanners, build/package checks, README quick
start, and hosted CI verification. Record only sanitized URLs, hashes, run
IDs, feature states, and status fields. Do not copy the private development
repository's `.git` directory or its release receipts into the public target.

If a check fails, stop the announcement and follow `SECURITY.md`. Do not
casually rewrite public history. A repository-private rollback or credential
rotation requires a separate explicit decision.

To verify an approved publication, use a new empty directory and the receipt:

```text
python -B scripts/configure-public-github.py verify --policy release/publication-policy.json --receipt <publication receipt> --fresh-clone <new directory> --output <verified receipt>
```

## Status interpretation

`SETUP_COMPLETE`, `HOST_ACTIVATION_VERIFIED`, `PUBLIC_SOURCE_READY`,
`PUBLIC_RELEASE_READY`, `PRODUCTION_COMPLETE`, and `EFFECT_VALIDATED` are
independent. Before an exact public subject exists,
evidence is `awaiting_public_subject`. Missing real CLI receipts or A/B samples
remain `awaiting_real_host_receipts` or `awaiting_sample`.
