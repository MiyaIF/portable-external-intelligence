# Operations

## Daily flow

Use the machine runtime explicitly and keep synchronization disabled until the
private remote has passed assurance:

```text
python -B -m ei.cli recall --repo <clone> --runtime-root <runtime> --query "<bounded task>" --max-chars 2000 --json
python -B -m ei.cli closeout --repo <clone> --runtime-root <runtime> --input-json <sanitized closeout> --json
python -B -m ei.cli maintain --repo <clone> --runtime-root <runtime> --time-budget-ms 30000 --sync-policy disabled --json
```

The four lifecycle capabilities are one managed package: the inheritance gate
decides whether a sanitized observation is reusable, the curator proposes a
validated ChangeSet, recall selects only budget-fitting personal and optional
team knowledge, and the maintainer handles deduplication, contradiction,
ageing, tombstones, projection, queue, and recovery. The deterministic
runtime—not free-form model output—applies repository changes.

## Capture boundary

The installed Hook and global context send a sanitized envelope. At most the
configured observations per session are captured. Session, turn, CWD, and
source identifiers are hashed. Prompts, responses, tool output, credentials,
client-confidential text, and copied article telemetry are rejected or kept
local. If capture is unavailable, the task continues and a bounded retry
state is reported; no success is fabricated.

## Health and recovery

```text
python -B -m ei.cli status --repo <clone> --runtime-root <runtime> --json
python -B -m ei.cli doctor --repo <clone> --runtime-root <runtime> --strict --json
python -B -m ei.cli queue drain --repo <clone> --runtime-root <runtime> --max-items 100 --time-budget-ms 5000 --json
python -B -m ei.cli maintain --repo <clone> --runtime-root <runtime> --time-budget-ms 30000 --sync-policy disabled --json
```

Common states:

- `SYNC_BLOCKED` / `UNRELATED_WORKTREE_CHANGES`: inspect the private knowledge
  worktree and resolve unrelated edits before retrying.
- `PRIVACY_REJECTED`: remove the sensitive source; never bypass the gate.
- `AGENTS_MARKER_CORRUPT`: restore the recorded context backup and inspect the
  marker pair before reinstalling.
- `NO_PROVIDER_AVAILABLE`: a retryable provider/budget state, not a semantic
  NO.
- `UNINSTALL_CONFLICT` / rollback conflict: preserve the current target and
  resolve ownership manually.

Projection is rebuildable from the append-only event journal. Tombstones stop
default retrieval but preserve audit history. Team projection reads only the
externally managed shared layout and writes its index/cursor under
machine-local `team-cache`; partial or conflict files are reported while valid
events remain eligible.

## Repair-only repository bootstrap

The normal installation and new-PC journeys use the setup wrapper, which
creates or restores the knowledge repository in the same approved operation.
The lower-level `python -B -m ei.cli knowledge init ...` command is retained
only for explicit repair, migration tooling, and repository-contract
diagnostics. It does not install host integration, verify Hook trust, connect a
private GitHub repository, or establish `SETUP_COMPLETE`; do not present it as
a required second installation step.

## Provider quota and scheduling

Local LLMs do not consume hosted subscription quota. Subscription/free-tier
providers are deferred when their limit, authentication, or rate limit blocks
them. Cloud providers remain disabled when the configured spend cap is zero.
Maintenance retries eligible deferred work after the reset or availability
window. Scheduling is optional; manual `maintain` and `queue drain` are the
recovery path.

For `subscription-cli`, the active install manifest's selected host is the
source of truth. Status must show only the provider order approved during
setup, and the selected CLI executable must be available. Candidate content is
sent on standard input rather than command-line arguments. A missing executable
is `NO_PROVIDER_AVAILABLE`, not evidence for a NO gate decision.

## Git synchronization and conflicts

Only the personal knowledge root may synchronize. The remote must be private
or local-only, explicitly approved, and free of unrelated worktree changes.
The team shared folder is not synchronized, mounted, pushed, or ACL-managed by
this project. Semantic conflicts stop the personal operation and preserve both
sides for review; there is no automatic overwrite or force push. Run a dry plan
before enabling personal sync and retain the sync receipt.

## Retention and purge

Rotating runtime logs are bounded by byte limit and retention count. Expired
encrypted spool entries are removed with sanitized hash evidence. Knowledge
events are retained as the audit source of truth. Purging runtime cache,
spool, or knowledge is a separate owner-approved action; absence of a provider
or a scheduler never triggers a purge.

## Scheduler-free operation

If the OS scheduler is unavailable or disabled, run the same bounded CLI
commands manually. Record scheduler status as unavailable; do not claim that a
timer ran merely because its configuration file exists. Team status is
reported independently; an unavailable shared root is `DEFERRED` and does not
invalidate personal work.

## Optional monthly batching

Teams may review and consolidate reusable team candidates once per month to
reduce coordination overhead. This is only an optional batching cadence:
monthly maintenance is never an approval state, correctness requirement,
activation proof, or reason to delay personal capture. Run `maintain` manually
when a team needs a different cadence.

## Release evidence gates

`SETUP_COMPLETE`, `HOST_ACTIVATION_VERIFIED`, `PUBLIC_SOURCE_READY`,
`PUBLIC_RELEASE_READY`, `PRODUCTION_COMPLETE`, and `EFFECT_VALIDATED` are
separate evidence states. The release evaluator binds
all affirmative states to the exact public subject SHA. Missing publication,
scanner, hosted CI, real-host, lifecycle, or A/B evidence remains visible as a
pending gate and never becomes a pass flag.
