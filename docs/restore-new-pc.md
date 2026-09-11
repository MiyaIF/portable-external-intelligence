# Restore on a new PC

The portable unit is the public engine repository plus the user's separate
private knowledge Git repository. Runtime queues, caches, locks, logs,
credentials, installed Skill copies, Hook trust, and scheduler state are
machine-local and must be recreated rather than copied.

## Private GitHub restoration

1. Install Git, Python 3.11 or newer, the target CLI agents, and GitHub CLI.
2. Authenticate GitHub CLI and verify the account with `gh auth status`.
3. Clone the public engine into any clean directory.
4. From that clone, run `scripts/setup.ps1` on Windows or
   `scripts/setup.sh` on macOS/Linux.
5. Select `github-existing`, the existing private `owner/repository`, a new
   empty knowledge path, a new runtime path, and the CLI hosts on this machine.
6. Review the plan and approve it. Setup verifies private visibility and the
   remote fingerprint, restores knowledge, installs managed host integration,
   writes a new machine manifest, and optionally registers maintenance.

No old runtime directory, global context file, installed Skill directory,
SQLite database, or credential store is needed. The normal restore is the same
one-command setup flow used for first installation.

Non-interactive example:

```powershell
.\scripts\setup.ps1 -KnowledgeMode github-existing -GitHubRepository owner/private-ei-knowledge -KnowledgeRoot "D:\AI data\private knowledge" -RuntimeRoot "D:\AI data\runtime" -Hosts codex-cli -HostHome "codex-cli=<codex-cli-home>" -Sync -NonInteractive -CheckOnly -Json
.\scripts\setup.ps1 -KnowledgeMode github-existing -GitHubRepository owner/private-ei-knowledge -KnowledgeRoot "D:\AI data\private knowledge" -RuntimeRoot "D:\AI data\runtime" -Hosts codex-cli -HostHome "codex-cli=<codex-cli-home>" -Sync -NonInteractive -AcceptPlan -Json
```

Do not pass `--confirm-github-create` in `github-existing` mode. That flag is
reserved for exact authorization of a new private repository.

## Local-only restoration

`local` mode has no network replica. Restore its entire private knowledge Git
repository from an owner-controlled backup into the chosen knowledge path,
then run setup in `local` mode. Setup reuses it only when the repository
descriptor, required layout, Git state, and root separation are valid. It does
not import arbitrary folders or repair unrelated Git history automatically.

Use `github-new` only for a genuinely new private destination. It refuses an
existing GitHub repository and requires the exact repository slug as creation
confirmation.

## Offline and interrupted restore

`github-existing` requires GitHub visibility verification and Git transport.
If the network, GitHub API, authentication, or quota is temporarily
unavailable, setup records the exact completed stage and retains safe local
work. Rerun the same setup command after recovery. Do not delete the retained
knowledge root or force-push.

A public/unknown remote, fingerprint change, branch mismatch, unrelated local
history, symlink/junction escape, or overlapping root is not retryable by
force. Correct the owner-controlled configuration and rerun the check-only
plan.

## Moved engine clone

The engine clone path is machine-specific. If it moves, rerun setup from the
new clone with the same knowledge and runtime roots so managed Hook, context,
Skill, scheduler, and manifest paths are regenerated transactionally. Do not
edit absolute paths in the manifest by hand.

## Activation and validation

After setup, complete each official CLI's Hook trust and Skill consent flow.
Then run:

```text
python -B -m ei.cli status --repo <public clone> --runtime-root <runtime> --json
python -B -m ei.cli doctor --repo <public clone> --runtime-root <runtime> --strict --json
python -B -m ei.cli recall --repo <public clone> --runtime-root <runtime> --query "restore canary" --max-chars 1000 --json
```

Doctor restores the knowledge path and remote assurance from the validated
machine manifest. It rechecks live private visibility for a GitHub remote. A
repository clone alone does not prove Hook execution or Skill discovery.

Codex App is outside the public target. Supported host IDs are `codex-cli`,
`claude-code`, `gemini-cli`, and `qwen-code`. A legacy `codex-app` record is
migrated visibly to `codex-cli`; it is not treated as App support.

## Synchronized and retained boundaries

The private knowledge repository contains append-only accepted events,
rebuildable knowledge projections, policies, and bounded evidence. It excludes
raw prompts/responses/tool output, credentials, cookies, client-confidential
files, runtime queues, locks, caches, logs, and local provider state.

Default uninstall removes only managed machine integration and records
`knowledge_retained=true`; it does not delete the private repository or GitHub
remote. This allows the same `github-existing` restore flow on another PC.

## Independent completion states

- `SETUP_COMPLETE`: this machine's knowledge destination and managed files are ready.
- `HOST_ACTIVATION_VERIFIED`: the official CLI emitted bound Hook and Skill evidence.
- `PRODUCTION_COMPLETE`: the complete required host/OS and recovery matrix passed.
- `EFFECT_VALIDATED`: the preregistered A/B experiment passed its causal gates.

Keep these states separate in restore records. A successful clone or setup is
not, by itself, production or effect evidence.
