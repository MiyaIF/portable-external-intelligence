# Rollback

The installer writes timestamped `config.toml.before-ei-*` and `hooks.json.before-ei-*` backups and records their paths in `external-intelligence/install-manifest.json`.

```powershell
./scripts/uninstall.ps1 -ManifestPath $env:USERPROFILE\.codex\external-intelligence\install-manifest.json -RestoreConfigBackup
```

This removes only the four managed hook IDs and restores the exact config backup. It does not remove `events/` or `knowledge/`. Runtime cache removal requires the explicit `-RemoveRuntimeCache` switch and is limited to the engine-owned `cache` and `locks` directories.
## Release rollback and evidence preservation

Rollback is staged and reversible:

1. stop the scheduler and disable automatic promotion;
2. preserve the sanitized health, canary, migration, and sync evidence;
3. restore the last known-good projection or append a deprecation/tombstone event;
4. use the installer manifest to remove only managed Hook/Skill changes and restore the verified backup;
5. keep the event journal and provenance unless a separately approved legal/secret purge is required;
6. run strict doctor, recall, closeout, and a bounded maintenance pass before re-enabling anything.

A failed real-host certification never gets repaired by editing its receipt. Re-run the official host flow and produce a new timestamped receipt. A failed release attestation is recovered by correcting the prerequisite run or evidence input and generating a new post-push artifact; the subject manifest is not amended with an evidence SHA. Never force-push, reset the operator's worktree, or delete the journal to hide a failed promotion.