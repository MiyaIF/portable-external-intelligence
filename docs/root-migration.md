# Combined-layout migration

The migration command copies only sanitized knowledge data from an old
combined repository into a separate `knowledge_root`. It records a
content-addressed plan before copying, verifies every source file again at
apply time, rebuilds the projection, and writes a machine-local receipt under
`runtime_root`.

The source is never deleted by migration. A failed copy removes only its
private staging directory. Rollback removes the destination only when the
ownership receipt and destination digest still match. Legacy cleanup is a
separate, explicitly confirmed operation requiring a verified backup and the
exact plan hash.

Inspect example:

```text
ei migration inspect --repo OLD_ROOT --knowledge-root NEW_ROOT --runtime-root RUNTIME_ROOT --json
```

Save the plan under the machine-local runtime root, then apply only after
reviewing its digest:

```text
ei migration inspect --repo OLD_ROOT --knowledge-root NEW_ROOT --runtime-root RUNTIME_ROOT --plan-output RUNTIME_ROOT/migration/plan.json --json
ei migration apply --plan RUNTIME_ROOT/migration/plan.json --confirm-plan-hash sha256:... --json
```

If a process is interrupted before the atomic rename, inspect and recover only
the staging directory belonging to the exact plan:

```text
ei migration inspect-recovery --knowledge-root NEW_ROOT --runtime-root RUNTIME_ROOT --json
ei migration recover-staging --knowledge-root NEW_ROOT --runtime-root RUNTIME_ROOT --plan-hash sha256:... --confirm --json
```

Rollback is receipt-bound and refuses a changed destination:

```text
ei migration rollback --receipt RUNTIME_ROOT/migration/<plan-digest>.json --confirm-plan-hash sha256:... --json
```

Legacy cleanup is never implicit. It requires the exact plan digest, a backup
directory whose authorized file hashes match the plan, and a completed
migration receipt:

```text
ei migration cleanup --plan RUNTIME_ROOT/migration/plan.json --confirm-plan-hash sha256:... --verified-backup BACKUP_ROOT --json
```

Apply and cleanup are intentionally separate commands. Do not place raw
transcripts, credentials, client source, SQLite files, or absolute personal
paths in a migration source.
