# Existing-source inventory

`inventory_existing_state(roots, settings)` is a read-only coverage ledger. It
resolves and authorizes every source root before enumerating any child path. The
legacy `inventory_existing_state(codex_home, memory_root)` call remains as a
compatibility adapter for existing integrations.

Supported source classes are:

- current memory Markdown, project memory, pattern evidence, rollout summary, and
  ad-hoc correction notes;
- Skill source and global context/config/hook metadata;
- SQLite file schema metadata only; message rows and raw bodies are never queried;
- external article copies as references;
- historical Git commit/blob hashes, without copying historical blob content into
  the ledger.

Every discovered source receives exactly one terminal disposition:

```text
imported
referenced_only
duplicate
skipped_with_reason
rejected_privacy
rejected_secret
unsupported_format
```

The accounting identity is mandatory:

```text
discovered = imported + referenced_only + duplicate
           + skipped_with_reason + rejected_privacy
           + rejected_secret + unsupported_format
unclassified = 0
```

Reports record only source class, normalized path hash, content hash, size,
provenance identifier, disposition, reason, historical flag, and produced event
IDs. Raw paths, claims, transcript text, SQLite rows, article figures, secrets,
and credentials are not included.

Article-copy values are classified as `external_article_copy` /
`external-reference`. They are never imported into the user knowledge baseline
and never become local quota, cache, token, or A/B evidence. Migration may create a
sanitized `source.reference.recorded` event containing only hashes and the fixed
fact that the source is an external reference.

## Source authorization

Task 15 commands require an explicit source directory and an explicit isolated
runtime directory. `source=auto` is denied unless `--allow-global-source` is
present and a Task 19 approval record exists under the runtime/release approval
locations. The repository root, runtime root, reparse-point root, and unapproved
global home are denied before scanning. This prevents an unrelated working
directory from being treated as the memory source.

Example:

```powershell
$fixtureRoot = (Resolve-Path 'tests/fixtures/migration/complete-legacy-tree').Path
$runtimeRoot = Join-Path ([IO.Path]::GetTempPath()) ('ei-task15-' + [guid]::NewGuid().ToString('N'))
python -m ei.cli inventory-existing --repo (Get-Location).Path --runtime-root $runtimeRoot --source $fixtureRoot --json
```

## Migration lifecycle

Migration is hash-bound and source read-only:

1. inventory and privacy scan;
2. deterministic dry-run plan and plan hash;
3. duplicate, contradiction, and article-reference review;
4. apply only when source hashes, inventory hash, privacy scan, and plan hash match;
5. append-only events and deterministic projection rebuild;
6. checkpoint and rollback manifest update after each event.

The checkpoint and rollback manifest live below the machine-local runtime state.
A second apply is idempotent. An interrupted apply resumes from its checkpoint
without deleting or rewriting already appended events. Source bytes and mtimes
remain unchanged.
