# Migration report format

`migrate-existing` writes a sanitized JSON report containing:

- `plan_hash`: source content, normalized item, and inventory hash;
- `source_hashes`: local apply gate hashes; the sync worker never stages this
  report;
- `planned_items`: normalized observation/reference/policy item count;
- `inventory`: balanced terminal-disposition ledger and exact counts;
- `imported`, `skipped`, `duplicates`: apply counters;
- `external_references`: external article references excluded from the user
  baseline;
- `secret_rejected`: count only; secret bytes are never echoed;
- `policy_provenance`: prior policy statements imported as provenance, never as
  promotion proof;
- `cluster_provenances`: deterministic cluster-to-provenance mapping;
- `checkpoint_path` and `rollback_manifest_path`: machine-local recovery
  artifacts.

Use an explicit source and an isolated runtime for inventory and dry-run:

```powershell
$fixtureRoot = (Resolve-Path 'tests/fixtures/migration/complete-legacy-tree').Path
$runtimeRoot = Join-Path ([IO.Path]::GetTempPath()) ('ei-task15-' + [guid]::NewGuid().ToString('N'))
python -m ei.cli inventory-existing --repo (Get-Location).Path --runtime-root $runtimeRoot --source $fixtureRoot --inventory (Join-Path $runtimeRoot 'migration-inventory.json') --json
python -m ei.cli migrate-existing --repo (Get-Location).Path --runtime-root $runtimeRoot --source $fixtureRoot --dry-run --report (Join-Path $runtimeRoot 'migration-preview.json') --inventory (Join-Path $runtimeRoot 'migration-inventory.json') --json
```

Apply requires the same source bytes, inventory hash, and plan hash as the dry run:

```powershell
$preview = Get-Content -Raw (Join-Path $runtimeRoot 'migration-preview.json') | ConvertFrom-Json
python -m ei.cli migrate-existing --repo (Get-Location).Path --runtime-root $runtimeRoot --source $fixtureRoot --apply-plan-hash $preview.plan_hash --report (Join-Path $runtimeRoot 'migration-apply.json') --inventory (Join-Path $runtimeRoot 'migration-inventory.json') --json
```

`source=auto` is not a shortcut for Task 15. It requires both the explicit
`--allow-global-source` flag and a recorded Task 19 approval. A missing,
changed, unreadable, or privacy-incomplete source fails closed before apply.
