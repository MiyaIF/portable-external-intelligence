# CLI certification runbook

## Public host set

Certify the four CLI agents independently:

```text
codex-cli
claude-code
gemini-cli
qwen-code
```

For each host/OS pair in the declared 20-pair matrix, use its official executable and actual instance. The
receipt must include the detected version, OS profile, Hook/template hash,
Skill hash, required normalized event hashes, activation state, and a bounded
timestamp. Do not include paths, prompts, responses, tool output, credentials,
or client data.

## Fixture versus real

`mode=fixture` is an isolated adapter/schema check only. `mode=real` is a PASS
only when the official CLI produced all required lifecycle evidence within the
TTL. An unbound real-looking receipt remains `private_development`; it cannot
complete a public release. Codex App receipts are legacy/private only and do
not satisfy this matrix.

## Procedure

1. Run `setup --check-only` with isolated roots.
2. Apply setup with sync and scheduler disabled.
3. Complete the official CLI Hook trust and Skill consent flow.
4. Run the host's real canary and write a sanitized receipt.
5. Validate the receipt and import only its hash-bound, path-free form into
   the private ops trust domain.
6. Repeat for all 20 advertised host/OS pairs. Hosted CI does not replace a
   real Windows 10/11 receipt or any other real pair.

Example wrapper calls:

```text
scripts/certify-host.ps1 -Repo <clone> -HostId codex-cli -InstanceId <instance> -Mode real -RuntimeRoot <runtime> -HostHome <CLI home> -OsProfile windows-11 -Output <receipt>
scripts/certify-host.sh --repo <clone> --host claude-code --instance <instance> --mode real --runtime-root <runtime> --host-home <CLI home> --os-profile macos-current --output <receipt>
```

## Release evidence

Generate evidence only for the exact public subject SHA. The subject manifest
does not contain a later evidence commit SHA. After hosted CI, validate the
required workflow run IDs, exact head SHA, manifest/workflow/certification
hashes, scanner receipts, and independent production/effect states.

```text
python -B scripts/verify-release-evidence.py --manifest release/evidence-manifest.json --status-only --json
```

Before public publication, `awaiting_public_subject` is the correct status.
Do not replace it by hand with a pass flag.
