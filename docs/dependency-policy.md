# Dependency policy

The public package keeps build, runtime, and CI dependencies in separate
`requirements-*.in` inputs. Every input is an exact version pin and every
generated lock entry contains one or more SHA-256 hashes for the upstream
distribution files.

- The build baseline is `setuptools==84.0.0` and the checked-in lock generator
  is `pip-tools==7.6.1`.
- Runtime encryption uses `cryptography==50.0.1` and its resolved transitive
  dependencies.
- CI uses `pip-audit==2.10.1` and `detect-secrets==1.5.0` plus their resolved
  transitive dependencies.
- Lock updates require `scripts/update-dependency-locks.py --verify-upstream
  --generate`; the command fails when the pinned release cannot be verified.
- CI installs each lock with `pip install --require-hashes` and verifies the
  lock/input/`pyproject.toml` contract before testing.
- `scripts/generate-sbom.py` emits deterministic SPDX 2.3 metadata from the
  locks. It contains package names, versions, distribution hashes, and no
  local paths, credentials, or runtime data.

The project does not silently move to a newer dependency when an advisory is
found. A version change requires an explicit plan amendment with the upstream
release URL, compatibility evidence, advisory comparison, regenerated hashes,
and a clean dependency audit.
