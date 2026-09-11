# Security remediation report

## Current state

```text
status: awaiting_public_subject
subject_commit_sha: unavailable
finding_count: derived from the sealed scanner artifact
```

The security scan has not yet been re-run against an exact sanitized public
subject SHA. Therefore this report intentionally records no fixed finding and
cannot satisfy `PUBLIC_RELEASE_READY`.

For the public release, the CI-produced remediation artifact supplies the
dynamic reportable-finding count and complete finding-set digest. Each finding
must contain a finding ID, severity, `status=fixed`, the exact public subject
SHA, and a regression-evidence hash. The sealed scanner receipt, snapshot,
remediation report, and CI artifact receipt are hash-bound. A count/set
mismatch or any open or unbound finding blocks the release.
