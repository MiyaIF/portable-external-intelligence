# Scheduled maintenance

Scheduling is optional. The generated user-level action invokes the Python
executable directly with explicit roots and arguments; it does not use a shell
bridge, write repository logs, wake the computer, or run with elevated
privileges.

## Check first

```text
scripts/install-scheduled-task.ps1 -RepoPath <clone> -CodexHome <CLI home> -RuntimeRoot <runtime> -PythonExe <python> -CheckOnly
scripts/install-launchd.sh --repo <clone> --codex-home <CLI home> --runtime-root <runtime> --python-exe <python> --check-only
scripts/install-systemd-user.sh --repo <clone> --codex-home <CLI home> --runtime-root <runtime> --python-exe <python> --check-only
```

Check-only renders the exact executable, argv, working directory, runtime log,
and ownership boundary. It does not register a task or service and does not
write scheduler state.

## Register and inspect

Apply only after reviewing the check-only output. On Windows, inspect the live
Task Scheduler action, current-user principal, limited run level, trigger,
last result, next run, and executable hash. On macOS inspect the managed
launchd label and `ProgramArguments`; on Linux inspect the systemd user unit
and timer. The live action must match the recorded action exactly.

The Windows task uses Task Scheduler's current-user `Interactive` default,
limited run level, and a once-plus-repetition trigger beginning two minutes
after registration. It repeats every 30 minutes for a bounded 3650-day
duration with `StopAtDurationEnd=false` and `StartWhenAvailable=true`; this
avoids the elevation requirement of a root-level `AtLogOn` trigger. The
check-only JSON exposes those values before registration.

The scheduled command runs bounded maintenance against the personal knowledge
root and, only when explicitly enabled, refreshes the optional team projection
and local outbox. It writes only sanitized status, counts, hashes, reason
codes, and timing to rotating machine-local logs. It does not write prompts,
claims, raw source, credentials, or transcripts. Personal and team results are
reported separately; an unavailable shared root is `DEFERRED` and does not
make personal maintenance fail.

## Failure and removal

If a service manager is unavailable, run `maintain` manually and record
`SCHEDULER_UNAVAILABLE`. If a live action differs, stop and preserve it for
manual review. Remove only after a check-only verification and ownership
match. Uninstalling the engine never purges private knowledge.

Overlapping runs are bounded by the runtime lock. A stale lock is handled only
after verifying the owning process is gone; never delete a lock by pattern or
outside the runtime root.

## Optional monthly cadence

A team may choose a monthly maintenance/review batch to collect and consolidate
individual knowledge. This cadence is optional and is never an approval state,
correctness requirement, activation proof, or reason to defer personal work.
Manual `maintain` remains valid when a different cadence is appropriate.
