# Testing

The release validation runner executes every tracked `tests/**/test_*.py` module in a separate Python child process. It uses one job by default, bounds each child by a timeout, captures bounded per-module logs under ignored `artifacts/test-logs/`, and writes the aggregate summary atomically.

Run it from the repository root with the bundled or activated Python:

```powershell
python -B scripts/run-release-validation.py --jobs 1 --timeout-seconds 300 --output artifacts/unittest-summary.json
```

`--jobs N` enables bounded parallelism explicitly. A missing, duplicate, crashed, timed-out, or zero-test module fails the aggregate result. A module may declare `PLATFORM_SKIP = True` only for an approved platform-specific omission; it remains visible in the summary.

Inside a desktop agent, do not use a monolithic `python -m unittest discover` invocation when its output can destabilize the host. Use focused modules while developing and this child-process runner for the complete release check; hosted CI is the independent OS-matrix verification.
