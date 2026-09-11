# Contributing

Issues and pull requests are welcome. A contribution is reviewed for correctness, portability, privacy, security, documentation, and compatibility with the supported CLI-agent adapters. Submission does not guarantee review, merge, or a response by a fixed date.

## Before opening an issue or pull request

- Remove secrets, credentials, access tokens, private keys, absolute home or client paths, raw prompts, raw responses, tool output, transcripts, SQLite files, and client-confidential data.
- Use a synthetic fixture when a reproduction can be expressed without private data.
- Read `SECURITY.md` first for a vulnerability; do not disclose an unpatched issue publicly.
- Run the narrow tests relevant to the change and describe any unavailable platform or provider evidence.
- Keep runtime state, private knowledge, caches, logs, and generated artifacts outside the tracked repository.

## Pull requests

Explain the user-visible behavior, affected platforms and CLI adapters, migration or rollback impact, and the evidence used. Changes to hooks, command quoting, filesystem operations, Git sync, privacy boundaries, dependencies, release workflows, or evidence contracts need focused tests and documentation.

## Developer Certificate of Origin

This project requires the Developer Certificate of Origin (DCO) and does not require a CLA. Each commit must include a sign-off asserting that you have the right to submit the work under the project license:

~~~text
Signed-off-by: Your Name <your-email@example.com>
~~~

Use `git commit -s` or add the line manually. The sign-off must use an identity you control; do not include private client information.
