# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Report a vulnerability

Do not open a public issue for an unpatched vulnerability, proof of concept, credential, path, transcript, or client data.
Use GitHub Private Vulnerability Reporting:

https://github.com/MiyaIF/portable-external-intelligence/security/advisories/new

Please include a concise impact description, affected version or commit, reproduction steps that contain no secrets, and a proposed mitigation if available. Do not attach raw prompts, responses, logs, credentials, SQLite files, or private repository data.

The maintainer target is acknowledgement within 7 days and initial triage within 14 days. These are operational targets, not a guaranteed response SLA. There is no bug bounty.

## Disclosure

Keep the report private while a fix and release are coordinated. The maintainer may request a sanitized reproduction or a private follow-up. Public disclosure timing is decided case by case after impact and affected versions are understood.

Security-sensitive changes involving hooks, command construction, filesystem mutation, private knowledge, Git synchronization, migration, encryption, or release evidence require security review.

## Team-store trust boundary

The optional team store relies on the shared-folder transport and ACL supplied by the organization. Event hashes detect corruption and collisions; they do not cryptographically authenticate individual team members. Every account with write access to the shared folder must therefore be trusted to contribute team knowledge. Leave team knowledge disabled when that condition cannot be enforced, and treat `access_control_verified: false` as unverified external state.
