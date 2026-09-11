# Closeout workflow

1. Summarize only the reusable candidate fields: title, claim, evidence hashes, benefit, scope, precondition, failure mode, exception, and version constraint.
2. Run the inheritance-gate prompt and require exactly YES or NO with a fixed reason class.
3. For NO, ask whether an aggregate decision history is enabled. Never save the candidate body or a free-text reason.
4. For YES, pass exactly one UTF-8 JSON object on stdin to the generated Skill launcher with mode `closeout`; never call `scripts/closeout.py` directly or use the active project root.
5. Review the returned ChangeSet. The deterministic runtime validates source hashes, privacy, policy version, lifecycle, and size before any append.
6. A ChangeSet is not applied by the prompt. Apply it only through the production curation command or an explicitly approved workflow.
7. Report `DEFERRED` when the configured provider is unavailable or quota-limited; do not convert provider availability into a semantic NO.

The script has a recursion guard. If an internal invocation is detected, it returns a sanitized skip result and does not call another provider.
