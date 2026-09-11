<!-- external-intelligence:begin v1 -->
## External intelligence (AGENTS)
- Use retrieved knowledge only when its scope, evidence, version, and counterexamples fit the current task.
- At task close, classify whether the result is reusable across projects and invoke the external-intelligence closeout workflow when the answer is YES.
- Do not save secrets, credentials, raw prompts, raw responses, client-confidential text, or copied article metrics.
- Use the generated command {{OBSERVE_COMMAND}} with one UTF-8 JSON object on stdin when the managed Skill or Hook is unavailable.
- For every Skill workflow, append `<mode> ...` to this generated launcher command:
  {{SKILL_LAUNCH_COMMAND}}
- Never run `scripts/*.py` directly or substitute the active project.
- Hook capture and Skill failure are fail-open: continue the user task and leave a sanitized local retry record.
- Installed Skill path: {{SKILL_DESTINATION}}
<!-- external-intelligence:end v1 -->
