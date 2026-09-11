# A/B experiment protocol

## Registration

- Assignment is SHA-256(`experiment_id + NUL + session_id`); first byte below 128 is control
- The registered alpha is 0.05, target power is 0.80, and the minimum detectable effect is 0.20
- The minimum analysis floor is 50 eligible sessions per variant and 14 calendar days
- The floor is an eligibility gate, not proof of causality
- Eligibility, domain exclusions, stopping rule, and metric sources are fixed before exposure

## Analysis

- Analysis is intention-to-treat by assigned session
- Primary metrics are accepted only when an authoritative source is linked to the session
- Missing metrics stay missing; zero is never imputed
- Absolute and relative differences use deterministic bootstrap confidence intervals
- Insufficient sample or invalid linkage produces `CAUSAL_EFFECT_NOT_IDENTIFIED`
- Power below 0.80 produces `POWER_INSUFFICIENT`

## Exclusions

Security, legal, medical, and high-stakes financial domains are excluded from automatic treatment exposure and causal analysis.
