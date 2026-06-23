# External Gold Standard Rubric

External cases are hand-authored and must not be generated from the analyzer.

## Required gates

- Output must be schema-valid.
- Critical cases fail if the primary intent, primary telemetry, primary MITRE family, or selected query domain is wrong.
- Query drafts are judged as draft guidance; generic/KQL/SPL are acceptable if the domain and fields are correct.

## Scoring

- Threat summary: correct attack type/action/target.
- Key behaviors: recall of meaningful actions, partial credit for same domain.
- MITRE mapping: exact technique preferred, parent technique accepted as partial in manual review.
- Telemetry: primary sources must be present; noisy wrong-domain telemetry is a penalty.
- Checklist: must be actionable for SOC junior and not push the analyst into the wrong domain.
- Query drafts: must match the alert intent and expected telemetry/schema family.
