# Phishing Escalation and Reporting Playbook

- **Incident type:** Phishing Email
- **Document type:** Playbook escalation, recovery and report
- **Goal:** Define escalation conditions, report completeness checks, and closure requirements.

## Investigation / Response Steps

| Step | Name | What to check | Report output |
| --- | --- | --- | --- |
| 1 | Confirm severity rationale | Escalate when credentials may be submitted, attachment execution/OAuth consent/BEC is involved, executive or finance users are targeted, or the campaign affects many recipients. | Suggested severity and rationale |
| 2 | Validate missing evidence | List all evidence required before a confident conclusion. | Missing Evidence |
| 3 | Escalate if needed | Route to senior SOC/IR owner when escalation conditions are met. | Escalation condition and owner |
| 4 | Record approval state | Keep final decision with analyst and track approval. | Pending/Approved status |
| 5 | Close or monitor | Close only after evidence, response notes, and owner approval are complete. | Final status and next review |

## Response Guardrail

The assistant may recommend response actions but must not perform containment, blocking, account lock, token revoke, or endpoint isolation.
