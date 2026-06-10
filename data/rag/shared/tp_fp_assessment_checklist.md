# True Positive / False Positive Assessment Checklist

## Evidence Leaning True Positive

- Alert contains successful suspicious action, not only a detection label.
- User interaction, execution, outbound traffic, or post-login sensitive action is visible.
- Asset/user is privileged, sensitive, or business critical.
- Indicator appears across multiple logs or multiple hosts/users.
- No approved ticket, allowlist, baseline, or owner confirmation explains the activity.

## Evidence Leaning False Positive / Benign

- Control blocked/quarantined the event before exposure.
- User/owner confirms legitimate action through an official channel.
- Destination/process/tool matches approved vendor, change ticket, or known baseline.
- No follow-on activity appears after the alert.
- Indicator scope is isolated and explainable.

## Required Output

- Use `likely_true_positive`, `needs_validation_possible_false_positive`, or `inconclusive`.
- Always list evidence for both TP and FP where possible.
- Never claim final certainty when missing evidence remains.
