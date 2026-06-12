# Data Plan

The old incident-case dataset was removed because the project direction changed.

The new dataset should focus on threat intelligence inputs and expected hunt-package outputs.

## Needed Data

- Sample threat reports or synthetic advisories.
- Log source schemas describing available telemetry fields.
- Query templates for SIEM/EDR languages such as KQL and Splunk SPL.
- MITRE ATT&CK mapping references.
- Gold expected hunt packages for evaluation.

## Suggested Evaluation Pair

Input: threat report describing malware behavior.

Expected output:
- threat summary
- extracted IOC
- attack behaviors
- MITRE techniques
- required telemetry
- hunt checklist
- query drafts
- escalation condition
