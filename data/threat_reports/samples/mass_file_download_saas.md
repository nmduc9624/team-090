# Alert Report: Mass File Download From SaaS

## Alert Metadata
- alert_name: Mass File Download From SaaS
- alert_source: SaaS Audit
- severity: High
- category: SaaS
- data_type: synthetic_mvp_alert_report

## Summary
A user downloads an unusually large number of files from a SaaS platform.

## Observed Behaviors
- SaaS activity volume is far above user baseline
- activity follows unusual authentication or device context
- downloaded files or accessed resources may contain sensitive data

## Indicators
- domains: mass-file-download-saas.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
