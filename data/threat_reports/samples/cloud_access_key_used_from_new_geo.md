# Alert Report: Cloud Access Key Used From New Geography

## Alert Metadata
- alert_name: Cloud Access Key Used From New Geography
- alert_source: Cloud Audit
- severity: High
- category: Cloud Security
- data_type: synthetic_mvp_alert_report

## Summary
A cloud access key is used from a country or ASN not previously associated with the workload.

## Observed Behaviors
- cloud control plane setting changes unexpectedly
- actor, key, or workload is unusual for the action
- sensitive resource access or privilege expansion follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
