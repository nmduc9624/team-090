# Alert Report: DCSync Replication Request

## Alert Metadata
- alert_name: DCSync Replication Request
- alert_source: Windows Security
- severity: Critical
- category: Active Directory
- data_type: synthetic_mvp_alert_report

## Summary
A non-domain-controller account performs directory replication operations.

## Observed Behaviors
- domain authentication or directory activity spikes
- source host is not expected for directory administration
- activity targets privileged identities or credential material

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
