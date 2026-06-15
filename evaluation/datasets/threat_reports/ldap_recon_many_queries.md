# Alert Report: LDAP Reconnaissance Query Spike

## Alert Metadata
- alert_name: LDAP Reconnaissance Query Spike
- alert_source: Windows Security
- severity: Medium
- category: Active Directory
- data_type: synthetic_mvp_alert_report

## Summary
A workstation performs many LDAP queries for users, groups, computers and privileged objects.

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
