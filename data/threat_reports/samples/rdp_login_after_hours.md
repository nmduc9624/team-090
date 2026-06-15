# Alert Report: After-Hours RDP Login

## Alert Metadata
- alert_name: After-Hours RDP Login
- alert_source: Windows Security
- severity: Medium
- category: Remote Access
- data_type: synthetic_mvp_alert_report

## Summary
An RDP login occurs outside normal working hours from a new source.

## Observed Behaviors
- remote access session appears from unusual source
- session occurs outside baseline or normal working pattern
- internal resource access follows the session

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
