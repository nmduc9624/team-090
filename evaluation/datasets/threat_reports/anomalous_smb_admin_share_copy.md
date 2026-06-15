# Alert Report: Large File Copy To Admin Share

## Alert Metadata
- alert_name: Large File Copy To Admin Share
- alert_source: Windows Security
- severity: Medium
- category: Lateral Movement
- data_type: synthetic_mvp_alert_report

## Summary
A host copies executable files to administrative shares on multiple systems.

## Observed Behaviors
- remote execution or remote administration activity appears
- source account or host is unusual for this action
- target host shows new process, service, task, or file activity

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: wmic.exe, psexesvc.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
