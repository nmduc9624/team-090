# Alert Report: Remote Scheduled Task Created

## Alert Metadata
- alert_name: Remote Scheduled Task Created
- alert_source: Windows Security
- severity: High
- category: Lateral Movement
- data_type: synthetic_mvp_alert_report

## Summary
A scheduled task is created remotely on another host.

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
