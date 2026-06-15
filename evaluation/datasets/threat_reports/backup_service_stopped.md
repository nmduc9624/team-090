# Alert Report: Backup Service Stopped

## Alert Metadata
- alert_name: Backup Service Stopped
- alert_source: EDR
- severity: High
- category: Ransomware Behavior
- data_type: synthetic_mvp_alert_report

## Summary
Backup or recovery services are stopped unexpectedly.

## Observed Behaviors
- recovery, backup, or shadow copy capability is modified
- change occurs shortly before suspicious file activity
- multiple hosts or critical servers may be affected

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: vssadmin.exe, sc.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
