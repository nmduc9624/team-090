# Alert Report: Windows Security Log Cleared

## Alert Metadata
- alert_name: Windows Security Log Cleared
- alert_source: Windows Security
- severity: Critical
- category: Defense Evasion
- data_type: synthetic_mvp_alert_report

## Summary
The Windows Security event log is cleared unexpectedly.

## Observed Behaviors
- security control or forensic evidence is modified
- change occurs outside approved maintenance activity
- suspicious process or authentication activity appears nearby

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: powershell.exe, wevtutil.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
