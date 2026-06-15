# Alert Report: Defender Real-Time Protection Disabled

## Alert Metadata
- alert_name: Defender Real-Time Protection Disabled
- alert_source: EDR
- severity: Critical
- category: Defense Evasion
- data_type: synthetic_mvp_alert_report

## Summary
Endpoint real-time protection is disabled using PowerShell or policy change.

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
- registry_keys: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
