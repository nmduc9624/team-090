# Alert Report: PowerShell Download Cradle

## Alert Metadata
- alert_name: PowerShell Download Cradle
- alert_source: EDR
- severity: High
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
PowerShell downloads and executes content from a remote URL.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: powershell_download_cradle.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
