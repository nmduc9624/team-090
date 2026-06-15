# Alert Report: Executable Runs From Temp Directory

## Alert Metadata
- alert_name: Executable Runs From Temp Directory
- alert_source: EDR
- severity: Medium
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
An executable runs from a temporary directory and starts network activity.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: suspicious_temp_executable_run.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
