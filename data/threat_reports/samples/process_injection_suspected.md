# Alert Report: Process Injection Suspected

## Alert Metadata
- alert_name: Process Injection Suspected
- alert_source: EDR
- severity: High
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
A process writes memory into another process and starts a remote thread.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: process_injection_suspected.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
