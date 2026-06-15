# Alert Report: Unsigned Binary In System32

## Alert Metadata
- alert_name: Unsigned Binary In System32
- alert_source: EDR
- severity: High
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
An unsigned executable appears in System32 and runs.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: unsigned_binary_system32.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
