# Alert Report: Obfuscated Windows Command Shell

## Alert Metadata
- alert_name: Obfuscated Windows Command Shell
- alert_source: EDR
- severity: Medium
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
cmd.exe runs with unusual quoting, environment expansion and chained commands.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: cmd_obfuscated_command.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
