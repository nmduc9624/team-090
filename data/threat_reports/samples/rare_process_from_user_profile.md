# Alert Report: Rare Process From User Profile

## Alert Metadata
- alert_name: Rare Process From User Profile
- alert_source: EDR
- severity: Medium
- category: Endpoint Execution
- data_type: synthetic_mvp_alert_report

## Summary
A low-prevalence executable starts from a user profile path.

## Observed Behaviors
- suspicious process starts from unusual path or parent process
- command line or child process differs from normal baseline
- file write, network connection, or payload activity follows

## Indicators
- domains: none
- ips: none
- hashes: none
- files: rare_process_from_user_profile.bin
- processes: powershell.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
