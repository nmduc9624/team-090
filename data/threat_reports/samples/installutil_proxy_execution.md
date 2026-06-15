# Alert Report: InstallUtil Proxy Execution

## Alert Metadata
- alert_name: InstallUtil Proxy Execution
- alert_source: EDR
- severity: High
- category: Signed Binary Abuse
- data_type: synthetic_mvp_alert_report

## Summary
InstallUtil.exe executes an untrusted .NET assembly from a user-writable directory.

## Observed Behaviors
- trusted Windows binary runs with unusual arguments
- binary is used to download, execute, or proxy suspicious code
- network or child process activity follows execution

## Indicators
- domains: none
- ips: none
- hashes: none
- files: installutil_proxy_execution.bin
- processes: rundll32.exe, regsvr32.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
