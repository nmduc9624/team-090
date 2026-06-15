# Alert Report: Chained LOLBin Execution

## Alert Metadata
- alert_name: Chained LOLBin Execution
- alert_source: EDR
- severity: High
- category: Signed Binary Abuse
- data_type: synthetic_mvp_alert_report

## Summary
Multiple trusted Windows binaries execute in sequence.

## Observed Behaviors
- trusted Windows binary runs with unusual arguments
- binary is used to download, execute, or proxy suspicious code
- network or child process activity follows execution

## Indicators
- domains: none
- ips: none
- hashes: none
- files: lolbin_suspicious_chain.bin
- processes: rundll32.exe, regsvr32.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
