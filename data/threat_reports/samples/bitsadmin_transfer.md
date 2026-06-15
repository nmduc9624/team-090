# Alert Report: Bitsadmin Suspicious Transfer

## Alert Metadata
- alert_name: Bitsadmin Suspicious Transfer
- alert_source: EDR
- severity: Medium
- category: Signed Binary Abuse
- data_type: synthetic_mvp_alert_report

## Summary
bitsadmin.exe creates a transfer job to download a file from the Internet.

## Observed Behaviors
- trusted Windows binary runs with unusual arguments
- binary is used to download, execute, or proxy suspicious code
- network or child process activity follows execution

## Indicators
- domains: none
- ips: none
- hashes: none
- files: bitsadmin_transfer.bin
- processes: rundll32.exe, regsvr32.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
