# Alert Report: Rundll32 JavaScript URL Handler

## Alert Metadata
- alert_name: Rundll32 JavaScript URL Handler
- alert_source: EDR
- severity: High
- category: Signed Binary Abuse
- data_type: synthetic_mvp_alert_report

## Summary
rundll32.exe is used with JavaScript or URL handler patterns to execute code.

## Observed Behaviors
- trusted Windows binary runs with unusual arguments
- binary is used to download, execute, or proxy suspicious code
- network or child process activity follows execution

## Indicators
- domains: none
- ips: none
- hashes: none
- files: rundll32_javascript_url.bin
- processes: rundll32.exe, regsvr32.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
