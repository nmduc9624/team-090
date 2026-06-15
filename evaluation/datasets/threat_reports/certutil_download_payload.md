# Alert Report: Certutil Downloads Payload

## Alert Metadata
- alert_name: Certutil Downloads Payload
- alert_source: EDR
- severity: High
- category: Signed Binary Abuse
- data_type: synthetic_mvp_alert_report

## Summary
certutil.exe downloads or decodes a payload from a remote location.

## Observed Behaviors
- trusted Windows binary runs with unusual arguments
- binary is used to download, execute, or proxy suspicious code
- network or child process activity follows execution

## Indicators
- domains: none
- ips: none
- hashes: none
- files: certutil_download_payload.bin
- processes: rundll32.exe, regsvr32.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
