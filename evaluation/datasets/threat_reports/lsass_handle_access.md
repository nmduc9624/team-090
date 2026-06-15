# Alert Report: Suspicious LSASS Handle Access

## Alert Metadata
- alert_name: Suspicious LSASS Handle Access
- alert_source: EDR
- severity: Critical
- category: Credential Access
- data_type: synthetic_mvp_alert_report

## Summary
A non-standard process opens LSASS with high privileges.

## Observed Behaviors
- process accesses credential material or sensitive memory
- actor or process is not part of normal security tooling
- credential access is followed by authentication or lateral movement

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: lsass.exe, procdump.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
