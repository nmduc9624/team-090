# Alert Report: Linux SSH Brute Force

## Alert Metadata
- alert_name: Linux SSH Brute Force
- alert_source: Linux Auth
- severity: Medium
- category: Linux Identity
- data_type: synthetic_mvp_alert_report

## Summary
A Linux host receives many failed SSH login attempts.

## Observed Behaviors
- Linux authentication attempts spike or behave unusually
- source account or IP is not expected
- successful shell or privilege activity may follow

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: sshd
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
