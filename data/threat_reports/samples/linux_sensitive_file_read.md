# Alert Report: Sensitive Linux File Read

## Alert Metadata
- alert_name: Sensitive Linux File Read
- alert_source: Linux Audit
- severity: Medium
- category: Linux Discovery
- data_type: synthetic_mvp_alert_report

## Summary
A process reads sensitive files such as passwd, shadow, SSH keys or cloud credentials.

## Observed Behaviors
- sensitive local files are accessed unexpectedly
- accessing process is not normal administration tooling
- archive, staging, or outbound upload activity may follow

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: cat, python
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
