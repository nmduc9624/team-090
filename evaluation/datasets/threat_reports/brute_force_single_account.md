# Alert Report: Brute Force Against Single Account

## Alert Metadata
- alert_name: Brute Force Against Single Account
- alert_source: Identity Provider
- severity: Medium
- category: Identity
- data_type: synthetic_mvp_alert_report

## Summary
One account receives repeated failed login attempts followed by lockout or possible success.

## Observed Behaviors
- unusual authentication pattern appears for the user
- source IP or device is not part of the user's baseline
- follow-on access occurs after the suspicious login

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
