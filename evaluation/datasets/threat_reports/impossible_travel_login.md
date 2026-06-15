# Alert Report: Impossible Travel Login

## Alert Metadata
- alert_name: Impossible Travel Login
- alert_source: Identity Provider
- severity: Medium
- category: Identity
- data_type: synthetic_mvp_alert_report

## Summary
A user logs in from two distant countries within an impossible travel window, then accesses cloud applications.

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
