# Alert Report: Dormant Account Login

## Alert Metadata
- alert_name: Dormant Account Login
- alert_source: Identity Provider
- severity: High
- category: Identity
- data_type: synthetic_mvp_alert_report

## Summary
An account inactive for a long period suddenly authenticates and accesses resources.

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
