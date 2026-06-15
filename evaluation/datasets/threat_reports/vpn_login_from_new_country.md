# Alert Report: VPN Login From New Country

## Alert Metadata
- alert_name: VPN Login From New Country
- alert_source: VPN
- severity: Medium
- category: Remote Access
- data_type: synthetic_mvp_alert_report

## Summary
A VPN session starts from a country or ASN not previously seen for the user.

## Observed Behaviors
- remote access session appears from unusual source
- session occurs outside baseline or normal working pattern
- internal resource access follows the session

## Indicators
- domains: none
- ips: 203.0.113.32
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
