# Alert Report: Regular Interval DNS Beaconing

## Alert Metadata
- alert_name: Regular Interval DNS Beaconing
- alert_source: DNS
- severity: High
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host queries the same external domain at a highly regular interval.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: dns-beaconing-regular-interval.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
