# Alert Report: High NXDOMAIN Query Rate

## Alert Metadata
- alert_name: High NXDOMAIN Query Rate
- alert_source: DNS
- severity: Medium
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host generates a high rate of failed DNS queries.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: dns-many-failed-queries.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
