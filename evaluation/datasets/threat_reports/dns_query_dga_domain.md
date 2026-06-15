# Alert Report: Possible DGA Domain Queries

## Alert Metadata
- alert_name: Possible DGA Domain Queries
- alert_source: DNS
- severity: Medium
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host queries many algorithmically generated-looking domains.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: dns-query-dga-domain.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
