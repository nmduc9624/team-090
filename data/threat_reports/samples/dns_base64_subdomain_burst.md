# Alert Report: Base64-Like DNS Subdomain Burst

## Alert Metadata
- alert_name: Base64-Like DNS Subdomain Burst
- alert_source: DNS
- severity: High
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host sends bursts of DNS queries with long base64-like subdomains.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: dns-base64-subdomain-burst.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
