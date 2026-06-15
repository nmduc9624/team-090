# Alert Report: Tor2Web Proxy Access

## Alert Metadata
- alert_name: Tor2Web Proxy Access
- alert_source: Proxy
- severity: Medium
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host accesses Tor2Web gateway domains.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: proxy-tor2web-access.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
