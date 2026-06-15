# Alert Report: Suspicious User-Agent Beacon

## Alert Metadata
- alert_name: Suspicious User-Agent Beacon
- alert_source: Proxy
- severity: Medium
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
Outbound HTTP traffic uses a rare user-agent repeatedly from one host.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: proxy-suspicious-user-agent.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
