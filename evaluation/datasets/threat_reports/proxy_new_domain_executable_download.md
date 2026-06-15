# Alert Report: Executable Download From Newly Registered Domain

## Alert Metadata
- alert_name: Executable Download From Newly Registered Domain
- alert_source: Proxy
- severity: High
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A host downloads an executable from a newly registered domain.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: proxy-new-domain-executable-download.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
