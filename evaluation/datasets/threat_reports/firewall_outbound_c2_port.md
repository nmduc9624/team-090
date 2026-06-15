# Alert Report: Outbound Connection To Unusual C2 Port

## Alert Metadata
- alert_name: Outbound Connection To Unusual C2 Port
- alert_source: Firewall
- severity: High
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
A workstation connects outbound to an uncommon port on an untrusted Internet host.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: firewall-outbound-c2-port.example
- ips: 203.0.113.78
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
