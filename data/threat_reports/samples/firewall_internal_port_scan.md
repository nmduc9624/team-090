# Alert Report: Internal Port Scan Detected

## Alert Metadata
- alert_name: Internal Port Scan Detected
- alert_source: Firewall
- severity: High
- category: Network
- data_type: synthetic_mvp_alert_report

## Summary
One internal host attempts connections to many ports or many internal systems.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: firewall-internal-port-scan.example
- ips: 203.0.113.79
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
