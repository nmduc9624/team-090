# Alert Report: Privileged Container Started

## Alert Metadata
- alert_name: Privileged Container Started
- alert_source: Container Runtime
- severity: High
- category: Container Security
- data_type: synthetic_mvp_alert_report

## Summary
A container starts with privileged mode or host namespace access.

## Observed Behaviors
- container runtime action weakens isolation
- image, namespace, or host mount differs from approved deployment
- host-level access or suspicious process activity may follow

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: containerd, dockerd
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
