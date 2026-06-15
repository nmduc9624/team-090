# Alert Report: Kubernetes Secret Read Spike

## Alert Metadata
- alert_name: Kubernetes Secret Read Spike
- alert_source: Kubernetes Audit
- severity: High
- category: Kubernetes Security
- data_type: synthetic_mvp_alert_report

## Summary
A service account reads many Kubernetes secrets in a short time window.

## Observed Behaviors
- Kubernetes API action is unusual for the user or service account
- activity targets secrets, pods, or production namespace
- interactive access or sensitive data access may follow

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: kubectl
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
