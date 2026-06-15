# Alert Report: Kubernetes Exec Into Pod

## Alert Metadata
- alert_name: Kubernetes Exec Into Pod
- alert_source: Kubernetes Audit
- severity: Medium
- category: Kubernetes Security
- data_type: synthetic_mvp_alert_report

## Summary
A user or service account executes an interactive command inside a pod.

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
