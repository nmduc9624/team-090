# Alert Report: Linux Reverse Shell Pattern

## Alert Metadata
- alert_name: Linux Reverse Shell Pattern
- alert_source: Linux EDR
- severity: High
- category: Linux Execution
- data_type: synthetic_mvp_alert_report

## Summary
A shell process connects outbound to an external IP.

## Observed Behaviors
- Linux shell or process starts suspicious command activity
- process connects externally or downloads content
- parent process is unusual for interactive shell behavior

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: bash, sh
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
