# Alert Report: Mailbox Forwarding Rule To External Address

## Alert Metadata
- alert_name: Mailbox Forwarding Rule To External Address
- alert_source: Email Security
- severity: High
- category: Email
- data_type: synthetic_mvp_alert_report

## Summary
A mailbox rule forwards messages to an external address after suspicious authentication.

## Observed Behaviors
- mailbox configuration changes after suspicious login
- messages are redirected, hidden, or accessed unusually
- activity may support mailbox compromise or data exposure

## Indicators
- domains: mailbox-forwarding-rule-external.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
