# Alert Report: Inbox Rule Hides Security Mail

## Alert Metadata
- alert_name: Inbox Rule Hides Security Mail
- alert_source: Email Security
- severity: Medium
- category: Email
- data_type: synthetic_mvp_alert_report

## Summary
A mailbox rule moves security notifications or password reset messages to hidden folders.

## Observed Behaviors
- mailbox configuration changes after suspicious login
- messages are redirected, hidden, or accessed unusually
- activity may support mailbox compromise or data exposure

## Indicators
- domains: inbox-rule-hides-security-mail.example
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
