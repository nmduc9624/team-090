# Alert Report: SQL Injection Attempt Against Web App

## Alert Metadata
- alert_name: SQL Injection Attempt Against Web App
- alert_source: Web Server
- severity: Medium
- category: Web Attack
- data_type: synthetic_mvp_alert_report

## Summary
Web logs show requests containing SQL injection patterns.

## Observed Behaviors
- web request contains exploit, brute force, or suspicious upload pattern
- same source repeats probing or exploitation attempts
- server-side process or file activity should be checked

## Indicators
- domains: web-sql-injection-attempt.example
- ips: 203.0.113.81
- hashes: none
- files: web_sql_injection_attempt.bin
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
