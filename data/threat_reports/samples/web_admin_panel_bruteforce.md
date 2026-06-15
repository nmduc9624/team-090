# Alert Report: Admin Panel Brute Force

## Alert Metadata
- alert_name: Admin Panel Brute Force
- alert_source: Web Server
- severity: Medium
- category: Web Attack
- data_type: synthetic_mvp_alert_report

## Summary
An external source repeatedly attempts to authenticate to a web admin panel.

## Observed Behaviors
- web request contains exploit, brute force, or suspicious upload pattern
- same source repeats probing or exploitation attempts
- server-side process or file activity should be checked

## Indicators
- domains: web-admin-panel-bruteforce.example
- ips: 203.0.113.84
- hashes: none
- files: web_admin_panel_bruteforce.bin
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
