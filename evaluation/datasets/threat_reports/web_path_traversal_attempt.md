# Alert Report: Path Traversal Attempt Against Web Server

## Alert Metadata
- alert_name: Path Traversal Attempt Against Web Server
- alert_source: Web Server
- severity: Medium
- category: Web Attack
- data_type: synthetic_mvp_alert_report

## Summary
Web requests attempt to access files outside the application directory.

## Observed Behaviors
- web request contains exploit, brute force, or suspicious upload pattern
- same source repeats probing or exploitation attempts
- server-side process or file activity should be checked

## Indicators
- domains: web-path-traversal-attempt.example
- ips: 203.0.113.82
- hashes: none
- files: web_path_traversal_attempt.bin
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
