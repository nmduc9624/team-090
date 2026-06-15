# Alert Report: Executable File Uploaded To Web App

## Alert Metadata
- alert_name: Executable File Uploaded To Web App
- alert_source: Web Server
- severity: High
- category: Web Attack
- data_type: synthetic_mvp_alert_report

## Summary
A web app receives an uploaded executable or script file type.

## Observed Behaviors
- web request contains exploit, brute force, or suspicious upload pattern
- same source repeats probing or exploitation attempts
- server-side process or file activity should be checked

## Indicators
- domains: web-file-upload-executable.example
- ips: 203.0.113.85
- hashes: none
- files: web_file_upload_executable.bin
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
