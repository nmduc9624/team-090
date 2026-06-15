# Alert Report: Large Upload To Personal Cloud Drive

## Alert Metadata
- alert_name: Large Upload To Personal Cloud Drive
- alert_source: Proxy
- severity: High
- category: Data Loss
- data_type: synthetic_mvp_alert_report

## Summary
A user uploads a large archive to a personal cloud storage service.

## Observed Behaviors
- large data movement or upload occurs outside normal baseline
- archive or staging activity appears before outbound transfer
- destination is personal, untrusted, or newly observed

## Indicators
- domains: data-loss-large-upload-personal-drive.example
- ips: none
- hashes: none
- files: data_loss_large_upload_personal_drive.bin
- processes: 7z.exe, chrome.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
