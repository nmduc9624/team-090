# Threat Report: Data Staging and Exfiltration with Rclone

## Summary
The report describes attackers using rclone to stage and transfer archive files from file servers to external storage.

## Observed Behaviors
- rclone.exe runs on server
- large outbound transfer
- archive files created before transfer

## Indicators
- domains: storage-sync.example
- files: rclone.exe, finance_archive.zip
- processes: rclone.exe, 7z.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
