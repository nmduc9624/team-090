# Threat Report: Encoded PowerShell Payload Loader

## Summary
A malware report describes hidden PowerShell launched from a script host, using encoded commands to download a payload and run it from a user temp folder.

## Observed Behaviors
- wscript.exe launches powershell.exe
- PowerShell uses encoded command
- payload is written under user temp path
- PowerShell connects to unknown domain

## Indicators
- domains: cdn-update-check.example
- files: update.tmp
- processes: wscript.exe, powershell.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
