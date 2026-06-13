# Threat Report: Scheduled Task Persistence After Payload Execution

## Summary
The report describes malware that creates a scheduled task named like a browser updater after initial execution.

## Observed Behaviors
- unknown executable creates scheduled task
- task runs from AppData path
- task executes at user logon

## Indicators
- files: browser_update.exe
- processes: schtasks.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
