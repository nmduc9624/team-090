# Threat Report: WMI Event Subscription Persistence

## Summary
A malware family persists through WMI event filters and consumers that execute scripts when users log in.

## Observed Behaviors
- WMI event filter created
- WMI consumer executes script
- script path under ProgramData

## Indicators
- files: updater.vbs
- processes: wmic.exe, scrcons.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
