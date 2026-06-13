# Threat Report: Persistence Through New Windows Service

## Summary
The report notes malware installing a service with a legitimate-looking name that runs from ProgramData.

## Observed Behaviors
- service created with suspicious binary path
- binary stored under ProgramData
- service starts automatically

## Indicators
- files: system_cache.exe
- processes: services.exe, sc.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
