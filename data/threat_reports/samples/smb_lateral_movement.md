# Threat Report: Lateral Movement Using Admin Shares

## Summary
The advisory describes attackers copying tools through ADMIN$ and creating remote services on adjacent Windows hosts.

## Observed Behaviors
- file copied to ADMIN$ share
- remote service created
- same account touches multiple hosts

## Indicators
- files: svc_update.exe
- processes: sc.exe, psexesvc.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
