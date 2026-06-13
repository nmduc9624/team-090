# Threat Report: Credential Dumping via LSASS Access

## Summary
A report describes attackers using dump utilities to access LSASS memory on admin workstations before lateral movement.

## Observed Behaviors
- process accesses lsass.exe
- dump file written to temp directory
- admin workstation involved

## Indicators
- files: lsass.dmp
- processes: procdump.exe, rundll32.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
