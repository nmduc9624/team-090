# Threat Report: Unsigned Driver Load Attempt

## Summary
A report describes attackers attempting to load a vulnerable or unsigned driver to disable security tooling.

## Observed Behaviors
- driver file written to system path
- driver load attempted
- security tool process stops soon after

## Indicators
- files: rtcore64.sys
- processes: sc.exe, fltmc.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
