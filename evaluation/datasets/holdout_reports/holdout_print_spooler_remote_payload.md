# Holdout Report: Print Spooler Remote Payload Staging

## Summary
A workstation receives unexpected print spooler activity, then spoolsv.exe writes a DLL into a temporary path and launches rundll32.exe. The host later connects to a rare external domain.

## Observed Behaviors
- spoolsv.exe writes DLL file to temporary directory
- rundll32.exe loads the newly written DLL
- host connects to a rare external domain after DLL load
- user does not normally perform printer administration

## Indicators
- domains: spool-update.example
- files: spoolcache.dll
- processes: spoolsv.exe, rundll32.exe
- registry_keys: none

## Analyst Note
This holdout report tests whether the assistant can combine suspicious service behavior, DLL execution, and outbound network activity.
