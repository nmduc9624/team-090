# Threat Report: Excel Malware Using mshta Persistence

## Summary
A fake invoice Excel attachment launches mshta, retrieves a remote payload, creates Registry Run Key persistence, then connects to unknown HTTPS domains.

## Observed Behaviors
- excel.exe launches mshta.exe
- mshta.exe retrieves a remote payload
- Registry Run Key is created
- host connects to newly registered or uncategorized HTTPS domain

## Indicators
- domains: invoice-checker.example
- files: invoice.xlsm
- processes: excel.exe, mshta.exe
- registry_keys: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
