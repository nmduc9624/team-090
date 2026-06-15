# Holdout Report: Database Dump Staged To Temporary Share

## Summary
A database administrator account runs an export job outside the maintenance window. A large dump file is created and copied to a temporary network share accessed by a workstation that normally has no database duties.

## Observed Behaviors
- database export job runs outside approved window
- large dump file is created and copied to temporary share
- workstation accesses the share shortly after export
- user account recently logged in from unusual VPN source

## Indicators
- files: customer_dump_2026.zip
- ips: 203.0.113.78
- domains: none
- processes: sqlcmd.exe, 7z.exe
- registry_keys: none

## Analyst Note
This holdout report tests data staging and account context without using one of the exact 100 reference scenarios.
