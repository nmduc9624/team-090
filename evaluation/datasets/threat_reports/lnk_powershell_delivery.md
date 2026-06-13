# Threat Report: Shortcut File Launching PowerShell

## Summary
A phishing campaign sends archive files containing LNK shortcuts that execute PowerShell and retrieve remote content.

## Observed Behaviors
- explorer.exe launches powershell.exe from LNK
- PowerShell downloads remote content
- archive attachment precedes execution

## Indicators
- domains: file-share-update.example
- files: invoice.lnk
- processes: explorer.exe, powershell.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
