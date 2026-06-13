# Threat Report: Office Macro Spawning Script Interpreter

## Summary
A malware write-up describes macro-enabled documents spawning script interpreters to run downloader logic.

## Observed Behaviors
- winword.exe launches wscript.exe
- wscript runs encoded script
- script reaches uncategorized domain

## Indicators
- domains: doc-preview.example
- files: document.docm
- processes: winword.exe, wscript.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
