# Threat Report: Browser Credential Store Theft

## Summary
Threat intel describes stealers reading browser credential databases and exfiltrating compressed data.

## Observed Behaviors
- process reads browser credential store
- archive file created
- small HTTPS POST to unknown domain

## Indicators
- domains: account-sync-check.example
- files: Login Data, browser_cache.zip
- processes: stealer.exe, 7z.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
