# Threat Report: OAuth Consent Phishing and Mail Access

## Summary
Threat intel reports phishing pages that trick users into granting OAuth apps access to mailbox data without using malware.

## Observed Behaviors
- new OAuth consent granted
- app requests Mail.Read or Mail.ReadWrite
- mailbox access follows consent

## Indicators
- domains: login-review-app.example

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
