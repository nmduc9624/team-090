# Threat Report: MFA Push Fatigue Followed by OAuth Access

## Summary
The report describes attackers repeatedly triggering MFA prompts before accessing cloud mail APIs.

## Observed Behaviors
- many MFA prompts in short window
- one approval follows repeated denials
- cloud mail API access occurs after approval

## Indicators
- ips: 203.0.113.88

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
