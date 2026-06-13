# Threat Report: Linux Cron Persistence with Curl Download

## Summary
A Linux malware advisory describes persistence through cron entries that run curl to retrieve a shell script.

## Observed Behaviors
- cron entry created
- curl downloads shell script
- script connects to external IP

## Indicators
- domains: repo-health-check.example
- ips: 192.0.2.44
- files: /tmp/.cache.sh
- processes: cron, curl, bash

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
