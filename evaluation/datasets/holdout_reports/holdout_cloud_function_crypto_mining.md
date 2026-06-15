# Holdout Report: Cloud Function Crypto Mining Behavior

## Summary
A serverless cloud function begins running longer than normal and connects to a mining pool domain. Cloud audit logs show a recent environment variable change made by an access key from a new geography.

## Observed Behaviors
- cloud function runtime duration spikes above baseline
- function connects to mining pool domain
- access key from new geography updates environment variables
- workload cost increases during the same time window

## Indicators
- domains: pool-worker.example
- ips: 203.0.113.77
- files: none
- processes: none
- registry_keys: none

## Analyst Note
This holdout report is designed to test cloud workload and resource abuse reasoning beyond endpoint-focused alerts.
