# Alert Report: Risky OAuth App Granted Tenant Permissions

## Alert Metadata
- alert_name: Risky OAuth App Granted Tenant Permissions
- alert_source: Cloud Audit
- severity: Critical
- category: Cloud Identity
- data_type: synthetic_mvp_alert_report

## Summary
A user grants an unverified OAuth application broad tenant permissions.

## Observed Behaviors
- cloud identity permission or consent changes unexpectedly
- actor or application is unusual for the tenant
- privileged cloud activity follows the change

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: none
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
