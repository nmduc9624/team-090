# Alert Report: New UID 0 User Created

## Alert Metadata
- alert_name: New UID 0 User Created
- alert_source: Linux Audit
- severity: Critical
- category: Linux Privilege
- data_type: synthetic_mvp_alert_report

## Summary
A new Linux user is created with UID 0 or root-equivalent privileges.

## Observed Behaviors
- Linux privilege-related file or account setting changes
- change is not tied to approved administration
- interactive shell or privileged command follows the change

## Indicators
- domains: none
- ips: none
- hashes: none
- files: none
- processes: bash, useradd
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
