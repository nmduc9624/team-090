# Alert Report: Linux Crypto Miner Process

## Alert Metadata
- alert_name: Linux Crypto Miner Process
- alert_source: Linux EDR
- severity: High
- category: Malware
- data_type: synthetic_mvp_alert_report

## Summary
A Linux host runs a process with crypto-mining behavior and mining pool connections.

## Observed Behaviors
- malware-like process or detection appears on endpoint
- remediation status or process behavior needs validation
- network, persistence, or file activity may follow

## Indicators
- domains: none
- ips: none
- hashes: none
- files: linux_crypto_miner_process.bin
- processes: malware.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
