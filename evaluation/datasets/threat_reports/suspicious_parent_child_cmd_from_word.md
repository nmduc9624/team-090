# Alert Report: Word Launches Command Shell

## Alert Metadata
- alert_name: Word Launches Command Shell
- alert_source: EDR
- severity: High
- category: Office Malware
- data_type: synthetic_mvp_alert_report

## Summary
winword.exe launches cmd.exe, which is unusual for normal document viewing.

## Observed Behaviors
- network traffic pattern differs from normal baseline
- destination, protocol, domain, or timing is suspicious
- endpoint or identity context should be correlated

## Indicators
- domains: none
- ips: none
- hashes: none
- files: suspicious_parent_child_cmd_from_word.bin
- processes: winword.exe, cmd.exe
- registry_keys: none

## Analyst Note
Synthetic MVP alert report. The expected use is to convert this alert context into a hunt package with telemetry checks, investigation steps, and escalation guidance.
