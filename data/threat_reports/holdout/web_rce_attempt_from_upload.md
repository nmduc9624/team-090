# Holdout Report: Web RCE Attempt From Upload

## Summary
An attacker uploads a suspicious file to a public web application and then probes for remote code execution.

## Observed Behaviors
- executable upload is attempted through a web form
- web application receives suspicious request patterns
- remote code execution payloads are attempted after upload

## Indicators
- domains: app-upload.example
- ips: 192.0.2.44
- files: shell.aspx
- processes: none
- registry_keys: none
