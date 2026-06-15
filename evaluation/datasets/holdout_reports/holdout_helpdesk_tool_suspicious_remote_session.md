# Holdout Report: Helpdesk Tool Suspicious Remote Session

## Summary
A remote support tool starts an unattended session on a finance workstation after hours. The session launches PowerShell and compresses documents before uploading traffic appears in proxy logs.

## Observed Behaviors
- remote support tool starts unattended session after hours
- powershell.exe launches from the support tool process
- sensitive documents are archived before upload
- proxy logs show large outbound upload to unfamiliar domain

## Indicators
- domains: support-transfer.example
- files: finance_docs.zip
- processes: supportagent.exe, powershell.exe, 7z.exe
- registry_keys: none

## Analyst Note
This holdout report tests whether the assistant can guide investigation for legitimate tooling used in a suspicious way.
