# Holdout Report: Linux Reverse Shell Persistence

## Summary
A Linux host launches a shell download from cron, then opens an unexpected reverse shell to an external host.

## Observed Behaviors
- cron job is added for shell download
- bash downloads and executes a payload
- reverse shell connection is established

## Indicators
- domains: shell-sync.example
- ips: 198.51.100.88
- files: /etc/cron.d/backup-sync
- processes: bash, curl, sh
- registry_keys: none
