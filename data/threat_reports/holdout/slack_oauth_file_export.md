# Holdout Report: Suspicious Slack OAuth App Exports Files

## Summary
A user approves a Slack productivity app after receiving an external workspace invite. The app reads channel history and exports files from private channels, then the same user logs in from an unfamiliar IP address.

## Observed Behaviors
- external Slack workspace sends app installation link to internal user
- user grants OAuth permissions to an unverified productivity app
- OAuth app reads channel history and exports files from private channels
- user login occurs from unfamiliar IP address shortly before app activity
- large file export activity occurs outside normal working hours

## Indicators
- domains: slack-productivity-sync.example
- urls: https://slack-productivity-sync.example/install
- ips: 203.0.113.144
- files: private_channel_export.zip
- processes: none
- registry_keys: none
