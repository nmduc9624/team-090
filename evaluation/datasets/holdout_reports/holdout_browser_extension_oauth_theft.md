# Holdout Report: Browser Extension OAuth Token Theft

## Summary
A browser extension installed by a user begins reading mail and drive permissions through OAuth tokens. The extension publisher is unknown and the activity starts after the user clicks a software productivity prompt.

## Observed Behaviors
- user grants OAuth permission to unknown browser extension
- extension reads mailbox and cloud drive metadata
- access comes from a new application ID not seen before
- user reports unexpected consent prompt in browser

## Indicators
- domains: extension-sync.example
- files: productivity_helper.crx
- processes: chrome.exe
- registry_keys: none

## Analyst Note
This holdout report is not part of the 100 reference alert cases. It should still produce a useful hunt package by matching related OAuth, SaaS, browser, and cloud audit behavior.
