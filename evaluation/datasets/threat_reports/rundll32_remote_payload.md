# Threat Report: Rundll32 Loading Remote Payload

## Summary
The advisory describes abuse of rundll32 to load DLL payloads from user-writable directories after browser download.

## Observed Behaviors
- browser downloads DLL
- rundll32.exe loads DLL from Downloads
- outbound network follows execution

## Indicators
- domains: cdn-driver-update.example
- files: driver_update.dll
- processes: chrome.exe, rundll32.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
