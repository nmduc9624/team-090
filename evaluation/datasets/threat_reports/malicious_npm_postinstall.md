# Threat Report: Malicious NPM Postinstall Script

## Summary
The report describes a typosquatted npm package that runs postinstall commands to download a second-stage script.

## Observed Behaviors
- node.exe launches shell during npm install
- postinstall downloads script
- script writes startup file

## Indicators
- domains: pkg-verify.example
- files: postinstall.js, update.cmd
- processes: node.exe, npm.exe, cmd.exe

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
