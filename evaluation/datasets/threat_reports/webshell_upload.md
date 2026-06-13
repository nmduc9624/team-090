# Threat Report: Webshell Uploaded to Public Web Server

## Summary
A CVE advisory describes exploitation that uploads a webshell under the web root, then runs OS commands through the web worker process.

## Observed Behaviors
- new script file appears in web root
- web worker spawns command shell
- outbound connection from server

## Indicators
- domains: drop-zone.example
- files: shell.aspx, cmd.jsp
- processes: w3wp.exe, cmd.exe, bash

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
