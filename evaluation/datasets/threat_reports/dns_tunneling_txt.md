# Threat Report: DNS Tunneling Through TXT Queries

## Summary
A threat advisory reports malware using high-volume DNS TXT queries with encoded-looking subdomains for command and data transfer.

## Observed Behaviors
- many TXT queries to same base domain
- long encoded subdomains
- repeated NXDOMAIN before successful response

## Indicators
- domains: sync-api-dns.example

## Analyst Note
This is a synthetic MVP report for building and evaluating hunt-package generation. The goal is to convert behavior descriptions into telemetry checks and query drafts.
