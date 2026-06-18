# Holdout Report: Suspicious GitHub OAuth App Accesses Private Repositories

## Summary
A developer authorizes an unverified GitHub OAuth app from a public issue. The app accesses private repositories, reads repository secrets metadata, creates a deploy key, and the developer logs in from a new IP address.

## Observed Behaviors
- public GitHub issue contains link to install an unverified OAuth app
- developer grants repository read permissions to the OAuth app
- OAuth app accesses multiple private repositories
- repository secrets metadata is read shortly after authorization
- new deploy key is created on an internal repository
- developer login occurs from unfamiliar IP address

## Indicators
- domains: github-productivity-review.example
- urls: https://github-productivity-review.example/install
- ips: 203.0.113.188
- files: none
- processes: none
- registry_keys: none
