# Severity Matrix

| Severity | General Criteria |
|---|---|
| Low | Alert is blocked/quarantined, asset is low criticality, no user interaction, and benign explanation is likely. |
| Medium | Suspicious activity exists but impact is unclear, no sensitive action is confirmed, or evidence is incomplete. |
| High | Successful suspicious action, user interaction, sensitive account/asset, allowed execution/outbound, or large campaign scope. |
| Critical | Confirmed compromise, credential access, active ransomware, C2/exfiltration, privileged account takeover, or multiple critical assets. |

## Incident-Specific Notes

- Login: raise severity for privileged/service accounts, MFA fatigue, successful login after failures, secrets/export/mailbox rule access.
- Phishing: raise severity for credential submission, OAuth consent, BEC/payment, malware attachment execution, executive/finance targets.
- EDR: raise severity for allowed execution, persistence, credential access, servers/jump hosts/domain controllers, lateral movement, C2.
- Network: raise severity for high bytes_out, unknown destination, DGA/beaconing/C2, critical host, related endpoint/auth alerts.
