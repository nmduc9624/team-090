# Escalation Policy

## Escalate To Senior SOC / IR When

- Privileged account, service account, domain controller, jump host, server, finance/HR/payroll asset, or executive mailbox is involved.
- Credential theft, OAuth consent, BEC/payment change, malware execution, persistence, lateral movement, C2, or exfiltration is suspected.
- Multiple users/hosts/accounts are affected.
- The action was allowed/active and cannot be quickly validated as benign.
- Required evidence is missing but potential impact is high.

## Guardrail

The assistant can recommend escalation and response actions. It must not automatically block IPs/domains, lock accounts, revoke tokens, purge mail, or isolate endpoints. Analyst approval is required.
