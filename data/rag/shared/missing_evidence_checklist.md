# Missing Evidence Checklist

## Login

- User confirmation, MFA/device details, IP reputation/geo/ASN, VPN/allowlist, post-login audit, session list.

## Phishing

- Credential submission status, full URL, proxy/DNS click, endpoint browser artifact, sandbox verdict, campaign scope.

## Malware / EDR

- File hash, full command line, decoded script, source of file, EDR triage package, IOC hunt, memory/persistence artifacts.

## Outbound Connection

- Process source, allowlist/vendor confirmation, TI result, URL/TLS detail, traffic baseline, related EDR/auth/email alerts.

## Report Rule

If missing evidence prevents a firm conclusion, keep approval status as `Pending analyst approval`.
