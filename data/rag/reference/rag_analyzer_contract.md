# RAG Analyzer Contract

The RAG analyzer receives a threat report or alert context and must return a single hunt package JSON object.

Required fields:

- `package_id`
- `report_title`
- `threat_summary`
- `key_behaviors`
- `ioc`
- `mitre_mapping`
- `required_telemetry`
- `hunt_checklist`
- `query_drafts`
- `correlation_logic`
- `escalation_condition`
- `analyst_notes`

Operational rules:

- Prefer retrieved playbook, query template, telemetry schema, MITRE, and expected case context over general model knowledge.
- Use the deterministic hybrid analyzer as baseline when retrieved context is weak.
- If a field is uncertain, keep the baseline field rather than inventing a new one.
- Query drafts are drafts and must be validated against the real SIEM/EDR schema.
- Always mention analyst validation in `analyst_notes`.

Context guardrail examples:

- SaaS OAuth reports should not include Windows registry persistence, mshta, or LSASS unless endpoint evidence is explicit.
- GitHub/GitLab OAuth reports should focus on repository access, deploy keys, secrets metadata, OAuth scopes, and developer login context.
- Linux cron persistence should not include Windows Registry Run Key techniques.
- Password spray should focus on auth telemetry and should not imply malware process execution without evidence.
