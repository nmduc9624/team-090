# SOC Response Assistant

AI-assisted SOC post-alert investigation and response guidance system.

This project supports SOC Analyst level 1 workflows after SIEM/EDR/firewall/email security alerts have already been generated. It helps analyze logs, collect evidence, assess TP/FP, retrieve playbooks, suggest response steps, and draft incident reports for analyst approval.

## Project Structure

- `backend/`: API, incident services, AI analysis, RAG, reports, exports.
- `frontend/`: web dashboard, incident analysis views, report editor.
- `data/`: incident cases, RAG playbooks, shared docs, uploads, exports.
- `evaluation/`: datasets, runs, and metrics for prompt/RAG evaluation.
- `infra/`: Docker, database, and vector-store setup.
- `docs/`: product, architecture, API, data, and demo docs.
- `scripts/`: data, RAG, and development helper scripts.

## Guardrail

The assistant does not replace SIEM/EDR and does not automatically block IPs/domains, lock accounts, purge email, revoke tokens, or isolate endpoints. All response actions require analyst approval.
