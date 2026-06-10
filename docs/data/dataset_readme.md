# SOC Response Assistant Dataset

This folder contains the normalized dataset generated from the current DOCX data files.

## Contents

- `data/cases/*.jsonl`: normalized incident cases.
- `data/rag/playbooks/*.md`: 12 playbooks, split by incident type and purpose.
- `data/rag/shared/*.md`: 5 shared RAG documents.
- `manifest.json`: schema and validation metadata.
- `docs/validation_report.md`: human-readable validation report.

## Guardrail

The assistant supports post-alert investigation and response guidance. It must not automatically block IPs/domains, lock accounts, purge email, revoke tokens, or isolate endpoints. All response actions are recommendations pending analyst approval.

## Counts

- Incident cases: 120
- Playbooks: 12
- Shared RAG docs: 5
