# Architecture Overview

```text
React Frontend
  |
  v
FastAPI Backend
  |-- Threat Report Service
  |-- IOC Extraction Service
  |-- TTP / MITRE Mapping Service
  |-- Telemetry Schema Service
  |-- Query Generation Service
  |-- Hunt Package Service
  |
  v
PostgreSQL / File Storage
  |
  v
LLM API + optional RAG reference docs
```

## MVP Flow

```text
Threat report input
→ AI extracts summary, behaviors, IOC, TTP
→ Backend loads available telemetry schema
→ AI generates hunt checklist and query drafts
→ Analyst reviews and exports hunt package
```

## Later Enhancements

- Store reports and packages in PostgreSQL.
- Use pgvector/Chroma for MITRE, query examples, and detection engineering references.
- Add versioning and analyst feedback for generated hunt packages.
