# MVP Architecture Diagram

This document describes the current MVP architecture for the AI Threat Intel to Hunt Package Assistant.

## Component View

```mermaid
flowchart LR
    Analyst["SOC junior analyst"] --> Browser["React/Vite frontend"]
    Browser -->|HTTP JSON| API["FastAPI backend"]

    API --> Routes["API routes"]
    Routes --> Analyze["Threat report analyzer"]
    Routes --> DataAPI["Data/sample report API"]
    Routes --> PackageStore["In-memory hunt package store"]

    Analyze --> ExtractIOC["IOC extractor"]
    Analyze --> BehaviorRules["Behavior rules"]
    Analyze --> Retriever["Reference case retriever"]
    Analyze --> MitreMapper["MITRE mapper"]
    Analyze --> QuerySelector["Query template selector"]

    Retriever --> ExpectedData["evaluation/datasets/expected_hunt_packages"]
    DataAPI --> SampleReports["data/threat_reports/samples"]
    DataAPI --> AlertCatalog["data/alert_catalog/alert_types_100.json"]
    QuerySelector --> QueryTemplates["data/query_templates"]
    MitreMapper --> MitreRef["data/mitre/technique_mapping.md"]
    ExtractIOC --> ReportText["Input report text"]

    Analyze --> HuntPackage["Structured hunt package"]
    HuntPackage --> PackageStore
    HuntPackage --> Browser
```

## End-to-End Data Flow

```mermaid
sequenceDiagram
    participant U as SOC analyst
    participant F as Frontend
    participant B as FastAPI backend
    participant A as Hybrid analyzer
    participant D as Local data files
    participant S as In-memory store

    U->>F: Select sample case or paste custom report
    F->>B: POST /api/threat-reports/analyze
    B->>A: Analyze title and report content
    A->>D: Retrieve reference cases, MITRE mapping, query templates
    A->>A: Extract IOC, detect behaviors, map MITRE, choose telemetry
    A->>A: Apply context guardrails
    A->>B: Return HuntPackage object
    B->>S: Save generated package for current runtime
    B->>F: JSON hunt package
    F->>U: Show summary, behaviors, IOC, MITRE, telemetry, checklist, queries, escalation
```

## Current Runtime Components

| Component | Technology | Location | Purpose |
| --- | --- | --- | --- |
| Frontend | React, Vite, TypeScript | `frontend/` | Main UI for selecting reports, submitting analysis, and reading hunt package output. |
| Backend API | FastAPI, Pydantic | `backend/` | Exposes health, data, threat report analysis, and generated hunt package endpoints. |
| Analyzer | Python hybrid logic | `backend/app/services/threat_reports/` | Combines rules, retrieval, IOC extraction, MITRE mapping, query selection, and guardrails. |
| Data | Markdown, JSON, KQL, SPL, YAML | `data/` | Stores 100 sample reports, alert catalog, query templates, log schemas, and references. |
| Evaluation | Python runners | `evaluation/` | Runs 100-case quality gate and holdout smoke tests. |
| Store | In-memory Python store | `backend/app/services/hunt_packages/` | Keeps generated hunt packages during the running backend process. |

## Main API Calls

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/health` | Backend health check. |
| GET | `/api/data/sample-reports` | List available sample alert/report cases. |
| GET | `/api/data/sample-reports/{slug}` | Load one sample report. |
| POST | `/api/threat-reports/analyze` | Convert a report into a hunt package. |
| GET | `/api/hunt-packages` | List generated packages from the current runtime. |
| GET | `/api/hunt-packages/{package_id}` | Read one generated package from the current runtime. |

## MVP Boundaries

- The MVP uses local files and in-memory storage.
- It does not require a database yet.
- It does not call an LLM yet; the analyzer is hybrid rule-based plus retrieval.
- Query drafts are investigation starting points and must be adjusted to the real SIEM/EDR schema before production use.
