# AI Threat Intel to Hunt Package Assistant

AI assistant for SOC Junior analysts that converts long threat reports, advisories, and malware write-ups into practical hunt packages.

The app does not detect attacks by itself and does not replace SIEM/EDR. Its goal is to help analysts quickly answer: what should we search for in our telemetry, which queries should we run, and when should we escalate?

## Core Workflow

1. Analyst uploads or pastes a threat report.
2. AI extracts threat summary, IOC, behaviors, and TTPs.
3. AI maps behaviors to available telemetry such as EDR process logs, DNS logs, proxy logs, registry logs, email logs, and auth logs.
4. AI generates a hunt checklist and query drafts.
5. Analyst reviews, edits, exports, and runs the hunt package in the real tools.

## Project Structure

- `backend/`: API and services for threat report parsing, IOC extraction, TTP mapping, query generation, and hunt packages.
- `frontend/`: UI for report upload, hunt package review, and query editing.
- `data/threat_reports/`: sample and future threat reports.
- `data/log_schemas/`: telemetry schema definitions used by the query generator.
- `data/query_templates/`: KQL/Splunk/query templates.
- `data/mitre/`: MITRE mapping references.
- `data/rag/reference/`: reference docs for RAG-assisted generation.
- `evaluation/`: test threat reports and expected hunt packages.

## Guardrail

The assistant creates investigation guidance and query drafts only. It must not claim the organization is compromised without evidence, and it must not perform containment actions automatically.
