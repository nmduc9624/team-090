# Backend Core

FastAPI backend for the AI Threat Intel to Hunt Package Assistant MVP.

## Run locally

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Main endpoints

- `GET /api/health`
- `POST /api/threat-reports/analyze`
- `GET /api/data/log-schema`
- `GET /api/data/query-templates`
- `GET /api/data/mitre-mapping`
- `GET /api/hunt-packages/{package_id}`

The MVP uses a deterministic mock analyzer by default. It reads the project data files and produces a structured hunt package without requiring an LLM key.
