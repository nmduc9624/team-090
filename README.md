# AI Threat Intel to Hunt Package Assistant

MVP web app for SOC junior analysts. The app converts a threat report or alert context into a practical hunt package: summary, suspicious behaviors, IOC, MITRE ATT&CK mapping, required telemetry, investigation checklist, query drafts, and escalation guidance.

The assistant does not replace SIEM/EDR and does not perform containment. It helps an analyst understand what to check next.

## MVP Status

Current MVP includes:

- React/Vite frontend.
- FastAPI backend.
- Hybrid analyzer: rule-based extraction plus retrieval from curated reference cases.
- 100 curated alert/report cases.
- 5 additional holdout reports not included in the 100-case reference set.
- Evaluation runner for the 100-case dataset.
- Holdout smoke runner for new/custom report wording.

## Project Structure

```text
backend/      FastAPI backend, analyzer, schemas, API routes
frontend/     React/Vite frontend MVP
data/         alert catalog, sample reports, query templates, MITRE references
evaluation/   datasets, runners, generated evaluation reports
infra/        placeholder for future database/docker/vector store setup
docs/         deeper project documentation
scripts/      development helper scripts
tests/        future cross-module tests
```

Root documents:

- `README.md`: full app setup and run guide.
- `DEMO_FLOW.md`: short demo script for presenting the MVP.
- `BACKEND_SUMMARY.md`: backend summary.
- `MVP_FINAL_CHECK.md`: latest verification result.

## Requirements

- Python 3.13 or compatible Python 3.x.
- Node.js 22.x or compatible Node.js.
- PowerShell on Windows.

Use `npm.cmd` instead of `npm` in PowerShell if script execution policy blocks `npm.ps1`.

## Backend Setup

```powershell
cd D:\AI20k\team-090\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run backend:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

Health check:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

## Frontend Setup

Open a second terminal:

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd install
npm.cmd run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

## Run The Full App

Use two VS Code terminals:

Terminal 1, backend:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Terminal 2, frontend:

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd run dev
```

Then open:

```text
http://127.0.0.1:5173
```

## MVP User Flow

1. Select one of the 100 alert cases in the left panel, or paste a custom report.
2. Review/edit the report title and content.
3. Click `Analyze`.
4. Review the generated hunt package:
   - summary
   - suspicious behaviors
   - IOC
   - MITRE mapping
   - required telemetry
   - investigation checklist
   - query drafts
   - escalation condition
5. Analyst uses the output as investigation guidance, not as automatic proof of compromise.

## Evaluation

Run backend unit tests:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m pytest -q
```

Build frontend:

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd run build
```

Run 100-case MVP evaluation:

```powershell
cd D:\AI20k\team-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_mvp_evaluation.py
```

Run holdout smoke test:

```powershell
cd D:\AI20k\team-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_holdout_smoke.py
```

Evaluation outputs are written to:

```text
evaluation/runs/<timestamp>
```

Runtime evaluation outputs are ignored by git.

## Stop The App

In each terminal running backend/frontend, press:

```text
Ctrl + C
```

If a port remains occupied:

```powershell
netstat -ano | Select-String ":8000"
netstat -ano | Select-String ":5173"
Stop-Process -Id <PID> -Force
```

## Current Limitation

The hybrid analyzer works well for the curated MVP dataset because it retrieves from known reference cases. For production-level quality, the next step is LLM mode with schema validation, more holdout data, analyst feedback, and persistent database storage.
