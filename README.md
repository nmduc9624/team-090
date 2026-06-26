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

Required demo/evaluation artifacts:

- `docs/architecture/mvp_architecture.md`: architecture diagram, component view, and data flow.
- `docs/architecture/rag_llm_analyzer.md`: RAG/LLM analyzer architecture, config, and API notes.
- `evaluation/manual_evidence/manual_test_cases_2026-06-17.md`: 5 manual test cases with actual analyzer output.
- `docs/repo/pr_merged_evidence.md`: status and checklist for the `>= 10 merged PRs` requirement.
- `DEMO_FLOW.md`: 3-minute demo flow script. The actual video file is intentionally not included.

## Requirements

- Python 3.13 or compatible Python 3.x.
- Node.js 22.x or compatible Node.js.
- PowerShell on Windows.

Use `npm.cmd` instead of `npm` in PowerShell if script execution policy blocks `npm.ps1`.

## Backend Setup

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run backend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
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

Backend environment variables use the `APP_` prefix and can be placed in `backend/.env`:

```text
APP_APP_NAME=AI Threat Intel to Hunt Package Assistant
APP_APP_VERSION=0.1.0
APP_AI_PROVIDER=mock
APP_ANALYZER_MODE=hybrid
APP_OPENAI_API_KEY=
APP_OPENAI_CHAT_MODEL=gpt-4.1-mini
APP_OPENAI_EMBEDDING_MODEL=text-embedding-3-small
APP_VECTOR_STORE=local
APP_RAG_TOP_K=8
APP_DATA_DIR=D:\AI20k\c2-app-090\C2-App-090\data
APP_CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]
APP_FIRESTORE_ENABLED=true
APP_FIREBASE_PROJECT_ID=soc-hunt-assistant
APP_FIREBASE_REQUIRE_AUTH=false
GOOGLE_APPLICATION_CREDENTIALS=D:\AI20k\c2-app-090\C2-App-090\firebase-keys\soc-hunt-assistant.json
```

For the MVP, `APP_AI_PROVIDER=mock` and `APP_ANALYZER_MODE=hybrid` are expected. To enable RAG/LLM later, use `APP_ANALYZER_MODE=rag`, `APP_AI_PROVIDER=openai`, and fill `APP_OPENAI_API_KEY` locally in `backend/.env`. Do not commit real API keys.

Health check:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

Auth status check:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/auth/me" -UseBasicParsing
```

`APP_FIREBASE_REQUIRE_AUTH=false` keeps the backend compatible with local development while Firebase Auth is being rolled out. Set it to `true` after `users/{uid}` documents and role checks are ready.

Seed demo Firestore structure:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\scripts\seed_firestore.py
```

The seed creates demo `users`, `cases`, nested hunt workflow collections, warning/help documents, audit logs, and `discord_tickets`. Demo document IDs are prefixed with `demo_`.

## Frontend Setup

Open a second terminal:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd install
npm.cmd run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

Optional frontend environment variable:

```text
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Firebase Email/Password login is configured through `frontend/.env`:

```text
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_FIREBASE_API_KEY=<firebase-web-api-key>
VITE_FIREBASE_AUTH_DOMAIN=soc-hunt-assistant.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=soc-hunt-assistant
VITE_FIREBASE_APP_ID=<firebase-web-app-id>
```

If no API URL is provided, the frontend defaults to `http://127.0.0.1:8000`. Authenticated frontend requests attach `Authorization: Bearer <firebase_id_token>`. The current backend still accepts unauthenticated requests until the backend Firebase Admin verification phase is completed.

## Run The Full App

Use two VS Code terminals:

Terminal 1, backend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Terminal 2, frontend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd run dev
```

Optional Terminal 3, Discord bot for warning tickets:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\bot\main.py
```

The Discord bot listens locally on:

```text
http://127.0.0.1:8001
```

Required Discord variables can be placed in `backend/.env`:

```text
DISCORD_BOT_TOKEN=<your-discord-bot-token>
DISCORD_ESCALATION_CHANNEL_ID=<optional-fallback-channel-id>
DISCORD_SUPERVISOR_USER_ID=<optional-supervisor-user-id>
DISCORD_SUPERVISOR_ROLE_ID=<optional-supervisor-role-id>
```

Current warning/ticket behavior:

- A Discord ticket channel is created automatically after a hunt package is generated.
- Ticket name format is `[username]-[hunt-package-title]`, where `username` is taken from the signed-in email before `@`.
- The ticket receives only `initial_warning` immediately after analyze.
- `priority_action_warning` is sent only when the analyst confirms Priority Actions in the hunt report.
- `step_warning` is sent when the analyst starts a specific investigation step.
- `ask-for-help` is sent when the analyst asks a supervisor from a specific step or from the help action.
- `escalation_warning` is sent when the analyst confirms evidence and chooses to escalate.
- `final_summary` is sent when the analyst clicks `End case`.
- Discord tickets are retained for audit/review and are not deleted by the web app.
- Ask-for-help sends current step, completed steps, evidence available, current warning, severity, and confidence.
- Ticket mapping is stored in Firestore at `discord_tickets/{case_id}` when the ticket is created.
- Replies posted inside a Discord ticket are stored as web notifications for the original case owner at `users/{uid}/notifications`.

Mention note: `DISCORD_SUPERVISOR_ROLE_ID` must be the raw Discord role ID and the bot must have permission to mention that role. If Discord shows plain white text, check that the value is not a role name and that the bot can mention roles in the target channel.

Then open:

```text
http://127.0.0.1:5173
```

## Sample API Queries

Health check:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

List sample reports:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/data/sample-reports" -UseBasicParsing
```

Load one sample report:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/data/sample-reports/excel_mshta_persistence" -UseBasicParsing
```

Analyze a custom report:

```powershell
$body = @{
  title = "GitHub OAuth repository access"
  content = "A developer authorizes an unverified GitHub OAuth app. The app accesses private repositories, reads repository secrets metadata, creates a deploy key, and the developer logs in from a new IP address."
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/threat-reports/analyze" `
  -ContentType "application/json" `
  -Body $body
```

List generated hunt packages from current backend runtime:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/hunt-packages" -UseBasicParsing
```

## RAG/LLM Analyzer

The backend now supports analyzer modes:

```text
APP_ANALYZER_MODE=hybrid
APP_ANALYZER_MODE=rag
APP_ANALYZER_MODE=llm
```

RAG uses local knowledge sources from:

```text
data/playbooks/
data/mitre/
data/query_templates/
data/log_schemas/
data/rag/reference/
data/guardrails/
evaluation/datasets/expected_hunt_packages/
```

Rebuild the local RAG index:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/rag/reindex" -UseBasicParsing
```

Check RAG status:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/rag/status" -UseBasicParsing
```

If `APP_OPENAI_API_KEY` is empty, RAG/LLM mode falls back to the hybrid analyzer and appends RAG citations. After you fill the key locally, the same endpoint `POST /api/threat-reports/analyze` can call OpenAI for JSON generation with schema validation.

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
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m pytest -q
```

Build frontend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd run build
```

Run 100-case MVP evaluation:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_mvp_evaluation.py
```

Run holdout smoke test:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_holdout_smoke.py
```

Run RAG comparison:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_rag_comparison.py
```

Evaluation outputs are written to:

```text
evaluation/runs/<timestamp>
```

Runtime evaluation outputs are ignored by git.

Manual evaluation evidence is stored at:

```text
evaluation/manual_evidence/manual_test_cases_2026-06-17.md
```

Latest final check summary is stored at:

```text
MVP_FINAL_CHECK.md
```

## Architecture And Demo Evidence

Architecture diagram:

```text
docs/architecture/mvp_architecture.md
```

RAG/LLM analyzer architecture:

```text
docs/architecture/rag_llm_analyzer.md
```

Demo flow script:

```text
DEMO_FLOW.md
```

PR merged requirement status:

```text
docs/repo/pr_merged_evidence.md
```

Note: the requested 3-minute demo video is excluded by request. The repo also cannot truthfully claim `>= 10 merged PRs` from local files alone; the evidence/checklist file explains how to complete and verify that requirement on GitHub.

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

The hybrid analyzer works well for the curated MVP dataset because it retrieves from known reference cases. RAG/LLM mode has now been scaffolded with local indexing, retrieval, guardrails, schema validation, and OpenAI integration hooks. Production SOC usage still needs redaction, audit logging, persistent database storage, analyst feedback, and environment-specific SIEM schema validation.
