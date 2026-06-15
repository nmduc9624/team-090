# Frontend MVP

React + Vite frontend for the AI Threat Intel to Hunt Package Assistant MVP.

## Run locally

Open backend in terminal 1:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open frontend in terminal 2:

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd install
npm.cmd run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

Backend API URL:

```text
http://127.0.0.1:8000
```

## MVP flow

1. Select one of the 100 sample alert cases.
2. Review or edit the report content.
3. Click Analyze.
4. Review the generated hunt package: summary, behaviors, IOC, MITRE mapping, telemetry, checklist, query drafts, and escalation condition.

## Build

```powershell
npm.cmd run build
```
