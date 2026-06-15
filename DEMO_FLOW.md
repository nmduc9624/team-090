# MVP Demo Flow

This is a short demo script for presenting the AI Threat Intel to Hunt Package Assistant MVP.

## Goal

Show that a SOC junior analyst can paste or select an alert/report and quickly receive a structured hunt package that explains what to investigate next.

## Demo Setup

Open two VS Code terminals.

Terminal 1:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Terminal 2:

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

## Demo Script

1. Start at the main screen.
   - Point out the left panel with 100 sample alert cases.
   - Explain that these cases cover EDR, identity, email, cloud, DNS, proxy, firewall, web, Linux, Kubernetes, and container alerts.

2. Pick a simple endpoint case.
   - Example: `Excel Mshta Persistence`.
   - Click the case and show that the report content loads into the editor.
   - Click `Analyze`.
   - Explain the generated output: behaviors, IOC, MITRE mapping, telemetry, checklist, queries, and escalation.

3. Pick a non-endpoint case.
   - Example: `Password Spray Against Many Users` or `Cloud Storage Bucket Made Public`.
   - Click `Analyze`.
   - Explain that the hybrid analyzer can handle identity/cloud context, not only process logs.

4. Paste a custom holdout-style report.
   - Use one of the holdout reports in `evaluation/datasets/holdout_reports`.
   - Explain that this report is not one of the 100 curated reference cases.
   - Click `Analyze` and show that the app still produces a schema-valid hunt package.

5. Show evaluation evidence.
   - Open `MVP_FINAL_CHECK.md`.
   - Mention that backend tests, frontend build, 100-case evaluation, and holdout smoke test were run.

## Suggested Demo Case

Use this if you need a quick custom report:

```text
# Demo Report: Helpdesk Tool Suspicious Remote Session

## Summary
A remote support tool starts an unattended session on a finance workstation after hours. The session launches PowerShell and compresses documents before uploading traffic appears in proxy logs.

## Observed Behaviors
- remote support tool starts unattended session after hours
- powershell.exe launches from the support tool process
- sensitive documents are archived before upload
- proxy logs show large outbound upload to unfamiliar domain

## Indicators
- domains: support-transfer.example
- files: finance_docs.zip
- processes: supportagent.exe, powershell.exe, 7z.exe
- registry_keys: none
```

## Key Message

The app does not replace SOC tools. It helps analysts turn long or unclear alert context into a concrete investigation plan faster.
