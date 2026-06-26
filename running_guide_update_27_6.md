# huong dan chay project team-090 - update 27/6

Thu muc project chinh:

```powershell
D:\AI20k\c2-app-090\C2-App-090
```

## 1. dieu kien truoc khi chay

Can co cac thanh phan sau:

```text
backend/.venv da cai dependencies
frontend/node_modules da cai dependencies
backend/.env da cau hinh Firebase, Firestore, OpenAI/RAG va Discord neu dung bot
firebase-keys/soc-hunt-assistant.json ton tai neu dung Firestore
```

Kiem tra nhanh file service account:

```powershell
Test-Path "D:\AI20k\c2-app-090\C2-App-090\firebase-keys\soc-hunt-assistant.json"
```

Ket qua dung:

```text
True
```

## 2. chay backend

Mo terminal thu nhat trong VS Code:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Kiem tra backend:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

Ket qua mong doi:

```text
status: ok
analyzer_mode: rag hoac hybrid
firestore_enabled: True
firebase_project_id: soc-hunt-assistant
```

Neu da bat auth bat buoc:

```env
APP_FIREBASE_REQUIRE_AUTH=true
```

Thi goi API truc tiep khong co Firebase token se bi `401 Unauthorized`. Day la dung.

## 3. chay frontend

Mo terminal thu hai:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd run dev
```

Mo app tai URL Vite in ra, thuong la:

```text
http://127.0.0.1:5173
```

Neu port 5173 dang ban, Vite co the tu chuyen sang 5174. Khi do mo dung URL terminal in ra.

## 4. dang nhap frontend

Sau khi mo frontend, can dang nhap truoc khi dung app.

Tai khoan test hien tai:

```text
junior@example.com
```

Luu y: Firebase co the giu session dang nhap cu trong browser. Neu mo app thay da vao san bang `junior@example.com`, do la session cu cua trinh duyet, khong phai backend tu dang nhap.

Neu muon hien lai man hinh login:

```text
Bam Logout tren frontend
Hoac mo incognito/private window
Hoac xoa site data cua http://127.0.0.1:5173
```

## 5. chay Discord bot

Mo terminal thu ba:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\bot\main.py
```

Bot se lang nghe local tai:

```text
http://127.0.0.1:8001
```

Can cau hinh trong `backend/.env`:

```env
DISCORD_BOT_TOKEN=<discord-bot-token>
DISCORD_ESCALATION_CHANNEL_ID=<optional-fallback-channel-id>
DISCORD_SUPERVISOR_USER_ID=<optional-supervisor-user-id>
DISCORD_SUPERVISOR_ROLE_ID=<optional-supervisor-role-id>
```

Neu tag role supervisor:

```env
DISCORD_SUPERVISOR_USER_ID=
DISCORD_SUPERVISOR_ROLE_ID=<role-id-so>
```

`DISCORD_SUPERVISOR_ROLE_ID` phai la ID so cua role, khong phai ten role. Vi du dung:

```text
123456789012345678
```

Khong dung:

```text
@supervisor
supervisor
<@supervisor>
```

Bot can co quyen:

```text
Create Channels
Send Messages
Embed Links
Read Message History
Mention Roles
Read Message Content
```

## 6. flow dung app hien tai

1. Chay backend.
2. Chay frontend.
3. Chay bot neu can Discord ticket/warning.
4. Mo frontend va dang nhap.
5. Chon sample case hoac paste report moi.
6. Bam `Analyze`.
7. App sinh hunt package.
8. Bot tao Discord ticket neu bot dang chay.

Ten ticket hien tai co dang:

```text
[username]-[ten-hunt-package]
```

Vi du user dang nhap la:

```text
junior@example.com
```

Thi ticket se co dang:

```text
junior-cloud-iam-admin-policy-attached
```

Ticket se khong bi xoa tu web app nua. Ticket duoc giu lai tren Discord de audit/review.

## 7. cac warning va action trong hunt package

Sau khi hunt package duoc sinh:

```text
initial_warning duoc gui vao Discord ticket ngay khi ticket duoc tao
```

Trong frontend:

```text
Confirm priority actions -> gui priority_action_warning, case status thanh in_progress
Start this step -> gui step_warning, step status thanh started
Ask for help -> gui ask-for-help vao Discord, case status thanh needs_help
Send escalation warning -> gui escalation_warning, case status thanh escalated
End case -> gui final_summary, case status thanh ended
```

Nút `Solved` da bi bo. Khong con logic xoa Discord ticket.

## 8. supervisor reply ve web notification

Khi junior bam `Ask for help`, bot tag supervisor trong Discord ticket.

Neu supervisor reply trong ticket Discord, bot se ghi notification ve Firestore cho dung user tao case:

```text
users/{uid}/notifications
cases/{case_id}/notifications
```

Frontend se hien reply trong panel:

```text
Supervisor replies
```

Trong notification co:

```text
ten nguoi reply
noi dung reply
case title/case id
link Open in Discord
nut dismiss
```

## 9. case history

Frontend da co tab:

```text
Recent cases
```

Dung de:

```text
xem case da tao
xem status: open, in_progress, needs_help, escalated, ended
xem unread notification theo case
mo lai hunt package cu
xem Case Activity timeline
```

Backend API lien quan:

```text
GET /api/cases
GET /api/cases/{case_id}
```

## 10. Firestore dang luu gi

Firestore hien luu cac nhom chinh:

```text
users/{uid}
users/{uid}/notifications
cases/{case_id}
cases/{case_id}/hunt_packages/{package_id}
cases/{case_id}/priority_actions/{action_id}
cases/{case_id}/steps/{step_id}
cases/{case_id}/warnings
cases/{case_id}/help_requests
cases/{case_id}/audit_logs
cases/{case_id}/notifications
discord_tickets/{case_id}
```

## 11. RAG status va rebuild index

Kiem tra RAG status:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/rag/status" -UseBasicParsing
```

Rebuild RAG index:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/rag/reindex" -UseBasicParsing
```

## 12. AI runtime log hien tai

App hien co AI runtime log dang JSONL fallback:

```text
.ai-log/runtime.jsonl
```

Logger ghi:

```text
analyze_requested
ai_generation_completed
ai_generation_failed
discord_ticket_requested
```

Logger khong ghi raw report content, chi ghi:

```text
report_content_hash
report_content_length
latency_ms
package_id
severity_hint
query_draft_count
mitre_mapping_count
ioc counts
```

## 13. MLflow neu muon chay that

Hien tai project co JSONL AI log. Neu muon dung MLflow UI that, can cai `mlflow` va them code MLflow logger neu chua co.

Cai MLflow:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m pip install mlflow
```

Them vao `backend/requirements.txt`:

```text
mlflow>=2.14,<3
```

Them vao `backend/.env`:

```env
APP_MLFLOW_ENABLED=true
MLFLOW_TRACKING_URI=http://127.0.0.1:5000
MLFLOW_EXPERIMENT_NAME=soc-hunt-assistant
```

Chay MLflow server:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\mlflow.exe server `
  --backend-store-uri sqlite:///mlflow.db `
  --default-artifact-root ./mlruns `
  --host 127.0.0.1 `
  --port 5000
```

Mo UI:

```text
http://127.0.0.1:5000
```

Luu y: neu chua them code MLflow logger vao `ai_logger.py`, MLflow server se chay nhung chua co run duoc ghi vao UI.

## 14. test nhanh

Backend tests:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m pytest
```

Frontend build:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd run build
```

Bot compile:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe -m py_compile .\bot\main.py
```

AI logger test:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m pytest tests\unit\test_runtime_ai_logger.py -q
```

## 15. loi thuong gap

### frontend bao failed to fetch

Kiem tra backend:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

Neu backend chua chay hoac port sai, frontend se failed to fetch.

### API bao 401 Unauthorized

Neu da bat:

```env
APP_FIREBASE_REQUIRE_AUTH=true
```

Thi can dang nhap frontend truoc. API goi truc tiep khong co Firebase token se bi 401.

### frontend tu dang nhap san

Do Firebase Auth luu session trong browser. Cach xu ly:

```text
Bam Logout
Hoac mo incognito
Hoac xoa site data cua 127.0.0.1:5173
```

### backend khong vao duoc venv

Neu PowerShell chan script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Hoac chay truc tiep khong can activate:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### loi did not find executable at C:\Python313\python.exe

Thuong do copy project kem `.venv` bi hong. Tao lai venv:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
Remove-Item -Recurse -Force .venv
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### bot khong tag duoc supervisor

Kiem tra:

```text
DISCORD_SUPERVISOR_ROLE_ID phai la ID so
Bot co quyen Mention Roles
Role co the duoc mention hoac bot co quyen mention role
Da restart bot sau khi sua .env
```

### supervisor reply khong ve web

Kiem tra:

```text
Bot dang chay
Bot co Read Message Content
Reply nam trong channel thuoc category Tickets
Channel topic co Case ID
Backend Firestore dang enabled
Frontend dang login dung user tao case
```

## 16. dung app

Tai moi terminal dang chay backend, frontend, bot hoac MLflow:

```text
Ctrl + C
```
