# End-to-End Test Flow - 27/6

Muc tieu: kiem tra toan bo app tu login, analyze report, tao Discord ticket, ask for help, supervisor reply, notification, case history, den AI runtime log.

## 1. Chay he thong

Chay backend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Chay frontend:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090\frontend
npm.cmd run dev
```

Chay Discord bot:

```powershell
cd D:\AI20k\c2-app-090\C2-App-090
.\backend\.venv\Scripts\python.exe .\bot\main.py
```

Kiem tra backend:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing
```

Ket qua dung:

```text
status = ok
firestore_enabled = true
firebase_project_id = soc-hunt-assistant
```

## 2. Dang nhap

Mo frontend tai URL Vite in ra, thuong la:

```text
http://127.0.0.1:5173
```

Dang nhap bang:

```text
junior@example.com
```

Can kiem tra:

```text
Khong bi 401
Khong bi failed to fetch
Man hinh app hien thi sau khi login
```

## 3. Tao case moi

Thao tac:

```text
Chon 1 sample alert hoac paste report moi
Bam Analyze
```

Can kiem tra:

```text
Hunt package duoc sinh ra
Discord tu tao ticket
Ten ticket co dang junior-[ten-hunt-package]
Firestore co cases/{case_id}
Firestore co discord_tickets/{case_id}
```

## 4. Kiem tra hunt package

Kiem tra cac muc sau tren giao dien:

```text
Summary
Risk Explanation
Key Behaviors
Priority Actions
Investigation Flow
Timeline / Attack Path
Case Activity
IOC
MITRE
Telemetry
Checklist
False Positive Checks
Recommended Response
Query Drafts
Escalation
```

Can kiem tra them:

```text
Khong con nut Solved
Khong hien High confidence/100%
```

## 5. Confirm priority actions

Thao tac:

```text
Bam Confirm priority actions
```

Can kiem tra:

```text
Discord ticket nhan priority_action_warning
Firestore case status thanh in_progress
Firestore co priority_actions_confirmed = true
Button doi trang thai thanh Priority warning sent
```

## 6. Start investigation step

Thao tac:

```text
Bam Start this step o mot investigation step
```

Can kiem tra:

```text
Discord ticket nhan step_warning
Button doi thanh Started
Firestore step status = started
Firestore case co active_step_id
```

## 7. Ask for help

Thao tac:

```text
Bam Ask for help o step dang xu ly
Xem modal tom tat tinh hinh
Nhap cau hoi
Bam Submit
```

Can kiem tra:

```text
Discord ticket co ask-for-help
Bot tag supervisor dung role/user
Firestore case status = needs_help
Firestore co cases/{case_id}/help_requests
```

## 8. Supervisor reply

Thao tac:

```text
Trong Discord ticket, supervisor reply mot cau tra loi
Quay lai web app
```

Can kiem tra:

```text
Panel Supervisor replies co notification moi
Notification hien author, message, case title va link Open in Discord
Firestore co users/{uid}/notifications
Firestore co cases/{case_id}/notifications
```

## 9. Mo case tu notification

Thao tac:

```text
Bam vao case title trong notification
```

Can kiem tra:

```text
App mo lai dung case
Hunt package cu hien thi lai
Case Activity co them notification/reply
```

## 10. Escalation

Thao tac:

```text
Bam Send escalation warning
```

Can kiem tra:

```text
Discord ticket nhan escalation_warning
Firestore case status = escalated
Firestore audit_logs co escalation_warning
```

## 11. End case

Thao tac:

```text
Bam End case
```

Can kiem tra:

```text
Discord ticket nhan final_summary
Firestore case status = ended
Discord ticket van con, khong bi xoa
```

## 12. Recent cases

Thao tac:

```text
Mo tab Recent cases
Tim case vua xu ly
Bam mo case
```

Can kiem tra:

```text
Case cu mo lai duoc
Hunt package cu mo lai duoc
Status hien dung: ended/escalated/needs_help/in_progress
Unread notification hien dung neu co
Case Activity co timeline gom analyze, warning, help request, notification, escalation, final summary
```

## 13. Notification read/unread

Thao tac:

```text
Bam nut X de dismiss notification
```

Can kiem tra:

```text
Notification bien mat khoi panel unread
Firestore notification read = true
```

## 14. AI runtime log

Kiem tra file:

```text
D:\AI20k\c2-app-090\C2-App-090\.ai-log\runtime.jsonl
```

Can co event:

```text
analyze_requested
ai_generation_completed
discord_ticket_requested
```

Can kiem tra:

```text
Khong log raw report content
Chi log report_content_hash va report_content_length
Co latency_ms
Co package_id
Co severity_hint
```

## 15. Refresh va session

Thao tac:

```text
Refresh frontend
```

Can kiem tra:

```text
Neu Firebase con session thi app vao lai user junior@example.com
Neu logout thi quay ve login
Recent cases van lay lai duoc tu Firestore
Khong mat Discord ticket
```

## 16. Dieu kien pass

Flow duoc coi la pass khi:

```text
Login thanh cong
Analyze sinh hunt package
Discord ticket duoc tao va khong bi xoa
Priority warning gui duoc
Step warning gui duoc
Ask for help gui duoc va tag supervisor
Supervisor reply ve web notification
Escalation warning gui duoc
End case gui final summary
Case history mo lai duoc
Case Activity co timeline
AI runtime log co event va khong co raw report content
```
