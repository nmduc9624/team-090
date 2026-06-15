# Backend Summary - AI Threat Intel to Hunt Package Assistant

## Mục tiêu backend

Backend hiện tại là phần core MVP cho ứng dụng **AI Threat Intel to Hunt Package Assistant**. Nhiệm vụ chính của backend là nhận threat report ở dạng văn bản, phân tích nội dung, trích xuất hành vi/IOC, ánh xạ MITRE ATT&CK, chọn telemetry cần kiểm tra và sinh ra một hunt package để SOC analyst sử dụng.

Backend chưa dùng LLM thật ở giai đoạn này. Hệ thống đang chạy ở chế độ `mock` để kiểm chứng luồng xử lý, API contract và dữ liệu đầu ra trước khi tích hợp AI provider.

## Công nghệ sử dụng

- **Python**: ngôn ngữ chính cho backend.
- **FastAPI**: xây dựng REST API.
- **Pydantic**: định nghĩa schema request/response và validate dữ liệu.
- **Uvicorn**: chạy API server local.
- **Pytest**: kiểm thử backend core.
- **YAML/Markdown data files**: lưu log schema, query template, MITRE mapping và dữ liệu mẫu.

## Cấu trúc backend chính

```text
backend/
  app/
    main.py
    core/
      config.py
    api/routes/
      threat_reports.py
      hunt_packages.py
      data.py
    schemas/
      threat_report.py
      hunt_package.py
      data.py
    services/
      threat_reports/analyzer.py
      ioc_extraction/extractor.py
      ttp_mapping/mapper.py
      query_generation/template_loader.py
      telemetry_schemas/loader.py
      hunt_packages/store.py
  tests/unit/
  requirements.txt
  pytest.ini
```

## API đã xây dựng

### 1. Health check

```http
GET /api/health
```

Dùng để kiểm tra backend server có đang chạy không.

### 2. Phân tích threat report

```http
POST /api/threat-reports/analyze
```

Input gồm `title` và `content` của threat report. Backend sẽ trả về hunt package gồm:

- threat summary
- detected behaviors
- extracted IOCs
- MITRE ATT&CK mapping
- required telemetry
- recommended hunt queries
- analyst checklist
- escalation conditions

### 3. Lấy danh sách hunt packages

```http
GET /api/hunt-packages
```

Trả về các hunt package đã sinh trong phiên chạy hiện tại.

### 4. Lấy chi tiết một hunt package

```http
GET /api/hunt-packages/{package_id}
```

Trả về chi tiết hunt package theo ID.

### 5. Xem dữ liệu nền

```http
GET /api/data/log-schema
GET /api/data/query-templates
GET /api/data/mitre-mapping
```

Các API này giúp frontend hoặc analyst xem các dữ liệu nền mà backend đang dùng.

## Cách chạy backend

Từ thư mục backend:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Sau đó mở API docs tại:

```text
http://127.0.0.1:8000/docs
```

## Cách test API bằng PowerShell

```powershell
$body = @{
  title = "Excel malware"
  content = "excel.exe launches mshta.exe and creates Registry Run Key"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/threat-reports/analyze" `
  -ContentType "application/json" `
  -Body $body
```

## Cách chạy test

Nên chạy bằng Python trong virtual environment để tránh nhầm sang global Python:

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m pytest -q
```

Kết quả kiểm tra gần nhất: `3 passed`.

## Trạng thái hiện tại

Backend MVP đã hoàn thành phần core:

- Có REST API chạy được.
- Có schema dữ liệu rõ ràng.
- Có mock analyzer để sinh hunt package.
- Có loader cho log schema, query template và MITRE mapping.
- Có in-memory store cho hunt package.
- Có unit test cơ bản.

## Giới hạn hiện tại

- Chưa tích hợp LLM thật.
- Chưa có database, hunt package đang lưu tạm trong memory.
- Chưa có authentication/authorization.
- Chưa có frontend.
- Query sinh ra hiện ở mức template/draft, chưa tối ưu cho từng SIEM cụ thể.

## Hướng phát triển tiếp theo

1. Tích hợp AI provider để phân tích threat report tự nhiên hơn.
2. Thêm database để lưu hunt package lâu dài.
3. Xây dựng frontend cho SOC junior nhập report và xem kết quả.
4. Bổ sung evaluation để so sánh AI output với expected hunt package.
5. Chuẩn hóa query output theo Splunk, Microsoft Sentinel hoặc Elastic.
