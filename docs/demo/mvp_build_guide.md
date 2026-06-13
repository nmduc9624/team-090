# Hướng Dẫn Xây Dựng MVP

## Dự án

**AI Threat Intel to Hunt Package Assistant**

MVP giúp SOC Junior dán hoặc upload một threat report, sau đó AI chuyển report thành hunt package gồm summary, IOC/TTP, telemetry cần kiểm tra, query mẫu, checklist điều tra và điều kiện escalation.

## Mục tiêu MVP

MVP cần demo được luồng:

```text
Threat report
→ AI phân tích nội dung
→ Trích xuất behavior / IOC / TTP
→ Map sang telemetry có sẵn
→ Sinh query draft
→ Sinh hunt checklist
→ Export hunt package
```

AI không tự kết luận tổ chức đã bị compromise và không tự thực hiện containment. Output chỉ là hướng dẫn điều tra để analyst review.

## 1. Backend MVP

Khuyến nghị dùng **FastAPI**.

### API tối thiểu

```text
POST /api/threat-reports/analyze
GET  /api/hunt-packages/{id}
GET  /api/data/log-schema
GET  /api/data/query-templates
```

### Service cần có

```text
backend/app/services/threat_reports
backend/app/services/ioc_extraction
backend/app/services/ttp_mapping
backend/app/services/query_generation
backend/app/services/hunt_packages
backend/app/services/telemetry_schemas
```

### Backend flow

```text
1. Nhận threat report text.
2. Load log schema từ data/log_schemas/log_source_schema.yml.
3. Load MITRE mapping từ data/mitre/technique_mapping.md.
4. Load query templates từ data/query_templates.
5. Gửi report + context vào LLM.
6. Nhận structured JSON hunt package.
7. Trả kết quả về frontend.
```

## 2. AI Output Schema

AI nên trả về JSON theo schema:

```json
{
  "threat_summary": "",
  "key_behaviors": [],
  "ioc": {
    "domains": [],
    "ips": [],
    "hashes": [],
    "files": [],
    "processes": [],
    "registry_keys": []
  },
  "mitre_mapping": [],
  "required_telemetry": [],
  "hunt_checklist": [],
  "query_drafts": [
    {
      "name": "",
      "platform": "KQL | SPL | generic",
      "query": "",
      "purpose": ""
    }
  ],
  "correlation_logic": "",
  "escalation_condition": "",
  "analyst_notes": ""
}
```

Schema tham chiếu nằm ở:

```text
data/rag/reference/hunt_package_output_schema.md
```

## 3. Prompt MVP

Prompt chính nằm ở:

```text
backend/prompts/threat_report_to_hunt_package_prompt.md
```

Nguyên tắc prompt:

```text
- Không khẳng định hệ thống đã bị tấn công nếu chưa có evidence.
- Trích xuất behavior và IOC từ report.
- Map behavior sang telemetry có sẵn.
- Sinh query draft dựa trên schema và template.
- Ghi rõ missing telemetry nếu thiếu.
- Action/escalation chỉ là khuyến nghị cho analyst review.
```

## 4. Frontend MVP

Khuyến nghị dùng **React**.

### Màn hình tối thiểu

```text
1. Threat Report Input
   - Textarea để paste report
   - Upload file .md / .txt
   - Button Analyze

2. Hunt Package Result
   - Threat Summary
   - Key Behaviors
   - IOC
   - MITRE Mapping
   - Required Telemetry
   - Hunt Checklist
   - Escalation Condition

3. Query Draft Viewer
   - Tabs: KQL / SPL / Generic
   - Copy query
   - Export Markdown
```

### Frontend folder

```text
frontend/src/features/threat_reports
frontend/src/features/hunt_packages
frontend/src/features/query_builder
```

## 5. Data MVP

Data đã có sẵn:

```text
data/threat_reports/samples
evaluation/datasets/threat_reports
evaluation/datasets/expected_hunt_packages
data/log_schemas
data/query_templates
data/mitre
data/rag/reference
```

Số lượng hiện tại:

```text
20 threat reports
20 expected hunt packages
1 log source schema
10 query templates
30 MITRE/TTP mappings
20 IOC pattern references
```

Inventory:

```text
docs/data/mvp_data_inventory.md
```

## 6. Evaluation MVP

Tạo script:

```text
scripts/evaluation/run_eval.py
```

Script sẽ:

```text
1. Đọc từng report trong evaluation/datasets/threat_reports.
2. Gọi API hoặc service analyze.
3. So sánh output với expected_hunt_packages.
4. Tính điểm theo các nhóm:
   - threat summary
   - key behaviors
   - IOC
   - MITRE mapping
   - required telemetry
   - hunt checklist
   - escalation condition
```

MVP chưa cần chấm quá phức tạp. Có thể dùng overlap keyword / exact field match trước.

## 7. Thứ Tự Triển Khai

```text
Bước 1: Scaffold FastAPI backend.
Bước 2: Tạo endpoint POST /api/threat-reports/analyze.
Bước 3: Load data context: log schema, MITRE mapping, query templates.
Bước 4: Gọi LLM và trả structured JSON.
Bước 5: Test backend với 20 threat reports.
Bước 6: Làm React UI input + result.
Bước 7: Thêm copy/export Markdown cho hunt package.
Bước 8: Viết evaluation script.
```

## 8. Tiêu Chí MVP Hoàn Thành

MVP được xem là đạt khi:

```text
- Analyst paste được một threat report.
- App sinh được hunt package JSON hợp lệ.
- Output có behavior, IOC, telemetry, checklist và query draft.
- Analyst copy/export được query hoặc hunt package.
- Chạy được ít nhất 20 sample reports.
- Có evaluation đơn giản so với expected output.
```

## 9. Guardrail

```text
- Không tự chạy query trên hệ thống thật.
- Không tự block domain/IP.
- Không tự isolate host.
- Không tự disable account.
- Không khẳng định compromise nếu chỉ có threat report.
- Mọi query và escalation cần analyst review.
```
