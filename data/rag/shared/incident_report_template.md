# Incident Report Template

## Required Sections

1. Incident Title
2. Executive Summary
3. Timeline
4. Affected Assets
5. Evidence from Log
6. AI Inference
7. TP/FP Assessment
8. Suggested Severity
9. Recommended Actions
10. Missing Evidence
11. Approval Status

## Output Schema

| Trường output | Nội dung chuẩn |
| --- | --- |
| incident_type | Một trong 4 loại: login, phishing, malware/EDR, outbound. |
| summary | Tóm tắt ngắn gọn bằng tiếng Việt, dựa trên evidence. |
| timeline | Danh sách event theo timestamp. |
| affected_assets | User, host, mailbox, file, IP/domain, app/server liên quan. |
| evidence_from_log | Bằng chứng trực tiếp từ log/alert. |
| ai_inference | Suy luận có kiểm soát, không viết như kết luận tuyệt đối. |
| tp_fp_assessment | True positive / false positive / inconclusive kèm lý do. |
| suggested_severity | Low/Medium/High/Critical. |
| recommended_next_step | Bước tiếp theo: cần thêm log, chuyển response, monitor hoặc analyst review. |
| missing_evidence | Danh sách bằng chứng còn thiếu. |
| approval_status | Pending analyst approval. |

## Writing Rules

- Evidence from Log must contain only facts present in the raw log/alert.
- AI Inference must use cautious language and explain assumptions.
- Recommended Actions must be recommendations pending analyst approval.
- Approval Status defaults to `Pending analyst approval`.
