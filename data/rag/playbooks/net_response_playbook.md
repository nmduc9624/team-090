# Outbound Connection Response Playbook

- **Trường:** Nội dung
- **Incident type:** Suspicious Outbound Connection
- **Document type:** Playbook xử lý incident
- **Mục tiêu:** Hướng dẫn response an toàn khi phát hiện kết nối outbound đáng ngờ, tập trung vào containment có kiểm soát và xác minh trước khi kết luận.
- **Output mong muốn:** Checklist gồm xác minh, block tạm theo phê duyệt, kiểm tra host, hunt mở rộng và closing report.

## Investigation / Response Steps

| Bước | Tên bước | Nội dung thực hiện | Kết quả cần ghi vào report / hành động cần tạo |
| --- | --- | --- | --- |
| 1 | Xác minh hợp lệ | Kiểm tra vendor/allowlist/ticket để loại trừ dịch vụ hợp lệ hoặc traffic nghiệp vụ. | Ghi kết quả xác minh destination. |
| 2 | Containment có phê duyệt | Nếu không xác minh được và rủi ro cao, đề xuất block tạm domain/IP hoặc isolate host theo quy trình. | Ghi action recommended, không tự động thực thi. |
| 3 | Kiểm tra process và endpoint | Xác định process tạo kết nối, EDR related alerts, task scheduler và lịch sử đăng nhập user. | Ghi process hoặc missing evidence. |
| 4 | Hunt host khác | Tìm host khác truy cập cùng domain/IP trong 24-72 giờ gần nhất. | Ghi số host và scope. |
| 5 | Cập nhật rule và report | Sau khi analyst duyệt, cập nhật allowlist/blocklist/rule theo kết luận và lưu report. | Ghi final decision và approval. |

## Approval Requirement

All containment, blocking, account reset, purge, revoke, or isolation actions are recommendations. The application must present them as pending analyst approval, not execute them automatically.
