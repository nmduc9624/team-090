# Login Response Playbook

- **Trường:** Nội dung
- **Incident type:** Suspicious Login / Brute Force nghi vấn
- **Document type:** Playbook xử lý incident
- **Mục tiêu:** Đưa ra các bước response an toàn sau khi có alert đăng nhập bất thường, không tự động thực thi hành động.
- **Output mong muốn:** Checklist hành động: xác minh, containment theo quy trình, reset/revoke nếu cần, escalation và report.

## Investigation / Response Steps

| Bước | Tên bước | Nội dung thực hiện | Kết quả cần ghi vào report / hành động cần tạo |
| --- | --- | --- | --- |
| 1 | Xác minh chủ tài khoản | Liên hệ user qua kênh chính thức để xác nhận phiên đăng nhập, thiết bị và lý do truy cập. | Ghi kết quả xác minh: confirmed/denied/unreachable. |
| 2 | Containment có kiểm soát | Nếu user phủ nhận hoặc không xác minh được, đề xuất khóa tạm thời, revoke session/token, reset mật khẩu theo quy trình nội bộ. | Ghi rõ hành động chỉ là khuyến nghị cần phê duyệt. |
| 3 | Kiểm tra hoạt động sau login | Rà soát thay đổi quyền, export dữ liệu, truy cập secret, tạo rule mailbox, truy cập console. | Ghi action_after_login và tài sản bị ảnh hưởng. |
| 4 | Hunt mở rộng | Tìm cùng IP/user agent/device trên các tài khoản khác trong 24 giờ gần nhất. | Ghi phạm vi mở rộng nếu có. |
| 5 | Escalation | Escalate cho senior nếu liên quan tài khoản đặc quyền, secret, dữ liệu nhạy cảm hoặc nhiều tài khoản. | Ghi điều kiện escalation và người nhận. |

## Approval Requirement

All containment, blocking, account reset, purge, revoke, or isolation actions are recommendations. The application must present them as pending analyst approval, not execute them automatically.
