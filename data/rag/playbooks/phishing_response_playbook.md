# Phishing Response Playbook

- **Trường:** Nội dung
- **Incident type:** Phishing Email
- **Document type:** Playbook xử lý incident
- **Mục tiêu:** Hướng dẫn các bước response khi email phishing đã được phát hiện và cần xử lý an toàn.
- **Output mong muốn:** Checklist xử lý gồm purge/quarantine, block indicator, hỗ trợ người dùng, kiểm tra tài khoản và cập nhật rule.

## Investigation / Response Steps

| Bước | Tên bước | Nội dung thực hiện | Kết quả cần ghi vào report / hành động cần tạo |
| --- | --- | --- | --- |
| 1 | Đề xuất đề xuất cô lập theo quy trình phê duyệt theo quy trình phê duyệt email | Giữ quarantine hoặc đề xuất purge email khỏi mailbox theo chính sách nếu đã delivered. | Ghi delivery_action và phạm vi purge. |
| 2 | Block indicator | Đề xuất đề xuất block domain theo quy trình phê duyệt/URL/hash/sender theo quy trình, không tự động chặn nếu chưa duyệt. | Ghi indicator cần block và nguồn evidence. |
| 3 | Xử lý user đã tương tác | Nếu user click/open/reply/consent, kiểm tra đăng nhập, reset mật khẩu hoặc revoke OAuth consent theo quy trình. | Ghi user liên quan và hành động khuyến nghị. |
| 4 | Kiểm tra endpoint | Nếu có file/attachment, liên kết EDR alert và kiểm tra endpoint của người dùng. | Ghi host, hash, EDR status. |
| 5 | Truyền thông và closing | Cảnh báo người dùng liên quan, cập nhật rule lọc và ghi lại report final sau analyst approval. | Ghi action taken và owner. |

## Approval Requirement

All containment, blocking, account reset, purge, revoke, or isolation actions are recommendations. The application must present them as pending analyst approval, not execute them automatically.
