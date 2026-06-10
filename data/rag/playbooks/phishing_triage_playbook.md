# Phishing Triage Playbook

- **Mã playbook:** PB-INV-PHISH-01
- **Incident type:** Phishing Email
- **Document type:** Playbook điều tra / Investigation playbook
- **Mục tiêu:** Hỗ trợ analyst xác định email có phải phishing không, người dùng đã click/tải file/nhập credential hay chưa và chiến dịch có lan tới người dùng khác không.
- **Phạm vi áp dụng:** Dùng cho alert từ email security gateway, user report, sandbox, proxy hoặc SIEM khi email chứa sender lạ, URL/domain đáng ngờ, attachment, BEC hoặc OAuth consent phishing.
- **Output mong muốn:** Report có Summary, Timeline, Affected Assets, Evidence from Log, AI Inference, TP/FP Assessment, Suggested Severity, Recommended Next Step, Missing Evidence.

## Entity Fields

| Trường | Ý nghĩa |
| --- | --- |
| sender | Địa chỉ gửi |
| recipient | Người nhận hoặc nhóm nhận |
| subject | Tiêu đề email |
| message_id | ID email để truy vết |
| url/domain | Indicator trong email |
| attachment_hash | Hash file đính kèm nếu có |
| delivery_action | delivered/quarantine/blocked/purged |
| user_clicked | true/false/unknown |
| campaign_scope | Số người nhận/click cùng chiến dịch |

## Investigation / Response Steps

| Bước | Tên bước | Nội dung analyst/app cần làm | Kết quả cần ghi nhận |
| --- | --- | --- | --- |
| 1 | Xác nhận alert email | Ghi alert_id, message_id, sender, recipient, subject, thời điểm nhận. | Có metadata email để truy vết. |
| 2 | Kiểm tra header/authentication | So sánh From, Reply-To, Return-Path; kiểm tra SPF/DKIM/DMARC. | Nhận diện spoofing hoặc domain giả mạo. |
| 3 | Trích xuất indicator | Lấy URL/domain, attachment name/hash, brand bị giả mạo, OAuth app nếu có. | Danh sách IOC đưa vào RAG/report. |
| 4 | Kiểm tra delivery status | Xác định email bị chặn, quarantine, delivered hay đã purge khỏi mailbox. | Biết user có thể đã tiếp xúc email hay chưa. |
| 5 | Kiểm tra user interaction | Tra proxy/DNS/browser/EDR xem có click URL, tải file, mở file, nhập form hay không. | user_clicked, downloaded, endpoint_event. |
| 6 | Phân tích indicator | Đối chiếu URL/domain/hash với TI, sandbox, allowlist, lịch sử nội bộ. | Indicator verdict: malicious/suspicious/unknown/benign. |
| 7 | Tìm phạm vi chiến dịch | Search message_id, sender, subject, URL, hash trên toàn bộ mailbox/log. | campaign_scope, related_recipients. |
| 8 | Phân biệt phishing/BEC/malware | Dựa vào nội dung email, URL, attachment, người nhận, hành động yêu cầu. | incident subtype. |
| 9 | Đánh giá severity | High nếu clicked, credential exposure, attachment executed, BEC tài chính hoặc gửi diện rộng. | Severity gợi ý. |
| 10 | Tạo report nháp | Ghi summary, timeline, evidence, user interaction, scope, missing evidence. | Report Pending analyst approval. |

## Example Correlation Queries

| Nguồn/nhóm truy vấn | Mẫu logic truy vấn giả lập |
| --- | --- |
| Mailbox search | message_id=<message_id> OR sender=<sender> OR url=<url> OR attachment_hash=<hash> |
| Proxy/DNS | user=<recipient> domain=<domain> earliest=<email_time> latest=<email_time+24h> |
| EDR attachment | user=<recipient> file_hash=<hash> OR process_name IN (wscript,powershell,mshta,rundll32) |
| Campaign scope | sender=<sender> OR subject~<similar_subject> OR domain=<domain> | stats count by recipient, delivery_action |

## Severity Guidance

| Severity | Điều kiện gợi ý |
| --- | --- |
| Low | Email bị block/quarantine, không có người nhận khác, indicator chưa xác nhận độc hại. |
| Medium | Email delivered nhưng chưa click, hoặc URL suspicious nhưng chưa có credential exposure. |
| High | User click URL, tải file, email gửi diện rộng, nhắm tài chính/admin hoặc OAuth consent phishing. |
| Critical | Có credential submitted, malware executed, BEC gây giao dịch sai hoặc nhiều tài khoản bị chiếm. |

## Report Output Requirements

| Mục trong report | Nội dung cần sinh |
| --- | --- |
| Incident Title | Phishing email from <sender> to <recipient>. |
| Executive Summary | Tóm tắt sender, subject, URL/attachment, delivery action và user interaction. |
| Evidence from Log | message_id, sender, recipient, URL, delivery_action, proxy/EDR event. |
| AI Inference | Nhận định credential phishing/BEC/malware delivery dựa trên evidence. |
| Missing Evidence | Credential submitted, full URL, sandbox verdict, endpoint artifact, campaign scope. |

## Guardrails

This playbook supports post-alert investigation only. It must not automatically block, lock, isolate, or close an incident. All final decisions require analyst approval.
