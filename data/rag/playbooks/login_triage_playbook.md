# Login Triage Playbook

- **Mã playbook:** PB-INV-LOGIN-01
- **Incident type:** Suspicious Login / Brute Force nghi vấn
- **Document type:** Playbook điều tra / Investigation playbook
- **Mục tiêu:** Hỗ trợ SOC analyst xác định alert đăng nhập bất thường là false positive, brute force chưa thành công, password spraying, MFA fatigue hay credential compromise.
- **Phạm vi áp dụng:** Dùng cho alert từ SIEM, SSO/IdP, VPN, AD, PAM, cloud IAM khi có failed login bất thường, successful login sau nhiều lần lỗi, login ngoài giờ, impossible travel hoặc tài khoản đặc quyền.
- **Output mong muốn:** Report có Summary, Timeline, Affected Assets, Evidence from Log, AI Inference, TP/FP Assessment, Suggested Severity, Recommended Next Step, Missing Evidence.

## Entity Fields

| Trường | Ý nghĩa |
| --- | --- |
| user | Tài khoản bị ảnh hưởng |
| account_type | normal/admin/service/temporary |
| src_ip | IP nguồn tạo login |
| target_host | SSO/VPN/PAM/app/server nhận login |
| failed_count | Số lần đăng nhập thất bại |
| success_after_failure | Có đăng nhập thành công sau chuỗi thất bại không |
| mfa_status | passed/failed/approved/denied/unknown |
| device_status | known/new/unknown |
| action_after_login | Tạo token, export dữ liệu, xem secret, đổi quyền... |

## Investigation / Response Steps

| Bước | Tên bước | Nội dung analyst/app cần làm | Kết quả cần ghi nhận |
| --- | --- | --- | --- |
| 1 | Xác nhận alert | Lấy alert_id, rule_name, severity ban đầu, nguồn alert và time window. | Có đủ metadata để mở case điều tra. |
| 2 | Dựng timeline đăng nhập | Sắp xếp failed_login, successful_login, MFA prompt, lockout, password reset theo thời gian. | Timeline rõ trước/sau để app sinh report. |
| 3 | Phân loại tài khoản | Kiểm tra user là admin, service account, contractor, tài khoản tạm hay tài khoản thường. | Xác định asset/user criticality. |
| 4 | Kiểm tra IP và vị trí | Đối chiếu IP với VPN/allowlist, geo giả lập, ASN, impossible travel, threat intel nếu có. | Kết luận IP quen thuộc/lạ/chưa xác minh. |
| 5 | Kiểm tra MFA/device | Xem prompt count, approve/deny, thiết bị MFA, device fingerprint, user agent. | Nhận diện MFA fatigue hoặc thiết bị mới. |
| 6 | Kiểm tra hành động sau login | Rà cloud/app audit: export, xem secret, tạo token, đổi rule mailbox, đổi quyền. | Xác định có hậu quả sau login hay không. |
| 7 | Hunt mở rộng | Tìm cùng src_ip, user_agent, device_id trên các tài khoản khác trong 24 giờ. | Xác định password spray/campaign hay case đơn lẻ. |
| 8 | Đánh giá TP/FP | So sánh với lịch làm việc, ticket thay đổi, xác nhận user, baseline truy cập. | Ghi evidence nghiêng TP, evidence nghiêng FP và missing evidence. |
| 9 | Đề xuất severity | High nếu admin/service account, successful login, MFA fatigue, action nhạy cảm hoặc ngoài giờ. | Severity gợi ý cho analyst duyệt. |
| 10 | Tạo output report nháp | Sinh summary, timeline, affected assets, evidence, inference, missing evidence. | Report ở trạng thái Pending analyst approval. |

## Example Correlation Queries

| Nguồn/nhóm truy vấn | Mẫu logic truy vấn giả lập |
| --- | --- |
| SIEM/Auth | user=<user> earliest=<alert_time-1h> latest=<alert_time+2h> event_type IN (failed_login,successful_login,mfa,lockout,password_reset) |
| IP correlation | src_ip=<src_ip> earliest=-24h | stats count by user, host, event_type |
| Post-login audit | user=<user> earliest=<success_time> latest=<success_time+2h> action IN (export,create_token,change_permission,list_secret,mail_rule_change) |
| Impossible travel | user=<user> | sort timestamp | compare previous src_ip/geo/time_gap |

## Severity Guidance

| Severity | Điều kiện gợi ý |
| --- | --- |
| Low | Chỉ có vài failed_login, IP quen thuộc, không có successful login, user xác nhận nhập sai. |
| Medium | Failed nhiều lần, IP chưa xác minh, tài khoản thường, chưa có hành động sau login. |
| High | Successful login sau failed, MFA fatigue, thiết bị lạ, tài khoản đặc quyền hoặc ngoài giờ. |
| Critical | Tài khoản đặc quyền bị chiếm, có export dữ liệu/secret/token hoặc nhiều tài khoản bị ảnh hưởng. |

## Report Output Requirements

| Mục trong report | Nội dung cần sinh |
| --- | --- |
| Incident Title | Suspicious login involving <user> from <src_ip>. |
| Executive Summary | Tóm tắt số lần failed login, successful login, MFA/device và hành động sau login. |
| Evidence from Log | failed_count, success_after_failure, mfa_status, src_ip, host, action_after_login. |
| AI Inference | Nhận định brute force/MFA fatigue/credential compromise dựa trên evidence. |
| Missing Evidence | User confirmation, IP reputation, baseline, full MFA detail, audit sau login. |

## Guardrails

This playbook supports post-alert investigation only. It must not automatically block, lock, isolate, or close an incident. All final decisions require analyst approval.
