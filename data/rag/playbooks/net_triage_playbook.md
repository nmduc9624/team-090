# Outbound Connection Triage Playbook

- **Mã playbook:** PB-INV-NET-01
- **Incident type:** Suspicious Outbound Connection
- **Document type:** Playbook điều tra / Investigation playbook
- **Mục tiêu:** Hỗ trợ analyst đánh giá kết nối outbound lạ là traffic hợp lệ, vendor chưa allowlist, beacon/C2 hay dấu hiệu data exfiltration.
- **Phạm vi áp dụng:** Dùng cho alert từ firewall, proxy, DNS, IDS hoặc netflow khi host kết nối nhiều lần tới domain/IP lạ, bytes_out cao, ngoài giờ hoặc liên quan EDR alert.
- **Output mong muốn:** Report có Summary, Timeline, Affected Assets, Evidence from Log, AI Inference, TP/FP Assessment, Suggested Severity, Recommended Next Step, Missing Evidence.

## Entity Fields

| Trường | Ý nghĩa |
| --- | --- |
| source_host | Host nguồn tạo kết nối |
| user | User trên host nếu có |
| src_ip | IP nội bộ của host |
| destination_ip/domain | Đích kết nối |
| port/protocol | Cổng và giao thức |
| connection_count | Số lần kết nối |
| bytes_in/bytes_out | Dung lượng vào/ra |
| proxy_category | Category của proxy |
| process_name | Process tạo kết nối nếu có |

## Investigation / Response Steps

| Bước | Tên bước | Nội dung analyst/app cần làm | Kết quả cần ghi nhận |
| --- | --- | --- | --- |
| 1 | Xác nhận alert network | Ghi alert_id, source host, destination, port, protocol, action, timestamp. | Metadata network alert. |
| 2 | Phân tích mẫu kết nối | Tính connection_count, interval, bytes_out, thời lượng, giờ xảy ra. | Biết có beacon/exfil pattern không. |
| 3 | Xác minh destination | Đối chiếu allowlist, vendor, TI, proxy category, domain age nếu có. | destination_verdict. |
| 4 | Kiểm tra DNS/proxy context | Xem domain query, URL path, HTTP method, user agent, proxy action. | Context của truy cập. |
| 5 | Liên kết với endpoint/process | Tra EDR để biết process nào tạo kết nối, signer/path, parent process. | process_source. |
| 6 | Đánh giá bytes_out/exfil | So sánh bytes_out với baseline, chú ý upload path, paste/file transfer/cloud storage. | exfil_signal. |
| 7 | Tìm host liên quan | Search cùng destination/domain/IP trên các host khác trong 24-72 giờ. | related_hosts. |
| 8 | Kiểm tra liên hệ incident khác | Tra EDR alert, phishing click, suspicious login trên cùng host/user. | correlated_incidents. |
| 9 | Đánh giá TP/FP và severity | Nếu vendor hợp lệ thì FP/benign; nếu unknown + bytes_out cao/process lạ thì TP nghi vấn. | TP/FP assessment. |
| 10 | Tạo report nháp | Ghi timeline, evidence, destination verdict, process, scope, missing evidence. | Report Pending analyst approval. |

## Example Correlation Queries

| Nguồn/nhóm truy vấn | Mẫu logic truy vấn giả lập |
| --- | --- |
| Network timeline | host=<source_host> dest=<destination> earliest=<alert_time-1h> latest=<alert_time+24h> |
| Same destination | dest_domain=<domain> OR dest_ip=<ip> earliest=-72h | stats count by host,user,bytes_out |
| Process source | host=<source_host> dest=<destination> | join EDR network/process events by process_guid |
| Correlated alerts | host=<source_host> earliest=<alert_time-24h> latest=<alert_time+24h> source IN (edr,email_security,auth,proxy,dns) |

## Severity Guidance

| Severity | Điều kiện gợi ý |
| --- | --- |
| Low | Destination là vendor hợp lệ, bytes_out bình thường, process signed và owner xác nhận. |
| Medium | Destination unknown/uncategorized, traffic lặp lại nhưng bytes_out thấp và chưa có EDR alert. |
| High | bytes_out cao, ngoài giờ, process lạ, domain DGA-like hoặc host chứa dữ liệu quan trọng. |
| Critical | C2 confirmed, exfiltration suspected rõ, nhiều host liên quan hoặc có malware/credential incident đi kèm. |

## Report Output Requirements

| Mục trong report | Nội dung cần sinh |
| --- | --- |
| Incident Title | Suspicious outbound connection from <source_host> to <destination>. |
| Executive Summary | Tóm tắt source, destination, connection_count, bytes_out, verdict và liên hệ endpoint. |
| Evidence from Log | dest, port, protocol, bytes_out, proxy_category, action, process_name. |
| AI Inference | Nhận định vendor traffic/C2/exfiltration suspected dựa trên evidence. |
| Missing Evidence | TI result, process source, baseline traffic, URL/TLS detail, owner confirmation. |

## Guardrails

This playbook supports post-alert investigation only. It must not automatically block, lock, isolate, or close an incident. All final decisions require analyst approval.
