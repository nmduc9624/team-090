# Malware EDR Triage Playbook

- **Mã playbook:** PB-INV-EDR-01
- **Incident type:** Malware / EDR Alert
- **Document type:** Playbook điều tra / Investigation playbook
- **Mục tiêu:** Hỗ trợ analyst phân tích cảnh báo EDR, xác định process/file đáng ngờ, phân biệt blocked với executed và kiểm tra dấu hiệu lan rộng.
- **Phạm vi áp dụng:** Dùng cho cảnh báo endpoint liên quan malware, macro/script, suspicious child process, PowerShell encoded command, file quarantine, persistence, C2 hoặc lateral movement.
- **Output mong muốn:** Report có Summary, Timeline, Affected Assets, Evidence from Log, AI Inference, TP/FP Assessment, Suggested Severity, Recommended Next Step, Missing Evidence.

## Entity Fields

| Trường | Ý nghĩa |
| --- | --- |
| host | Endpoint/server bị cảnh báo |
| user | User đăng nhập trên host |
| parent_process | Tiến trình cha |
| child_process | Tiến trình con đáng ngờ |
| command_line | Command line đầy đủ nếu có |
| file_path/hash | File liên quan và hash |
| edr_action | blocked/quarantined/allowed/monitored |
| network_destination | Domain/IP kết nối sau cảnh báo |
| related_hosts | Host khác có cùng IOC |

## Investigation / Response Steps

| Bước | Tên bước | Nội dung analyst/app cần làm | Kết quả cần ghi nhận |
| --- | --- | --- | --- |
| 1 | Xác nhận alert EDR | Lấy alert_id, host, user, rule, severity, edr_action, timestamp. | Metadata cảnh báo rõ ràng. |
| 2 | Dựng process tree | Xác định parent-child process, command line, integrity level, signer. | Biết hành vi đáng ngờ đến từ đâu. |
| 3 | Phân tích file/hash | Lấy path, hash, created time, signer, verdict, quarantine status. | IOC file cho hunting/report. |
| 4 | Phân biệt blocked/executed | Kiểm tra process có chạy thành công, có child process/file/network sau đó không. | execution_status. |
| 5 | Kiểm tra nguồn lây | Tra email/download/USB/share/package install trước alert. | possible_initial_vector. |
| 6 | Rà network sau alert | Tìm DNS/proxy/firewall/outbound connection từ host trong 2-24 giờ. | C2/exfil signal nếu có. |
| 7 | Kiểm tra persistence | Tìm scheduled task, registry run key, service, startup folder, WMI event. | persistence_signal. |
| 8 | Hunt IOC mở rộng | Tìm hash, process, command line, domain/IP trên toàn bộ endpoint. | scope_result. |
| 9 | Đánh giá TP/FP và severity | So sánh với tool hợp lệ, admin activity, software update, developer script. | TP/FP assessment và severity. |
| 10 | Tạo report nháp | Ghi timeline, evidence, execution status, IOC, missing evidence. | Report Pending analyst approval. |

## Example Correlation Queries

| Nguồn/nhóm truy vấn | Mẫu logic truy vấn giả lập |
| --- | --- |
| Process tree | host=<host> process_guid=<guid> OR parent_process=<parent> earliest=<alert_time-30m> latest=<alert_time+2h> |
| File IOC | file_hash=<hash> OR file_name=<name> | stats count by host,user,file_path |
| Network after alert | host=<host> earliest=<alert_time> latest=<alert_time+24h> dest_domain=* OR dest_ip=* |
| Persistence | host=<host> event_type IN (scheduled_task,service_created,registry_run_key,wmi_event) |

## Severity Guidance

| Severity | Điều kiện gợi ý |
| --- | --- |
| Low | EDR alert trùng tool hợp lệ, không có file/network/persistence bất thường. |
| Medium | EDR blocked/quarantined, chưa thấy execution thành công hoặc lan rộng. |
| High | Execution thành công, command nguy hiểm, host quan trọng, outbound suspicious hoặc persistence. |
| Critical | Lateral movement, credential access, nhiều host có IOC, C2 confirmed hoặc data exfiltration. |

## Report Output Requirements

| Mục trong report | Nội dung cần sinh |
| --- | --- |
| Incident Title | EDR alert on <host> involving <process/file>. |
| Executive Summary | Tóm tắt host/user, process tree, edr_action, execution status và IOC. |
| Evidence from Log | parent_process, child_process, command_line, hash, edr_action, network event. |
| AI Inference | Nhận định malware blocked/executed/compromise suspected dựa trên evidence. |
| Missing Evidence | File source, full hash reputation, memory artifact, IOC hunt result, user confirmation. |

## Guardrails

This playbook supports post-alert investigation only. It must not automatically block, lock, isolate, or close an incident. All final decisions require analyst approval.
