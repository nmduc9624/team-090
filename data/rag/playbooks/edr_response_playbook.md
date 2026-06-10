# Malware EDR Response Playbook

- **Trường:** Nội dung
- **Incident type:** Malware / EDR Alert
- **Document type:** Playbook xử lý incident
- **Mục tiêu:** Hướng dẫn containment và thu thập bằng chứng an toàn cho endpoint có cảnh báo EDR.
- **Output mong muốn:** Checklist gồm isolate nếu cần, triage package, quarantine, scan lại, hunt IOC và report.

## Investigation / Response Steps

| Bước | Tên bước | Nội dung thực hiện | Kết quả cần ghi vào report / hành động cần tạo |
| --- | --- | --- | --- |
| 1 | Xác định mức containment | Nếu EDR đã block/quarantine và không có lan rộng, tiếp tục điều tra; nếu allowed/outbound/host quan trọng, đề xuất isolate theo quy trình. | Ghi trạng thái isolate: not_required/recommended/pending. |
| 2 | Thu thập triage package | Yêu cầu lấy EDR triage package, process tree, file metadata, hash và event timeline. | Ghi evidence đã có và còn thiếu. |
| 3 | Quarantine và scan | Đảm bảo file đáng ngờ bị quarantine, sau đó scan lại host và kiểm tra persistence. | Ghi scan_result và findings. |
| 4 | Hunt mở rộng | Tìm IOC trên các endpoint khác và liên kết với email/network alert nếu có. | Ghi số host liên quan. |
| 5 | Escalation và phục hồi | Escalate nếu host là server/jump host hoặc có data movement; hướng dẫn phục hồi theo quy trình IT sau khi sạch. | Ghi owner và next steps. |

## Approval Requirement

All containment, blocking, account reset, purge, revoke, or isolation actions are recommendations. The application must present them as pending analyst approval, not execute them automatically.
