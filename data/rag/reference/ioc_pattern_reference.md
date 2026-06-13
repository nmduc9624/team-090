# IOC Pattern Reference

| IOC / Pattern Type | Example | Notes for AI Extraction |
|---|---|---|
| Domain | update-check.example | Extract domains and preserve original casing when useful. |
| Defanged domain | update-check[.]example | Normalize to `update-check.example` and keep original in notes. |
| IPv4 | 198.51.100.44 | Treat documentation ranges as synthetic when used in sample data. |
| SHA256 hash | 64 hex characters | Extract as file hash. |
| Windows path | C:\Users\user\AppData\... | Extract as file path and identify user-writable locations. |
| Linux path | /tmp/.cache.sh | Extract as file path and flag temp/hidden paths. |
| Process name | powershell.exe | Extract process and note parent/child relationships. |
| Command flag | -EncodedCommand | Extract suspicious flags from command lines. |
| Registry Run Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Map to persistence checks. |
| Scheduled task | schtasks /create | Map to scheduled task telemetry. |
| Service creation | sc create | Map to Windows service telemetry. |
| WMI persistence | __EventFilter / CommandLineEventConsumer | Map to WMI telemetry. |
| OAuth scope | Mail.ReadWrite | Map to cloud audit and high-risk consent review. |
| DNS TXT query | query_type=TXT | Map to DNS tunneling checks. |
| Long subdomain | length > 80 | Map to DGA/tunnel heuristic. |
| High bytes_out | bytes_out > baseline | Map to proxy/firewall exfil review. |
| Admin share | ADMIN$ | Map to lateral movement checks. |
| LSASS | lsass.exe | Map to credential access checks. |
| Web root file | shell.aspx / cmd.jsp | Map to webshell checks. |
| New API key | create_api_key | Map to cloud credential checks. |
