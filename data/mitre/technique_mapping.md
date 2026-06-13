# MITRE ATT&CK Mapping Reference

| Behavior | Possible Technique |
|---|---|
| Office process launches mshta.exe | T1218.005 - Mshta |
| Encoded or hidden PowerShell | T1059.001 - PowerShell |
| Registry Run Key persistence | T1547.001 - Registry Run Keys / Startup Folder |
| Scheduled task persistence | T1053.005 - Scheduled Task |
| WMI event subscription persistence | T1546.003 - WMI Event Subscription |
| Windows service persistence | T1543.003 - Windows Service |
| Rundll32 loading DLL | T1218.011 - Rundll32 |
| Credential dumping from LSASS | T1003.001 - LSASS Memory |
| Browser credential theft | T1555.003 - Credentials from Web Browsers |
| OAuth token abuse | T1528 - Steal Application Access Token |
| MFA push fatigue | T1621 - MFA Request Generation |
| Email collection | T1114 - Email Collection |
| SMB/admin share movement | T1021.002 - SMB/Windows Admin Shares |
| Service execution | T1569.002 - Service Execution |
| Web shell | T1505.003 - Web Shell |
| Ingress tool transfer | T1105 - Ingress Tool Transfer |
| DNS tunneling | T1071.004 - DNS |
| HTTPS C2 | T1071.001 - Web Protocols |
| Data archived before exfiltration | T1560 - Archive Collected Data |
| Exfiltration over C2 | T1041 - Exfiltration Over C2 Channel |
| Software supply-chain package abuse | T1195.002 - Compromise Software Supply Chain |
| Malicious shortcut or document execution | T1204.002 - Malicious File |
| Masquerading as updater/service | T1036 - Masquerading |
| Disable or modify security tools | T1562.001 - Disable or Modify Tools |
| Cloud account manipulation | T1098 - Account Manipulation |
| Audit/logging impairment | T1562 - Impair Defenses |
| Unix shell execution | T1059.004 - Unix Shell |
| Cron persistence | T1053.003 - Cron |
| Privilege escalation through vulnerable driver | T1068 - Exploitation for Privilege Escalation |
| Command and scripting interpreter | T1059 - Command and Scripting Interpreter |

Use this file as a lightweight MVP reference. Analysts should validate mappings before production use.
