# Alert Types Catalog

Synthetic catalog of 100 distinct SOC alert/report scenarios for the MVP dataset.

| # | Slug | Alert name | Source | Severity | Category | Status |
|---:|---|---|---|---|---|---|
| 1 | `admin_role_assignment_unusual` | Unusual Admin Role Assignment | Cloud Audit | Critical | Cloud Identity | new |
| 2 | `anomalous_smb_admin_share_copy` | Large File Copy To Admin Share | Windows Security | Medium | Lateral Movement | new |
| 3 | `asrep_roasting_attempt` | AS-REP Roasting Attempt | Windows Security | High | Active Directory | new |
| 4 | `backup_service_stopped` | Backup Service Stopped | EDR | High | Ransomware Behavior | new |
| 5 | `bitsadmin_transfer` | Bitsadmin Suspicious Transfer | EDR | Medium | Signed Binary Abuse | new |
| 6 | `browser_credential_theft` | Browser Credential Theft | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 7 | `brute_force_single_account` | Brute Force Against Single Account | Identity Provider | Medium | Identity | new |
| 8 | `certutil_download_payload` | Certutil Downloads Payload | EDR | High | Signed Binary Abuse | new |
| 9 | `cloud_access_key_used_from_new_geo` | Cloud Access Key Used From New Geography | Cloud Audit | High | Cloud Security | new |
| 10 | `cloud_api_key_creation` | Cloud Api Key Creation | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 11 | `cloud_iam_policy_admin_attach` | Cloud IAM Admin Policy Attached | Cloud Audit | Critical | Cloud Security | new |
| 12 | `cloud_instance_metadata_token_abuse` | Cloud Metadata Credential Access | Cloud Audit | Critical | Cloud Security | new |
| 13 | `cloud_storage_public_bucket` | Cloud Storage Bucket Made Public | Cloud Audit | Critical | Cloud Security | new |
| 14 | `cmd_obfuscated_command` | Obfuscated Windows Command Shell | EDR | Medium | Endpoint Execution | new |
| 15 | `container_privileged_started` | Privileged Container Started | Container Runtime | High | Container Security | new |
| 16 | `credential_dump_lsass` | Credential Dump Lsass | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 17 | `data_loss_large_upload_personal_drive` | Large Upload To Personal Cloud Drive | Proxy | High | Data Loss | new |
| 18 | `dc_sync_replication_request` | DCSync Replication Request | Windows Security | Critical | Active Directory | new |
| 19 | `defender_realtime_disabled` | Defender Real-Time Protection Disabled | EDR | Critical | Defense Evasion | new |
| 20 | `disabled_mfa_for_user` | MFA Disabled For User | Identity Provider | Critical | Identity | new |
| 21 | `dns_base64_subdomain_burst` | Base64-Like DNS Subdomain Burst | DNS | High | Network | new |
| 22 | `dns_beaconing_regular_interval` | Regular Interval DNS Beaconing | DNS | High | Network | new |
| 23 | `dns_many_failed_queries` | High NXDOMAIN Query Rate | DNS | Medium | Network | new |
| 24 | `dns_query_dga_domain` | Possible DGA Domain Queries | DNS | Medium | Network | new |
| 25 | `dns_tunneling_txt` | Dns Tunneling Txt | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 26 | `dormant_account_login` | Dormant Account Login | Identity Provider | High | Identity | new |
| 27 | `edr_malware_quarantine_failed` | EDR Malware Quarantine Failed | EDR | Critical | Malware | new |
| 28 | `excel_mshta_persistence` | Excel Mshta Persistence | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 29 | `firewall_blocked_malware_ip` | Firewall Blocks Known Malware IP | Firewall | Medium | Network | new |
| 30 | `firewall_internal_port_scan` | Internal Port Scan Detected | Firewall | High | Network | new |
| 31 | `firewall_outbound_c2_port` | Outbound Connection To Unusual C2 Port | Firewall | High | Network | new |
| 32 | `firewall_rule_added` | Suspicious Firewall Rule Added | EDR | Medium | Defense Evasion | new |
| 33 | `golden_ticket_suspicious_kerberos` | Suspicious Kerberos Ticket Lifetime | Windows Security | Critical | Active Directory | new |
| 34 | `hollowing_suspected` | Process Hollowing Suspected | EDR | High | Endpoint Execution | new |
| 35 | `impossible_travel_login` | Impossible Travel Login | Identity Provider | Medium | Identity | new |
| 36 | `inbox_rule_hides_security_mail` | Inbox Rule Hides Security Mail | Email Security | Medium | Email | new |
| 37 | `installutil_proxy_execution` | InstallUtil Proxy Execution | EDR | High | Signed Binary Abuse | new |
| 38 | `kerberoasting_spn_requests` | Kerberoasting Service Ticket Spike | Windows Security | High | Active Directory | new |
| 39 | `kubernetes_exec_into_pod` | Kubernetes Exec Into Pod | Kubernetes Audit | Medium | Kubernetes Security | new |
| 40 | `kubernetes_secret_read_spike` | Kubernetes Secret Read Spike | Kubernetes Audit | High | Kubernetes Security | new |
| 41 | `ldap_recon_many_queries` | LDAP Reconnaissance Query Spike | Windows Security | Medium | Active Directory | new |
| 42 | `linux_cron_persistence` | Linux Cron Persistence | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 43 | `linux_crypto_miner_process` | Linux Crypto Miner Process | Linux EDR | High | Malware | new |
| 44 | `linux_new_root_user` | New UID 0 User Created | Linux Audit | Critical | Linux Privilege | new |
| 45 | `linux_reverse_shell` | Linux Reverse Shell Pattern | Linux EDR | High | Linux Execution | new |
| 46 | `linux_sensitive_file_read` | Sensitive Linux File Read | Linux Audit | Medium | Linux Discovery | new |
| 47 | `linux_ssh_bruteforce` | Linux SSH Brute Force | Linux Auth | Medium | Linux Identity | new |
| 48 | `linux_sudoers_modified` | Linux Sudoers File Modified | Linux Audit | High | Linux Privilege | new |
| 49 | `lnk_powershell_delivery` | Lnk Powershell Delivery | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 50 | `login_from_tor_exit_node` | Login From Tor Exit Node | Identity Provider | High | Identity | new |
| 51 | `lolbin_suspicious_chain` | Chained LOLBin Execution | EDR | High | Signed Binary Abuse | new |
| 52 | `lsass_handle_access` | Suspicious LSASS Handle Access | EDR | Critical | Credential Access | new |
| 53 | `mailbox_forwarding_rule_external` | Mailbox Forwarding Rule To External Address | Email Security | High | Email | new |
| 54 | `malicious_npm_postinstall` | Malicious Npm Postinstall | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 55 | `mass_file_download_saas` | Mass File Download From SaaS | SaaS Audit | High | SaaS | new |
| 56 | `msbuild_inline_task` | MSBuild Inline Task Execution | EDR | High | Signed Binary Abuse | new |
| 57 | `new_service_install` | New Service Install | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 58 | `oauth_consent_abuse` | Oauth Consent Abuse | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 59 | `office_macro_child_process` | Office Macro Child Process | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 60 | `password_spray_many_users` | Password Spray Against Many Users | Identity Provider | High | Identity | new |
| 61 | `powershell_amsi_bypass` | PowerShell AMSI Bypass String | EDR | High | Defense Evasion | new |
| 62 | `powershell_download_cradle` | PowerShell Download Cradle | EDR | High | Endpoint Execution | new |
| 63 | `powershell_encoded_loader` | Powershell Encoded Loader | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 64 | `process_injection_suspected` | Process Injection Suspected | EDR | High | Endpoint Execution | new |
| 65 | `proxy_new_domain_executable_download` | Executable Download From Newly Registered Domain | Proxy | High | Network | new |
| 66 | `proxy_suspicious_user_agent` | Suspicious User-Agent Beacon | Proxy | Medium | Network | new |
| 67 | `proxy_tor2web_access` | Tor2Web Proxy Access | Proxy | Medium | Network | new |
| 68 | `psexec_service_execution` | PsExec-Like Service Execution | Windows Security | High | Lateral Movement | new |
| 69 | `rare_process_from_user_profile` | Rare Process From User Profile | EDR | Medium | Endpoint Execution | new |
| 70 | `rclone_data_staging` | Rclone Data Staging | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 71 | `rdp_login_after_hours` | After-Hours RDP Login | Windows Security | Medium | Remote Access | new |
| 72 | `regsvr32_scriptlet_execution` | Regsvr32 Scriptlet Execution | EDR | High | Signed Binary Abuse | new |
| 73 | `remote_registry_enabled` | Remote Registry Service Enabled | Windows Security | Medium | Lateral Movement | new |
| 74 | `risky_oauth_app_granted` | Risky OAuth App Granted Tenant Permissions | Cloud Audit | Critical | Cloud Identity | new |
| 75 | `rundll32_javascript_url` | Rundll32 JavaScript URL Handler | EDR | High | Signed Binary Abuse | new |
| 76 | `rundll32_remote_payload` | Rundll32 Remote Payload | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 77 | `scheduled_task_persistence` | Scheduled Task Persistence | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 78 | `scheduled_task_remote_creation` | Remote Scheduled Task Created | Windows Security | High | Lateral Movement | new |
| 79 | `security_log_cleared` | Windows Security Log Cleared | Windows Security | Critical | Defense Evasion | new |
| 80 | `service_account_interactive_login` | Service Account Interactive Login | Identity Provider | High | Identity | new |
| 81 | `shadow_copy_deleted` | Volume Shadow Copies Deleted | EDR | Critical | Ransomware Behavior | new |
| 82 | `smb_lateral_movement` | Smb Lateral Movement | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 83 | `successful_login_after_failures` | Successful Login After Repeated Failures | Identity Provider | High | Identity | new |
| 84 | `suspicious_driver_load` | Suspicious Driver Load | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 85 | `suspicious_mfa_device_registration` | Suspicious MFA Device Registration | Identity Provider | High | Identity | new |
| 86 | `suspicious_mfa_push_fatigue` | Suspicious Mfa Push Fatigue | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 87 | `suspicious_parent_child_cmd_from_word` | Word Launches Command Shell | EDR | High | Office Malware | new |
| 88 | `suspicious_temp_executable_run` | Executable Runs From Temp Directory | EDR | Medium | Endpoint Execution | new |
| 89 | `suspicious_wmi_remote_process` | Remote Process Creation Via WMI | Windows Security | High | Lateral Movement | new |
| 90 | `unsigned_binary_system32` | Unsigned Binary In System32 | EDR | High | Endpoint Execution | new |
| 91 | `vpn_login_from_new_country` | VPN Login From New Country | VPN | Medium | Remote Access | new |
| 92 | `vulnerable_driver_loaded` | Vulnerable Driver Loaded | EDR | Critical | Defense Evasion | new |
| 93 | `web_admin_panel_bruteforce` | Admin Panel Brute Force | Web Server | Medium | Web Attack | new |
| 94 | `web_file_upload_executable` | Executable File Uploaded To Web App | Web Server | High | Web Attack | new |
| 95 | `web_path_traversal_attempt` | Path Traversal Attempt Against Web Server | Web Server | Medium | Web Attack | new |
| 96 | `web_rce_attempt` | Remote Code Execution Attempt Against Web App | Web Server | High | Web Attack | new |
| 97 | `web_sql_injection_attempt` | SQL Injection Attempt Against Web App | Web Server | Medium | Web Attack | new |
| 98 | `webshell_upload` | Webshell Upload | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
| 99 | `winrm_remote_command` | WinRM Remote Command Execution | Windows Security | High | Lateral Movement | new |
| 100 | `wmi_event_persistence` | Wmi Event Persistence | Mixed SOC Telemetry | Medium/High | Existing MVP Scenario | existing |
