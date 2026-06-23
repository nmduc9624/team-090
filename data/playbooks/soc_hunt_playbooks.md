# SOC Hunt Playbooks

These playbooks are compact RAG grounding notes for the MVP analyzer. They are not a replacement for environment-specific SOC runbooks.

## Endpoint Malware: Office To Mshta And Persistence

Category: endpoint
Telemetry: edr_process, edr_registry, dns, proxy, firewall
Relevant MITRE: T1218.005, T1105, T1547.001, T1071.001

Investigation steps:

- Search for Office parent processes spawning `mshta.exe`, `powershell.exe`, `wscript.exe`, or `rundll32.exe`.
- Review command line, parent process, user, host, and file path.
- Check Registry Run Key, scheduled task, WMI, or service persistence on the same host.
- Correlate outbound DNS/proxy/firewall activity after the process execution.
- Escalate when process execution, persistence, and suspicious outbound activity align on the same host/user.

## DNS Tunneling

Category: dns
Telemetry: dns, proxy, firewall, edr_process
Relevant MITRE: T1071.004, T1041, T1105

Investigation steps:

- Find hosts with high TXT query count, long subdomains, high entropy labels, or many NXDOMAIN responses.
- Group by source host, user, base domain, query type, and time window.
- Review whether endpoint process telemetry shows suspicious script or malware behavior around the same time.
- Escalate when one host shows abnormal DNS volume to unknown domains and no business justification exists.

## Identity: Password Spray

Category: identity
Telemetry: auth, cloud_audit, proxy
Relevant MITRE: T1110.003, T1110, T1078

Investigation steps:

- Group failed logins by source IP, ASN, user count, and time bucket.
- Look for many accounts with low failure count per account from the same source.
- Check successful login after the spray window.
- Review MFA prompts, impossible travel, new device, and recent account changes.
- Escalate when spray activity is followed by a successful login or privileged access.

## SaaS OAuth Abuse

Category: saas
Telemetry: cloud_audit, auth, email_audit, proxy
Relevant MITRE: T1528, T1530, T1567.002, T1078, T1098

Investigation steps:

- Review OAuth consent or app authorization events for the user.
- Check app publisher, tenant approval status, redirect URI, app ID, and requested scopes.
- Review SaaS audit logs for file export, mailbox access, channel reads, or data download activity.
- Correlate with user login IP, device, MFA, session, and proxy activity.
- Do not include endpoint persistence techniques unless the report has real endpoint evidence.

## Developer Platform OAuth Abuse

Category: developer_platform
Telemetry: cloud_audit, auth, proxy, github_audit, gitlab_audit
Relevant MITRE: T1528, T1098, T1552, T1530, T1078

Investigation steps:

- Review GitHub/GitLab OAuth app authorization, app owner, callback URL, and granted scopes.
- Check private repository access, clone/download activity, secret metadata access, deploy key creation, and workflow token use.
- Correlate app activity with developer login IP, device, MFA, and session changes.
- Identify other developers who authorized the same app.
- Do not map this to Cloud Instance Metadata API unless the report explicitly mentions metadata service access such as `169.254.169.254`.

## Linux Persistence: Cron And Shell Download

Category: linux
Telemetry: linux_process, linux_audit, dns, proxy, firewall
Relevant MITRE: T1053.003, T1105, T1059.004, T1548.003

Investigation steps:

- Review cron file changes, user crontab modifications, and unusual commands in scheduled entries.
- Search for `curl`, `wget`, `bash`, `sh`, or temp-directory script execution.
- Correlate with outbound DNS/proxy/firewall activity and recent SSH/sudo changes.
- Do not include Windows Registry Run Key or mshta techniques.

## Cloud IAM And Storage

Category: cloud
Telemetry: cloud_audit, auth, proxy
Relevant MITRE: T1098, T1098.003, T1530, T1552.005, T1078.004

Investigation steps:

- Review IAM policy/role changes, access key creation, bucket ACL changes, metadata credential access, and unusual API calls.
- Correlate actor, workload, source IP, target resource, user agent, and time window.
- Confirm whether the action was approved change activity.
- Escalate when privilege expansion or public data exposure affects production or sensitive assets.
