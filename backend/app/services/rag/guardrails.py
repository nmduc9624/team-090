import re

from app.schemas.hunt_package import HuntPackage, QueryDraft
from app.services.rag.models import IntentContext


INTENTS: dict[str, IntentContext] = {
    "kerberos_ad": IntentContext(
        name="kerberos_ad",
        categories=("active directory", "identity", "auth"),
        telemetry_allow=("auth", "windows_security", "active_directory", "domain_controller", "kerberos"),
        required_telemetry=("auth", "windows_security", "active_directory"),
        blocked_telemetry=("cloud_audit", "edr_registry", "proxy"),
        mitre_allow_prefixes=("T1558", "T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1003.006", "T1078", "T1087"),
        query_keywords=("kerberos", "as-rep", "asrep", "spn", "dcsync", "ldap", "ticket", "domain controller"),
        blocked_keywords=(
            "cloud iam",
            "admin policy",
            "cloud instance metadata",
            "169.254.169.254",
            "oauth",
            "deploy key",
            "registry run",
            "mshta",
            "bucket",
        ),
        checklist=(
            "Review Windows Security or identity telemetry for Kerberos ticket anomalies, SPN requests, AS-REP activity, DCSync, or LDAP enumeration.",
            "Identify the source host, account, service principal, domain controller, ticket encryption type, and ticket lifetime.",
            "Check whether the source host is expected to perform domain administration or service ticket requests.",
            "Correlate suspicious Kerberos activity with privileged account use and recent authentication anomalies.",
            "Escalate if abnormal Kerberos behavior targets privileged identities or cannot be tied to approved administration.",
        ),
        correlation_logic=(
            "Correlate Kerberos and directory events by account, source host, domain controller, service principal, "
            "ticket properties, and time window. Keep the investigation focused on directory authentication unless "
            "the report contains explicit cloud or process evidence."
        ),
        escalation_condition=(
            "Escalate when abnormal Kerberos ticket, DCSync, AS-REP, SPN, or LDAP activity targets privileged identities "
            "or comes from an unexpected host and cannot be explained by approved directory administration."
        ),
    ),
    "mfa_fatigue": IntentContext(
        name="mfa_fatigue",
        categories=("identity", "auth"),
        telemetry_allow=("auth", "cloud_audit", "email_audit", "proxy"),
        required_telemetry=("auth",),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events"),
        mitre_allow_prefixes=("T1621", "T1078", "T1098", "T1114"),
        query_keywords=("mfa", "push", "challenge", "login", "auth"),
        blocked_keywords=("mshta", "registry run", "lsass", "kerberos", "cloud iam admin policy"),
        checklist=(
            "Search authentication telemetry for repeated MFA push prompts and their outcomes in a short time window.",
            "Identify successful logins that follow multiple denied MFA challenges from unfamiliar IPs, devices, or user agents.",
            "Review follow-on mailbox, SaaS, or cloud access after the suspicious MFA approval.",
            "Compare the source IP, device, and user agent against the user's normal baseline.",
            "Escalate if the approved MFA challenge and follow-on access cannot be explained by the user.",
        ),
        correlation_logic=(
            "Correlate MFA prompt events, denied and approved outcomes, successful login, source IP, device, user agent, "
            "and follow-on SaaS/cloud/email activity within the MFA window and the next 24 hours."
        ),
        escalation_condition=(
            "Escalate when repeated MFA prompts are followed by an approved challenge, suspicious login, or sensitive follow-on access."
        ),
    ),
    "mfa_auth_change": IntentContext(
        name="mfa_auth_change",
        categories=("identity", "auth"),
        telemetry_allow=("auth", "cloud_audit", "email_audit", "proxy"),
        required_telemetry=("auth", "cloud_audit"),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events"),
        mitre_allow_prefixes=("T1098", "T1078", "T1556"),
        query_keywords=("mfa", "authentication method", "strong auth", "security info", "disabled", "removed"),
        blocked_keywords=("push prompt", "push fatigue", "denied mfa", "approved challenge", "mshta", "registry run", "lsass"),
        checklist=(
            "Review identity provider audit logs for MFA disable, authentication method removal, or strong authentication setting changes.",
            "Identify the actor who changed MFA, the target user, source IP, device, user agent, and application used.",
            "Confirm whether the MFA change has an approved change request or helpdesk workflow.",
            "Review successful logins and sensitive application access before and after MFA was disabled.",
            "Check whether other authentication methods, recovery options, or security information were modified.",
            "Escalate if MFA was disabled without approval or is followed by suspicious login or sensitive access.",
        ),
        correlation_logic=(
            "Correlate MFA disable or authentication method change events by actor, target user, source IP, device, "
            "user agent, session, and follow-on login or application access."
        ),
        escalation_condition=(
            "Escalate when MFA or authentication methods are disabled or removed without an approved workflow, "
            "especially when suspicious login or sensitive access follows."
        ),
    ),
    "password_spray": IntentContext(
        name="password_spray",
        categories=("identity", "auth"),
        telemetry_allow=("auth", "proxy", "cloud_audit"),
        required_telemetry=("auth",),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service"),
        mitre_allow_prefixes=("T1110.003", "T1110", "T1078"),
        query_keywords=("password", "spray", "brute", "failed login", "auth"),
        blocked_keywords=("mshta", "registry run", "lsass", "oauth consent", "cloud iam"),
        checklist=(
            "Review authentication logs for many failed logins across many users from the same source IP, ASN, device, or user agent.",
            "Measure distinct failed users, failures per user, target applications, and any successful login after the spray window.",
            "Check whether the source IP, user agent, or application is known business infrastructure, VPN, SSO, or automation.",
            "Identify users with successful logins after repeated failures and review MFA/session context.",
            "Escalate if broad user targeting or a post-spray successful login cannot be explained by approved activity.",
        ),
        correlation_logic=(
            "Correlate failed authentication events by source IP, user agent, application, tenant, and 15-60 minute window. "
            "Review any successful login from the same source or user agent after the spray activity."
        ),
        escalation_condition=(
            "Escalate when one source targets many accounts with repeated failures or when a target account successfully logs in after spray activity."
        ),
    ),
    "remote_access": IntentContext(
        name="remote_access",
        categories=("remote access", "identity", "auth"),
        telemetry_allow=("auth", "firewall", "proxy"),
        required_telemetry=("auth", "firewall"),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events", "cloud_audit"),
        mitre_allow_prefixes=("T1133", "T1078", "T1021"),
        query_keywords=("rdp", "vpn", "remote access", "remote desktop", "after-hours", "after hours", "new country"),
        blocked_keywords=("oauth consent", "cloud iam", "bucket", "registry run", "mshta", "lsass", "remote registry"),
        checklist=(
            "Review authentication and remote access telemetry for RDP, VPN, or remote portal logins from unusual source IPs, countries, devices, or times.",
            "Identify the user, source IP, user agent, remote access application, destination asset, and session outcome.",
            "Compare the login time, geography, device, and destination with the user's normal baseline.",
            "Review firewall or VPN session logs for destination resources accessed after the remote login.",
            "Escalate if the remote access session is unusual, outside approved hours, or followed by sensitive internal access.",
        ),
        correlation_logic=(
            "Correlate auth, VPN/RDP/firewall, proxy, source IP, device, user agent, destination asset, login time, and follow-on internal access."
        ),
        escalation_condition=(
            "Escalate when remote access login is confirmed from an unusual source, time, or device and cannot be explained by approved business activity."
        ),
    ),    "cloud_storage": IntentContext(
        name="cloud_storage",
        categories=("cloud", "cloud security", "storage"),
        telemetry_allow=("cloud_audit", "auth", "proxy"),
        required_telemetry=("cloud_audit",),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service"),
        mitre_allow_prefixes=("T1530", "T1567.002", "T1078.004", "T1098"),
        query_keywords=("bucket", "storage", "acl", "public", "object"),
        blocked_keywords=("mshta", "registry run", "lsass", "cloud instance metadata", "deploy key", "process chain", "persistence changes"),
        checklist=(
            "Review cloud audit logs for bucket, container, object ACL, or storage policy changes that grant public access.",
            "Identify the actor/principal, bucket or object, operation, source IP, user agent, and exact public access scope.",
            "Check whether public access includes allUsers, anonymous, Everyone, or equivalent public principals.",
            "Confirm whether the exposure was approved and whether public access was reverted.",
            "Review object access or download activity after the public access change.",
            "Escalate if sensitive or production storage was exposed without approval.",
        ),
        correlation_logic=(
            "Correlate storage ACL or policy changes by actor/principal, bucket/object, public principal, source IP, "
            "user agent, and follow-on object access or download activity."
        ),
        escalation_condition=(
            "Escalate when a bucket or object is made public without approval, especially if sensitive or production data is exposed."
        ),
    ),
    "cloud_metadata": IntentContext(
        name="cloud_metadata",
        categories=("cloud", "cloud security", "identity"),
        telemetry_allow=("cloud_audit", "auth", "proxy", "edr_process"),
        required_telemetry=("cloud_audit",),
        blocked_telemetry=("edr_registry", "windows_service"),
        mitre_allow_prefixes=("T1552.005", "T1078.004", "T1098"),
        query_keywords=("metadata", "169.254.169.254", "imds", "token"),
        blocked_keywords=("registry run", "mshta", "oauth consent", "deploy key", "persistence changes"),
        checklist=(
            "Identify the workload, instance, role, or service account that accessed cloud instance metadata credentials.",
            "Check metadata endpoint access such as 169.254.169.254, metadata.google.internal, or IMDS token activity.",
            "Review cloud audit logs for API calls made after metadata credential access.",
            "Determine whether the API calls are unusual for that workload identity or service account.",
            "Check source IP, user agent, instance ID, role or service account, target resources, and time window.",
            "Escalate if metadata credentials are used from an unexpected workload or cause unusual API activity.",
        ),
        correlation_logic=(
            "Correlate metadata endpoint access with workload identity, instance ID, role or service account, "
            "source IP, user agent, and follow-on cloud API calls."
        ),
        escalation_condition=(
            "Escalate when metadata credentials are accessed or used by an unexpected workload, or when follow-on API activity is unusual."
        ),
    ),
    "developer_platform": IntentContext(
        name="developer_platform",
        categories=("developer_platform", "saas", "identity"),
        telemetry_allow=("cloud_audit", "auth", "proxy", "github_audit", "gitlab_audit"),
        required_telemetry=("cloud_audit", "auth"),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events"),
        mitre_allow_prefixes=("T1528", "T1098", "T1552", "T1530", "T1078"),
        query_keywords=("developer", "oauth", "saas", "repo", "repository", "github", "gitlab"),
        blocked_keywords=("mshta", "registry run", "lsass", "windows registry", "cloud instance metadata"),
        checklist=(
            "Review GitHub audit logs for OAuth app authorization, granted scopes, private repository access, deploy key creation, and secrets metadata access.",
            "Identify the developer account, OAuth app, publisher, source IP, user agent, repositories, organizations, and permission scopes.",
            "Confirm whether the app and deploy key are approved by engineering or platform security.",
            "Review follow-on repository clone/read, workflow, token, and secret metadata activity after app authorization.",
            "Escalate if the app is unapproved, has broad repo/secrets permissions, or creates deploy keys on sensitive repositories.",
        ),
        correlation_logic=(
            "Correlate GitHub OAuth authorization, repository access, deploy key creation, secrets metadata access, "
            "developer login source IP, user agent, and repository sensitivity within the same session or 24-hour window."
        ),
        escalation_condition=(
            "Escalate when an unapproved GitHub OAuth app accesses private repositories, reads secrets metadata, or creates deploy keys."
        ),
    ),
    "saas_oauth": IntentContext(
        name="saas_oauth",
        categories=("saas", "identity", "cloud"),
        telemetry_allow=("cloud_audit", "auth", "email_audit", "proxy"),
        required_telemetry=("cloud_audit", "email_audit", "proxy"),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events"),
        mitre_allow_prefixes=("T1528", "T1530", "T1567.002", "T1078", "T1098", "T1114"),
        query_keywords=("oauth", "saas", "consent", "file export"),
        blocked_keywords=("mshta", "registry run", "lsass", "windows registry"),
        checklist=(
            "Review SaaS or identity audit logs for OAuth consent, app authorization, permission scope changes, and app install events.",
            "Identify the user, app, publisher, permission scopes, source IP, user agent, tenant/workspace, and app risk status.",
            "Review SaaS audit activity for file reads, channel reads, exports, or bulk downloads after consent.",
            "Check whether the same app was authorized by other users or accessed sensitive workspaces.",
            "Escalate if the app is unverified, has broad read/export scopes, or accesses sensitive collaboration data.",
        ),
        correlation_logic=(
            "Correlate OAuth consent, app authorization, SaaS file/channel access, user login context, source IP, user agent, "
            "and export/download actions by user and app."
        ),
        escalation_condition=(
            "Escalate when an unapproved SaaS OAuth app receives broad scopes or performs sensitive read/export activity."
        ),
    ),
    "linux": IntentContext(
        name="linux",
        categories=("linux", "endpoint"),
        telemetry_allow=("linux_process", "linux_audit", "auth", "file_events", "dns", "proxy", "firewall", "edr_process"),
        required_telemetry=("linux_audit", "auth"),
        blocked_telemetry=("edr_registry", "windows_service", "wmi_events", "driver_load"),
        mitre_allow_prefixes=("T1136", "T1136.001", "T1053.003", "T1105", "T1059.004", "T1548", "T1548.003", "T1021.004", "T1204.002", "T1005", "T1110", "T1110.003", "T1078"),
        query_keywords=("linux", "cron", "ssh", "bash", "shell", "uid 0", "root-equivalent", "passwd", "useradd"),
        blocked_keywords=("windows registry", "run key", "mshta", "lsass"),
        checklist=(
            "Review Linux audit/process telemetry for cron, systemd, shell profile, sudoers, SSH authorized_keys, or /etc persistence changes.",
            "Identify the user, UID, parent process, command line, file path, source IP, and host baseline.",
            "Check whether curl, wget, bash, python, perl, or reverse-shell commands appear near persistence changes.",
            "Review recent SSH, sudo, privilege escalation, and outbound network activity on the same host.",
            "Escalate if persistence or privilege changes are not approved administration activity.",
        ),
        correlation_logic=(
            "Correlate Linux file modification, process execution, SSH/auth events, UID changes, source IP, and outbound network activity on the same host."
        ),
        escalation_condition=(
            "Escalate when Linux persistence, root privilege change, or reverse-shell behavior is confirmed outside approved administration."
        ),
    ),
    "kubernetes_container": IntentContext(
        name="kubernetes_container",
        categories=("kubernetes security", "container security", "kubernetes", "container"),
        telemetry_allow=("kubernetes_audit", "cloud_audit", "auth", "container_runtime", "linux_audit", "linux_process"),
        required_telemetry=("kubernetes_audit", "cloud_audit", "auth"),
        blocked_telemetry=("edr_registry", "windows_service", "wmi_events"),
        mitre_allow_prefixes=("T1609", "T1611", "T1552", "T1078", "T1098"),
        query_keywords=("kubernetes", "kubectl", "pod", "container", "secret", "privileged"),
        blocked_keywords=("windows registry", "run key", "mshta", "lsass", "oauth consent"),
        checklist=(
            "Review Kubernetes audit logs for kubectl exec, privileged pod creation, secret reads, service account changes, and role binding changes.",
            "Identify the user, source IP, namespace, resource, object name, verb, request URI, and response status.",
            "Check whether the action is expected for that user, namespace, workload, and deployment workflow.",
            "Review container runtime telemetry for follow-on command execution or unusual image/workload activity.",
            "Escalate if secret access, privileged workload creation, or exec into pod is unapproved or targets sensitive namespaces.",
        ),
        correlation_logic=(
            "Correlate Kubernetes API activity by user, source IP, namespace, resource, object, verb, and follow-on container runtime activity."
        ),
        escalation_condition=(
            "Escalate when sensitive Kubernetes API actions are unapproved, target secrets or privileged workloads, or occur from unusual users/IPs."
        ),
    ),
    "web_attack": IntentContext(
        name="web_attack",
        categories=("web attack", "web"),
        telemetry_allow=("web_server", "waf", "proxy", "auth", "file_events", "firewall", "edr_process"),
        required_telemetry=("web_server",),
        blocked_telemetry=("edr_registry", "cloud_audit"),
        mitre_allow_prefixes=("T1190", "T1505.003", "T1059", "T1078"),
        query_keywords=("web", "waf", "sql", "rce", "traversal", "upload", "webshell", "admin panel"),
        blocked_keywords=("cloud iam", "oauth consent", "registry run", "lsass"),
        checklist=(
            "Review web server, WAF, and reverse proxy logs for exploit patterns such as RCE, SQL injection, traversal, upload abuse, or webshell access.",
            "Identify source IP, host, URI, method, status code, user agent, request pattern, and affected application.",
            "Check whether the request created or executed files, spawned child processes, or changed application content.",
            "Correlate WAF detections with web server responses and endpoint/file telemetry on the web host.",
            "Escalate if exploit attempts succeed, create files, execute commands, or target production applications.",
        ),
        correlation_logic=(
            "Correlate WAF/web server detections with application host file/process activity by source IP, URI, host, user agent, and time window."
        ),
        escalation_condition=(
            "Escalate when a web attack appears successful or creates execution, file write, authentication bypass, or sensitive data access evidence."
        ),
    ),
    "email_mailbox": IntentContext(
        name="email_mailbox",
        categories=("email", "saas", "identity"),
        telemetry_allow=("email", "email_audit", "auth", "proxy", "dns"),
        required_telemetry=("email_audit",),
        blocked_telemetry=("edr_registry", "windows_service"),
        mitre_allow_prefixes=("T1566", "T1114", "T1098", "T1078"),
        query_keywords=("mailbox", "inbox", "forwarding", "email", "mail"),
        blocked_keywords=("mshta", "registry run", "lsass", "cloud iam"),
    ),
    "endpoint_lolbin": IntentContext(
        name="endpoint_lolbin",
        categories=("endpoint", "malware", "signed binary abuse", "office malware"),
        telemetry_allow=("edr_process", "edr_registry", "dns", "proxy", "file_events"),
        required_telemetry=("edr_process",),
        blocked_telemetry=("cloud_audit", "email_audit"),
        mitre_allow_prefixes=("T1218", "T1059", "T1105", "T1204.002", "T1071", "T1547", "T1546", "T1562", "T1070"),
        query_keywords=("process", "powershell", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild", "registry", "npm", "postinstall"),
        blocked_keywords=("oauth consent", "deploy key", "repository secrets", "cloud iam"),
    ),
    "endpoint_credential": IntentContext(
        name="endpoint_credential",
        categories=("credential access", "endpoint", "malware"),
        telemetry_allow=("edr_process", "file_events", "edr_file", "auth"),
        required_telemetry=("edr_process",),
        blocked_telemetry=("cloud_audit", "email_audit"),
        mitre_allow_prefixes=("T1003", "T1003.001", "T1055", "T1078"),
        query_keywords=("lsass", "credential", "dump", "browser credential"),
        blocked_keywords=("oauth consent", "cloud iam", "bucket", "deploy key"),
    ),
    "endpoint_lateral": IntentContext(
        name="endpoint_lateral",
        categories=("lateral movement", "endpoint"),
        telemetry_allow=("edr_process", "windows_service", "wmi_events", "auth", "file_events", "firewall"),
        required_telemetry=("edr_process", "auth"),
        blocked_telemetry=("cloud_audit", "email_audit"),
        mitre_allow_prefixes=("T1021", "T1047", "T1569.002", "T1078", "T1105", "T1546", "T1543", "T1036"),
        query_keywords=("service", "psexec", "smb", "admin$", "winrm", "wmi", "lateral"),
        blocked_keywords=("oauth consent", "cloud iam", "bucket"),
        checklist=(
            "Review process, Windows service, WMI, authentication, and firewall telemetry for remote administration or lateral movement activity.",
            "Identify source host, target host, account, service name, process command line, admin share use, and remote logon type.",
            "For Remote Registry, confirm service enable/start events and related sc.exe, reg.exe, wmic.exe, or psexec activity.",
            "Check target host for follow-on process, service, task, file, or registry changes after remote access.",
            "Escalate if the source account/host is unusual or the remote action is not approved administration.",
        ),
        correlation_logic=(
            "Correlate remote logon, service creation/start, WMI/WinRM/PsExec, admin share/file events, and target-host process activity by source host, account, and time window."
        ),
        escalation_condition=(
            "Escalate when remote administration or Remote Registry activity is confirmed from an unusual source or lacks approved change context."
        ),
    ),
    "defense_evasion": IntentContext(
        name="defense_evasion",
        categories=("defense evasion", "ransomware behavior", "endpoint"),
        telemetry_allow=("edr_process", "edr_registry", "windows_service", "driver_load", "file_events", "auth"),
        required_telemetry=("edr_process", "edr_registry", "auth"),
        blocked_telemetry=("cloud_audit", "email_audit"),
        mitre_allow_prefixes=("T1562", "T1068", "T1070", "T1490"),
        query_keywords=("defender", "driver", "security log", "shadow copy", "backup", "tamper"),
        blocked_keywords=("oauth consent", "cloud iam", "bucket"),
        checklist=(
            "Review EDR, Windows service, driver load, and file telemetry for security tool tampering, log clearing, shadow copy deletion, or backup disruption.",
            "Identify the user, host, process, command line, service, driver, signer, and action result.",
            "Check whether the activity was initiated by approved security tooling, patching, or administrator workflow.",
            "Review nearby process chains and authentication events for ransomware or privilege escalation indicators.",
            "Escalate if defensive controls are disabled, logs are cleared, backups are stopped, or shadow copies are deleted without approval.",
        ),
        correlation_logic=(
            "Correlate tampering commands, service/driver changes, file deletion, backup/shadow copy events, and recent authentication by host and user."
        ),
        escalation_condition=(
            "Escalate when security tooling, logs, drivers, backups, or shadow copies are modified without approved administrative context."
        ),
    ),
    "identity": IntentContext(
        name="identity",
        categories=("identity", "auth", "cloud"),
        telemetry_allow=("auth", "cloud_audit", "proxy", "email_audit"),
        mitre_allow_prefixes=("T1110", "T1110.003", "T1078", "T1098", "T1556"),
        query_keywords=("auth", "login", "password", "spray", "oauth"),
        blocked_keywords=("mshta", "registry run", "lsass", "malware process chain"),
    ),
    "dns": IntentContext(
        name="dns",
        categories=("network", "dns", "endpoint"),
        telemetry_allow=("dns", "proxy", "firewall", "edr_process"),
        mitre_allow_prefixes=("T1071", "T1071.004", "T1041", "T1105", "T1059"),
        query_keywords=("dns", "tunneling", "powershell"),
        blocked_keywords=("oauth consent", "deploy key", "repository secrets"),
    ),
    "cloud": IntentContext(
        name="cloud",
        categories=("cloud", "identity"),
        telemetry_allow=("cloud_audit", "auth", "proxy"),
        mitre_allow_prefixes=("T1530", "T1552.005", "T1078.004", "T1098", "T1528", "T1562"),
        query_keywords=("cloud", "iam", "bucket", "metadata", "oauth"),
        blocked_keywords=("mshta", "registry run", "lsass"),
    ),
    "data_exfil": IntentContext(
        name="data_exfil",
        categories=("data loss", "network", "endpoint"),
        telemetry_allow=("edr_process", "proxy", "file_events", "dns", "firewall", "cloud_audit"),
        required_telemetry=("proxy", "file_events"),
        blocked_telemetry=("edr_registry", "windows_service"),
        mitre_allow_prefixes=("T1567.002", "T1560", "T1041", "T1530", "T1105"),
        query_keywords=("rclone", "exfil", "upload", "cloud drive", "personal drive", "bytes_out", "archive"),
        blocked_keywords=("oauth consent", "cloud iam", "kerberos", "registry run"),
    ),
    "cloud_iam": IntentContext(
        name="cloud_iam",
        categories=("cloud", "identity"),
        telemetry_allow=("cloud_audit", "auth", "proxy"),
        required_telemetry=("cloud_audit", "auth"),
        blocked_telemetry=("edr_process", "edr_registry", "windows_service", "wmi_events", "driver_load"),
        mitre_allow_prefixes=("T1098", "T1098.003", "T1078.004"),
        query_keywords=("cloud", "iam", "admin", "administrator", "policy", "role", "attach", "audit"),
        blocked_keywords=(
            "mshta",
            "registry run",
            "lsass",
            "windows service",
            "remote service execution",
            "cloud instance metadata",
            "169.254.169.254",
            "bucket",
            "public access",
            "cloud storage",
            "t1530",
        ),
    ),
    "endpoint": IntentContext(
        name="endpoint",
        categories=("endpoint", "malware"),
        telemetry_allow=("edr_process", "edr_registry", "dns", "proxy", "firewall", "windows_service", "wmi_events"),
        mitre_allow_prefixes=(
            "T1218",
            "T1547",
            "T1546",
            "T1543",
            "T1036",
            "T1003",
            "T1055",
            "T1105",
            "T1071",
            "T1053",
            "T1204.002",
            "T1560",
            "T1041",
            "T1195",
            "T1562",
            "T1068",
            "T1070",
            "T1490",
        ),
        query_keywords=("process", "registry", "powershell", "dns", "service"),
        blocked_keywords=("oauth consent", "repository secrets", "deploy key"),
    ),
}


def classify_intent(title: str, content: str) -> IntentContext:
    text = f"{title}\n{content}".lower()
    if re.search(r"\bkerberos\b|\bkerberoast|\bas-?rep\b|\bdcsync\b|\bspn\b|\bgolden ticket\b|\btgt\b|\btgs\b|\bldap\b|\bdomain controller\b", text):
        return INTENTS["kerberos_ad"]
    if re.search(r"\bmfa\b", text) and re.search(r"\bdisabled\b|\bdisable\b|\bremoved?\b|\bauthentication method\b|\bsecurity info\b|\bstrong auth\b", text):
        return INTENTS["mfa_auth_change"]
    if re.search(r"\bmfa\b|\bpush fatigue\b|\bpush prompts?\b|\bchallenge\b", text):
        return INTENTS["mfa_fatigue"]
    if re.search(r"\blinux\b", text) and re.search(r"\bssh\b|\bsshd\b", text) and re.search(r"\bbrute force\b|\bfailed logins?\b|\bauthentication attempts?\b", text):
        return INTENTS["linux"]
    if re.search(r"\brdp\b|\bvpn\b|\bremote access\b|\bremote desktop\b|\bafter-hours rdp\b|\bafter hours rdp\b", text):
        return INTENTS["remote_access"]
    if re.search(r"\bpassword spray\b|\bspraying\b|\bfailed logins?\b", text) or (
        re.search(r"\bbrute force\b", text) and not re.search(r"\bweb server\b|\bweb app\b|\bweb attack\b|\badmin panel\b", text)
    ):
        return INTENTS["password_spray"]
    if re.search(r"\bgithub\b|\bgitlab\b|\bbitbucket\b|\brepositor(?:y|ies)\b|\bdeploy key\b|\bsecrets? metadata\b", text):
        return INTENTS["developer_platform"]
    if re.search(r"\boauth\b|\bconsent\b|\bunverified app\b", text) and re.search(r"\bslack\b|\bteams\b|\bworkspace\b|\bchannel\b|\bsaas\b|\bexport", text):
        return INTENTS["saas_oauth"]
    if re.search(r"\bshadow cop(?:y|ies)\b|\bvssadmin\b|\bwbadmin\b|\bransomware\b|\bransom extension\b", text):
        return INTENTS["defense_evasion"]
    if re.search(r"\bdata loss\b|\blarge upload\b|\bpersonal drive\b|\brclone\b|\bbytes_out\b|\bexfil\b", text):
        return INTENTS["data_exfil"]
    if re.search(r"\bsaas\b|\bcloud drive\b|\bmass file download\b|\bfile download\b", text) and re.search(r"\bdownload(?:ed)? files?\b|\bexport\b|\bsensitive data\b|\bbaseline\b", text):
        return INTENTS["saas_oauth"]
    if re.search(r"\bmailbox\b|\binbox\b|\bforwarding rule\b|\bmail rule\b", text):
        return INTENTS["email_mailbox"]
    if re.search(r"\blinux\b|\bcron\b|\bsudoers\b|\bssh\b|\breverse shell\b|\buid\s*0\b|root-equivalent|root equivalent|/etc/passwd", text):
        return INTENTS["linux"]
    if re.search(r"\bkubernetes\b|\bkubectl\b|\bpod\b|\bprivileged container\b", text):
        return INTENTS["kubernetes_container"]
    if re.search(r"\bwebshell\b|\bsql injection\b|\bpath traversal\b|\brce\b|\bremote code execution\b|\bfile upload\b|\bfile uploaded\b|\bupload pattern\b|\bweb attack\b|\bweb server\b|\bweb app\b|\badmin panel\b", text):
        return INTENTS["web_attack"]
    if re.search(r"\blsass\b|\bcredential dump\b|\bbrowser credential\b|\bcredentials? from web browsers?\b", text):
        return INTENTS["endpoint_credential"]
    if re.search(r"\bcloud\b", text) and re.search(r"\bapi key\b|\baccess key\b|\btoken\b|\baudit settings?\b", text):
        return INTENTS["cloud"]
    if re.search(r"\bpassword spray\b|\bspraying\b|\bbrute force\b|\bmfa\b|\bimpossible travel\b|\blogin\b", text):
        return INTENTS["identity"]
    if re.search(r"\bdns\b|\btxt\b|\bnxdomain\b|\btunneling\b|\bdga\b", text):
        return INTENTS["dns"]
    if re.search(r"\biam\b|\badmin(?:istrator)? policy\b|\badmin role\b|\battach(?:ed)? policy\b|\bsetiampolicy\b|\battachpolicy\b", text):
        return INTENTS["cloud_iam"]
    if re.search(r"\bpublic bucket\b|\bstorage bucket\b|\bbucket\b|\bobject storage\b|\bacl\b", text):
        return INTENTS["cloud_storage"]
    if re.search(r"\bcloud instance metadata\b|\binstance metadata\b|\bmetadata service\b|\bmetadata token\b|\b169\.254\.169\.254\b|\bimds\b", text):
        return INTENTS["cloud_metadata"]
    if re.search(r"\bcloud\b|\biam\b|\bbucket\b|\baccess key\b", text):
        return INTENTS["cloud"]
    if re.search(r"\bpsexec\b|\bpsexesvc\b|\badmin share\b|\badministrative share\b|\badmin\$\b|\bsmb\b|\bwinrm\b|\bwmi\b|\bremote service\b|\bremote administration\b", text):
        return INTENTS["endpoint_lateral"]
    if re.search(r"\bpowershell\b|\bmshta\b|\brundll32\b|\bregsvr32\b|\bcertutil\b|\bbitsadmin\b|\bmsbuild\b|\binstallutil\b|\boffice\b|\bmacro\b|\bexcel\b", text):
        return INTENTS["endpoint_lolbin"]
    if re.search(r"\bdefender\b|\bsecurity log\b|\bshadow copy\b|\bdriver\b|\bbackup service\b|\btamper\b|\bfirewall rule\b", text):
        return INTENTS["defense_evasion"]
    return INTENTS["endpoint"]


def filter_retrieval_metadata(intent: IntentContext, metadata: dict[str, str]) -> bool:
    category = metadata.get("category", "").lower()
    telemetry = metadata.get("telemetry", "").lower()
    source_type = metadata.get("source_type", "").lower()

    if category and category in intent.categories:
        return True
    if telemetry and telemetry in intent.telemetry_allow:
        return True
    if source_type in {"mitre", "schema", "guardrail"}:
        return True
    return not category


def apply_output_guardrails(package: HuntPackage, intent: IntentContext) -> HuntPackage:
    allowed_telemetry = set(intent.telemetry_allow)
    if allowed_telemetry:
        blocked_telemetry = set(intent.blocked_telemetry)
        package.required_telemetry = [item for item in package.required_telemetry if item in allowed_telemetry and item not in blocked_telemetry]
        package.required_telemetry = _merge_ordered([*intent.required_telemetry, *package.required_telemetry])
        if not package.required_telemetry:
            package.required_telemetry = list(intent.telemetry_allow[:3])

    def allowed_mitre(item: str) -> bool:
        code = item.split(" - ", 1)[0]
        return any(code.startswith(prefix) for prefix in intent.mitre_allow_prefixes)

    if intent.mitre_allow_prefixes:
        package.mitre_mapping = [item for item in package.mitre_mapping if allowed_mitre(item)]

    blocked = tuple(keyword.lower() for keyword in intent.blocked_keywords)
    package.key_behaviors = [item for item in package.key_behaviors if not any(keyword in item.lower() for keyword in blocked)]
    package.mitre_mapping = [item for item in package.mitre_mapping if not any(keyword in item.lower() for keyword in blocked)]
    package.hunt_checklist = [item for item in package.hunt_checklist if not any(keyword in item.lower() for keyword in blocked)]
    package.query_drafts = _filter_queries(package.query_drafts, intent)
    if intent.checklist:
        package.hunt_checklist = _intent_checklist(intent, package.hunt_checklist)
    elif intent.name == "cloud_iam":
        package.hunt_checklist = _cloud_iam_checklist(package.hunt_checklist)
    if intent.correlation_logic:
        package.correlation_logic = intent.correlation_logic
    elif intent.name == "cloud_iam":
        package.correlation_logic = (
            "Correlate cloud audit events by actor/principal, target user/role/service account, "
            "resource, source IP, user agent, and time window. Confirm whether the IAM admin policy "
            "attachment was approved change activity."
        )
    if intent.escalation_condition:
        package.escalation_condition = intent.escalation_condition
    return package


def _merge_ordered(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if not item:
            continue
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _intent_checklist(intent: IntentContext, existing: list[str]) -> list[str]:
    blocked = tuple(keyword.lower() for keyword in intent.blocked_keywords)
    preferred = [*intent.checklist, *existing]
    return _merge_ordered([item for item in preferred if not any(keyword in item.lower() for keyword in blocked)])[:10]


def _cloud_iam_checklist(existing: list[str]) -> list[str]:
    preferred = [
        "Review cloud audit logs for IAM admin policy attachment or privileged role assignment events.",
        "Identify the actor/principal, target user, role or service account, resource, source IP, and user agent.",
        "Check whether the actor normally performs IAM changes and whether the change was approved.",
        "Review follow-on activity after the privilege expansion, especially access to sensitive resources.",
        "Check authentication context for the actor, including new location, new device, MFA, and session anomalies.",
        "Escalate if admin privileges were granted to an unusual identity, workload, service account, or production asset.",
    ]
    seen = set()
    output = []
    for item in [*preferred, *existing]:
        if "host" in item.lower():
            continue
        key = item.lower()
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output[:10]


def _filter_queries(queries: list[QueryDraft], intent: IntentContext) -> list[QueryDraft]:
    allowed = []
    name_tokens = _query_name_tokens(intent.name)
    for query in queries:
        haystack = f"{query.name}\n{query.purpose}\n{query.query}".lower()
        identity = f"{query.name}\n{query.purpose}".lower()
        matched = any(token in identity for token in name_tokens) if name_tokens else any(
            keyword in haystack for keyword in intent.query_keywords
        )
        if matched:
            if not any(keyword in haystack for keyword in intent.blocked_keywords):
                allowed.append(query)
    return allowed


def _query_name_tokens(intent_name: str) -> tuple[str, ...]:
    return {
        "kerberos_ad": ("kerberos", "dcsync", "asrep", "spn"),
        "mfa_fatigue": ("mfa",),
        "mfa_auth_change": ("mfa", "auth method", "authentication method"),
        "password_spray": ("password", "spray"),
        "cloud_iam": ("cloud iam", "admin policy", "role assignment"),
        "cloud_storage": ("cloud storage", "bucket"),
        "cloud_metadata": ("metadata",),
        "developer_platform": ("developer", "github", "gitlab", "repo"),
        "saas_oauth": ("saas", "oauth"),
        "linux": ("linux", "cron", "ssh", "uid 0", "uid0", "passwd", "useradd"),
        "kubernetes_container": ("kubernetes", "container"),
        "web_attack": ("web", "waf"),
        "data_exfil": ("rclone", "exfil", "upload", "proxy"),
        "email_mailbox": ("mailbox", "email"),
        "endpoint_lolbin": ("powershell", "process", "registry", "encoded", "lolbin"),
        "endpoint_credential": ("credential", "lsass", "procdump"),
        "remote_access": ("remote", "rdp", "vpn", "remote access"),
        "endpoint_lateral": ("lateral", "service", "psexec", "smb", "winrm", "wmi", "remote registry"),
        "defense_evasion": ("defense", "driver", "shadow", "tamper"),
    }.get(intent_name, ())














