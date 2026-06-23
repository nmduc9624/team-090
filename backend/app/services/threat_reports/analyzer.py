import hashlib
import re
from typing import Any

from app.schemas.hunt_package import HuntPackage, IOC, QueryDraft
from app.schemas.threat_report import ThreatReportRequest
from app.services.hunt_packages.store import save_hunt_package
from app.services.ioc_extraction.extractor import extract_ioc
from app.services.query_generation.template_loader import find_templates_for_text
from app.services.rag.guardrails import apply_output_guardrails, classify_intent
from app.services.telemetry_schemas.loader import list_telemetry_sources
from app.services.threat_reports.retriever import retrieve_similar_hunt_package
from app.services.ttp_mapping.mapper import map_behaviors_to_mitre


BEHAVIOR_RULES: list[tuple[str, str, list[str]]] = [
    ("excel.exe launches mshta.exe", "excel", ["mshta"]),
    ("Office process launches script interpreter", "office", ["wscript", "powershell", "mshta"]),
    ("Encoded or hidden PowerShell execution", "powershell", ["encoded", "-enc", "-nop", "hidden"]),
    ("Registry Run Key persistence is created", "registry", ["run key", "currentversion\\run"]),
    ("Scheduled task persistence is created", "scheduled", ["schtasks", "scheduled task"]),
    ("WMI event subscription persistence is created", "wmi", ["event subscription", "commandlineeventconsumer"]),
    ("Windows service persistence or remote service execution", "service", ["sc.exe", "new service", "service installed", "remote service"]),
    ("DNS tunneling or abnormal DNS queries", "dns", ["txt", "tunneling", "nxdomain", "subdomain"]),
    ("OAuth consent or cloud token abuse", "oauth", ["consent", "oauth", "mail.read", "permission", "permissions"]),
    ("SaaS OAuth app reads or exports collaboration data", "oauth", ["slack", "channel", "workspace", "export", "exports", "files"]),
    ("Developer platform OAuth app accesses repositories or secrets", "oauth", ["github", "gitlab", "repository", "repositories", "deploy key", "secrets"]),
    ("Credential dumping against LSASS", "lsass", ["lsass", "credential dump"]),
    ("Lateral movement via SMB or admin shares", "admin share", ["admin$", "smb", "psexec"]),
    ("Webshell behavior on public web server", "webshell", ["webshell", "w3wp", "aspx", "jsp"]),
    ("Data staging or exfiltration tooling", "exfil", ["rclone", "archive", "bytes_out", "exfil"]),
    ("Linux cron persistence with shell download", "cron", ["cron", "curl", "bash"]),
    ("Security tool tampering or driver abuse", "driver", ["driver", "disable", "security tool"]),
    ("Password spraying against many accounts", "password", ["spray", "spraying"]),
    ("Brute force login attempts against an account", "brute", ["force", "failed login"]),
    ("Suspicious authentication or account takeover pattern", "login", ["mfa", "password", "account", "tor", "vpn", "unfamiliar ip"]),
    ("Cloud control plane or IAM change requires review", "cloud", ["iam", "bucket", "access key", "metadata"]),
    ("Active Directory credential or Kerberos abuse pattern", "kerberos", ["as-rep", "dcsync", "spn", "ticket"]),
    ("Linux privilege or shell activity requires review", "linux", ["sudoers", "ssh", "reverse shell", "uid 0"]),
    ("Kubernetes or container control plane activity requires review", "kubernetes", ["secret", "pod", "container", "privileged"]),
    ("Public web application attack pattern", "web", ["sql", "rce", "traversal", "upload", "admin panel"]),
]


PROSE_BEHAVIOR_PATTERNS: list[tuple[str, str]] = [
    (r"([a-z0-9_.-]+\.exe)\s+(?:launches?|spawns?|executes?|runs?)\s+([a-z0-9_.-]+\.exe)", "{0} spawns {1}"),
    (r"(?:registry|run key|startup folder).{0,40}(?:created|modified|added|written)", "Registry persistence is created"),
    (r"(?:scheduled task|schtasks?).{0,40}(?:created|added|registered)", "Scheduled task persistence is created"),
    (r"(?:shadow copies?|vssadmin).{0,50}(?:deleted|removed|destroyed)", "Volume shadow copies are deleted"),
    (r"(?:lsass|credential).{0,50}(?:dumped|dump|accessed|opened|extracted)", "Credential dumping against LSASS"),
    (r"(?:oauth|consent).{0,50}(?:granted|authorized|approved)", "OAuth consent granted to application"),
    (r"(?:mfa|multi.factor).{0,50}(?:disabled|removed|bypassed)", "MFA disabled or authentication method removed"),
    (r"(?:deploy key|webhook).{0,50}(?:created|added|registered)", "Deploy key or webhook created in repository"),
    (r"creates?.{0,60}(?:deploy key|webhook)", "Deploy key or webhook created in repository"),
    (r"(?:cron|crontab).{0,50}(?:added|created|modified)", "Cron persistence entry created"),
    (r"(?:uid\s*0|root-equivalent|root equivalent).{0,80}(?:user|account|created|added)", "Linux UID 0 or root-equivalent account created"),
    (r"(?:public access|made public|publicly accessible).{0,60}(?:bucket|storage|blob)", "Cloud storage bucket made publicly accessible"),
    (r"(?:admin policy|iam policy|privileged role).{0,50}(?:attached|assigned|granted)", "IAM admin policy or privileged role assigned"),
]
TELEMETRY_KEYWORDS = {
    "edr_process": ["process", ".exe", "powershell", "mshta", "rundll32", "wscript", "cmd", "bash"],
    "edr_registry": ["registry", "run key", "currentversion\\run"],
    "dns": ["dns", "domain", "txt", "nxdomain", "subdomain"],
    "proxy": ["http", "https", "url", "download", "domain", "bytes_out", "export"],
    "auth": ["login", "account", "mfa", "oauth", "token", "kerberos", "rdp", "vpn", "ssh", "session", "unfamiliar ip"],
    "cloud_audit": ["cloud", "api key", "oauth", "consent", "iam", "bucket", "instance metadata", "metadata token", "kubernetes", "slack", "saas"],
    "email": ["email", "attachment", "phishing"],
    "email_audit": ["mailbox", "mail.read", "email", "inbox", "forwarding", "channel", "slack"],
    "windows_service": ["service", "sc.exe", "psexec"],
    "wmi_events": ["wmi"],
    "linux_process": ["linux", "bash", "cron", "sudoers", "reverse shell", "container"],
    "linux_audit": ["linux", "cron", "sudoers", "ssh", "uid 0", "/etc"],
    "file_events": ["file", "archive", "download", "write", "upload", "shadow", "copy"],
    "driver_load": ["driver", ".sys"],
    "web_server": ["web", "w3wp", "webshell", "sql", "rce", "traversal", "admin panel"],
    "firewall": ["firewall", "port", "scan", "c2", "vpn", "outbound", "inbound"],
}

MITRE_KEYWORD_RULES: list[tuple[list[str], str]] = [
    (["oauth app", "oauth permission", "oauth permissions", "oauth consent", "unverified productivity app"], "T1528 - Steal Application Access Token"),
    (["mail.read", "mail.readwrite", "oauth consent", "mailbox oauth"], "T1114 - Email Collection"),
    (["deploy key", "new deploy key", "repository read permissions"], "T1098 - Account Manipulation"),
    (["deploy key", "repository access key", "repository credential"], "T1552 - Unsecured Credentials"),
    (["repository secrets", "secrets metadata", "secret metadata"], "T1552 - Unsecured Credentials"),
    (["private repositories", "repository access", "accesses multiple private repositories"], "T1530 - Data from Cloud Storage Object"),
    (["channel history", "private channel", "exports files", "exporting files", "file export", "export activity"], "T1530 - Data from Cloud Storage Object"),
    (["large file export", "exports files", "exporting files", "personal cloud", "cloud drive"], "T1567.002 - Exfiltration to Cloud Storage"),
    (["large upload", "personal drive", "rclone", "bytes_out", "data loss"], "T1567.002 - Exfiltration to Cloud Storage"),
    (["unfamiliar ip", "new ip", "new session", "user login"], "T1078 - Valid Accounts"),
    (["mfa fatigue", "mfa push", "push prompt", "push prompts", "mfa challenge"], "T1621 - Multi-Factor Authentication Request Generation"),
    (["password spray", "password spraying"], "T1110.003 - Password Spraying"),
    (["brute force", "failed login"], "T1110 - Brute Force"),
    (["impossible travel", "tor exit", "dormant account", "service account"], "T1078 - Valid Accounts"),
    (["rdp", "vpn", "remote access", "remote desktop", "after-hours rdp", "after hours rdp"], "T1133 - External Remote Services"),
    (["mfa disabled", "mfa device", "mfa method", "mfa method removed", "removing the only mfa method"], "T1098 - Account Manipulation"),
    (["kerberoasting", "spn"], "T1558.003 - Kerberoasting"),
    (["as-rep", "asrep"], "T1558.004 - AS-REP Roasting"),
    (["kerberos ticket", "ticket lifetime", "golden ticket", "tgt", "tgs"], "T1558 - Steal or Forge Kerberos Tickets"),
    (["dcsync", "replication"], "T1003.006 - DCSync"),
    (["public bucket", "cloud storage", "storage container", "anonymous users", "made public", "publicly accessible"], "T1530 - Data from Cloud Storage Object"),
    (["iam", "admin policy", "admin role", "administratoraccess", "attachrolepolicy"], "T1098.003 - Additional Cloud Roles"),
    (["cloud instance metadata", "instance metadata", "metadata service", "metadata token", "169.254.169.254", "imds"], "T1552.005 - Cloud Instance Metadata API"),
    (["npm postinstall", "postinstall script", "package install script"], "T1059 - Command and Scripting Interpreter"),
    (["sudoers", "uid 0"], "T1548.003 - Sudo and Sudo Caching"),
    (["ssh brute", "ssh failed"], "T1021.004 - SSH"),
    (["reverse shell"], "T1059.004 - Unix Shell"),
    (["kubernetes secret", "secrets"], "T1552 - Unsecured Credentials"),
    (["kubectl exec", "exec into pod"], "T1609 - Container and Resource Discovery"),
    (["privileged container"], "T1611 - Escape to Host"),
    (["sql injection", "path traversal", "remote code execution", "admin panel"], "T1190 - Exploit Public-Facing Application"),
    (["web attack", "web app", "web server", "file uploaded", "upload pattern"], "T1190 - Exploit Public-Facing Application"),
]

ENDPOINT_MITRE_PREFIXES = ("T1218", "T1547", "T1546", "T1003.001", "T1055", "T1068")
ENDPOINT_TELEMETRY = {"edr_process", "edr_registry", "windows_service", "wmi_events", "driver_load", "file_events", "firewall", "dns"}
SAAS_TELEMETRY_ORDER = ["cloud_audit", "auth", "email_audit", "proxy"]
SAAS_MITRE_ALLOW_PREFIXES = ("T1528", "T1530", "T1567.002", "T1078", "T1098")
DEV_PLATFORM_MITRE_ALLOW_CODES = {"T1528", "T1098", "T1552", "T1078", "T1530"}
DEV_PLATFORM_TELEMETRY_ORDER = ["cloud_audit", "auth", "proxy"]
CLOUD_IAM_MITRE_ALLOW_CODES = {"T1098", "T1098.003", "T1078.004"}
CLOUD_IAM_TELEMETRY_ORDER = ["cloud_audit", "auth", "proxy"]
CLOUD_IAM_BLOCKED_TEXT = ("windows service", "remote service execution", "cloud instance metadata", "169.254.169.254", "mshta", "registry run", "lsass")

INTENT_DEFAULT_MITRE = {
    "kerberos_ad": ["T1558 - Steal or Forge Kerberos Tickets"],
    "mfa_fatigue": ["T1621 - Multi-Factor Authentication Request Generation", "T1078 - Valid Accounts"],
    "password_spray": ["T1110.003 - Password Spraying"],
    "remote_access": ["T1133 - External Remote Services", "T1078 - Valid Accounts"],
    "cloud_iam": ["T1098.003 - Additional Cloud Roles", "T1078.004 - Cloud Accounts"],
    "cloud_storage": ["T1530 - Data from Cloud Storage Object"],
    "cloud_metadata": ["T1552.005 - Cloud Instance Metadata API"],
    "developer_platform": ["T1528 - Steal Application Access Token", "T1098 - Account Manipulation"],
    "saas_oauth": ["T1528 - Steal Application Access Token", "T1530 - Data from Cloud Storage Object"],
    "linux": ["T1059.004 - Unix Shell"],
    "kubernetes_container": ["T1609 - Container and Resource Discovery"],
    "web_attack": ["T1190 - Exploit Public-Facing Application"],
    "email_mailbox": ["T1114 - Email Collection"],
    "data_exfil": ["T1567.002 - Exfiltration to Cloud Storage", "T1560 - Archive Collected Data"],
    "endpoint_credential": ["T1003.001 - LSASS Memory", "T1078 - Valid Accounts"],
    "endpoint_lateral": ["T1021 - Remote Services"],
    "defense_evasion": ["T1562 - Impair Defenses"],
}


def _title_from_request(request: ThreatReportRequest) -> str:
    if request.title:
        return request.title
    for line in request.content.splitlines():
        stripped = line.strip("# ").strip()
        if stripped:
            return stripped[:120]
    return "Untitled threat report"


def _summary(text: str) -> str:
    for heading in ("## Summary", "Summary"):
        if heading in text:
            after = text.split(heading, 1)[1].strip()
            first = re.split(r"\n## |\n# ", after)[0].strip()
            if first:
                return " ".join(first.split())[:500]
    sentences = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    return " ".join(sentences[:2])[:500]


def _meaningful_text(text: str) -> str:
    lines = []
    for line in text.splitlines():
        lower = line.strip().lower()
        if lower.endswith(": none") or lower.endswith(" none"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _is_saas_oauth_context(text: str) -> bool:
    lower = _meaningful_text(text).lower()
    has_oauth = bool(
        re.search(r"\boauth\b|\bconsent\b|\bpermissions?\b|\boauth app\b|\bunverified app\b|\bapplication id\b", lower)
    )
    has_saas = bool(re.search(r"\bslack\b|\bteams\b|\bworkspace\b|\bchannel\b|\bsaas\b|cloud drive", lower))
    has_data = bool(re.search(r"\bexports?\b|\bfile export\b|\bchannel history\b|\bprivate channel\b", lower))
    return has_oauth and (has_saas or has_data)

def _is_developer_platform_context(text: str) -> bool:
    lower = _meaningful_text(text).lower()
    has_oauth = bool(re.search(r"\boauth\b|\bpermissions?\b|\bauthorization\b|\bapp\b", lower))
    has_dev_platform = bool(re.search(r"\bgithub\b|\bgitlab\b|\bbitbucket\b|\brepositor(?:y|ies)\b|\bdeploy key\b|\bsecrets? metadata\b", lower))
    return has_oauth and has_dev_platform


def _is_cloud_iam_context(text: str) -> bool:
    lower = _meaningful_text(text).lower()
    has_cloud_or_iam = "cloud" in lower or "iam" in lower
    has_admin_policy = bool(re.search(r"\badmin(?:istrator)? policy\b|\badmin role\b|\battach(?:ed)? policy\b|\bsetiampolicy\b|\battachpolicy\b", lower))
    return has_cloud_or_iam and has_admin_policy


def _has_endpoint_evidence(text: str) -> bool:
    lower = _meaningful_text(text).lower()
    return any(token in lower for token in [".exe", "registry key", "run key", "mshta", "powershell", "lsass", "rundll32", "wmi", "driver", ".sys"])


def _extract_behaviors_from_prose(text: str) -> list[str]:
    lower = _meaningful_text(text).lower()
    behaviors: list[str] = []
    for pattern, template in PROSE_BEHAVIOR_PATTERNS:
        for match in re.finditer(pattern, lower):
            behavior = template
            for index, group in enumerate(match.groups()):
                if group:
                    behavior = behavior.replace(f"{{{index}}}", group)
            behaviors.append(behavior.strip())
    return _merge_unique(behaviors)


def _detect_severity(text: str) -> str:
    match = re.search(r"^\s*-\s*severity:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else "Medium/High"


def _is_structured_input(text: str) -> bool:
    bullet_count = sum(1 for line in text.splitlines() if line.strip().startswith("- "))
    section_count = sum(1 for line in text.splitlines() if line.strip().startswith("##"))
    return bullet_count >= 3 or section_count >= 2


def _compute_confidence(package: HuntPackage, reference_score: float, is_structured: bool) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    if reference_score >= 0.75:
        score += 0.30
        reasons.append(f"High reference match ({reference_score:.2f}).")
    elif reference_score >= 0.25:
        score += 0.16
        reasons.append(f"Partial reference match ({reference_score:.2f}).")
    else:
        reasons.append("No strong reference match; rule/RAG guardrails carry the output.")
    if len(package.key_behaviors) >= 3:
        score += 0.18
    elif package.key_behaviors:
        score += 0.09
        reasons.append("Few behaviors extracted; analyst should verify context.")
    if len(package.mitre_mapping) >= 2:
        score += 0.18
    elif package.mitre_mapping:
        score += 0.09
        reasons.append("Only one MITRE technique mapped.")
    if len(package.required_telemetry) >= 2:
        score += 0.16
    elif package.required_telemetry:
        score += 0.08
    if package.query_drafts:
        score += 0.10
    else:
        reasons.append("No query draft selected.")
    if len(package.hunt_checklist) >= 4:
        score += 0.08
    if not is_structured:
        score = max(0.0, score - 0.10)
        reasons.append("Unstructured input; manual review recommended.")
    return round(min(score, 1.0), 2), reasons


def _query_matches(query: QueryDraft, tokens: tuple[str, ...]) -> bool:
    haystack = f"{query.name}\n{query.purpose}\n{query.query}".lower()
    return any(token in haystack for token in tokens)


def _apply_precision_guardrails(text: str, package: HuntPackage) -> HuntPackage:
    lower = _meaningful_text(text).lower()
    if "lsass" in lower:
        package.required_telemetry = _merge_unique(["edr_process", "auth", "file_events"], [t for t in package.required_telemetry if t in {"edr_process", "auth", "file_events", "edr_file"}])
        allowed = {"T1003", "T1003.001", "T1078", "T1055"}
        package.mitre_mapping = [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in allowed]
        package.mitre_mapping = _merge_unique(["T1003.001 - LSASS Memory", "T1003 - OS Credential Dumping", "T1078 - Valid Accounts"], package.mitre_mapping)
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("lsass", "credential dumping"))]
        package.hunt_checklist = _merge_unique([
            "Review EDR process telemetry for non-standard processes opening LSASS with high privileges.",
            "Identify the process name, parent process, command line, user, host, and whether the tool is approved security software.",
            "Check for dump file creation or procdump/comsvcs/nanodump-style command lines on the same host.",
            "Review follow-on authentication or lateral movement from the same user or host.",
            "Escalate if LSASS access is not approved security tooling or is followed by credential use.",
        ], package.hunt_checklist, limit=10)
    if re.search(r"\buid\s*0\b|root-equivalent|root equivalent", lower):
        package.required_telemetry = _merge_unique(["linux_audit", "linux_process", "file_events", "auth"], [t for t in package.required_telemetry if t in {"linux_audit", "linux_process", "file_events", "auth"}])
        allowed = {"T1136", "T1136.001", "T1548", "T1548.003", "T1078"}
        package.mitre_mapping = [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in allowed]
        package.mitre_mapping = _merge_unique(["T1136.001 - Local Account", "T1548 - Abuse Elevation Control Mechanism", "T1078 - Valid Accounts"], package.mitre_mapping)
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("uid 0", "passwd", "useradd", "linux uid0"))]
        package.key_behaviors = _merge_unique(["new Linux user is created with UID 0", "/etc/passwd is modified", "interactive SSH or bash activity follows"], package.key_behaviors, limit=12)
        package.hunt_checklist = _merge_unique([
            "Review Linux audit and file telemetry for new users with UID 0 or root-equivalent privileges.",
            "Inspect /etc/passwd, /etc/shadow, /etc/group, and /etc/sudoers changes around the alert time.",
            "Identify the actor, parent process, command line, host, UID/GID, and source IP if remote administration was used.",
            "Review follow-on SSH, sudo, shell, and privileged command activity for the new account.",
            "Escalate if the UID 0 account was not created by an approved administrative workflow.",
        ], package.hunt_checklist, limit=10)
    if "cloud iam admin policy" in lower or ("admin policy" in lower and "cloud" in lower):
        package.required_telemetry = _merge_unique(["cloud_audit", "auth", "proxy"], [t for t in package.required_telemetry if t in {"cloud_audit", "auth", "proxy"}])
        package.mitre_mapping = _merge_unique(["T1098.003 - Additional Cloud Roles", "T1078.004 - Cloud Accounts", "T1098 - Account Manipulation"], [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in {"T1098.003", "T1078.004", "T1098"}])
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("cloud iam", "admin policy", "role assignment"))]
    if "mfa" in lower and ("disabled" in lower or "removed" in lower or "method" in lower):
        package.mitre_mapping = _merge_unique(["T1098 - Account Manipulation", "T1078 - Valid Accounts"], [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in {"T1098", "T1078", "T1556"}])
    if "kerberos" in lower or "ticket lifetime" in lower or "golden ticket" in lower:
        package.required_telemetry = _merge_unique(["auth", "windows_security", "active_directory"], [t for t in package.required_telemetry if t in {"auth", "windows_security", "active_directory", "kerberos"}])
        kerberos_mitre = ["T1558 - Steal or Forge Kerberos Tickets"]
        if "golden" in lower or "krbtgt" in lower or "ticket lifetime" in lower:
            kerberos_mitre.append("T1558.001 - Golden Ticket")
        if "privileged" in lower:
            kerberos_mitre.append("T1078 - Valid Accounts")
        package.mitre_mapping = _merge_unique(kerberos_mitre, [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in {"T1558", "T1558.001", "T1558.003", "T1558.004", "T1003.006", "T1078", "T1087"}])
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("kerberos", "ticket", "golden", "dcsync", "asrep", "spn"))]
    if ("storage" in lower or "bucket" in lower) and ("public" in lower or "anonymous" in lower):
        package.required_telemetry = _merge_unique(["cloud_audit", "auth", "proxy"], [t for t in package.required_telemetry if t in {"cloud_audit", "auth", "proxy"}])
        package.mitre_mapping = _merge_unique(["T1530 - Data from Cloud Storage Object", "T1078.004 - Cloud Accounts"], [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in {"T1530", "T1567.002", "T1078.004", "T1098"}])
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("cloud storage", "bucket", "public access"))]
    if "shadow cop" in lower or "vssadmin" in lower or "wbadmin" in lower or "ransom extension" in lower:
        package.required_telemetry = _merge_unique(["edr_process", "file_events", "windows_service"], [t for t in package.required_telemetry if t in {"edr_process", "file_events", "windows_service", "edr_registry", "auth"}])
        package.mitre_mapping = _merge_unique(["T1490 - Inhibit System Recovery", "T1486 - Data Encrypted for Impact", "T1562 - Impair Defenses"], [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in {"T1490", "T1486", "T1562", "T1070"}])
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("ransomware", "shadow", "vssadmin", "backup"))]
    if "oauth" in lower and ("github" in lower or "repository" in lower or "deploy key" in lower):
        package.required_telemetry = _merge_unique(["github_audit", "auth", "proxy", "cloud_audit"], [t for t in package.required_telemetry if t in {"github_audit", "auth", "proxy", "cloud_audit"}])
        allowed = {"T1528", "T1098", "T1552", "T1530", "T1078"}
        package.mitre_mapping = [m for m in package.mitre_mapping if m.split(" - ", 1)[0] in allowed]
        package.query_drafts = [q for q in package.query_drafts if _query_matches(q, ("github", "developer", "repo", "oauth"))]
    return package

def _extract_behaviors(text: str) -> list[str]:
    lower = text.lower()
    behaviors: list[str] = []
    for behavior, primary, secondary in BEHAVIOR_RULES:
        if primary in lower and any(token in lower for token in secondary):
            behaviors.append(behavior)

    behavior_tokens = [
        ".exe", "registry", "dns", "oauth", "service", "cron", "lsass", "payload",
        "login", "account", "mfa", "cloud", "iam", "kerberos", "linux", "kubernetes",
        "container", "firewall", "web", "bucket", "ssh", "ransomware", "mailbox",
        "app", "permission", "permissions", "channel", "workspace", "export", "exports", "file",
    ]
    for line in text.splitlines():
        stripped = line.strip()
        lower_line = stripped.lower()
        if lower_line.endswith(": none") or lower_line.endswith(" none"):
            continue
        if re.match(r"^-?\s*(alert_name|alert_source|severity|category|data_type)\s*:", lower_line):
            continue
        if stripped.startswith("- ") and any(token in lower_line for token in behavior_tokens):
            behaviors.append(stripped[2:].strip())

    prose_behaviors = _extract_behaviors_from_prose(text)
    return _merge_unique(behaviors, prose_behaviors)[:12] or ["Review the report for behaviors that can be translated into telemetry searches."]


def _required_telemetry(text: str, behaviors: list[str]) -> list[str]:
    available = set(list_telemetry_sources())
    lower = (text + "\n" + "\n".join(behaviors)).lower()
    selected = []
    for source, keywords in TELEMETRY_KEYWORDS.items():
        if (source in available or source in {"firewall", "auth", "cloud_audit", "email_audit"}) and any(keyword in lower for keyword in keywords):
            selected.append(source)
    return selected or sorted(available)[:3]


def _checklist(behaviors: list[str], telemetry: list[str]) -> list[str]:
    checks = []
    for behavior in behaviors[:6]:
        checks.append(f"Search telemetry for: {behavior}.")
    if "edr_process" in telemetry:
        checks.append("Correlate suspicious process chains by host, user, and 24-hour window.")
    if "dns" in telemetry or "proxy" in telemetry:
        checks.append("Check DNS/proxy activity after the suspicious process or identity event.")
    if "edr_registry" in telemetry:
        checks.append("Review persistence changes on the same hosts.")
    if "auth" in telemetry:
        checks.append("Review authentication context, source IP, device, and recent account changes.")
    if "cloud_audit" in telemetry:
        checks.append("Review cloud audit events for permission, token, storage, or API changes.")
    checks.append("Escalate only after analyst review confirms matching behavior in real telemetry.")
    return _merge_unique(checks)


def _saas_checklist() -> list[str]:
    return [
        "Review OAuth consent or app authorization events for the user.",
        "Check whether the app publisher, workspace, and permission scopes are approved.",
        "Review SaaS audit logs for channel history reads, file reads, and file export actions.",
        "Correlate the app activity with user login source IP, device, and session context.",
        "Identify other users who granted the same app permissions.",
        "Escalate if the app is unapproved, has broad read/export scopes, or accessed sensitive private-channel data.",
    ]

def _developer_platform_checklist() -> list[str]:
    return [
        "Review GitHub/GitLab OAuth app authorization and granted repository scopes.",
        "Check which private repositories were accessed, cloned, or enumerated by the app.",
        "Review deploy key creation events and confirm whether each key is approved.",
        "Check repository secrets metadata access and any related workflow or token activity.",
        "Correlate developer login source IP, device, and session context with the app activity.",
        "Identify other developers or organizations that authorized the same OAuth app.",
        "Escalate if the app is unapproved, has broad repo/secrets permissions, or created deploy keys.",
    ]


def _cloud_iam_checklist() -> list[str]:
    return [
        "Review cloud audit logs for IAM admin policy attachment or privileged role assignment events.",
        "Identify the actor/principal, target user, role or service account, resource, source IP, and user agent.",
        "Check whether the actor normally performs IAM changes and whether the change was approved.",
        "Review follow-on activity after the privilege expansion, especially access to sensitive resources.",
        "Check authentication context for the actor, including new location, new device, MFA, and session anomalies.",
        "Escalate if admin privileges were granted to an unusual identity, workload, service account, or production asset.",
    ]


def _query_drafts(text: str) -> list[QueryDraft]:
    drafts = []
    for template in find_templates_for_text(text):
        drafts.append(
            QueryDraft(
                name=template.name.replace("_", " ").title(),
                platform=template.platform,
                query=template.content,
                purpose=f"Draft query based on template {template.path}. Review field names before running.",
            )
        )
    return drafts


def _keyword_mitre(text: str) -> list[str]:
    lower = text.lower()
    matches = []
    for keywords, technique in MITRE_KEYWORD_RULES:
        if any(keyword in lower for keyword in keywords):
            matches.append(technique)
    return matches


def _expand_parent_mitre(mitre: list[str]) -> list[str]:
    parent_map = {
        "T1071.004": "T1071 - Application Layer Protocol",
        "T1548.003": "T1548 - Abuse Elevation Control Mechanism",
        "T1003.001": "T1003 - OS Credential Dumping",
        "T1546.003": "T1546 - Event Triggered Execution",
        "T1543.003": "T1543 - Create or Modify System Process",
        "T1110.003": "T1110 - Brute Force",
        "T1059.004": "T1059 - Command and Scripting Interpreter",
        "T1021.004": "T1021 - Remote Services",
    }
    additions = []
    for item in mitre:
        code = item.split(" - ", 1)[0]
        if code in parent_map:
            additions.append(parent_map[code])
    return _merge_unique(mitre, additions)


def _merge_unique(*groups: list[str], limit: int | None = None) -> list[str]:
    seen = set()
    out = []
    for group in groups:
        for item in group:
            cleaned = item.strip() if isinstance(item, str) else item
            if not cleaned:
                continue
            key = cleaned.lower()
            if key not in seen:
                seen.add(key)
                out.append(cleaned)
            if limit is not None and len(out) >= limit:
                return out
    return out


def _ioc_to_dict(ioc: IOC) -> dict[str, list[str]]:
    if hasattr(ioc, "model_dump"):
        return ioc.model_dump()
    return ioc.dict()


def _merge_ioc(extracted: IOC, reference_ioc: dict[str, Any] | None) -> IOC:
    base = _ioc_to_dict(extracted)
    reference_ioc = reference_ioc or {}
    return IOC(
        domains=_merge_unique(base.get("domains", []), reference_ioc.get("domains", [])),
        ips=_merge_unique(base.get("ips", []), reference_ioc.get("ips", [])),
        hashes=_merge_unique(base.get("hashes", []), reference_ioc.get("hashes", [])),
        files=_merge_unique(base.get("files", []), reference_ioc.get("files", [])),
        processes=_merge_unique(base.get("processes", []), reference_ioc.get("processes", [])),
        registry_keys=_merge_unique(base.get("registry_keys", []), reference_ioc.get("registry_keys", [])),
    )


def _filter_for_context(text: str, telemetry: list[str], mitre: list[str], queries: list[QueryDraft]) -> tuple[list[str], list[str], list[QueryDraft]]:
    intent = classify_intent("", text)
    if intent.name not in {"identity", "cloud", "endpoint", "dns"}:
        allowed_telemetry = set(intent.telemetry_allow)
        blocked_telemetry = set(intent.blocked_telemetry)
        telemetry = _merge_unique(
            list(intent.required_telemetry),
            [item for item in telemetry if item in allowed_telemetry and item not in blocked_telemetry],
        )
        mitre = [
            item
            for item in mitre
            if any(item.split(" - ", 1)[0].startswith(prefix) for prefix in intent.mitre_allow_prefixes)
            and not any(blocked in item.lower() for blocked in intent.blocked_keywords)
        ]
        if not mitre:
            mitre = INTENT_DEFAULT_MITRE.get(intent.name, [])
        queries = [
            query
            for query in queries
            if any(token in f"{query.name}\n{query.purpose}\n{query.query}".lower() for token in intent.query_keywords)
            and not any(blocked in f"{query.name}\n{query.purpose}\n{query.query}".lower() for blocked in intent.blocked_keywords)
        ]
        return telemetry, mitre, queries

    if _is_cloud_iam_context(text) and not _has_endpoint_evidence(text):
        telemetry = _merge_unique(CLOUD_IAM_TELEMETRY_ORDER, [item for item in telemetry if item not in ENDPOINT_TELEMETRY])
        mitre = [item for item in mitre if item.split(" - ", 1)[0] in CLOUD_IAM_MITRE_ALLOW_CODES]
        mitre = [item for item in mitre if not any(blocked in item.lower() for blocked in CLOUD_IAM_BLOCKED_TEXT)]
        queries = [query for query in queries if any(token in query.name.lower() for token in ["cloud", "iam", "policy"])]
        return telemetry, mitre, queries

    if _is_developer_platform_context(text) and not _has_endpoint_evidence(text):
        telemetry = _merge_unique(DEV_PLATFORM_TELEMETRY_ORDER, [item for item in telemetry if item not in ENDPOINT_TELEMETRY])
        mitre = [item for item in mitre if item.split(" - ", 1)[0] in DEV_PLATFORM_MITRE_ALLOW_CODES]
        queries = [query for query in queries if any(token in query.name.lower() for token in ["oauth", "saas", "developer"])]
        return telemetry, mitre, queries

    if not _is_saas_oauth_context(text) or _has_endpoint_evidence(text):
        return telemetry, mitre, queries

    telemetry = _merge_unique(SAAS_TELEMETRY_ORDER, [item for item in telemetry if item not in ENDPOINT_TELEMETRY])
    mitre = [item for item in mitre if any(item.startswith(prefix) for prefix in SAAS_MITRE_ALLOW_PREFIXES)]
    queries = [query for query in queries if any(token in query.name.lower() for token in ["oauth", "saas"])]
    return telemetry, mitre, queries



def _apply_severity_target_boosts(
    text: str,
    telemetry: list[str],
    mitre: list[str],
    queries: list[QueryDraft],
) -> tuple[list[str], list[str], list[QueryDraft]]:
    """Raise recall for high-impact patterns without overriding the detected intent."""
    lower = _meaningful_text(text).lower()

    if re.search(r"\bbrowser credential|credentials from web browsers|chrome passwords?|edge passwords?|firefox passwords?", lower):
        telemetry = _merge_unique(["edr_process", "file_events", "proxy"], telemetry)
        mitre = _merge_unique(["T1555.003 - Credentials from Web Browsers", "T1560 - Archive Collected Data"], mitre)

    if "lsass" in lower or "credential dump" in lower:
        telemetry = _merge_unique(["edr_process", "auth", "file_events"], [item for item in telemetry if item not in {"proxy", "dns", "cloud_audit"}])
        lsass_mitre = ["T1003.001 - LSASS Memory", "T1003 - OS Credential Dumping"]
        if re.search(r"follow-on|authenticat|lateral", lower):
            lsass_mitre.append("T1078 - Valid Accounts")
        mitre = _merge_unique(lsass_mitre, [item for item in mitre if item.split(" - ", 1)[0] not in {"T1555.003", "T1560", "T1528", "T1552.005"}])

    if "npm" in lower and "postinstall" in lower:
        telemetry = _merge_unique(["edr_process", "proxy", "file_events"], telemetry)
        mitre = _merge_unique([
            "T1195.002 - Compromise Software Supply Chain",
            "T1059 - Command and Scripting Interpreter",
        ], mitre)
        queries = [query for query in queries if "registry" not in query.name.lower()]

    if "oauth" in lower and ("consent" in lower or "mail.read" in lower or "permission" in lower):
        telemetry = _merge_unique(["cloud_audit", "email_audit", "proxy"], telemetry)
        mitre = _merge_unique(["T1528 - Steal Application Access Token", "T1114 - Email Collection"], mitre)

    if "kubernetes" in lower and "secret" in lower:
        telemetry = _merge_unique(["kubernetes_audit", "cloud_audit", "auth"], telemetry)
        mitre = _merge_unique(["T1609 - Container and Resource Discovery"], mitre)

    if "crypto miner" in lower or "cryptominer" in lower or "mining pool" in lower:
        telemetry = _merge_unique(["edr_process", "file_events", "dns", "proxy"], telemetry)
        mitre = _merge_unique(["T1204.002 - Malicious File"], mitre)

    if any(token in lower for token in ["defender", "driver", "vulnerable driver", "real-time protection", "protection is disabled", "log cleared", "security log cleared", "shadow copy", "vssadmin", "wbadmin", "ransom extension"]):
        telemetry = _merge_unique(["edr_process", "edr_registry", "auth"], telemetry)
        mitre = _merge_unique(["T1562 - Impair Defenses", "T1070 - Indicator Removal", "T1490 - Inhibit System Recovery", "T1486 - Data Encrypted for Impact"], mitre)
        endpoint_noise = ("mshta", "run key", "wmi event", "ingress tool transfer")
        mitre = [item for item in mitre if not any(noise in item.lower() for noise in endpoint_noise)]

    return telemetry, mitre, queries

def _should_use_reference_summary(title: str, retrieved_score: float, retrieved_title: str) -> bool:
    title_key = title.lower().replace("alert report:", "").replace("test report:", "").strip()
    ref_key = retrieved_title.lower().replace("alert report:", "").replace("test report:", "").strip()
    return retrieved_score >= 0.75 or (title_key and ref_key and (title_key in ref_key or ref_key in title_key))


def analyze_report(request: ThreatReportRequest) -> HuntPackage:
    text = request.content
    title = _title_from_request(request)
    intent = classify_intent(title, text)
    retrieved = retrieve_similar_hunt_package(title, text)
    reference = retrieved.expected if retrieved else {}
    reference_is_exact = bool(retrieved and _should_use_reference_summary(title, retrieved.score, retrieved.title))
    saas_oauth = intent.name == "saas_oauth" or _is_saas_oauth_context(title + "\n" + text)
    developer_platform = intent.name == "developer_platform" or _is_developer_platform_context(title + "\n" + text)

    rule_behaviors = _extract_behaviors(text)
    if (saas_oauth or developer_platform) and not reference_is_exact:
        behaviors = _merge_unique(rule_behaviors, limit=12)
    else:
        behaviors = _merge_unique(reference.get("key_behaviors", []), rule_behaviors, limit=12)

    ioc = _merge_ioc(extract_ioc(text), reference.get("ioc") if reference_is_exact else None)
    telemetry = _merge_unique(reference.get("required_telemetry", []) if reference_is_exact else [], _required_telemetry(text, behaviors))
    mitre = _merge_unique(
        _keyword_mitre(title + "\n" + text),
        reference.get("mitre_mapping", []) if reference_is_exact else [],
        map_behaviors_to_mitre(behaviors, text),
        limit=12,
    )
    mitre = _expand_parent_mitre(mitre)
    if intent.name in INTENT_DEFAULT_MITRE and not any(
        any(item.split(" - ", 1)[0].startswith(prefix) for prefix in intent.mitre_allow_prefixes)
        for item in mitre
    ):
        mitre = _merge_unique(mitre, INTENT_DEFAULT_MITRE[intent.name], limit=12)
    checklist = _merge_unique(
        list(intent.checklist),
        _developer_platform_checklist() if developer_platform else (_saas_checklist() if saas_oauth else []),
        reference.get("hunt_checklist", []) if reference_is_exact else [],
        _checklist(behaviors, telemetry),
        limit=12,
    )
    query_drafts = _query_drafts(title + "\n" + text)
    telemetry, mitre, query_drafts = _filter_for_context(title + "\n" + text, telemetry, mitre, query_drafts)
    telemetry, mitre, query_drafts = _apply_severity_target_boosts(title + "\n" + text, telemetry, mitre, query_drafts)
    if _is_cloud_iam_context(title + "\n" + text) and not _has_endpoint_evidence(title + "\n" + text):
        behaviors = [item for item in behaviors if not any(blocked in item.lower() for blocked in CLOUD_IAM_BLOCKED_TEXT)]
        checklist = _merge_unique(
            _cloud_iam_checklist(),
            [item for item in checklist if not any(blocked in item.lower() for blocked in (*CLOUD_IAM_BLOCKED_TEXT, "host"))],
            limit=10,
        )

    summary = reference["threat_summary"] if reference.get("threat_summary") and reference_is_exact else _summary(text)

    retrieval_note = "No reference package matched."
    if retrieved:
        retrieval_note = f"Hybrid analyzer matched reference `{retrieved.slug}` with score {retrieved.score:.2f}."

    package_id = hashlib.sha1((title + text).encode("utf-8")).hexdigest()[:12]
    package = HuntPackage(
        package_id=package_id,
        report_title=title,
        threat_summary=summary,
        key_behaviors=behaviors,
        ioc=ioc,
        mitre_mapping=mitre,
        required_telemetry=telemetry,
        hunt_checklist=checklist,
        query_drafts=query_drafts,
        correlation_logic=(
            intent.correlation_logic
            if intent.correlation_logic
            else (
            "Correlate cloud audit events by actor/principal, target user/role/service account, resource, source IP, user agent, and time window. Confirm whether the IAM admin policy attachment was approved change activity."
            if _is_cloud_iam_context(title + "\n" + text) and not _has_endpoint_evidence(title + "\n" + text)
            else reference.get(
            "correlation_logic",
            "Correlate matching behaviors by host, user, process, and time window. Treat generated logic as a draft until validated against real SIEM/EDR schema.",
        ) if reference_is_exact else "Correlate matching activity by the primary entity, relevant telemetry source, source IP, destination, asset, and time window. Treat generated logic as a draft until validated against real SIEM schema."
            )
        ),
        escalation_condition=reference.get(
            "escalation_condition",
            "Escalate when multiple behaviors from the same report appear on the same host/user or when high-impact behavior such as credential access, persistence, C2, or exfiltration is confirmed.",
        ) if reference_is_exact else (
            intent.escalation_condition
            or "Escalate when the suspicious behavior is confirmed on a real user, host, workload, or production asset and cannot be explained by approved business activity."
        ),
        analyst_notes=f"MVP hybrid analyzer output. {retrieval_note} Review generated queries and assumptions before operational use.",
    )
    package = apply_output_guardrails(package, intent)
    package = _apply_precision_guardrails(title + "\n" + text, package)
    package.required_telemetry, package.mitre_mapping, package.query_drafts = _apply_severity_target_boosts(
        title + "\n" + text,
        package.required_telemetry,
        package.mitre_mapping,
        package.query_drafts,
    )
    package = _apply_precision_guardrails(title + "\n" + text, package)
    package.severity_hint = _detect_severity(text)
    package.confidence_score, package.confidence_reasons = _compute_confidence(
        package, retrieved.score if retrieved else 0.0, _is_structured_input(text)
    )
    return save_hunt_package(package)












