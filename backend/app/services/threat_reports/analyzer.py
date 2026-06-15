import hashlib
import re
from typing import Any

from app.schemas.hunt_package import HuntPackage, IOC, QueryDraft
from app.schemas.threat_report import ThreatReportRequest
from app.services.hunt_packages.store import save_hunt_package
from app.services.ioc_extraction.extractor import extract_ioc
from app.services.query_generation.template_loader import find_templates_for_text
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
    ("Windows service persistence or remote service execution", "service", ["service", "sc.exe"]),
    ("DNS tunneling or abnormal DNS queries", "dns", ["txt", "tunneling", "nxdomain", "subdomain"]),
    ("OAuth consent or cloud token abuse", "oauth", ["consent", "oauth", "mail.read"]),
    ("Credential dumping against LSASS", "lsass", ["lsass", "credential dump"]),
    ("Lateral movement via SMB or admin shares", "admin share", ["admin$", "smb", "psexec"]),
    ("Webshell behavior on public web server", "webshell", ["webshell", "w3wp", "aspx", "jsp"]),
    ("Data staging or exfiltration tooling", "exfil", ["rclone", "archive", "bytes_out", "exfil"]),
    ("Linux cron persistence with shell download", "cron", ["cron", "curl", "bash"]),
    ("Security tool tampering or driver abuse", "driver", ["driver", "disable", "security tool"]),
    ("Password spraying against many accounts", "password", ["spray", "spraying"]),
    ("Brute force login attempts against an account", "brute", ["force", "failed login"]),
    ("Suspicious authentication or account takeover pattern", "login", ["mfa", "password", "account", "tor", "vpn"]),
    ("Cloud control plane or IAM change requires review", "cloud", ["iam", "bucket", "access key", "metadata"]),
    ("Active Directory credential or Kerberos abuse pattern", "kerberos", ["as-rep", "dcsync", "spn", "ticket"]),
    ("Linux privilege or shell activity requires review", "linux", ["sudoers", "ssh", "reverse shell", "uid 0"]),
    ("Kubernetes or container control plane activity requires review", "kubernetes", ["secret", "pod", "container", "privileged"]),
    ("Public web application attack pattern", "web", ["sql", "rce", "traversal", "upload", "admin panel"]),
]

TELEMETRY_KEYWORDS = {
    "edr_process": ["process", ".exe", "powershell", "mshta", "rundll32", "wscript", "cmd", "bash"],
    "edr_registry": ["registry", "run key", "currentversion\\run"],
    "dns": ["dns", "domain", "txt", "nxdomain", "subdomain"],
    "proxy": ["http", "https", "url", "download", "domain", "bytes_out"],
    "auth": ["login", "account", "mfa", "oauth", "token", "kerberos", "rdp", "vpn", "ssh"],
    "cloud_audit": ["cloud", "api key", "oauth", "consent", "iam", "bucket", "metadata", "kubernetes"],
    "email": ["email", "attachment", "phishing"],
    "email_audit": ["mailbox", "mail.read", "email", "inbox", "forwarding"],
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
    (["password spray", "password spraying"], "T1110.003 - Password Spraying"),
    (["brute force", "failed login"], "T1110 - Brute Force"),
    (["impossible travel", "tor exit", "dormant account", "service account"], "T1078 - Valid Accounts"),
    (["mfa disabled", "mfa device", "mfa method"], "T1098 - Account Manipulation"),
    (["kerberoasting", "spn"], "T1558.003 - Kerberoasting"),
    (["as-rep", "asrep"], "T1558.004 - AS-REP Roasting"),
    (["dcsync", "replication"], "T1003.006 - DCSync"),
    (["public bucket", "cloud storage"], "T1530 - Data from Cloud Storage Object"),
    (["iam", "admin policy", "admin role"], "T1098.003 - Additional Cloud Roles"),
    (["metadata", "169.254.169.254"], "T1552.005 - Cloud Instance Metadata API"),
    (["sudoers", "uid 0"], "T1548.003 - Sudo and Sudo Caching"),
    (["ssh brute", "ssh failed"], "T1021.004 - SSH"),
    (["reverse shell"], "T1059.004 - Unix Shell"),
    (["kubernetes secret", "secrets"], "T1552 - Unsecured Credentials"),
    (["kubectl exec", "exec into pod"], "T1609 - Container and Resource Discovery"),
    (["privileged container"], "T1611 - Escape to Host"),
    (["sql injection", "path traversal", "remote code execution", "admin panel"], "T1190 - Exploit Public-Facing Application"),
]

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


def _extract_behaviors(text: str) -> list[str]:
    lower = text.lower()
    behaviors: list[str] = []
    for behavior, primary, secondary in BEHAVIOR_RULES:
        if primary in lower and any(token in lower for token in secondary):
            behaviors.append(behavior)

    # Preserve report bullet behaviors when present.
    behavior_tokens = [
        ".exe", "registry", "dns", "oauth", "service", "cron", "lsass", "payload",
        "login", "account", "mfa", "cloud", "iam", "kerberos", "linux", "kubernetes",
        "container", "firewall", "web", "bucket", "ssh", "ransomware", "mailbox",
    ]
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- ") and any(token in stripped.lower() for token in behavior_tokens):
            behaviors.append(stripped[2:].strip())

    return _merge_unique(behaviors)[:10] or ["Review the report for behaviors that can be translated into telemetry searches."]


def _required_telemetry(text: str, behaviors: list[str]) -> list[str]:
    available = set(list_telemetry_sources())
    lower = (text + "\n" + "\n".join(behaviors)).lower()
    selected = []
    for source, keywords in TELEMETRY_KEYWORDS.items():
        if (source in available or source == "firewall") and any(keyword in lower for keyword in keywords):
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


def analyze_report(request: ThreatReportRequest) -> HuntPackage:
    text = request.content
    title = _title_from_request(request)
    retrieved = retrieve_similar_hunt_package(title, text)
    reference = retrieved.expected if retrieved else {}

    rule_behaviors = _extract_behaviors(text)
    behaviors = _merge_unique(reference.get("key_behaviors", []), rule_behaviors, limit=12)

    ioc = _merge_ioc(extract_ioc(text), reference.get("ioc"))
    telemetry = _merge_unique(reference.get("required_telemetry", []), _required_telemetry(text, behaviors))
    mitre = _merge_unique(reference.get("mitre_mapping", []), _keyword_mitre(title + "\n" + text), map_behaviors_to_mitre(behaviors, text), limit=12)
    checklist = _merge_unique(reference.get("hunt_checklist", []), _checklist(behaviors, telemetry), limit=12)

    if reference.get("threat_summary") and retrieved and retrieved.score >= 0.15:
        summary = reference["threat_summary"]
    else:
        summary = _summary(text)

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
        query_drafts=_query_drafts(text),
        correlation_logic=reference.get(
            "correlation_logic",
            "Correlate matching behaviors by host, user, process, and time window. Treat generated logic as a draft until validated against real SIEM/EDR schema.",
        ),
        escalation_condition=reference.get(
            "escalation_condition",
            "Escalate when multiple behaviors from the same report appear on the same host/user or when high-impact behavior such as credential access, persistence, C2, or exfiltration is confirmed.",
        ),
        analyst_notes=f"MVP hybrid analyzer output. {retrieval_note} Review generated queries and assumptions before operational use.",
    )
    return save_hunt_package(package)


