import hashlib
import re

from app.schemas.hunt_package import HuntPackage, QueryDraft
from app.schemas.threat_report import ThreatReportRequest
from app.services.hunt_packages.store import save_hunt_package
from app.services.ioc_extraction.extractor import extract_ioc
from app.services.query_generation.template_loader import find_templates_for_text
from app.services.telemetry_schemas.loader import list_telemetry_sources
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
]

TELEMETRY_KEYWORDS = {
    "edr_process": ["process", ".exe", "powershell", "mshta", "rundll32", "wscript", "cmd", "bash"],
    "edr_registry": ["registry", "run key", "currentversion\\run"],
    "dns": ["dns", "domain", "txt", "nxdomain", "subdomain"],
    "proxy": ["http", "https", "url", "download", "domain", "bytes_out"],
    "auth": ["login", "account", "mfa", "oauth", "token"],
    "cloud_audit": ["cloud", "api key", "oauth", "consent"],
    "email": ["email", "attachment", "phishing"],
    "email_audit": ["mailbox", "mail.read", "email"],
    "windows_service": ["service", "sc.exe"],
    "wmi_events": ["wmi"],
    "linux_process": ["linux", "bash", "cron"],
    "linux_audit": ["linux", "cron"],
    "file_events": ["file", "archive", "download", "write"],
    "driver_load": ["driver", ".sys"],
    "web_server": ["web", "w3wp", "webshell"],
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


def _extract_behaviors(text: str) -> list[str]:
    lower = text.lower()
    behaviors: list[str] = []
    for behavior, primary, secondary in BEHAVIOR_RULES:
        if primary in lower and any(token in lower for token in secondary):
            behaviors.append(behavior)

    # Preserve report bullet behaviors when present.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- ") and any(token in stripped.lower() for token in [".exe", "registry", "dns", "oauth", "service", "cron", "lsass", "payload"]):
            behaviors.append(stripped[2:].strip())

    seen = set()
    out = []
    for behavior in behaviors:
        key = behavior.lower()
        if key not in seen:
            seen.add(key)
            out.append(behavior)
    return out[:10] or ["Review the report for behaviors that can be translated into telemetry searches."]


def _required_telemetry(text: str, behaviors: list[str]) -> list[str]:
    available = set(list_telemetry_sources())
    lower = (text + "\n" + "\n".join(behaviors)).lower()
    selected = []
    for source, keywords in TELEMETRY_KEYWORDS.items():
        if source in available and any(keyword in lower for keyword in keywords):
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
    checks.append("Escalate only after analyst review confirms matching behavior in real telemetry.")
    return checks


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


def analyze_report(request: ThreatReportRequest) -> HuntPackage:
    text = request.content
    title = _title_from_request(request)
    behaviors = _extract_behaviors(text)
    ioc = extract_ioc(text)
    telemetry = _required_telemetry(text, behaviors)
    mitre = map_behaviors_to_mitre(behaviors, text)
    package_id = hashlib.sha1((title + text).encode("utf-8")).hexdigest()[:12]
    package = HuntPackage(
        package_id=package_id,
        report_title=title,
        threat_summary=_summary(text),
        key_behaviors=behaviors,
        ioc=ioc,
        mitre_mapping=mitre,
        required_telemetry=telemetry,
        hunt_checklist=_checklist(behaviors, telemetry),
        query_drafts=_query_drafts(text),
        correlation_logic="Correlate matching behaviors by host, user, process, and time window. Treat generated logic as a draft until validated against real SIEM/EDR schema.",
        escalation_condition="Escalate when multiple behaviors from the same report appear on the same host/user or when high-impact behavior such as credential access, persistence, C2, or exfiltration is confirmed.",
        analyst_notes="MVP mock analyzer output. Review generated queries and assumptions before operational use.",
    )
    return save_hunt_package(package)
