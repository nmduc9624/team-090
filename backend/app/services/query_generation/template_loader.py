from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.schemas.data import QueryTemplate
from app.services.rag.guardrails import INTENTS, classify_intent


TEMPLATE_REGISTRY: dict[str, dict[str, Any]] = {
    "linux_uid0_account_creation_hunt": {
        "intents": ["linux"],
        "telemetry": ["linux_audit", "linux_process", "file_events", "auth"],
        "mitre": ["T1136.001", "T1136", "T1548", "T1078"],
        "keywords": ["uid 0", "root-equivalent", "root equivalent", "useradd", "/etc/passwd"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["windows registry", "mshta", "oauth", "bucket"],
        "priority": 130,
    },
    "dcsync_replication_hunt": {
        "intents": ["kerberos_ad"],
        "telemetry": ["auth", "windows_security", "active_directory"],
        "mitre": ["T1003.006", "T1078", "T1558"],
        "keywords": ["dcsync", "replication", "drsuapi", "directory replication"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "endpoint_lolbin"],
        "blocked_keywords": ["oauth", "bucket", "mshta"],
        "priority": 125,
    },
    "golden_ticket_hunt": {
        "intents": ["kerberos_ad"],
        "telemetry": ["auth", "windows_security", "active_directory"],
        "mitre": ["T1558", "T1558.001", "T1078"],
        "keywords": ["golden ticket", "forged ticket", "krbtgt", "ticket lifetime"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "endpoint_lolbin"],
        "blocked_keywords": ["oauth", "bucket", "mshta"],
        "priority": 125,
    },
    "ransomware_preparation_hunt": {
        "intents": ["defense_evasion"],
        "telemetry": ["edr_process", "windows_service", "file_events"],
        "mitre": ["T1490", "T1486", "T1562"],
        "keywords": ["shadow copy", "vssadmin", "backup deleted", "ransomware"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad", "linux"],
        "blocked_keywords": ["oauth", "bucket", "linux"],
        "priority": 120,
    },
    "cloud_iam_admin_policy_attachment_hunt": {
        "intents": ["cloud_iam"],
        "telemetry": ["cloud_audit", "auth"],
        "mitre": ["T1098", "T1098.003", "T1078.004"],
        "keywords": ["iam", "admin policy", "administratoraccess", "role assignment", "attachpolicy", "attachrolepolicy", "setiampolicy"],
        "blocked_intents": ["cloud_storage", "cloud_metadata", "endpoint_lolbin", "endpoint_credential", "kerberos_ad"],
        "blocked_keywords": ["bucket", "public access", "metadata endpoint", "lsass", "mshta", "registry run"],
        "priority": 100,
    },
    "cloud_storage_public_access_hunt": {
        "intents": ["cloud_storage"],
        "telemetry": ["cloud_audit", "auth", "proxy"],
        "mitre": ["T1530", "T1567.002", "T1078.004", "T1098"],
        "keywords": ["bucket", "storage", "acl", "public", "allusers", "anonymous"],
        "blocked_intents": ["cloud_iam", "cloud_metadata", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["admin policy", "metadata endpoint", "lsass", "mshta", "registry run"],
        "priority": 100,
    },
    "cloud_metadata_token_abuse_hunt": {
        "intents": ["cloud_metadata"],
        "telemetry": ["cloud_audit", "proxy", "edr_process"],
        "mitre": ["T1552.005", "T1078.004", "T1098"],
        "keywords": ["metadata", "169.254.169.254", "imds", "metadata.google.internal"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "saas_oauth", "developer_platform", "kerberos_ad"],
        "blocked_keywords": ["admin policy", "bucket public", "oauth consent", "deploy key", "kerberos"],
        "priority": 100,
    },
    "kerberos_ticket_anomaly_hunt": {
        "intents": ["kerberos_ad"],
        "telemetry": ["auth", "windows_security", "active_directory", "kerberos"],
        "mitre": ["T1558", "T1558.003", "T1558.004", "T1003.006", "T1078"],
        "keywords": ["kerberos", "ticket", "spn", "as-rep", "dcsync", "ldap", "domain controller"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "cloud_metadata", "endpoint_lolbin"],
        "blocked_keywords": ["cloud iam", "cloud storage", "bucket", "instance metadata", "metadata endpoint", "mshta", "registry run"],
        "priority": 100,
    },
    "password_spray_hunt": {
        "intents": ["password_spray"],
        "telemetry": ["auth", "proxy", "cloud_audit"],
        "mitre": ["T1110.003", "T1110", "T1078"],
        "keywords": ["password spray", "failed login", "many users", "source ip"],
        "blocked_intents": ["mfa_fatigue", "mfa_auth_change", "web_attack", "endpoint_lolbin"],
        "blocked_keywords": ["mfa push", "auth method", "web admin panel", "mshta"],
        "priority": 95,
    },
    "mfa_push_fatigue_hunt": {
        "intents": ["mfa_fatigue"],
        "telemetry": ["auth", "cloud_audit", "email_audit", "proxy"],
        "mitre": ["T1621", "T1078", "T1098"],
        "keywords": ["mfa push", "push prompt", "challenge", "approved", "denied"],
        "blocked_intents": ["mfa_auth_change", "password_spray", "endpoint_lolbin"],
        "blocked_keywords": ["mfa disabled", "authentication method removed", "registry run", "mshta"],
        "priority": 95,
    },
    "mfa_auth_method_change_hunt": {
        "intents": ["mfa_auth_change"],
        "telemetry": ["auth", "cloud_audit"],
        "mitre": ["T1098", "T1078", "T1556"],
        "keywords": ["mfa disabled", "mfa method", "authentication method", "method removed", "strong auth", "security info"],
        "blocked_intents": ["mfa_fatigue", "password_spray", "endpoint_lolbin"],
        "blocked_keywords": ["push fatigue", "push prompt", "approved challenge", "mshta"],
        "priority": 100,
    },
    "developer_oauth_repo_access_hunt": {
        "intents": ["developer_platform"],
        "telemetry": ["cloud_audit", "auth", "proxy", "github_audit"],
        "mitre": ["T1528", "T1098", "T1552", "T1530", "T1078"],
        "keywords": ["github", "repository", "deploy key", "secrets metadata", "oauth"],
        "blocked_intents": ["cloud_iam", "cloud_metadata", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["instance metadata", "admin policy", "lsass", "registry run"],
        "priority": 100,
    },
    "saas_oauth_file_export_hunt": {
        "intents": ["saas_oauth"],
        "telemetry": ["cloud_audit", "auth", "email_audit", "proxy"],
        "mitre": ["T1528", "T1530", "T1567.002", "T1078", "T1098"],
        "keywords": ["oauth", "saas", "file export", "channel", "workspace"],
        "blocked_intents": ["developer_platform", "cloud_iam", "cloud_metadata", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["deploy key", "repository", "instance metadata", "mshta", "registry run"],
        "priority": 95,
    },
    "oauth_consent_hunt": {
        "intents": ["saas_oauth", "developer_platform", "identity"],
        "telemetry": ["cloud_audit", "auth"],
        "mitre": ["T1528", "T1078", "T1098"],
        "keywords": ["oauth", "consent", "permission", "scope"],
        "blocked_intents": ["endpoint_lolbin", "endpoint_credential", "kerberos_ad"],
        "blocked_keywords": ["mshta", "lsass", "kerberos"],
        "priority": 60,
    },
    "linux_ssh_auth_hunt": {
        "intents": ["linux"],
        "telemetry": ["linux_audit", "auth", "firewall"],
        "mitre": ["T1110", "T1110.003", "T1021.004"],
        "keywords": ["linux", "ssh", "sshd", "brute force", "failed login"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["windows registry", "mshta", "oauth", "bucket"],
        "priority": 115,
    },    "linux_persistence_execution_hunt": {
        "intents": ["linux"],
        "telemetry": ["linux_audit", "linux_process", "dns", "proxy", "firewall"],
        "mitre": ["T1053.003", "T1059.004", "T1548.003", "T1021.004", "T1105"],
        "keywords": ["linux", "cron", "sudoers", "ssh", "reverse shell", "bash"],
        "blocked_intents": ["endpoint_lolbin", "cloud_iam", "kerberos_ad"],
        "blocked_keywords": ["windows registry", "run key", "mshta", "lsass"],
        "priority": 100,
    },
    "kubernetes_control_plane_hunt": {
        "intents": ["kubernetes_container"],
        "telemetry": ["kubernetes_audit", "container_runtime", "cloud_audit", "linux_audit"],
        "mitre": ["T1609", "T1611", "T1552", "T1078", "T1098"],
        "keywords": ["kubernetes", "kubectl", "pod", "container", "secret", "privileged"],
        "blocked_intents": ["cloud_iam", "endpoint_lolbin", "kerberos_ad"],
        "blocked_keywords": ["registry run", "mshta", "kerberos"],
        "priority": 100,
    },
    "web_attack_hunt": {
        "intents": ["web_attack"],
        "telemetry": ["web_server", "waf", "proxy", "file_events", "firewall"],
        "mitre": ["T1190", "T1505.003", "T1059"],
        "keywords": ["web", "rce", "sql injection", "path traversal", "webshell", "admin panel", "upload"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["cloud iam", "oauth consent", "kerberos ticket"],
        "priority": 95,
    },
    "credential_dumping_lsass_hunt": {
        "intents": ["endpoint_credential"],
        "telemetry": ["edr_process", "file_events", "auth"],
        "mitre": ["T1003", "T1003.001", "T1555", "T1055"],
        "keywords": ["lsass", "credential", "dump", "procdump", "handle access"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["cloud metadata", "bucket", "oauth"],
        "priority": 100,
    },
    "lateral_movement_service_hunt": {
        "intents": ["endpoint_lateral"],
        "telemetry": ["edr_process", "windows_service", "wmi_events", "auth", "file_events", "firewall"],
        "mitre": ["T1021", "T1021.002", "T1047", "T1569.002", "T1543.003"],
        "keywords": ["psexec", "wmic", "winrm", "remote service", "admin$", "remote registry", "service"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["oauth consent", "cloud iam", "bucket public"],
        "priority": 95,
    },
    "remote_registry_service_hunt": {
        "intents": ["endpoint_lateral"],
        "telemetry": ["windows_service", "edr_process", "auth", "windows_security"],
        "mitre": ["T1021", "T1021.002", "T1569.002", "T1543.003"],
        "keywords": ["remote registry", "remoteregistry", "service enabled", "service started"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["oauth", "bucket", "instance metadata", "metadata endpoint"],
        "priority": 110,
    },
    "data_exfil_large_upload_hunt": {
        "intents": ["data_exfil"],
        "telemetry": ["proxy", "file_events", "cloud_audit", "dns", "firewall"],
        "mitre": ["T1567.002", "T1560", "T1041", "T1530"],
        "keywords": ["data loss", "large upload", "bytes_out", "rclone", "cloud drive", "personal drive", "exfil"],
        "blocked_intents": ["cloud_iam", "kerberos_ad", "endpoint_lateral"],
        "blocked_keywords": ["admin policy", "kerberos", "remote registry"],
        "priority": 105,
    },    "remote_access_login_hunt": {
        "intents": ["remote_access"],
        "telemetry": ["auth", "firewall", "proxy"],
        "mitre": ["T1133", "T1078", "T1021"],
        "keywords": ["rdp", "vpn", "remote access", "remote desktop", "after hours", "new country"],
        "blocked_intents": ["endpoint_lateral", "cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["psexec", "remote registry", "oauth", "bucket", "kerberos"],
        "priority": 105,
    },    "defense_evasion_tampering_hunt": {
        "intents": ["defense_evasion"],
        "telemetry": ["edr_process", "windows_service", "driver_load", "file_events", "windows_security"],
        "mitre": ["T1562", "T1070", "T1490", "T1068"],
        "keywords": ["defender", "tamper", "security log", "shadow copy", "backup", "driver"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["oauth", "bucket public", "kerberos ticket"],
        "priority": 95,
    },
    "dns_tunneling_hunt": {
        "intents": ["dns"],
        "telemetry": ["dns", "proxy", "firewall"],
        "mitre": ["T1071.004", "T1071", "T1041"],
        "keywords": ["dns", "txt", "nxdomain", "tunneling", "subdomain", "dga"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["oauth consent", "admin policy", "kerberos ticket"],
        "priority": 90,
    },
    "mailbox_rule_forwarding_hunt": {
        "intents": ["email_mailbox"],
        "telemetry": ["email_audit", "auth", "email", "proxy"],
        "mitre": ["T1114", "T1098", "T1078"],
        "keywords": ["mailbox", "inbox", "forwarding", "mail rule", "email"],
        "blocked_intents": ["endpoint_lolbin", "cloud_iam", "kerberos_ad"],
        "blocked_keywords": ["mshta", "admin policy", "kerberos"],
        "priority": 95,
    },
    "software_supply_chain_postinstall_hunt": {
        "intents": ["endpoint_lolbin"],
        "telemetry": ["edr_process", "proxy", "file_events"],
        "mitre": ["T1195.002", "T1059", "T1105"],
        "keywords": ["npm", "postinstall", "supply chain", "package install", "node"],
        "blocked_intents": ["cloud_iam", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["bucket", "oauth consent", "kerberos"],
        "priority": 110,
    },    "process_registry_network_hunt": {
        "intents": ["endpoint_lolbin"],
        "telemetry": ["edr_process", "edr_registry", "dns", "proxy"],
        "mitre": ["T1218", "T1547.001", "T1105", "T1071.001"],
        "keywords": ["mshta", "excel", "office", "registry", "network", "payload"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["cloud iam", "bucket", "oauth", "kerberos"],
        "priority": 95,
    },
    "registry_runkey_hunt": {
        "intents": ["endpoint_lolbin", "endpoint"],
        "telemetry": ["edr_registry", "edr_process"],
        "mitre": ["T1547.001"],
        "keywords": ["registry", "run key", "currentversion\\run"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "saas_oauth", "kerberos_ad", "linux"],
        "blocked_keywords": ["cloud", "oauth", "linux", "kerberos"],
        "priority": 75,
    },
    "encoded_powershell_hunt": {
        "intents": ["endpoint_lolbin"],
        "telemetry": ["edr_process", "dns", "proxy"],
        "mitre": ["T1059.001", "T1105", "T1071.001"],
        "keywords": ["powershell", "encoded", "-enc", "download cradle"],
        "blocked_intents": ["cloud_iam", "cloud_storage", "saas_oauth", "kerberos_ad"],
        "blocked_keywords": ["oauth", "bucket", "kerberos"],
        "priority": 80,
    },
}


INTENT_FALLBACK_TOKENS: dict[str, tuple[str, ...]] = {
    "kerberos_ad": ("kerberos", "dcsync", "asrep", "spn", "ldap", "golden"),
    "mfa_fatigue": ("mfa_push", "mfa"),
    "mfa_auth_change": ("mfa_auth", "authentication_method", "auth_method"),
    "password_spray": ("password_spray", "password", "spray"),
    "cloud_iam": ("cloud_iam", "admin_policy", "role_assignment"),
    "cloud_storage": ("cloud_storage", "bucket"),
    "cloud_metadata": ("cloud_metadata", "metadata"),
    "developer_platform": ("developer", "github", "repo"),
    "saas_oauth": ("saas", "oauth"),
    "linux": ("linux", "cron", "ssh", "uid0", "uid 0", "passwd", "useradd"),
    "kubernetes_container": ("kubernetes", "container"),
    "web_attack": ("web_attack", "web", "waf"),
    "data_exfil": ("rclone", "exfil", "upload", "proxy"),
    "email_mailbox": ("mailbox", "email"),
    "endpoint_credential": ("credential", "lsass"),
    "endpoint_lateral": ("lateral", "service", "remote_registry"),
    "remote_access": ("remote_access", "rdp", "vpn", "remote"),
    "defense_evasion": ("defense", "driver", "shadow", "tamper"),
    "dns": ("dns", "tunneling"),
    "endpoint_lolbin": ("process", "registry", "powershell", "mshta", "encoded"),
}


def list_query_templates() -> list[QueryTemplate]:
    settings = get_settings()
    root = Path(settings.data_dir) / "query_templates"
    templates: list[QueryTemplate] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".kql", ".spl", ".md", ".txt"}:
            platform = path.parent.name.upper()
            if path.suffix.lower() == ".kql":
                platform = "KQL"
            elif path.suffix.lower() == ".spl":
                platform = "SPL"
            templates.append(
                QueryTemplate(
                    name=path.stem,
                    platform=platform,
                    path=str(path.relative_to(settings.data_dir)),
                    content=path.read_text(encoding="utf-8"),
                    metadata=_metadata_for_template(path.stem, platform),
                )
            )
    return templates


def _metadata_for_template(name: str, platform: str) -> dict[str, Any]:
    metadata = dict(TEMPLATE_REGISTRY.get(name.lower(), {}))
    metadata.setdefault("intents", [])
    metadata.setdefault("telemetry", [])
    metadata.setdefault("mitre", [])
    metadata.setdefault("keywords", [])
    metadata.setdefault("blocked_intents", [])
    metadata.setdefault("blocked_keywords", [])
    metadata.setdefault("priority", 50)
    metadata["platform"] = platform
    metadata["schema_mode"] = "generic_field_mapping_required"
    return metadata


def _meaningful_text(text: str) -> str:
    lines = []
    for line in text.splitlines():
        lower = line.strip().lower()
        if lower.endswith(": none") or lower.endswith(" none"):
            continue
        lines.append(line)
    return "\n".join(lines).lower()


def find_templates_for_text(text: str) -> list[QueryTemplate]:
    lower = _meaningful_text(text)
    intent = classify_intent("", lower)
    templates = list_query_templates()
    selected = _select_templates_for_intent(templates, intent, lower)
    if selected:
        return selected
    return _legacy_keyword_fallback(templates, lower)[:4]


def _select_templates_for_intent(templates: list[QueryTemplate], intent, lower: str) -> list[QueryTemplate]:
    scored: list[tuple[int, QueryTemplate]] = []
    for template in templates:
        score = _score_template(template, intent.name, lower)
        if score > 0:
            scored.append((score, template))
    scored.sort(key=lambda item: (-item[0], _platform_order(item[1].platform), item[1].name))
    return [template for _, template in scored[:4]]


def _score_template(template: QueryTemplate, intent_name: str, lower: str) -> int:
    metadata = template.metadata or {}
    name = template.name.lower()
    path = template.path.lower()
    content = template.content.lower()
    identity = f"{name}\n{path}"
    haystack = f"{identity}\n{content}"
    score = int(metadata.get("priority", 50))

    blocked_intents = set(metadata.get("blocked_intents", []))
    if intent_name in blocked_intents:
        return -1000

    blocked_keywords = [str(item).lower() for item in metadata.get("blocked_keywords", [])]
    if any(keyword and keyword in lower for keyword in blocked_keywords):
        return -1000

    intents = set(metadata.get("intents", []))
    if intent_name in intents:
        score += 200
    elif intents:
        score -= 150

    intent = INTENTS.get(intent_name)
    if intent:
        telemetry = set(metadata.get("telemetry", []))
        if telemetry & set(intent.required_telemetry):
            score += 40
        if telemetry & set(intent.telemetry_allow):
            score += 30
        if telemetry & set(intent.blocked_telemetry):
            score -= 120
        if any(keyword in haystack for keyword in intent.blocked_keywords):
            score -= 160

    keywords = [str(item).lower() for item in metadata.get("keywords", [])]
    score += sum(20 for keyword in keywords if keyword and keyword in lower)

    fallback_tokens = INTENT_FALLBACK_TOKENS.get(intent_name, ())
    if any(token in identity for token in fallback_tokens):
        score += 50
    elif any(token in haystack for token in fallback_tokens):
        score += 15

    if template.platform == "GENERIC":
        score += 10
    elif template.platform in {"KQL", "SPL"}:
        score += 5

    return score if score >= 90 else 0


def _platform_order(platform: str) -> int:
    return {"GENERIC": 0, "KQL": 1, "SPL": 2}.get(platform, 9)


def _legacy_keyword_fallback(templates: list[QueryTemplate], lower: str) -> list[QueryTemplate]:
    keyword_map = {
        "powershell": ["powershell"],
        "encoded": ["powershell"],
        "dns": ["dns"],
        "txt": ["dns"],
        "registry": ["registry", "runkey"],
        "run key": ["registry", "runkey"],
        "oauth": ["oauth", "saas"],
        "consent": ["oauth", "saas"],
        "github": ["developer"],
        "repository": ["developer"],
        "deploy key": ["developer"],
        "service": ["service", "lateral"],
        "remote registry": ["remote_registry", "service", "lateral"],
        "mshta": ["process", "registry", "network"],
        "excel": ["process", "registry", "network"],
    }
    wanted = set()
    for token, names in keyword_map.items():
        if token in lower:
            wanted.update(names)
    if not wanted:
        return []
    selected = []
    for template in templates:
        name = template.name.lower()
        if any(w in name for w in wanted):
            selected.append(template)
    return selected








