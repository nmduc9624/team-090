from pathlib import Path

from app.core.config import get_settings
from app.schemas.data import QueryTemplate


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
                )
            )
    return templates


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
    templates = list_query_templates()
    selected: list[QueryTemplate] = []
    keyword_map = {
        "powershell": ["powershell"],
        "encoded": ["powershell"],
        "dns": ["dns"],
        "txt": ["dns"],
        "registry": ["registry", "runkey"],
        "run key": ["registry", "runkey"],
        "oauth": ["oauth", "saas"],
        "consent": ["oauth", "saas"],
        "slack": ["oauth", "saas"],
        "github": ["oauth", "saas", "developer"],
        "gitlab": ["oauth", "saas", "developer"],
        "repository": ["developer"],
        "repositories": ["developer"],
        "deploy key": ["developer"],
        "secrets": ["developer"],
        "saas": ["oauth", "saas"],
        "channel history": ["oauth", "saas"],
        "private channel": ["oauth", "saas"],
        "export": ["saas"],
        "service": ["service", "lateral"],
        "admin$": ["service", "lateral"],
        "mshta": ["process", "registry", "network"],
        "excel": ["process", "registry", "network"],
    }
    wanted = set()
    for token, names in keyword_map.items():
        if token in lower:
            wanted.update(names)

    developer_platform_context = any(
        token in lower
        for token in ["github", "gitlab", "bitbucket", "repository", "repositories", "deploy key", "secrets metadata"]
    ) and any(token in lower for token in ["oauth", "authorization", "app", "permission", "permissions"])
    if not developer_platform_context:
        wanted.discard("developer")

    if not wanted:
        return []

    # SaaS/OAuth reports should not pull endpoint templates merely because the
    # indicator block contains fields such as "registry_keys: none".
    saas_oauth_context = bool({"oauth", "saas"} & wanted)
    endpoint_context = any(token in lower for token in [".exe", "registry key", "run key", "mshta", "powershell", "lsass", "rundll32"])
    if saas_oauth_context and not endpoint_context:
        wanted -= {"process", "registry", "runkey", "network", "powershell", "service", "lateral"}

    for template in templates:
        name = template.name.lower()
        if any(w in name for w in wanted):
            selected.append(template)

    if selected:
        return selected[:4]
    return []
