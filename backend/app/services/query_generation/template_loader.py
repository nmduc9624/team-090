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


def find_templates_for_text(text: str) -> list[QueryTemplate]:
    lower = text.lower()
    templates = list_query_templates()
    selected: list[QueryTemplate] = []
    keyword_map = {
        "powershell": ["powershell"],
        "encoded": ["powershell"],
        "dns": ["dns"],
        "txt": ["dns"],
        "registry": ["registry", "runkey"],
        "run key": ["registry", "runkey"],
        "oauth": ["oauth"],
        "service": ["service", "lateral"],
        "admin$": ["service", "lateral"],
        "mshta": ["process", "registry", "network"],
        "excel": ["process", "registry", "network"],
    }
    wanted = set()
    for token, names in keyword_map.items():
        if token in lower:
            wanted.update(names)
    for template in templates:
        name = template.name.lower()
        content = template.content.lower()
        if any(w in name or w in content for w in wanted):
            selected.append(template)
    return selected[:4] if selected else templates[:2]
