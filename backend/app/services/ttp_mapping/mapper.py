from pathlib import Path

from app.core.config import get_settings


def load_mitre_mapping_text() -> str:
    settings = get_settings()
    path = Path(settings.data_dir) / "mitre" / "technique_mapping.md"
    return path.read_text(encoding="utf-8")


def map_behaviors_to_mitre(behaviors: list[str], report_text: str) -> list[str]:
    mapping_text = load_mitre_mapping_text()
    lower = ("\n".join(behaviors) + "\n" + report_text).lower()
    candidates: list[str] = []
    for line in mapping_text.splitlines():
        if not line.startswith("|") or "---" in line or "Behavior" in line:
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) < 2:
            continue
        behavior, technique = parts[0].lower(), parts[1]
        tokens = [t for t in behavior.replace("/", " ").replace("-", " ").split() if len(t) > 3]
        if any(token in lower for token in tokens):
            candidates.append(technique)
    seen = set()
    deduped = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped[:8]
