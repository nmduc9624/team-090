from pathlib import Path
from typing import Any

from app.core.config import get_settings


def _simple_yaml_parse(text: str) -> dict[str, Any]:
    # Small fallback parser for the current MVP schema shape when PyYAML is not installed.
    result: dict[str, Any] = {"log_sources": {}}
    current_source: str | None = None
    current_field_list = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            continue
        if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
            current_source = stripped[:-1]
            result["log_sources"][current_source] = {"fields": []}
            current_field_list = False
            continue
        if current_source and stripped.startswith("description:"):
            result["log_sources"][current_source]["description"] = stripped.split(":", 1)[1].strip()
            current_field_list = False
            continue
        if current_source and stripped == "fields:":
            current_field_list = True
            continue
        if current_source and current_field_list and stripped.startswith("- "):
            result["log_sources"][current_source]["fields"].append(stripped[2:].strip())
    return result


def load_log_schema() -> dict[str, Any]:
    settings = get_settings()
    path = Path(settings.data_dir) / "log_schemas" / "log_source_schema.yml"
    text = path.read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except Exception:
        return _simple_yaml_parse(text)


def list_telemetry_sources() -> list[str]:
    schema = load_log_schema()
    return sorted((schema.get("log_sources") or {}).keys())
