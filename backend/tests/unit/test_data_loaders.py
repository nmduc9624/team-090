from app.services.query_generation.template_loader import list_query_templates
from app.services.telemetry_schemas.loader import load_log_schema


def test_load_log_schema():
    schema = load_log_schema()
    assert "log_sources" in schema
    assert "edr_process" in schema["log_sources"]


def test_list_query_templates():
    templates = list_query_templates()
    assert len(templates) >= 10
    assert any(template.platform == "KQL" for template in templates)
