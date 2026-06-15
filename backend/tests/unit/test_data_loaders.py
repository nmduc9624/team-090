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

def test_list_sample_reports():
    from app.services.threat_reports.sample_loader import get_sample_report, list_sample_reports

    reports = list_sample_reports()
    assert len(reports) >= 100
    assert any(report.slug == "excel_mshta_persistence" for report in reports)

    sample = get_sample_report("excel_mshta_persistence")
    assert "excel.exe launches mshta.exe" in sample.content
