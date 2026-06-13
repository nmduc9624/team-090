import sys
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
backend = repo / "backend"
sys.path.insert(0, str(backend))

from app.schemas.threat_report import ThreatReportRequest
from app.services.query_generation.template_loader import list_query_templates
from app.services.telemetry_schemas.loader import load_log_schema
from app.services.threat_reports.analyzer import analyze_report


def main() -> None:
    report_path = repo / "data" / "threat_reports" / "samples" / "excel_mshta_persistence.md"
    report = report_path.read_text(encoding="utf-8")
    schema = load_log_schema()
    templates = list_query_templates()
    package = analyze_report(ThreatReportRequest(title="Excel mshta persistence", content=report))

    print("log_sources", sorted(schema["log_sources"].keys())[:5], "...")
    print("query_templates", len(templates))
    print("package_id", package.package_id)
    print("behaviors", package.key_behaviors[:3])
    print("telemetry", package.required_telemetry)
    print("queries", [q.name for q in package.query_drafts])


if __name__ == "__main__":
    main()
