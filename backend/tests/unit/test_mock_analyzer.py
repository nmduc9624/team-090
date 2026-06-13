from pathlib import Path

from app.schemas.threat_report import ThreatReportRequest
from app.services.threat_reports.analyzer import analyze_report


def test_excel_mshta_report_generates_hunt_package():
    repo = Path(__file__).resolve().parents[3]
    report = (repo / "data" / "threat_reports" / "samples" / "excel_mshta_persistence.md").read_text(encoding="utf-8")

    package = analyze_report(ThreatReportRequest(title="Excel mshta", content=report))

    assert package.threat_summary
    assert package.key_behaviors
    assert "edr_process" in package.required_telemetry
    assert package.query_drafts
    assert any("mshta" in item.lower() for item in package.key_behaviors)
